// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Pre-flight infrastructure-prerequisite gate.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/keyctl.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "config.h"
#include "initrd.h"
#include "crypto.h"
#include "io.h"
#include "kernel_abi.h"
#include "kernel_prereq.h"
#include "keys.h"
#include "loader.h"
#include "malloc.h"
#include "paths.h"
#include "preflight.h"

#ifndef KEY_SPEC_USER_KEYRING
#define KEY_SPEC_USER_KEYRING	(-4)
#endif
#ifndef KEY_SPEC_THREAD_KEYRING
#define KEY_SPEC_THREAD_KEYRING	(-1)
#endif
#ifndef KEY_SPEC_BPF_KEYRING
#define KEY_SPEC_BPF_KEYRING	(-9)
#endif

#define PREFLIGHT_CERT_MAX	(1u * 1024u * 1024u)

static struct preflight_check *
next_slot(struct preflight_result *r, enum preflight_id id,
	  const char *name)
{
	struct preflight_check *c = &r->checks[r->n++];

	c->id = id;
	c->name = name;
	c->detail[0] = '\0';
	return c;
}

static void pass(struct preflight_check *c)
{
	c->ok = true;
}

__printf(3, 4)
static void fail(struct preflight_result *r,
		 struct preflight_check *c, const char *fmt, ...)
{
	va_list ap;

	c->ok = false;
	va_start(ap, fmt);
	if (vstrsprintf(c->detail, sizeof(c->detail), fmt, ap) < 0)
		strscpy_literal(c->detail, "?");
	va_end(ap);
	r->n_failed++;
}

static void check_root(struct preflight_result *r)
{
	struct preflight_check *c =
		next_slot(r, PRE_ROOT, "root");

	if (geteuid() == 0)
		pass(c);
	else
		fail(r, c, "must run as root (EUID=%u)",
		     (__u32)geteuid());
}

static bool lsm_lists_bpf(void)
{
	char buf[1024 + 1];
	const char *name;
	size_t len;
	ssize_t n;
	int fd;

	fd = open("/sys/kernel/security/lsm", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0 || span_to_str(buf, sizeof(buf), buf, (size_t)n))
		return false;
	for_each_token(name, len, buf, (size_t)n, ",\n") {
		if (span_equals(name, len, "bpf"))
			return true;
	}
	return false;
}

static void check_bpf_lsm(struct preflight_result *r)
{
	struct preflight_check *c =
		next_slot(r, PRE_BPF_LSM, "bpf_lsm_active");

	if (lsm_lists_bpf())
		pass(c);
	else
		fail(r, c,
		     "/sys/kernel/security/lsm has no \"bpf\" entry "
		     "(needs CONFIG_BPF_LSM=y, bpf in CONFIG_LSM)");
}

#define POWER_DISK_MAX		256u
#define POWER_RESUME_MAX	64u

/*
 * The first line of the sysfs attribute at path, its line ending cut,
 * in buf; NULL when the attribute is absent or holds no line.
 */
static const char *power_line(const char *path, char *buf, size_t cap)
{
	char *line = NULL;
	size_t capacity = 0, len;
	FILE *f;
	int got;

	f = fopen(path, "re");
	if (!f)
		return NULL;
	got = read_text_line(f, &line, &capacity, cap - 1);
	fclose(f);
	if (got != 1) {
		libc_free(line);
		return NULL;
	}
	len = span_until(line, strlen(line), "\r\n");
	if (span_to_str(buf, cap, line, len))
		buf[0] = '\0';
	libc_free(line);
	return buf[0] ? buf : NULL;
}

#define FILESYSTEMS_LINE_MAX	127u

static bool bpffs_in_proc_filesystems(void)
{
	FILE *f = fopen("/proc/filesystems", "re");
	size_t capacity = 0;
	bool found = false;
	char *line = NULL;
	int got;

	if (!f)
		return false;
	while ((got = read_text_line(f, &line, &capacity,
				     FILESYSTEMS_LINE_MAX)) != 0) {
		char *tab, *name, *nl;

		if (got == -E2BIG)
			continue;
		if (got < 0)
			break;
		tab = strchr(line, '\t');
		if (!tab)
			continue;
		name = tab + 1;
		nl = strchr(name, '\n');
		if (nl)
			*nl = '\0';
		if (strcmp(name, "bpf") == 0) {
			found = true;
			break;
		}
	}
	libc_free(line);
	fclose(f);
	return found;
}

static void check_bpffs(struct preflight_result *r)
{
	struct preflight_check *c =
		next_slot(r, PRE_BPFFS, "bpffs_supported");

	if (bpffs_in_proc_filesystems())
		pass(c);
	else
		fail(r, c,
		     "/proc/filesystems does not advertise bpf "
		     "(needs CONFIG_BPF_FS=y)");
}

static void check_signed_loader_abi(struct preflight_result *r)
{
	struct preflight_check *c =
		next_slot(r, PRE_SIGNED_LOADER_ABI,
			  "signed_loader_kernel_abi");

	if (kernel_abi_check(c->detail, sizeof(c->detail)) == 0) {
		pass(c);
	} else {
		c->ok = false;
		r->n_failed++;
	}
}

/*
 * The hooks come from the embedded objects themselves, so a program
 * added on a hook only a carried kernel patch provides is checked
 * without a list here to keep in step.
 */
static void check_lsm_hooks(struct preflight_result *r)
{
	const struct embedded_bpf *objs[] = { bpf2_blob(), seal_blob() };
	struct preflight_check *c =
		next_slot(r, PRE_LSM_HOOKS, "kernel_lsm_hooks");
	struct lsm_hooks hooks = {};
	size_t i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(objs); i++) {
		if (!objs[i]->size) {
			pass(c);
			strscpy_literal(c->detail,
					"skipped (embedded objects missing)");
			return;
		}
		ret = kernel_abi_lsm_hooks(objs[i], &hooks);
		if (ret) {
			fail(r, c, "cannot read the LSM hooks of the embedded %s object: %s",
			     objs[i]->name, strerror(-ret));
			return;
		}
	}
	if (kernel_abi_check_lsm_hooks(&hooks, c->detail,
				       sizeof(c->detail)) == 0) {
		pass(c);
	} else {
		c->ok = false;
		r->n_failed++;
	}
}

static void check_module_signatures(struct preflight_result *r,
				    const struct kernel_options *opts)
{
	struct preflight_check *c =
		next_slot(r, PRE_MODULE_SIG, "module_signatures");

	if (!opts)
		fail(r, c, "cannot read the kernel BTF");
	else if (!opts->modules || opts->module_sig)
		pass(c);
	else
		fail(r, c, "the kernel loads modules without checking their "
		     "signatures (needs CONFIG_MODULE_SIG=y, or CONFIG_MODULES=n)");
}

static void check_compat_syscalls(struct preflight_result *r,
				  const struct kernel_options *opts)
{
	struct preflight_check *c =
		next_slot(r, PRE_COMPAT, "compat_syscalls");

	if (!opts)
		fail(r, c, "cannot read the kernel BTF");
	else if (!opts->compat)
		pass(c);
	else
		fail(r, c,
		     "the kernel runs 32-bit compatibility syscalls "
		     "(needs CONFIG_COMPAT=n, and on x86-64 "
		     "CONFIG_IA32_EMULATION=n and CONFIG_X86_X32_ABI=n)");
}

static void check_resume_device(struct preflight_result *r)
{
	struct preflight_check *c =
		next_slot(r, PRE_RESUME, "resume_device");
	char disk[POWER_DISK_MAX], resume[POWER_RESUME_MAX];
	const char *d, *p;

	d = power_line("/sys/power/disk", disk, sizeof(disk));
	p = power_line("/sys/power/resume", resume, sizeof(resume));
	if (!kernel_hibernation_resumes(d, p))
		pass(c);
	else
		fail(r, c, "the boot may resume from a hibernation image "
		     "(resume device %s; needs CONFIG_HIBERNATION=n, "
		     "nohibernate, or no resume device)", p);
}

#define MOUNTS_LINE_MAX	4096u

/*
 * Whether the kernel allows writing to the block device that a file
 * system holds mounted under the state tree: it refuses open() for
 * writing with -EBUSY when CONFIG_BLK_DEV_WRITE_MOUNTED is off. The
 * mount that holds the state tree covers the option and the command
 * line's bdev_allow_write_mounted= alike. A file system that is no
 * block device has nothing to probe, and any other failure leaves the
 * property unknown; both read as not writable.
 */
static bool mounted_device_writable(void)
{
	char state[PATH_MAX], source[PATH_MAX] = {};
	char *line = NULL;
	size_t capacity = 0, best = 0;
	FILE *f;
	int fd, ret;

	ret = state_source(state, sizeof(state));
	if (ret)
		return false;
	f = fopen("/proc/mounts", "re");
	if (!f)
		return false;
	while (read_text_line(f, &line, &capacity, MOUNTS_LINE_MAX) == 1) {
		char dev[PATH_MAX];
		size_t depth;

		if (!kernel_prereq_mount_source(line, state, &depth, dev,
						sizeof(dev)))
			continue;
		/* A later mount over the same mountpoint is the visible one. */
		if (depth < best)
			continue;
		if (strscpy(source, dev, sizeof(source)) < 0)
			continue;
		best = depth;
	}
	libc_free(line);
	fclose(f);
	if (!best || !str_has_prefix(source, "/dev/"))
		return false;
	/*
	 * The path is a field of /proc/mounts, which the kernel writes,
	 * and starts with /dev/, so it names no tree the caller chose.
	 * openat() with AT_FDCWD is open() here; CodeQL's path injection
	 * query takes the field for caller input and flags open().
	 */
	fd = openat(AT_FDCWD, source, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	close(fd);
	return true;
}

static void check_bdev_write_mounted(struct preflight_result *r)
{
	struct preflight_check *c =
		next_slot(r, PRE_BDEV, "bdev_write_mounted");

	if (mounted_device_writable())
		fail(r, c, "the kernel allows writes to the mounted block "
		     "device that holds the state tree (needs "
		     "CONFIG_BLK_DEV_WRITE_MOUNTED=n)");
	else
		pass(c);
}

/* A BTF that cannot be read fails the check that needs it. */
static void check_kernel_options(struct preflight_result *r)
{
	const struct kernel_options *have = NULL;
	struct kernel_options opts = {};
	struct btf *btf;

	btf = btf__load_vmlinux_btf();
	if (!libbpf_get_error(btf)) {
		kernel_prereq_options(btf, &opts);
		have = &opts;
		btf__free(btf);
	}
	check_module_signatures(r, have);
	check_compat_syscalls(r, have);
	check_resume_device(r);
	check_bdev_write_mounted(r);
}

static void check_cert(struct preflight_result *r)
{
	struct preflight_check *c =
		next_slot(r, PRE_CERT_ON_DISK, "cert_on_disk");
	struct stat st;

	if (stat(get_cert_path(), &st) == 0 &&
	    S_ISREG(st.st_mode) && st.st_size > 0)
		pass(c);
	else
		fail(r, c,
		     "%s missing or empty (copy the operator's cert)",
		     get_cert_path());
}

/*
 * shirudo's trust anchor is ML-DSA-87 only: a classical certificate on
 * disk is refused before any kernel state is touched, so a fleet cannot
 * drift back to RSA by provisioning the wrong cert.der.
 */
/*
 * The certificates init would enrol: cert.der and the trusted set
 * beside it. A set that cannot be read is reported by cert_on_disk;
 * the checks below skip rather than fail twice.
 */
static int preflight_keys(struct trusted_set *set)
{
	return keys_load(get_keys_dir(), KEYS_REVOKED_DIR,
			 true, set);
}

static void check_cert_algorithm(struct preflight_result *r)
{
	struct preflight_check *c =
		next_slot(r, PRE_CERT_ALGORITHM, "cert_algorithm");
	struct trusted_set set;
	size_t i;

	if (preflight_keys(&set)) {
		pass(c);
		strscpy_literal(c->detail, "skipped (cert unreadable)");
		return;
	}
	for (i = 0; i < set.n; i++) {
		struct cert cert = {};
		char name[64];
		int ret;

		if (keys_cert_read(&set.certs[i], &cert)) {
			fail(r, c, "%s: cannot parse", set.certs[i].path);
			return;
		}
		ret = cert_key_algorithm(&cert, name, sizeof(name));
		cert_free(&cert);
		if (ret) {
			fail(r, c, "%s: cannot determine public-key algorithm",
			     set.certs[i].path);
			return;
		}
		if (strcmp(name, "ML-DSA-87") != 0) {
			fail(r, c, "%s is %s; shirudo accepts only ML-DSA-87 "
			     "certificates (re-key with shirudo genkey)",
			     set.certs[i].path, name);
			return;
		}
	}
	pass(c);
}

/*
 * The only authoritative answer to "can this kernel use the cert" is the
 * kernel's own X.509 parser. An ML-DSA cert on a kernel without
 * CONFIG_CRYPTO_MLDSA fails add_key(2) with ENOENT (parser knows the
 * OID, no "mldsa87" algorithm is registered) or ENOPKG (parser predates
 * the OID); the same probe triggers module autoload where the algorithm
 * is modular. The probe key goes into the thread keyring, which is
 * private to this thread and discarded with it, so no durable kernel
 * state is touched; it is cleared right away regardless.
 */
static void check_cert_kernel_algo(struct preflight_result *r)
{
	struct preflight_check *c =
		next_slot(r, PRE_CERT_KERNEL_ALGO, "cert_kernel_support");
	struct trusted_set set;
	size_t i;

	if (preflight_keys(&set)) {
		pass(c);
		strscpy_literal(c->detail, "skipped (cert unreadable)");
		return;
	}
	for (i = 0; i < set.n; i++) {
		const __u8 *der = NULL;
		size_t der_sz = 0;
		int ret, err;
		long key;

		ret = keys_cert_der(&set.certs[i], &der, &der_sz);
		if (ret) {
			fail(r, c, "%s: %s", set.certs[i].path, strerror(-ret));
			return;
		}
		key = syscall(__NR_add_key, "asymmetric", "", der, der_sz,
			      (long)KEY_SPEC_THREAD_KEYRING);
		err = key < 0 ? errno : 0;
		syscall(__NR_keyctl, KEYCTL_CLEAR,
			(long)KEY_SPEC_THREAD_KEYRING, 0L, 0L, 0L);
		if (!err)
			continue;
		if (err == ENOENT || err == ENOPKG)
			fail(r, c,
			     "kernel cannot verify the public-key algorithm of %s (ML-DSA certs need CONFIG_CRYPTO_MLDSA=y and CONFIG_CRYPTO_SHA512=y)",
			     set.certs[i].path);
		else
			fail(r, c, "kernel rejected %s: %s "
			     "(add_key asymmetric)", set.certs[i].path,
			     strerror(err));
		return;
	}
	pass(c);
}

static void check_keyring(struct preflight_result *r)
{
	struct preflight_check *c =
		next_slot(r, PRE_KEYRING, "kernel_keyring");
	long ret;

	ret = syscall(__NR_keyctl, KEYCTL_GET_KEYRING_ID,
		      (long)KEY_SPEC_USER_KEYRING, 0L, 0L, 0L);
	if (ret < 0) {
		fail(r, c,
		     "keyctl(GET_KEYRING_ID, USER) failed: %s "
		     "(needs CONFIG_KEYS=y)", strerror(errno));
		return;
	}
	ret = syscall(__NR_keyctl, KEYCTL_GET_KEYRING_ID,
		      (long)KEY_SPEC_BPF_KEYRING, 0L, 0L, 0L);
	if (ret >= 0)
		pass(c);
	else
		fail(r, c,
		     "keyctl(GET_KEYRING_ID, BPF) failed: %s (the kernel has "
		     "no bpf keyring)", strerror(errno));
}

static void check_embedded_loader(struct preflight_result *r)
{
	struct preflight_check *c =
		next_slot(r, PRE_EMBEDDED_LOADER, "embedded_loader");
	const struct embedded_bpf *bpf2 = bpf2_blob();
	const struct embedded_bpf *seal = seal_blob();

	if (bpf2 && bpf2->size && seal && seal->size)
		pass(c);
	else
		fail(r, c, "embedded BPF objects missing");
}

static void check_tpm(struct preflight_result *r)
{
	struct preflight_check *c =
		next_slot(r, PRE_TPM, "tpm2_reachable");

	/*
	 * A TCTI override points at a software TPM, where the kernel resource
	 * manager is not in play, so the device check would refuse a valid
	 * setup. The operator's expectation still rejects what a fake TPM
	 * produces, so this is a convenience, not a relaxation.
	 */
	{
		struct config cfg __cleanup(config_clear) = {};
		bool override = config_load(&cfg) == 0 && cfg.tpm_tcti[0];

		if (override) {
			pass(c);
			if (strsprintf(c->detail, sizeof(c->detail),
				       "TCTI from the config: %s",
				       cfg.tpm_tcti) < 0)
				strscpy_literal(c->detail,
						"TCTI from the config");
		}
		if (override)
			return;
	}
	if (access("/dev/tpmrm0", R_OK | W_OK) == 0)
		pass(c);
	else
		fail(r, c,
		     "/dev/tpmrm0: %s (shirudo requires a TPM 2.0; for swtpm "
		     "set tpm.tcti = swtpm:host=...,port=... in "
		     "/etc/shirudo/shirudo.conf or SHIRUDO_TPM_TCTI)",
		     strerror(errno));
}

void preflight_run(struct preflight_result *out)
{
	memset(out, 0, sizeof(*out));
	check_root(out);
	check_bpf_lsm(out);
	check_bpffs(out);
	check_signed_loader_abi(out);
	check_lsm_hooks(out);
	check_kernel_options(out);
	check_cert(out);
	check_cert_algorithm(out);
	check_cert_kernel_algo(out);
	check_keyring(out);
	check_embedded_loader(out);
	check_tpm(out);
}
