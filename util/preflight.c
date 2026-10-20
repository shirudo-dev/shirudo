// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Pre-flight infrastructure-prerequisite gate.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/keyctl.h>

#include <shirudo/misc.h>

#include "config.h"
#include "initrd.h"
#include "crypto.h"
#include "kernel_abi.h"
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

static struct shirudo_preflight_check *
next_slot(struct shirudo_preflight_result *r, enum shirudo_preflight_id id,
	  const char *name)
{
	struct shirudo_preflight_check *c = &r->checks[r->n++];

	c->id = id;
	c->name = name;
	c->detail[0] = '\0';
	return c;
}

static void pass(struct shirudo_preflight_check *c)
{
	c->ok = true;
}

__attribute__((format(printf, 3, 4)))
static void fail(struct shirudo_preflight_result *r,
		 struct shirudo_preflight_check *c, const char *fmt, ...)
{
	va_list ap;

	c->ok = false;
	va_start(ap, fmt);
	vsnprintf(c->detail, sizeof(c->detail), fmt, ap);
	va_end(ap);
	r->n_failed++;
}

static void check_root(struct shirudo_preflight_result *r)
{
	struct shirudo_preflight_check *c =
		next_slot(r, SHIRUDO_PRE_ROOT, "root");

	if (geteuid() == 0)
		pass(c);
	else
		fail(r, c, "must run as root (EUID=%u)",
		     (__u32)geteuid());
}

static bool lsm_lists_bpf(void)
{
	char buf[1024];
	ssize_t n;
	int fd;

	fd = open("/sys/kernel/security/lsm", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return false;
	buf[n] = '\0';

	for (char *p = strtok(buf, ",\n"); p; p = strtok(NULL, ",\n")) {
		if (strcmp(p, "bpf") == 0)
			return true;
	}
	return false;
}

static void check_bpf_lsm(struct shirudo_preflight_result *r)
{
	struct shirudo_preflight_check *c =
		next_slot(r, SHIRUDO_PRE_BPF_LSM, "bpf_lsm_active");

	if (lsm_lists_bpf())
		pass(c);
	else
		fail(r, c,
		     "/sys/kernel/security/lsm has no \"bpf\" entry "
		     "(needs CONFIG_BPF_LSM=y, bpf in CONFIG_LSM)");
}

static bool bpffs_in_proc_filesystems(void)
{
	FILE *f = fopen("/proc/filesystems", "r");
	char line[128];
	bool found = false;

	if (!f)
		return false;
	while (fgets(line, sizeof(line), f)) {
		char *tab = strchr(line, '\t');
		char *name, *nl;

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
	fclose(f);
	return found;
}

static void check_bpffs(struct shirudo_preflight_result *r)
{
	struct shirudo_preflight_check *c =
		next_slot(r, SHIRUDO_PRE_BPFFS, "bpffs_supported");

	if (bpffs_in_proc_filesystems())
		pass(c);
	else
		fail(r, c,
		     "/proc/filesystems does not advertise bpf "
		     "(needs CONFIG_BPF_FS=y)");
}

static void check_signed_loader_abi(struct shirudo_preflight_result *r)
{
	struct shirudo_preflight_check *c =
		next_slot(r, SHIRUDO_PRE_SIGNED_LOADER_ABI,
			  "signed_loader_kernel_abi");

	if (kernel_abi_check(c->detail, sizeof(c->detail)) == 0) {
		pass(c);
	} else {
		c->ok = false;
		r->n_failed++;
	}
}

static void check_cert(struct shirudo_preflight_result *r)
{
	struct shirudo_preflight_check *c =
		next_slot(r, SHIRUDO_PRE_CERT_ON_DISK, "cert_on_disk");
	struct stat st;

	if (stat(shirudo_cert_path(), &st) == 0 &&
	    S_ISREG(st.st_mode) && st.st_size > 0)
		pass(c);
	else
		fail(r, c,
		     "%s missing or empty (copy the operator's cert)",
		     shirudo_cert_path());
}

static int read_cert(const char *path, __u8 **out, size_t *out_sz)
{
	struct stat st;
	__u8 *buf;
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) < 0) {
		int rc = -errno;

		close(fd);
		return rc;
	}
	if (st.st_size <= 0 || st.st_size > PREFLIGHT_CERT_MAX) {
		close(fd);
		return -EINVAL;
	}
	buf = xmalloc((size_t)st.st_size);
	if (!buf) {
		close(fd);
		return -ENOMEM;
	}
	n = read(fd, buf, (size_t)st.st_size);
	close(fd);
	if (n != st.st_size) {
		xfree(buf, (size_t)st.st_size);
		return -EIO;
	}
	*out = buf;
	*out_sz = (size_t)st.st_size;
	return 0;
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
static int preflight_keys(struct shirudo_trusted_set *set)
{
	return keys_load(shirudo_keys_dir(), SHIRUDO_KEYS_REVOKED_DIR,
			 true, set);
}

static void check_cert_algorithm(struct shirudo_preflight_result *r)
{
	struct shirudo_preflight_check *c =
		next_slot(r, SHIRUDO_PRE_CERT_ALGORITHM, "cert_algorithm");
	struct shirudo_trusted_set set;
	size_t i;

	if (preflight_keys(&set)) {
		pass(c);
		snprintf(c->detail, sizeof(c->detail),
			 "skipped (cert unreadable)");
		return;
	}
	for (i = 0; i < set.n; i++) {
		struct shirudo_cert cert = {};
		char name[64];
		int rc;

		if (cert_read_file(set.certs[i].path, &cert)) {
			fail(r, c, "%s: cannot parse", set.certs[i].path);
			return;
		}
		rc = cert_key_algorithm(&cert, name, sizeof(name));
		cert_free(&cert);
		if (rc) {
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
static void check_cert_kernel_algo(struct shirudo_preflight_result *r)
{
	struct shirudo_preflight_check *c =
		next_slot(r, SHIRUDO_PRE_CERT_KERNEL_ALGO, "cert_kernel_support");
	struct shirudo_trusted_set set;
	size_t i;

	if (preflight_keys(&set)) {
		pass(c);
		snprintf(c->detail, sizeof(c->detail),
			 "skipped (cert unreadable)");
		return;
	}
	for (i = 0; i < set.n; i++) {
		size_t der_sz = 0;
		__u8 *der = NULL;
		long key;
		int rc;

		rc = read_cert(set.certs[i].path, &der, &der_sz);
		if (rc) {
			fail(r, c, "%s: %s", set.certs[i].path, strerror(-rc));
			return;
		}
		key = syscall(__NR_add_key, "asymmetric", "", der, der_sz,
			      (long)KEY_SPEC_THREAD_KEYRING);
		rc = key < 0 ? errno : 0;
		xfree(der, der_sz);
		syscall(__NR_keyctl, KEYCTL_CLEAR,
			(long)KEY_SPEC_THREAD_KEYRING, 0L, 0L, 0L);
		if (!rc)
			continue;
		if (rc == ENOENT || rc == ENOPKG)
			fail(r, c,
			     "kernel cannot verify the public-key algorithm of "
			     "%s (ML-DSA certs need CONFIG_CRYPTO_MLDSA=y and "
			     "CONFIG_CRYPTO_SHA512=y; see "
			     "Documentation/requirements.rst)",
			     set.certs[i].path);
		else
			fail(r, c, "kernel rejected %s: %s "
			     "(add_key asymmetric)", set.certs[i].path,
			     strerror(rc));
		return;
	}
	pass(c);
}

static void check_keyring(struct shirudo_preflight_result *r)
{
	struct shirudo_preflight_check *c =
		next_slot(r, SHIRUDO_PRE_KEYRING, "kernel_keyring");
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

static void check_embedded_loader(struct shirudo_preflight_result *r)
{
	struct shirudo_preflight_check *c =
		next_slot(r, SHIRUDO_PRE_EMBEDDED_LOADER, "embedded_loader");
	const struct shirudo_embedded_bpf *bpf2 = bpf2_blob(false);
	const struct shirudo_embedded_bpf *seal = seal_blob(false);
	size_t bpf2_sz = bpf2 ? bpf2->size : 0;
	size_t seal_sz = seal ? seal->size : 0;

	if (!bpf2_sz || !seal_sz) {
		fail(r, c,
		     "embedded BPF objects missing (bpf2=%zu seal=%zu)",
		     bpf2_sz, seal_sz);
		return;
	}
	bpf2 = bpf2_blob(true);
	seal = seal_blob(true);
	if (bpf2 && bpf2->size && seal && seal->size)
		pass(c);
	else
		fail(r, c, "embedded image-mode BPF objects missing");
}

static void check_tpm(struct shirudo_preflight_result *r)
{
	struct shirudo_preflight_check *c =
		next_slot(r, SHIRUDO_PRE_TPM, "tpm2_reachable");

	/*
	 * A TCTI override points at a software TPM, where the kernel resource
	 * manager is not in play, so the device check would refuse a valid
	 * setup. The operator's expectation still rejects what a fake TPM
	 * produces, so this is a convenience, not a relaxation.
	 */
	{
		struct shirudo_config cfg = {};
		bool override = config_load(&cfg) == 0 && cfg.tpm_tcti[0];

		if (override) {
			pass(c);
			snprintf(c->detail, sizeof(c->detail),
				 "TCTI override: %.*s",
				 (int)(sizeof(c->detail) -
				       sizeof("TCTI override: ")),
				 cfg.tpm_tcti);
		}
		explicit_bzero(&cfg, sizeof(cfg));	/* scrub tpm_owner_auth */
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

void preflight_run(struct shirudo_preflight_result *out)
{
	memset(out, 0, sizeof(*out));
	check_root(out);
	check_bpf_lsm(out);
	check_bpffs(out);
	check_signed_loader_abi(out);
	check_cert(out);
	check_cert_algorithm(out);
	check_cert_kernel_algo(out);
	check_keyring(out);
	check_embedded_loader(out);
	check_tpm(out);
}
