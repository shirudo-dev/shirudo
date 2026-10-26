// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Bootstrap shirudo enforcement on a target.
 */

#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/magic.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>
#include <shirudo/upatch.h>

#include "builtin.h"
#include "util/bpm_tree.h"
#include "util/chain.h"
#include "util/config.h"
#include "util/eventlog.h"
#include "util/help.h"
#include "util/json.h"
#include "util/macros.h"
#include "util/identity.h"
#include "util/initrd.h"
#include "util/image_config.h"
#include "util/image_guards.h"
#include "util/image_runtime.h"
#include "util/keyring.h"
#include "util/keys.h"
#include "util/loader.h"
#include "util/log.h"
#include "util/malloc.h"
#include "util/nv_writer.h"
#include "util/paths.h"
#include "util/preflight.h"
#include "util/seal.h"
#include "util/tpm.h"
#include "util/upatch.h"
#include "util/upatch_resolve.h"

static void print_preflight(const struct shirudo_preflight_result *r)
{
	int i;

	printf("pre-flight checks:\n");
	for (i = 0; i < r->n; i++) {
		const struct shirudo_preflight_check *c = &r->checks[i];

		printf("  %-22s %s%s%s\n",
		       c->name,
		       c->ok ? "OK" : "FAIL",
		       c->detail[0] ? ": " : "",
		       c->detail);
	}
	printf("%d/%d passed (%d failed)\n",
	       r->n - r->n_failed, r->n, r->n_failed);
}

static int read_der(const char *path, __u8 **out, size_t *out_sz)
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
	if (st.st_size <= 0 || st.st_size > 1u * 1024u * 1024u) {
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

static void keyring_count_asymmetric(key_serial_t serial, const char *type,
				     const char *description, void *ud)
{
	size_t *n = ud;

	(void)serial;
	(void)description;
	if (strcmp(type, "asymmetric") == 0)
		(*n)++;
}

static int keyring_asymmetric_count(key_serial_t ring)
{
	size_t n = 0;
	int rc = keyring_list(ring, keyring_count_asymmetric, &n);

	if (rc)
		return rc;
	return (int)n;
}

static struct shirudo_trusted_set enrolled;

static bool initrd_mode;

static int keyring_holds_set(key_serial_t ring,
			     const struct shirudo_trusted_set *set)
{
	size_t i, held = 0;

	for (i = 0; i < set->n; i++) {
		size_t der_sz = 0;
		__u8 *der = NULL;
		int rc;

		rc = read_der(set->certs[i].path, &der, &der_sz);
		if (rc)
			return rc;
		rc = keyring_holds_cert(ring, der, der_sz);
		xfree(der, der_sz);
		if (rc < 0)
			return rc;
		held += rc;
	}
	return (int)held;
}

/*
 * The bpf keyring is the trust anchor a signed loader is verified
 * against once it is sealed. Booted with bpf.keyring_unsealed=1 it
 * takes keys until the first seal, which is init's job from the initrd:
 * enrol every trusted certificate and seal. Found sealed, it either
 * holds exactly that set (-EEXIST: use it) or was sealed empty by the
 * kernel at boot (-ENOKEY: initialization refuses until reboot with the
 * enrollment parameter); sealed around anything else, it is refused.
 */
static int init_bpf_keyring(key_serial_t ring,
			    const struct shirudo_trusted_set *set)
{
	int count, held, rc;
	size_t i;

	for (i = 0; i < set->n; i++) {
		size_t der_sz = 0;
		__u8 *der = NULL;
		key_serial_t key;

		rc = read_der(set->certs[i].path, &der, &der_sz);
		if (rc) {
			pr_err("read %s: %s", set->certs[i].path,
			       strerror(-rc));
			return rc;
		}
		key = keyring_bpf_add_cert(der, der_sz);
		xfree(der, der_sz);
		if (key >= 0) {
			pr_info("bpf keyring serial=%d: %s enrolled (key "
				"serial=%d)", (int)ring, set->certs[i].path,
				(int)key);
			continue;
		}
		if (key != -EPERM && key != -EACCES) {
			pr_err("bpf keyring: add %s: %s", set->certs[i].path,
			       strerror(-key));
			if (key == -ENOENT || key == -ENOPKG)
				pr_err("kernel cannot verify this cert's "
				       "public-key algorithm (ML-DSA needs "
				       "CONFIG_CRYPTO_MLDSA=y and "
				       "CONFIG_CRYPTO_SHA512=y; see "
				       "Documentation/requirements.rst)");
			return key;
		}
		if (i > 0) {
			pr_err("bpf keyring serial=%d was sealed while init "
			       "enrolled the certificates (tampered)",
			       (int)ring);
			return -EKEYREJECTED;
		}
		/* Sealed before init: by init earlier this boot, or not. */
		held = keyring_holds_set(ring, set);
		if (held < 0) {
			pr_err("bpf keyring: compare: %s", strerror(-held));
			return held;
		}
		count = keyring_asymmetric_count(ring);
		if (count < 0) {
			pr_err("bpf keyring: list: %s", strerror(-count));
			return count;
		}
		if (count == 0)
			return -ENOKEY;
		if ((size_t)held == set->n && (size_t)count == set->n) {
			pr_info("bpf keyring serial=%d: already holds the %zu "
				"trusted certificate%s, sealed this boot",
				(int)ring, set->n, set->n == 1 ? "" : "s");
			return -EEXIST;
		}
		pr_err("bpf keyring serial=%d is sealed around %d key%s, "
		       "%d of the %zu trusted certificates (tampered)",
		       (int)ring, count, count == 1 ? "" : "s", held, set->n);
		return -EKEYREJECTED;
	}
	rc = keyring_bpf_seal();
	if (rc) {
		pr_err("bpf keyring: certificates enrolled but the keyring "
		       "could not be sealed: %s", strerror(-rc));
		return rc;
	}
	pr_info("bpf keyring serial=%d: %zu certificate%s enrolled and sealed",
		(int)ring, set->n, set->n == 1 ? "" : "s");
	return 0;
}

static int init_keyring(void)
{
	struct shirudo_trusted_set set;
	struct shirudo_identity id;
	key_serial_t ring;
	int rc;

	ring = keyring_bpf_serial();
	if (ring <= 0) {
		rc = ring ? ring : -ENOKEY;
		pr_err("bpf keyring lookup: %s", strerror(-rc));
		return rc;
	}
	if (!identity_read(&id)) {
		if (id.keyring_type != SHIRUDO_SIG_KEYRING_BPF ||
		    id.keyring_serial != ring ||
		    memcmp(id.runtime_root, shirudo_image_runtime_root(), 32))
			return -EKEYREJECTED;
		return 0;
	}
	rc = shirudo_image_boot_keys(&set);
	if (rc)
		return rc;
	rc = init_bpf_keyring(ring, &set);
	if (rc && rc != -EEXIST)
		return rc;
	enrolled = set;
	return 0;
}

static int is_bpffs_mounted(const char *path)
{
	FILE *f = fopen("/proc/self/mounts", "r");
	char line[4096];
	int found = 0;

	if (!f)
		return -errno;
	while (fgets(line, sizeof(line), f)) {
		char src[256], target[256], type[256];

		if (sscanf(line, "%255s %255s %255s",
			   src, target, type) != 3)
			continue;
		if (strcmp(target, path) == 0 && strcmp(type, "bpf") == 0) {
			found = 1;
			break;
		}
	}
	fclose(f);
	return found;
}

static int init_bpffs(void)
{
	struct stat parent, run;
	int rc;

	rc = seal_mkdir_p(SHIRUDO_VAR_LIB, 0700);
	if (rc) {
		pr_err("mkdir %s: %s", SHIRUDO_VAR_LIB, strerror(-rc));
		return rc;
	}
	rc = seal_mkdir_p(SHIRUDO_RUN_DIR, 0700);
	if (rc) {
		pr_err("mkdir %s: %s", SHIRUDO_RUN_DIR, strerror(-rc));
		return rc;
	}
	rc = is_bpffs_mounted(SHIRUDO_BPFFS_DIR);
	if (rc < 0)
		return rc;
	if (rc)
		return 0;
	if (stat(SHIRUDO_RUN_DIR, &parent) || stat("/run", &run))
		return -errno;
	if (parent.st_dev == run.st_dev) {
		rc = seal_label(SHIRUDO_RUN_DIR);
		if (rc)
			return rc;
		if (mount("tmpfs", SHIRUDO_RUN_DIR, "tmpfs",
			  MS_NOSUID | MS_NODEV | MS_NOEXEC,
			  "mode=0700,size=16M"))
			return -errno;
	}
	if (mount(NULL, SHIRUDO_RUN_DIR, NULL,
		  MS_PRIVATE | MS_REC, NULL))
		return -errno;

	/* So that the init record left here is sealed from its creation. */
	rc = seal_label(SHIRUDO_RUN_DIR);
	if (rc)
		return rc;
	rc = seal_mkdir_p(SHIRUDO_BPFFS_DIR, 0700);
	if (rc) {
		pr_err("mkdir %s: %s",
		       SHIRUDO_BPFFS_DIR, strerror(-rc));
		return rc;
	}

	rc = is_bpffs_mounted(SHIRUDO_BPFFS_DIR);
	if (rc < 0) {
		pr_err("read /proc/self/mounts: %s", strerror(-rc));
		return rc;
	}
	if (rc) {
		pr_info("bpffs already mounted at %s", SHIRUDO_BPFFS_DIR);
		return 0;
	}

	if (mount("bpf", SHIRUDO_BPFFS_DIR, "bpf",
		  MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=0700") != 0) {
		pr_err("mount bpffs at %s: %s",
		       SHIRUDO_BPFFS_DIR, strerror(errno));
		return -errno;
	}

	pr_info("mounted private bpffs at %s "
		"(mode=0700,nosuid,nodev,noexec)", SHIRUDO_BPFFS_DIR);
	return 0;
}

/* The BPF side compares s_dev in the kernel's encoding, not glibc's. */
static __u32 kernel_dev_t(dev_t st_dev)
{
	return ((__u32)major(st_dev) << 20) | (minor(st_dev) & 0xfffffu);
}

static int attach_pin(struct bpf_program *p, const char *pin,
		      struct bpf_link **out)
{
	struct bpf_link *l;
	int err;

	*out = NULL;
	l = bpf_program__attach(p);
	err = libbpf_get_error(l);
	if (err)
		return err;
	if (bpf_link__pin(l, pin) != 0) {
		err = -errno;
		bpf_link__destroy(l);
		return err;
	}
	*out = l;
	return 0;
}

static struct bpf_program *guard_program(struct bpf_object *object,
					 enum shirudo_gate_guard guard)
{
	const struct shirudo_image_guard *entry = &shirudo_gate_guards[guard];

	return bpf_object__find_program_by_name(object, entry->prog);
}

static int attach_guard(struct bpf_program *program,
			enum shirudo_gate_guard guard, struct bpf_link **link)
{
	return attach_pin(program, shirudo_gate_guards[guard].pin, link);
}

/* The admission and seal objects share bootstrap state and task marks. */
static int share_policy_maps(struct bpf_object *source,
			     struct bpf_object *destination)
{
	struct bpf_map *from, *to;
	size_t i;
	int rc;

	for (i = 0; i < ARRAY_SIZE(shirudo_guard_maps); i++) {
		from = bpf_object__find_map_by_name(source,
						    shirudo_guard_maps[i].name);
		to = bpf_object__find_map_by_name(destination,
						  shirudo_guard_maps[i].name);
		if (!from || !to)
			return -ENOENT;
		rc = bpf_map__reuse_fd(to, bpf_map__fd(from));
		if (rc)
			return rc;
	}
	return 0;
}

/* Attach in order. The caller owns each pinned link, including on failure. */
static int attach_guard_group(struct bpf_object *obj,
			      const struct shirudo_image_guard *guards,
			      size_t count, struct bpf_link **links)
{
	struct bpf_program *program;
	size_t i;
	int rc;

	for (i = 0; i < count; i++) {
		program = bpf_object__find_program_by_name(obj, guards[i].prog);
		if (!program) {
			pr_err("program %s missing", guards[i].prog);
			return -ENOENT;
		}
		rc = attach_pin(program, guards[i].pin, &links[i]);
		if (rc) {
			pr_err("attach %s: %s", guards[i].prog, strerror(-rc));
			return rc;
		}
	}
	return 0;
}

/* Writable state and runtime processes always get the full seal. */
static int attach_seal(struct bpf_object *policy, struct bpf_object **obj_out,
		       struct bpf_link **links, struct bpf_link **image_links)
{
	const struct shirudo_embedded_bpf *blob = seal_blob();
	struct bpf_object *obj;
	int err;

	*obj_out = NULL;
	if (!blob || !blob->data || !blob->size) {
		pr_err("embedded seal blob missing");
		return -ENOENT;
	}
	obj = bpf_object__open_mem(blob->data, blob->size, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		pr_err("seal: bpf_object__open_mem: %d", err);
		return err;
	}
	err = share_policy_maps(policy, obj);
	if (!err)
		err = bpf_object__load(obj);
	if (!err) {
		struct bpf_map *scratch;

		scratch = bpf_object__find_map_by_name(obj, "seal_scratch_map");
		err = scratch ? bpf_map_freeze(bpf_map__fd(scratch)) : -ENOENT;
	}
	if (err) {
		pr_err("seal: bpf_object__load: %d", err);
		bpf_object__close(obj);
		return err;
	}
	err = attach_guard_group(obj, shirudo_seal_guards,
				 ARRAY_SIZE(shirudo_seal_guards), links);
	if (!err)
		err = attach_guard_group(obj, shirudo_image_seal_guards,
					 ARRAY_SIZE(shirudo_image_seal_guards),
					 image_links);
	if (err) {
		bpf_object__close(obj);
		return err;
	}
	*obj_out = obj;
	return 0;
}

_Static_assert(SHIRUDO_IDENTITY_KEYS_MAX == SHIRUDO_KEYS_MAX,
	       "the identity map holds one serial per trusted certificate");

struct anchor_keys {
	__s32	serials[SHIRUDO_IDENTITY_KEYS_MAX];
	size_t	n;
	bool	overflow;
};

static void collect_asymmetric(key_serial_t serial, const char *type,
			       const char *description, void *ud)
{
	struct anchor_keys *k = ud;

	(void)description;
	if (strcmp(type, "asymmetric"))
		return;
	if (k->n >= ARRAY_SIZE(k->serials)) {
		k->overflow = true;
		return;
	}
	k->serials[k->n++] = (__s32)serial;
}

/* Seed bootstrap and freeze shared state except the expected config root. */
static int freeze_task_maps(struct bpf_object *obj)
{
	struct shirudo_task_authority authority = {
		.trusted = SHIRUDO_TASK_BOOTSTRAP,
	};
	struct bpf_map *map;
	int fd, pidfd, rc = 0;
	__u32 i;

	pidfd = syscall(SYS_pidfd_open, getpid(), 0);
	if (pidfd < 0)
		return -errno;
	for (i = SHIRUDO_GUARD_TASKS; i < SHIRUDO_GUARD_MAP_COUNT; i++) {
		const struct shirudo_guard_map *expected =
			&shirudo_guard_maps[i];

		map = bpf_object__find_map_by_name(obj, expected->name);
		if (!map) {
			rc = -ENOENT;
			break;
		}
		fd = bpf_map__fd(map);
		if (i == SHIRUDO_GUARD_TASKS &&
		    bpf_map_update_elem(fd, &pidfd, &authority, BPF_ANY)) {
			rc = -errno;
			break;
		}
		/* Expected roots change for each mapping. */
		if ((i != SHIRUDO_GUARD_ROOTS && bpf_map_freeze(fd)) ||
		    bpf_obj_pin(fd, expected->pin)) {
			rc = -errno;
			break;
		}
	}
	close(pidfd);
	return rc;
}

static int init_lsm(void)
{
	struct bpf_link *image_links[SHIRUDO_IMAGE_OBSERVER_HOOK_COUNT] = {};
	struct bpf_link *image_seal[SHIRUDO_IMAGE_SEAL_HOOK_COUNT] = {};
	struct bpf_link *link_setx = NULL, *link_rmx = NULL, *link_pload = NULL;
	struct bpf_link *identity_links[ARRAY_SIZE(shirudo_observer_guards)] = {};
	struct bpf_link *mount_links[ARRAY_SIZE(shirudo_mount_guards)] = {};
	struct bpf_program *p_bpf, *p_bpf_map, *p_unlink, *p_setx, *p_rmx;
	const struct shirudo_embedded_bpf *blob = bpf2_blob();
	struct bpf_link *seal_links[SHIRUDO_SEAL_HOOK_COUNT] = {};
	struct bpf_link *link_bpf = NULL, *link_bpf_map = NULL;
	struct bpf_object *obj = NULL, *seal_obj = NULL;
	struct bpf_link *link_keyperm = NULL;
	struct bpf_link *link_unlink = NULL;
	struct shirudo_identity id = {};
	struct anchor_keys keys = {};
	struct bpf_program *p_pload;
	struct bpf_program *p_key;
	key_serial_t keyring;
	struct bpf_map *m_sb;
	int err, map_fd, i;
	__u32 zero = 0;
	struct stat st;

	if (access(shirudo_gate_guards[SHIRUDO_GUARD_BPF].pin, F_OK) == 0) {
		err = identity_read(&id);
		if (err || id.nv_writer_ring <= 0 ||
		    id.nv_writer_key <= 0 ||
		    access(SHIRUDO_KEY_PERMISSION_LINK_PIN, F_OK)) {
			pr_err("init: NV writer protection missing; reboot "
			       "with the updated initrd");
			return err ? err : -EACCES;
		}
		pr_info("bpf2 already attached (%s exists)",
			shirudo_gate_guards[SHIRUDO_GUARD_BPF].pin);
		return 0;
	}
	/* A pin without the links behind it is what a failed attempt leaves. */
	if (unlink(SHIRUDO_IDENTITY_PIN) != 0 && errno != ENOENT) {
		pr_err("unlink stale %s: %s", SHIRUDO_IDENTITY_PIN,
		       strerror(errno));
		return -errno;
	}
	if (unlink(SHIRUDO_TAMPER_PIN) != 0 && errno != ENOENT) {
		pr_err("unlink stale %s: %s", SHIRUDO_TAMPER_PIN,
		       strerror(errno));
		return -errno;
	}

	if (!blob || !blob->data || !blob->size) {
		pr_err("embedded bpf2 blob missing");
		return -ENOENT;
	}

	obj = bpf_object__open_mem(blob->data, blob->size, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		pr_err("bpf_object__open_mem: %d", err);
		return err;
	}

	err = bpf_object__load(obj);
	if (err) {
		pr_err("bpf_object__load: %d", err);
		goto out;
	}

	if (stat(SHIRUDO_BPFFS_DIR, &st) != 0) {
		err = -errno;
		pr_err("stat %s: %s", SHIRUDO_BPFFS_DIR, strerror(errno));
		goto out;
	}
	id.sb_dev = kernel_dev_t(st.st_dev);
	if (stat(SHIRUDO_RUN_DIR, &st)) {
		err = -errno;
		goto out;
	}
	id.run_dev = kernel_dev_t(st.st_dev);

	memcpy(id.runtime_root, shirudo_image_runtime_root(), 32);

	/*
	 * The trust anchor lsm/bpf_prog_load enforces: only a load the
	 * kernel verified against exactly this sealed keyring, of exactly
	 * this kind, is admitted from userspace. init_keyring has already
	 * enrolled the cert and sealed the keyring, so this resolves the
	 * serial the kernel records for a load that names it as keyring_id.
	 */
	keyring = keyring_bpf_serial();
	id.keyring_type = SHIRUDO_SIG_KEYRING_BPF;
	if (keyring <= 0) {
		err = keyring ? keyring : -ENOKEY;
		pr_err("resolve the bpf keyring serial: %s", strerror(-err));
		goto out;
	}
	id.keyring_serial = (__s32)keyring;

	/*
	 * The keys that keyring holds, for lsm/key_permission: with the
	 * keyring itself, what no task but shirudo may write, unlink,
	 * revoke or invalidate for the rest of the boot.
	 */
	err = keyring_list(keyring, collect_asymmetric, &keys);
	if (err) {
		pr_err("list the anchor keyring %d: %s", (int)keyring,
		       strerror(-err));
		goto out;
	}
	if (keys.overflow || keys.n == 0) {
		pr_err("anchor keyring %d holds %s asymmetric keys",
		       (int)keyring, keys.overflow ? "too many" : "no");
		err = keys.overflow ? -E2BIG : -ENOKEY;
		goto out;
	}
	id.n_keys = (__u32)keys.n;
	memcpy(id.key_serials, keys.serials, keys.n * sizeof(keys.serials[0]));
	err = nv_writer_create(&id.nv_writer_ring, &id.nv_writer_key, id.nv_writer_public);
	if (err) {
		pr_err("init: create RSA-3072 NV writer: %s "
		       "(requires kernel PKCS#8 private-key and RSA support)",
		       strerror(-err));
		goto out;
	}

	m_sb = bpf_object__find_map_by_name(obj, "shirudo_bpffs_sb");
	if (!m_sb) {
		pr_err("shirudo_bpffs_sb map not in embedded bpf2");
		err = -ENOENT;
		goto out;
	}
	map_fd = bpf_map__fd(m_sb);
	if (bpf_map_update_elem(map_fd, &zero, &id, BPF_ANY) != 0) {
		err = -errno;
		pr_err("populate sb-identity map: %s", strerror(errno));
		goto out;
	}
	if (bpf_map_freeze(map_fd) != 0) {
		err = -errno;
		pr_err("freeze sb-identity map: %s", strerror(errno));
		goto out;
	}
	err = freeze_task_maps(obj);
	if (err)
		goto out;
	/*
	 * Pinned so that every later command reads the anchor init froze
	 * from the kernel rather than from a file: the serial a load names
	 * and status reports is the one lsm/bpf_prog_load enforces.
	 */
	if (bpf_obj_pin(map_fd, SHIRUDO_IDENTITY_PIN) != 0) {
		err = -errno;
		pr_err("pin identity map at %s: %s", SHIRUDO_IDENTITY_PIN,
		       strerror(errno));
		goto out;
	}

	/* The executable-identity guard precedes every BPF admission gate. */
	err = attach_guard_group(obj, shirudo_observer_guards,
				 ARRAY_SIZE(shirudo_observer_guards),
				 identity_links);
	if (!err)
		err = attach_guard_group(obj, shirudo_image_observer_guards,
					 SHIRUDO_IMAGE_OBSERVER_HOOK_COUNT,
					 image_links);
	if (err)
		goto out;

	p_unlink = guard_program(obj, SHIRUDO_GUARD_UNLINK);
	p_setx = guard_program(obj, SHIRUDO_GUARD_SETXATTR);
	p_rmx = guard_program(obj, SHIRUDO_GUARD_REMOVEXATTR);
	p_pload = guard_program(obj, SHIRUDO_GUARD_PROG_LOAD);
	p_bpf_map = guard_program(obj, SHIRUDO_GUARD_BPF_MAP);
	p_key = guard_program(obj, SHIRUDO_GUARD_KEY_PERMISSION);
	p_bpf = guard_program(obj, SHIRUDO_GUARD_BPF);
	if (!p_unlink || !p_setx || !p_rmx || !p_pload || !p_bpf_map ||
	    !p_bpf ||
	    !p_key) {
		pr_err("expected programs missing in bpf2 object");
		err = -ENOENT;
		goto out;
	}

	/*
	 * The prctl identity guard is already active. Order the remaining
	 * hooks as bpffs guards, seal's filesystem and exec-identity hooks,
	 * then the bpf() gates (map fd access, bpf_prog_load admission, then
	 * lsm/bpf) LAST.
	 * Pinning a link creates a bpffs inode, gated by neither guard set;
	 * seal's unsigned load and the identity-map freeze precede the gates.
	 */
	err = attach_guard(p_unlink, SHIRUDO_GUARD_UNLINK, &link_unlink);
	if (err) {
		pr_err("attach lsm/inode_unlink: %s", strerror(-err));
		goto out;
	}
	err = attach_guard(p_setx, SHIRUDO_GUARD_SETXATTR, &link_setx);
	if (err) {
		pr_err("attach lsm/inode_setxattr: %s", strerror(-err));
		goto out;
	}
	err = attach_guard(p_rmx, SHIRUDO_GUARD_REMOVEXATTR, &link_rmx);
	if (err) {
		pr_err("attach lsm/inode_removexattr: %s", strerror(-err));
		goto out;
	}
	err = attach_guard(p_key, SHIRUDO_GUARD_KEY_PERMISSION, &link_keyperm);
	if (err) {
		pr_err("attach lsm/key_permission: %s", strerror(-err));
		goto out;
	}
	/*
	 * With the other bpffs guards, so the mount is immutable before
	 * enforcement goes live.
	 */
	err = attach_guard_group(obj, shirudo_mount_guards,
				 ARRAY_SIZE(shirudo_mount_guards), mount_links);
	if (err)
		goto out;

	err = attach_seal(obj, &seal_obj, seal_links, image_seal);
	if (err)
		goto out;

	err = attach_guard(p_bpf_map, SHIRUDO_GUARD_BPF_MAP, &link_bpf_map);
	if (err) {
		pr_err("attach lsm/bpf_map: %s", strerror(-err));
		goto out;
	}

	err = attach_guard(p_pload, SHIRUDO_GUARD_PROG_LOAD, &link_pload);
	if (err) {
		pr_err("attach lsm/bpf_prog_load: %s", strerror(-err));
		goto out;
	}

	err = attach_guard(p_bpf, SHIRUDO_GUARD_BPF, &link_bpf);
	if (err) {
		pr_err("attach lsm/bpf: %s", strerror(-err));
		goto out;
	}

	pr_info("%s + seal attached: lsm/bpf gate live, writable state sealed",
		blob->name);
	err = 0;
out:
	for (i = 0; i < (int)ARRAY_SIZE(image_seal); i++) {
		if (err && image_seal[i])
			bpf_link__unpin(image_seal[i]);
		bpf_link__destroy(image_seal[i]);
	}
	for (i = 0; i < (int)ARRAY_SIZE(image_links); i++) {
		if (err && image_links[i])
			bpf_link__unpin(image_links[i]);
		bpf_link__destroy(image_links[i]);
	}
	for (i = 0; i < (int)ARRAY_SIZE(identity_links); i++) {
		if (err && identity_links[i])
			bpf_link__unpin(identity_links[i]);
		bpf_link__destroy(identity_links[i]);
	}
	for (i = 0; i < (int)ARRAY_SIZE(seal_links); i++) {
		if (err && seal_links[i])
			bpf_link__unpin(seal_links[i]);
		bpf_link__destroy(seal_links[i]);
	}
	for (i = 0; i < (int)ARRAY_SIZE(mount_links); i++) {
		if (err && mount_links[i])
			bpf_link__unpin(mount_links[i]);
		bpf_link__destroy(mount_links[i]);
	}
	if (err) {
		struct bpf_link *links[] = {
			link_bpf, link_bpf_map, link_pload, link_keyperm,
			link_rmx, link_setx, link_unlink,
		};

		for (i = 0; i < (int)ARRAY_SIZE(links); i++)
			if (links[i])
				bpf_link__unpin(links[i]);
		(void)unlink(SHIRUDO_IDENTITY_PIN);
		(void)unlink(SHIRUDO_TAMPER_PIN);
		(void)unlink(SHIRUDO_BPFFS_DIR "/task_authority");
		(void)unlink(SHIRUDO_BPFFS_DIR "/devices");
		(void)unlink(SHIRUDO_BPFFS_DIR "/config_roots");
	}
	bpf_object__close(seal_obj);
	bpf_link__destroy(link_bpf);
	bpf_link__destroy(link_bpf_map);
	bpf_link__destroy(link_pload);
	bpf_link__destroy(link_keyperm);
	bpf_link__destroy(link_rmx);
	bpf_link__destroy(link_setx);
	bpf_link__destroy(link_unlink);
	bpf_object__close(obj);
	return err;
}

#define HEXLEN(n)	((n) * 2 + 1)

/*
 * All or nothing: one failure leaves init incomplete and the register
 * unextended. On a re-run an upatch already pinned this boot with the
 * archived payload is counted and left alone; loading it again would
 * only attach a second link to fail at the pin. Once this boot's init
 * event is on record the restore has happened and the register covers
 * what it loaded, so an archived artifact that is not loaded cannot be
 * applied any more: nothing would measure it. It was renamed into the
 * archive since, or left behind by an unload cut short, and either is
 * for the operator to resolve.
 */
static int boot_restore(bool recorded,
			struct shirudo_measured_upatch **out_set, size_t *out_n)
{
	struct shirudo_measured_upatch *set = NULL;
	struct dirent **names = NULL;
	int n, i, rc = 0;
	size_t cnt = 0;

	*out_set = NULL;
	*out_n = 0;

	n = scandir(SHIRUDO_UPATCHES_DIR, &names, upatch_select,
		    alphasort);
	if (n < 0) {
		if (errno == ENOENT)
			return 0;
		pr_err("boot-restore: scandir %s: %s",
		       SHIRUDO_UPATCHES_DIR, strerror(errno));
		return -errno;
	}
	if (n == 0) {
		libc_free(names);
		return 0;
	}

	set = xcalloc((size_t)n, sizeof(*set));
	if (!set) {
		for (i = 0; i < n; i++)
			libc_free(names[i]);
		libc_free(names);
		return -ENOMEM;
	}

	pr_info("boot-restore: re-applying %d upatch%s from %s",
		n, n == 1 ? "" : "es", SHIRUDO_UPATCHES_DIR);

	for (i = 0; i < n; i++) {
		char pinned_hex[2 * SHIRUDO_UPATCH_PAYLOAD_HASH_LEN + 1];
		char path[PATH_MAX];
		struct shirudo_upatch u;
		int fd;

		if (rc)
			goto next;
		if (strsprintf(path, sizeof(path), "%s/%s", SHIRUDO_UPATCHES_DIR,
			       names[i]->d_name) < 0) {
			pr_err("boot-restore: path too long: %s",
			       names[i]->d_name);
			rc = -ENAMETOOLONG;
			goto next;
		}
		if (!seal_owns(path)) {
			pr_warn("boot-restore: %s is not shirudo's own "
				"(foreign entry); ignored", names[i]->d_name);
			goto next;
		}
		if (upatch_open(path, &u) != 0) {
			pr_warn("boot-restore: %s is not an artifact shirudo "
				"archived (foreign entry); ignored",
				names[i]->d_name);
			goto next;
		}
		memcpy(set[cnt].name, u.hdr.name, SHIRUDO_UPATCH_NAME_MAX);
		set[cnt].name[SHIRUDO_UPATCH_NAME_MAX] = '\0';
		hex_encode(u.hdr.payload_sha256, SHIRUDO_UPATCH_PAYLOAD_HASH_LEN,
			   set[cnt].payload_hex);
		upatch_close(&u);
		fd = upatch_open_first_link(set[cnt].name);
		if (fd >= 0) {
			close(fd);
			upatch_payload_sha256(set[cnt].name, pinned_hex,
					      sizeof(pinned_hex));
			if (strcmp(pinned_hex, set[cnt].payload_hex) != 0) {
				pr_err("boot-restore: %s is loaded with a "
				       "payload other than the archived one "
				       "(tampered)", set[cnt].name);
				rc = -EINVAL;
				goto next;
			}
			pr_info("boot-restore: %s already loaded",
				set[cnt].name);
			cnt++;
			goto next;
		}
		if (recorded) {
			pr_err("boot-restore: %s is archived but not loaded "
			       "after the register was bound this boot "
			       "(tampered); unload it or reboot",
			       names[i]->d_name);
			rc = -EPERM;
			goto next;
		}
		if (shirudo_upatch_apply(path) != 0) {
			pr_err("boot-restore: failed to apply %s",
			       names[i]->d_name);
			rc = -EINVAL;
			goto next;
		}
		cnt++;
next:
		libc_free(names[i]);
	}
	libc_free(names);

	if (rc) {
		xfree(set, (size_t)n * sizeof(*set));
		return rc;
	}

	*out_set = set;
	*out_n = cnt;
	pr_info("boot-restore: %zu upatch%s re-applied", cnt,
		cnt == 1 ? "" : "es");
	return 0;
}

/* The binding a verifier needs to recompute the register's public area. */
static int append_init_event(const struct shirudo_measured_upatch *set,
			     size_t n,
			     const __u8 cert_sha[32],
			     const __u8 set_digest[32],
			     const __u8 tree_root[32],
			     const __u8 init_digest[32],
			     const struct shirudo_chain_init_info *info)
{
	char writer_hex[HEXLEN(SHIRUDO_TPM_NV_RSA_BYTES)];
	char buf[64 * 1024];
	struct shirudo_json_emit e = { .buf = buf, .cap = sizeof(buf) };
	char cert_hex[HEXLEN(32)], set_hex[HEXLEN(32)], digest_hex[HEXLEN(32)];
	char pcr_hex[HEXLEN(32)], anchor_hex[HEXLEN(32)], chain_hex[HEXLEN(32)];
	char phase_hex[HEXLEN(32)];
	char name_hex[HEXLEN(SHIRUDO_TPM_NAME_LEN)], tree_hex[HEXLEN(32)];
	char ts[32], boot_id[64], nv_index[16];
	size_t i;

	eventlog_timestamp(ts, sizeof(ts));
	eventlog_boot_id(boot_id, sizeof(boot_id));
	if (strsprintf(nv_index, sizeof(nv_index), "0x%08X",
		       SHIRUDO_NV_INDEX) < 0)
		return -E2BIG;
	hex_encode(cert_sha, 32, cert_hex);
	hex_encode(set_digest, 32, set_hex);
	hex_encode(tree_root, 32, tree_hex);
	hex_encode(init_digest, 32, digest_hex);
	hex_encode(info->pcr_before, 32, pcr_hex);
	hex_encode(info->phase_before, 32, phase_hex);
	hex_encode(info->name, SHIRUDO_TPM_NAME_LEN, name_hex);
	hex_encode(info->anchor_digest, 32, anchor_hex);
	hex_encode(info->value, 32, chain_hex);
	hex_encode(info->writer_public, sizeof(info->writer_public), writer_hex);

	json_obj_open(&e);
	json_kv_int(&e, "schema", 2);
	json_kv_string(&e, "ts", ts);
	json_kv_string(&e, "nv_index", nv_index);
	json_kv_string(&e, "alg", "sha256");
	json_kv_string(&e, "digest", digest_hex);
	json_kv_string(&e, "type", "init");
	json_kv_string(&e, "boot_id", boot_id);
	json_kv_int(&e, "tpm_reset_count", info->reset_count);
	json_kv_string(&e, "cert_sha256", cert_hex);
	json_arr_open(&e, "certs");
	for (i = 0; i < enrolled.n; i++) {
		char sha_hex[HEXLEN(32)];

		hex_encode(enrolled.certs[i].sha256, 32, sha_hex);
		json_str(&e, sha_hex);
	}
	json_arr_close(&e);
	json_kv_string(&e, "set_digest", set_hex);
	json_kv_string(&e, "tree_root", tree_hex);
	json_arr_open(&e, "set");
	for (i = 0; i < n; i++) {
		json_obj_open(&e);
		json_kv_string(&e, "name", set[i].name);
		json_kv_string(&e, "payload_sha256",
			       set[i].payload_hex);
		json_obj_close(&e);
	}
	json_arr_close(&e);
	json_kv_int(&e, "pcr", SHIRUDO_CHAIN_PCR);
	json_kv_string(&e, "pcr_before", pcr_hex);
	json_kv_int(&e, "phase_pcr", SHIRUDO_CHAIN_PHASE_PCR);
	json_kv_string(&e, "phase_before", phase_hex);
	json_kv_string(&e, "bound_in",
		       info->initrd ? "initrd" : "root");
	json_kv_string(&e, "nv_name", name_hex);
	json_kv_string(&e, "nv_writer_public", writer_hex);
	json_kv_string(&e, "anchor", info->anchor);
	json_kv_string(&e, "anchor_digest", anchor_hex);
	json_kv_string(&e, "chain", chain_hex);
	json_obj_close(&e);

	if (e.err) {
		pr_err("eventlog: init entry encode failed: %s",
		       strerror(-e.err));
		return e.err;
	}
	/*
	 * From the initrd the record waits under /run for the root file
	 * system's init: the eventlog is on a root that is read-only here.
	 */
	return eventlog_append_to(initrd_mode ?
				  eventlog_pending_path() :
				  eventlog_path(), buf);
}

static bool phase_unmeasured(const __u8 pcr[32])
{
	int i;

	for (i = 0; i < 32; i++) {
		if (pcr[i])
			return false;
	}
	return true;
}

static void tree_root_at_boot(__u8 out[32])
{
	struct shirudo_tree_state s = {};

	memset(out, 0, 32);
	if (tree_state_read(&s) == 0 &&
	    hex_decode(s.projection_root, out, 32) != 0)
		memset(out, 0, 32);
}

/*
 * Bind this boot's register and extend it by one "init" event covering
 * the restored set, then append the matching eventlog entry. One
 * extension per boot regardless of upatch count (architecture.rst,
 * boot restore); a re-run of init finds the register written and on
 * record and leaves it alone. The register is mandatory: a TPM that
 * cannot be opened or an index that cannot be bound is a hard error
 * (category tpm_error), never an unmeasured init, because an
 * unmeasured target is indistinguishable from a tampered one.
 */
static int chain_extend_init(struct shirudo_measured_upatch *set, size_t n)
{
	__u8 cert_sha[32], set_digest[32], tree_root[32], init_digest[32];
	struct shirudo_chain_init_info info;
	int rc;

	{
		struct shirudo_config cfg;
		__u64 max_bytes;
		bool full;

		config_load(&cfg);
		max_bytes = cfg.eventlog_max_bytes;
		full = eventlog_would_exceed(max_bytes);
		explicit_bzero(&cfg, sizeof(cfg));
		if (full) {
			pr_err("eventlog %s would exceed eventlog.max_bytes=%llu; "
			       "refusing chain extend (eventlog_full)",
			       eventlog_path(), max_bytes);
			return -ENOSPC;
		}
	}

	if (!enrolled.n) {
		pr_err("chain: no certificate enrolled");
		return -ENOENT;
	}
	keys_set_digest(&enrolled, cert_sha);

	/*
	 * init_event = SHA256("shirudo-init\0" || cert_sha256 || set_digest
	 *                     || tree_root), the formula the operator's
	 * predictor shares (util/attest.c).
	 */
	tree_root_at_boot(tree_root);
	chain_init_event(cert_sha, set, n, tree_root, set_digest,
			 init_digest);

	rc = chain_init(init_digest, &info);
	if (rc == -ENODEV) {
		pr_err("tpm: not usable; shirudo requires a TPM 2.0 "
		       "(tpm_error)");
		return rc;
	}
	if (rc == -EEXIST) {
		pr_err("tpm: the register this boot recorded is gone or "
		       "replaced; refusing to bind another before the next "
		       "TPM reset (tampered)");
		return rc;
	}
	if (rc == -EACCES) {
		pr_err("tpm: register 0x%08X cannot be bound (tpm_error); on "
		       "a TPM with owner auth set, supply it via "
		       "tpm.owner_auth in /etc/shirudo/shirudo.conf or "
		       "SHIRUDO_TPM_OWNER_AUTH", SHIRUDO_NV_INDEX);
		return rc;
	}
	if (rc) {
		pr_err("tpm: register extend failed -- chain NOT advanced "
		       "while LSM active (tpm_error); operator must "
		       "reconcile");
		return rc;
	}
	if (info.reused) {
		pr_info("tpm: register already bound this boot; chain "
			"unchanged (index 0x%08X)", SHIRUDO_NV_INDEX);
		return 0;
	}

	rc = append_init_event(set, n, cert_sha, set_digest, tree_root,
			       init_digest, &info);
	if (rc) {
		pr_err("eventlog: append failed after extend -- chain/log "
		       "desync; operator must reconcile");
		return rc;
	}

	pr_info("tpm: register bound in the %s and extended (index 0x%08X, "
		"PCR %u anchored, %zu upatch%s in set)",
		info.initrd ? "initrd" : "root file system", SHIRUDO_NV_INDEX,
		SHIRUDO_CHAIN_PCR, n, n == 1 ? "" : "es");
	if (!info.initrd)
		pr_warn("tpm: init ran after the initrd; the register's binding "
			"can be told from an initrd one by PCR %u",
			SHIRUDO_CHAIN_PHASE_PCR);
	else if (phase_unmeasured(info.phase_before))
		pr_warn("tpm: PCR %u holds no phase measurement; systemd "
			"measures enter-initrd only for a measured UKI boot, so "
			"a verifier cannot pin this binding to the initrd by it",
			SHIRUDO_CHAIN_PHASE_PCR);
	return 0;
}

static const struct shirudo_help_item init_options[] = {
	{ "--check-only", "run the pre-flight only; never touch kernel state" },
};

static const struct shirudo_help_section init_help_sections[] = {
	{ "options:", init_options,
	  ARRAY_SIZE(init_options) },
};

static const struct shirudo_help init_help = {
	.usage      = "shirudo init [--check-only]",
	.summary    = "Bootstrap enforcement on this target. Idempotent; safe "
		      "to re-run.\nThe pinned link survives the process exit.",
	.sections   = init_help_sections,
	.n_sections = sizeof(init_help_sections) /
		      sizeof(init_help_sections[0]),
};

static void usage(void)
{
	fprintf(stderr, "usage: %s\n", init_help.usage);
}

/*
 * The initrd phase reads the root's state tree: the archived upatches
 * to restore, the eventlog to continue, the keys to compare. A
 * recursive writable bind of <sysroot>/var/lib/shirudo keeps every path
 * the same and lets config recovery record its selection durably. The
 * bind is detached when init leaves. The private bpffs is under /run, which systemd carries
 * across the switch.
 */
static int initrd_enter(void)
{
	struct statvfs state;
	struct statfs root;
	char src[PATH_MAX];
	struct stat st;
	int rc;

	/*
	 * /etc/initrd-release is root's to create on the root file system;
	 * the initramfs is not. Binding a tree of root's over the state
	 * directory is what a run from the root file system would do here.
	 */
	if (statfs("/", &root) != 0)
		return -errno;
	if (root.f_type != TMPFS_MAGIC && root.f_type != RAMFS_MAGIC) {
		pr_err("initrd: the root file system is not an initramfs");
		return -ENOTBLK;
	}
	if (strsprintf(src, sizeof(src), "%s%s", sysroot(),
		       SHIRUDO_VAR_LIB) < 0)
		return -ENAMETOOLONG;
	if (stat(src, &st) != 0 || !S_ISDIR(st.st_mode)) {
		pr_err("initrd: %s is not a directory; the root file system "
		       "must be mounted at %s with /var on it or mounted "
		       "there (x-initrd.mount)", src, sysroot());
		return -ENOENT;
	}
	rc = seal_mkdir_p(SHIRUDO_VAR_LIB, 0700);
	if (rc) {
		pr_err("initrd: mkdir %s: %s", SHIRUDO_VAR_LIB, strerror(-rc));
		return rc;
	}
	if (mount(src, SHIRUDO_VAR_LIB, NULL, MS_BIND | MS_REC, NULL) != 0) {
		pr_err("initrd: bind %s at %s: %s", src, SHIRUDO_VAR_LIB,
		       strerror(errno));
		return -errno;
	}
	rc = statvfs(SHIRUDO_VAR_LIB, &state) ? -errno :
		(state.f_flag & ST_RDONLY ? -EROFS : 0);
	if (rc) {
		umount2(SHIRUDO_VAR_LIB, MNT_DETACH);
		return rc;
	}
	pr_info("initrd: %s bound writable at %s for config recovery",
		src, SHIRUDO_VAR_LIB);
	return 0;

}

static void initrd_leave(void)
{
	if (umount2(SHIRUDO_VAR_LIB, MNT_DETACH) != 0)
		pr_warn("initrd: detach %s: %s", SHIRUDO_VAR_LIB,
			strerror(errno));
}

static int init_phase_error(int rc, const char *phase)
{
	if (rc)
		pr_err("init: %s failed: %s", phase, strerror(-rc));
	return rc;
}

static int run_init(void)
{
	struct shirudo_measured_upatch *set = NULL;
	struct shirudo_eventlog_init rec;
	bool recorded;
	size_t n = 0;
	int rc;

	rc = init_bpffs();
	if (rc)
		return init_phase_error(rc, "private bpffs setup");

	rc = init_keyring();
	if (rc)
		return init_phase_error(rc, "BPF keyring initialization");
	rc = shirudo_image_boot_keys_close();
	if (rc)
		return init_phase_error(rc, "closing the boot key image");

	/* Seal writable state before the hooks attach, then adopt the initrd log. */
	rc = seal_label_tree();
	if (rc)
		return init_phase_error(rc, "sealing persistent state");
	rc = eventlog_adopt_pending();
	if (rc)
		return init_phase_error(rc, "adopting the pending eventlog");

	rc = init_lsm();
	if (rc)
		return init_phase_error(rc, "loading enforcement");

	rc = seal_label_tree();
	if (rc)
		return init_phase_error(rc, "sealing initialized state");
	rc = shirudo_image_runtime_mount();
	if (rc)
		return init_phase_error(rc, "mounting the authenticated runtime");
	rc = shirudo_image_boot();
	if (rc)
		return init_phase_error(rc, "loading authenticated boot settings");
	rc = keys_load(SHIRUDO_RUNTIME_DIR "/keys",
		       SHIRUDO_KEYS_REVOKED_DIR, true, &enrolled);
	if (rc)
		return init_phase_error(rc, "loading trusted keys");

	/*
	 * The record is the eventlog's, which root can hide behind a mount;
	 * the register is the TPM's, written once this boot by whoever bound
	 * it. Either says the restore has happened.
	 */
	rc = eventlog_boot_init(&rec);
	if (rc && rc != -ENOENT) {
		pr_err("init: eventlog %s unreadable: %s", eventlog_path(),
		       strerror(-rc));
		return rc;
	}
	recorded = rc == 0 || chain_bound();
	rc = boot_restore(recorded, &set, &n);
	if (rc) {
		pr_err("init: boot-restore failed; further changes "
		       "and attestation remain blocked");
		xfree(set, n * sizeof(*set));
		return init_phase_error(rc, "restoring boot upatches");
	}

	rc = chain_extend_init(set, n);
	xfree(set, n * sizeof(*set));
	if (rc) {
		pr_err("init: incomplete -- LSM active and upatches "
		       "loaded, but TPM register not advanced");
		return init_phase_error(rc, "binding the TPM register");
	}

	rc = shirudo_image_boot_complete();
	if (rc)
		return init_phase_error(rc, "completing authenticated boot");

	pr_info("init: complete (LSM active, writable state sealed)");
	return 0;
}

int cmd_init(int argc, const char **argv)
{
	struct shirudo_preflight_result res;
	bool check_only = false;
	int i, rc;

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (strcmp(a, "--check-only") == 0) {
			check_only = true;
			continue;
		}
		if (is_help(a)) {
			print_help(&init_help);
			return 0;
		}
		pr_err("init: unknown option '%s'", a);
		usage();
		return 2;
	}

	initrd_mode = in_initrd();
	rc = shirudo_image_bootstrap_load();
	if (rc < 0) {
		pr_err("init: authenticated image settings: %s", strerror(-rc));
		return 1;
	}
	preflight_run(&res);
	print_preflight(&res);

	if (res.n_failed > 0) {
		pr_err("init: pre-flight failed (%d/%d checks)",
		       res.n_failed, res.n);
		return 1;
	}

	if (check_only)
		return 0;

	if (initrd_mode && initrd_enter())
		return 1;
	rc = run_init();
	shirudo_image_leave();
	if (initrd_mode)
		initrd_leave();
	return rc ? 1 : 0;
}
