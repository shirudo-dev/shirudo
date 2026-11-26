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
#include <sys/types.h>
#include <unistd.h>

#include <linux/magic.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>
#include <shirudo/upatch.h>

#include "builtin.h"
#include "util/bpm_tree.h"
#include "util/chain.h"
#include "util/config.h"
#include "util/eventlog.h"
#include "util/help.h"
#include "util/json.h"
#include "util/identity.h"
#include "util/initrd.h"
#include "util/io.h"
#include "util/java_agent.h"
#include "util/image_config.h"
#include "util/image_guards.h"
#include "util/image_runtime.h"
#include "util/keyring.h"
#include "util/keys.h"
#include "util/loader.h"
#include "util/log.h"
#include "util/options.h"
#include "util/malloc.h"
#include "util/nv_writer.h"
#include "util/paths.h"
#include "util/preflight.h"
#include "util/measured.h"
#include "util/seal.h"
#include "util/tpm.h"
#include "util/upatch.h"
#include "util/upatch_pins.h"
#include "util/upatch_resolve.h"
#include "util/upatch_verify.h"

static void print_preflight(const struct preflight_result *r)
{
	int i;

	printf("Pre-flight checks:\n");
	for (i = 0; i < r->n; i++) {
		const struct preflight_check *c = &r->checks[i];

		printf("  %-4s  %s%s%s\n", c->ok ? "OK" : "FAIL", c->name,
		       c->detail[0] ? ": " : "", c->detail);
	}
	printf("%d of %d passed\n", r->n - r->n_failed, r->n);
}

static int print_preflight_json(const struct preflight_result *r)
{
	char buf[8192];
	struct json_emit e = { .buf = buf, .cap = sizeof(buf) };
	int i;

	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_kv_int(&e, "passed", r->n - r->n_failed);
	json_kv_int(&e, "failed", r->n_failed);
	json_arr_open(&e, "checks");
	for (i = 0; i < r->n; i++) {
		const struct preflight_check *c = &r->checks[i];

		json_obj_open(&e);
		json_kv_string(&e, "name", c->name);
		json_kv_bool(&e, "ok", c->ok);
		if (c->detail[0])
			json_kv_string(&e, "detail", c->detail);
		else
			json_kv_null(&e, "detail");
		json_obj_close(&e);
	}
	json_arr_close(&e);
	json_obj_close(&e);
	if (e.err)
		return e.err;
	puts(buf);
	return 0;
}

static struct trusted_set enrolled;

static bool initrd_mode;

static int keyring_holds_set(key_serial_t ring,
			     const struct trusted_set *set)
{
	struct keyring_cert certs[KEYS_MAX];
	size_t i;
	int ret;

	for (i = 0; i < set->n; i++) {
		ret = keys_cert_der(&set->certs[i], &certs[i].der,
				    &certs[i].len);
		if (ret)
			return ret;
	}
	return keyring_holds_exactly(ring, certs, set->n);
}

/*
 * The bpf keyring is the trust anchor a signed loader is verified
 * against once it is sealed. Booted with bpf.keyring_unsealed=1 it
 * takes keys until the first seal, which is init's job from the initrd:
 * enrol every trusted certificate and seal. Found sealed, it was sealed
 * by init earlier this boot (-EEXIST: use it) or empty by the kernel at
 * boot (-ENOKEY). Either way it must then hold exactly the trusted set;
 * a key another task linked before the seal, or a restriction init did
 * not install, is refused.
 */
static int init_bpf_keyring(key_serial_t ring,
			    const struct trusted_set *set)
{
	bool sealed = false;
	size_t i;
	int ret;

	for (i = 0; i < set->n && !sealed; i++) {
		const __u8 *der = NULL;
		size_t der_sz = 0;
		key_serial_t key;

		ret = keys_cert_der(&set->certs[i], &der, &der_sz);
		if (ret) {
			pr_err("read %s: %s", set->certs[i].path,
			       strerror(-ret));
			return ret;
		}
		key = keyring_bpf_add_cert(der, der_sz);
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
				pr_err("kernel cannot verify this cert's public-key algorithm (ML-DSA needs CONFIG_CRYPTO_MLDSA=y and CONFIG_CRYPTO_SHA512=y)");
			return key;
		}
		if (i > 0) {
			pr_err("bpf keyring serial=%d was sealed while init "
			       "enrolled the certificates (tampered)",
			       (int)ring);
			return -EKEYREJECTED;
		}
		sealed = true;
	}
	if (!sealed) {
		ret = keyring_bpf_seal();
		if (ret == -EEXIST) {
			pr_err("bpf keyring serial=%d carries a restriction "
			       "init did not install (tampered)", (int)ring);
			return -EKEYREJECTED;
		}
		if (ret) {
			pr_err("bpf keyring: certificates enrolled but the "
			       "keyring could not be sealed: %s",
			       strerror(-ret));
			return ret;
		}
	}
	ret = keyring_holds_set(ring, set);
	if (ret < 0) {
		pr_err("bpf keyring: compare: %s", strerror(-ret));
		return ret;
	}
	if (!ret && sealed && keyring_holds_exactly(ring, NULL, 0) == 1) {
		pr_err("bpf keyring serial=%d was sealed empty at boot; boot "
		       "with bpf.keyring_unsealed=1", (int)ring);
		return -ENOKEY;
	}
	if (!ret) {
		pr_err("bpf keyring serial=%d is sealed around keys other than "
		       "the %zu trusted certificate%s (tampered)", (int)ring,
		       set->n, set->n == 1 ? "" : "s");
		return -EKEYREJECTED;
	}
	if (sealed) {
		pr_info("bpf keyring serial=%d: already holds the %zu trusted "
			"certificate%s, sealed this boot", (int)ring, set->n,
			set->n == 1 ? "" : "s");
		return -EEXIST;
	}
	pr_info("bpf keyring serial=%d: %zu certificate%s enrolled and sealed",
		(int)ring, set->n, set->n == 1 ? "" : "s");
	return 0;
}

static int init_keyring(void)
{
	struct trusted_set set;
	struct identity id;
	key_serial_t ring;
	int ret;

	ring = keyring_bpf_serial();
	if (ring <= 0) {
		ret = ring ? ring : -ENOKEY;
		pr_err("bpf keyring lookup: %s", strerror(-ret));
		return ret;
	}
	if (!identity_read(&id)) {
		if (id.keyring_type != SIG_KEYRING_BPF ||
		    id.keyring_serial != ring ||
		    memcmp(id.runtime_root, image_runtime_root(), 32))
			return -EKEYREJECTED;
		return 0;
	}
	ret = image_boot_keys(&set);
	if (ret)
		return ret;
	ret = init_bpf_keyring(ring, &set);
	if (ret && ret != -EEXIST)
		return ret;
	enrolled = set;
	return 0;
}

static int init_bpffs(void)
{
	struct stat parent, run;
	int ret;

	ret = seal_mkdir_p(VAR_LIB, 0700);
	if (ret) {
		pr_err("mkdir %s: %s", VAR_LIB, strerror(-ret));
		return ret;
	}
	ret = seal_mkdir_p(RUN_DIR, 0700);
	if (ret) {
		pr_err("mkdir %s: %s", RUN_DIR, strerror(-ret));
		return ret;
	}
	ret = bpffs_mounted_at(BPFFS_DIR);
	if (ret < 0)
		return ret;
	if (ret)
		return 0;
	if (stat(RUN_DIR, &parent) || stat("/run", &run))
		return -errno;
	if (parent.st_dev == run.st_dev) {
		ret = seal_label(RUN_DIR);
		if (ret)
			return ret;
		if (mount("tmpfs", RUN_DIR, "tmpfs",
			  MS_NOSUID | MS_NODEV | MS_NOEXEC,
			  "mode=0700,size=16M"))
			return -errno;
	}
	if (mount(NULL, RUN_DIR, NULL,
		  MS_PRIVATE | MS_REC, NULL))
		return -errno;

	/* So that the init record left here is sealed from its creation. */
	ret = seal_label(RUN_DIR);
	if (ret)
		return ret;
	ret = seal_mkdir_p(BPFFS_DIR, 0700);
	if (ret) {
		pr_err("mkdir %s: %s",
		       BPFFS_DIR, strerror(-ret));
		return ret;
	}

	ret = bpffs_mounted_at(BPFFS_DIR);
	if (ret < 0) {
		pr_err("check the bpffs at %s: %s", BPFFS_DIR, strerror(-ret));
		return ret;
	}
	if (ret) {
		pr_info("bpffs already mounted at %s", BPFFS_DIR);
		return 0;
	}

	if (mount("bpf", BPFFS_DIR, "bpf",
		  MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=0700") != 0) {
		pr_err("mount bpffs at %s: %s",
		       BPFFS_DIR, strerror(errno));
		return -errno;
	}

	pr_info("mounted private bpffs at %s "
		"(mode=0700,nosuid,nodev,noexec)", BPFFS_DIR);
	return 0;
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

static int find_gate_programs(struct bpf_object *obj,
			      struct bpf_program *programs[GATE_HOOK_COUNT])
{
	__u32 guard;

	for (guard = 0; guard < GATE_HOOK_COUNT; guard++) {
		const char *name = shirudo_gate_guards[guard].prog;

		programs[guard] = bpf_object__find_program_by_name(obj, name);
		if (!programs[guard]) {
			pr_err("expected programs missing in bpf2 object");
			return -ENOENT;
		}
	}
	return 0;
}

/* Attach in order. The caller owns each pinned link, including on failure. */
static int attach_gates(struct bpf_program *const programs[GATE_HOOK_COUNT],
			const enum gate_guard *order, size_t count,
			struct bpf_link *links[GATE_HOOK_COUNT])
{
	struct bpf_program *program;
	enum gate_guard guard;
	size_t i;
	int err;

	for (i = 0; i < count; i++) {
		guard = order[i];
		program = programs[guard];
		err = attach_pin(program, shirudo_gate_guards[guard].pin,
				 &links[guard]);
		if (err) {
			pr_err("attach %s: %s",
			       bpf_program__section_name(program),
			       strerror(-err));
			return err;
		}
	}
	return 0;
}

/* The admission and seal objects share bootstrap state and task marks. */
static int share_policy_maps(struct bpf_object *source,
			     struct bpf_object *destination)
{
	struct bpf_map *from, *to;
	size_t i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(shirudo_guard_maps); i++) {
		from = bpf_object__find_map_by_name(source,
						    shirudo_guard_maps[i].name);
		to = bpf_object__find_map_by_name(destination,
						  shirudo_guard_maps[i].name);
		if (!from || !to)
			return -ENOENT;
		ret = bpf_map__reuse_fd(to, bpf_map__fd(from));
		if (ret)
			return ret;
	}
	return 0;
}

/* Attach in order. The caller owns each pinned link, including on failure. */
static int attach_guard_group(struct bpf_object *obj,
			      const struct image_guard *guards,
			      size_t count, struct bpf_link **links)
{
	struct bpf_program *program;
	size_t i;
	int ret;

	for (i = 0; i < count; i++) {
		program = bpf_object__find_program_by_name(obj, guards[i].prog);
		if (!program) {
			pr_err("program %s missing", guards[i].prog);
			return -ENOENT;
		}
		ret = attach_pin(program, guards[i].pin, &links[i]);
		if (ret) {
			pr_err("attach %s: %s", guards[i].prog, strerror(-ret));
			return ret;
		}
	}
	return 0;
}

static int mount_id_unique(const char *path, __u64 *id)
{
	struct statx stx;

	if (statx(AT_FDCWD, path, 0, STATX_MNT_ID_UNIQUE, &stx))
		return -errno;
	if (!(stx.stx_mask & STATX_MNT_ID_UNIQUE) || !stx.stx_mnt_id)
		return -EOPNOTSUPP;
	*id = stx.stx_mnt_id;
	return 0;
}

/*
 * The recorder in the mount guards sees the bootstrap task open the
 * bpffs root; the record is read back, since a guard with none to keep
 * would let an unmount above the bpffs through.
 */
static int record_bpffs_mount(struct bpf_object *obj)
{
	struct mount_record rec = {};
	struct bpf_map *map;
	__u32 zero = 0;
	int fd, ret;

	fd = open(BPFFS_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	close(fd);
	map = bpf_object__find_map_by_name(obj, "shirudo_mnt_rec");
	if (!map)
		return -ENOENT;
	if (bpf_map_lookup_elem(bpf_map__fd(map), &zero, &rec))
		return -errno;
	if (!rec.mount || !rec.mount_ns)
		return -ENOENT;
	if (initrd_mode) {
		ret = mount_id_unique("/", &rec.initrd_root_id);
		if (!ret)
			ret = mount_id_unique(sysroot(), &rec.sysroot_id);
		if (ret)
			return ret;
		if (rec.initrd_root_id == rec.sysroot_id)
			return -EINVAL;
		if (bpf_map_update_elem(bpf_map__fd(map), &zero, &rec, BPF_EXIST))
			return -errno;
	}
	return bpf_map_freeze(bpf_map__fd(map)) ? -errno : 0;
}

static int attach_mount_guards(struct bpf_object *obj, struct bpf_link **links)
{
	int err;

	err = attach_guard_group(obj, shirudo_mount_guards,
				 ARRAY_SIZE(shirudo_mount_guards), links);
	if (err)
		return err;
	err = record_bpffs_mount(obj);
	if (err)
		pr_err("record the bpffs mount: %s", strerror(-err));
	return err;
}

/* Writable state and runtime processes always get the full seal. */
static int attach_seal(struct bpf_object *policy, struct bpf_object **obj_out,
		       struct bpf_link **links, struct bpf_link **image_links)
{
	const struct embedded_bpf *blob = seal_blob();
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

BUILD_BUG_ON_MSG(IDENTITY_KEYS_MAX != KEYS_MAX,
		 "the identity map holds one serial per trusted certificate");

struct anchor_keys {
	__s32	serials[IDENTITY_KEYS_MAX];
	size_t	n;
	bool	overflow;
};

static void collect_asymmetric(key_serial_t serial, const char *type,
			       const char *description, void *ud)
{
	struct anchor_keys *k = ud;

	if (strcmp(type, "asymmetric"))
		return;
	if (k->n >= ARRAY_SIZE(k->serials)) {
		k->overflow = true;
		return;
	}
	k->serials[k->n++] = (__s32)serial;
}

static int bpf_anchor(struct identity *id)
{
	struct anchor_keys keys = {};
	key_serial_t keyring;
	int err;

	/*
	 * The trust anchor lsm/bpf_prog_load enforces: only a load the
	 * kernel verified against exactly this sealed keyring, of exactly
	 * this kind, is admitted from userspace. init_keyring has already
	 * enrolled the cert and sealed the keyring, so this resolves the
	 * serial the kernel records for a load that names it as keyring_id.
	 */
	keyring = keyring_bpf_serial();
	id->keyring_type = SIG_KEYRING_BPF;
	if (keyring <= 0) {
		err = keyring ? keyring : -ENOKEY;
		pr_err("resolve the bpf keyring serial: %s", strerror(-err));
		return err;
	}
	id->keyring_serial = (__s32)keyring;

	/*
	 * The keys that keyring holds, for lsm/key_permission: with the
	 * keyring itself, what no task but shirudo may write, unlink,
	 * revoke or invalidate for the rest of the boot.
	 */
	err = keyring_list(keyring, collect_asymmetric, &keys);
	if (err) {
		pr_err("list the anchor keyring %d: %s", (int)keyring,
		       strerror(-err));
		return err;
	}
	if (keys.overflow || keys.n == 0) {
		pr_err("anchor keyring %d holds %s asymmetric keys",
		       (int)keyring, keys.overflow ? "too many" : "no");
		return keys.overflow ? -E2BIG : -ENOKEY;
	}
	id->n_keys = (__u32)keys.n;
	memcpy(id->key_serials, keys.serials, keys.n * sizeof(keys.serials[0]));
	return 0;
}

/* Boot validation checked the complete config verification key set. */
static int dm_verity_anchor(struct identity *id)
{
	struct anchor_keys keys = {};
	key_serial_t ring;
	int err;

	ring = keyring_dm_verity_serial();
	if (ring <= 0) {
		err = ring ? ring : -ENOKEY;
		pr_err("resolve the dm-verity keyring serial: %s",
		       strerror(-err));
		return err;
	}
	err = keyring_list(ring, collect_asymmetric, &keys);
	if (err) {
		pr_err("list the dm-verity keyring %d: %s", (int)ring,
		       strerror(-err));
		return err;
	}
	if (!keys.n || keys.overflow) {
		pr_err("dm-verity keyring %d has an invalid key count %zu",
		       (int)ring, keys.n);
		return -EKEYREJECTED;
	}
	id->dm_verity_ring = (__s32)ring;
	id->n_dm_verity_keys = keys.n;
	memcpy(id->dm_verity_keys, keys.serials,
	       keys.n * sizeof(keys.serials[0]));
	return 0;
}

/* Seed bootstrap and freeze shared state except the expected config root. */
static int freeze_task_maps(struct bpf_object *obj)
{
	struct task_authority authority = {
		.trusted = TASK_BOOTSTRAP,
	};
	struct bpf_map *map;
	int fd, pidfd, ret = 0;
	__u32 i;

	pidfd = syscall(SYS_pidfd_open, getpid(), 0);
	if (pidfd < 0)
		return -errno;
	for (i = GUARD_TASKS; i < GUARD_MAP_COUNT; i++) {
		const struct guard_map *expected =
			&shirudo_guard_maps[i];

		map = bpf_object__find_map_by_name(obj, expected->name);
		if (!map) {
			ret = -ENOENT;
			break;
		}
		fd = bpf_map__fd(map);
		if (i == GUARD_TASKS &&
		    bpf_map_update_elem(fd, &pidfd, &authority, BPF_ANY)) {
			ret = -errno;
			break;
		}
		/* Expected roots change for each mapping. */
		if ((i != GUARD_ROOTS && bpf_map_freeze(fd)) ||
		    bpf_obj_pin(fd, expected->pin)) {
			ret = -errno;
			break;
		}
	}
	close(pidfd);
	return ret;
}

/*
 * Initial TPM contact is trusted in the authenticated initrd. Later
 * connections salt their sessions with the key whose name we freeze here.
 */
static int record_ek_name(struct identity *id)
{
	struct tpm *tpm;
	int ret;

	ret = tpm_open(&tpm);
	if (ret)
		return ret;
	tpm_ek_name(tpm, id->ek_name);
	tpm_close(tpm);
	return 0;
}

static int identity_devices(struct identity *id)
{
	struct stat st;
	int err;

	if (stat(BPFFS_DIR, &st) != 0) {
		err = -errno;
		pr_err("stat %s: %s", BPFFS_DIR, strerror(errno));
		return err;
	}
	id->sb_dev = kernel_dev(st.st_dev);
	if (stat(RUN_DIR, &st))
		return -errno;
	id->run_dev = kernel_dev(st.st_dev);
	if (stat(VAR_LIB, &st))
		return -errno;
	id->state_dev = st.st_dev;
	id->state_ino = st.st_ino;
	return 0;
}

static int identity_build(struct identity *id)
{
	int err;

	err = identity_devices(id);
	if (err)
		return err;

	memcpy(id->runtime_root, image_runtime_root(), 32);
	id->nv_index = NV_INDEX;
	id->config_pcr = shirudo_image_config_pcr();

	err = bpf_anchor(id);
	if (err)
		return err;
	err = dm_verity_anchor(id);
	if (err)
		return err;
	err = nv_writer_create(id->nv_writer_seed, id->nv_writer_public);
	if (err) {
		pr_err("init: create TPM RSA-3072 NV writer: %s", strerror(-err));
		return err;
	}
	err = record_ek_name(id);
	if (err) {
		pr_err("init: record the endorsement key name: %s (tpm_error)",
		       strerror(-err));
		return err;
	}
	return 0;
}

static int identity_publish(struct bpf_object *obj, const struct identity *id)
{
	struct bpf_map *m_sb;
	int err, map_fd;
	__u32 zero = 0;

	m_sb = bpf_object__find_map_by_name(obj, "shirudo_bpffs_sb");
	if (!m_sb) {
		pr_err("shirudo_bpffs_sb map not in embedded bpf2");
		return -ENOENT;
	}
	map_fd = bpf_map__fd(m_sb);
	if (bpf_map_update_elem(map_fd, &zero, id, BPF_ANY) != 0) {
		err = -errno;
		pr_err("populate sb-identity map: %s", strerror(errno));
		return err;
	}
	if (bpf_map_freeze(map_fd) != 0) {
		err = -errno;
		pr_err("freeze sb-identity map: %s", strerror(errno));
		return err;
	}
	err = freeze_task_maps(obj);
	if (err)
		return err;
	/*
	 * Pinned so that every later command reads the anchor init froze
	 * from the kernel rather than from a file: the serial a load names
	 * and status reports is the one lsm/bpf_prog_load enforces.
	 */
	if (bpf_obj_pin(map_fd, IDENTITY_PIN) != 0) {
		err = -errno;
		pr_err("pin identity map at %s: %s", IDENTITY_PIN,
		       strerror(errno));
		return err;
	}
	return 0;
}

struct lsm_links {
	struct bpf_link *observers[OBSERVER_HOOK_COUNT];
	struct bpf_link *image_observers[IMAGE_OBSERVER_HOOK_COUNT];
	struct bpf_link *gates[GATE_HOOK_COUNT];
	struct bpf_link *mounts[MOUNT_HOOK_COUNT];
	struct bpf_link *seal[SEAL_HOOK_COUNT];
	struct bpf_link *image_seal[IMAGE_SEAL_HOOK_COUNT];
	struct bpf_object *seal_obj;
};

static const enum gate_guard early_gates[] = {
	GUARD_UNLINK,
	GUARD_SETXATTR,
	GUARD_REMOVEXATTR,
	GUARD_KEY_PERMISSION,
	GUARD_TPM_COMMAND,
};

static const enum gate_guard bpf_gates[] = {
	GUARD_BPF_MAP,
	GUARD_BPF_PROG,
	GUARD_PROG_LOAD,
	GUARD_BPF,
};

static int attach_guards(struct bpf_object *obj, struct lsm_links *links)
{
	struct bpf_program *gates[GATE_HOOK_COUNT] = {};
	int err;

	/* The executable-identity guard precedes every BPF admission gate. */
	err = attach_guard_group(obj, shirudo_observer_guards,
				 ARRAY_SIZE(shirudo_observer_guards),
				 links->observers);
	if (!err)
		err = attach_guard_group(obj, shirudo_image_observer_guards,
					 IMAGE_OBSERVER_HOOK_COUNT,
					 links->image_observers);
	if (err)
		return err;

	err = find_gate_programs(obj, gates);
	if (err)
		return err;

	/*
	 * The prctl identity guard is already active. Order the remaining
	 * hooks as bpffs guards, seal's filesystem and exec-identity hooks,
	 * then the bpf() gates (map fd access, bpf_prog_load admission, then
	 * lsm/bpf) LAST.
	 * Pinning a link creates a bpffs inode, gated by neither guard set;
	 * seal's unsigned load and the identity-map freeze precede the gates.
	 */
	err = attach_gates(gates, early_gates, ARRAY_SIZE(early_gates),
			   links->gates);
	if (err)
		return err;
	/*
	 * With the other bpffs guards, so the mount is immutable before
	 * enforcement goes live.
	 */
	err = attach_mount_guards(obj, links->mounts);
	if (err)
		return err;

	err = attach_seal(obj, &links->seal_obj, links->seal,
			  links->image_seal);
	if (err)
		return err;

	return attach_gates(gates, bpf_gates, ARRAY_SIZE(bpf_gates),
			    links->gates);
}

static int lsm_attach(struct bpf_object *obj, struct lsm_links *links)
{
	struct identity id = {};
	int err;

	err = bpf_object__load(obj);
	if (err) {
		pr_err("bpf_object__load: %d", err);
		return err;
	}
	err = identity_build(&id);
	if (err)
		return err;
	err = identity_publish(obj, &id);
	if (err)
		return err;
	return attach_guards(obj, links);
}

static const enum gate_guard gate_release_order[] = {
	GUARD_BPF,
	GUARD_BPF_MAP,
	GUARD_BPF_PROG,
	GUARD_PROG_LOAD,
	GUARD_KEY_PERMISSION,
	GUARD_TPM_COMMAND,
	GUARD_REMOVEXATTR,
	GUARD_SETXATTR,
	GUARD_UNLINK,
};

static const enum guard_map_index map_release_order[] = {
	GUARD_IDENTITY,
	GUARD_TAMPER,
	GUARD_INTEGRITY,
	GUARD_UNLINK_GRANT,
	GUARD_TASKS,
	GUARD_POLICY,
	GUARD_SOCKET_POLICY,
	GUARD_DEVICES,
	GUARD_ROOTS,
};

static void release_link_group(struct bpf_link **links, size_t count,
			       bool unpin)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (unpin && links[i])
			bpf_link__unpin(links[i]);
		bpf_link__destroy(links[i]);
	}
}

/* A pinned link outlives its descriptor; after a failure the pins go too. */
static void lsm_links_release(struct lsm_links *links, bool failed)
{
	struct bpf_link *link;
	size_t i;

	release_link_group(links->image_seal, ARRAY_SIZE(links->image_seal),
			   failed);
	release_link_group(links->image_observers,
			   ARRAY_SIZE(links->image_observers), failed);
	release_link_group(links->observers, ARRAY_SIZE(links->observers),
			   failed);
	release_link_group(links->seal, ARRAY_SIZE(links->seal), failed);
	release_link_group(links->mounts, ARRAY_SIZE(links->mounts), failed);
	if (failed) {
		for (i = 0; i < ARRAY_SIZE(gate_release_order); i++) {
			link = links->gates[gate_release_order[i]];
			if (link)
				bpf_link__unpin(link);
		}
		for (i = 0; i < ARRAY_SIZE(map_release_order); i++)
			unlink(shirudo_guard_maps[map_release_order[i]].pin);
	}
	bpf_object__close(links->seal_obj);
	for (i = 0; i < ARRAY_SIZE(gate_release_order); i++)
		bpf_link__destroy(links->gates[gate_release_order[i]]);
}

static int lsm_check_attached(void)
{
	struct identity id = {};
	int err;

	err = identity_read(&id);
	if (err || !(id.nv_writer_public[0] & 0x80) ||
	    id.nv_index != NV_INDEX ||
	    access(TPM_COMMAND_LINK_PIN, F_OK)) {
		pr_err("init: TPM NV index guard missing or changed; reboot "
		       "with the updated initrd");
		return err ? err : -EACCES;
	}
	pr_info("bpf2 already attached (%s exists)",
		shirudo_gate_guards[GUARD_BPF].pin);
	return 0;
}

static int unlink_stale_pins(void)
{
	__u32 i;
	int err;

	/*
	 * A failed attempt removes its own pins, a crash does not. Once the
	 * identity map is pinned, image_bootstrap_load() refuses a re-run
	 * before it gets here, so map pins are all a crash can have left.
	 */
	for (i = 0; i < GUARD_MAP_COUNT; i++) {
		const char *pin = shirudo_guard_maps[i].pin;

		if (unlink(pin) != 0 && errno != ENOENT) {
			err = -errno;
			pr_err("unlink stale %s: %s", pin, strerror(-err));
			return err;
		}
	}
	return 0;
}

static int init_lsm(void)
{
	const struct embedded_bpf *blob = bpf2_blob();
	struct lsm_links links = {};
	struct bpf_object *obj;
	int err;

	if (access(shirudo_gate_guards[GUARD_BPF].pin, F_OK) == 0)
		return lsm_check_attached();
	err = unlink_stale_pins();
	if (err)
		return err;

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

	err = lsm_attach(obj, &links);
	if (!err)
		pr_info("%s and seal attached: lsm/bpf gate live, writable state sealed",
			blob->name);
	lsm_links_release(&links, err != 0);
	bpf_object__close(obj);
	return err;
}

#define HEXLEN(n)	((n) * 2 + 1)

/*
 * A Java upatch is in place when its jar is the archived one. Once the
 * register was bound this boot a missing or other jar is refused, as a
 * BPF upatch without its pins is: JVMs may have started without the agent
 * meanwhile, which writing the jar again would hide.
 */
static int java_restore(const char *name, const char *path, bool recorded)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN];
	int ret;

	ret = java_agent_payload(name, payload);
	if (!ret) {
		pr_info("boot-restore: %s already installed", name);
		return 0;
	}
	if (ret != -ESTALE) {
		pr_err("boot-restore: cannot tell whether %s is installed: %s",
		       name, strerror(-ret));
		return ret;
	}
	if (recorded) {
		pr_err("boot-restore: the jar of %s is missing or another "
		       "after the register was bound this boot (tampered); "
		       "unload it or reboot", name);
		return -EPERM;
	}
	if (upatch_restore(path) != 0) {
		pr_err("boot-restore: failed to install %s", name);
		return -EINVAL;
	}
	return 0;
}

/*
 * All or nothing: one failure leaves init incomplete and the register
 * unextended. The eventlog says which archives are shirudo's to
 * restore: those whose load it records without a later unload. One it
 * does not, an archive root brought back through a hard link after its
 * unload or one a stopped load left without a record, carries the
 * label and is ignored. On a re-run an upatch already pinned this boot
 * with the archived payload is counted and left alone; loading it again
 * would only attach a second link to fail at the pin. Once this boot's
 * init event is on record the restore has happened and the register
 * covers what it loaded, so an archived artifact that is not loaded
 * cannot be applied any more: nothing would measure it. It was renamed
 * into the archive since, or left behind by an unload cut short, and
 * either is for the operator to resolve.
 */
static int boot_restore_locked(bool recorded,
			       struct measured_upatch **out_set, size_t *out_n)
{
	struct measured_upatch *set = NULL;
	struct measured_set *measured = NULL;
	struct dirent **names = NULL;
	int n, i, ret = 0;
	size_t cnt = 0;

	*out_set = NULL;
	*out_n = 0;

	n = scandir(UPATCHES_DIR, &names, upatch_select,
		    alphasort);
	if (n < 0) {
		if (errno == ENOENT)
			return 0;
		pr_err("boot-restore: scandir %s: %s",
		       UPATCHES_DIR, strerror(errno));
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
	ret = measured_set_log(&measured);
	if (ret) {
		pr_err("boot-restore: cannot read the eventlog's loads: %s",
		       strerror(-ret));
		for (i = 0; i < n; i++)
			libc_free(names[i]);
		libc_free(names);
		xfree(set, (size_t)n * sizeof(*set));
		return ret;
	}

	pr_info("boot-restore: re-applying %d upatch%s from %s",
		n, n == 1 ? "" : "es", UPATCHES_DIR);

	for (i = 0; i < n; i++) {
		char pinned_hex[2 * UPATCH_PAYLOAD_HASH_LEN + 1];
		char path[PATH_MAX];
		struct upatch u;
		int loaded;

		if (ret)
			goto next;
		if (strsprintf(path, sizeof(path), "%s/%s", UPATCHES_DIR,
			       names[i]->d_name) < 0) {
			pr_err("boot-restore: path too long: %s",
			       names[i]->d_name);
			ret = -ENAMETOOLONG;
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
		measured_upatch_of(&set[cnt], &u);
		upatch_close(&u);
		if (!measured_holds(measured, set[cnt].name,
				    set[cnt].payload_hex)) {
			pr_warn("boot-restore: %s is archived without a "
				"record of its load (returned or foreign "
				"entry); ignored", names[i]->d_name);
			goto next;
		}
		if (set[cnt].type == UPATCH_TYPE_JAVA) {
			ret = java_restore(set[cnt].name, path, recorded);
			if (!ret)
				cnt++;
			goto next;
		}
		loaded = upatch_loaded_pins(set[cnt].name);
		if (loaded < 0) {
			pr_err("boot-restore: cannot read the pins of %s: %s",
			       set[cnt].name, strerror(-loaded));
			ret = loaded;
			goto next;
		}
		if (loaded) {
			upatch_payload_sha256(set[cnt].name, pinned_hex,
					      sizeof(pinned_hex));
			if (strcmp(pinned_hex, set[cnt].payload_hex) != 0) {
				pr_err("boot-restore: %s is loaded with a "
				       "payload other than the archived one "
				       "(tampered)", set[cnt].name);
				ret = -EINVAL;
				goto next;
			}
			if (upatch_links_complete(set[cnt].name, path) != 1) {
				pr_err("boot-restore: %s is loaded without every "
				       "link its signed metadata implies "
				       "(tampered); unload it or reboot",
				       set[cnt].name);
				ret = -EPERM;
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
			ret = -EPERM;
			goto next;
		}
		if (upatch_restore(path) != 0) {
			pr_err("boot-restore: failed to apply %s",
			       names[i]->d_name);
			ret = -EINVAL;
			goto next;
		}
		cnt++;
next:
		libc_free(names[i]);
	}
	libc_free(names);
	measured_set_free(measured);

	if (ret) {
		xfree(set, (size_t)n * sizeof(*set));
		return ret;
	}

	*out_set = set;
	*out_n = cnt;
	pr_info("boot-restore: %zu upatch%s re-applied", cnt,
		cnt == 1 ? "" : "es");
	return 0;
}

/*
 * A failure leaves JVMs without the agents, which the status of the
 * archive shows, and does not stop the boot.
 */
static void java_restore_options(void)
{
	int ret = java_agents_sync();

	if (ret)
		pr_warn("boot-restore: cannot bring the Java agents and %s in line: %s",
			JAVA_ENV_PATH, strerror(-ret));
}

/*
 * A run after the register was bound this boot runs beside the upatch
 * commands the completed activation admits, so it takes their lock: an
 * unload between the archive scan and the pin check is otherwise taken
 * for an archived upatch that is not loaded.
 */
static int boot_restore(bool recorded,
			struct measured_upatch **out_set, size_t *out_n)
{
	int lock = -1, ret;

	if (recorded) {
		lock = eventlog_lock();
		if (lock < 0) {
			pr_err("boot-restore: cannot take the register lock: %s",
			       strerror(-lock));
			*out_set = NULL;
			*out_n = 0;
			return lock;
		}
	}
	ret = boot_restore_locked(recorded, out_set, out_n);
	if (!ret)
		java_restore_options();
	eventlog_unlock(lock);
	return ret;
}

/* The binding a verifier needs to recompute the register's public area. */
static int append_init_event(const struct measured_upatch *set,
			     size_t n,
			     const __u8 cert_sha[32],
			     const __u8 set_digest[32],
			     const __u8 tree_root[32],
			     const __u8 init_digest[32],
			     const struct chain_init_info *info)
{
	char pcr_hex[HEXLEN(32)], anchor_hex[HEXLEN(32)], chain_hex[HEXLEN(32)];
	/* Every set entry is a name, its digest and their keys. */
	size_t cap = size_add(64 * 1024, size_mul(n, UPATCH_NAME_MAX + 128));
	char name_hex[HEXLEN(TPM_NAME_LEN)], tree_hex[HEXLEN(32)];
	char writer_hex[HEXLEN(TPM_NV_RSA_BYTES)];
	char cert_hex[HEXLEN(32)], set_hex[HEXLEN(32)];
	struct json_emit e = { .cap = cap };
	char phase_hex[HEXLEN(32)];
	size_t i;
	int ret;

	e.buf = xmalloc(cap);
	if (!e.buf)
		return -ENOMEM;

	hex_encode(cert_sha, 32, cert_hex);
	hex_encode(set_digest, 32, set_hex);
	hex_encode(tree_root, 32, tree_hex);
	hex_encode(info->pcr_before, 32, pcr_hex);
	hex_encode(info->phase_before, 32, phase_hex);
	hex_encode(info->name, TPM_NAME_LEN, name_hex);
	hex_encode(info->anchor_digest, 32, anchor_hex);
	hex_encode(info->value, 32, chain_hex);
	hex_encode(info->writer_public, sizeof(info->writer_public), writer_hex);

	eventlog_record_open(&e, "init", init_digest);
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
		if (set[i].type == UPATCH_TYPE_JAVA)
			json_kv_string(&e, "type", "java");
		json_obj_close(&e);
	}
	json_arr_close(&e);
	json_kv_int(&e, "pcr", CHAIN_PCR);
	json_kv_string(&e, "pcr_before", pcr_hex);
	json_kv_int(&e, "phase_pcr", CHAIN_PHASE_PCR);
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
		xfree(e.buf, cap);
		return e.err;
	}
	/*
	 * From the initrd the record waits under /run for the root file
	 * system's init: the eventlog is on a root that is read-only here.
	 */
	ret = eventlog_append_to(initrd_mode ?
				 eventlog_pending_path() :
				 eventlog_path(), e.buf);
	xfree(e.buf, cap);
	return ret;
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

static int tree_root_at_boot(__u8 out[32])
{
	struct tree_state s = {};
	int ret;

	memset(out, 0, 32);
	ret = tree_state_read(&s);
	if (ret == -ENOENT)
		return 0;
	if (!ret)
		ret = hex_decode(s.projection_root, out, 32);
	if (ret)
		memset(out, 0, 32);
	return ret;
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
static int chain_extend_init(struct measured_upatch *set, size_t n)
{
	__u8 cert_sha[32], set_digest[32], tree_root[32], init_digest[32];
	struct chain_init_info info;
	int ret;

	{
		struct config cfg __cleanup(config_clear);
		__u64 max_bytes;
		bool full;

		ret = config_load(&cfg);
		if (ret) {
			pr_err("chain: configuration unreadable: %s",
			       strerror(-ret));
			return ret;
		}
		max_bytes = cfg.eventlog_max_bytes;
		full = eventlog_would_exceed(max_bytes);
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
	ret = keys_set_digest(&enrolled, cert_sha);
	if (ret) {
		pr_err("chain: cannot hash the enrolled set: %s", strerror(-ret));
		return ret;
	}

	/*
	 * init_event = SHA256("shirudo-init\0" || cert_sha256 || set_digest
	 *                     || tree_root), the formula the operator's
	 * predictor shares (util/attest.c).
	 */
	ret = tree_root_at_boot(tree_root);
	if (ret) {
		pr_err("chain: cannot read the upatch tree state %s: %s",
		       BPM_TREE_STATE_PATH, strerror(-ret));
		return ret;
	}
	ret = chain_init_event(cert_sha, set, n, tree_root, set_digest,
			       init_digest);

	if (ret) {
		pr_err("chain: cannot hash the init event: %s", strerror(-ret));
		return ret;
	}
	ret = chain_init(init_digest, &info);
	if (ret == -ENODEV) {
		pr_err("tpm: not usable; shirudo requires a TPM 2.0 "
		       "(tpm_error)");
		return ret;
	}
	if (ret == -EEXIST) {
		pr_err("tpm: the register this boot recorded is gone or "
		       "replaced; refusing to bind another before the next "
		       "TPM reset (tampered)");
		return ret;
	}
	if (ret == -EACCES) {
		pr_err("tpm: register 0x%08X cannot be bound (tpm_error); on "
		       "a TPM with owner auth set, supply it via "
		       "tpm.owner_auth in /etc/shirudo/shirudo.conf or "
		       "SHIRUDO_TPM_OWNER_AUTH", NV_INDEX);
		return ret;
	}
	if (ret) {
		pr_err("tpm: register extend failed, the chain did not advance "
		       "while the LSM is active (tpm_error); the operator must "
		       "reconcile");
		return ret;
	}
	if (info.reused) {
		pr_info("tpm: register already bound this boot; chain "
			"unchanged (index 0x%08X)", NV_INDEX);
		return 0;
	}

	ret = append_init_event(set, n, cert_sha, set_digest, tree_root,
				init_digest, &info);
	if (ret) {
		pr_err("eventlog: append failed after the extend: register and "
		       "log disagree; the operator must reconcile");
		return ret;
	}

	pr_info("tpm: register bound in the %s and extended (index 0x%08X, "
		"PCR %u anchored, %zu upatch%s in set)",
		info.initrd ? "initrd" : "root file system", NV_INDEX,
		CHAIN_PCR, n, n == 1 ? "" : "es");
	if (!info.initrd)
		pr_warn("tpm: init ran after the initrd; the register's binding "
			"can be told from an initrd one by PCR %u",
			CHAIN_PHASE_PCR);
	else if (phase_unmeasured(info.phase_before))
		pr_warn("tpm: PCR %u holds no phase measurement; systemd "
			"measures enter-initrd only for a measured UKI boot, so "
			"a verifier cannot pin this binding to the initrd by it",
			CHAIN_PHASE_PCR);
	return 0;
}

enum init_opt {
	INIT_CHECK_ONLY,
	INIT_JSON,
};

static const struct opt_spec init_opts[] = {
	[INIT_CHECK_ONLY] = { "--check-only", 0, 0, NULL,
		"run the pre-flight only; never touch kernel state" },
	[INIT_JSON] = { "--json", 0, 0, NULL,
		"with --check-only, print the checks as JSON" },
};

static const struct help_section init_help_sections[] = {
	HELP_OPTIONS("options:", init_opts),
};

static const struct help init_help = {
	.usage      = "shirudo init [--check-only [--json]]",
	.summary    = "Bootstrap enforcement on this target. Idempotent; safe "
		      "to re-run.\nThe pinned link survives the process exit.",
	.sections   = init_help_sections,
	.n_sections = ARRAY_SIZE(init_help_sections),
};

/* Where the state tree is on the root file system, which the initrd binds. */
static int state_source(char *buf, size_t cap)
{
	if (!initrd_mode)
		return strscpy(buf, VAR_LIB, cap);
	return strsprintf(buf, cap, "%s%s", sysroot(), VAR_LIB);
}

static void initrd_leave(void)
{
	if (umount2(VAR_LIB, MNT_DETACH) != 0)
		pr_warn("initrd: detach %s: %s", VAR_LIB,
			strerror(errno));
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
	int ret;

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
	if (state_source(src, sizeof(src)) < 0)
		return -ENAMETOOLONG;
	if (stat(src, &st) != 0 || !S_ISDIR(st.st_mode)) {
		pr_err("initrd: %s is not a directory; the root file system "
		       "must be mounted at %s with /var on it or mounted "
		       "there (x-initrd.mount)", src, sysroot());
		return -ENOENT;
	}
	ret = seal_mkdir_p(VAR_LIB, 0700);
	if (ret) {
		pr_err("initrd: mkdir %s: %s", VAR_LIB, strerror(-ret));
		return ret;
	}
	if (mount(src, VAR_LIB, NULL, MS_BIND | MS_REC, NULL) != 0) {
		pr_err("initrd: bind %s at %s: %s", src, VAR_LIB,
		       strerror(errno));
		return -errno;
	}
	if (statvfs(VAR_LIB, &state)) {
		ret = -errno;
		pr_err("initrd: statvfs %s: %s", src, strerror(-ret));
	} else if (state.f_flag & ST_RDONLY) {
		ret = -EROFS;
		pr_err("initrd: %s is read-only", src);
	} else {
		ret = 0;
	}
	if (ret) {
		initrd_leave();
		return ret;
	}
	pr_info("initrd: %s bound writable at %s for config recovery",
		src, VAR_LIB);
	return 0;
}

static int init_phase_error(int ret, const char *phase)
{
	if (ret)
		pr_err("init: %s failed: %s", phase, strerror(-ret));
	return ret;
}

static int run_init(void)
{
	struct measured_upatch *set = NULL;
	struct eventlog_init rec;
	bool recorded, bootstrap;
	size_t n = 0;
	int ret;

	/* Only the run that brings enforcement up may label an unlabelled tree. */
	ret = enforcement_active();
	if (ret < 0)
		return init_phase_error(ret, "reading the enforcement state");
	bootstrap = ret == 0;
	ret = init_bpffs();
	if (ret)
		return init_phase_error(ret, "private bpffs setup");
	/* Labelled before anyone else can make it, as RUN_DIR is. */
	ret = java_agent_dir_prepare();
	if (ret)
		return init_phase_error(ret, "Java agent directory setup");

	ret = init_keyring();
	if (ret)
		return init_phase_error(ret, "BPF keyring initialization");
	ret = image_boot_keys_close();
	if (ret)
		return init_phase_error(ret, "closing the boot key image");

	/* Seal writable state before the hooks attach, then adopt the initrd log. */
	ret = seal_label_tree(bootstrap);
	if (ret)
		return init_phase_error(ret, "sealing persistent state");
	if (bootstrap) {
		char src[PATH_MAX];

		ret = state_source(src, sizeof(src));
		if (ret >= 0)
			ret = seal_mark_ancestors(src);
		if (ret)
			return init_phase_error(ret, "marking the directories above the state root");
	}
	ret = eventlog_adopt_pending();
	if (ret)
		return init_phase_error(ret, "adopting the pending eventlog");

	ret = init_lsm();
	if (ret)
		return init_phase_error(ret, "loading enforcement");

	ret = seal_label_tree(bootstrap);
	if (ret)
		return init_phase_error(ret, "sealing initialized state");
	ret = image_runtime_mount();
	if (ret)
		return init_phase_error(ret, "mounting the authenticated runtime");
	ret = image_boot();
	if (ret)
		return init_phase_error(ret, "loading authenticated boot settings");
	ret = keys_load(RUNTIME_DIR "/keys",
			KEYS_REVOKED_DIR, true, &enrolled);
	if (ret)
		return init_phase_error(ret, "loading trusted keys");

	/*
	 * The record is the eventlog's, which root can hide behind a mount;
	 * the register is the TPM's, written once this boot by whoever bound
	 * it. Either says the restore has happened.
	 */
	ret = eventlog_boot_init(&rec);
	if (ret && ret != -ENOENT) {
		pr_err("init: eventlog %s unreadable: %s", eventlog_path(),
		       strerror(-ret));
		return ret;
	}
	recorded = ret == 0 || chain_bound();
	ret = boot_restore(recorded, &set, &n);
	if (ret) {
		pr_err("init: boot-restore failed; further changes "
		       "and attestation remain blocked");
		xfree(set, n * sizeof(*set));
		return init_phase_error(ret, "restoring boot upatches");
	}

	ret = chain_extend_init(set, n);
	xfree(set, n * sizeof(*set));
	if (ret) {
		pr_err("init: incomplete: LSM active and upatches loaded, but "
		       "the TPM register did not advance");
		return init_phase_error(ret, "binding the TPM register");
	}

	ret = image_boot_complete();
	if (ret)
		return init_phase_error(ret, "completing authenticated boot");

	pr_info("init: complete (LSM active, writable state sealed)");
	return 0;
}

int cmd_init(int argc, const char **argv)
{
	bool check_only = false, json = false;
	struct preflight_result res;
	struct opt_parser p;
	int opt, ret;

	OPT_INIT(&p, "init", init_opts, &init_help, argc, argv, 1);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case INIT_CHECK_ONLY:
			check_only = true;
			break;
		case INIT_JSON:
			json = true;
			break;
		case OPT_ARG:
			opt_usage(&p, "unexpected argument '%s'", p.value);
			return EXIT_USAGE;
		case OPT_DONE:
			return 0;
		default:
			return EXIT_USAGE;
		}
	}

	initrd_mode = in_initrd();
	ret = image_bootstrap_load();
	if (ret < 0) {
		pr_err("init: authenticated image settings: %s", strerror(-ret));
		return 1;
	}
	if (json && !check_only) {
		opt_usage(&p, "--json takes --check-only");
		return EXIT_USAGE;
	}
	preflight_run(&res);
	if (json) {
		if (print_preflight_json(&res))
			return 1;
	} else {
		print_preflight(&res);
	}

	if (res.n_failed > 0) {
		pr_err("init: pre-flight failed, %d of %d checks",
		       res.n_failed, res.n);
		return 1;
	}

	if (check_only)
		return 0;

	if (initrd_mode && initrd_enter())
		return 1;
	ret = run_init();
	image_leave();
	if (initrd_mode)
		initrd_leave();
	return ret ? 1 : 0;
}
