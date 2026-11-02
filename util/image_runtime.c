// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include <shirudo/enforcement.h>
#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "../builtin.h"
#include "chain.h"
#include "config.h"
#include "config_image.h"
#include "config_update.h"
#include "dm_verity.h"
#include "hex.h"
#include "identity.h"
#include "image_bootstrap.h"
#include "image_cache.h"
#include "image_config.h"
#include "image_guards.h"
#include "image_keys.h"
#include "image_runtime.h"
#include "json.h"
#include "keys.h"
#include "keyring.h"
#include "malloc.h"
#include "log.h"
#include "paths.h"
#include "seal.h"
#include "tpm.h"

struct image_context {
	struct config_update_target boot_target;
	struct dm_verity boot_runtime;
	struct config_update update;
	struct config_image_open candidate;
	struct dm_verity candidate_device;
	struct config bootstrap_config;
	struct image_bootstrap bootstrap;
	struct tpm *tpm;
	int candidate_fd;
	int certificate_fd;
	int config_state;	/* what current_config() refused status with */
	bool loaded;
	bool boot_keys_open;
	bool boot_target_valid;
};

static struct image_context image = {
	.candidate_fd = -1,
	.certificate_fd = -1,
	.update = { .dir_fd = -1, .lock_fd = -1 },
	.candidate = { .data_fd = -1, .hash_fd = -1, .signature_fd = -1 },
	.candidate_device = { .data_loop_fd = -1, .hash_loop_fd = -1 },
};

static int load_runtime_config(bool trusted_boot);
static int current_config(void);

struct config_update *image_update_context(void)
{
	return image.update.lock_fd >= 0 ? &image.update : NULL;
}

static int reject_overrides(void)
{
	static const char *const names[] = {
		"SHIRUDO_KEYS_DIR",
		"SHIRUDO_TPM_TCTI",
		"SHIRUDO_TPM_OWNER_AUTH",
		"SHIRUDO_EVENTLOG_PATH",
		"SHIRUDO_EVENTLOG_PENDING_PATH",
		"SHIRUDO_INITRD_RELEASE",
		"SHIRUDO_SYSROOT",
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		if (getenv(names[i])) {
			pr_err("bootstrap override %s is forbidden",
			       names[i]);
			return -EPERM;
		}
	}
	return 0;
}

int image_bootstrap_load(void)
{
	struct identity identity;
	int mode, ret;

	if (image.loaded)
		return 1;
	mode = enforcement_active();
	if (mode < 0)
		return mode;
	ret = identity_read(&identity);
	if (mode && ret)
		return ret;
	if (!ret && !mode)
		return -EPROTO;
	if (!ret) {
		memcpy(image.bootstrap.runtime_root, identity.runtime_root, 32);
		image.bootstrap.have_root = true;
		ret = load_runtime_config(false);
	} else {
		ret = image_bootstrap_read(CONF_PATH,
					   &image.bootstrap, true);
		if (!ret &&
		    (!image.bootstrap.runtime[0] || !image.bootstrap.have_root))
			ret = -EINVAL;
		if (!ret)
			ret = config_load_path(&image.bootstrap_config,
					       CONF_PATH);
	}
	if (ret)
		return ret;
	ret = reject_overrides();
	if (ret)
		return ret;
	ret = image_config_set(&image.bootstrap_config, -1);
	if (!ret)
		image.loaded = true;
	return ret ? ret : 1;
}

const __u8 *image_runtime_root(void)
{
	return image.loaded ? image.bootstrap.runtime_root : NULL;
}

static int mkdir_owned(const char *path)
{
	struct stat st;
	bool created;

	created = mkdir(path, 0700) == 0;
	if (!created && errno != EEXIST)
		return -errno;
	if (lstat(path, &st))
		return -errno;
	if (!S_ISDIR(st.st_mode) || st.st_uid || (st.st_mode & 0022))
		return -EPERM;
	return created ? seal_label(path) : 0;
}

static int mapping_name(const __u8 root[32], char out[128])
{
	char hex[65];

	hex_encode(root, 32, hex);
	return strsprintf(out, 128, "shirudo-config-%s", hex) < 0 ? -ENAMETOOLONG : 0;
}

static int device_observed(dev_t device, const __u8 root[32], __u32 kind)
{
	struct device_authority entry;
	__u32 dev = (major(device) << 20) | minor(device);
	__u64 key, next, diskseq;
	struct stat st;
	char path[64];
	int fd, block, ret = -EACCES;

	if (strsprintf(path, sizeof(path), "/dev/dm-%u", minor(device)) < 0)
		return -ENAMETOOLONG;
	block = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (block < 0)
		return -errno;
	if (fstat(block, &st))
		ret = -errno;
	else if (!S_ISBLK(st.st_mode) || st.st_rdev != device)
		ret = -EPERM;
	else if (ioctl(block, BLKGETDISKSEQ, &diskseq))
		ret = -errno;
	else
		ret = 0;
	if (ret) {
		close(block);
		return ret;
	}
	fd = bpf_obj_get(BPFFS_DIR "/devices");
	if (fd < 0) {
		ret = -errno;
		goto out_block;
	}
	if (bpf_map_get_next_key(fd, NULL, &key))
		goto out;
	do {
		if (!bpf_map_lookup_elem(fd, &key, &entry) &&
		    entry.dev == dev && entry.kind == kind &&
		    entry.diskseq == diskseq &&
		    (!root || !memcmp(entry.root, root, 32))) {
			ret = 0;
			break;
		}
		if (bpf_map_get_next_key(fd, &key, &next))
			break;
		key = next;
	} while (1);
out:
	close(fd);
out_block:
	close(block);
	return ret;
}

static int runtime_observed(dev_t device)
{
	return device_observed(device, image.bootstrap.runtime_root,
			       DEVICE_RUNTIME);
}

static int mount_flags(int fd, bool executable)
{
	__u64 required = ST_RDONLY | ST_NOSUID | ST_NODEV;
	struct statvfs st;

	if (!executable)
		required |= ST_NOEXEC;
	if (fstatvfs(fd, &st))
		return -errno;
	return (st.f_flag & required) == required ? 0 : -EPERM;
}

static int open_runtime_file(const char *path, dev_t device)
{
	struct stat st;
	int fd, ret;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -errno;
	ret = fstat(fd, &st) ? -errno : 0;
	if (!ret && (!S_ISREG(st.st_mode) || st.st_dev != device))
		ret = -EPERM;
	if (ret) {
		close(fd);
		return ret;
	}
	return fd;
}

static int load_runtime_config(bool trusted_boot)
{
	struct stat root;
	int fd, ret;

	if (!trusted_boot) {
		ret = image_guards_ready();
		if (ret)
			return ret;
	}
	if (stat(RUNTIME_DIR, &root))
		return -errno;
	if (!trusted_boot) {
		ret = runtime_observed(root.st_dev);
		if (ret)
			return ret;
	}

	fd = open_runtime_file(RUNTIME_CONF_PATH, root.st_dev);
	if (fd < 0)
		return fd;
	ret = image_bootstrap_read_fd(fd, &image.bootstrap, false);
	if (!ret)
		ret = config_load_fd(&image.bootstrap_config, fd,
				     RUNTIME_CONF_PATH);
	close(fd);
	if (ret)
		return ret;
	if (!image.bootstrap.config[0] || !image.bootstrap.certificate[0] ||
	    !image.bootstrap.have_pcr)
		return -EINVAL;
	ret = image_config_set(&image.bootstrap_config, -1);
	if (ret)
		return ret;

	fd = open_runtime_file(image.bootstrap.certificate, root.st_dev);
	if (fd < 0)
		return fd;
	if (image.certificate_fd >= 0)
		close(image.certificate_fd);
	image.certificate_fd = fd;

	fd = open_runtime_file(RUNTIME_CERT_PATH, root.st_dev);
	if (fd < 0)
		return fd;
	ret = mount_flags(fd, true);
	close(fd);
	if (ret)
		return ret;

	/* The verified config certificate stays open through key enrollment. */
	return 0;
}

/* The initrd checks the runtime against its authenticated UKI root. */
static int mount_runtime(bool trusted_boot)
{
	const char *step = "open runtime image";
	struct config_image_open opened = {
		.data_fd = -1,
		.hash_fd = -1,
		.signature_fd = -1,
	};
	struct dm_verity device = {
		.data_loop_fd = -1,
		.hash_loop_fd = -1,
	};
	bool created = false;
	int ret, cleanup;
	struct stat st;

	if (!image.loaded)
		return -EINVAL;
	if (!trusted_boot && !stat(RUNTIME_DIR, &st) &&
	    !runtime_observed(st.st_dev))
		return load_runtime_config(trusted_boot);
	ret = config_image_open_root(image.bootstrap.runtime,
				     image.bootstrap.runtime_root,
				     &opened);
	if (!ret) {
		step = "prepare runtime mountpoint";
		ret = mkdir_owned(RUNTIME_DIR);
	}
	if (!ret) {
		step = "create runtime dm-verity mapping";
		ret = dm_verity_create(&opened, "shirudo-runtime",
				       &device);
		created = !ret;
	}
	if (ret == -EEXIST) {
		step = "inspect runtime dm-verity mapping";
		ret = dm_verity_inspect("shirudo-runtime", &opened.image,
					&device);
	}
	if (!ret) {
		step = "verify runtime image";
		ret = dm_verity_verify(&device, &opened);
	}
	if (!ret) {
		step = "mount runtime image";
		ret = dm_verity_mount(&device, RUNTIME_DIR,
				      true);
	}
	if (ret && created) {
		cleanup = dm_verity_remove(&device, false);
		if (cleanup)
			pr_warn("image: cannot remove runtime mapping: %s",
				strerror(-cleanup));
	}
	dm_verity_close(&device);
	if (!ret && trusted_boot)
		image.boot_runtime = device;
	config_image_close(&opened);
	if (!ret) {
		step = "load runtime config";
		ret = load_runtime_config(trusted_boot);
		if (ret && umount2(RUNTIME_DIR, MNT_DETACH))
			pr_warn("image: cannot unmount the runtime: %s",
				strerror(errno));
	}
	if (ret)
		pr_err("image: %s: %s", step, strerror(-ret));
	return ret;
}

int image_runtime_mount(void)
{
	return mount_runtime(false);
}

static int seal_fd(void *ctx __attribute__((__unused__)), int fd)
{
	return fsetxattr(fd, XATTR_NAME, SEAL_LABEL,
			 strlen(SEAL_LABEL), 0) ?
		       -errno :
		       0;
}

static int boot_identity(void *ctx, __u32 *reset, __u32 *restart)
{
	struct image_context *current = ctx;

	return tpm_boot_identity(current->tpm, reset, restart);
}

static int pcr_read(void *ctx, __u32 pcr, __u8 out[32])
{
	struct image_context *current = ctx;

	return tpm_pcr_read(current->tpm, pcr, out);
}

static int pcr_extend(void *ctx, __u32 pcr, const __u8 event[32])
{
	struct image_context *current = ctx;

	return tpm_pcr_extend(current->tpm, pcr, event);
}

static int collect_mapping(const char *name, dev_t device, void *ctx)
{
	struct dm_verity retired = {
		.data_loop_fd = -1,
		.hash_loop_fd = -1,
	};
	const dev_t *active = ctx;
	int ret;

	if (device == *active ||
	    device_observed(device, NULL, DEVICE_CONFIG))
		return 0;
	if (strlen(name) >= sizeof(retired.name))
		return -ENAMETOOLONG;
	strscpy(retired.name, name, sizeof(retired.name));
	retired.device = device;
	ret = dm_verity_remove(&retired, false);
	if (ret && ret != -EBUSY && ret != -ENXIO && ret != -ENODEV)
		pr_warn("image: cannot remove retired mapping %s: %s", name,
			strerror(-ret));
	return 0;
}

static void collect_mappings(void)
{
	struct stat st;
	dev_t active = 0;
	int ret;

	if (image.update.lock_fd < 0)
		return;
	if (!stat(CONFIG_IMAGE_DIR, &st))
		active = st.st_dev;
	ret = dm_verity_list(collect_mapping, &active);
	if (ret)
		pr_warn("image: cannot collect retired mappings: %s",
			strerror(-ret));
}

static void close_candidate(void)
{
	if (image.candidate_fd >= 0)
		close(image.candidate_fd);
	image.candidate_fd = -1;
	if (image.update.lock_fd >= 0 &&
	    umount2(CONFIG_CANDIDATE_DIR, MNT_DETACH) &&
	    errno != EINVAL && errno != ENOENT)
		pr_warn("image: cannot release candidate mount: %s",
			strerror(errno));
	dm_verity_close(&image.candidate_device);
	config_image_close(&image.candidate);
}

static int remove_candidate(struct dm_verity *device)
{
	__u32 attempt;
	int ret;

	for (attempt = 0; attempt < 100; attempt++) {
		ret = dm_verity_remove(device, false);
		if (ret != -EBUSY)
			return ret;
		if (attempt < 99)
			nanosleep(&(struct timespec){ .tv_nsec = 10000000 }, NULL);
	}
	return ret;
}

static int candidate_keys(int fd)
{
	int ret;

	ret = keys_validate_image(fd);
	if (ret == -ENOKEY)
		pr_err("image: BPF signer was not enrolled at boot; "
		       "reboot with the new trusted key set required");
	return ret;
}

static int mount_candidate(struct image_context *current)
{
	struct dm_verity *device = &current->candidate_device;
	const char *mountpoint = CONFIG_CANDIDATE_DIR;
	struct stat st;
	int ret;

	if (!stat(CONFIG_IMAGE_DIR, &st) &&
	    st.st_dev == current->candidate_device.device) {
		current->candidate_fd = open(CONFIG_IMAGE_DIR,
					     O_PATH | O_DIRECTORY | O_CLOEXEC);
	} else {
		if (umount2(mountpoint, MNT_DETACH) &&
		    errno != EINVAL && errno != ENOENT)
			return -errno;
		ret = mkdir_owned(mountpoint);
		if (!ret)
			ret = dm_verity_mount(device, mountpoint, false);
		if (ret)
			return ret;
		current->candidate_fd = open(mountpoint,
					     O_PATH | O_DIRECTORY | O_CLOEXEC);
	}
	return current->candidate_fd < 0 ? -errno : 0;
}

static int prepare_config(struct image_context *current,
			  const struct config_update_target *target,
			  bool trusted_boot)
{
	struct dm_verity *device = &current->candidate_device;
	bool created = false;
	int ret, cleanup;
	char name[128];

	close_candidate();
	if (!trusted_boot)
		collect_mappings();
	if (strncmp(target->prefix, IMAGE_CACHE_DIR "/",
		    sizeof(IMAGE_CACHE_DIR)) ||
	    !image_path_valid(target->prefix))
		return -EPERM;
	ret = config_image_open(target->prefix, &current->candidate);
	if (ret)
		return ret;
	if (memcmp(target->root_hash, current->candidate.image.root_hash, 32))
		return -EKEYREJECTED;
	ret = mapping_name(target->root_hash, name);
	if (ret)
		return ret;
	ret = dm_verity_inspect(name, &current->candidate.image,
				device);
	if (ret == -ENXIO || ret == -ENODEV || ret == -ENOENT) {
		ret = dm_verity_create(&current->candidate, name,
				       device);
		created = !ret;
	}
	if (!ret)
		ret = dm_verity_verify(device, &current->candidate);
	if (!ret && !trusted_boot)
		ret = device_observed(current->candidate_device.device,
				      current->candidate.image.root_hash,
				      DEVICE_CONFIG);
	if (ret)
		goto out;
	ret = mount_candidate(current);
	if (ret)
		goto out;
	ret = mount_flags(current->candidate_fd, false);
	if (!ret)
		ret = image_config_validate(current->candidate_fd);
	if (!ret && !trusted_boot)
		ret = candidate_keys(current->candidate_fd);
out:
	if (ret && created) {
		close_candidate();
		cleanup = remove_candidate(device);
		if (cleanup && cleanup != -ENXIO && cleanup != -ENODEV)
			pr_warn("image: cannot remove rejected mapping %s: %s",
				device->name, strerror(-cleanup));
	}
	return ret;
}

static int activate_config(struct image_context *current, bool boot)
{
	struct stat st;
	int fd, ret;

	ret = keys_apply_image(current->candidate_fd, boot);
	if (ret)
		return ret;
	ret = mkdir_owned(CONFIG_IMAGE_DIR);
	if (ret)
		return ret;
	if (stat(CONFIG_IMAGE_DIR, &st))
		return -errno;
	if (st.st_dev != current->candidate_device.device) {
		if (umount2(CONFIG_IMAGE_DIR, MNT_DETACH) &&
		    errno != EINVAL)
			return -errno;
		ret = dm_verity_mount(&current->candidate_device,
				      CONFIG_IMAGE_DIR, false);
		if (ret)
			return ret;
	}
	fd = open(CONFIG_IMAGE_DIR, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st))
		ret = -errno;
	else if (st.st_dev != current->candidate_device.device)
		ret = -ESTALE;
	else
		ret = mount_flags(fd, false);
	if (!ret)
		ret = image_config_set(&current->bootstrap_config, fd);
	close(fd);
	return ret;
}

static int prepare_update(void *ctx,
			  const struct config_update_target *target)
{
	return prepare_config(ctx, target, false);
}

static int activate_update(void *ctx,
			   const struct config_update_target *target
			   __attribute__((__unused__)))
{
	return activate_config(ctx, false);
}

static int activate_boot(void *ctx,
			 const struct config_update_target *target
			 __attribute__((__unused__)))
{
	return activate_config(ctx, true);
}

static const struct config_update_ops update_ops = {
	.boot_identity = boot_identity,
	.pcr_read = pcr_read,
	.pcr_extend = pcr_extend,
	.prepare = prepare_update,
	.activate = activate_update,
	.seal = seal_fd,
	.lock_wait_ms = 30 * 1000,
};

static const struct config_update_ops boot_ops = {
	.boot_identity = boot_identity,
	.pcr_read = pcr_read,
	.pcr_extend = pcr_extend,
	.prepare = prepare_update,
	.activate = activate_boot,
	.seal = seal_fd,
};

static int open_update(void)
{
	int ret;

	if (image.update.lock_fd >= 0)
		return 0;
	ret = mkdir_owned(CONFIG_UPDATE_DIR);
	if (!ret)
		ret = tpm_open(&image.tpm);
	if (!ret)
		ret = chain_tpm_bound(image.tpm);
	if (!ret)
		ret = config_update_open(CONFIG_UPDATE_DIR,
					 &update_ops, &image,
					 &image.update);
	return ret;
}

static int boot_target(struct config_update_target *target)
{
	struct config_update_record previous;
	struct config_image_open opened;
	const char *prefix;
	bool selected;
	int ret;

	ret = config_update_read(&image.update, &previous);
	selected = !ret;
	prefix = selected ? previous.target.prefix : image.bootstrap.config;
	if (ret && ret != -ENOENT)
		return ret;
	ret = config_image_open(prefix, &opened);
	if (ret)
		return ret;
	if (selected && memcmp(previous.target.root_hash,
			       opened.image.root_hash, 32)) {
		ret = -EKEYREJECTED;
	} else {
		strscpy(target->prefix, prefix, sizeof(target->prefix));
		memcpy(target->root_hash, opened.image.root_hash, 32);
	}
	config_image_close(&opened);
	return ret;
}

static int boot_keys_error(const char *step, int ret)
{
	pr_err("initrd boot keys: %s: %s", step, strerror(-ret));
	return ret;
}

/*
 * The kernel trusts every key in the sealed keyring for config roots, so
 * whether init sealed it now or earlier this boot, it must hold exactly
 * the config certificate.
 */
static int seal_config_key(key_serial_t ring, const __u8 *der, size_t size)
{
	struct keyring_cert cert = { .der = der, .len = size };
	key_serial_t key;
	int ret;

	key = keyring_dm_verity_add_cert(der, size);
	if (key < 0 && key != -EPERM && key != -EACCES)
		return boot_keys_error("add config verification certificate",
				       (int)key);
	if (key < 0 && keyring_holds_exactly(ring, NULL, 0) == 1)
		return boot_keys_error("dm-verity keyring sealed empty at boot; "
				       "boot with dm_verity.keyring_unsealed=1",
				       -ENOKEY);
	if (key >= 0) {
		ret = keyring_dm_verity_seal();
		if (ret == -EEXIST)
			return boot_keys_error("seal dm-verity keyring restricted "
					       "by another task (tampered)",
					       -EKEYREJECTED);
		if (ret)
			return boot_keys_error("seal dm-verity keyring", ret);
	}
	ret = keyring_holds_exactly(ring, &cert, 1);
	if (ret <= 0)
		return boot_keys_error("check dm-verity keyring holds only the "
				       "config certificate",
				       ret ? ret : -EKEYREJECTED);
	return 0;
}

static int enroll_config_key(void)
{
	__u8 *der = NULL;
	key_serial_t ring;
	size_t size = 0;
	int ret;

	ret = image.certificate_fd < 0 ? -EBADF :
	     keys_read_der_fd(image.certificate_fd, &der, &size);
	if (ret)
		return boot_keys_error("read config verification certificate", ret);
	ring = keyring_dm_verity_serial();
	if (ring < 0) {
		ret = (int)ring;
		xfree(der, size);
		return boot_keys_error("lookup dm-verity keyring", ret);
	}
	ret = seal_config_key(ring, der, size);
	xfree(der, size);
	return ret;
}

/* The authenticated initrd validates the boot set before installing guards. */
int image_boot_keys(struct trusted_set *set)
{
	struct trusted_cert primary = { .primary = true };
	size_t i;
	int ret;

	/* These temporary mounts are released before loading the guards. */
	image.boot_keys_open = true;
	ret = mount_runtime(true);
	if (ret)
		return boot_keys_error("mount runtime", ret);
	ret = enroll_config_key();
	if (ret)
		return boot_keys_error("enrol config certificate", ret);
	ret = open_update();
	if (ret)
		return boot_keys_error("open config update state", ret);
	ret = boot_target(&image.boot_target);
	if (ret)
		return boot_keys_error("select boot config", ret);
	ret = prepare_config(&image, &image.boot_target, true);
	if (ret)
		return boot_keys_error("prepare boot config", ret);
	ret = keys_validate_image_set(RUNTIME_CERT_PATH,
				      image.candidate_fd, set);
	if (ret)
		return boot_keys_error("validate BPF trust set", ret);
	/* Guard loaders need the initial signer until activation. */
	strscpy(primary.path, RUNTIME_CERT_PATH, sizeof(primary.path));
	ret = keys_digest_file(primary.path, primary.sha256,
			       primary.fingerprint);
	if (ret)
		return boot_keys_error("digest primary certificate", ret);
	for (i = 0; i < set->n; i++)
		if (!memcmp(set->certs[i].sha256, primary.sha256, 32))
			break;
	if (i == set->n) {
		if (set->n == KEYS_MAX)
			return boot_keys_error("add runtime certificate to "
					       "trusted set", -E2BIG);
		set->certs[set->n++] = primary;
	}
	image.boot_target_valid = true;
	return 0;
}

int image_boot_keys_close(void)
{
	int ret = 0, err;

	if (!image.boot_keys_open)
		return 0;
	image_config_clear();
	if (image.candidate_fd >= 0)
		close(image.candidate_fd);
	image.candidate_fd = -1;
	if (image.certificate_fd >= 0)
		close(image.certificate_fd);
	image.certificate_fd = -1;
	if (umount(CONFIG_CANDIDATE_DIR) && errno != EINVAL &&
	    errno != ENOENT)
		ret = -errno;
	if (image.candidate_device.name[0]) {
		err = dm_verity_remove(&image.candidate_device, false);
		if (!ret && err && err != -ENXIO && err != -ENODEV)
			ret = err;
	}
	config_image_close(&image.candidate);
	if (umount(RUNTIME_DIR) && errno != EINVAL && errno != ENOENT &&
	    !ret)
		ret = -errno;
	if (image.boot_runtime.name[0]) {
		err = dm_verity_remove(&image.boot_runtime, false);
		if (!ret && err && err != -ENXIO && err != -ENODEV)
			ret = err;
	}
	image.boot_keys_open = false;
	return ret;
}

int image_boot(void)
{
	struct config_update_target target = {};
	int ret;

	ret = open_update();
	if (ret)
		return ret;
	if (image.boot_target_valid) {
		target = image.boot_target;
	} else {
		ret = boot_target(&target);
		if (ret)
			return ret;
	}
	/* Boot and live updates record key revocations differently. */
	image.update.ops = &boot_ops;
	ret = config_update_boot(&image.update, &target,
				 image.bootstrap.pcr);
	image.update.ops = &update_ops;
	if (ret == -EINPROGRESS)
		pr_err("image: activation is pending; further changes are blocked");
	return ret;
}

static int config_mount_check(const struct config_update_record *record)
{
	struct config_image_open opened;
	struct dm_verity device;
	struct stat st;
	char name[128];
	int fd, ret;

	ret = config_image_open(record->target.prefix, &opened);
	if (ret)
		return ret;
	if (memcmp(record->target.root_hash, opened.image.root_hash, 32))
		ret = -EKEYREJECTED;
	if (!ret)
		ret = mapping_name(record->target.root_hash, name);
	if (!ret)
		ret = dm_verity_inspect(name, &opened.image, &device);
	config_image_close(&opened);
	if (ret)
		return ret;
	if (stat(CONFIG_IMAGE_DIR, &st) || st.st_dev != device.device) {
		ret = -EUCLEAN;
		goto out;
	}
	ret = device_observed(device.device, record->target.root_hash,
			      DEVICE_CONFIG);
	if (ret)
		goto out;
	fd = open(CONFIG_IMAGE_DIR, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0) {
		ret = -errno;
		goto out;
	}
	if (fstat(fd, &st))
		ret = -errno;
	else if (st.st_dev != device.device)
		ret = -EUCLEAN;
	else
		ret = mount_flags(fd, false);
	if (!ret)
		ret = image_config_set(&image.bootstrap_config, fd);
	close(fd);
out:
	dm_verity_close(&device);
	return ret;
}

int image_boot_complete(void)
{
	struct config_update_record record;
	int ret;

	ret = config_update_read(&image.update, &record);
	if (!ret)
		ret = config_mount_check(&record);
	if (!ret)
		ret = config_update_complete_boot(&image.update);
	return ret;
}

static int current_config(void)
{
	struct config_update_record record;
	int ret;

	ret = open_update();
	if (!ret)
		ret = config_update_check(&image.update, &record);
	return ret ? ret : config_mount_check(&record);
}

/*
 * status is how a fleet sees these states, so it runs in them while every
 * other command refuses: with the pending config's settings when that is
 * the config mounted, and with the runtime image's alone otherwise, since
 * a config the record cannot vouch for names no export destination.
 */
static int status_config(int state)
{
	struct config_update_record record;

	image.config_state = state;
	if (state == -EINPROGRESS &&
	    !config_update_read(&image.update, &record))
		config_mount_check(&record);
	return 0;
}

int image_enter(const char *command, int argc, const char **argv)
{
	struct identity identity;
	int mode, ret;

	if (!strcmp(command, "image") && argc > 1 &&
	    (!strcmp(argv[1], "build") || !strcmp(argv[1], "verify") ||
	     !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h") ||
	     !strcmp(argv[1], "--list-cmds")))
		return 0;
	if (!strcmp(command, "init") || !strcmp(command, "genkey") ||
	    !strcmp(command, "build") || !strcmp(command, "help") ||
	    !strcmp(command, "version"))
		return 0;
	mode = enforcement_active();
	if (mode < 0)
		return mode;
	ret = identity_read(&identity);
	if (mode && ret)
		return ret;
	if (ret)
		return ret == -ENOENT || ret == -EPERM || ret == -EACCES ? 0 : ret;
	if (!mode)
		return -EPROTO;
	ret = image_bootstrap_load();
	if (ret < 0)
		return ret;
	ret = load_runtime_config(false);
	if (ret)
		return ret;
	for (int i = 1; i < argc; i++) {
		if (!strncmp(argv[i], "--keys-dir", 10) ||
		    !strncmp(argv[i], "--cert", 6) ||
		    !strncmp(argv[i], "--tcti", 6))
			return -EPERM;
	}
	if (!strcmp(command, "image"))
		return open_update();
	ret = current_config();
	if (!strcmp(command, "status") &&
	    (ret == -EINPROGRESS || ret == -EUCLEAN || ret == -ESTALE ||
	     ret == -EKEYREJECTED))
		return status_config(ret);
	return ret;
}

int image_config_state(__u8 root[32])
{
	struct config_update_record record;

	if (image.update.lock_fd < 0)
		return -ENODEV;
	if (config_update_read(&image.update, &record))
		memset(root, 0, 32);
	else
		memcpy(root, record.target.root_hash, 32);
	return image.config_state;
}

int image_status(void)
{
	struct config_update_record record;
	char buffer[512], root[65];
	struct json_emit emit = {
		.buf = buffer,
		.cap = sizeof(buffer),
	};
	int ret;

	if (image.update.lock_fd < 0)
		return -ENODEV;
	ret = config_update_read(&image.update, &record);
	if (ret)
		return ret;
	hex_encode(record.target.root_hash, 32, root);
	ret = record.pending ? -EINPROGRESS : current_config();
	json_obj_open(&emit);
	json_kv_string(&emit, "root_hash", root);
	json_kv_int(&emit, "pcr", record.pcr);
	json_kv_int(&emit, "sequence", record.sequence);
	json_kv_int(&emit, "reset_count", record.reset_count);
	json_kv_int(&emit, "restart_count", record.restart_count);
	json_kv_bool(&emit, "pending", record.pending);
	json_kv_bool(&emit, "consistent", !ret);
	json_obj_close(&emit);
	if (emit.err)
		return emit.err;
	puts(buffer);
	return ret;
}

void image_leave(void)
{
	image_boot_keys_close();
	image_config_clear();
	close_candidate();
	collect_mappings();
	if (image.update.lock_fd >= 0)
		config_update_close(&image.update);
	tpm_close(image.tpm);
	image.tpm = NULL;
	if (image.certificate_fd >= 0)
		close(image.certificate_fd);
	image.certificate_fd = -1;
	memzero_explicit(&image.bootstrap_config, sizeof(image.bootstrap_config));
}

int image_update(const char *prefix)
{
	struct config_update_target target = {};
	int ret;

	if (image.update.lock_fd < 0)
		return -ENODEV;
	ret = current_config();
	if (!ret)
		ret = mkdir_owned(IMAGE_CACHE_DIR);
	if (!ret)
		ret = image_cache_fetch(prefix, &target);
	if (!ret)
		ret = config_update_begin(&image.update, &target,
					  image.bootstrap.pcr);
	return ret;
}
