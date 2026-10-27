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
#include <unistd.h>

#include <bpf/bpf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "../builtin.h"
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
#include "macros.h"
#include "paths.h"
#include "seal.h"
#include "shirudo_enforcement.h"
#include "tpm.h"

struct image_context {
	struct shirudo_config_update_target boot_target;
	struct shirudo_dm_verity boot_runtime;
	struct shirudo_config_update update;
	struct shirudo_config_image_open candidate;
	struct shirudo_dm_verity candidate_device;
	struct shirudo_config bootstrap_config;
	struct shirudo_image_bootstrap bootstrap;
	struct shirudo_tpm *tpm;
	int candidate_fd;
	int certificate_fd;
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

struct shirudo_config_update *shirudo_image_update_context(void)
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

int shirudo_image_bootstrap_load(void)
{
	struct shirudo_identity identity;
	int mode, rc;

	if (image.loaded)
		return 1;
	mode = shirudo_enforcement_active();
	if (mode < 0)
		return mode;
	rc = identity_read(&identity);
	if (mode && rc)
		return rc;
	if (!rc && !mode)
		return -EPROTO;
	if (!rc) {
		memcpy(image.bootstrap.runtime_root, identity.runtime_root, 32);
		image.bootstrap.have_root = true;
		rc = load_runtime_config(false);
	} else {
		rc = shirudo_image_bootstrap_read(SHIRUDO_CONF_PATH,
						  &image.bootstrap, true);
		if (!rc &&
		    (!image.bootstrap.runtime[0] || !image.bootstrap.have_root))
			rc = -EINVAL;
		if (!rc)
			rc = config_load_path(&image.bootstrap_config,
					      SHIRUDO_CONF_PATH);
	}
	if (rc)
		return rc;
	rc = reject_overrides();
	if (rc)
		return rc;
	rc = shirudo_image_config_set(&image.bootstrap_config, -1);
	if (!rc)
		image.loaded = true;
	return rc ? rc : 1;
}

const __u8 *shirudo_image_runtime_root(void)
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
	struct shirudo_device_authority entry;
	__u32 dev = (major(device) << 20) | minor(device);
	__u64 key, next, diskseq;
	struct stat st;
	char path[64];
	int fd, block, rc = -EACCES;

	if (strsprintf(path, sizeof(path), "/dev/dm-%u", minor(device)) < 0)
		return -ENAMETOOLONG;
	block = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (block < 0)
		return -errno;
	if (fstat(block, &st) || !S_ISBLK(st.st_mode) || st.st_rdev != device ||
	    ioctl(block, BLKGETDISKSEQ, &diskseq)) {
		rc = errno ? -errno : -EPERM;
		close(block);
		return rc;
	}
	fd = bpf_obj_get(SHIRUDO_BPFFS_DIR "/devices");
	if (fd < 0) {
		rc = -errno;
		goto out_block;
	}
	if (bpf_map_get_next_key(fd, NULL, &key))
		goto out;
	do {
		if (!bpf_map_lookup_elem(fd, &key, &entry) &&
		    entry.dev == dev && entry.kind == kind &&
		    entry.diskseq == diskseq &&
		    (!root || !memcmp(entry.root, root, 32))) {
			rc = 0;
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
	return rc;
}

static int runtime_observed(dev_t device)
{
	return device_observed(device, image.bootstrap.runtime_root,
			       SHIRUDO_DEVICE_RUNTIME);
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
	int fd, rc;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -errno;
	rc = fstat(fd, &st) ? -errno : 0;
	if (!rc && (!S_ISREG(st.st_mode) || st.st_dev != device))
		rc = -EPERM;
	if (rc) {
		close(fd);
		return rc;
	}
	return fd;
}

static int load_runtime_config(bool trusted_boot)
{
	struct stat root;
	char path[64];
	int fd, rc;

	if (!trusted_boot) {
		rc = shirudo_image_guards_ready();
		if (rc)
			return rc;
	}
	if (stat(SHIRUDO_RUNTIME_DIR, &root))
		return -errno;
	if (!trusted_boot) {
		rc = runtime_observed(root.st_dev);
		if (rc)
			return rc;
	}

	fd = open_runtime_file(SHIRUDO_RUNTIME_CONF_PATH, root.st_dev);
	if (fd < 0)
		return fd;
	if (strsprintf(path, sizeof(path), "/proc/self/fd/%d", fd) < 0)
		rc = -ENAMETOOLONG;
	else
		rc = shirudo_image_bootstrap_read(path, &image.bootstrap, false);
	if (!rc)
		rc = config_load_path(&image.bootstrap_config, path);
	close(fd);
	if (rc)
		return rc;
	if (!image.bootstrap.config[0] || !image.bootstrap.certificate[0] ||
	    !image.bootstrap.have_pcr)
		return -EINVAL;
	rc = shirudo_image_config_set(&image.bootstrap_config, -1);
	if (rc)
		return rc;

	fd = open_runtime_file(image.bootstrap.certificate, root.st_dev);
	if (fd < 0)
		return fd;
	if (image.certificate_fd >= 0)
		close(image.certificate_fd);
	image.certificate_fd = fd;

	fd = open_runtime_file(SHIRUDO_RUNTIME_CERT_PATH, root.st_dev);
	if (fd < 0)
		return fd;
	rc = mount_flags(fd, true);
	close(fd);
	if (rc)
		return rc;

	/* Keep the verified config certificate open through key enrollment. */
	if (strsprintf(image.bootstrap.certificate,
		       sizeof(image.bootstrap.certificate), "/proc/self/fd/%d",
		       image.certificate_fd) < 0)
		return -ENAMETOOLONG;
	return 0;
}

/* The initrd checks the runtime against its authenticated UKI root. */
static int mount_runtime(bool trusted_boot)
{
	const char *step = "open runtime image";
	struct shirudo_config_image_open opened = {
		.data_fd = -1,
		.hash_fd = -1,
		.signature_fd = -1,
	};
	struct shirudo_dm_verity device = {
		.data_loop_fd = -1,
		.hash_loop_fd = -1,
	};
	bool created = false;
	int rc, cleanup;
	struct stat st;

	if (!image.loaded)
		return -EINVAL;
	if (!trusted_boot && !stat(SHIRUDO_RUNTIME_DIR, &st) &&
	    !runtime_observed(st.st_dev))
		return load_runtime_config(trusted_boot);
	rc = shirudo_config_image_open_root(image.bootstrap.runtime,
					    image.bootstrap.runtime_root,
					    &opened);
	if (!rc) {
		step = "prepare runtime mountpoint";
		rc = mkdir_owned(SHIRUDO_RUNTIME_DIR);
	}
	if (!rc) {
		step = "create runtime dm-verity mapping";
		rc = shirudo_dm_verity_create(&opened, "shirudo-runtime",
					      &device);
		created = !rc;
	}
	if (rc == -EEXIST) {
		step = "inspect runtime dm-verity mapping";
		rc = shirudo_dm_verity_inspect("shirudo-runtime", &opened.image,
					       &device);
	}
	if (!rc) {
		step = "verify runtime image";
		rc = shirudo_dm_verity_verify(&device, &opened);
	}
	if (!rc) {
		step = "mount runtime image";
		rc = shirudo_dm_verity_mount(&device, SHIRUDO_RUNTIME_DIR,
					     true);
	}
	if (rc && created) {
		cleanup = shirudo_dm_verity_remove(&device, false);
		if (cleanup)
			pr_warn("image: cannot remove runtime mapping: %s",
				strerror(-cleanup));
	}
	shirudo_dm_verity_close(&device);
	if (!rc && trusted_boot)
		image.boot_runtime = device;
	shirudo_config_image_close(&opened);
	if (!rc) {
		step = "load runtime config";
		rc = load_runtime_config(trusted_boot);
	}
	if (rc)
		pr_err("image: %s: %s", step, strerror(-rc));
	return rc;
}

int shirudo_image_runtime_mount(void)
{
	return mount_runtime(false);
}

static int seal_fd(void *ctx, int fd)
{
	(void)ctx;
	return fsetxattr(fd, SHIRUDO_XATTR_NAME, SHIRUDO_SEAL_LABEL,
			 strlen(SHIRUDO_SEAL_LABEL), 0) ?
		       -errno :
		       0;
}

static int boot_identity(void *ctx, __u32 *reset, __u32 *restart)
{
	struct image_context *current = ctx;

	return shirudo_tpm_boot_identity(current->tpm, reset, restart);
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
	struct shirudo_dm_verity retired = {
		.data_loop_fd = -1,
		.hash_loop_fd = -1,
	};
	const dev_t *active = ctx;
	int rc;

	if (device == *active ||
	    device_observed(device, NULL, SHIRUDO_DEVICE_CONFIG))
		return 0;
	if (strlen(name) >= sizeof(retired.name))
		return -ENAMETOOLONG;
	strscpy(retired.name, name, sizeof(retired.name));
	retired.device = device;
	rc = shirudo_dm_verity_remove(&retired, false);
	if (rc && rc != -EBUSY && rc != -ENXIO && rc != -ENODEV)
		pr_warn("image: cannot remove retired mapping %s: %s", name,
			strerror(-rc));
	return 0;
}

static void collect_mappings(void)
{
	struct stat st;
	dev_t active = 0;
	int rc;

	if (image.update.lock_fd < 0)
		return;
	if (!stat(SHIRUDO_CONFIG_IMAGE_DIR, &st))
		active = st.st_dev;
	rc = shirudo_dm_verity_list(collect_mapping, &active);
	if (rc)
		pr_warn("image: cannot collect retired mappings: %s",
			strerror(-rc));
}

static void close_candidate(void)
{
	if (image.candidate_fd >= 0)
		close(image.candidate_fd);
	image.candidate_fd = -1;
	if (image.update.lock_fd >= 0 &&
	    umount2(SHIRUDO_CONFIG_CANDIDATE_DIR, MNT_DETACH) &&
	    errno != EINVAL && errno != ENOENT)
		pr_warn("image: cannot release candidate mount: %s",
			strerror(errno));
	shirudo_dm_verity_close(&image.candidate_device);
	shirudo_config_image_close(&image.candidate);
}

static int remove_candidate(struct shirudo_dm_verity *device)
{
	__u32 attempt;
	int rc;

	for (attempt = 0; attempt < 100; attempt++) {
		rc = shirudo_dm_verity_remove(device, false);
		if (rc != -EBUSY)
			return rc;
		if (attempt < 99)
			usleep(10000);
	}
	return rc;
}

static int candidate_keys(int fd)
{
	int rc;

	rc = shirudo_keys_validate_image(fd);
	if (rc == -ENOKEY)
		pr_err("image: BPF signer was not enrolled at boot; "
		       "reboot with the new trusted key set required");
	return rc;
}

static int mount_candidate(struct image_context *current)
{
	struct shirudo_dm_verity *device = &current->candidate_device;
	const char *mountpoint = SHIRUDO_CONFIG_CANDIDATE_DIR;
	struct stat st;
	int rc;

	if (!stat(SHIRUDO_CONFIG_IMAGE_DIR, &st) &&
	    st.st_dev == current->candidate_device.device) {
		current->candidate_fd = open(SHIRUDO_CONFIG_IMAGE_DIR,
					     O_PATH | O_DIRECTORY | O_CLOEXEC);
	} else {
		if (umount2(mountpoint, MNT_DETACH) &&
		    errno != EINVAL && errno != ENOENT)
			return -errno;
		rc = mkdir_owned(mountpoint);
		if (!rc)
			rc = shirudo_dm_verity_mount(device, mountpoint, false);
		if (rc)
			return rc;
		current->candidate_fd = open(mountpoint,
					     O_PATH | O_DIRECTORY | O_CLOEXEC);
	}
	return current->candidate_fd < 0 ? -errno : 0;
}

static int prepare_config(struct image_context *current,
			  const struct shirudo_config_update_target *target,
			  bool trusted_boot)
{
	struct shirudo_dm_verity *device = &current->candidate_device;
	bool created = false;
	int rc, cleanup;
	char name[128];

	close_candidate();
	if (!trusted_boot)
		collect_mappings();
	if (strncmp(target->prefix, SHIRUDO_IMAGE_CACHE_DIR "/",
		    sizeof(SHIRUDO_IMAGE_CACHE_DIR)) ||
	    !shirudo_image_path_valid(target->prefix))
		return -EPERM;
	rc = shirudo_config_image_open(target->prefix, &current->candidate);
	if (rc)
		return rc;
	if (memcmp(target->root_hash, current->candidate.image.root_hash, 32))
		return -EKEYREJECTED;
	rc = mapping_name(target->root_hash, name);
	if (rc)
		return rc;
	rc = shirudo_dm_verity_inspect(name, &current->candidate.image,
				       device);
	if (rc == -ENXIO || rc == -ENODEV || rc == -ENOENT) {
		rc = shirudo_dm_verity_create(&current->candidate, name,
					      device);
		created = !rc;
	}
	if (!rc)
		rc = shirudo_dm_verity_verify(device, &current->candidate);
	if (!rc && !trusted_boot)
		rc = device_observed(current->candidate_device.device,
				     current->candidate.image.root_hash,
				     SHIRUDO_DEVICE_CONFIG);
	if (rc)
		goto out;
	rc = mount_candidate(current);
	if (rc)
		goto out;
	rc = mount_flags(current->candidate_fd, false);
	if (!rc)
		rc = shirudo_image_config_validate(current->candidate_fd);
	if (!rc && !trusted_boot)
		rc = candidate_keys(current->candidate_fd);
out:
	if (rc && created) {
		close_candidate();
		cleanup = remove_candidate(device);
		if (cleanup && cleanup != -ENXIO && cleanup != -ENODEV)
			pr_warn("image: cannot remove rejected mapping %s: %s",
				device->name, strerror(-cleanup));
	}
	return rc;
}

static int activate_config(struct image_context *current, bool boot)
{
	struct stat st;
	int fd, rc;

	rc = shirudo_keys_apply_image(current->candidate_fd, boot);
	if (rc)
		return rc;
	rc = mkdir_owned(SHIRUDO_CONFIG_IMAGE_DIR);
	if (rc)
		return rc;
	if (stat(SHIRUDO_CONFIG_IMAGE_DIR, &st))
		return -errno;
	if (st.st_dev != current->candidate_device.device) {
		if (umount2(SHIRUDO_CONFIG_IMAGE_DIR, MNT_DETACH) &&
		    errno != EINVAL)
			return -errno;
		rc = shirudo_dm_verity_mount(&current->candidate_device,
					     SHIRUDO_CONFIG_IMAGE_DIR, false);
		if (rc)
			return rc;
	}
	fd = open(SHIRUDO_CONFIG_IMAGE_DIR, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st))
		rc = -errno;
	else if (st.st_dev != current->candidate_device.device)
		rc = -ESTALE;
	else
		rc = mount_flags(fd, false);
	if (!rc)
		rc = shirudo_image_config_set(&current->bootstrap_config, fd);
	close(fd);
	return rc;
}

static int prepare_update(void *ctx,
			  const struct shirudo_config_update_target *target)
{
	return prepare_config(ctx, target, false);
}

static int activate_update(void *ctx,
			   const struct shirudo_config_update_target *target)
{
	(void)target;
	return activate_config(ctx, false);
}

static int activate_boot(void *ctx,
			 const struct shirudo_config_update_target *target)
{
	(void)target;
	return activate_config(ctx, true);
}

static const struct shirudo_config_update_ops update_ops = {
	.boot_identity = boot_identity,
	.pcr_read = pcr_read,
	.pcr_extend = pcr_extend,
	.prepare = prepare_update,
	.activate = activate_update,
	.seal = seal_fd,
};

static const struct shirudo_config_update_ops boot_ops = {
	.boot_identity = boot_identity,
	.pcr_read = pcr_read,
	.pcr_extend = pcr_extend,
	.prepare = prepare_update,
	.activate = activate_boot,
	.seal = seal_fd,
};

static int open_update(void)
{
	int rc;

	if (image.update.lock_fd >= 0)
		return 0;
	rc = mkdir_owned(SHIRUDO_CONFIG_UPDATE_DIR);
	if (!rc)
		rc = tpm_open(&image.tpm);
	if (!rc)
		rc = shirudo_config_update_open(SHIRUDO_CONFIG_UPDATE_DIR,
						&update_ops, &image,
						&image.update);
	return rc;
}

static int boot_target(struct shirudo_config_update_target *target)
{
	struct shirudo_config_update_record previous;
	struct shirudo_config_image_open opened;
	const char *prefix;
	bool selected;
	int rc;

	rc = shirudo_config_update_read(&image.update, &previous);
	selected = !rc;
	prefix = selected ? previous.target.prefix : image.bootstrap.config;
	if (rc && rc != -ENOENT)
		return rc;
	rc = shirudo_config_image_open(prefix, &opened);
	if (rc)
		return rc;
	if (selected && memcmp(previous.target.root_hash,
			       opened.image.root_hash, 32)) {
		rc = -EKEYREJECTED;
	} else {
		strscpy(target->prefix, prefix, sizeof(target->prefix));
		memcpy(target->root_hash, opened.image.root_hash, 32);
	}
	shirudo_config_image_close(&opened);
	return rc;
}

static int boot_keys_error(const char *step, int rc)
{
	pr_err("initrd boot keys: %s: %s", step, strerror(-rc));
	return rc;
}

static int enroll_config_key(void)
{
	__u8 *der = NULL;
	const char *step = "read config verification certificate";
	key_serial_t ring;
	size_t size = 0;
	int rc;

	rc = keys_read_der(image.bootstrap.certificate, &der, &size);
	if (rc)
		goto fail;
	step = "lookup dm-verity keyring";
	ring = shirudo_keyring_dm_verity_serial();
	if (ring < 0) {
		rc = (int)ring;
		goto fail;
	}
	step = "check config certificate enrollment";
	rc = keyring_holds_cert(ring, der, size);
	if (rc < 0)
		goto fail;
	if (!rc) {
		step = "add config verification certificate";
		rc = shirudo_keyring_dm_verity_add_cert(der, size);
		if (rc < 0)
			goto fail;
	}
	xfree(der, size);
	step = "seal dm-verity keyring";
	rc = shirudo_keyring_dm_verity_seal();
	if (rc == -EEXIST)
		return 0;
	if (rc)
		return boot_keys_error(step, rc);
	return 0;

fail:
	xfree(der, size);
	return boot_keys_error(step, rc);
}

/* The authenticated initrd validates the boot set before installing guards. */
int shirudo_image_boot_keys(struct shirudo_trusted_set *set)
{
	struct shirudo_trusted_cert primary = { .primary = true };
	const char *step = "mount runtime";
	size_t i;
	int rc;

	/* These temporary mounts are released before loading the guards. */
	image.boot_keys_open = true;
	rc = mount_runtime(true);
	if (rc)
		goto fail;
	step = "enrol config certificate";
	rc = enroll_config_key();
	if (rc)
		goto fail;
	step = "open config update state";
	rc = open_update();
	if (rc)
		goto fail;
	step = "select boot config";
	rc = boot_target(&image.boot_target);
	if (rc)
		goto fail;
	step = "prepare boot config";
	rc = prepare_config(&image, &image.boot_target, true);
	if (rc)
		goto fail;
	step = "validate BPF trust set";
	rc = shirudo_keys_validate_image_set(SHIRUDO_RUNTIME_CERT_PATH,
					     image.candidate_fd, set);
	if (rc)
		goto fail;

	/* Guard loaders need the initial signer until activation. */
	step = "digest primary certificate";
	strscpy(primary.path, SHIRUDO_RUNTIME_CERT_PATH, sizeof(primary.path));
	rc = keys_digest_file(primary.path, primary.sha256,
			      primary.fingerprint);
	if (rc)
		goto fail;
	for (i = 0; i < set->n; i++)
		if (!memcmp(set->certs[i].sha256, primary.sha256, 32))
			break;
	if (i == set->n) {
		if (set->n == SHIRUDO_KEYS_MAX) {
			rc = -E2BIG;
			step = "add runtime certificate to trusted set";
			goto fail;
		}
		set->certs[set->n++] = primary;
	}
	image.boot_target_valid = true;
	return 0;

fail:
	return boot_keys_error(step, rc);
}

int shirudo_image_boot_keys_close(void)
{
	int rc = 0, err;

	if (!image.boot_keys_open)
		return 0;
	shirudo_image_config_clear();
	if (image.candidate_fd >= 0)
		close(image.candidate_fd);
	image.candidate_fd = -1;
	if (image.certificate_fd >= 0)
		close(image.certificate_fd);
	image.certificate_fd = -1;
	if (umount(SHIRUDO_CONFIG_CANDIDATE_DIR) && errno != EINVAL &&
	    errno != ENOENT)
		rc = -errno;
	if (image.candidate_device.name[0]) {
		err = shirudo_dm_verity_remove(&image.candidate_device, false);
		if (!rc && err && err != -ENXIO && err != -ENODEV)
			rc = err;
	}
	shirudo_config_image_close(&image.candidate);
	if (umount(SHIRUDO_RUNTIME_DIR) && errno != EINVAL && errno != ENOENT &&
	    !rc)
		rc = -errno;
	if (image.boot_runtime.name[0]) {
		err = shirudo_dm_verity_remove(&image.boot_runtime, false);
		if (!rc && err && err != -ENXIO && err != -ENODEV)
			rc = err;
	}
	image.boot_keys_open = false;
	return rc;
}

int shirudo_image_boot(void)
{
	struct shirudo_config_update_target target = {};
	int rc;

	rc = open_update();
	if (rc)
		return rc;
	if (image.boot_target_valid) {
		target = image.boot_target;
	} else {
		rc = boot_target(&target);
		if (rc)
			return rc;
	}
	/* Boot and live updates record key revocations differently. */
	image.update.ops = &boot_ops;
	rc = shirudo_config_update_boot(&image.update, &target,
					image.bootstrap.pcr);
	image.update.ops = &update_ops;
	if (rc == -EINPROGRESS)
		pr_err("image: activation is pending; further changes are blocked");
	return rc;
}

static int config_mount_check(const struct shirudo_config_update_record *record)
{
	struct shirudo_config_image_open opened;
	struct shirudo_dm_verity device;
	struct stat st;
	char name[128];
	int fd, rc;

	rc = shirudo_config_image_open(record->target.prefix, &opened);
	if (rc)
		return rc;
	if (memcmp(record->target.root_hash, opened.image.root_hash, 32))
		rc = -EKEYREJECTED;
	if (!rc)
		rc = mapping_name(record->target.root_hash, name);
	if (!rc)
		rc = shirudo_dm_verity_inspect(name, &opened.image, &device);
	shirudo_config_image_close(&opened);
	if (rc)
		return rc;
	if (stat(SHIRUDO_CONFIG_IMAGE_DIR, &st) || st.st_dev != device.device) {
		rc = -EUCLEAN;
		goto out;
	}
	rc = device_observed(device.device, record->target.root_hash,
			     SHIRUDO_DEVICE_CONFIG);
	if (rc)
		goto out;
	fd = open(SHIRUDO_CONFIG_IMAGE_DIR, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0) {
		rc = -errno;
		goto out;
	}
	rc = mount_flags(fd, false);
	if (!rc)
		rc = shirudo_image_config_set(&image.bootstrap_config, fd);
	close(fd);
out:
	shirudo_dm_verity_close(&device);
	return rc;
}

int shirudo_image_boot_complete(void)
{
	struct shirudo_config_update_record record;
	int rc;

	rc = shirudo_config_update_read(&image.update, &record);
	if (!rc)
		rc = config_mount_check(&record);
	if (!rc)
		rc = shirudo_config_update_complete_boot(&image.update);
	return rc;
}

static int current_config(void)
{
	struct shirudo_config_update_record record;
	int rc;

	rc = open_update();
	if (!rc)
		rc = shirudo_config_update_check(&image.update, &record);
	return rc ? rc : config_mount_check(&record);
}

int shirudo_image_enter(const char *command, int argc, const char **argv)
{
	struct shirudo_identity identity;
	int mode, rc;

	if (!strcmp(command, "image") && argc > 1 &&
	    (!strcmp(argv[1], "build") || !strcmp(argv[1], "verify") ||
	     !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h") ||
	     !strcmp(argv[1], "--list-cmds")))
		return 0;
	if (!strcmp(command, "init") || !strcmp(command, "genkey") ||
	    !strcmp(command, "build") || !strcmp(command, "help") ||
	    !strcmp(command, "version"))
		return 0;
	mode = shirudo_enforcement_active();
	if (mode < 0)
		return mode;
	rc = identity_read(&identity);
	if (mode && rc)
		return rc;
	if (rc)
		return rc == -ENOENT || rc == -EPERM || rc == -EACCES ? 0 : rc;
	if (!mode)
		return -EPROTO;
	rc = shirudo_image_bootstrap_load();
	if (rc < 0)
		return rc;
	rc = load_runtime_config(false);
	if (rc)
		return rc;
	for (int i = 1; i < argc; i++) {
		if (!strncmp(argv[i], "--keys-dir", 10) ||
		    !strncmp(argv[i], "--cert", 6) ||
		    !strncmp(argv[i], "--tcti", 6))
			return -EPERM;
	}
	if (!strcmp(command, "image"))
		return open_update();
	return current_config();
}

int shirudo_image_status(void)
{
	struct shirudo_config_update_record record;
	char buffer[512], root[65];
	struct shirudo_json_emit emit = {
		.buf = buffer,
		.cap = sizeof(buffer),
	};
	int rc;

	if (image.update.lock_fd < 0)
		return -ENODEV;
	rc = shirudo_config_update_read(&image.update, &record);
	if (rc)
		return rc;
	hex_encode(record.target.root_hash, 32, root);
	rc = record.pending ? -EINPROGRESS : current_config();
	json_obj_open(&emit);
	json_kv_string(&emit, "root_hash", root);
	json_kv_int(&emit, "pcr", record.pcr);
	json_kv_int(&emit, "sequence", record.sequence);
	json_kv_int(&emit, "reset_count", record.reset_count);
	json_kv_int(&emit, "restart_count", record.restart_count);
	json_kv_bool(&emit, "pending", record.pending);
	json_kv_bool(&emit, "consistent", !rc);
	json_obj_close(&emit);
	if (emit.err)
		return emit.err;
	puts(buffer);
	return rc;
}

void shirudo_image_leave(void)
{
	(void)shirudo_image_boot_keys_close();
	shirudo_image_config_clear();
	close_candidate();
	collect_mappings();
	if (image.update.lock_fd >= 0)
		shirudo_config_update_close(&image.update);
	tpm_close(image.tpm);
	image.tpm = NULL;
	if (image.certificate_fd >= 0)
		close(image.certificate_fd);
	image.certificate_fd = -1;
	explicit_bzero(&image.bootstrap_config, sizeof(image.bootstrap_config));
}

int shirudo_image_update(const char *prefix)
{
	struct shirudo_config_update_target target = {};
	int rc;

	if (image.update.lock_fd < 0)
		return -ENODEV;
	rc = current_config();
	if (!rc)
		rc = mkdir_owned(SHIRUDO_IMAGE_CACHE_DIR);
	if (!rc)
		rc = shirudo_image_cache_fetch(prefix, &target);
	if (!rc)
		rc = shirudo_config_update_begin(&image.update, &target,
						 image.bootstrap.pcr);
	return rc;
}
