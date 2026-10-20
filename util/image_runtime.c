// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>
#include <shirudo/string.h>

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

#include "../builtin.h"
#include "config.h"
#include "config_image.h"
#include "config_measure.h"
#include "config_update.h"
#include "crypto.h"
#include "dm_verity.h"
#include "hex.h"
#include "identity.h"
#include "image_bootstrap.h"
#include "image_cache.h"
#include "image_config.h"
#include "image_guards.h"
#include "image_runtime.h"
#include "io.h"
#include "json.h"
#include "keys.h"
#include "keyring.h"
#include "malloc.h"
#include "log.h"
#include "macros.h"
#include "paths.h"
#include "seal.h"
#include "shirudo_mode.h"
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
	bool locked;
	bool preparing_boot;
	bool boot_prepared;
	bool boot_activation;
};

static struct image_context image = {
	.candidate_fd = -1,
	.certificate_fd = -1,
	.candidate = { .data_fd = -1, .hash_fd = -1, .signature_fd = -1 },
	.candidate_device = { .data_loop_fd = -1, .hash_loop_fd = -1 },
};

#include "image_keys.h"

static int load_runtime_config(void);
static int current_config(void);

struct shirudo_config_update *shirudo_image_update_context(void)
{
	return image.locked ? &image.update : NULL;
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
			pr_err("image mode: bootstrap override %s is forbidden",
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
	mode = shirudo_identity_mode();
	if (mode < 0)
		return mode;
	rc = identity_read(&identity);
	if (mode != SHIRUDO_MODE_NONE && rc)
		return rc;
	if (!rc && mode != (identity.runtime_mode ?
		SHIRUDO_MODE_IMAGE : SHIRUDO_MODE_LEGACY))
		return -EPROTO;
	if (!rc && identity.runtime_mode) {
		memcpy(image.bootstrap.runtime_root, identity.runtime_root, 32);
		image.bootstrap.have_root = true;
		rc = load_runtime_config();
	} else {
		rc = shirudo_image_bootstrap_read(SHIRUDO_CONF_PATH,
						  &image.bootstrap, true);
		if (rc == -ENOENT)
			return 0;
		if (!rc && !image.bootstrap.runtime[0] &&
		    !image.bootstrap.have_root)
			return 0;
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

static void mapping_name(const __u8 root[32], char out[128])
{
	char hex[65];

	hex_encode(root, 32, hex);
	snprintf(out, 128, "shirudo-config-%s", hex);
}

static int device_observed(dev_t device, const __u8 root[32], __u32 kind)
{
	struct shirudo_device_authority entry;
	__u32 dev = (major(device) << 20) | minor(device);
	__u64 key, next, diskseq;
	struct stat st;
	char path[64];
	int fd, block, rc = -EACCES;

	snprintf(path, sizeof(path), "/dev/dm-%u", minor(device));
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

static int load_runtime_config(void)
{
	struct stat root, cert;
	char certificate[64];
	int rc;

	if (!image.preparing_boot) {
		rc = shirudo_image_guards_ready();
		if (rc)
			return rc;
	}
	if (stat(SHIRUDO_RUNTIME_DIR, &root))
		return -errno;
	if (!image.preparing_boot) {
		rc = runtime_observed(root.st_dev);
		if (rc)
			return rc;
	}
	{
		struct stat metadata;
		char path[64];
		int fd;

		fd = open(SHIRUDO_RUNTIME_CONF_PATH,
			  O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
		if (fd < 0)
			return -errno;
		rc = fstat(fd, &metadata) ? -errno : 0;
		if (!rc && (!S_ISREG(metadata.st_mode) ||
			    metadata.st_dev != root.st_dev))
			rc = -EPERM;
		snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
		if (!rc)
			rc = shirudo_image_bootstrap_read(path,
							  &image.bootstrap,
							  false);
		if (!rc)
			rc = config_load_path(&image.bootstrap_config,
					      path);
		close(fd);
	}
	if (rc)
		return rc;
	if (!image.bootstrap.config[0] || !image.bootstrap.certificate[0] ||
	    !image.bootstrap.have_pcr)
		return -EINVAL;
	rc = shirudo_image_config_set(&image.bootstrap_config, -1);
	if (rc)
		return rc;
	if (image.certificate_fd >= 0)
		close(image.certificate_fd);
	image.certificate_fd = open(image.bootstrap.certificate,
				    O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (image.certificate_fd < 0)
		return -errno;
	if (fstat(image.certificate_fd, &cert))
		return -errno;
	if (!S_ISREG(cert.st_mode) || cert.st_dev != root.st_dev)
		return -EPERM;
	{
		int fd = open(SHIRUDO_RUNTIME_CERT_PATH,
			      O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

		if (fd < 0)
			return -errno;
		rc = fstat(fd, &cert) ? -errno : 0;
		if (!rc &&
		    (!S_ISREG(cert.st_mode) || cert.st_dev != root.st_dev))
			rc = -EPERM;
		if (!rc)
			rc = mount_flags(fd, true);
		close(fd);
		if (rc)
			return rc;
	}
	snprintf(certificate, sizeof(certificate), "/proc/self/fd/%d",
		 image.certificate_fd);
	strscpy(image.bootstrap.certificate, certificate, sizeof(image.bootstrap.certificate));
	return 0;
}

int shirudo_image_runtime_mount(void)
{
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
	if (!image.preparing_boot && !stat(SHIRUDO_RUNTIME_DIR, &st) &&
	    !runtime_observed(st.st_dev))
		return load_runtime_config();
	rc = shirudo_config_image_open_root(image.bootstrap.runtime,
					    image.bootstrap.runtime_root,
					    &opened);
	if (rc)
		return rc;
	rc = mkdir_owned(SHIRUDO_RUNTIME_DIR);
	if (!rc) {
		rc = shirudo_dm_verity_create(&opened, "shirudo-runtime",
					      &device);
		created = !rc;
	}
	if (rc == -EEXIST)
		rc = shirudo_dm_verity_inspect("shirudo-runtime", &opened.image,
					       &device);
	if (!rc)
		rc = shirudo_dm_verity_verify(&device, &opened);
	if (!rc)
		rc = shirudo_dm_verity_mount(&device, SHIRUDO_RUNTIME_DIR,
					     true);
	if (rc && created) {
		cleanup = shirudo_dm_verity_remove(&device, false);
		if (cleanup)
			pr_warn("image: cannot remove runtime mapping: %s",
				strerror(-cleanup));
	}
	shirudo_dm_verity_close(&device);
	if (!rc && image.preparing_boot)
		image.boot_runtime = device;
	shirudo_config_image_close(&opened);
	if (!rc)
		rc = load_runtime_config();
	return rc;
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

	if (!image.locked)
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
	if (image.locked && umount2(SHIRUDO_CONFIG_CANDIDATE_DIR, MNT_DETACH) &&
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

static int prepare(void *ctx, const struct shirudo_config_update_target *target)
{
	const char *mountpoint = SHIRUDO_CONFIG_CANDIDATE_DIR;
	struct image_context *current = ctx;
	struct shirudo_dm_verity *device = &current->candidate_device;
	bool created = false;
	int rc, cleanup;
	char name[128];
	struct stat st;

	close_candidate();
	if (!current->preparing_boot)
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
	mapping_name(target->root_hash, name);
	rc = shirudo_dm_verity_inspect(name, &current->candidate.image,
				       device);
	if (rc == -ENXIO || rc == -ENODEV || rc == -ENOENT) {
		rc = shirudo_dm_verity_create(&current->candidate, name,
					      device);
		created = !rc;
	}
	if (!rc)
		rc = shirudo_dm_verity_verify(device,
					      &current->candidate);
	if (!rc && !current->preparing_boot)
		rc = device_observed(current->candidate_device.device,
				     current->candidate.image.root_hash,
				     SHIRUDO_DEVICE_CONFIG);
	if (rc)
		goto out;
	if (!stat(SHIRUDO_CONFIG_IMAGE_DIR, &st) &&
	    st.st_dev == current->candidate_device.device) {
		current->candidate_fd = open(SHIRUDO_CONFIG_IMAGE_DIR,
					     O_PATH | O_DIRECTORY | O_CLOEXEC);
	} else {
		if (umount2(mountpoint, MNT_DETACH) &&
		    errno != EINVAL && errno != ENOENT) {
			rc = -errno;
			goto out;
		}
		rc = mkdir_owned(mountpoint);
		if (!rc)
			rc = shirudo_dm_verity_mount(device,
						     mountpoint,
						     false);
		if (rc)
			goto out;
		current->candidate_fd = open(mountpoint,
					     O_PATH | O_DIRECTORY | O_CLOEXEC);
	}
	if (current->candidate_fd < 0) {
		rc = -errno;
		goto out;
	}
	rc = mount_flags(current->candidate_fd, false);
	if (!rc)
		rc = shirudo_image_config_validate(current->candidate_fd);
	if (!rc && !current->preparing_boot)
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

static int activate(void *ctx,
		    const struct shirudo_config_update_target *target)
{
	struct image_context *current = ctx;
	struct stat st;
	int fd, rc;

	(void)target;
	rc = shirudo_keys_apply_image(current->candidate_fd,
				      current->boot_activation);
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

static const struct shirudo_config_update_ops update_ops = {
	.boot_identity = boot_identity,
	.pcr_read = pcr_read,
	.pcr_extend = pcr_extend,
	.prepare = prepare,
	.activate = activate,
	.seal = seal_fd,
};

static int open_update(void)
{
	int rc;

	if (image.locked)
		return 0;
	rc = mkdir_owned(SHIRUDO_CONFIG_UPDATE_DIR);
	if (!rc)
		rc = tpm_open(&image.tpm);
	if (!rc)
		rc = shirudo_config_update_open(SHIRUDO_CONFIG_UPDATE_DIR,
						&update_ops, &image,
						&image.update);
	if (!rc)
		image.locked = true;
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

static int enroll_config_key(void)
{
	__u8 *der = NULL;
	key_serial_t ring;
	size_t size = 0;
	int rc;

	rc = keys_read_der(image.bootstrap.certificate, &der, &size);
	if (rc)
		return rc;
	ring = shirudo_keyring_dm_verity_serial();
	rc = ring < 0 ? ring : keyring_holds_cert(ring, der, size);
	if (!rc)
		rc = shirudo_keyring_dm_verity_add_cert(der, size);
	xfree(der, size);
	if (rc < 0)
		return rc;
	rc = shirudo_keyring_dm_verity_seal();
	return rc == -EEXIST ? 0 : rc;
}

/* The authenticated initrd validates the boot set before installing guards. */
int shirudo_image_boot_keys(struct shirudo_trusted_set *set)
{
	struct shirudo_trusted_cert primary = { .primary = true };
	size_t i;
	int rc;

	image.preparing_boot = true;
	rc = shirudo_image_runtime_mount();
	if (!rc)
		rc = enroll_config_key();
	if (!rc)
		rc = open_update();
	if (!rc)
		rc = boot_target(&image.boot_target);
	if (!rc)
		rc = prepare(&image, &image.boot_target);
	if (!rc)
		rc = shirudo_keys_validate_image_set(SHIRUDO_RUNTIME_CERT_PATH,
						     image.candidate_fd, set);
	if (rc)
		return rc;
	/* Guard loaders need the initial signer until activation. */
	strscpy(primary.path, SHIRUDO_RUNTIME_CERT_PATH, sizeof(primary.path));
	rc = keys_digest_file(primary.path, primary.sha256,
			      primary.fingerprint);
	if (rc)
		return rc;
	for (i = 0; i < set->n; i++)
		if (!memcmp(set->certs[i].sha256, primary.sha256, 32))
			break;
	if (i == set->n) {
		if (set->n == SHIRUDO_KEYS_MAX)
			return -E2BIG;
		set->certs[set->n++] = primary;
	}
	image.boot_prepared = true;
	return 0;
}

int shirudo_image_boot_keys_close(void)
{
	int rc = 0, err;

	if (!image.preparing_boot)
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
	image.preparing_boot = false;
	return rc;
}

int shirudo_image_boot(void)
{
	struct shirudo_config_update_target target = {};
	int rc;

	rc = open_update();
	if (rc)
		return rc;
	if (image.boot_prepared) {
		target = image.boot_target;
	} else {
		rc = boot_target(&target);
		if (rc)
			return rc;
	}
	image.boot_activation = true;
	rc = shirudo_config_update_boot(&image.update, &target,
					image.bootstrap.pcr);
	image.boot_activation = false;
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
	mapping_name(record->target.root_hash, name);
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
	mode = shirudo_identity_mode();
	if (mode < 0)
		return mode;
	rc = identity_read(&identity);
	if (mode != SHIRUDO_MODE_NONE && rc)
		return rc;
	if (rc)
		return rc == -ENOENT || rc == -EPERM || rc == -EACCES ? 0 : rc;
	if (mode != (identity.runtime_mode ?
		SHIRUDO_MODE_IMAGE : SHIRUDO_MODE_LEGACY))
		return -EPROTO;
	if (!identity.runtime_mode)
		return 0;
	rc = shirudo_image_bootstrap_load();
	if (rc < 0)
		return rc;
	rc = load_runtime_config();
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

	if (!image.locked)
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
	if (image.locked)
		shirudo_config_update_close(&image.update);
	image.locked = false;
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

	if (!image.locked)
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
