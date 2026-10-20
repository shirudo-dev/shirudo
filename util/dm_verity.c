// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/dm-ioctl.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <linux/keyctl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "dm_verity.h"
#include "hex.h"
#include "keyring.h"
#include "malloc.h"

#define DM_BUFFER_SIZE 4096

union dm_buffer {
	struct dm_ioctl io;
	__u8 bytes[DM_BUFFER_SIZE];
};

static bool dm_name_ok(const char *name)
{
	size_t n;

	if (!name || !*name || !strcmp(name, ".") || !strcmp(name, ".."))
		return false;
	for (n = 0; name[n]; n++)
		if (n >= 127 ||
		    !((name[n] >= 'a' && name[n] <= 'z') ||
		      (name[n] >= 'A' && name[n] <= 'Z') ||
		      (name[n] >= '0' && name[n] <= '9') || name[n] == '-' ||
		      name[n] == '_' || name[n] == '.'))
			return false;
	return true;
}

static void dm_init(union dm_buffer *buf, const char *name)
{
	memset(buf, 0, sizeof(*buf));
	buf->io.version[0] = DM_VERSION_MAJOR;
	buf->io.version[1] = 0;
	buf->io.version[2] = 0;
	buf->io.data_size = sizeof(*buf);
	buf->io.data_start = sizeof(buf->io);
	strscpy(buf->io.name, name, sizeof(buf->io.name));
}

static int dm_command(int fd, __u64 command, union dm_buffer *buf)
{
	if (ioctl(fd, command, &buf->io))
		return -errno;
	if (buf->io.flags & DM_BUFFER_FULL_FLAG)
		return -EOVERFLOW;
	return 0;
}

static int dm_control_open(void)
{
	struct stat st;
	int fd, rc;

	fd = open("/dev/mapper/control", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -errno;
	rc = fstat(fd, &st) ? -errno : 0;
	if (!rc && (!S_ISCHR(st.st_mode) || st.st_rdev != makedev(10, 236)))
		rc = -ENODEV;
	if (rc) {
		close(fd);
		return rc;
	}
	return fd;
}

int shirudo_dm_verity_list(shirudo_dm_verity_cb callback, void *ctx)
{
	const size_t header = offsetof(struct dm_name_list, name);
	const size_t capacity = 64 * 1024;
	struct dm_name_list *entry;
	struct dm_ioctl *io;
	size_t offset, avail;
	int control, rc;
	void *buffer;

	if (!callback)
		return -EINVAL;
	control = dm_control_open();
	if (control < 0)
		return control;
	buffer = xcalloc(1, capacity);
	if (!buffer) {
		close(control);
		return -ENOMEM;
	}
	io = buffer;
	io->version[0] = DM_VERSION_MAJOR;
	io->data_size = capacity;
	io->data_start = sizeof(*io);
	rc = ioctl(control, DM_LIST_DEVICES, io) ? -errno : 0;
	if (!rc && io->flags & DM_BUFFER_FULL_FLAG)
		rc = -EOVERFLOW;
	if (!rc && (io->data_size > capacity || io->data_start < sizeof(*io) ||
		    io->data_start > io->data_size || io->data_start % 8))
		rc = -EINVAL;
	offset = io->data_start;
	while (!rc && offset < io->data_size) {
		avail = io->data_size - offset;
		if (avail < header + 1) {
			rc = -EINVAL;
			break;
		}
		entry = (void *)((__u8 *)buffer + offset);
		if (!entry->dev) {
			if (entry->next || entry->name[0])
				rc = -EINVAL;
			break;
		}
		if (entry->next) {
			if (entry->next > avail || entry->next % 8 ||
			    entry->next < header + 1) {
				rc = -EINVAL;
				break;
			}
			avail = entry->next;
		}
		avail -= header;
		if (avail > DM_NAME_LEN)
			avail = DM_NAME_LEN;
		if (!memchr(entry->name, 0, avail) || !entry->name[0]) {
			rc = -EINVAL;
			break;
		}
		rc = callback(entry->name, (dev_t)entry->dev, ctx);
		if (!entry->next)
			break;
		offset += entry->next;
	}
	xfree(buffer, capacity);
	close(control);
	return rc;
}

static int loop_attach(int file_fd, __u64 bytes, int *out)
{
	struct loop_config config = {};
	char path[64];
	int control, loop, n, rc;

	control = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
	if (control < 0)
		return -errno;
	n = ioctl(control, LOOP_CTL_GET_FREE);
	rc = n < 0 ? -errno : 0;
	close(control);
	if (rc)
		return rc;
	snprintf(path, sizeof(path), "/dev/loop%d", n);
	loop = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (loop < 0)
		return -errno;
	config.fd = file_fd;
	config.block_size = SHIRUDO_CONFIG_IMAGE_BLOCK_SIZE;
	config.info.lo_sizelimit = bytes;
	config.info.lo_flags = LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR;
	if (ioctl(loop, LOOP_CONFIGURE, &config)) {
		rc = -errno;
		close(loop);
		return rc;
	}
	*out = loop;
	return 0;
}

static int device_path(struct shirudo_dm_verity *device, __u64 dev)
{
	struct stat st;
	int n;

	device->device = (dev_t)dev;
	n = snprintf(device->path, sizeof(device->path), "/dev/dm-%u",
		     minor(device->device));
	if (n < 0 || (size_t)n >= sizeof(device->path))
		return -ENAMETOOLONG;
	if (lstat(device->path, &st)) {
		if (errno != ENOENT)
			return -errno;
		if (mknod(device->path, S_IFBLK | 0600, device->device))
			return -errno;
		if (lstat(device->path, &st))
			return -errno;
	}
	return S_ISBLK(st.st_mode) && st.st_rdev == device->device ? 0
								   : -ESTALE;
}

static int dm_number(const char *token, __u64 *out)
{
	if (!token)
		return -EINVAL;
	return parse_u64(token, strlen(token), ~0ULL, out) ? -EINVAL : 0;
}

static int dm_device(char *token, dev_t *out)
{
	__u64 major_nr, minor_nr;
	char *separator;

	separator = strchr(token, ':');
	if (!separator)
		return -EINVAL;
	*separator = '\0';
	if (dm_number(token, &major_nr) ||
	    dm_number(separator + 1, &minor_nr) ||
	    major_nr > UINT_MAX || minor_nr > UINT_MAX)
		return -EINVAL;
	*out = makedev(major_nr, minor_nr);
	return major(*out) == major_nr && minor(*out) == minor_nr ? 0 : -EINVAL;
}

static int check_table(union dm_buffer *buf,
		       const struct shirudo_config_image *image,
		       struct shirudo_dm_verity *device)
{
	char root[65], salt[65], *tokens[13], *save = NULL, *token;
	struct dm_target_spec *target;
	__u64 value;
	size_t offset, avail;
	__u32 count = 0, i;
	char *params;

	if (!(buf->io.flags & DM_READONLY_FLAG) ||
	    buf->io.flags & (DM_SUSPEND_FLAG | DM_INACTIVE_PRESENT_FLAG) ||
	    !(buf->io.flags & DM_ACTIVE_PRESENT_FLAG) ||
	    buf->io.target_count != 1)
		return -EKEYREJECTED;
	offset = buf->io.data_start;
	if (buf->io.data_size > sizeof(*buf) || offset > buf->io.data_size ||
	    buf->io.data_size - offset < sizeof(*target))
		return -EINVAL;
	target = (void *)(buf->bytes + offset);
	if (target->sector_start ||
	    target->length != image->data_blocks *
				      (SHIRUDO_CONFIG_IMAGE_BLOCK_SIZE / 512) ||
	    strncmp(target->target_type, "verity", sizeof(target->target_type)))
		return -EKEYREJECTED;
	params = (char *)(target + 1);
	avail = buf->io.data_size - offset - sizeof(*target);
	if (!memchr(params, 0, avail))
		return -EINVAL;
	for (token = strtok_r(params, " ", &save); token;
	     token = strtok_r(NULL, " ", &save)) {
		if (count == 13)
			return -EKEYREJECTED;
		tokens[count++] = token;
	}
	if (image->signed_root) {
		if (count != 13 || strcmp(tokens[10], "2") ||
		    strcmp(tokens[11], "root_hash_sig_key_desc"))
			return -EKEYREJECTED;
	} else if ((count != 10 && count != 11) ||
		   (count == 11 && strcmp(tokens[10], "0"))) {
		return -EKEYREJECTED;
	}
	for (i = 0; i < 7; i++) {
		if (i == 1 || i == 2)
			continue;
		if (dm_number(tokens[i], &value))
			return -EINVAL;
		if ((i == 0 && value != 1) ||
		    ((i == 3 || i == 4) &&
		     value != SHIRUDO_CONFIG_IMAGE_BLOCK_SIZE) ||
		    (i == 5 && value != image->data_blocks) ||
		    (i == 6 && value != 1))
			return -EKEYREJECTED;
	}
	hex_encode(image->root_hash, 32, root);
	hex_encode(image->salt, 32, salt);
	if (strcmp(tokens[7], "sha256") || strcmp(tokens[8], root) ||
	    strcmp(tokens[9], salt))
		return -EKEYREJECTED;
	if (dm_device(tokens[1], &device->data_device) ||
	    dm_device(tokens[2], &device->hash_device))
		return -EINVAL;
	return 0;
}

int shirudo_dm_verity_inspect(const char *name,
			      const struct shirudo_config_image *image,
			      struct shirudo_dm_verity *out)
{
	struct shirudo_dm_verity device = {.data_loop_fd = -1,
					   .hash_loop_fd = -1};
	union dm_buffer buf;
	int control, rc;

	if (!out || !image || !dm_name_ok(name))
		return -EINVAL;
	*out = device;
	control = dm_control_open();
	if (control < 0)
		return control;
	dm_init(&buf, name);
	buf.io.flags = DM_STATUS_TABLE_FLAG;
	rc = dm_command(control, DM_TABLE_STATUS, &buf);
	if (!rc)
		rc = check_table(&buf, image, &device);
	if (!rc)
		rc = device_path(&device, buf.io.dev);
	close(control);
	if (!rc) {
		strscpy(device.name, name, sizeof(device.name));
		device.image = *image;
		*out = device;
	}
	return rc;
}

void shirudo_dm_verity_close(struct shirudo_dm_verity *device)
{
	if (!device)
		return;
	if (device->data_loop_fd >= 0)
		close(device->data_loop_fd);
	if (device->hash_loop_fd >= 0)
		close(device->hash_loop_fd);
	device->data_loop_fd = -1;
	device->hash_loop_fd = -1;
}

int shirudo_dm_verity_remove(struct shirudo_dm_verity *device, bool deferred)
{
	union dm_buffer buf;
	int control, rc;

	if (!device || !dm_name_ok(device->name))
		return -EINVAL;
	control = dm_control_open();
	if (control < 0)
		return control;
	dm_init(&buf, device->name);
	if (deferred)
		buf.io.flags = DM_DEFERRED_REMOVE;
	rc = dm_command(control, DM_DEV_REMOVE, &buf);
	close(control);
	if (!rc)
		shirudo_dm_verity_close(device);
	return rc;
}

/* request_key() can find this immutable signature in the caller's thread. */
static key_serial_t signature_key(int fd, char description[64])
{
	__u8 signature[SHIRUDO_CONFIG_IMAGE_SIG_MAX], random[16];
	char suffix[33];
	struct stat st;
	size_t done = 0;
	ssize_t n;
	long key;

	if (fstat(fd, &st))
		return -errno;
	if (!S_ISREG(st.st_mode) || st.st_size <= 0 ||
	    (__u64)st.st_size > sizeof(signature))
		return -EINVAL;
	while (done < (size_t)st.st_size) {
		n = pread(fd, signature + done, st.st_size - done, done);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (!n)
			return -EIO;
		done += n;
	}
	done = 0;
	while (done < sizeof(random)) {
		n = getrandom(random + done, sizeof(random) - done, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (!n)
			return -EIO;
		done += n;
	}
	hex_encode(random, sizeof(random), suffix);
	snprintf(description, 64, "shirudo-verity-%s", suffix);
	key = syscall(__NR_add_key, "user", description, signature,
		      (size_t)st.st_size, KEY_SPEC_THREAD_KEYRING);
	if (key < 0)
		return -errno;
	/* Keep possessor search, but prevent payload and permission changes. */
	if (syscall(__NR_keyctl, KEYCTL_SETPERM, key, 0x08000000, 0, 0) < 0) {
		int rc = -errno;

		(void)keyring_unlink_key(KEY_SPEC_THREAD_KEYRING, key);
		return rc;
	}
	return key;
}

int shirudo_dm_verity_create(const struct shirudo_config_image_open *image,
			     const char *name, struct shirudo_dm_verity *out)
{
	struct shirudo_dm_verity device = {.data_loop_fd = -1,
					   .hash_loop_fd = -1};
	char root[65], salt[65], params[512], signature[64];
	struct stat data_st, hash_st;
	struct dm_target_spec *target;
	union dm_buffer buf;
	bool created = false;
	key_serial_t key = -1;
	int control = -1, rc, n;

	if (!image || !out || !dm_name_ok(name))
		return -EINVAL;
	*out = device;
	rc = shirudo_config_image_check_files(image->data_fd, image->hash_fd,
					      &image->image);
	if (rc)
		return rc;
	device.image = image->image;
	strscpy(device.name, name, sizeof(device.name));
	rc = loop_attach(image->data_fd,
			 image->image.data_blocks *
				 SHIRUDO_CONFIG_IMAGE_BLOCK_SIZE,
			 &device.data_loop_fd);
	if (!rc)
		rc = loop_attach(image->hash_fd,
				 image->image.hash_blocks *
					 SHIRUDO_CONFIG_IMAGE_BLOCK_SIZE,
				 &device.hash_loop_fd);
	if (rc)
		goto out;
	if (fstat(device.data_loop_fd, &data_st) ||
	    fstat(device.hash_loop_fd, &hash_st)) {
		rc = -errno;
		goto out;
	}
	hex_encode(image->image.root_hash, 32, root);
	hex_encode(image->image.salt, 32, salt);
	n = snprintf(params, sizeof(params),
		     "1 %u:%u %u:%u 4096 4096 %llu 1 sha256 %s %s",
		     major(data_st.st_rdev), minor(data_st.st_rdev),
		     major(hash_st.st_rdev), minor(hash_st.st_rdev),
		     (__u64)image->image.data_blocks, root, salt);
	if (n < 0 || (size_t)n >= sizeof(params)) {
		rc = -EOVERFLOW;
		goto out;
	}
	if (image->image.signed_root) {
		int remaining = sizeof(params) - n;
		int written;

		key = signature_key(image->signature_fd, signature);
		if (key < 0) {
			rc = key;
			goto out;
		}
		written = snprintf(params + n, remaining,
				   " 2 root_hash_sig_key_desc %s", signature);
		if (written < 0 || written >= remaining) {
			rc = -EOVERFLOW;
			goto out;
		}
		n += written;
	}
	control = dm_control_open();
	if (control < 0) {
		rc = control;
		goto out;
	}
	dm_init(&buf, name);
	rc = dm_command(control, DM_DEV_CREATE, &buf);
	if (rc)
		goto out;
	created = true;
	dm_init(&buf, name);
	buf.io.flags = DM_READONLY_FLAG;
	buf.io.target_count = 1;
	target = (void *)(buf.bytes + buf.io.data_start);
	target->length = image->image.data_blocks *
			 (SHIRUDO_CONFIG_IMAGE_BLOCK_SIZE / 512);
	snprintf(target->target_type, sizeof(target->target_type), "verity");
	memcpy(target + 1, params, n + 1);
	target->next = (sizeof(*target) + n + 1 + 7) & ~7u;
	buf.io.data_size = buf.io.data_start + target->next;
	rc = dm_command(control, DM_TABLE_LOAD, &buf);
	if (rc)
		goto out;
	dm_init(&buf, name);
	buf.io.flags = DM_READONLY_FLAG;
	rc = dm_command(control, DM_DEV_SUSPEND, &buf);
	if (rc)
		goto out;
	dm_init(&buf, name);
	buf.io.flags = DM_STATUS_TABLE_FLAG;
	rc = dm_command(control, DM_TABLE_STATUS, &buf);
	if (!rc)
		rc = check_table(&buf, &image->image, &device);
	if (!rc)
		rc = device_path(&device, buf.io.dev);
out:
	if (key >= 0)
		(void)keyring_unlink_key(KEY_SPEC_THREAD_KEYRING, key);
	if (rc) {
		if (created) {
			dm_init(&buf, name);
			(void)dm_command(control, DM_DEV_REMOVE, &buf);
		}
		shirudo_dm_verity_close(&device);
	} else {
		*out = device;
	}
	if (control >= 0)
		close(control);
	return rc;
}

static int loop_open(dev_t device)
{
	struct stat st;
	char path[64];
	int fd, rc;

	if (major(device) != 7)
		return -ENODEV;
	snprintf(path, sizeof(path), "/dev/loop%u", minor(device));
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (fd < 0)
		return -errno;
	rc = fstat(fd, &st) ? -errno : 0;
	if (!rc && (!S_ISBLK(st.st_mode) || st.st_rdev != device))
		rc = -ESTALE;
	if (rc) {
		close(fd);
		return rc;
	}
	return fd;
}

static int loop_check(int loop_fd, int file_fd, __u64 bytes)
{
	struct loop_info64 info = {};
	struct stat st;

	if (fstat(file_fd, &st) || ioctl(loop_fd, LOOP_GET_STATUS64, &info))
		return -errno;
	if (!S_ISREG(st.st_mode) || st.st_size < 0 ||
	    (__u64)st.st_size != bytes || info.lo_device != st.st_dev ||
	    info.lo_inode != st.st_ino || info.lo_offset ||
	    info.lo_sizelimit != bytes ||
	    !(info.lo_flags & LO_FLAGS_READ_ONLY) ||
	    info.lo_encrypt_type != LO_CRYPT_NONE)
		return -ESTALE;
	return 0;
}

/* Direct reads verify all logical data, including blocks outside live files. */
int shirudo_dm_verity_verify(const struct shirudo_dm_verity *device,
			     const struct shirudo_config_image_open *image)
{
	_Alignas(4096) __u8 buffer[65536];
	int data = -1, hashes = -1, fd = -1;
	struct shirudo_dm_verity checked;
	__u64 bytes, size, offset = 0;
	int rc, readonly;
	struct stat st;
	size_t count;
	ssize_t n;

	if (!device || !image)
		return -EINVAL;
	rc = shirudo_config_image_check_files(image->data_fd, image->hash_fd,
					      &image->image);
	if (rc)
		return rc;
	bytes = image->image.data_blocks * SHIRUDO_CONFIG_IMAGE_BLOCK_SIZE;
	rc = shirudo_dm_verity_inspect(device->name, &image->image, &checked);
	if (rc)
		return rc;
	if (checked.device != device->device ||
	    checked.data_device != device->data_device ||
	    checked.hash_device != device->hash_device)
		return -ESTALE;
	data = loop_open(device->data_device);
	if (data < 0)
		return data;
	hashes = loop_open(device->hash_device);
	if (hashes < 0) {
		rc = hashes;
		goto out;
	}
	rc = loop_check(data, image->data_fd, bytes);
	if (!rc)
		rc = loop_check(hashes, image->hash_fd,
				image->image.hash_blocks *
					SHIRUDO_CONFIG_IMAGE_BLOCK_SIZE);
	if (rc)
		goto out;
	fd = open(device->path,
		  O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | O_DIRECT);
	if (fd < 0) {
		rc = -errno;
		goto out;
	}
	if (fstat(fd, &st) || ioctl(fd, BLKGETSIZE64, &size) ||
	    ioctl(fd, BLKROGET, &readonly)) {
		rc = -errno;
		goto out;
	}
	if (!S_ISBLK(st.st_mode) || st.st_rdev != device->device ||
	    size != bytes || !readonly) {
		rc = -ESTALE;
		goto out;
	}
	while (offset < bytes) {
		count = sizeof(buffer);
		if (count > bytes - offset)
			count = bytes - offset;
		n = pread(fd, buffer, count, offset);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			rc = -errno;
			goto out;
		}
		if (!n) {
			rc = -EIO;
			goto out;
		}
		offset += n;
	}
	rc = shirudo_dm_verity_inspect(device->name, &image->image, &checked);
	if (!rc && (checked.device != device->device ||
		    checked.data_device != device->data_device ||
		    checked.hash_device != device->hash_device))
		rc = -ESTALE;
	if (!rc)
		rc = loop_check(data, image->data_fd, bytes);
	if (!rc)
		rc = loop_check(hashes, image->hash_fd,
				image->image.hash_blocks *
					SHIRUDO_CONFIG_IMAGE_BLOCK_SIZE);
out:
	if (fd >= 0)
		close(fd);
	if (hashes >= 0)
		close(hashes);
	close(data);
	return rc;
}

int shirudo_dm_verity_mount(const struct shirudo_dm_verity *device,
			    const char *mountpoint, bool executable)
{
	__u64 flags = MS_RDONLY | MS_NODEV | MS_NOSUID;
	struct shirudo_dm_verity checked;
	struct stat st;
	int rc;

	if (!device || !mountpoint || mountpoint[0] != '/')
		return -EINVAL;
	rc = shirudo_dm_verity_inspect(device->name, &device->image, &checked);
	if (rc)
		return rc;
	if (checked.device != device->device)
		return -ESTALE;
	if (!executable)
		flags |= MS_NOEXEC;
	if (mount(device->path, mountpoint, "ext4", flags, "noload"))
		return -errno;
	if (stat(mountpoint, &st))
		rc = -errno;
	else if (st.st_dev != device->device)
		rc = -ESTALE;
	else
		rc = shirudo_dm_verity_inspect(device->name, &device->image,
					       &checked);
	if (rc)
		(void)umount2(mountpoint, 0);
	return rc;
}
