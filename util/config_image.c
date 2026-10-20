// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config_image.h"
#include "hex.h"

#define VERITY_DIGESTS_PER_BLOCK (SHIRUDO_CONFIG_IMAGE_BLOCK_SIZE / 32)

/* The standard veritysetup superblock occupies the first 512 bytes. */
struct verity_superblock {
	__u8 magic[8];
	__u32 version_le;
	__u32 hash_type_le;
	__u8 uuid[16];
	char algorithm[32];
	__u32 data_block_size_le;
	__u32 hash_block_size_le;
	__u64 data_blocks_le;
	__u16 salt_size_le;
	__u8 reserved[6];
	__u8 salt[256];
	__u8 padding[168];
};

_Static_assert(sizeof(struct verity_superblock) == 512,
	       "verity superblock layout must match the disk format");

static int verity_hash_blocks(__u64 data_blocks, __u64 *out)
{
	__u64 total = 1;

	if (!data_blocks || data_blocks > SHIRUDO_CONFIG_IMAGE_MAX_BYTES /
					SHIRUDO_CONFIG_IMAGE_BLOCK_SIZE)
		return -EFBIG;
	while (data_blocks > 1) {
		data_blocks = (data_blocks + VERITY_DIGESTS_PER_BLOCK - 1) /
			      VERITY_DIGESTS_PER_BLOCK;
		total += data_blocks;
	}
	*out = total;
	return 0;
}

static int regular_file_size(int fd, __u64 *size)
{
	struct stat st;

	*size = 0;
	if (fstat(fd, &st))
		return -errno;
	if (!S_ISREG(st.st_mode) || st.st_size < 0)
		return -EINVAL;
	*size = st.st_size;
	return 0;
}

static int read_exact_at_start(int fd, void *buffer, size_t size)
{
	size_t done = 0;
	ssize_t n;

	while (done < size) {
		n = pread(fd, (__u8 *)buffer + done, size - done, done);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (!n)
			return -EIO;
		done += n;
	}
	return 0;
}

static int validate_superblock(const struct verity_superblock *header)
{
	static const __u8 magic[8] = "verity";
	static const char algorithm[32] = "sha256";

	if (memcmp(header->magic, magic, sizeof(magic)) ||
	    le32toh(header->version_le) != 1 ||
	    le32toh(header->hash_type_le) != 1 ||
	    memcmp(header->algorithm, algorithm, sizeof(algorithm)) ||
	    le32toh(header->data_block_size_le) !=
		SHIRUDO_CONFIG_IMAGE_BLOCK_SIZE ||
	    le32toh(header->hash_block_size_le) !=
		SHIRUDO_CONFIG_IMAGE_BLOCK_SIZE ||
	    le16toh(header->salt_size_le) != SHIRUDO_CONFIG_IMAGE_SALT_SIZE)
		return -EINVAL;
	return 0;
}

int shirudo_config_image_read_header(int hash_fd,
				     struct shirudo_config_image *out)
{
	struct shirudo_config_image image = {};
	struct verity_superblock header;
	int rc;

	if (!out)
		return -EINVAL;
	rc = read_exact_at_start(hash_fd, &header, sizeof(header));
	if (!rc)
		rc = validate_superblock(&header);
	if (rc)
		return rc;
	image.data_blocks = le64toh(header.data_blocks_le);
	rc = verity_hash_blocks(image.data_blocks, &image.hash_blocks);
	if (rc)
		return rc;
	memcpy(image.salt, header.salt, sizeof(image.salt));
	*out = image;
	return 0;
}

int shirudo_config_image_check_files(int data_fd, int hash_fd,
				     const struct shirudo_config_image *image)
{
	__u64 data_size, hash_size, blocks;
	int rc;

	if (!image)
		return -EINVAL;
	rc = verity_hash_blocks(image->data_blocks, &blocks);
	if (rc)
		return rc;
	if (blocks != image->hash_blocks)
		return -EINVAL;
	rc = regular_file_size(data_fd, &data_size);
	if (!rc)
		rc = regular_file_size(hash_fd, &hash_size);
	if (rc)
		return rc;
	if (data_size != image->data_blocks * SHIRUDO_CONFIG_IMAGE_BLOCK_SIZE ||
	    hash_size != image->hash_blocks * SHIRUDO_CONFIG_IMAGE_BLOCK_SIZE)
		return -EINVAL;
	return 0;
}

static int open_part(const char *prefix, const char *suffix)
{
	char path[PATH_MAX];
	int n, fd;

	n = snprintf(path, sizeof(path), "%s%s", prefix, suffix);
	if (n < 0 || (size_t)n >= sizeof(path))
		return -ENAMETOOLONG;
	fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
	return fd < 0 ? -errno : fd;
}

static int read_root(const char *prefix, __u8 root[32])
{
	char text[65] = {};
	__u64 size;
	__u32 i;
	int fd, rc;

	fd = open_part(prefix, ".roothash");
	if (fd < 0)
		return fd;
	rc = regular_file_size(fd, &size);
	if (!rc && size != 64)
		rc = -EINVAL;
	if (!rc)
		rc = read_exact_at_start(fd, text, 64);
	close(fd);
	if (rc)
		return rc;
	for (i = 0; i < 64; i++)
		if (!((text[i] >= '0' && text[i] <= '9') ||
		      (text[i] >= 'a' && text[i] <= 'f')))
			return -EINVAL;
	return hex_decode(text, root, 32);
}

void shirudo_config_image_close(struct shirudo_config_image_open *image)
{
	if (!image)
		return;
	if (image->data_fd >= 0)
		close(image->data_fd);
	if (image->hash_fd >= 0)
		close(image->hash_fd);
	if (image->signature_fd >= 0)
		close(image->signature_fd);
	image->data_fd = -1;
	image->hash_fd = -1;
	image->signature_fd = -1;
}

static int open_image(const char *prefix, const __u8 *expected_root,
		      struct shirudo_config_image_open *out)
{
	struct shirudo_config_image_open image = {
		.data_fd = -1, .hash_fd = -1, .signature_fd = -1,
	};
	__u64 size;
	int rc;

	if (!prefix || !*prefix || !out)
		return -EINVAL;
	*out = image;
	image.data_fd = open_part(prefix, ".img");
	if (image.data_fd < 0)
		return image.data_fd;
	image.hash_fd = open_part(prefix, ".verity");
	if (image.hash_fd < 0) {
		rc = image.hash_fd;
		goto out;
	}
	rc = shirudo_config_image_read_header(image.hash_fd,
					      &image.image);
	if (!rc)
		rc = read_root(prefix, image.image.root_hash);
	if (!rc)
		rc = shirudo_config_image_check_files(image.data_fd,
						      image.hash_fd,
						      &image.image);
	if (rc)
		goto out;
	if (expected_root) {
		if (memcmp(expected_root, image.image.root_hash, 32))
			rc = -EKEYREJECTED;
	} else {
		image.image.signed_root = true;
		image.signature_fd = open_part(prefix, ".p7s");
		rc = image.signature_fd < 0 ? image.signature_fd :
			regular_file_size(image.signature_fd, &size);
		if (!rc && (!size || size > SHIRUDO_CONFIG_IMAGE_SIG_MAX))
			rc = -EINVAL;
	}
out:
	if (rc)
		shirudo_config_image_close(&image);
	else
		*out = image;
	return rc;
}

int shirudo_config_image_open(const char *prefix,
			      struct shirudo_config_image_open *out)
{
	return open_image(prefix, NULL, out);
}

int shirudo_config_image_open_root(const char *prefix,
				   const __u8 expected_root[32],
				   struct shirudo_config_image_open *out)
{
	return expected_root ? open_image(prefix, expected_root, out) : -EINVAL;
}
