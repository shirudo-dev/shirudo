// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <tss2/tss2_esys.h>

#include <shirudo/misc.h>

#include "image-fault.h"
#include "util/config_image.h"
#include "util/dm_verity.h"
#include "util/identity.h"
#include "util/io.h"
#include "util/paths.h"

enum root_test_mode {
	ROOT_NORMAL,
	ROOT_MISSING,
	ROOT_WRONG,
	ROOT_MATCH,
};

static enum root_test_mode root_mode;
static __u32 begin_calls, end_calls;
static int consumed_valid = -1;

int __wrap_config_root_begin(const __u8 root[32],
			     struct config_root_guard *guard)
{
	__u8 wrong[32];

	if (root_mode == ROOT_NORMAL)
		return __real_config_root_begin(root, guard);
	begin_calls++;
	if (root_mode == ROOT_MISSING) {
		guard->map_fd = -1;
		guard->task_fd = -1;
		return 0;
	}
	memcpy(wrong, root, sizeof(wrong));
	if (root_mode == ROOT_WRONG)
		wrong[0] ^= 1;
	return __real_config_root_begin(wrong, guard);
}

int __wrap_config_root_end(struct config_root_guard *guard)
{
	struct expected_root expected = {};
	int ret = 0, cleanup;

	if (root_mode != ROOT_NORMAL) {
		end_calls++;
		if (guard->map_fd >= 0 &&
		    bpf_map_lookup_elem(guard->map_fd, &guard->task_fd,
					&expected))
			ret = -errno;
		consumed_valid = expected.valid;
	}
	cleanup = __real_config_root_end(guard);
	return ret ? ret : cleanup;
}

static int check_root_cleared(void)
{
	struct expected_root expected = {}, empty = {};
	int map, task, ret;

	map = bpf_obj_get(BPFFS_DIR "/config_roots");
	if (map < 0)
		return -errno;
	task = syscall(SYS_pidfd_open, getpid(), 0);
	if (task < 0) {
		ret = -errno;
		goto out;
	}
	ret = bpf_map_lookup_elem(map, &task, &expected) ? -errno : 0;
	if (root_mode == ROOT_MISSING && ret == -ENOENT)
		ret = 0;
	if (!ret && memcmp(&expected, &empty, sizeof(empty)))
		ret = -EUCLEAN;
	close(task);
out:
	close(map);
	return ret;
}

static int check_classification(const struct dm_verity *device)
{
	__u32 dev = kernel_dev(device->device);
	struct device_authority entry;
	__u64 key, next, diskseq;
	__u32 matches = 0;
	int map, block, ret = 0;
	void *cursor = NULL;

	block = open(device->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (block < 0)
		return -errno;
	if (ioctl(block, BLKGETDISKSEQ, &diskseq)) {
		ret = -errno;
		goto out_block;
	}
	map = bpf_obj_get(BPFFS_DIR "/devices");
	if (map < 0) {
		ret = -errno;
		goto out_block;
	}
	while (!bpf_map_get_next_key(map, cursor, &next)) {
		if (bpf_map_lookup_elem(map, &next, &entry)) {
			ret = -errno;
			break;
		}
		if (entry.dev == dev)
			printf("device=%u diskseq=%llu record_diskseq=%llu "
			       "kind=%u root_match=%d\n", dev,
			       (__u64)diskseq,
			       (__u64)entry.diskseq, entry.kind,
			       !memcmp(entry.root, device->image.root_hash,
				       sizeof(entry.root)));
		if (entry.dev == dev && entry.diskseq == diskseq) {
			matches++;
			if (entry.kind != DEVICE_CONFIG ||
			    memcmp(entry.root, device->image.root_hash, 32)) {
				ret = -EUCLEAN;
				break;
			}
		}
		key = next;
		cursor = &key;
	}
	if (!ret && errno != ENOENT)
		ret = -errno;
	if (!ret && matches != (root_mode == ROOT_MATCH ? 1u : 0u))
		ret = -EACCES;
	printf("classified=%u consumed_valid=%d\n", matches, consumed_valid);
	close(map);
out_block:
	close(block);
	return ret;
}

static int config_root_test(const char *mode, const char *prefix)
{
	struct config_image_open opened;
	struct dm_verity device;
	bool created = false;
	int ret, cleanup;
	char name[128];

	if (!strcmp(mode, "missing"))
		root_mode = ROOT_MISSING;
	else if (!strcmp(mode, "wrong"))
		root_mode = ROOT_WRONG;
	else if (!strcmp(mode, "match"))
		root_mode = ROOT_MATCH;
	else
		return 2;
	ret = config_image_open(prefix, &opened);
	if (ret)
		goto done;
	snprintf(name, sizeof(name), "shirudo-verify-root-test-%ld",
		 (long)getpid());
	ret = dm_verity_create(&opened, name, &device);
	created = !ret;
	if (!ret && (begin_calls != 1 || end_calls != 1 ||
		     consumed_valid != (root_mode == ROOT_WRONG ? 1 : 0)))
		ret = -EUCLEAN;
	if (!ret)
		ret = check_root_cleared();
	if (!ret)
		ret = dm_verity_verify(&device, &opened);
	if (!ret)
		ret = check_classification(&device);
	if (created) {
		cleanup = dm_verity_remove(&device, true);
		dm_verity_close(&device);
		if (!ret)
			ret = cleanup;
	}
	config_image_close(&opened);
done:
	if (ret)
		fprintf(stderr, "config root test: %s\n", strerror(-ret));
	return ret ? 1 : 0;
}

/* Shorter than a .upatch header, as a torn write leaves an archive. */
#define ARCHIVE_TORN_SIZE	16

/*
 * The seal lets only a task of the runtime image change an archive, which
 * this helper is.
 */
static int archive_truncate(const char *name)
{
	char path[PATH_MAX];
	int len;

	len = snprintf(path, sizeof(path), "%s/%s.upatch", UPATCHES_DIR, name);
	if (strchr(name, '/') || len < 0 || (size_t)len >= sizeof(path))
		return 2;
	if (truncate(path, ARCHIVE_TORN_SIZE)) {
		fprintf(stderr, "archive truncate: %s: %s\n", path,
			strerror(errno));
		return 1;
	}
	return 0;
}

int __wrap_main(int argc, const char **argv)
{
	if (argc == 4 && !strcmp(argv[1], "config-root"))
		return config_root_test(argv[2], argv[3]);
	if (argc == 3 && !strcmp(argv[1], "archive-truncate"))
		return archive_truncate(argv[2]);
	if (argc != 4 || strcmp(argv[1], "image") ||
	    strcmp(argv[2], "update")) {
		fprintf(stderr, "usage: shirudo-image-fault "
			"image update <prefix>\n"
			"       shirudo-image-fault "
			"archive-truncate <upatch>\n");
		return 2;
	}
	return __real_main(argc, argv);
}

TSS2_RC __wrap_Esys_PCR_Extend(ESYS_CONTEXT *context, ESYS_TR pcr,
			       ESYS_TR first, ESYS_TR second, ESYS_TR third,
			       const TPML_DIGEST_VALUES *digests)
{
	TSS2_RC ret;

	ret = __real_Esys_PCR_Extend(context, pcr, first, second, third,
				     digests);
	if (!ret)
		_exit(99);
	return ret;
}
