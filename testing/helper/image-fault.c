// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include "image-fault.h"
#include "util/config_image.h"
#include "util/dm_verity.h"
#include "util/identity.h"
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

int __wrap_shirudo_config_root_begin(const __u8 root[32],
				     struct shirudo_config_root_guard *guard)
{
	__u8 wrong[32];

	if (root_mode == ROOT_NORMAL)
		return __real_shirudo_config_root_begin(root, guard);
	begin_calls++;
	if (root_mode == ROOT_MISSING) {
		guard->map_fd = -1;
		guard->task_fd = -1;
		return 0;
	}
	memcpy(wrong, root, sizeof(wrong));
	if (root_mode == ROOT_WRONG)
		wrong[0] ^= 1;
	return __real_shirudo_config_root_begin(wrong, guard);
}

int __wrap_shirudo_config_root_end(struct shirudo_config_root_guard *guard)
{
	struct shirudo_expected_root expected = {};
	int rc = 0, cleanup;

	if (root_mode != ROOT_NORMAL) {
		end_calls++;
		if (guard->map_fd >= 0 &&
		    bpf_map_lookup_elem(guard->map_fd, &guard->task_fd,
					&expected))
			rc = -errno;
		consumed_valid = expected.valid;
	}
	cleanup = __real_shirudo_config_root_end(guard);
	return rc ? rc : cleanup;
}

static int check_root_cleared(void)
{
	struct shirudo_expected_root expected = {}, empty = {};
	int map, task, rc;

	map = bpf_obj_get(SHIRUDO_BPFFS_DIR "/config_roots");
	if (map < 0)
		return -errno;
	task = syscall(SYS_pidfd_open, getpid(), 0);
	if (task < 0) {
		rc = -errno;
		goto out;
	}
	rc = bpf_map_lookup_elem(map, &task, &expected) ? -errno : 0;
	if (root_mode == ROOT_MISSING && rc == -ENOENT)
		rc = 0;
	if (!rc && memcmp(&expected, &empty, sizeof(empty)))
		rc = -EUCLEAN;
	close(task);
out:
	close(map);
	return rc;
}

static int check_classification(const struct shirudo_dm_verity *device)
{
	__u32 dev = (major(device->device) << 20) | minor(device->device);
	struct shirudo_device_authority entry;
	__u64 key, next, diskseq;
	__u32 matches = 0;
	int map, block, rc = 0;
	void *cursor = NULL;

	block = open(device->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (block < 0)
		return -errno;
	if (ioctl(block, BLKGETDISKSEQ, &diskseq)) {
		rc = -errno;
		goto out_block;
	}
	map = bpf_obj_get(SHIRUDO_BPFFS_DIR "/devices");
	if (map < 0) {
		rc = -errno;
		goto out_block;
	}
	while (!bpf_map_get_next_key(map, cursor, &next)) {
		if (bpf_map_lookup_elem(map, &next, &entry)) {
			rc = -errno;
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
			if (entry.kind != SHIRUDO_DEVICE_CONFIG ||
			    memcmp(entry.root, device->image.root_hash, 32)) {
				rc = -EUCLEAN;
				break;
			}
		}
		key = next;
		cursor = &key;
	}
	if (!rc && errno != ENOENT)
		rc = -errno;
	if (!rc && matches != (root_mode == ROOT_MATCH ? 1u : 0u))
		rc = -EACCES;
	printf("classified=%u consumed_valid=%d\n", matches, consumed_valid);
	close(map);
out_block:
	close(block);
	return rc;
}

static int config_root_test(const char *mode, const char *prefix)
{
	struct shirudo_config_image_open opened;
	struct shirudo_dm_verity device;
	bool created = false;
	int rc, cleanup;
	char name[128];

	if (!strcmp(mode, "missing"))
		root_mode = ROOT_MISSING;
	else if (!strcmp(mode, "wrong"))
		root_mode = ROOT_WRONG;
	else if (!strcmp(mode, "match"))
		root_mode = ROOT_MATCH;
	else
		return 2;
	rc = shirudo_config_image_open(prefix, &opened);
	if (rc)
		goto done;
	snprintf(name, sizeof(name), "shirudo-verify-root-test-%ld",
		 (long)getpid());
	rc = shirudo_dm_verity_create(&opened, name, &device);
	created = !rc;
	if (!rc && (begin_calls != 1 || end_calls != 1 ||
		    consumed_valid != (root_mode == ROOT_WRONG ? 1 : 0)))
		rc = -EUCLEAN;
	if (!rc)
		rc = check_root_cleared();
	if (!rc)
		rc = shirudo_dm_verity_verify(&device, &opened);
	if (!rc)
		rc = check_classification(&device);
	if (created) {
		cleanup = shirudo_dm_verity_remove(&device, true);
		shirudo_dm_verity_close(&device);
		if (!rc)
			rc = cleanup;
	}
	shirudo_config_image_close(&opened);
done:
	if (rc)
		fprintf(stderr, "config root test: %s\n", strerror(-rc));
	return rc ? 1 : 0;
}

int __wrap_main(int argc, const char **argv)
{
	if (argc == 4 && !strcmp(argv[1], "config-root"))
		return config_root_test(argv[2], argv[3]);
	if (argc != 4 || strcmp(argv[1], "image") ||
	    strcmp(argv[2], "update")) {
		fprintf(stderr, "usage: shirudo-image-fault "
			"image update <prefix>\n");
		return 2;
	}
	return __real_main(argc, argv);
}

TSS2_RC __wrap_Esys_PCR_Extend(ESYS_CONTEXT *context, ESYS_TR pcr,
			       ESYS_TR first, ESYS_TR second, ESYS_TR third,
			       const TPML_DIGEST_VALUES *digests)
{
	TSS2_RC rc;

	rc = __real_Esys_PCR_Extend(context, pcr, first, second, third,
				    digests);
	if (!rc)
		_exit(99);
	return rc;
}
