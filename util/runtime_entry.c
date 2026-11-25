// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <linux/fs.h>
#include <linux/openat2.h>
#include <bpf/bpf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "dm_verity.h"
#include "paths.h"
#include "runtime_entry.h"

#define RUNTIME_ENTRY_PIN BPFFS_DIR "/runtime_entry_v1"

_Static_assert(sizeof(struct shirudo_runtime_entry) ==
	       24 + 8 * SHIRUDO_RUNTIME_ENTRY_MAX,
	       "runtime entry v2 is a fixed record");

static int inode_order(const void *a, const void *b)
{
	__u64 x = *(const __u64 *)a, y = *(const __u64 *)b;

	return x < y ? -1 : x > y;
}

/*
 * The other executables of the image's usr/bin, by inode. Anything that
 * is not a regular executable file of the mapping itself is not bound:
 * a symlink, a directory or another device's file grants nothing.
 */
static int runtime_tools(int root, dev_t device,
			 struct shirudo_runtime_entry *entry)
{
	struct open_how how = {
		.flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC,
		.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
	};
	struct dirent *e;
	struct stat st;
	int dir, ret = 0;
	DIR *d;

	dir = syscall(SYS_openat2, root, "usr/bin", &how, sizeof(how));
	if (dir < 0)
		return -errno;
	d = fdopendir(dir);
	if (!d) {
		ret = -errno;
		close(dir);
		return ret;
	}
	dir = dirfd(d);
	if (dir < 0) {
		ret = -errno;
		closedir(d);
		return ret;
	}
	while ((e = readdir(d))) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..") ||
		    !strcmp(e->d_name, "shirudo"))
			continue;
		if (fstatat(dir, e->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
			ret = -errno;
			break;
		}
		if (!S_ISREG(st.st_mode) || !(st.st_mode & 0111) ||
		    st.st_dev != device || !st.st_ino)
			continue;
		if (entry->count == SHIRUDO_RUNTIME_ENTRY_MAX) {
			ret = -E2BIG;
			break;
		}
		entry->inodes[entry->count++] = st.st_ino;
	}
	closedir(d);
	if (!ret)
		qsort(entry->inodes + 1, entry->count - 1, sizeof(entry->inodes[0]),
		      inode_order);
	return ret;
}

int shirudo_runtime_worker_open(int root, dev_t device, __u64 diskseq,
				struct shirudo_runtime_entry *entry)
{
	struct open_how how = {
		.flags = O_PATH | O_CLOEXEC,
		.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
	};
	struct stat st;
	int fd, ret = 0;

	memset(entry, 0, sizeof(*entry));
	if (!diskseq)
		return -EKEYREJECTED;
	fd = syscall(SYS_openat2, root, "usr/bin/shirudo", &how, sizeof(how));
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st)) {
		ret = -errno;
	} else if (!S_ISREG(st.st_mode) || !(st.st_mode & 0111) ||
		   st.st_dev != device || !st.st_ino) {
		ret = -EKEYREJECTED;
	} else {
		entry->version = SHIRUDO_RUNTIME_ENTRY_VERSION;
		entry->size = sizeof(*entry);
		entry->diskseq = diskseq;
		entry->inodes[0] = st.st_ino;
		entry->count = 1;
		entry->dev = (major(device) << 20) | minor(device);
	}
	close(fd);
	if (!ret)
		ret = runtime_tools(root, device, entry);
	if (ret)
		memset(entry, 0, sizeof(*entry));
	return ret;
}

/* Only the authenticated bootstrap can acquire a writable descriptor. */
int shirudo_runtime_entry_install(int map,
				  const struct shirudo_runtime_entry *entry)
{
	struct shirudo_runtime_entry observed = {}, empty = {};
	__u32 zero = 0;

	if (!entry || !shirudo_runtime_entry_matches(entry, entry->dev, entry->diskseq))
		return -EKEYREJECTED;
	if (bpf_map_lookup_elem(map, &zero, &observed))
		return -errno;
	if (memcmp(&observed, &empty, sizeof(empty)))
		return -EEXIST;
	if (bpf_map_update_elem(map, &zero, entry, BPF_ANY) || bpf_map_freeze(map))
		return -errno;
	memset(&observed, 0, sizeof(observed));
	if (bpf_map_lookup_elem(map, &zero, &observed))
		return -errno;
	return memcmp(entry, &observed, sizeof(observed)) ? -EKEYREJECTED : 0;
}

static int runtime_entry_map(bool writable)
{
	struct bpf_obj_get_opts opts = {
		.sz = sizeof(opts),
		.file_flags = writable ? 0 : BPF_F_RDONLY,
	};
	struct bpf_map_info info = {};
	__u32 size = sizeof(info);
	int fd, ret;

	fd = bpf_obj_get_opts(RUNTIME_ENTRY_PIN, &opts);
	if (fd < 0)
		return -errno;
	ret = bpf_map_get_info_by_fd(fd, &info, &size) ? -errno : 0;
	if (!ret && (size < sizeof(info) || !info.id ||
		     info.type != BPF_MAP_TYPE_ARRAY || info.key_size != sizeof(__u32) ||
		     info.value_size != sizeof(struct shirudo_runtime_entry) ||
		     info.max_entries != 1 || info.map_flags != BPF_F_RDONLY_PROG ||
		     strcmp(info.name, "shirudo_rt_ent")))
		ret = -EPROTO;
	if (ret) {
		close(fd);
		return ret;
	}
	return fd;
}

static int runtime_entry_open(const char *mountpoint, dev_t device,
			      struct shirudo_runtime_entry *entry)
{
	struct statvfs flags;
	char block_path[64];
	struct stat st;
	__u64 diskseq;
	int root, block, ret;

	root = open(mountpoint, O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (root < 0)
		return -errno;
	ret = fstat(root, &st) || fstatvfs(root, &flags) ? -errno : 0;
	if (ret)
		goto out;
	if ((device && device != st.st_dev) ||
	    (flags.f_flag & (ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC)) !=
	    (ST_RDONLY | ST_NOSUID | ST_NODEV)) {
		ret = -EKEYREJECTED;
		goto out;
	}
	device = st.st_dev;
	ret = strsprintf(block_path, sizeof(block_path), "/dev/dm-%u", minor(device));
	if (ret < 0)
		goto out;
	block = open(block_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (block < 0) {
		ret = -errno;
		goto out;
	}
	ret = fstat(block, &st) || ioctl(block, BLKGETDISKSEQ, &diskseq) ? -errno : 0;
	if (!ret && (!S_ISBLK(st.st_mode) || st.st_rdev != device || !diskseq))
		ret = -EKEYREJECTED;
	close(block);
	if (!ret)
		ret = shirudo_runtime_worker_open(root, device, diskseq, entry);
out:
	close(root);
	return ret;
}

int shirudo_runtime_entry_bind(const char *mountpoint,
			       const struct dm_verity *device)
{
	struct shirudo_runtime_entry entry = {};
	int map, ret;

	ret = runtime_entry_open(mountpoint, device->device, &entry);
	if (ret)
		return ret;
	map = runtime_entry_map(true);
	if (map < 0)
		return map;
	ret = shirudo_runtime_entry_install(map, &entry);
	close(map);
	return ret;
}

int shirudo_runtime_entry_check(const char *mountpoint)
{
	struct shirudo_runtime_entry expected = {}, observed = {};
	__u32 zero = 0;
	int map, ret;

	ret = runtime_entry_open(mountpoint, 0, &expected);
	if (ret)
		return ret;
	map = runtime_entry_map(false);
	if (map < 0)
		return map;
	ret = bpf_map_lookup_elem(map, &zero, &observed) ? -errno : 0;
	if (!ret && memcmp(&expected, &observed, sizeof(expected)))
		ret = -EKEYREJECTED;
	close(map);
	return ret;
}
