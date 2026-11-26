// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Read back the identity map init pinned in the private bpffs, and check
 * the shape of every map init pins there.
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <linux/bpf.h>

#include <bpf/bpf.h>

#include <shirudo/enforcement.h>
#include <shirudo/misc.h>

#include "identity.h"
#include "integrity.h"
#include "io.h"
#include "paths.h"
#include "seal.h"
#include "tamper.h"

const struct guard_map shirudo_guard_maps[GUARD_MAP_COUNT] = {
	[GUARD_IDENTITY] = {
		"shirudo_bpffs_sb", IDENTITY_PIN,
		BPF_MAP_TYPE_ARRAY, sizeof(__u32),
		sizeof(struct identity), 1, BPF_F_RDONLY_PROG,
	},
	[GUARD_TASKS] = {
		"shirudo_tasks", BPFFS_DIR "/task_authority",
		BPF_MAP_TYPE_TASK_STORAGE, sizeof(__u32),
		sizeof(struct task_authority), 0, BPF_F_NO_PREALLOC,
	},
	[GUARD_POLICY] = {
		"shirudo_task_policy", POLICY_PIN,
		BPF_MAP_TYPE_TASK_STORAGE, sizeof(__u32),
		sizeof(struct task_policy), 0, BPF_F_NO_PREALLOC,
	},
	[GUARD_SOCKET_POLICY] = {
		"shirudo_sock_policy", SOCKET_POLICY_PIN,
		BPF_MAP_TYPE_SK_STORAGE, sizeof(__u32), sizeof(__u64), 0,
		BPF_F_NO_PREALLOC | BPF_F_CLONE,
	},
	[GUARD_DEVICES] = {
		"shirudo_devices", BPFFS_DIR "/devices",
		BPF_MAP_TYPE_HASH, sizeof(__u64),
		sizeof(struct device_authority), 128, 0,
	},
	[GUARD_ROOTS] = {
		"shirudo_roots", BPFFS_DIR "/config_roots",
		BPF_MAP_TYPE_TASK_STORAGE, sizeof(__u32),
		sizeof(struct expected_root), 0, BPF_F_NO_PREALLOC,
	},
	[GUARD_TAMPER] = {
		"shirudo_tamper", TAMPER_PIN,
		BPF_MAP_TYPE_ARRAY, sizeof(__u32),
		sizeof(__u64), TAMPER_MAX, 0,
	},
	[GUARD_INTEGRITY] = {
		"shirudo_integrity", INTEGRITY_PIN,
		BPF_MAP_TYPE_ARRAY, sizeof(__u32),
		sizeof(__u64), INTEGRITY_MAX, 0,
	},
};

int enforcement_active(void)
{
	int ret = prctl(PR_GET_ENFORCEMENT, 0, 0, 0, 0);

	if (ret >= 0)
		return -EPROTO;
	if (errno == PR_ENFORCING_ERR)
		return 1;
	return errno == EINVAL || errno == ENOSYS ? 0 : -errno;
}

bool guard_name_matches(const char *name, const char *full)
{
	size_t len = strnlen(name, BPF_OBJ_NAME_LEN);

	return len < BPF_OBJ_NAME_LEN &&
	       len == strnlen(full, BPF_OBJ_NAME_LEN - 1) &&
	       !memcmp(name, full, len);
}

int guard_map_check(int fd, const struct guard_map *expected, __u32 *id)
{
	struct bpf_map_info info = {};
	__u32 length = sizeof(info);

	if (bpf_map_get_info_by_fd(fd, &info, &length))
		return -errno;
	if (!info.id || info.type != expected->type ||
	    info.key_size != expected->key_size ||
	    info.value_size != expected->value_size ||
	    info.max_entries != expected->max_entries ||
	    info.map_flags != expected->flags ||
	    !guard_name_matches(info.name, expected->name))
		return -EPROTO;
	if (id)
		*id = info.id;
	return 0;
}

static int identity_map_read(int fd, struct identity *out)
{
	__u32 zero = 0;
	int ret;

	ret = guard_map_check(fd, &shirudo_guard_maps[GUARD_IDENTITY], NULL);
	if (ret)
		return ret;
	if (bpf_map_lookup_elem(fd, &zero, out))
		return -errno;
	return 0;
}

int identity_read_at(int dirfd, const char *name, struct identity *out)
{
	LIBBPF_OPTS(bpf_obj_get_opts, opts,
		    .file_flags = BPF_F_PATH_FD,
		    .path_fd = dirfd);
	int fd, ret;

	memset(out, 0, sizeof(*out));
	fd = bpf_obj_get_opts(name, &opts);
	if (fd < 0)
		return -errno;
	ret = identity_map_read(fd, out);
	close(fd);
	return ret;
}

int identity_read(struct identity *out)
{
	return identity_read_at(AT_FDCWD, IDENTITY_PIN, out);
}

/*
 * Root may mount over /run/shirudo in a mount namespace of its own, but
 * no mount lands inside the private bpffs and no pin but shirudo's
 * enters it, so the one directory that holds the identity pin and lies
 * on the device it records is the bpffs root, reached through any mount.
 */
static int bpffs_open_identity(struct identity *id)
{
	struct stat st;
	int fd, ret;

	fd = open(BPFFS_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	ret = identity_read_at(fd, IDENTITY_PIN_NAME, id);
	if (!ret && fstat(fd, &st))
		ret = -errno;
	if (!ret && kernel_dev(st.st_dev) != id->sb_dev)
		ret = -EXDEV;
	if (ret) {
		close(fd);
		return ret;
	}
	return fd;
}

int bpffs_root_open(void)
{
	struct identity id;

	return bpffs_open_identity(&id);
}

int identity_check_state_root(const struct identity *id, int fd)
{
	struct stat st;

	if (fstat(fd, &st))
		return -errno;
	if (!S_ISDIR(st.st_mode) || st.st_dev != id->state_dev || st.st_ino != id->state_ino)
		return -EXDEV;
	return 0;
}

int state_root_open(void)
{
	struct identity id;
	int bpffs, fd, ret;

	bpffs = bpffs_open_identity(&id);
	if (bpffs < 0)
		return bpffs;
	close(bpffs);
	fd = seal_open_state_root();
	if (fd < 0)
		return fd;
	ret = identity_check_state_root(&id, fd);
	if (ret) {
		close(fd);
		return ret;
	}
	return fd;
}
