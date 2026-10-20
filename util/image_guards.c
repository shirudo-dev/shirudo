// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/btf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "identity.h"
#include "image_guards.h"
#include "log.h"
#include "macros.h"
#include "paths.h"
#include "shirudo_mode.h"
#include "tamper.h"

const struct shirudo_image_guard
shirudo_seal_guards[SHIRUDO_SEAL_HOOK_COUNT] = {
	{ "shirudo_seal_bprm_check_security",
	  SHIRUDO_SEAL_BPRM_CHECK_PIN },
	{ "shirudo_seal_bprm_committed_creds",
	  SHIRUDO_SEAL_BPRM_COMMITTED_PIN },
	{ "shirudo_seal_task_alloc", SHIRUDO_SEAL_TASK_ALLOC_PIN },
	{ "shirudo_seal_file_open",        SHIRUDO_SEAL_FILE_OPEN_PIN },
	{ "shirudo_seal_inode_unlink",     SHIRUDO_SEAL_UNLINK_PIN },
	{ "shirudo_seal_inode_rename",     SHIRUDO_SEAL_RENAME_PIN },
	{ "shirudo_seal_inode_setattr",    SHIRUDO_SEAL_SETATTR_PIN },
	{ "shirudo_seal_inode_setxattr",   SHIRUDO_SEAL_SETXATTR_PIN },
	{ "shirudo_seal_inode_removexattr", SHIRUDO_SEAL_RMXATTR_PIN },
	{ "shirudo_seal_inode_post_setxattr",
	  SHIRUDO_SEAL_POST_SETXATTR_PIN },
	{ "shirudo_seal_inode_post_removexattr",
	  SHIRUDO_SEAL_POST_RMXATTR_PIN },
	{ "shirudo_seal_inode_init_security",
	  SHIRUDO_SEAL_INIT_SECURITY_PIN },
	{ "shirudo_seal_ptrace_access_check",
	  SHIRUDO_SEAL_PTRACE_PIN },
	{ "shirudo_seal_perf_event_alloc",
	  SHIRUDO_SEAL_PERF_PIN },
};

const struct shirudo_image_guard
shirudo_image_seal_guards[SHIRUDO_IMAGE_SEAL_HOOK_COUNT] = {
	{ "shirudo_seal_mmap_file",
	  SHIRUDO_BPFFS_DIR "/seal_mmap_link" },
	{ "shirudo_seal_file_mprotect",
	  SHIRUDO_BPFFS_DIR "/seal_mprotect_link" },
};

const struct shirudo_image_guard
shirudo_mount_guards[SHIRUDO_MOUNT_HOOK_COUNT] = {
	{ "shirudo_lsm_sb_umount",  SHIRUDO_SB_UMOUNT_LINK_PIN },
	{ "shirudo_lsm_move_mount", SHIRUDO_MOVE_MOUNT_LINK_PIN },
	{ "shirudo_lsm_sb_mount",   SHIRUDO_SB_MOUNT_LINK_PIN },
	{ "shirudo_lsm_sb_remount", SHIRUDO_SB_REMOUNT_LINK_PIN },
};

const struct shirudo_image_guard
shirudo_observer_guards[SHIRUDO_OBSERVER_HOOK_COUNT] = {
	{ "shirudo_lsm_task_prctl", SHIRUDO_TASK_PRCTL_LINK_PIN },
	{ "shirudo_lsm_bprm_check_security", SHIRUDO_BPRM_CHECK_LINK_PIN },
	{ "shirudo_lsm_inode_rmdir",
	  SHIRUDO_BPFFS_DIR "/inode_rmdir_link" },
	{ "shirudo_lsm_inode_rename",
	  SHIRUDO_INODE_RENAME_LINK_PIN },
};

const struct shirudo_image_guard
shirudo_image_observer_guards[SHIRUDO_IMAGE_OBSERVER_HOOK_COUNT] = {
	{ "shirudo_lsm_file_ioctl", SHIRUDO_BPFFS_DIR "/file_ioctl_link" },
	{ "shirudo_lsm_bdev_setintegrity",
	  SHIRUDO_BPFFS_DIR "/bdev_integrity_link" },
	{ "shirudo_lsm_bdev_free_security",
	  SHIRUDO_BPFFS_DIR "/bdev_free_link" },
};

const struct shirudo_image_guard
shirudo_gate_guards[SHIRUDO_GATE_HOOK_COUNT] = {
	[SHIRUDO_GUARD_UNLINK] = {
		"shirudo_lsm_inode_unlink", SHIRUDO_INODE_UNLINK_LINK_PIN,
	},
	[SHIRUDO_GUARD_SETXATTR] = {
		"shirudo_lsm_inode_setxattr", SHIRUDO_INODE_SETXATTR_LINK_PIN,
	},
	[SHIRUDO_GUARD_REMOVEXATTR] = {
		"shirudo_lsm_inode_removexattr", SHIRUDO_INODE_RMXATTR_LINK_PIN,
	},
	[SHIRUDO_GUARD_KEY_PERMISSION] = {
		"shirudo_lsm_key_permission", SHIRUDO_KEY_PERMISSION_LINK_PIN,
	},
	[SHIRUDO_GUARD_BPF_MAP] = {
		"shirudo_lsm_bpf_map", SHIRUDO_LSM_BPF_MAP_LINK_PIN,
	},
	[SHIRUDO_GUARD_PROG_LOAD] = {
		"shirudo_lsm_bpf_prog_load", SHIRUDO_LSM_PROG_LOAD_LINK_PIN,
	},
	[SHIRUDO_GUARD_BPF] = {
		"shirudo_lsm_bpf", SHIRUDO_LSM_LINK_PIN,
	},
};

const struct shirudo_guard_map shirudo_guard_maps[SHIRUDO_GUARD_MAP_COUNT] = {
	[SHIRUDO_GUARD_IDENTITY] = {
		"shirudo_bpffs_sb", SHIRUDO_IDENTITY_PIN,
		BPF_MAP_TYPE_ARRAY, sizeof(__u32),
		sizeof(struct shirudo_identity), 1, 0,
	},
	[SHIRUDO_GUARD_TASKS] = {
		"shirudo_tasks", SHIRUDO_BPFFS_DIR "/task_authority",
		BPF_MAP_TYPE_TASK_STORAGE, sizeof(__u32),
		sizeof(struct shirudo_task_authority), 0, BPF_F_NO_PREALLOC,
	},
	[SHIRUDO_GUARD_DEVICES] = {
		"shirudo_devices", SHIRUDO_BPFFS_DIR "/devices",
		BPF_MAP_TYPE_HASH, sizeof(__u64),
		sizeof(struct shirudo_device_authority), 128, 0,
	},
	[SHIRUDO_GUARD_ROOTS] = {
		"shirudo_roots", SHIRUDO_BPFFS_DIR "/config_roots",
		BPF_MAP_TYPE_TASK_STORAGE, sizeof(__u32),
		sizeof(struct shirudo_expected_root), 0, BPF_F_NO_PREALLOC,
	},
	[SHIRUDO_GUARD_TAMPER] = {
		"shirudo_tamper", SHIRUDO_TAMPER_PIN,
		BPF_MAP_TYPE_ARRAY, sizeof(__u32),
		sizeof(__u64), SHIRUDO_TAMPER_MAX, 0,
	},
};

/* Initial authenticated boot creates mappings before these guards exist. */
int shirudo_config_root_begin(const __u8 root[32],
			      struct shirudo_config_root_guard *guard)
{
	struct shirudo_expected_root previous = {}, expected = { .valid = 1 };
	const struct shirudo_guard_map *map =
		&shirudo_guard_maps[SHIRUDO_GUARD_ROOTS];
	int mode, rc;

	*guard = (struct shirudo_config_root_guard) {
		.map_fd = -1,
		.task_fd = -1,
	};
	mode = shirudo_identity_mode();
	if (mode == SHIRUDO_MODE_NONE)
		return 0;
	if (mode != SHIRUDO_MODE_IMAGE)
		return mode < 0 ? mode : -EPERM;
	guard->map_fd = bpf_obj_get(map->pin);
	if (guard->map_fd < 0)
		return -errno;
	guard->task_fd = syscall(SYS_pidfd_open, getpid(), 0);
	if (guard->task_fd < 0) {
		rc = -errno;
		goto fail;
	}
	if (bpf_map_lookup_elem(guard->map_fd, &guard->task_fd, &previous)) {
		if (errno != ENOENT) {
			rc = -errno;
			goto fail;
		}
	} else if (previous.valid) {
		rc = -EBUSY;
		goto fail;
	}
	memcpy(expected.root, root, sizeof(expected.root));
	if (bpf_map_update_elem(guard->map_fd, &guard->task_fd, &expected,
				BPF_ANY)) {
		rc = -errno;
		goto fail;
	}
	return 0;
fail:
	if (guard->task_fd >= 0)
		close(guard->task_fd);
	close(guard->map_fd);
	guard->map_fd = -1;
	guard->task_fd = -1;
	return rc;
}

/* Clear through retained FDs on every exit; report failure to clear. */
int shirudo_config_root_end(struct shirudo_config_root_guard *guard)
{
	struct shirudo_expected_root empty = {};
	int rc = 0;

	if (guard->map_fd < 0)
		return 0;
	if (bpf_map_update_elem(guard->map_fd, &guard->task_fd, &empty,
				BPF_ANY))
		rc = -errno;
	close(guard->task_fd);
	close(guard->map_fd);
	guard->map_fd = -1;
	guard->task_fd = -1;
	return rc;
}

static int guard_map_ids(__u32 ids[SHIRUDO_GUARD_MAP_COUNT])
{
	struct bpf_map_info info;
	__u32 length;
	__u32 i;
	int fd, rc;

	for (i = 0; i < SHIRUDO_GUARD_MAP_COUNT; i++) {
		const struct shirudo_guard_map *expected =
			&shirudo_guard_maps[i];

		fd = bpf_obj_get(expected->pin);
		if (fd < 0)
			return -errno;
		memset(&info, 0, sizeof(info));
		length = sizeof(info);
		rc = bpf_map_get_info_by_fd(fd, &info, &length);
		if (rc)
			rc = -errno;
		else if (!info.id || info.type != expected->type ||
			 info.key_size != expected->key_size ||
			 info.value_size != expected->value_size ||
			 info.max_entries != expected->max_entries ||
			 info.map_flags != expected->flags ||
			 info.name[sizeof(info.name) - 1] ||
			 strncmp(info.name, expected->name,
				 sizeof(info.name) - 1))
			rc = -EPROTO;
		close(fd);
		if (rc) {
			pr_err("image: invalid guard map %s: %s", expected->pin,
			       strerror(-rc));
			return rc;
		}
		ids[i] = info.id;
	}
	return 0;
}

static int guard_program_maps(const struct bpf_prog_info *program,
			      const __u32 *map_ids,
			      const __u32 expected[SHIRUDO_GUARD_MAP_COUNT])
{
	struct bpf_map_info info;
	__u32 i, j;
	__u32 length;
	int fd, rc;

	for (i = 0; i < program->nr_map_ids; i++) {
		fd = bpf_map_get_fd_by_id(map_ids[i]);
		if (fd < 0)
			return -errno;
		memset(&info, 0, sizeof(info));
		length = sizeof(info);
		rc = bpf_map_get_info_by_fd(fd, &info, &length);
		if (rc)
			rc = -errno;
		close(fd);
		if (rc)
			return rc;
		for (j = 0; j < SHIRUDO_GUARD_MAP_COUNT; j++) {
			if (strncmp(info.name, shirudo_guard_maps[j].name,
				    sizeof(info.name) - 1))
				continue;
			if (info.id != expected[j])
				return -EPROTO;
		}
	}
	return 0;
}

static int guard_kernel_btf(__u32 id, struct btf **result)
{
	struct bpf_btf_info info = {};
	__u32 length = sizeof(info);
	char name[16] = {};
	struct btf *btf;
	int fd, rc;

	fd = bpf_btf_get_fd_by_id(id);
	if (fd < 0)
		return -errno;
	info.name = (uintptr_t)name;
	info.name_len = sizeof(name);
	rc = bpf_btf_get_info_by_fd(fd, &info, &length);
	if (rc)
		rc = -errno;
	else if (!info.kernel_btf ||
		 !memchr(name, '\0', sizeof(name)) ||
		 strcmp(name, "vmlinux"))
		rc = -EPROTO;
	close(fd);
	if (rc)
		return rc;
	btf = btf__load_from_kernel_by_id(id);
	rc = libbpf_get_error(btf);
	if (rc)
		return rc;
	*result = btf;
	return 0;
}

static int guard_link(const struct shirudo_image_guard *guard,
		      const __u32 maps[SHIRUDO_GUARD_MAP_COUNT],
		      struct btf **kernel, __u32 *kernel_id)
{
	struct bpf_link_info link = {};
	struct bpf_prog_info program = {};
	__u32 map_ids[16] = {};
	char function[96];
	__u32 length;
	const char *suffix;
	int fd, prog, rc, type_id;

	fd = bpf_obj_get(guard->pin);
	if (fd < 0)
		return -errno;
	length = sizeof(link);
	rc = bpf_link_get_info_by_fd(fd, &link, &length);
	if (rc)
		rc = -errno;
	else if (link.type != BPF_LINK_TYPE_TRACING ||
		 !link.id || !link.prog_id ||
		 link.tracing.attach_type != BPF_LSM_MAC)
		rc = -EPROTO;
	close(fd);
	if (rc)
		return rc;
	prog = bpf_prog_get_fd_by_id(link.prog_id);
	if (prog < 0)
		return -errno;
	program.map_ids = (uintptr_t)map_ids;
	program.nr_map_ids = ARRAY_SIZE(map_ids);
	length = sizeof(program);
	rc = bpf_prog_get_info_by_fd(prog, &program, &length);
	if (rc)
		rc = -errno;
	close(prog);
	if (rc)
		return rc;
	if (program.type != BPF_PROG_TYPE_LSM || !program.attach_btf_id ||
	    !program.attach_btf_obj_id || program.id != link.prog_id ||
	    program.nr_map_ids > ARRAY_SIZE(map_ids) ||
	    strncmp(program.name, guard->prog, sizeof(program.name) - 1) ||
	    link.tracing.target_obj_id != program.attach_btf_obj_id ||
	    link.tracing.target_btf_id != program.attach_btf_id)
		return -EPROTO;
	if (!*kernel) {
		rc = guard_kernel_btf(program.attach_btf_obj_id, kernel);
		if (rc)
			return rc;
		*kernel_id = program.attach_btf_obj_id;
	}
	if (*kernel_id != program.attach_btf_obj_id)
		return -EPROTO;
	suffix = !strncmp(guard->prog, "shirudo_lsm_", 12) ?
		 guard->prog + 12 : guard->prog + 13;
	if (snprintf(function, sizeof(function), "bpf_lsm_%s", suffix) >=
	    (int)sizeof(function))
		return -ENAMETOOLONG;
	type_id = btf__find_by_name_kind(*kernel, function, BTF_KIND_FUNC);
	if (type_id <= 0 || (__u32)type_id != program.attach_btf_id)
		return -EPROTO;
	return guard_program_maps(&program, map_ids, maps);
}

/* Authenticated initrd bootstrap precedes every hostile task. */
int shirudo_image_guards_ready(void)
{
	const struct {
		const struct shirudo_image_guard *guards;
		size_t count;
	} groups[] = {
		{
			.guards = shirudo_gate_guards,
			.count = ARRAY_SIZE(shirudo_gate_guards),
		},
		{
			.guards = shirudo_observer_guards,
			.count = ARRAY_SIZE(shirudo_observer_guards),
		},
		{
			.guards = shirudo_mount_guards,
			.count = ARRAY_SIZE(shirudo_mount_guards),
		},
		{
			.guards = shirudo_seal_guards,
			.count = ARRAY_SIZE(shirudo_seal_guards),
		},
		{
			.guards = shirudo_image_seal_guards,
			.count = ARRAY_SIZE(shirudo_image_seal_guards),
		},
		{
			.guards = shirudo_image_observer_guards,
			.count = ARRAY_SIZE(shirudo_image_observer_guards),
		},
	};
	__u32 map_ids[SHIRUDO_GUARD_MAP_COUNT] = {};
	struct btf *kernel = NULL;
	__u32 kernel_id = 0;
	__u32 i, j;
	int rc;

	rc = guard_map_ids(map_ids);
	if (rc)
		return rc;
	for (i = 0; i < ARRAY_SIZE(groups); i++) {
		for (j = 0; j < groups[i].count; j++) {
			const struct shirudo_image_guard *guard =
				&groups[i].guards[j];

			rc = guard_link(guard, map_ids, &kernel, &kernel_id);
			if (rc) {
				pr_err("image: missing or invalid guard %s: %s",
				       guard->pin, strerror(-rc));
				goto out;
			}
		}
	}
out:
	btf__free(kernel);
	return rc;
}
