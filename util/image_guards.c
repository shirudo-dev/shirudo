// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/perf_event.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/enforcement.h>
#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "identity.h"
#include "image_guards.h"
#include "integrity.h"
#include "log.h"
#include "paths.h"
#include "tamper.h"

const struct image_guard
shirudo_seal_guards[SEAL_HOOK_COUNT] = {
	{ "shirudo_seal_socket_post_create", SEAL_SOCKET_POST_CREATE_PIN },
	{ "shirudo_seal_bprm_creds_for_exec", SEAL_BPRM_CREDS_PIN },
	{ "shirudo_seal_bprm_check_security",
	  SEAL_BPRM_CHECK_PIN },
	{ "shirudo_seal_bprm_committed_creds",
	  SEAL_BPRM_COMMITTED_PIN },
	{ "shirudo_seal_task_alloc", SEAL_TASK_ALLOC_PIN },
	{ "shirudo_seal_file_open",        SEAL_FILE_OPEN_PIN },
	{ "shirudo_seal_inode_unlink",     SEAL_UNLINK_PIN },
	{ "shirudo_seal_inode_rmdir",      SEAL_RMDIR_PIN },
	{ "shirudo_seal_inode_rename",     SEAL_RENAME_PIN },
	{ "shirudo_seal_inode_setattr",    SEAL_SETATTR_PIN },
	{ "shirudo_seal_inode_file_setattr",
	  SEAL_FILE_SETATTR_PIN },
	{ "shirudo_seal_inode_setxattr",   SEAL_SETXATTR_PIN },
	{ "shirudo_seal_inode_removexattr", SEAL_RMXATTR_PIN },
	{ "shirudo_seal_inode_set_acl",    SEAL_SET_ACL_PIN },
	{ "shirudo_seal_inode_remove_acl", SEAL_REMOVE_ACL_PIN },
	{ "shirudo_seal_inode_post_setxattr",
	  SEAL_POST_SETXATTR_PIN },
	{ "shirudo_seal_inode_post_removexattr",
	  SEAL_POST_RMXATTR_PIN },
	{ "shirudo_seal_inode_init_security",
	  SEAL_INIT_SECURITY_PIN },
	{ "shirudo_seal_inode_create",     SEAL_CREATE_PIN },
	{ "shirudo_seal_inode_mkdir",      SEAL_MKDIR_PIN },
	{ "shirudo_seal_inode_symlink",    SEAL_SYMLINK_PIN },
	{ "shirudo_seal_inode_mknod",      SEAL_MKNOD_PIN },
	{ "shirudo_seal_inode_link",       SEAL_LINK_PIN },
	{ "shirudo_seal_inode_copy_up",    SEAL_COPY_UP_PIN },
	{ "shirudo_seal_ptrace_access_check",
	  SEAL_PTRACE_PIN },
	{ "shirudo_seal_mm_read_access",
	  BPFFS_DIR "/seal_mm_read_access_link" },
	{ "shirudo_seal_perf_event_alloc",
	  SEAL_PERF_PIN },
	{ "shirudo_seal_task_kill",        SEAL_TASK_KILL_PIN },
	{ "shirudo_seal_task_setrlimit",
	  BPFFS_DIR "/seal_task_setrlimit_link" },
};

const struct image_guard
shirudo_image_seal_guards[IMAGE_SEAL_HOOK_COUNT] = {
	{ "shirudo_seal_mmap_file",
	  BPFFS_DIR "/seal_mmap_link" },
	{ "shirudo_seal_file_mprotect",
	  BPFFS_DIR "/seal_mprotect_link" },
};

const struct image_guard
shirudo_mount_guards[MOUNT_HOOK_COUNT] = {
	{ "shirudo_lsm_sb_umount",  SB_UMOUNT_LINK_PIN },
	{ "shirudo_lsm_move_mount", MOVE_MOUNT_LINK_PIN },
	{ "shirudo_lsm_sb_mount",   SB_MOUNT_LINK_PIN },
	{ "shirudo_lsm_sb_remount", SB_REMOUNT_LINK_PIN },
	{ "shirudo_lsm_sb_pivotroot", BPFFS_DIR "/bpf2_sb_pivotroot_link" },
	{ "shirudo_lsm_file_open", BPFFS_DIR "/bpf2_file_open_link" },
};

const struct image_guard
shirudo_observer_guards[OBSERVER_HOOK_COUNT] = {
	{ "shirudo_lsm_task_prctl", TASK_PRCTL_LINK_PIN },
	{ "shirudo_lsm_bprm_check_security", BPRM_CHECK_LINK_PIN },
	{ "shirudo_lsm_inode_rmdir",
	  BPFFS_DIR "/inode_rmdir_link" },
	{ "shirudo_lsm_inode_rename",
	  INODE_RENAME_LINK_PIN },
	{ "shirudo_lsm_inode_mkdir",
	  BPFFS_DIR "/inode_mkdir_link" },
	{ "shirudo_lsm_inode_symlink",
	  BPFFS_DIR "/inode_symlink_link" },
	{ "shirudo_lsm_inode_link",
	  BPFFS_DIR "/inode_link_link" },
	{ "shirudo_lsm_kernel_load_data",
	  BPFFS_DIR "/kernel_load_data_link" },
	{ "shirudo_lsm_kernel_read_file",
	  BPFFS_DIR "/kernel_read_file_link" },
	{ "shirudo_lsm_locked_down",
	  BPFFS_DIR "/locked_down_link" },
};

const struct image_guard
shirudo_image_observer_guards[IMAGE_OBSERVER_HOOK_COUNT] = {
	{ "shirudo_lsm_file_ioctl", BPFFS_DIR "/file_ioctl_link" },
	{ "shirudo_lsm_file_ioctl_compat",
	  BPFFS_DIR "/file_ioctl_compat_link" },
	{ "shirudo_lsm_bdev_setintegrity",
	  BPFFS_DIR "/bdev_integrity_link" },
	{ "shirudo_lsm_bdev_free_security",
	  BPFFS_DIR "/bdev_free_link" },
};

const struct image_guard
shirudo_shared_guards[SHARED_HOOK_COUNT] = {
	{ "shirudo_lsm_inode_permission",
	  BPFFS_DIR "/bpf2_inode_permission_link" },
	{ "shirudo_lsm_bpf_map_free", BPFFS_DIR "/bpf2_bpf_map_free_link" },
	{ "shirudo_lsm_bpf_prog_free", BPFFS_DIR "/bpf2_bpf_prog_free_link" },
	{ "shirudo_lsm_bpf_map_create",
	  BPFFS_DIR "/bpf2_bpf_map_create_link" },
};

const struct image_guard
shirudo_gate_guards[GATE_HOOK_COUNT] = {
	[GUARD_UNLINK] = {
		"shirudo_lsm_inode_unlink", INODE_UNLINK_LINK_PIN,
	},
	[GUARD_SETXATTR] = {
		"shirudo_lsm_inode_setxattr", INODE_SETXATTR_LINK_PIN,
	},
	[GUARD_REMOVEXATTR] = {
		"shirudo_lsm_inode_removexattr", INODE_RMXATTR_LINK_PIN,
	},
	[GUARD_KEY_PERMISSION] = {
		"shirudo_lsm_key_permission", KEY_PERMISSION_LINK_PIN,
	},
	[GUARD_TPM_COMMAND] = {
		"shirudo_lsm_tpm_command", TPM_COMMAND_LINK_PIN,
	},
	[GUARD_BPF_MAP] = {
		"shirudo_lsm_bpf_map", LSM_BPF_MAP_LINK_PIN,
	},
	[GUARD_BPF_PROG] = {
		"shirudo_lsm_bpf_prog", LSM_BPF_PROG_LINK_PIN,
	},
	[GUARD_PROG_LOAD] = {
		"shirudo_lsm_bpf_prog_load", LSM_PROG_LOAD_LINK_PIN,
	},
	[GUARD_BPF] = {
		"shirudo_lsm_bpf", LSM_LINK_PIN,
	},
};

/* Initial authenticated boot creates mappings before these guards exist. */
int config_root_begin(const __u8 root[32],
		      struct config_root_guard *guard)
{
	struct expected_root previous = {}, expected = { .valid = 1 };
	const struct guard_map *map =
		&shirudo_guard_maps[GUARD_ROOTS];
	int mode, ret;

	*guard = (struct config_root_guard) {
		.map_fd = -1,
		.task_fd = -1,
	};
	mode = enforcement_active();
	if (!mode)
		return 0;
	if (mode < 0)
		return mode;
	guard->map_fd = bpf_obj_get(map->pin);
	if (guard->map_fd < 0)
		return -errno;
	ret = guard_map_check(guard->map_fd, map, NULL);
	if (ret)
		goto fail;
	guard->task_fd = syscall(SYS_pidfd_open, getpid(), 0);
	if (guard->task_fd < 0) {
		ret = -errno;
		goto fail;
	}
	if (bpf_map_lookup_elem(guard->map_fd, &guard->task_fd, &previous)) {
		if (errno != ENOENT) {
			ret = -errno;
			goto fail;
		}
	} else if (previous.valid) {
		ret = -EBUSY;
		goto fail;
	}
	memcpy(expected.root, root, sizeof(expected.root));
	if (bpf_map_update_elem(guard->map_fd, &guard->task_fd, &expected,
				BPF_ANY)) {
		ret = -errno;
		goto fail;
	}
	return 0;
fail:
	if (guard->task_fd >= 0)
		close(guard->task_fd);
	close(guard->map_fd);
	guard->map_fd = -1;
	guard->task_fd = -1;
	return ret;
}

/* Clear through retained FDs on every exit; report failure to clear. */
int config_root_end(struct config_root_guard *guard)
{
	struct expected_root empty = {};
	int ret = 0;

	if (guard->map_fd < 0)
		return 0;
	if (bpf_map_update_elem(guard->map_fd, &guard->task_fd, &empty,
				BPF_ANY))
		ret = -errno;
	close(guard->task_fd);
	close(guard->map_fd);
	guard->map_fd = -1;
	guard->task_fd = -1;
	return ret;
}

static int guard_map_ids(__u32 ids[GUARD_MAP_COUNT])
{
	__u32 i;
	int fd, ret;

	for (i = 0; i < GUARD_MAP_COUNT; i++) {
		const struct guard_map *expected =
			&shirudo_guard_maps[i];

		fd = bpf_obj_get(expected->pin);
		if (fd < 0)
			return -errno;
		ret = guard_map_check(fd, expected, &ids[i]);
		close(fd);
		if (ret) {
			pr_err("image: invalid guard map %s: %s", expected->pin,
			       strerror(-ret));
			return ret;
		}
	}
	return 0;
}

static int guard_program_maps(const struct bpf_prog_info *program,
			      const __u32 *map_ids,
			      const __u32 expected[GUARD_MAP_COUNT])
{
	struct bpf_map_info info;
	__u32 i, j;
	__u32 length;
	int fd, ret;

	for (i = 0; i < program->nr_map_ids; i++) {
		fd = bpf_map_get_fd_by_id(map_ids[i]);
		if (fd < 0)
			return -errno;
		memset(&info, 0, sizeof(info));
		length = sizeof(info);
		ret = bpf_map_get_info_by_fd(fd, &info, &length);
		if (ret)
			ret = -errno;
		close(fd);
		if (ret)
			return ret;
		for (j = 0; j < GUARD_MAP_COUNT; j++) {
			if (!guard_name_matches(info.name,
						shirudo_guard_maps[j].name))
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
	int fd, ret;

	fd = bpf_btf_get_fd_by_id(id);
	if (fd < 0)
		return -errno;
	info.name = (uintptr_t)name;
	info.name_len = sizeof(name);
	ret = bpf_btf_get_info_by_fd(fd, &info, &length);
	if (ret)
		ret = -errno;
	else if (!info.kernel_btf ||
		 !memchr(name, '\0', sizeof(name)) ||
		 strcmp(name, "vmlinux"))
		ret = -EPROTO;
	close(fd);
	if (ret)
		return ret;
	btf = btf__load_from_kernel_by_id(id);
	ret = libbpf_get_error(btf);
	if (ret)
		return ret;
	*result = btf;
	return 0;
}

static int guard_link(const struct image_guard *guard,
		      const __u32 maps[GUARD_MAP_COUNT],
		      struct btf **kernel, __u32 *kernel_id)
{
	struct bpf_link_info link = {};
	struct bpf_prog_info program = {};
	__u32 map_ids[16] = {};
	char function[96];
	__u32 length;
	const char *suffix;
	int fd, prog, ret, type_id;

	fd = bpf_obj_get(guard->pin);
	if (fd < 0)
		return -errno;
	length = sizeof(link);
	ret = bpf_link_get_info_by_fd(fd, &link, &length);
	if (ret)
		ret = -errno;
	else if (link.type != BPF_LINK_TYPE_TRACING ||
		 !link.id || !link.prog_id ||
		 link.tracing.attach_type != BPF_LSM_MAC)
		ret = -EPROTO;
	close(fd);
	if (ret)
		return ret;
	prog = bpf_prog_get_fd_by_id(link.prog_id);
	if (prog < 0)
		return -errno;
	program.map_ids = (uintptr_t)map_ids;
	program.nr_map_ids = ARRAY_SIZE(map_ids);
	length = sizeof(program);
	ret = bpf_prog_get_info_by_fd(prog, &program, &length);
	if (ret)
		ret = -errno;
	close(prog);
	if (ret)
		return ret;
	if (program.type != BPF_PROG_TYPE_LSM || !program.attach_btf_id ||
	    !program.attach_btf_obj_id || program.id != link.prog_id ||
	    program.nr_map_ids > ARRAY_SIZE(map_ids) ||
	    !guard_name_matches(program.name, guard->prog) ||
	    link.tracing.target_obj_id != program.attach_btf_obj_id ||
	    link.tracing.target_btf_id != program.attach_btf_id)
		return -EPROTO;
	if (!*kernel) {
		ret = guard_kernel_btf(program.attach_btf_obj_id, kernel);
		if (ret)
			return ret;
		*kernel_id = program.attach_btf_obj_id;
	}
	if (*kernel_id != program.attach_btf_obj_id)
		return -EPROTO;
	suffix = guard->prog;
	if (!str_skip_prefix(&suffix, "shirudo_lsm_") &&
	    !str_skip_prefix(&suffix, "shirudo_seal_"))
		return -EPROTO;
	if (strsprintf(function, sizeof(function), "bpf_lsm_%s", suffix) < 0)
		return -ENAMETOOLONG;
	type_id = btf__find_by_name_kind(*kernel, function, BTF_KIND_FUNC);
	if (type_id <= 0 || (__u32)type_id != program.attach_btf_id)
		return -EPROTO;
	return guard_program_maps(&program, map_ids, maps);
}

static int guards_ready(bool shared)
{
	const struct {
		const struct image_guard *guards;
		size_t count;
	} groups[] = {
		{
			.guards = shirudo_shared_guards,
			.count = shared ? SHARED_HOOK_COUNT : 0,
		},
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
	__u32 map_ids[GUARD_MAP_COUNT] = {};
	struct btf *kernel = NULL;
	__u32 kernel_id = 0;
	__u32 i, j;
	int ret;

	ret = guard_map_ids(map_ids);
	if (ret)
		return ret;
	for (i = 0; i < ARRAY_SIZE(groups); i++) {
		for (j = 0; j < groups[i].count; j++) {
			const struct image_guard *guard =
				&groups[i].guards[j];

			ret = guard_link(guard, map_ids, &kernel, &kernel_id);
			if (ret) {
				pr_err("image: missing or invalid guard %s: %s",
				       guard->pin, strerror(-ret));
				goto out;
			}
		}
	}
out:
	btf__free(kernel);
	return ret;
}

/*
 * Authenticated initrd bootstrap precedes every hostile task. Shared mode
 * opens bpf() to root, which only its own guards keep from shirudo's
 * pins and objects, so a shared record without them is refused.
 */
int image_guards_ready(void)
{
	struct identity id = {};
	int ret;

	ret = identity_read(&id);
	if (ret)
		return ret;
	return guards_ready(id.enforcement == ENFORCEMENT_SHARED);
}
