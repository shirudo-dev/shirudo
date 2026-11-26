/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Canonical filesystem paths shirudo owns at runtime.
 */

#ifndef SHIRUDO_PATHS_H
#define SHIRUDO_PATHS_H

#include <stdbool.h>

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include "image_config.h"

/* Target-side. */
#define ETC_DIR			"/etc/shirudo"
#define VAR_LIB			"/var/lib/shirudo"
#define KEYS_DIR		VAR_LIB "/keys"
#define KEYS_DIR_ENV		"SHIRUDO_KEYS_DIR"
#define CERT_FILE		"cert.der"
#define CERT_PATH		KEYS_DIR "/" CERT_FILE
/* The revoked certificates. */
#define KEYS_REVOKED_DIR	KEYS_DIR "/revoked"
/* The initrd's own copy of the keys, measured with the initrd. */
#define INITRD_KEYS_DIR		"/etc/shirudo/keys"
#define INITRD_CERT_PATH	INITRD_KEYS_DIR "/" CERT_FILE
#define UPATCHES_DIR		VAR_LIB "/upatches"
/*
 * The jars of the loaded Java upatches, the one directory of sealed
 * state a JVM reads, which boot restore writes again each boot: outside
 * the state root, which stays closed to other users. The options a user
 * manager's environment.d hands each JVM it starts live as long as the
 * jars they name, so that options never outlive the jars across a boot.
 */
#define JAVA_DIR		"/run/shirudo-java"
#define JAVA_ENV_DIR		"/run/environment.d"
#define JAVA_ENV_PATH		JAVA_ENV_DIR "/shirudo.conf"
#define LOCKS_DIR		VAR_LIB "/locks"
#define EVENTLOG_PATH		VAR_LIB "/eventlog"
/*
 * Per-boot state: the private bpffs holds the pins that keep the LSM
 * links alive. /run is what systemd carries from the initrd into the
 * root file system; a mount anywhere else in the initrd is detached at
 * switch-root and takes the links with it.
 */
#define RUN_DIR			"/run/shirudo"
#define BPFFS_DIR		RUN_DIR "/bpffs"
#define XDP_PROG_PIN_PREFIX	"xdp_prog_"
#define LINK_PIN_PREFIX		"link_"
/* The init record written from the initrd, until the root adopts it. */
#define EVENTLOG_PENDING_PATH	RUN_DIR "/eventlog.pending"
/* On a target with a config image these are the image's, opened from its root. */
#define BPM_ETC_DIR		"/etc/shirudo/bpm"
#define BPM_REGISTRIES_DIR	BPM_ETC_DIR "/registries.d"
#define BPM_KEYS_DIR		BPM_ETC_DIR "/keys"
#define BPM_VAR_DIR		VAR_LIB "/bpm"
#define BPM_REPOS_DIR		BPM_VAR_DIR "/repos"
#define BPM_PACKAGES_DIR	BPM_VAR_DIR "/packages"
#define BPM_STAGING_DIR	BPM_VAR_DIR "/staging"
#define BPM_STATE_PATH	BPM_VAR_DIR "/state.json"
#define BPM_TREE_ETC_PATH	"/etc/shirudo/bpm/upatch-tree.conf"
#define BPM_TREE_VAR_DIR	BPM_VAR_DIR "/upatch-tree"
#define BPM_TREE_STATE_PATH	BPM_TREE_VAR_DIR "/state.json"
#define BPM_TREE_EVENTLOG_PATH BPM_TREE_VAR_DIR "/tree-eventlog"
#define BPM_TREE_OUTCOMES_PATH BPM_TREE_VAR_DIR "/outcomes"
#define BPM_TREE_PENDING_PATH BPM_TREE_VAR_DIR "/pending.json"
#define BPM_TREE_ARTIFACTS_DIR BPM_TREE_VAR_DIR "/artifacts"
#define BPM_TREE_STATUS_DIR BPM_TREE_VAR_DIR "/status"
#define BPM_LOCK_PATH	LOCKS_DIR "/bpm.lock"
#define LSM_LINK_PIN		BPFFS_DIR "/lsm_link"
#define LSM_PROG_LOAD_LINK_PIN	BPFFS_DIR "/bpf2_bpf_prog_load_link"
#define LSM_BPF_MAP_LINK_PIN	BPFFS_DIR "/bpf2_bpf_map_link"
#define LSM_BPF_PROG_LINK_PIN	BPFFS_DIR "/bpf2_bpf_prog_link"
#define SB_UMOUNT_LINK_PIN	BPFFS_DIR "/bpf2_sb_umount_link"
#define MOVE_MOUNT_LINK_PIN	BPFFS_DIR "/bpf2_move_mount_link"
#define SB_MOUNT_LINK_PIN	BPFFS_DIR "/bpf2_sb_mount_link"
#define SB_REMOUNT_LINK_PIN	BPFFS_DIR "/bpf2_sb_remount_link"
#define SB_PIVOTROOT_LINK_PIN	BPFFS_DIR "/bpf2_sb_pivotroot_link"
#define INODE_UNLINK_LINK_PIN	BPFFS_DIR "/bpf2_inode_unlink_link"
#define INODE_RENAME_LINK_PIN	BPFFS_DIR "/bpf2_inode_rename_link"
#define INODE_SETXATTR_LINK_PIN	BPFFS_DIR "/bpf2_inode_setxattr_link"
#define INODE_RMXATTR_LINK_PIN	BPFFS_DIR "/bpf2_inode_removexattr_link"
#define KEY_PERMISSION_LINK_PIN	BPFFS_DIR "/bpf2_key_permission_link"
#define TPM_COMMAND_LINK_PIN	BPFFS_DIR "/bpf2_tpm_command_link"
#define TASK_PRCTL_LINK_PIN	BPFFS_DIR "/bpf2_task_prctl_link"
#define BPRM_CHECK_LINK_PIN	BPFFS_DIR "/bpf2_bprm_check_security_link"
#define SEAL_FILE_OPEN_PIN	BPFFS_DIR "/seal_file_open_link"
#define SEAL_BPRM_CHECK_PIN	BPFFS_DIR "/seal_bprm_check_security_link"
#define SEAL_BPRM_CREDS_PIN	BPFFS_DIR "/seal_bprm_creds_link"
#define SEAL_BPRM_COMMITTED_PIN BPFFS_DIR "/seal_bprm_committed_creds_link"
#define SEAL_TASK_ALLOC_PIN	BPFFS_DIR "/seal_task_alloc_link"
#define SEAL_PTRACE_PIN		BPFFS_DIR "/seal_ptrace_access_check_link"
#define SEAL_PERF_PIN		BPFFS_DIR "/seal_perf_event_alloc_link"
#define SEAL_TASK_KILL_PIN	BPFFS_DIR "/seal_task_kill_link"
#define SEAL_UNLINK_PIN		BPFFS_DIR "/seal_inode_unlink_link"
#define SEAL_RENAME_PIN		BPFFS_DIR "/seal_inode_rename_link"
#define SEAL_SETATTR_PIN \
	BPFFS_DIR "/seal_inode_setattr_link"
#define SEAL_SETXATTR_PIN	BPFFS_DIR "/seal_inode_setxattr_link"
#define SEAL_RMXATTR_PIN	BPFFS_DIR "/seal_inode_removexattr_link"
#define SEAL_POST_SETXATTR_PIN	BPFFS_DIR "/seal_inode_post_setxattr_link"
#define SEAL_POST_RMXATTR_PIN	BPFFS_DIR "/seal_inode_post_removexattr_link"
#define SEAL_COPY_UP_PIN	BPFFS_DIR "/seal_inode_copy_up_link"
#define SEAL_INIT_SECURITY_PIN	BPFFS_DIR "/seal_inode_init_security_link"
#define SEAL_CREATE_PIN		BPFFS_DIR "/seal_inode_create_link"
#define SEAL_MKDIR_PIN		BPFFS_DIR "/seal_inode_mkdir_link"
#define SEAL_SYMLINK_PIN	BPFFS_DIR "/seal_inode_symlink_link"
#define SEAL_MKNOD_PIN		BPFFS_DIR "/seal_inode_mknod_link"
#define SEAL_LINK_PIN		BPFFS_DIR "/seal_inode_link_link"
#define SEAL_RMDIR_PIN		BPFFS_DIR "/seal_inode_rmdir_link"
#define SEAL_SET_ACL_PIN	BPFFS_DIR "/seal_inode_set_acl_link"
#define SEAL_REMOVE_ACL_PIN	BPFFS_DIR "/seal_inode_remove_acl_link"
#define SEAL_FILE_SETATTR_PIN	BPFFS_DIR "/seal_inode_file_setattr_link"
#define BPFFS_UPATCHES_DIR	BPFFS_DIR "/upatches"
#define IDENTITY_PIN_NAME	"identity"
#define IDENTITY_PIN		BPFFS_DIR "/" IDENTITY_PIN_NAME
#define TAMPER_PIN		BPFFS_DIR "/tamper"
#define INTEGRITY_PIN		BPFFS_DIR "/integrity"
#define POLICY_PIN		BPFFS_DIR "/task_policy"
#define SEAL_SOCKET_POST_CREATE_PIN \
	BPFFS_DIR "/seal_socket_post_create_link"
#define SOCKET_POLICY_PIN	BPFFS_DIR "/socket_policy"

#define RUNTIME_DIR		RUN_DIR "/runtime"
#define CONFIG_IMAGE_DIR		RUN_DIR "/config"
#define CONFIG_CANDIDATE_DIR	RUN_DIR "/config-candidate"
#define CONFIG_UPDATE_DIR	VAR_LIB "/config-update"
#define IMAGE_CACHE_DIR		VAR_LIB "/images"
#define RUNTIME_CONF_PATH \
	RUNTIME_DIR "/etc/shirudo/shirudo.conf"
#define RUNTIME_CERT_PATH	RUNTIME_DIR "/keys/cert.der"

/* Operator-side. */
#define SIGNING_KEY_FILE	"signing_key.pem"
#define SIGNING_KEY_PATH	KEYS_DIR "/" SIGNING_KEY_FILE

#define XATTR_SEAL		"security.bpf.shirudo"
#define XATTR_POLICY		"security.bpf.shirudo.policy"
#define XATTR_ANCESTOR		"security.bpf.shirudo.ancestor"

/*
 * Per-upatch payload_sha256 recorded on the pin directory in bpffs.
 * Written at load, read at unload for the payload_mismatch check; made
 * unforgeable by the bpf2 inode_setxattr guard.
 */
#define XATTR_PAYLOAD		"security.bpf.shirudo.payload"

/*
 * TPM2 NV index of the measurement register (owner-defined range).
 * Override at build time if it collides with site policy. An NV
 * extend index rather than a PCR, as systemd's NvPCRs: no free PCR
 * exists on a stock Linux + grub + IMA system and PCR 23 is
 * application-resettable; PCR 15 only anchors the index name.
 */
#ifndef NV_INDEX
#define NV_INDEX		0x01818E00u
/*
 * The PCR-key branch of the config NvPCR's write policy, which
 * systemd-tpm2-setup records when it initializes the NvPCR.
 */
#define CONFIG_NVPCR_AUTH_PATH	"/run/systemd/nvpcr/shirudo-config.auth"
#endif

/* Site config. */
#define CONF_PATH		"/etc/shirudo/shirudo.conf"

int format_key_path(char *out, size_t out_sz,
		    const char *keys_dir, const char *file);
int key_paths(const char *keys_dir,
	      char *pkey_path, size_t pkey_sz,
	      char *cert_path, size_t cert_sz);
const char *keys_dir_resolve(const char *keys_dir_arg);

/*
 * bpffs reserves dots in path components, which upatch names may
 * carry, so a dot becomes ~d; ~ is not a valid name character, so no
 * raw name collides. The raw name stays the identity in the format and
 * the eventlog.
 */
static inline int upatch_bpffs_name(char *out, size_t out_sz,
				    const char *name)
{
	size_t i, j, len;

	if (!out || out_sz == 0 || !name)
		return -EINVAL;
	len = strlen(name);
	if (len * 2 + 1 > out_sz)
		return -ENAMETOOLONG;
	for (i = 0, j = 0; i < len; i++) {
		if (name[i] == '.') {
			out[j++] = '~';
			out[j++] = 'd';
		} else {
			out[j++] = name[i];
		}
	}
	out[j] = '\0';
	return 0;
}

static inline int upatch_name_from_bpffs(char *out, size_t out_sz,
					 const char *name)
{
	size_t i, j;

	if (!out || out_sz == 0 || !name)
		return -EINVAL;
	for (i = 0, j = 0; name[i]; i++) {
		char c = name[i];

		if (c == '~') {
			if (name[i + 1] != 'd')
				return -EINVAL;
			i++;
			c = '.';
		}
		if (j + 1 >= out_sz)
			return -ENAMETOOLONG;
		out[j++] = c;
	}
	out[j] = '\0';
	return 0;
}

/*
 * The pin directory of the upatch name, BPFFS_UPATCHES_DIR and its bpffs
 * name, and then each path component that follows, up to the NULL that
 * ends them. 0, or -ENAMETOOLONG with out empty.
 */
int upatch_pin_path(char *out, size_t cap, const char *name, ...) __sentinel;

/* dir, a slash and name: 0, or -ENAMETOOLONG with out empty. */
int path_join(char *out, size_t cap, const char *dir, const char *name);

bool path_exists(const char *path);

#endif /* SHIRUDO_PATHS_H */
