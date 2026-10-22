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
#define SHIRUDO_ETC_DIR			"/etc/shirudo"
#define SHIRUDO_VAR_LIB			"/var/lib/shirudo"
#define SHIRUDO_KEYS_DIR		SHIRUDO_VAR_LIB "/keys"
#define SHIRUDO_KEYS_DIR_ENV		"SHIRUDO_KEYS_DIR"
#define SHIRUDO_CERT_FILE		"cert.der"
#define SHIRUDO_CERT_PATH		SHIRUDO_KEYS_DIR "/" SHIRUDO_CERT_FILE
/* Further certificates enrolled beside cert.der, and the revoked ones. */
#define SHIRUDO_KEYS_TRUSTED_DIR \
	(shirudo_image_path(SHIRUDO_IMAGE_TRUSTED_KEYS) ?: \
	 SHIRUDO_KEYS_DIR "/trusted")
#define SHIRUDO_KEYS_REVOKED_DIR \
	(shirudo_image_path(SHIRUDO_IMAGE_REVOKED_KEYS) ?: \
	 SHIRUDO_KEYS_DIR "/revoked")
/* The initrd's own copy of the keys, measured with the initrd. */
#define SHIRUDO_INITRD_KEYS_DIR		"/etc/shirudo/keys"
#define SHIRUDO_INITRD_CERT_PATH	SHIRUDO_INITRD_KEYS_DIR "/" SHIRUDO_CERT_FILE
#define SHIRUDO_UPATCHES_DIR		SHIRUDO_VAR_LIB "/upatches"
#define SHIRUDO_INCOMING_DIR		SHIRUDO_VAR_LIB "/incoming"
#define SHIRUDO_LOCKS_DIR		SHIRUDO_VAR_LIB "/locks"
#define SHIRUDO_EVENTLOG_PATH		SHIRUDO_VAR_LIB "/eventlog"
/*
 * Per-boot state: the private bpffs holds the pins that keep the LSM
 * links alive. /run is what systemd carries from the initrd into the
 * root file system; a mount anywhere else in the initrd is detached at
 * switch-root and takes the links with it.
 */
#define SHIRUDO_RUN_DIR			"/run/shirudo"
#define SHIRUDO_BPFFS_DIR		SHIRUDO_RUN_DIR "/bpffs"
/* The init record written from the initrd, until the root adopts it. */
#define SHIRUDO_EVENTLOG_PENDING_PATH	SHIRUDO_RUN_DIR "/eventlog.pending"
#define SHIRUDO_BPM_ETC_DIR \
	(shirudo_image_path(SHIRUDO_IMAGE_ETC) ?: "/etc/shirudo/bpm")
#define SHIRUDO_BPM_REGISTRIES_DIR \
	(shirudo_image_path(SHIRUDO_IMAGE_REGISTRIES) ?: \
	 "/etc/shirudo/bpm/registries.d")
#define SHIRUDO_BPM_KEYS_DIR \
	(shirudo_image_path(SHIRUDO_IMAGE_REPOSITORY_KEYS) ?: \
	 "/etc/shirudo/bpm/keys")
#define SHIRUDO_BPM_VAR_DIR		SHIRUDO_VAR_LIB "/bpm"
#define SHIRUDO_BPM_REPOS_DIR		SHIRUDO_BPM_VAR_DIR "/repos"
#define SHIRUDO_BPM_PACKAGES_DIR	SHIRUDO_BPM_VAR_DIR "/packages"
#define SHIRUDO_BPM_STAGING_DIR	SHIRUDO_BPM_VAR_DIR "/staging"
#define SHIRUDO_BPM_STATE_PATH	SHIRUDO_BPM_VAR_DIR "/state.json"
#define SHIRUDO_BPM_TREE_ETC_PATH \
	(shirudo_image_path(SHIRUDO_IMAGE_TREE_CONF) ?: \
	 "/etc/shirudo/bpm/upatch-tree.conf")
#define SHIRUDO_BPM_TREE_VAR_DIR	SHIRUDO_BPM_VAR_DIR "/upatch-tree"
#define SHIRUDO_BPM_TREE_STATE_PATH	SHIRUDO_BPM_TREE_VAR_DIR "/state.json"
#define SHIRUDO_BPM_TREE_EVENTLOG_PATH SHIRUDO_BPM_TREE_VAR_DIR "/tree-eventlog"
#define SHIRUDO_BPM_TREE_PENDING_PATH SHIRUDO_BPM_TREE_VAR_DIR "/pending.json"
#define SHIRUDO_BPM_TREE_ARTIFACTS_DIR SHIRUDO_BPM_TREE_VAR_DIR "/artifacts"
#define SHIRUDO_BPM_TREE_STATUS_DIR SHIRUDO_BPM_TREE_VAR_DIR "/status"
#define SHIRUDO_BPM_LOCK_PATH	SHIRUDO_LOCKS_DIR "/bpm.lock"
#define SHIRUDO_LSM_LINK_PIN		SHIRUDO_BPFFS_DIR "/lsm_link"
#define SHIRUDO_LSM_PROG_LOAD_LINK_PIN	SHIRUDO_BPFFS_DIR "/bpf2_bpf_prog_load_link"
#define SHIRUDO_LSM_BPF_MAP_LINK_PIN	SHIRUDO_BPFFS_DIR "/bpf2_bpf_map_link"
#define SHIRUDO_SB_UMOUNT_LINK_PIN	SHIRUDO_BPFFS_DIR "/bpf2_sb_umount_link"
#define SHIRUDO_MOVE_MOUNT_LINK_PIN	SHIRUDO_BPFFS_DIR "/bpf2_move_mount_link"
#define SHIRUDO_SB_MOUNT_LINK_PIN	SHIRUDO_BPFFS_DIR "/bpf2_sb_mount_link"
#define SHIRUDO_SB_REMOUNT_LINK_PIN	SHIRUDO_BPFFS_DIR "/bpf2_sb_remount_link"
#define SHIRUDO_INODE_UNLINK_LINK_PIN	SHIRUDO_BPFFS_DIR "/bpf2_inode_unlink_link"
#define SHIRUDO_INODE_RENAME_LINK_PIN	SHIRUDO_BPFFS_DIR "/bpf2_inode_rename_link"
#define SHIRUDO_INODE_SETXATTR_LINK_PIN	SHIRUDO_BPFFS_DIR "/bpf2_inode_setxattr_link"
#define SHIRUDO_INODE_RMXATTR_LINK_PIN	SHIRUDO_BPFFS_DIR "/bpf2_inode_removexattr_link"
#define SHIRUDO_KEY_PERMISSION_LINK_PIN	SHIRUDO_BPFFS_DIR "/bpf2_key_permission_link"
#define SHIRUDO_TASK_PRCTL_LINK_PIN	SHIRUDO_BPFFS_DIR "/bpf2_task_prctl_link"
#define SHIRUDO_BPRM_CHECK_LINK_PIN	SHIRUDO_BPFFS_DIR "/bpf2_bprm_check_security_link"
#define SHIRUDO_SEAL_FILE_OPEN_PIN	SHIRUDO_BPFFS_DIR "/seal_file_open_link"
#define SHIRUDO_SEAL_BPRM_CHECK_PIN	SHIRUDO_BPFFS_DIR "/seal_bprm_check_security_link"
#define SHIRUDO_SEAL_BPRM_COMMITTED_PIN SHIRUDO_BPFFS_DIR "/seal_bprm_committed_creds_link"
#define SHIRUDO_SEAL_TASK_ALLOC_PIN	SHIRUDO_BPFFS_DIR "/seal_task_alloc_link"
#define SHIRUDO_SEAL_PTRACE_PIN		SHIRUDO_BPFFS_DIR "/seal_ptrace_access_check_link"
#define SHIRUDO_SEAL_PERF_PIN		SHIRUDO_BPFFS_DIR "/seal_perf_event_alloc_link"
#define SHIRUDO_SEAL_UNLINK_PIN		SHIRUDO_BPFFS_DIR "/seal_inode_unlink_link"
#define SHIRUDO_SEAL_RENAME_PIN		SHIRUDO_BPFFS_DIR "/seal_inode_rename_link"
#define SHIRUDO_SEAL_SETATTR_PIN \
	SHIRUDO_BPFFS_DIR "/seal_inode_setattr_link"
#define SHIRUDO_SEAL_SETXATTR_PIN	SHIRUDO_BPFFS_DIR "/seal_inode_setxattr_link"
#define SHIRUDO_SEAL_RMXATTR_PIN	SHIRUDO_BPFFS_DIR "/seal_inode_removexattr_link"
#define SHIRUDO_SEAL_POST_SETXATTR_PIN	SHIRUDO_BPFFS_DIR "/seal_inode_post_setxattr_link"
#define SHIRUDO_SEAL_POST_RMXATTR_PIN	SHIRUDO_BPFFS_DIR "/seal_inode_post_removexattr_link"
#define SHIRUDO_SEAL_INIT_SECURITY_PIN	SHIRUDO_BPFFS_DIR "/seal_inode_init_security_link"
#define SHIRUDO_BPFFS_UPATCHES_DIR	SHIRUDO_BPFFS_DIR "/upatches"
#define SHIRUDO_IDENTITY_PIN		SHIRUDO_BPFFS_DIR "/identity"
#define SHIRUDO_TAMPER_PIN		SHIRUDO_BPFFS_DIR "/tamper"

#define SHIRUDO_RUNTIME_DIR		SHIRUDO_RUN_DIR "/runtime"
#define SHIRUDO_CONFIG_IMAGE_DIR		SHIRUDO_RUN_DIR "/config"
#define SHIRUDO_CONFIG_CANDIDATE_DIR	SHIRUDO_RUN_DIR "/config-candidate"
#define SHIRUDO_CONFIG_UPDATE_DIR	SHIRUDO_VAR_LIB "/config-update"
#define SHIRUDO_IMAGE_CACHE_DIR		SHIRUDO_VAR_LIB "/images"
#define SHIRUDO_RUNTIME_CONF_PATH \
	SHIRUDO_RUNTIME_DIR "/etc/shirudo/shirudo.conf"
#define SHIRUDO_RUNTIME_CERT_PATH	SHIRUDO_RUNTIME_DIR "/keys/cert.der"

/* Operator-side. */
#define SHIRUDO_SIGNING_KEY_FILE	"signing_key.pem"
#define SHIRUDO_SIGNING_KEY_PATH	SHIRUDO_KEYS_DIR "/" SHIRUDO_SIGNING_KEY_FILE

#define SHIRUDO_XATTR_NAME		"security.bpf.shirudo"

/*
 * Per-upatch payload_sha256 recorded on the pin directory in bpffs.
 * Written at load, read at unload for the payload_mismatch check; made
 * unforgeable by the bpf2 inode_setxattr guard.
 */
#define SHIRUDO_XATTR_PAYLOAD		"security.bpf.shirudo.payload"

/*
 * TPM2 NV index of the measurement register (owner-defined range).
 * Override at build time if it collides with site policy. An NV
 * extend index rather than a PCR, as systemd's NvPCRs: no free PCR
 * exists on a stock Linux + grub + IMA system and PCR 23 is
 * application-resettable; PCR 15 only anchors the index name.
 */
#ifndef SHIRUDO_NV_INDEX
#define SHIRUDO_NV_INDEX		0x01818E00u
#endif

/* Site config. */
#define SHIRUDO_CONF_PATH		"/etc/shirudo/shirudo.conf"

int shirudo_key_path(char *out, size_t out_sz,
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

bool path_exists(const char *path);

#endif /* SHIRUDO_PATHS_H */
