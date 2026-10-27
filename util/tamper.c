// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Read back the tamper counters init pinned in the private bpffs.
 */
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>

#include <shirudo/misc.h>

#include "paths.h"
#include "tamper.h"

static const struct {
	const char	*name;
	const char	*meaning;
} tamper_points[SHIRUDO_TAMPER_MAX] = {
	[SHIRUDO_TAMPER_LOAD_NOT_LOADER] = { "LoadNotLoader",
		"program load that is not a signed loader" },
	[SHIRUDO_TAMPER_LOAD_UNSIGNED] = { "LoadUnsigned",
		"loader-type program load without a signature" },
	[SHIRUDO_TAMPER_LOAD_UNVERIFIED] = { "LoadUnverified",
		"program load whose signature the kernel did not verify" },
	[SHIRUDO_TAMPER_LOAD_KEYRING_KIND] = { "LoadKeyringKind",
		"program signed against a keyring of the wrong kind" },
	[SHIRUDO_TAMPER_LOAD_KEYRING] = { "LoadKeyring",
		"program signed against a keyring that is not the anchor" },
	[SHIRUDO_TAMPER_MAP_CREATE] = { "MapCreate",
		"map creation by another executable" },
	[SHIRUDO_TAMPER_MAP_WRITE] = { "MapWrite",
		"map update or freeze by another executable" },
	[SHIRUDO_TAMPER_MAP_FD] = { "MapFdWrite",
		"writable map descriptor for another executable" },
	[SHIRUDO_TAMPER_PROG_RUN] = { "ProgRun",
		"test run of a program by another executable" },
	[SHIRUDO_TAMPER_ATTACH] = { "ProgAttach",
		"link or raw tracepoint attach by another executable" },
	[SHIRUDO_TAMPER_OBJ_PIN] = { "ObjPin",
		"pin of a BPF object by another executable" },
	[SHIRUDO_TAMPER_BPF_CMD] = { "BpfCommand",
		"detach, update, delete or unclassified bpf() command" },
	[SHIRUDO_TAMPER_EXE_IDENTITY] = { "ExeIdentity",
		"executable change through PR_SET_MM" },
	[SHIRUDO_TAMPER_KEYRING] = { "KeyringWrite",
		"write, unlink, revoke or invalidate on the anchor keyring" },
	[SHIRUDO_TAMPER_PIN_UNLINK] = { "PinUnlink",
		"unlink of a pin in the private bpffs" },
	[SHIRUDO_TAMPER_PIN_RENAME] = { "PinRename",
		"rename of a pin in the private bpffs" },
	[SHIRUDO_TAMPER_PIN_XATTR] = { "PinXattr",
		"xattr change on a pin in the private bpffs" },
	[SHIRUDO_TAMPER_BPFFS_UMOUNT] = { "BpffsUmount",
		"unmount of the private bpffs" },
	[SHIRUDO_TAMPER_BPFFS_UMOUNT_ABOVE] = { "BpffsUmountAbove",
		"unmount of a mount above the private bpffs" },
	[SHIRUDO_TAMPER_BPFFS_MOUNT] = { "BpffsMount",
		"move, mount over or remount of the private bpffs" },
	[SHIRUDO_TAMPER_SEAL_WRITE] = { "SealWrite",
		"write open of a sealed file" },
	[SHIRUDO_TAMPER_SEAL_UNLINK] = { "SealUnlink",
		"unlink of a sealed file" },
	[SHIRUDO_TAMPER_SEAL_RENAME] = { "SealRename",
		"rename of or over a sealed file" },
	[SHIRUDO_TAMPER_SEAL_SETATTR] = { "SealSetattr",
		"truncate, chmod, chown or utimes of a sealed file" },
	[SHIRUDO_TAMPER_SEAL_XATTR] = { "SealXattr",
		"xattr change on a sealed file" },
	[SHIRUDO_TAMPER_SEAL_LABEL] = { "SealLabel",
		"seal label set by another executable" },
	[SHIRUDO_TAMPER_SEAL_PTRACE] = { "SealPtrace",
		"ptrace of a shirudo task" },
	[SHIRUDO_TAMPER_SEAL_PERF] = { "SealPerf",
		"perf event bound to a shirudo task" },
	[SHIRUDO_TAMPER_EXEC_TRACED] = { "ExecTraced",
		"exec of shirudo by a traced task" },
	[SHIRUDO_TAMPER_SEAL_ENTRY] = { "SealEntry",
		"entry created, linked or renamed into a sealed directory" },
};

const char *tamper_name(enum shirudo_tamper_point point)
{
	if (point >= SHIRUDO_TAMPER_MAX || !tamper_points[point].name)
		return "?";
	return tamper_points[point].name;
}

const char *tamper_meaning(enum shirudo_tamper_point point)
{
	if (point >= SHIRUDO_TAMPER_MAX || !tamper_points[point].meaning)
		return "?";
	return tamper_points[point].meaning;
}

int tamper_read(struct shirudo_tamper_counts *out)
{
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);
	int fd, rc;
	__u32 key;

	memset(out, 0, sizeof(*out));
	fd = bpf_obj_get(SHIRUDO_TAMPER_PIN);
	if (fd < 0)
		return -errno;
	rc = bpf_map_get_info_by_fd(fd, &info, &len);
	if (rc) {
		rc = -errno;
	} else if (info.max_entries != SHIRUDO_TAMPER_MAX ||
		   info.value_size != sizeof(out->count[0])) {
		rc = -EPROTO;
	} else {
		for (key = 0; key < SHIRUDO_TAMPER_MAX; key++) {
			rc = bpf_map_lookup_elem(fd, &key, &out->count[key]);
			if (rc) {
				rc = -errno;
				break;
			}
			out->total += out->count[key];
		}
	}
	close(fd);
	return rc;
}
