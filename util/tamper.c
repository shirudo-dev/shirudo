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
} tamper_points[TAMPER_MAX] = {
	[TAMPER_LOAD_NOT_LOADER] = { "LoadNotLoader",
		"program load that is not a signed loader" },
	[TAMPER_LOAD_UNSIGNED] = { "LoadUnsigned",
		"loader-type program load without a signature" },
	[TAMPER_LOAD_UNVERIFIED] = { "LoadUnverified",
		"program load whose signature the kernel did not verify" },
	[TAMPER_LOAD_KEYRING_KIND] = { "LoadKeyringKind",
		"program signed against a keyring of the wrong kind" },
	[TAMPER_LOAD_KEYRING] = { "LoadKeyring",
		"program signed against a keyring that is not the anchor" },
	[TAMPER_MAP_CREATE] = { "MapCreate",
		"map creation by another executable" },
	[TAMPER_MAP_WRITE] = { "MapWrite",
		"map update or freeze by another executable" },
	[TAMPER_MAP_FD] = { "MapFdWrite",
		"writable map descriptor for another executable" },
	[TAMPER_PROG_RUN] = { "ProgRun",
		"test run of a program by another executable" },
	[TAMPER_ATTACH] = { "ProgAttach",
		"link or raw tracepoint attach by another executable" },
	[TAMPER_OBJ_PIN] = { "ObjPin",
		"pin of a BPF object by another executable" },
	[TAMPER_BPF_CMD] = { "BpfCommand",
		"detach, update, delete or unclassified bpf() command" },
	[TAMPER_EXE_IDENTITY] = { "ExeIdentity",
		"executable change through PR_SET_MM" },
	[TAMPER_KEYRING] = { "KeyringWrite",
		"write, unlink, revoke or invalidate on the anchor keyring" },
	[TAMPER_PIN_UNLINK] = { "PinUnlink",
		"unlink of a pin in the private bpffs" },
	[TAMPER_PIN_RENAME] = { "PinRename",
		"rename of a pin in the private bpffs" },
	[TAMPER_PIN_XATTR] = { "PinXattr",
		"xattr change on a pin in the private bpffs" },
	[TAMPER_BPFFS_UMOUNT] = { "BpffsUmount",
		"unmount of the private bpffs" },
	[TAMPER_BPFFS_UMOUNT_ABOVE] = { "BpffsUmountAbove",
		"unmount of a mount above the private bpffs" },
	[TAMPER_BPFFS_MOUNT] = { "BpffsMount",
		"move, mount over or remount of the private bpffs" },
	[TAMPER_SEAL_WRITE] = { "SealWrite",
		"write open of a sealed file" },
	[TAMPER_SEAL_UNLINK] = { "SealUnlink",
		"unlink of a sealed file" },
	[TAMPER_SEAL_RENAME] = { "SealRename",
		"rename of or over a sealed file" },
	[TAMPER_SEAL_SETATTR] = { "SealSetattr",
		"truncate, chmod, chown or utimes of a sealed file" },
	[TAMPER_SEAL_XATTR] = { "SealXattr",
		"xattr change on a sealed file" },
	[TAMPER_SEAL_LABEL] = { "SealLabel",
		"seal or policy label changed by another executable" },
	[TAMPER_SEAL_PTRACE] = { "SealPtrace",
		"ptrace of a shirudo task" },
	[TAMPER_SEAL_PERF] = { "SealPerf",
		"perf event bound to a shirudo task" },
	[TAMPER_EXEC_TRACED] = { "ExecTraced",
		"exec of shirudo by a traced task" },
	[TAMPER_SEAL_ENTRY] = { "SealEntry",
		"entry created, linked or renamed into a sealed directory" },
	[TAMPER_PERF_ATTACH] = { "PerfAttach",
		"program attached to a perf event by another executable" },
	[TAMPER_PIN_ENTRY] = { "PinEntry",
		"directory or link made in the private bpffs by another executable" },
	[TAMPER_SEAL_COPY_UP] = { "SealCopyUp",
		"overlay copy-up of a sealed inode" },
	[TAMPER_KEXEC] = { "Kexec",
		"kexec image or initramfs load" },
	[TAMPER_TPM_EXTEND] = { "TpmExtend",
		"extension of shirudo's TPM NV index by another executable" },
	[TAMPER_OBJ_GET] = { "ObjGet",
		"pin, map or link opened by another executable" },
};

const char *tamper_name(enum tamper_point point)
{
	if (point >= TAMPER_MAX || !tamper_points[point].name)
		return "?";
	return tamper_points[point].name;
}

const char *tamper_meaning(enum tamper_point point)
{
	if (point >= TAMPER_MAX || !tamper_points[point].meaning)
		return "?";
	return tamper_points[point].meaning;
}

int tamper_read(struct tamper_counts *out)
{
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);
	int fd, ret;
	__u32 key;

	memset(out, 0, sizeof(*out));
	fd = bpf_obj_get(TAMPER_PIN);
	if (fd < 0)
		return -errno;
	ret = bpf_map_get_info_by_fd(fd, &info, &len);
	if (ret) {
		ret = -errno;
	} else if (info.max_entries != TAMPER_MAX ||
		   info.value_size != sizeof(out->count[0])) {
		ret = -EPROTO;
	} else {
		for (key = 0; key < TAMPER_MAX; key++) {
			ret = bpf_map_lookup_elem(fd, &key, &out->count[key]);
			if (ret) {
				ret = -errno;
				break;
			}
			out->total += out->count[key];
		}
	}
	close(fd);
	return ret;
}
