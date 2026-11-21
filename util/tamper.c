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

#include "identity.h"
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
		"unlink of a sealed file or removal of a sealed directory" },
	[TAMPER_SEAL_RENAME] = { "SealRename",
		"rename of or over a sealed file or a directory above the state root" },
	[TAMPER_SEAL_SETATTR] = { "SealSetattr",
		"truncate, chmod, chown, utimes or chattr of a sealed file" },
	[TAMPER_SEAL_XATTR] = { "SealXattr",
		"xattr or ACL change on a sealed file" },
	[TAMPER_SEAL_LABEL] = { "SealLabel",
		"seal or policy label changed by another executable" },
	[TAMPER_SEAL_PTRACE] = { "SealPtrace",
		"ptrace of a shirudo task" },
	[TAMPER_SEAL_PERF] = { "SealPerf",
		"perf event bound to a shirudo task" },
	[TAMPER_EXEC_TRACED] = { "ExecTraced",
		"exec of shirudo by a traced task" },
	[TAMPER_SEAL_ENTRY] = { "SealEntry",
		"entry into a sealed directory, or a sealed inode linked" },
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
	[TAMPER_SEAL_SIGNAL] = { "SealSignal",
		"signal to a shirudo task (let through)" },
	[TAMPER_SEAL_CORE_DUMP] = { "SealCoreDump",
		"core dump of a shirudo task, which acts without authority" },
	[TAMPER_SEAL_UPROBE] = { "SealUprobe",
		"uprobe in a shirudo task, which acts without authority" },
	[TAMPER_EXEC_SHARED] = { "ExecShared",
		"exec of the runtime binary by a task that shares its file system context" },
	[TAMPER_XATTR_HANDLE] = { "XattrHandle",
		"XFS attribute change by file handle, which passes no xattr hook" },
	[TAMPER_SEAL_RLIMIT] = { "SealRlimit",
		"resource limit of a shirudo task changed by another task" },
	[SHIRUDO_TAMPER_TPM_WRITE] = { "TpmWrite",
		"protected TPM mutation by an unauthorized task" },
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

int counters_read(const struct guard_map *map, __u32 n, __u64 *count,
		  __u64 *total)
{
	int fd, ret;
	__u32 key;

	memset(count, 0, n * sizeof(*count));
	*total = 0;
	fd = bpf_obj_get(map->pin);
	if (fd < 0)
		return -errno;
	ret = guard_map_check(fd, map, NULL);
	if (!ret && (map->max_entries != n ||
		     map->value_size != sizeof(*count)))
		ret = -EPROTO;
	for (key = 0; !ret && key < n; key++) {
		if (bpf_map_lookup_elem(fd, &key, &count[key]))
			ret = -errno;
		else
			*total += count[key];
	}
	close(fd);
	return ret;
}

int tamper_read(struct tamper_counts *out)
{
	return counters_read(&shirudo_guard_maps[GUARD_TAMPER], TAMPER_MAX,
			     out->count, &out->total);
}
