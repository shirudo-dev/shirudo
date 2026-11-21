/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The tamper counters: one per point at which a guard refuses a caller,
 * counted where the refusal happens, and one, SealSignal, at which the
 * seal counts what it lets through; read back by `shirudo status`.
 * On the BPF side, include after vmlinux.h and the libbpf headers.
 */

#ifndef SHIRUDO_TAMPER_H
#define SHIRUDO_TAMPER_H

enum tamper_point {
	TAMPER_LOAD_NOT_LOADER,
	TAMPER_LOAD_UNSIGNED,
	TAMPER_LOAD_UNVERIFIED,
	TAMPER_LOAD_KEYRING_KIND,
	TAMPER_LOAD_KEYRING,
	TAMPER_MAP_CREATE,
	TAMPER_MAP_WRITE,
	TAMPER_MAP_FD,
	TAMPER_PROG_RUN,
	TAMPER_ATTACH,
	TAMPER_OBJ_PIN,
	TAMPER_BPF_CMD,
	TAMPER_EXE_IDENTITY,
	TAMPER_KEYRING,
	TAMPER_PIN_UNLINK,
	TAMPER_PIN_RENAME,
	TAMPER_PIN_XATTR,
	TAMPER_BPFFS_UMOUNT,
	TAMPER_BPFFS_UMOUNT_ABOVE,
	TAMPER_BPFFS_MOUNT,
	TAMPER_SEAL_WRITE,
	TAMPER_SEAL_UNLINK,
	TAMPER_SEAL_RENAME,
	TAMPER_SEAL_SETATTR,
	TAMPER_SEAL_XATTR,
	TAMPER_SEAL_LABEL,
	TAMPER_SEAL_PTRACE,
	TAMPER_SEAL_PERF,
	TAMPER_EXEC_TRACED,
	TAMPER_SEAL_ENTRY,
	TAMPER_PERF_ATTACH,
	TAMPER_PIN_ENTRY,
	TAMPER_SEAL_COPY_UP,
	TAMPER_KEXEC,
	TAMPER_TPM_EXTEND,
	TAMPER_OBJ_GET,
	TAMPER_SEAL_SIGNAL,
	TAMPER_SEAL_CORE_DUMP,
	TAMPER_SEAL_UPROBE,
	TAMPER_EXEC_SHARED,
	TAMPER_XATTR_HANDLE,
	TAMPER_SEAL_RLIMIT,
	SHIRUDO_TAMPER_TPM_WRITE,
	TAMPER_MAX
};

#ifdef __BPF__
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, TAMPER_MAX);
	__type(key, __u32);
	__type(value, __u64);
} shirudo_tamper SEC(".maps");

static __always_inline void shirudo_tamper_count(enum tamper_point point)
{
	__u32 key = point;
	__u64 *count;

	count = bpf_map_lookup_elem(&shirudo_tamper, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
}

static __always_inline int shirudo_tamper_deny(enum tamper_point point,
					       int err)
{
	shirudo_tamper_count(point);
	return err;
}
#endif /* __BPF__ */
#endif /* SHIRUDO_TAMPER_H */
