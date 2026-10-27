/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The tamper counters: one per point at which a guard refuses a caller,
 * counted where the refusal happens and read back by `shirudo status`.
 * On the BPF side, include after vmlinux.h and the libbpf headers.
 */

#ifndef SHIRUDO_TAMPER_H
#define SHIRUDO_TAMPER_H

enum shirudo_tamper_point {
	SHIRUDO_TAMPER_LOAD_NOT_LOADER,
	SHIRUDO_TAMPER_LOAD_UNSIGNED,
	SHIRUDO_TAMPER_LOAD_UNVERIFIED,
	SHIRUDO_TAMPER_LOAD_KEYRING_KIND,
	SHIRUDO_TAMPER_LOAD_KEYRING,
	SHIRUDO_TAMPER_MAP_CREATE,
	SHIRUDO_TAMPER_MAP_WRITE,
	SHIRUDO_TAMPER_MAP_FD,
	SHIRUDO_TAMPER_PROG_RUN,
	SHIRUDO_TAMPER_ATTACH,
	SHIRUDO_TAMPER_OBJ_PIN,
	SHIRUDO_TAMPER_BPF_CMD,
	SHIRUDO_TAMPER_EXE_IDENTITY,
	SHIRUDO_TAMPER_KEYRING,
	SHIRUDO_TAMPER_PIN_UNLINK,
	SHIRUDO_TAMPER_PIN_RENAME,
	SHIRUDO_TAMPER_PIN_XATTR,
	SHIRUDO_TAMPER_BPFFS_UMOUNT,
	SHIRUDO_TAMPER_BPFFS_UMOUNT_ABOVE,
	SHIRUDO_TAMPER_BPFFS_MOUNT,
	SHIRUDO_TAMPER_SEAL_WRITE,
	SHIRUDO_TAMPER_SEAL_UNLINK,
	SHIRUDO_TAMPER_SEAL_RENAME,
	SHIRUDO_TAMPER_SEAL_SETATTR,
	SHIRUDO_TAMPER_SEAL_XATTR,
	SHIRUDO_TAMPER_SEAL_LABEL,
	SHIRUDO_TAMPER_SEAL_PTRACE,
	SHIRUDO_TAMPER_SEAL_PERF,
	SHIRUDO_TAMPER_EXEC_TRACED,
	SHIRUDO_TAMPER_SEAL_ENTRY,
	SHIRUDO_TAMPER_PERF_ATTACH,
	SHIRUDO_TAMPER_PIN_ENTRY,
	SHIRUDO_TAMPER_SEAL_COPY_UP,
	SHIRUDO_TAMPER_KEXEC,
	SHIRUDO_TAMPER_TPM_EXTEND,
	SHIRUDO_TAMPER_MAX
};

#ifdef __BPF__
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SHIRUDO_TAMPER_MAX);
	__type(key, __u32);
	__type(value, __u64);
} shirudo_tamper SEC(".maps");

static __always_inline int shirudo_tamper_deny(enum shirudo_tamper_point point,
					       int err)
{
	__u32 key = point;
	__u64 *count;

	count = bpf_map_lookup_elem(&shirudo_tamper, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
	return err;
}
#endif /* __BPF__ */
#endif /* SHIRUDO_TAMPER_H */
