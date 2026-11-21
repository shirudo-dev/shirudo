// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The signed loader requires map hashing, exclusive-map binding, and signed
 * program metadata, and the embedded programs attach to LSM hooks that only
 * the carried kernel patches add. Stock kernels can expose BPF and the BPF
 * LSM while lacking either, so reject those kernels before BPF_PROG_LOAD.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <linux/bpf.h>
#include <linux/btf.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "kernel_abi.h"
#include "loader.h"

#define MAP_SHA_SIZE	32U
#define BTF_MAX_UNWRAP	32

static __printf(3, 4) int abi_fail(char *detail, size_t detail_sz,
				    const char *fmt, ...)
{
	va_list ap;

	if (detail && detail_sz) {
		va_start(ap, fmt);
		if (vstrsprintf(detail, detail_sz, fmt, ap) < 0)
			strscpy(detail, "?", detail_sz);
		va_end(ap);
	}
	return -EOPNOTSUPP;
}

static const struct btf_type *unwrap_type(const struct btf *btf, __u32 id)
{
	const struct btf_type *t;
	int i;

	for (i = 0; i < BTF_MAX_UNWRAP; i++) {
		t = btf__type_by_id(btf, id);
		if (!t)
			return NULL;
		if (!btf_is_typedef(t) && !btf_is_mod(t))
			return t;
		id = t->type;
	}
	return NULL;
}

static const struct btf_member *find_member(const struct btf *btf,
					    const struct btf_type *t,
					    const char *name,
					    __u32 *index)
{
	const struct btf_member *members = btf_members(t);
	__u32 i;

	for (i = 0; i < btf_vlen(t); i++) {
		const char *member_name =
			btf__name_by_offset(btf, members[i].name_off);

		if (member_name && strcmp(member_name, name) == 0) {
			*index = i;
			return &members[i];
		}
	}
	return NULL;
}

static bool is_unsigned_int(const struct btf_type *t, __u32 bytes)
{
	return t && btf_is_int(t) && t->size == bytes &&
	       btf_int_offset(t) == 0 && btf_int_bits(t) == bytes * 8 &&
	       !(btf_int_encoding(t) & BTF_INT_SIGNED);
}

static bool is_signed_int(const struct btf_type *t, __u32 bytes)
{
	return t && btf_is_int(t) && t->size == bytes &&
	       btf_int_offset(t) == 0 && btf_int_bits(t) == bytes * 8 &&
	       (btf_int_encoding(t) & BTF_INT_SIGNED);
}

static bool is_byte_int(const struct btf_type *t)
{
	return t && btf_is_int(t) && t->size == 1 &&
	       btf_int_offset(t) == 0 && btf_int_bits(t) == 8;
}

int kernel_abi_validate_btf(const struct btf *btf,
			    char *detail, size_t detail_sz)
{
	const struct btf_member *sha, *excl_prog_sha, *sig;
	const struct btf_member *keyring_serial, *keyring_type, *verdict;
	const struct btf_type *map, *aux, *sha_type, *elem_type;
	const struct btf_type *excl_type, *sig_type, *member_type;
	const struct btf_array *array;
	__u32 member_idx;
	int map_id, aux_id;

	if (detail && detail_sz)
		detail[0] = '\0';
	if (!btf)
		return abi_fail(detail, detail_sz,
				"kernel BTF is unavailable; boot a shirudo-patched kernel");

	map_id = btf__find_by_name_kind(btf, "bpf_map", BTF_KIND_STRUCT);
	if (map_id < 0)
		return abi_fail(detail, detail_sz,
				"kernel BTF has no struct bpf_map; boot a shirudo-patched kernel");
	map = btf__type_by_id(btf, (__u32)map_id);
	if (!map)
		return abi_fail(detail, detail_sz,
				"kernel BTF cannot resolve struct bpf_map");

	sha = find_member(btf, map, "sha", &member_idx);
	if (!sha)
		return abi_fail(detail, detail_sz,
				"struct bpf_map.sha is missing; boot a shirudo-patched kernel");
	if (btf_member_bitfield_size(map, member_idx) != 0)
		return abi_fail(detail, detail_sz,
				"struct bpf_map.sha must be a non-bitfield");
	sha_type = unwrap_type(btf, sha->type);
	if (!sha_type || !btf_is_array(sha_type))
		return abi_fail(detail, detail_sz,
				"struct bpf_map.sha must have type u8[32]");
	array = btf_array(sha_type);
	elem_type = unwrap_type(btf, array->type);
	if (array->nelems != MAP_SHA_SIZE ||
	    !is_unsigned_int(elem_type, 1))
		return abi_fail(detail, detail_sz,
				"struct bpf_map.sha must have type u8[32]");

	excl_prog_sha = find_member(btf, map, "excl_prog_sha", &member_idx);
	if (!excl_prog_sha)
		return abi_fail(detail, detail_sz,
				"struct bpf_map.excl_prog_sha is missing; boot a shirudo-patched kernel");
	if (btf_member_bitfield_size(map, member_idx) != 0)
		return abi_fail(detail, detail_sz,
				"struct bpf_map.excl_prog_sha must be a non-bitfield");
	excl_type = unwrap_type(btf, excl_prog_sha->type);
	if (!excl_type || !btf_is_ptr(excl_type))
		return abi_fail(detail, detail_sz,
				"struct bpf_map.excl_prog_sha must have pointer type");
	elem_type = unwrap_type(btf, excl_type->type);
	if (!is_byte_int(elem_type))
		return abi_fail(detail, detail_sz,
				"struct bpf_map.excl_prog_sha must point to a byte");

	aux_id = btf__find_by_name_kind(btf, "bpf_prog_aux", BTF_KIND_STRUCT);
	if (aux_id < 0)
		return abi_fail(detail, detail_sz,
				"kernel BTF has no struct bpf_prog_aux; boot a shirudo-patched kernel");
	aux = btf__type_by_id(btf, (__u32)aux_id);
	if (!aux)
		return abi_fail(detail, detail_sz,
				"kernel BTF cannot resolve struct bpf_prog_aux");

	sig = find_member(btf, aux, "sig", &member_idx);
	if (!sig)
		return abi_fail(detail, detail_sz,
				"struct bpf_prog_aux.sig is missing; boot a shirudo-patched kernel");
	sig_type = unwrap_type(btf, sig->type);
	if (!sig_type || !btf_is_struct(sig_type))
		return abi_fail(detail, detail_sz,
				"struct bpf_prog_aux.sig must have struct type");

	keyring_serial = find_member(btf, sig_type, "keyring_serial", &member_idx);
	member_type = keyring_serial ? unwrap_type(btf, keyring_serial->type) : NULL;
	if (!keyring_serial || !is_signed_int(member_type, 4))
		return abi_fail(detail, detail_sz,
				"struct bpf_prog_aux.sig.keyring_serial must have type s32");
	keyring_type = find_member(btf, sig_type, "keyring_type", &member_idx);
	member_type = keyring_type ? unwrap_type(btf, keyring_type->type) : NULL;
	if (!keyring_type || !is_unsigned_int(member_type, 1))
		return abi_fail(detail, detail_sz,
				"struct bpf_prog_aux.sig.keyring_type must have type u8");
	verdict = find_member(btf, sig_type, "verdict", &member_idx);
	member_type = verdict ? unwrap_type(btf, verdict->type) : NULL;
	if (!verdict || !is_unsigned_int(member_type, 1))
		return abi_fail(detail, detail_sz,
				"struct bpf_prog_aux.sig.verdict must have type u8");
	if (btf__find_by_name_kind(btf, "bpf_lsm_tpm_command", BTF_KIND_FUNC) < 0)
		return abi_fail(detail, detail_sz,
				"tpm_command LSM hook is missing; boot a Shirudo-patched kernel");

	return 0;
}

int kernel_abi_check(char *detail, size_t detail_sz)
{
	struct btf *btf;
	long err;
	int ret;

	if (detail && detail_sz)
		detail[0] = '\0';
	btf = btf__load_vmlinux_btf();
	err = libbpf_get_error(btf);
	if (err)
		return abi_fail(detail, detail_sz,
				"cannot read target kernel BTF: %s; boot a shirudo-patched kernel",
				strerror((int)-err));

	ret = kernel_abi_validate_btf(btf, detail, detail_sz);
	btf__free(btf);
	return ret;
}

/* The hook an lsm or lsm.s program attaches to, NULL for another kind. */
static const char *lsm_hook(const struct bpf_program *prog)
{
	const char *sec = bpf_program__section_name(prog);

	if (sec && (str_skip_prefix(&sec, "lsm/") ||
		    str_skip_prefix(&sec, "lsm.s/")))
		return sec;
	return NULL;
}

static int lsm_hooks_add(struct lsm_hooks *hooks, const char *hook)
{
	size_t i;

	for (i = 0; i < hooks->n; i++)
		if (!strcmp(hooks->name[i], hook))
			return 0;
	if (hooks->n == ARRAY_SIZE(hooks->name) ||
	    strscpy(hooks->name[hooks->n], hook, sizeof(hooks->name[0])) < 0)
		return -E2BIG;
	hooks->n++;
	return 0;
}

int kernel_abi_lsm_hooks(const struct embedded_bpf *obj,
			 struct lsm_hooks *hooks)
{
	struct bpf_program *prog;
	struct bpf_object *bo;
	const char *hook;
	int ret = 0;
	long err;

	bo = bpf_object__open_mem(obj->data, obj->size, NULL);
	err = libbpf_get_error(bo);
	if (err)
		return (int)err;
	bpf_object__for_each_program(prog, bo) {
		hook = lsm_hook(prog);
		if (hook) {
			ret = lsm_hooks_add(hooks, hook);
			if (ret)
				break;
		}
	}
	bpf_object__close(bo);
	return ret;
}

int kernel_abi_validate_lsm_hooks(const struct btf *btf,
				  const struct lsm_hooks *hooks,
				  char *detail, size_t detail_sz)
{
	char missing[KERNEL_ABI_DETAIL_MAX] = "";
	char function[LSM_HOOK_NAME_MAX + 8];
	size_t i, n_missing = 0, len = 0;
	int ret;

	if (detail && detail_sz)
		detail[0] = '\0';
	if (!btf)
		return abi_fail(detail, detail_sz,
				"kernel BTF is unavailable; boot a shirudo-patched kernel");
	for (i = 0; i < hooks->n; i++) {
		if (strsprintf(function, sizeof(function), "bpf_lsm_%s",
			       hooks->name[i]) >= 0 &&
		    btf__find_by_name_kind(btf, function, BTF_KIND_FUNC) > 0)
			continue;
		ret = strsprintf(missing + len, sizeof(missing) - len, "%s%s",
				 n_missing ? ", " : "", hooks->name[i]);
		if (ret > 0)
			len += (size_t)ret;
		n_missing++;
	}
	if (!n_missing)
		return 0;
	return abi_fail(detail, detail_sz,
			"kernel has no LSM hook%s %s; boot a shirudo-patched kernel",
			n_missing > 1 ? "s" : "", missing);
}

int kernel_abi_check_lsm_hooks(const struct lsm_hooks *hooks,
			       char *detail, size_t detail_sz)
{
	struct btf *btf;
	long err;
	int ret;

	if (detail && detail_sz)
		detail[0] = '\0';
	btf = btf__load_vmlinux_btf();
	err = libbpf_get_error(btf);
	if (err)
		return abi_fail(detail, detail_sz,
				"cannot read target kernel BTF: %s; boot a shirudo-patched kernel",
				strerror((int)-err));
	ret = kernel_abi_validate_lsm_hooks(btf, hooks, detail, detail_sz);
	btf__free(btf);
	return ret;
}
