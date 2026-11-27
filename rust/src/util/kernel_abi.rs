// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The kernel ABI check. The signed loader
//! requires map hashing, exclusive-map binding and signed program
//! metadata. Stock kernels can expose BPF and the BPF LSM while still
//! lacking this contract, so those kernels are rejected before
//! BPF_PROG_LOAD.

use core::ffi::{CStr, c_int};

use crate::bpf::btf::{
    Btf, INT_SIGNED, KIND_ARRAY, KIND_CONST, KIND_FUNC, KIND_INT, KIND_PTR, KIND_RESTRICT,
    KIND_STRUCT, KIND_TYPE_TAG, KIND_TYPEDEF, KIND_VOLATILE, Member,
};
use crate::errno::text;
use crate::errno::{E2BIG, EINVAL, EOPNOTSUPP};
use crate::skel::EmbeddedBpf;
use crate::text::strscpy;
use crate::util::kernel_btf;

const MAP_SHA_SIZE: u32 = 32;
const BTF_MAX_UNWRAP: usize = 32;

/// The type `id` names past typedefs and modifiers, or none for one
/// that does not resolve within BTF_MAX_UNWRAP steps.
fn unwrap_type(btf: &Btf, mut id: u32) -> Option<u32> {
    for _ in 0..BTF_MAX_UNWRAP {
        if !btf.has(id) {
            return None;
        }
        if !matches!(
            btf.kind(id),
            KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG
        ) {
            return Some(id);
        }
        id = btf.size_or_type(id);
    }
    None
}

/// The member of the struct `t` named `name`.
fn find_member(btf: &Btf, t: u32, name: &[u8]) -> Option<Member> {
    btf.members(t)
        .find(|m| btf.str_at(m.name_off) == Some(name))
}

/// Whether `t` is an integer of `bytes` bytes, all bits its value, and
/// signed or not as `signed` says.
fn is_int(btf: &Btf, t: Option<u32>, bytes: u32, signed: bool) -> bool {
    t.is_some_and(|t| {
        btf.kind(t) == KIND_INT
            && btf.size_or_type(t) == bytes
            && btf.int_offset(t) == 0
            && u32::from(btf.int_bits(t)) == bytes * 8
            && (btf.int_encoding(t) & INT_SIGNED != 0) == signed
    })
}

/// is_byte_int(): an integer of a byte, signed or not.
fn is_byte_int(btf: &Btf, t: Option<u32>) -> bool {
    t.is_some_and(|t| {
        btf.kind(t) == KIND_INT
            && btf.size_or_type(t) == 1
            && btf.int_offset(t) == 0
            && btf.int_bits(t) == 8
    })
}

/// Whether `t` is a type, of `kind`.
fn is_kind(btf: &Btf, t: Option<u32>, kind: u32) -> bool {
    t.is_some_and(|t| btf.kind(t) == kind)
}

/// The type of the member `m`, past typedefs and modifiers.
fn member_type(btf: &Btf, m: Option<Member>) -> Option<u32> {
    unwrap_type(btf, m?.ty)
}

/// kernel_abi_validate_btf(): whether `btf` has the members the signed
/// loader needs, of the types it needs: 0, or -EOPNOTSUPP with what is
/// missing.
fn validate_btf(btf: Option<&Btf>) -> Result<(), &'static CStr> {
    let Some(btf) = btf else {
        return Err(c"kernel BTF is unavailable; boot a shirudo-patched kernel");
    };
    let Some(map) = btf.find_by_name_kind(b"bpf_map", KIND_STRUCT) else {
        return Err(c"kernel BTF has no struct bpf_map; boot a shirudo-patched kernel");
    };
    if !btf.has(map) {
        return Err(c"kernel BTF cannot resolve struct bpf_map");
    }

    let Some(sha) = find_member(btf, map, b"sha") else {
        return Err(c"struct bpf_map.sha is missing; boot a shirudo-patched kernel");
    };
    if sha.bitfield_size() != 0 {
        return Err(c"struct bpf_map.sha must be a non-bitfield");
    }
    let sha_type = unwrap_type(btf, sha.ty);
    if !is_kind(btf, sha_type, KIND_ARRAY) {
        return Err(c"struct bpf_map.sha must have type u8[32]");
    }
    let sha_array = btf.array(sha_type.unwrap_or(0));
    let elem_type = unwrap_type(btf, sha_array.ty);
    if sha_array.nelems != MAP_SHA_SIZE || !is_int(btf, elem_type, 1, false) {
        return Err(c"struct bpf_map.sha must have type u8[32]");
    }

    let Some(excl_prog_sha) = find_member(btf, map, b"excl_prog_sha") else {
        return Err(c"struct bpf_map.excl_prog_sha is missing; boot a shirudo-patched kernel");
    };
    if excl_prog_sha.bitfield_size() != 0 {
        return Err(c"struct bpf_map.excl_prog_sha must be a non-bitfield");
    }
    let excl_type = unwrap_type(btf, excl_prog_sha.ty);
    if !is_kind(btf, excl_type, KIND_PTR) {
        return Err(c"struct bpf_map.excl_prog_sha must have pointer type");
    }
    let elem_type = unwrap_type(btf, btf.size_or_type(excl_type.unwrap_or(0)));
    if !is_byte_int(btf, elem_type) {
        return Err(c"struct bpf_map.excl_prog_sha must point to a byte");
    }

    let Some(aux) = btf.find_by_name_kind(b"bpf_prog_aux", KIND_STRUCT) else {
        return Err(c"kernel BTF has no struct bpf_prog_aux; boot a shirudo-patched kernel");
    };
    if !btf.has(aux) {
        return Err(c"kernel BTF cannot resolve struct bpf_prog_aux");
    }

    let Some(sig) = find_member(btf, aux, b"sig") else {
        return Err(c"struct bpf_prog_aux.sig is missing; boot a shirudo-patched kernel");
    };
    let sig_type = unwrap_type(btf, sig.ty);
    if !is_kind(btf, sig_type, KIND_STRUCT) {
        return Err(c"struct bpf_prog_aux.sig must have struct type");
    }

    let sig_type = sig_type.unwrap_or(0);
    let keyring_serial = find_member(btf, sig_type, b"keyring_serial");
    if !is_int(btf, member_type(btf, keyring_serial), 4, true) {
        return Err(c"struct bpf_prog_aux.sig.keyring_serial must have type s32");
    }
    let keyring_type = find_member(btf, sig_type, b"keyring_type");
    if !is_int(btf, member_type(btf, keyring_type), 1, false) {
        return Err(c"struct bpf_prog_aux.sig.keyring_type must have type u8");
    }
    let verdict = find_member(btf, sig_type, b"verdict");
    if !is_int(btf, member_type(btf, verdict), 1, false) {
        return Err(c"struct bpf_prog_aux.sig.verdict must have type u8");
    }
    if btf
        .find_by_name_kind(b"bpf_lsm_tpm_command", KIND_FUNC)
        .is_none()
    {
        return Err(c"tpm_command LSM hook is missing; boot a Shirudo-patched kernel");
    }
    Ok(())
}

/// validate_btf() of the running kernel's BTF: Ok, or why the signed
/// loader cannot run on it.
pub(crate) fn check() -> Result<(), Vec<u8>> {
    match kernel_btf::load_vmlinux() {
        Ok(btf) => validate_btf(Some(&btf)).map_err(|why| why.to_bytes().to_vec()),
        Err(err) => Err(format!(
            "cannot read target kernel BTF: {}; boot a shirudo-patched kernel",
            text(err)
        )
        .into_bytes()),
    }
}

/// check(), its refusal into `detail` as a C string, or "?" where it
/// does not fit, and empty when it passes: 0 or -EOPNOTSUPP.
pub(crate) fn check_into(detail: &mut [u8]) -> c_int {
    if let Some(first) = detail.first_mut() {
        *first = 0;
    }
    let Err(why) = check() else {
        return 0;
    };
    if strscpy(detail, &why).is_err() {
        let _ = strscpy(detail, b"?");
    }
    -EOPNOTSUPP
}

/// `LSM_HOOKS_MAX` and `LSM_HOOK_NAME_MAX`.
const LSM_HOOKS_MAX: usize = 128;
const LSM_HOOK_NAME_MAX: usize = 64;
/// `KERNEL_ABI_DETAIL_MAX`.
const DETAIL_MAX: usize = 256;

/// `struct lsm_hooks`: the hooks programs attach to, each once.
pub struct LsmHooks {
    name: [[u8; LSM_HOOK_NAME_MAX]; LSM_HOOKS_MAX],
    n: usize,
}

impl LsmHooks {
    pub(crate) fn new() -> Box<Self> {
        Box::new(LsmHooks {
            name: [[0; LSM_HOOK_NAME_MAX]; LSM_HOOKS_MAX],
            n: 0,
        })
    }

    fn names(&self) -> impl Iterator<Item = &[u8]> {
        self.name[..self.n.min(LSM_HOOKS_MAX)]
            .iter()
            .map(|n| crate::text::cstr(n))
    }

    /// Adds `hook` unless it is there: -E2BIG when it does not fit.
    fn add(&mut self, hook: &[u8]) -> Result<(), c_int> {
        if self.names().any(|h| h == hook) {
            return Ok(());
        }
        if self.n >= LSM_HOOKS_MAX || hook.len() >= LSM_HOOK_NAME_MAX {
            return Err(-E2BIG);
        }
        let slot = &mut self.name[self.n];
        slot[..hook.len()].copy_from_slice(hook);
        slot[hook.len()] = 0;
        self.n += 1;
        Ok(())
    }
}

/// Adds the hooks the lsm and lsm.s programs of `obj` attach to, which
/// the skeleton generator read from the object: -EINVAL for an object
/// this build does not embed, -E2BIG when they do not fit.
pub(crate) fn lsm_hooks(obj: &EmbeddedBpf, hooks: &mut LsmHooks) -> Result<(), c_int> {
    obj.lsm_hooks()
        .ok_or(-EINVAL)?
        .iter()
        .try_for_each(|h| hooks.add(h.as_bytes()))
}

/// Whether `btf` has a bpf_lsm_<hook> function for every hook, or why
/// not, naming the hooks it lacks as far as the detail holds them.
pub(crate) fn validate_lsm_hooks(btf: Option<&Btf>, hooks: &LsmHooks) -> Result<(), Vec<u8>> {
    let Some(btf) = btf else {
        return Err(b"kernel BTF is unavailable; boot a shirudo-patched kernel".to_vec());
    };
    let mut missing: Vec<u8> = Vec::new();
    let mut n_missing = 0;
    for hook in hooks.names() {
        if btf
            .find_by_name_kind(&[b"bpf_lsm_", hook].concat(), KIND_FUNC)
            .is_some()
        {
            continue;
        }
        let sep: &[u8] = if n_missing > 0 { b", " } else { b"" };
        if missing.len() + sep.len() + hook.len() < DETAIL_MAX {
            missing.extend_from_slice(sep);
            missing.extend_from_slice(hook);
        }
        n_missing += 1;
    }
    if n_missing == 0 {
        return Ok(());
    }
    let plural: &[u8] = if n_missing > 1 { b"s" } else { b"" };
    Err([
        &b"kernel has no LSM hook"[..],
        plural,
        b" ",
        &missing,
        b"; boot a shirudo-patched kernel",
    ]
    .concat())
}

/// validate_lsm_hooks() on the running kernel's BTF.
pub(crate) fn check_lsm_hooks(hooks: &LsmHooks) -> Result<(), Vec<u8>> {
    match kernel_btf::load_vmlinux() {
        Ok(btf) => validate_lsm_hooks(Some(&btf), hooks),
        Err(err) => Err([
            &b"cannot read target kernel BTF: "[..],
            text(err).as_bytes(),
            b"; boot a shirudo-patched kernel",
        ]
        .concat()),
    }
}

#[cfg(test)]
mod tests;
