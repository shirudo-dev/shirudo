// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The `.rodata` of a upatch: found through
//! the loader's own sys_bpf() calls, the BTF it loads and the map update
//! that fills the section, then printed as text as libbpf's dumper
//! prints it, or as JSON from the BTF.

use core::ffi::{CStr, c_int};
use core::ptr;
use std::os::fd::AsFd;

use crate::bpf::btf::{
    Btf, INT_BOOL, INT_SIGNED, KIND_ARRAY, KIND_CONST, KIND_DATASEC, KIND_ENUM, KIND_ENUM64,
    KIND_FLOAT, KIND_FWD, KIND_INT, KIND_PTR, KIND_RESTRICT, KIND_STRUCT, KIND_TYPE_TAG,
    KIND_TYPEDEF, KIND_UNION, KIND_VAR, KIND_VOLATILE,
};
use crate::bpf::btf_dump::Dump;
use crate::errno::{E2BIG, EEXIST, EINVAL, ENODATA, ENOENT, ENOMEM, ENOSPC, EOPNOTSUPP};
use crate::ffi;
use crate::sys::libc::{fwrite, printf, putchar, stdout};
use crate::text::strsprintf;
use crate::util::format::fputs_sanitized;
use crate::util::io::write_complete;
use crate::util::json::{JsonEmit, MAX_BYTES};
use crate::util::upatch::{NAME_MAX, Upatch};

const MAPS_MAX: usize = 64;
const JSON_MAX_DEPTH: u32 = 8;
const TEXT_MAX_VALUES: u32 = 1 << 20;
const DECL_MAX: u32 = 32;

/// The instructions and calls of a loader libbpf's gen_loader wrote.
const INSN: usize = 8;
const LD_DW_IMM: u8 = 0x18;
const JMP_CALL: u8 = 0x85;
const ALU64_MOV_K: u8 = 0xb7;
const STX_W_MEM: u8 = 0x63;
const LDX_W_MEM: u8 = 0x61;
const STX_DW_MEM: u8 = 0x7b;
const PSEUDO_MAP_IDX_VALUE: u8 = 6;
const FUNC_SYS_BPF: i32 = 166;
const REG_0: u8 = 0;
const REG_1: u8 = 1;
const REG_2: u8 = 2;
const REG_3: u8 = 3;
const REG_7: u8 = 7;
const MAP_CREATE: u32 = 0;
const MAP_UPDATE_ELEM: u32 = 2;
const BTF_LOAD: u32 = 18;
const OBJ_NAME_LEN: usize = 16;

/// `union bpf_attr` of the vendored UAPI: its size, and the fields the
/// loader's calls set, as offsets.
const ATTR_SIZE: u32 = 168;
const ATTR_MAP_NAME: usize = 28;
const ATTR_MAP_NAME_END: u32 = 44;
const ATTR_VALUE_SIZE: usize = 8;
const ATTR_MAP_FD: u32 = 0;
const ATTR_VALUE: u32 = 16;
const ATTR_BTF: u32 = 0;
const ATTR_BTF_SIZE: usize = 16;
const ATTR_BTF_SIZE_END: u32 = 20;

/// Where a variable of a upatch's .rodata lies.
pub struct RodataRange {
    pub(crate) offset: u32,
    pub(crate) size: u32,
}

/// The `.rodata` the loader fills: its BTF, its bytes in the loader
/// data, and its DATASEC.
struct View {
    btf: Option<Btf>,
    bytes: *const u8,
    data_offset: u32,
    size: u32,
    type_id: u32,
}

impl View {
    const fn new() -> Self {
        View {
            btf: None,
            bytes: ptr::null(),
            data_offset: 0,
            size: 0,
            type_id: 0,
        }
    }
}

/// An instruction of the loader, as `struct bpf_insn` lays it out.
#[derive(Clone, Copy)]
struct Insn {
    code: u8,
    dst: u8,
    src: u8,
    off: i16,
    imm: i32,
}

/// The loader's instructions and its data, as bytes, and where the
/// header of their container says the .rodata starts in the data.
struct Loader<'a> {
    insns: &'a [u8],
    data: &'a [u8],
    header_rodata_off: Option<u32>,
}

impl<'a> Loader<'a> {
    /// The loader and data of `u`, none of a closed container.
    fn of(u: &'a Upatch) -> Self {
        Loader {
            insns: u.loader(),
            data: u.data(),
            header_rodata_off: Some(u.hdr.rodata_data_off),
        }
    }

    fn count(&self) -> usize {
        self.insns.len() / INSN
    }

    fn insn(&self, i: usize) -> Insn {
        let b = &self.insns[i * INSN..][..INSN];

        Insn {
            code: b[0],
            dst: b[1] & 0xf,
            src: b[1] >> 4,
            off: i16::from_le_bytes([b[2], b[3]]),
            imm: i32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        }
    }

    /// The map value index of the ld_imm64 at `i` into `reg`.
    fn lddw(&self, i: usize, reg: u8) -> Option<u32> {
        if i + 1 >= self.count() {
            return None;
        }
        let (a, b) = (self.insn(i), self.insn(i + 1));
        if a.code != LD_DW_IMM
            || a.dst != reg
            || a.src != PSEUDO_MAP_IDX_VALUE
            || a.off != 0
            || a.imm != 0
            || b.code != 0
            || b.off != 0
        {
            return None;
        }
        Some(b.imm as u32)
    }

    /// The command, attr offset and attr size of the sys_bpf() call at
    /// `i`, as gen_loader sets them up in the four instructions before.
    fn sys_bpf_call(&self, i: usize) -> Option<(u32, u32, u32)> {
        if i < 4 || i >= self.count() {
            return None;
        }
        let call = self.insn(i);
        let cmd = self.insn(i - 4);
        let size = self.insn(i - 1);
        if call.code != JMP_CALL
            || call.imm != FUNC_SYS_BPF
            || cmd.code != ALU64_MOV_K
            || cmd.dst != REG_1
            || self.insn(i - 3).code != LD_DW_IMM
        {
            return None;
        }
        let attr = self.lddw(i - 3, REG_2)?;
        if size.code != ALU64_MOV_K || size.dst != REG_3 {
            return None;
        }
        Some((cmd.imm as u32, attr, size.imm as u32))
    }

    /// The fd slot a map create between `call` and `next_call` stores its
    /// fd into.
    fn map_create_slot(&self, call: usize, next_call: usize) -> Option<u32> {
        let mut i = call + 1;

        while i + 2 < next_call {
            if let Some(off) = self.lddw(i, REG_1) {
                let st = self.insn(i + 2);

                if st.code == STX_W_MEM
                    && st.dst == REG_1
                    && st.src == REG_7
                    && st.off == 0
                    && off % 4 == 0
                    && (off / 4) < MAPS_MAX as u32
                {
                    return Some(off / 4);
                }
            }
            i += 1;
        }
        None
    }

    /// The fd slot of the map a map update at `call`, of attr at `attr`,
    /// updates.
    fn map_update_slot(&self, call: usize, attr: u32) -> Option<u32> {
        let map_fd_off = attr.wrapping_add(ATTR_MAP_FD);
        let mut i = call.saturating_sub(48);

        while i + 5 < call {
            let fd_array_off = self.lddw(i, REG_2);
            let ld = self.insn(i + 2);
            let dest_off = self.lddw(i + 3, REG_1);
            let st = self.insn(i + 5);

            if let (Some(fd_array_off), Some(dest_off)) = (fd_array_off, dest_off)
                && ld.code == LDX_W_MEM
                && ld.dst == REG_0
                && ld.src == REG_2
                && ld.off == 0
                && dest_off == map_fd_off
                && st.code == STX_W_MEM
                && st.dst == REG_1
                && st.src == REG_0
                && st.off == 0
                && fd_array_off % 4 == 0
                && (fd_array_off / 4) < MAPS_MAX as u32
            {
                return Some(fd_array_off / 4);
            }
            i += 1;
        }
        None
    }

    /// The data offset the loader stores into the attr field at `field`
    /// before the sys_bpf() call at `call`, as libbpf's gen_loader writes
    /// a pointer into its data.
    fn store_source(&self, call: usize, field: u32) -> Option<u32> {
        let mut i = call.saturating_sub(24);

        while i + 4 < call {
            let source_off = self.lddw(i, REG_0);
            let dest_off = self.lddw(i + 2, REG_1);
            let st = self.insn(i + 4);

            if let (Some(source_off), Some(dest_off)) = (source_off, dest_off)
                && dest_off == field
                && st.code == STX_DW_MEM
                && st.dst == REG_1
                && st.src == REG_0
                && st.off == 0
            {
                return Some(source_off);
            }
            i += 1;
        }
        None
    }

    /// `attr_size` bytes of the attr at `attr_off` over a zeroed union,
    /// when they lie in the data and fit it, with at least `min` of them.
    fn attr(&self, attr_off: u32, attr_size: u32, min: u32) -> Option<[u8; ATTR_SIZE as usize]> {
        let data_len = self.data.len() as u32;
        let mut attr = [0u8; ATTR_SIZE as usize];

        if attr_size > ATTR_SIZE
            || attr_size < min
            || attr_off > data_len
            || attr_size > data_len - attr_off
        {
            return None;
        }
        attr[..attr_size as usize]
            .copy_from_slice(&self.data[attr_off as usize..][..attr_size as usize]);
        Some(attr)
    }
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn map_name_rodata(name: &[u8]) -> bool {
    name.ends_with(b".rodata")
}

/// The `.rodata` the loader fills with the BTF's DATASEC `datasec_id`:
/// the bytes of the map update of a `.rodata` map it creates.
fn find_rodata_data(l: &Loader<'_>, btf: &Btf, datasec_id: u32, view: &mut View) -> c_int {
    let mut maps = [(0u32, false); MAPS_MAX];
    let count = l.count();

    if !btf.has(datasec_id)
        || btf.kind(datasec_id) != KIND_DATASEC
        || !l.insns.len().is_multiple_of(8)
    {
        return -EINVAL;
    }
    let sec_size = btf.size_or_type(datasec_id);
    for i in 4..count {
        let Some((cmd, attr_off, attr_size)) = l.sys_bpf_call(i) else {
            continue;
        };
        if cmd == MAP_CREATE {
            let Some(attr) = l.attr(attr_off, attr_size, ATTR_MAP_NAME_END) else {
                return -EINVAL;
            };
            let name = &attr[ATTR_MAP_NAME..][..OBJ_NAME_LEN];
            let name = &name[..name.iter().position(|&c| c == 0).unwrap_or(OBJ_NAME_LEN)];
            let end = (i + 1..count)
                .find(|&next| l.sys_bpf_call(next).is_some())
                .unwrap_or(count);
            if map_name_rodata(name) {
                let Some(slot) = l.map_create_slot(i, end) else {
                    return -EOPNOTSUPP;
                };
                maps[slot as usize] = (le32(&attr, ATTR_VALUE_SIZE), true);
            }
        } else if cmd == MAP_UPDATE_ELEM {
            let Some(value_field) = attr_off.checked_add(ATTR_VALUE) else {
                continue;
            };
            let Some(slot) = l.map_update_slot(i, attr_off) else {
                continue;
            };
            let Some(value_off) = l.store_source(i, value_field) else {
                continue;
            };
            let (value_size, found) = maps[slot as usize];
            if !found {
                continue;
            }
            let data_len = l.data.len() as u32;
            if value_size != sec_size || value_off > data_len || value_size > data_len - value_off {
                return -EINVAL;
            }
            view.bytes = l.data[value_off as usize..].as_ptr();
            view.data_offset = value_off;
            view.size = sec_size;
            view.type_id = datasec_id;
            return 0;
        }
    }
    -ENODATA
}

/// The BTF the loader's one BPF_BTF_LOAD loads: the offset in data it
/// stores into attr.btf, and the attr.btf_size beside it.
fn loader_btf(l: &Loader<'_>) -> Result<(u32, u32), c_int> {
    let mut found = None;

    if l.data.is_empty() {
        return Err(-ENOENT);
    }
    if !l.insns.len().is_multiple_of(8) {
        return Err(-EINVAL);
    }
    for i in 4..l.count() {
        let Some((cmd, attr_off, attr_size)) = l.sys_bpf_call(i) else {
            continue;
        };
        if cmd != BTF_LOAD {
            continue;
        }
        if found.is_some() {
            return Err(-E2BIG);
        }
        let Some(attr) = l.attr(attr_off, attr_size, ATTR_BTF_SIZE_END) else {
            return Err(-EINVAL);
        };
        let btf_size = le32(&attr, ATTR_BTF_SIZE);
        let data_len = l.data.len() as u32;
        let Some(btf_off) = attr_off
            .checked_add(ATTR_BTF)
            .and_then(|field| l.store_source(i, field))
        else {
            return Err(-EINVAL);
        };
        if btf_off > data_len || btf_size > data_len - btf_off {
            return Err(-EINVAL);
        }
        found = Some((btf_off, btf_size));
    }
    found.ok_or(-ENOENT)
}

fn btf_rodata_btf(l: &Loader<'_>, view: &mut View) -> c_int {
    let (btf_off, btf_size) = match loader_btf(l) {
        Ok(found) => found,
        Err(ret) => return ret,
    };
    let data = l.data;
    // loader_btf() kept the btf_size bytes at btf_off inside the data.
    let Ok(btf) = Btf::parse(&data[btf_off as usize..][..btf_size as usize]) else {
        return -ENOENT;
    };
    let Some(id) = btf
        .find_by_name_kind(b".rodata", KIND_DATASEC)
        .filter(|&id| id != 0)
    else {
        return -ENOENT;
    };
    // The header is not signed: .rodata is where the signed loader
    // takes it from, and a header that names another offset would aim a
    // rewrite the operator then signs at other bytes.
    let ret = find_rodata_data(l, &btf, id, view);
    view.btf = Some(btf);
    if ret == 0
        && l.header_rodata_off
            .is_some_and(|off| view.data_offset != off)
    {
        return -EINVAL;
    }
    ret
}

/// Where the .rodata of `l` starts in its data, or -errno.
fn rodata_offset(l: &Loader<'_>) -> Result<u32, c_int> {
    let mut view = View::new();

    match btf_rodata_btf(l, &mut view) {
        0 => Ok(view.data_offset),
        err => Err(err),
    }
}

/// Where the .rodata of the loader `insns` starts in its `data`, before
/// a header names it, or -errno.
pub(crate) fn loader_data_offset(insns: &[u8], data: &[u8]) -> Result<u32, c_int> {
    rodata_offset(&Loader {
        insns,
        data,
        header_rodata_off: None,
    })
}

/// The variables of the DATASEC `sec`: (type, offset, size) each.
fn secinfo(btf: &Btf, sec: u32) -> Vec<[u32; 3]> {
    (0..btf.vlen(sec))
        .map(|i| {
            let (ty, offset, size) = btf.secinfo(sec, i);
            [ty, offset, size]
        })
        .collect()
}

/// Where the variable `symbol` lies in the .rodata of the container
/// `u`, into `range`: 0 or -errno.
pub(crate) fn symbol_range(u: &Upatch, symbol: &CStr, range: &mut RodataRange) -> c_int {
    let symbol = symbol.to_bytes();
    if symbol.is_empty() {
        return -EINVAL;
    }
    let mut view = View::new();
    let mut found = false;

    let ret = btf_rodata_btf(&Loader::of(u), &mut view);
    if ret != 0 {
        return ret;
    }
    let Some(btf) = view.btf.as_ref() else {
        return -EINVAL;
    };
    if !btf.has(view.type_id) || btf.kind(view.type_id) != KIND_DATASEC {
        return -EINVAL;
    }
    for [ty, offset, size] in secinfo(btf, view.type_id) {
        if !btf.has(ty) || btf.kind(ty) != KIND_VAR {
            continue;
        }
        if btf.str_at(btf.name_off(ty)) != Some(symbol) {
            continue;
        }
        if found {
            return -EEXIST;
        }
        let inside = offset
            .checked_add(size)
            .filter(|&end| end <= view.size)
            .and_then(|end| view.data_offset.checked_add(end))
            .is_some_and(|end| end <= u.hdr.data_len);
        if !inside {
            return -EINVAL;
        }
        range.offset = view.data_offset + offset;
        range.size = size;
        found = true;
    }
    if found { 0 } else { -ENOENT }
}

/// The name at `off` of `btf`, when it is printable ASCII alone: the BTF
/// may come from an unsigned package, and its names go to the terminal.
fn name_printable(btf: &Btf, off: u32) -> bool {
    btf.str_at(off)
        .is_some_and(|name| name.iter().all(|&c| (0x20..=0x7e).contains(&c)))
}

/// The type `id` resolves to through typedefs and modifiers, or 0.
fn unwrap(btf: &Btf, mut id: u32) -> u32 {
    for _ in 0..JSON_MAX_DEPTH {
        if !btf.has(id) {
            return 0;
        }
        match btf.kind(id) {
            KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG => {
                id = btf.size_or_type(id);
            }
            _ => return id,
        }
    }
    0
}

/// `parts` appended at `*off` of `buf`, as strsprintf() writes them:
/// -ENOSPC when they do not fit.
fn append(buf: &mut [u8], off: &mut usize, parts: &[&[u8]]) -> c_int {
    match strsprintf(&mut buf[*off..], parts) {
        Ok(n) => {
            *off += n;
            0
        }
        Err(_) => -ENOSPC,
    }
}

/// The name of type `id`, its modifiers dropped, after `*off` in `buf`.
pub(crate) fn append_type_name(
    btf: &Btf,
    id: u32,
    buf: &mut [u8],
    off: &mut usize,
    depth: u32,
) -> c_int {
    if depth >= JSON_MAX_DEPTH || *off >= buf.len() {
        return -E2BIG;
    }
    if !btf.has(id) {
        return -EINVAL;
    }
    let kind = btf.kind(id);
    if !name_printable(btf, btf.name_off(id)) {
        return -EINVAL;
    }
    let name = btf.str_at(btf.name_off(id)).unwrap_or_default();
    let named = !name.is_empty();
    if kind == KIND_TYPEDEF && named {
        return append(buf, off, &[name]);
    }
    if matches!(
        kind,
        KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG
    ) {
        return append_type_name(btf, btf.size_or_type(id), buf, off, depth + 1);
    }
    if kind == KIND_ARRAY {
        let a = btf.array(id);
        if append_type_name(btf, a.ty, buf, off, depth + 1) != 0 {
            return -EINVAL;
        }
        return append(buf, off, &[format!("[{}]", a.nelems).as_bytes()]);
    }
    if kind == KIND_PTR {
        if append_type_name(btf, btf.size_or_type(id), buf, off, depth + 1) != 0 {
            return -EINVAL;
        }
        return append(buf, off, &[b" *"]);
    }
    if named {
        let prefix: &[u8] = match kind {
            KIND_STRUCT => b"struct ",
            KIND_UNION => b"union ",
            KIND_ENUM => b"enum ",
            _ => b"",
        };
        append(buf, off, &[prefix, name])
    } else {
        let fallback: &[u8] = match kind {
            KIND_INT => b"integer",
            KIND_STRUCT => b"struct",
            KIND_UNION => b"union",
            KIND_ENUM | KIND_ENUM64 => b"enum",
            KIND_FLOAT => b"float",
            KIND_FWD => b"forward declaration",
            _ => b"?",
        };
        append(buf, off, &[fallback])
    }
}

fn json_number(e: &mut JsonEmit, value: u64, signed: bool) -> c_int {
    let mut number = [0u8; 32];

    // SAFETY: the room of number, and the C's formats with an integer.
    let n = unsafe {
        if signed {
            crate::text::csprintf!(
                number.as_mut_ptr().cast(),
                number.len(),
                c"%lld".as_ptr(),
                value as i64,
            )
        } else {
            crate::text::csprintf!(
                number.as_mut_ptr().cast(),
                number.len(),
                c"%llu".as_ptr(),
                value,
            )
        }
    };
    if n < 0 {
        return n;
    }
    e.raw_value(&number[..n as usize]);
    e.err()
}

/// The integer of the INT `t` in `bytes`: its value, sign-extended when
/// signed, and whether it is signed and a bool.
fn btf_integer(btf: &Btf, t: u32, bytes: &[u8]) -> Result<(u64, bool, bool), c_int> {
    let enc = btf.int_encoding(t);
    let (size, enc_signed, enc_bool, bits, bit_off) = (
        btf.size_or_type(t),
        enc & INT_SIGNED != 0,
        enc & INT_BOOL != 0,
        u32::from(btf.int_bits(t)),
        u32::from(btf.int_offset(t)),
    );
    let mut result = 0u64;

    if size as usize > bytes.len() || size == 0 || size > 8 {
        return Err(-EINVAL);
    }
    if bits == 0 || bits > 64 || bit_off + bits > size * 8 {
        return Err(-EINVAL);
    }
    for i in 0..bits {
        let b = bit_off + i;

        if bytes[b as usize / 8] & (1u8 << (b % 8)) != 0 {
            result |= 1u64 << i;
        }
    }
    if enc_signed && bits < 64 && result & (1u64 << (bits - 1)) != 0 {
        result |= !((1u64 << bits) - 1);
    }
    Ok((result, enc_signed, enc_bool))
}

fn json_hex(e: &mut JsonEmit, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let cap = bytes.len().saturating_mul(2).saturating_add(3);

    if cap > MAX_BYTES {
        e.set_err(-E2BIG);
        return;
    }
    let mut text = Vec::new();
    if text.try_reserve_exact(cap).is_err() {
        e.set_err(-ENOMEM);
        return;
    }
    text.resize(cap, 0);
    text[0] = b'0';
    text[1] = b'x';
    for (i, &b) in bytes.iter().enumerate() {
        text[2 + i * 2] = HEX[usize::from(b >> 4)];
        text[3 + i * 2] = HEX[usize::from(b & 0xf)];
    }
    e.str_value(&text[..2 + bytes.len() * 2]);
}

/// The value of type `type_id` in `bytes` as JSON.
fn json_btf_value(e: &mut JsonEmit, btf: &Btf, type_id: u32, bytes: &[u8], depth: u32) -> c_int {
    if depth >= JSON_MAX_DEPTH || type_id == 0 {
        return -EINVAL;
    }
    let t = unwrap(btf, type_id);
    if !btf.has(t) {
        return -EINVAL;
    }
    let size = bytes.len();
    match btf.kind(t) {
        KIND_INT => {
            let (value, signed, boolean) = match btf_integer(btf, t, bytes) {
                Ok(v) => v,
                Err(ret) => return ret,
            };
            if boolean {
                e.raw_value(if value != 0 { b"true" } else { b"false" });
            } else {
                return json_number(e, value, signed);
            }
            e.err()
        }
        KIND_ENUM | KIND_ENUM64 => {
            let signed = btf.kflag(t);
            let tsize = btf.size_or_type(t) as usize;
            let mut value = 0u64;
            let mut enum_name: &[u8] = b"";

            if tsize == 0 || tsize > 8 || tsize > size {
                return -EINVAL;
            }
            for (i, &b) in bytes[..tsize].iter().enumerate() {
                value |= u64::from(b) << (i * 8);
            }
            if signed && tsize < 8 && value & (1u64 << (tsize * 8 - 1)) != 0 {
                value |= !((1u64 << (tsize * 8)) - 1);
            }
            let is_enum = btf.kind(t) == KIND_ENUM;
            let found = (0..btf.vlen(t))
                .map(|i| btf.enum_value(t, i))
                .find(|&(_, v)| {
                    if is_enum {
                        v as u32 == value as u32
                    } else {
                        v == value
                    }
                });
            if let Some((name_off, _)) = found {
                enum_name = btf.str_at(name_off).unwrap_or_default();
            }
            e.obj_value_open();
            if !enum_name.is_empty() {
                e.kv_string(b"name", enum_name);
            }
            e.key(b"value");
            json_number(e, value, signed);
            e.obj_close();
            e.err()
        }
        KIND_STRUCT => {
            e.obj_value_open();
            for (i, m) in btf.members(t).enumerate() {
                if e.err() != 0 {
                    break;
                }
                let bit_off = m.bit_offset();
                let bit_size = m.bitfield_size();
                let byte_off = (bit_off / 8) as usize;
                let name = btf.str_at(m.name_off).unwrap_or_default();
                let member_size = btf.resolve_size(m.ty).map_or(-1i64, i64::from);
                let mut fallback = [0u8; 24];

                if !name.is_empty() {
                    e.key(name);
                } else {
                    // SAFETY: the room of fallback, the C's format and
                    // an integer.
                    let n = unsafe {
                        crate::text::csprintf!(
                            fallback.as_mut_ptr().cast(),
                            fallback.len(),
                            c"member_%u".as_ptr(),
                            i as u32,
                        )
                    };
                    if n < 0 {
                        return -EINVAL;
                    }
                    e.key(&fallback[..n as usize]);
                }
                if bit_size != 0 {
                    let n = (bit_off % 8 + bit_size).div_ceil(8) as usize;
                    let mt = unwrap(btf, m.ty);
                    let int = btf.has(mt) && btf.kind(mt) == KIND_INT;
                    if bit_size > 64 || byte_off + n > size || !int {
                        return -EINVAL;
                    }
                    let signed = btf.int_encoding(mt) & INT_SIGNED != 0;
                    let mut val = 0u64;
                    for j in 0..bit_size {
                        let pos = bit_off + j;

                        if bytes[pos as usize / 8] & (1u8 << (pos % 8)) != 0 {
                            val |= 1u64 << j;
                        }
                    }
                    if signed && bit_size < 64 && val & (1u64 << (bit_size - 1)) != 0 {
                        val |= !((1u64 << bit_size) - 1);
                    }
                    json_number(e, val, signed);
                } else {
                    if member_size < 0 || byte_off > size || member_size as usize > size - byte_off
                    {
                        return -EINVAL;
                    }
                    let member = &bytes[byte_off..][..member_size as usize];
                    let ret = json_btf_value(e, btf, m.ty, member, depth + 1);
                    if ret != 0 {
                        return ret;
                    }
                }
            }
            e.obj_close();
            e.err()
        }
        KIND_ARRAY => {
            let a = btf.array(t);
            let elem_size = btf.resolve_size(a.ty).map_or(-1i64, i64::from);
            let total = (elem_size as u64).checked_mul(u64::from(a.nelems));

            if elem_size < 0 || total.is_none_or(|total| total > size as u64) {
                return -EINVAL;
            }
            e.arr_open_value();
            for i in 0..a.nelems as usize {
                if e.err() != 0 {
                    break;
                }
                if elem_size == 0 {
                    return -EINVAL;
                }
                let elem = &bytes[i * elem_size as usize..][..elem_size as usize];
                let ret = json_btf_value(e, btf, a.ty, elem, depth + 1);
                if ret != 0 {
                    return ret;
                }
            }
            e.arr_close();
            e.err()
        }
        KIND_PTR => {
            let mut value = [0u8; 8];
            let mut text = [0u8; 32];

            if size > value.len() {
                return -EINVAL;
            }
            value[..size].copy_from_slice(bytes);
            // SAFETY: the room of text, the C's format and an integer.
            let n = unsafe {
                crate::text::csprintf!(
                    text.as_mut_ptr().cast(),
                    text.len(),
                    c"0x%llx".as_ptr(),
                    u64::from_ne_bytes(value),
                )
            };
            if n < 0 {
                return n;
            }
            e.str_value(&text[..n as usize]);
            e.err()
        }
        _ => {
            json_hex(e, bytes);
            e.err()
        }
    }
}

/// The name of the variable of `var`, when it is a VAR with a printable
/// name.
fn var_name<'b>(btf: &'b Btf, var: &[u32; 3]) -> Option<&'b [u8]> {
    let t = var[0];
    (btf.has(t) && btf.kind(t) == KIND_VAR && name_printable(btf, btf.name_off(t)))
        .then(|| btf.str_at(btf.name_off(t)))
        .flatten()
}

/// The type of the variable of `var`.
fn var_type(btf: &Btf, var: &[u32; 3]) -> Option<u32> {
    let t = var[0];
    (btf.has(t) && btf.kind(t) == KIND_VAR).then(|| btf.size_or_type(t))
}

/// The cast libbpf's dumper writes before a value spells its type
/// through modifiers, pointers and arrays, and stops at no loop: a
/// pointer to itself grows its stack until memory runs out, and a
/// function prototype whose parameter leads back to it recurses until
/// the stack does.
fn decl_printable(btf: &Btf, mut id: u32) -> bool {
    for _ in 0..DECL_MAX {
        if id == 0 {
            return true;
        }
        if !btf.has(id) {
            return false;
        }
        match btf.kind(id) {
            KIND_PTR | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG => {
                id = btf.size_or_type(id);
            }
            KIND_ARRAY => id = btf.array(id).ty,
            KIND_INT | KIND_ENUM | KIND_ENUM64 | KIND_FWD | KIND_STRUCT | KIND_UNION
            | KIND_TYPEDEF | KIND_FLOAT => return name_printable(btf, btf.name_off(id)),
            _ => return false,
        }
    }
    false
}

/// What the dumper visits of a value of a type: values printed, types
/// deep.
#[derive(Clone, Copy, Default)]
pub(crate) struct DumpCost {
    values: u32,
    height: u32,
}

/// libbpf's dumper follows member, element and modifier types with no
/// bound, and the BTF may come from an unsigned package: a VAR whose
/// type is the DATASEC holding it sends it round until the stack is
/// gone, and billions of elements, of zero size or not, or members laid
/// over the same bytes keep it busy. Walk what it would follow first,
/// through value types alone, with the cast and the member and
/// enumerator names it would print, and count what it would visit:
/// -EINVAL for more than JSON_MAX_DEPTH types deep, -E2BIG for more than
/// TEXT_MAX_VALUES values. `cost` keeps the counts of the types found
/// fine, so a type reached again brings its depth and values along.
///
/// `cost` has a slot for each of the BTF's types.
pub(crate) fn dump_cost(btf: &Btf, id: u32, depth: u32, cost: &mut [DumpCost]) -> c_int {
    let mut c = DumpCost {
        values: 1,
        height: 1,
    };

    if !btf.has(id) || depth >= JSON_MAX_DEPTH {
        return -EINVAL;
    }
    if cost[id as usize].values != 0 {
        return 0;
    }
    if !decl_printable(btf, id) {
        return -EINVAL;
    }
    {
        match btf.kind(id) {
            KIND_INT | KIND_PTR | KIND_FLOAT => {}
            KIND_ENUM | KIND_ENUM64 => {
                for i in 0..btf.vlen(id) {
                    if !name_printable(btf, btf.enum_value(id, i).0) {
                        return -EINVAL;
                    }
                }
            }
            KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG => {
                let next = btf.size_or_type(id);
                let ret = dump_cost(btf, next, depth + 1, cost);
                if ret != 0 {
                    return ret;
                }
                c.values = cost[next as usize].values;
                c.height = cost[next as usize].height + 1;
            }
            KIND_ARRAY => {
                let a = btf.array(id);

                if a.nelems != 0 && btf.resolve_size(a.ty).unwrap_or(0) == 0 {
                    return -EINVAL;
                }
                let ret = dump_cost(btf, a.ty, depth + 1, cost);
                if ret != 0 {
                    return ret;
                }
                let Some(values) = cost[a.ty as usize]
                    .values
                    .checked_mul(a.nelems)
                    .and_then(|child| c.values.checked_add(child))
                else {
                    return -E2BIG;
                };
                c.values = values;
                c.height = cost[a.ty as usize].height + 1;
            }
            KIND_STRUCT | KIND_UNION => {
                for m in btf.members(id) {
                    if !name_printable(btf, m.name_off) {
                        return -EINVAL;
                    }
                    let ret = dump_cost(btf, m.ty, depth + 1, cost);
                    if ret != 0 {
                        return ret;
                    }
                    let Some(values) = c.values.checked_add(cost[m.ty as usize].values) else {
                        return -E2BIG;
                    };
                    c.values = values;
                    c.height = c.height.max(cost[m.ty as usize].height + 1);
                }
            }
            _ => return -EINVAL,
        }
    }
    if c.height > JSON_MAX_DEPTH {
        return -EINVAL;
    }
    if c.values > TEXT_MAX_VALUES {
        return -E2BIG;
    }
    cost[id as usize] = c;
    0
}

/// The DATASEC's variables of `view`, each checked to lie inside it: its
/// name, its type, and the length of the name of its type.
fn variable<'v>(
    view: &'v View,
    btf: &'v Btf,
    var: &[u32; 3],
    type_name: &mut [u8; 256],
) -> Result<(&'v [u8], u32, usize), c_int> {
    let mut type_off = 0;

    let Some(name) = var_name(btf, var).filter(|n| !n.is_empty()) else {
        return Err(-EINVAL);
    };
    let Some(type_id) = var_type(btf, var) else {
        return Err(-EINVAL);
    };
    let ret = append_type_name(btf, type_id, type_name, &mut type_off, 0);
    if ret != 0 {
        return Err(ret);
    }
    if var[1] > view.size || var[2] > view.size - var[1] {
        return Err(-EINVAL);
    }
    Ok((name, type_id, type_off))
}

/// The bytes of a variable at `offset` of `size` in the view.
fn var_bytes(view: &View, offset: u32, size: u32) -> &[u8] {
    // SAFETY: bytes of the section, which variable() checked.
    unsafe { ffi::slice(view.bytes.add(offset as usize), size as usize) }
}

/// # Safety
///
/// `view` holds a BTF with its DATASEC.
unsafe fn print_rodata_text(u: &Upatch, path: &CStr, view: &View) -> c_int {
    let Some(btf) = view.btf.as_ref() else {
        return -EINVAL;
    };
    let mut name = [0u8; NAME_MAX + 1];
    let mut values = 0u32;
    let mut ret = 0;

    let (vars, types) = (secinfo(btf, view.type_id), btf.type_cnt());
    let len = u.name().len();
    name[..len].copy_from_slice(u.name());
    // SAFETY: the name, a C string of len bytes, sanitised in place; the
    // path printed through the terminal-safe formatter; the C's formats
    // with C strings and integers.
    unsafe {
        crate::text::sanitize(&mut name[..len], false);
        printf(c"upatch %s (".as_ptr(), name.as_ptr());
        fputs_sanitized(path.to_bytes(), stdout);
        printf(
            c") .rodata: %u bytes at data+%u, file+%u\n".as_ptr(),
            view.size,
            view.data_offset,
            u.hdr.data_off.wrapping_add(view.data_offset),
        );
    }
    let mut costs = vec![
        DumpCost {
            values: 0,
            height: 0,
        };
        types as usize
    ];
    // The container's mapping, which the variables' bytes lie in and the
    // dumper reads past a bitfield into, as libbpf's did.
    let mem = u.bytes();
    let mut dump = Dump::new(btf);
    for var in &vars {
        let mut type_name = [0u8; 256];

        let (var_name, type_id, type_len) = match variable(view, btf, var, &mut type_name) {
            Ok(v) => v,
            Err(err) => {
                ret = err;
                break;
            }
        };
        ret = dump_cost(btf, type_id, 0, &mut costs);
        if ret == 0 {
            match values.checked_add(costs[type_id as usize].values) {
                Some(v) if v <= TEXT_MAX_VALUES => values = v,
                _ => ret = -E2BIG,
            }
        }
        if ret == -E2BIG {
            crate::log::err(format!("BTF text output exceeds {TEXT_MAX_VALUES} values").as_bytes());
        }
        if ret != 0 {
            break;
        }
        let header = format!(
            "\n{}: {}, size={}, rodata+{}, data+{}, file+{} = ",
            String::from_utf8_lossy(var_name),
            String::from_utf8_lossy(&type_name[..type_len]),
            var[2],
            var[1],
            view.data_offset + var[1],
            u.hdr
                .data_off
                .wrapping_add(view.data_offset)
                .wrapping_add(var[1]),
        );
        let bytes = var_bytes(view, var[1], var[2]);
        // An empty value has no place in the mapping, its pointer a
        // dangling one, and nothing is read of it.
        let start = match bytes {
            [] => 0,
            _ => bytes.as_ptr() as usize - mem.as_ptr() as usize,
        };
        let mut out = header.into_bytes();
        let dumped = dump.dump_type_data(&mut out, type_id, mem, start, bytes.len());
        out.extend_from_slice(if dumped.is_ok() { b"\n" } else { b"" });
        // SAFETY: the text, onto the stream the C's printf() writes.
        unsafe { fwrite(out.as_ptr().cast(), 1, out.len(), stdout) };
        if let Err(err) = dumped {
            ret = err;
            break;
        }
    }
    if ret >= 0 {
        // SAFETY: a character onto stdout.
        unsafe { putchar(c_int::from(b'\n')) };
    }
    ret.min(0)
}

/// # Safety
///
/// `view` holds a BTF with its DATASEC.
unsafe fn print_rodata_json(u: &Upatch, path: &CStr, view: &View) -> c_int {
    let mut e = JsonEmit::growing(MAX_BYTES);
    let mut ret = 0;

    let Some(btf) = view.btf.as_ref() else {
        return -EINVAL;
    };
    let vars = secinfo(btf, view.type_id);
    let name = u.name();
    e.obj_open();
    e.kv_int(b"schema", 1);
    e.key(b"upatch");
    e.str_lossy(name);
    e.key(b"path");
    e.str_lossy(path.to_bytes());
    e.kv_string(b"section", b".rodata");
    e.kv_int(b"size", i64::from(view.size));
    e.kv_int(b"data_offset", i64::from(view.data_offset));
    e.kv_int(
        b"file_offset",
        i64::from(u.hdr.data_off.wrapping_add(view.data_offset)),
    );
    e.arr_open(b"variables");
    for var in &vars {
        let mut type_name = [0u8; 256];

        if e.err() != 0 {
            break;
        }
        let (var_name, type_id, type_len) = match variable(view, btf, var, &mut type_name) {
            Ok(v) => v,
            Err(err) => {
                ret = err;
                break;
            }
        };
        e.obj_open();
        e.kv_string(b"name", var_name);
        e.kv_string(b"type", &type_name[..type_len]);
        e.kv_int(b"size", i64::from(var[2]));
        e.kv_int(b"rodata_offset", i64::from(var[1]));
        e.kv_int(b"data_offset", i64::from(view.data_offset + var[1]));
        e.kv_int(
            b"file_offset",
            i64::from(
                u.hdr
                    .data_off
                    .wrapping_add(view.data_offset)
                    .wrapping_add(var[1]),
            ),
        );
        e.key(b"value");
        ret = json_btf_value(&mut e, btf, type_id, var_bytes(view, var[1], var[2]), 0);
        e.obj_close();
        if ret != 0 {
            break;
        }
    }
    e.arr_close();
    e.obj_close();
    if ret == 0 && e.err() != 0 {
        ret = e.err();
    }
    if ret == 0 {
        let out = [e.output(), b"\n"].concat();
        let written = write_complete(std::io::stdout().as_fd(), &out);
        ret = written.err().unwrap_or(0);
    }
    if e.err() == -E2BIG {
        crate::log::err(format!("BTF JSON output exceeds {MAX_BYTES} bytes").as_bytes());
    }
    ret
}

/// The .rodata of the container `u`, read from `path`, as text or JSON
/// on stdout: 0 or -errno.
pub(crate) fn print(u: &Upatch, path: &CStr, json: bool) -> c_int {
    let mut view = View::new();

    if u.is_unload() {
        return -EINVAL;
    }
    let ret = btf_rodata_btf(&Loader::of(u), &mut view);
    if ret != 0 {
        return ret;
    }
    // SAFETY: the view btf_rodata_btf() filled, with its DATASEC.
    unsafe {
        if json {
            print_rodata_json(u, path, &view)
        } else {
            print_rodata_text(u, path, &view)
        }
    }
}

#[cfg(shirudo_fuzz)]
mod fuzz;
