// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The signed decoders of an upatch: Lua source that turns a map's raw
//! bytes into JSON or an OTLP AnyValue, run in a LuaJIT sandbox. The
//! sandbox has no io, os, package, debug, jit, ffi, load or garbage
//! collector control; it has 32 MiB of memory, scrubbed when freed, and
//! a budget of a million instructions with the JIT off so the budget
//! sees each; and its host API reads fixed-size records out of a
//! serializer's pages and does exact 64-bit arithmetic on decimal
//! strings.

use core::cell::Cell;
use core::ffi::{CStr, c_int, c_void};
use core::ops::Range;
use core::ptr;
use std::ffi::CString;
use std::fs::File;

use crate::errno::{E2BIG, EINVAL, ENAMETOOLONG, ENODATA, ENOENT, ERANGE, ESTALE, text};
use crate::sys::libc::{explicit_bzero, snprintf};
use crate::sys::luajit::{
    Allocator, LUA_MASKCOUNT, Lua, LuaCFunction, LuaDebug, LuaState, LuaType, Stack,
};
use crate::text::cstr;
use crate::util::chain::memneq_explicit;
use crate::util::json::JsonEmit;
use crate::util::map_read::MapView;
use crate::util::seal;
use crate::util::upatch::{self, DecoderView, Upatch};
use crate::util::upatch_verify::payload_digest;

const INSN_LIMIT: c_int = 1_000_000;
const HOOK_COUNT: c_int = 10_000;
const MEMORY_LIMIT: usize = 32 * 1024 * 1024;
const JSON_MAX_DEPTH: c_int = 32;
pub(crate) const JSON_MAX: usize = 8 * 1024 * 1024;
const SLOT_MT: &CStr = c"shirudo.slot";
/// SERIAL_CHUNK_PAYLOAD of bpf/lib/serializer.h.
const CHUNK_PAYLOAD: usize = 4032;
/// The largest integer a double holds exactly.
const MAX_EXACT: f64 = 9_007_199_254_740_991.0;
const UPATCHES_DIR: &str = "/var/lib/shirudo/upatches";
const PATH_MAX: usize = 4096;
/// UPATCH_DECODER_LANG_LUA, _INPUT_MAP_V1 and _EXPORT_LOG and _METRIC.
const LANG_LUA: u32 = 1;
const INPUT_MAP_V1: u32 = 1;
const EXPORT_LOG: u32 = 1;
const EXPORT_METRIC: u32 = 2;

/// isspace() of the C locale.
fn is_c_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// A double as printf() spells it with `fmt`, which takes one.
fn printf_double(fmt: &CStr, v: f64) -> Vec<u8> {
    let mut buf = [0u8; 64];
    // SAFETY: the room for the text and a format of one double.
    let n = unsafe { snprintf(buf.as_mut_ptr().cast(), buf.len(), fmt.as_ptr(), v) };
    let n = usize::try_from(n).unwrap_or(0).min(buf.len() - 1);
    buf[..n].to_vec()
}

/// What the decoder's memory has used, against its limit.
struct Memory<'a> {
    inner: Option<Allocator<'a>>,
    used: usize,
}

/// The decoder's allocator: LuaJIT's own, as a GC64 state must live
/// below 2^47, which LuaJIT's allocator guarantees and a PIE's heap on
/// arm64 does not meet; held to the limit, and what is freed scrubbed
/// first.
///
/// # Safety
///
/// `ud` holds this state's memory record. A non-null `p` is a block
/// of `old` bytes from its allocator.
unsafe extern "C" fn limited_alloc(
    ud: *mut c_void,
    p: *mut c_void,
    old: usize,
    new: usize,
) -> *mut c_void {
    // SAFETY: the caller passes the live, exclusive memory record.
    let m = unsafe { &mut *ud.cast::<Memory<'_>>() };
    let Some(inner) = &m.inner else {
        return ptr::null_mut();
    };
    let base = if !p.is_null() && m.used >= old {
        m.used - old
    } else {
        m.used
    };
    if new == 0 {
        if !p.is_null() {
            // SAFETY: p is writable for the old allocation's full size.
            unsafe { explicit_bzero(p, old) };
            // SAFETY: p is the allocator's live block of old bytes.
            unsafe { inner.resize(p, old, 0) };
            m.used = base;
        }
        return ptr::null_mut();
    }
    let Some(total) = base.checked_add(new).filter(|&t| t <= MEMORY_LIMIT) else {
        return ptr::null_mut();
    };
    // SAFETY: a null pointer requests a fresh block.
    let next = unsafe { inner.resize(ptr::null_mut(), 0, new) };
    if next.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the allocator gave us a writable block of new bytes.
    unsafe { next.cast::<u8>().write_bytes(0, new) };
    if !p.is_null() {
        // SAFETY: the old and new allocations are disjoint and this fits both.
        unsafe { ptr::copy_nonoverlapping(p.cast::<u8>(), next.cast::<u8>(), old.min(new)) };
        // SAFETY: p is writable for the old allocation's full size.
        unsafe { explicit_bzero(p, old) };
        // SAFETY: p is the allocator's live block of old bytes.
        unsafe { inner.resize(p, old, 0) };
    }
    m.used = total;
    next
}

/// Where a table key stands in an array: a whole number from 1 to the
/// largest int.
fn array_index(key: f64) -> Option<c_int> {
    // `as` saturates, and only a whole number in range comes back equal.
    let index = key as c_int;
    (index >= 1 && f64::from(index) == key).then_some(index)
}

/// Whether the table at `idx` is an array, 1 to its length with no
/// other key, and that length.
fn table_array_len(s: &mut Stack<'_>, idx: c_int) -> Option<c_int> {
    let idx = s.abs_index(idx)?;
    let (mut count, mut max, mut array) = (0, 0, true);
    s.push_nil();
    while s.next(idx) {
        let index = (s.type_of(-2) == LuaType::Number)
            .then(|| array_index(s.to_number(-2)))
            .flatten();
        match index {
            Some(index) => {
                max = max.max(index);
                count += 1;
            }
            None => array = false,
        }
        s.pop(1);
    }
    (array && count == max).then_some(max)
}

/// Whether a value of the type can be a key in the JSON.
fn is_key(t: LuaType) -> bool {
    matches!(t, LuaType::String | LuaType::Number | LuaType::Boolean)
}

/// A table key as text: a string as it is, a number and a boolean
/// spelled out. A name the kernel hands over is raw bytes, cut at a
/// fixed length mid-character as often as not, and one bad byte must
/// not cost the whole snapshot: the lossy writers make it U+FFFD.
fn emit_key(s: &Stack<'_>, idx: c_int, e: &mut JsonEmit, as_key: bool) {
    let number;
    let text: &[u8] = match s.type_of(idx) {
        LuaType::String => s.to_bytes(idx).unwrap_or_default(),
        LuaType::Number => {
            number = printf_double(c"%.17g", s.to_number(idx));
            &number
        }
        LuaType::Boolean if s.to_bool(idx) => b"true",
        LuaType::Boolean => b"false",
        _ => b"unsupported_key",
    };
    if as_key {
        e.key_lossy(text)
    } else {
        e.str_lossy(text)
    }
}

/// The Lua value at `idx` as JSON, into `e`, whose error says whether it
/// could be.
fn json_value(s: &mut Stack<'_>, idx: c_int, e: &mut JsonEmit, depth: c_int) {
    if depth > JSON_MAX_DEPTH {
        e.set_err(-E2BIG);
        return;
    }
    match s.type_of(idx) {
        LuaType::Nil => e.raw_value(b"null"),
        LuaType::Boolean if s.to_bool(idx) => e.raw_value(b"true"),
        LuaType::Boolean => e.raw_value(b"false"),
        LuaType::Number => {
            let v = s.to_number(idx);
            if !v.is_finite() {
                e.set_err(-EINVAL);
            } else {
                e.raw_value(&printf_double(c"%.17g", v));
            }
        }
        LuaType::String => e.str_lossy(s.to_bytes(idx).unwrap_or_default()),
        LuaType::Table => json_table(s, idx, e, depth),
        _ => e.set_err(-EINVAL),
    }
}

fn json_table(s: &mut Stack<'_>, idx: c_int, e: &mut JsonEmit, depth: c_int) {
    let Some(idx) = s.abs_index(idx) else {
        e.set_err(-EINVAL);
        return;
    };
    if let Some(len) = table_array_len(s, idx) {
        e.arr_open_value();
        for i in 1..=len {
            if e.err() != 0 {
                break;
            }
            s.raw_get_index(idx, i);
            json_value(s, -1, e, depth + 1);
            s.pop(1);
        }
        e.arr_close();
        return;
    }
    e.obj_value_open();
    s.push_nil();
    while s.next(idx) {
        if !is_key(s.type_of(-2)) {
            e.set_err(-EINVAL);
            s.pop(2);
            break;
        }
        emit_key(s, -2, e, true);
        json_value(s, -1, e, depth + 1);
        s.pop(1);
        if e.err() != 0 {
            s.pop(1);
            break;
        }
    }
    e.obj_close();
}

/// The Lua value at `idx` as the OTLP JSON form of an AnyValue, into
/// `e`, whose error says whether it could be.
fn otel_value(s: &mut Stack<'_>, idx: c_int, e: &mut JsonEmit, depth: c_int) {
    if depth > JSON_MAX_DEPTH {
        e.set_err(-E2BIG);
        return;
    }
    match s.type_of(idx) {
        // An empty AnyValue is the OTLP form of nil.
        LuaType::Nil => {
            e.obj_value_open();
            e.obj_close();
        }
        LuaType::Boolean => {
            e.obj_value_open();
            e.kv_bool(b"boolValue", s.to_bool(idx));
            e.obj_close();
        }
        LuaType::Number => {
            let v = s.to_number(idx);
            if !v.is_finite() {
                e.set_err(-EINVAL);
            } else {
                e.obj_value_open();
                if v.trunc() == v && v.abs() <= MAX_EXACT {
                    e.kv_string(
                        b"intValue",
                        &printf_double(c"%.0f", if v == 0.0 { 0.0 } else { v }),
                    );
                } else {
                    e.kv_raw(b"doubleValue", &printf_double(c"%.17g", v));
                }
                e.obj_close();
            }
        }
        LuaType::String => {
            e.obj_value_open();
            e.key(b"stringValue");
            e.str_lossy(s.to_bytes(idx).unwrap_or_default());
            e.obj_close();
        }
        LuaType::Table => otel_table(s, idx, e, depth),
        _ => e.set_err(-EINVAL),
    }
}

fn otel_table(s: &mut Stack<'_>, idx: c_int, e: &mut JsonEmit, depth: c_int) {
    let Some(idx) = s.abs_index(idx) else {
        e.set_err(-EINVAL);
        return;
    };
    e.obj_value_open();
    if let Some(len) = table_array_len(s, idx) {
        e.obj_open_key(b"arrayValue");
        e.arr_open(b"values");
        for i in 1..=len {
            if e.err() != 0 {
                break;
            }
            s.raw_get_index(idx, i);
            otel_value(s, -1, e, depth + 1);
            s.pop(1);
        }
        e.arr_close();
        e.obj_close();
        e.obj_close();
        return;
    }
    e.obj_open_key(b"kvlistValue");
    e.arr_open(b"values");
    s.push_nil();
    while s.next(idx) {
        if !is_key(s.type_of(-2)) {
            e.set_err(-EINVAL);
            s.pop(2);
            break;
        }
        e.obj_value_open();
        e.key(b"key");
        emit_key(s, -2, e, false);
        e.key(b"value");
        otel_value(s, -1, e, depth + 1);
        e.obj_close();
        s.pop(1);
        if e.err() != 0 {
            s.pop(1);
            break;
        }
    }
    e.arr_close();
    e.obj_close();
    e.obj_close();
}

/// Pushes the hex at `hex` decoded into a userdata, which the collector
/// frees: a Lua error raised while the bytes are in use would leak a
/// buffer of our own. Blanks between digits are skipped. False, with
/// nothing pushed, for what is not an even run of digits.
fn hex_decode_push(s: &mut Stack<'_>, hex: &[u8]) -> bool {
    let n_digits = hex.iter().filter(|&&c| !is_c_space(c)).count();
    if n_digits % 2 != 0 {
        return false;
    }
    let decoded = s.push_userdata_with(n_digits / 2, |bytes| {
        let mut digits = hex.iter().copied().filter(|&c| !is_c_space(c));
        bytes.iter_mut().all(|b| {
            let hi = digits.next().and_then(hex_nibble);
            let lo = digits.next().and_then(hex_nibble);
            let (Some(hi), Some(lo)) = (hi, lo) else {
                return false;
            };
            *b = hi << 4 | lo;
            true
        })
    });
    if !decoded {
        s.pop(1);
    }
    decoded
}

/// Pushes a slot: a userdata of the record's length and its bytes.
fn push_slot(s: &mut Stack<'_>, record: &[u8]) {
    let Ok(len) = u32::try_from(record.len()) else {
        s.error(c"invalid slot size");
    };
    let len = len.to_ne_bytes();
    s.push_userdata_with(len.len() + record.len(), |slot| {
        let (head, body) = slot.split_at_mut(len.len());
        head.copy_from_slice(&len);
        body.copy_from_slice(record);
    });
    s.push_metatable(SLOT_MT);
    s.set_metatable(-2);
}

/// A slot's record: the bytes after its length.
fn slot_record(slot: &[u8]) -> &[u8] {
    let Some((len, record)) = slot.split_first_chunk::<4>() else {
        return &[];
    };
    let len = usize::try_from(u32::from_ne_bytes(*len)).unwrap_or(0);
    record.get(..len).unwrap_or(record)
}

/// The record of the slot a method is called on, raising an error when
/// argument 1 is not a slot.
fn check_slot<'a>(s: &'a Stack<'_>) -> &'a [u8] {
    slot_record(s.check_userdata(1, SLOT_MT))
}

/// An int argument, raising an error for one out of range.
fn check_c_int(s: &Stack<'_>, arg: c_int) -> c_int {
    let v = s.check_integer(arg);
    c_int::try_from(v).unwrap_or_else(|_| s.arg_error(arg, c"integer out of range"))
}

/// The `N` bytes at offset argument 2 of the slot a method is called on,
/// zeros past its record.
fn slot_word<const N: usize>(s: &Stack<'_>) -> [u8; N] {
    let record = check_slot(s);
    let off = check_c_int(s, 2);
    usize::try_from(off)
        .ok()
        .and_then(|off| record.get(off..)?.first_chunk::<N>().copied())
        .unwrap_or([0; N])
}

unsafe extern "C-unwind" fn slot_u8(l: *mut LuaState) -> c_int {
    // SAFETY: LuaJIT called this C function with the state, and this is
    // the one Stack of its frame.
    let mut s = unsafe { Stack::from_raw(l) };
    let v = u8::from_le_bytes(slot_word(&s));
    s.push_integer(i32::from(v));
    1
}

unsafe extern "C-unwind" fn slot_u16(l: *mut LuaState) -> c_int {
    // SAFETY: as in slot_u8().
    let mut s = unsafe { Stack::from_raw(l) };
    let v = u16::from_le_bytes(slot_word(&s));
    s.push_integer(i32::from(v));
    1
}

unsafe extern "C-unwind" fn slot_u32(l: *mut LuaState) -> c_int {
    // SAFETY: as in slot_u8().
    let mut s = unsafe { Stack::from_raw(l) };
    let v = u32::from_le_bytes(slot_word(&s));
    s.push_number(f64::from(v));
    1
}

unsafe extern "C-unwind" fn slot_u64(l: *mut LuaState) -> c_int {
    // SAFETY: as in slot_u8().
    let mut s = unsafe { Stack::from_raw(l) };
    let v = u64::from_le_bytes(slot_word(&s));
    push_u64_string(&mut s, v);
    1
}

/// Where in the record the NUL-terminated string at `off` lies, of
/// `len` bytes at most and of `max` when `len` is not in 1 to `max`.
fn cstring_span(record: &[u8], off: c_int, len: c_int, max: c_int) -> Range<usize> {
    let Some(off) = usize::try_from(off).ok().filter(|&off| off < record.len()) else {
        return 0..0;
    };
    if max <= 0 {
        return 0..0;
    }
    let len = if len <= 0 || len > max { max } else { len };
    let Ok(len) = usize::try_from(len) else {
        return 0..0;
    };
    let text = record.get(off..).unwrap_or_default();
    let n = text.iter().take(len).position(|&c| c == 0);
    off..off + n.unwrap_or(len.min(text.len()))
}

/// `slot:cstring(off, len, max)`: the string cstring_span() finds.
unsafe extern "C-unwind" fn slot_cstring(l: *mut LuaState) -> c_int {
    // SAFETY: as in slot_u8().
    let mut s = unsafe { Stack::from_raw(l) };
    let span = {
        let record = check_slot(&s);
        let off = check_c_int(&s, 2);
        let len = if s.top() >= 3 { check_c_int(&s, 3) } else { 0 };
        let max = if s.top() >= 4 {
            check_c_int(&s, 4)
        } else {
            len
        };
        cstring_span(record, off, len, max)
    };
    let (held, mut above) = s.split();
    let record = slot_record(held.userdata(1).unwrap_or_default());
    above.push_bytes(record.get(span).unwrap_or_default());
    1
}

/// A page's numeric field, its fraction dropped: 0 unless it lies from 0
/// to the largest whole number a double holds exactly.
fn page_u64(s: &mut Stack<'_>, idx: c_int, field: &CStr) -> u64 {
    s.get_field(idx, field);
    let n = s.to_number(-1);
    s.pop(1);
    if n.is_finite() && (0.0..=MAX_EXACT).contains(&n) {
        n as u64
    } else {
        0
    }
}

/// Whether the value is a string, or a number that makes one.
fn is_text(t: LuaType) -> bool {
    matches!(t, LuaType::String | LuaType::Number)
}

/// The record at absolute index `abs` into the slots table at `slots`,
/// raising an error for an index past an int.
fn store_slot(s: &mut Stack<'_>, slots: c_int, abs: u64, record: &[u8]) {
    let Some(n) = c_int::try_from(abs).ok().and_then(|abs| abs.checked_add(1)) else {
        s.error(c"slot index too large");
    };
    push_slot(s, record);
    s.raw_set_index(slots, n);
}

/// A page's records into the slots table by their absolute index: the
/// serializer packs whole records into each chunk, so a record size that
/// does not divide the chunk leaves a gap at each chunk's end.
fn split_page_slots(
    s: &mut Stack<'_>,
    slots: c_int,
    data: &[u8],
    cursor: u64,
    chunks: u64,
    size: usize,
) {
    let per_chunk = CHUNK_PAYLOAD / size;
    if chunks > 1 && per_chunk > 0 && !CHUNK_PAYLOAD.is_multiple_of(size) {
        for (chunk, bytes) in (0..chunks).zip(data.chunks(CHUNK_PAYLOAD)) {
            for (i, record) in (0..).zip(bytes.chunks_exact(size).take(per_chunk)) {
                let page_slot = chunk * per_chunk as u64 + i;
                store_slot(s, slots, cursor.wrapping_add(page_slot), record);
            }
        }
        return;
    }
    for (i, record) in (0..).zip(data.chunks_exact(size)) {
        store_slot(s, slots, cursor.wrapping_add(i), record);
    }
}

/// A page's records in order: of each chunk, as many as the chunk holds
/// whole, up to the first chunk that holds none.
fn page_records(data: &[u8], chunks: u64, size: usize) -> impl Iterator<Item = &[u8]> {
    let (chunk, per_chunk) = if chunks > 1 {
        (CHUNK_PAYLOAD, CHUNK_PAYLOAD / size)
    } else {
        (data.len().max(1), usize::MAX)
    };
    data.chunks(chunk)
        .map_while(move |bytes| {
            let records = bytes.chunks_exact(size).take(per_chunk);
            (records.len() > 0).then_some(records)
        })
        .flatten()
}

/// `shirudo.page_slots(page, size)`: one page's records, in order.
unsafe extern "C-unwind" fn page_slots(l: *mut LuaState) -> c_int {
    // SAFETY: as in slot_u8().
    let mut s = unsafe { Stack::from_raw(l) };
    s.check_table(1);
    let size = check_c_int(&s, 2);
    let Some(size) = usize::try_from(size)
        .ok()
        .filter(|size| (1..=CHUNK_PAYLOAD).contains(size))
    else {
        s.error(c"invalid slot size");
    };
    let chunks = page_u64(&mut s, 1, c"chunks");
    s.get_field(1, c"data_hex");
    if !is_text(s.type_of(-1)) {
        s.pop(1);
        s.new_table();
        return 1;
    }
    let (held, mut above) = s.split();
    if !hex_decode_push(&mut above, held.to_bytes(-1).unwrap_or_default()) {
        above.error(c"invalid page data_hex");
    }
    let (data, mut above) = above.split();
    let data = data.userdata(-1).unwrap_or_default();
    above.new_table();
    for (n, record) in (1..=c_int::MAX).zip(page_records(data, chunks, size)) {
        push_slot(&mut above, record);
        above.raw_set_index(-2, n);
    }
    1
}

/// A decimal u64 string argument, raising an error for anything else.
fn check_u64_string(s: &Stack<'_>, arg: c_int) -> u64 {
    match crate::text::parse_u64(s.check_bytes(arg), u64::MAX) {
        Ok(v) => v,
        Err(err) if err == -ERANGE => s.arg_error(arg, c"u64 string out of range"),
        Err(_) => s.arg_error(arg, c"expected a decimal u64 string"),
    }
}

/// `shirudo.u64_add(a, b)`: exact, saturating; Lua numbers lose
/// nanoseconds.
unsafe extern "C-unwind" fn u64_add(l: *mut LuaState) -> c_int {
    // SAFETY: as in slot_u8().
    let mut s = unsafe { Stack::from_raw(l) };
    let a = check_u64_string(&s, 1);
    let b = check_u64_string(&s, 2);
    push_u64_string(&mut s, a.saturating_add(b));
    1
}

/// `shirudo.u64_sub(a, b)`: exact, at least 0.
unsafe extern "C-unwind" fn u64_sub(l: *mut LuaState) -> c_int {
    // SAFETY: as in slot_u8().
    let mut s = unsafe { Stack::from_raw(l) };
    let a = check_u64_string(&s, 1);
    let b = check_u64_string(&s, 2);
    push_u64_string(&mut s, a.saturating_sub(b));
    1
}

/// The little-endian u64 at byte `off` of the hex, 0 when it is not
/// there or not hex.
fn hex_word(hex: &[u8], off: c_int) -> u64 {
    let mut word = [0; 8];
    let digits = usize::try_from(off)
        .ok()
        .and_then(|off| hex.get(off.checked_mul(2)?..)?.get(..16));
    match digits.map(|digits| crate::util::hex::decode(digits, &mut word)) {
        Some(Ok(())) => u64::from_le_bytes(word),
        _ => 0,
    }
}

/// `shirudo.hex_u64(hex, off)`: hex_word() as a decimal string.
unsafe extern "C-unwind" fn hex_u64(l: *mut LuaState) -> c_int {
    // SAFETY: as in slot_u8().
    let mut s = unsafe { Stack::from_raw(l) };
    let off = check_c_int(&s, 2);
    let v = hex_word(s.check_bytes(1), off);
    push_u64_string(&mut s, v);
    1
}

/// Decodes the hex on top into a userdata pushed above it, and its
/// records into the slots table at `slots`: false, with nothing pushed,
/// for what is not hex.
fn add_page_slots(s: &mut Stack<'_>, slots: c_int, cursor: u64, chunks: u64, size: usize) -> bool {
    let (held, mut above) = s.split();
    if !hex_decode_push(&mut above, held.to_bytes(-1).unwrap_or_default()) {
        return false;
    }
    let (data, mut above) = above.split();
    let data = data.userdata(-1).unwrap_or_default();
    split_page_slots(&mut above, slots, data, cursor, chunks, size);
    true
}

/// `shirudo.fixed_records(pages, size)`: the records of every page by
/// their absolute index, from each page's cursor.
unsafe extern "C-unwind" fn fixed_records(l: *mut LuaState) -> c_int {
    // SAFETY: as in slot_u8().
    let mut s = unsafe { Stack::from_raw(l) };
    s.check_table(1);
    let size = check_c_int(&s, 2);
    let Some(size) = usize::try_from(size).ok().filter(|&size| size > 0) else {
        s.error(c"invalid slot size");
    };
    s.new_table();
    let slots = s.top();
    let pages = c_int::try_from(s.length(1)).unwrap_or(c_int::MAX);
    for i in 1..=pages {
        s.raw_get_index(1, i);
        if s.type_of(-1) != LuaType::Table {
            s.pop(1);
            continue;
        }
        let cursor = page_u64(&mut s, -1, c"cursor");
        let chunks = page_u64(&mut s, -1, c"chunks");
        s.get_field(-1, c"data_hex");
        if !is_text(s.type_of(-1)) {
            s.pop(2);
            continue;
        }
        if !add_page_slots(&mut s, slots, cursor, chunks, size) {
            s.pop(2);
            s.error(c"invalid page data_hex");
        }
        s.pop(3);
    }
    1
}

/// Pushes `v` as a decimal string, which a Lua number would round.
fn push_u64_string(s: &mut Stack<'_>, v: u64) {
    let mut digits = [0; 20];
    s.push_bytes(crate::text::decimal(v, &mut digits));
}

/// Pushes the bytes as lowercase hex, made in a userdata the collector
/// owns: a Lua error on an allocation would leak a buffer of our own.
fn push_hex(s: &mut Stack<'_>, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // The hex and a NUL.
    s.push_userdata_with(bytes.len() * 2 + 1, |hex| {
        for (pair, b) in hex.as_chunks_mut::<2>().0.iter_mut().zip(bytes) {
            pair.copy_from_slice(&[HEX[usize::from(b >> 4)], HEX[usize::from(b & 0xf)]]);
        }
    });
    {
        let (held, mut above) = s.split();
        above.push_bytes(cstr(held.userdata(-1).unwrap_or_default()));
    }
    s.remove(-2);
}

/// Sets field `key` of the table on top to `v`.
fn set_number(s: &mut Stack<'_>, key: &CStr, v: f64) {
    s.push_number(v);
    s.set_field(-2, key);
}

/// Sets field `key` of the table on top to `v`.
fn set_bool(s: &mut Stack<'_>, key: &CStr, v: bool) {
    s.push_bool(v);
    s.set_field(-2, key);
}

fn realtime_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| {
            d.as_secs()
                .wrapping_mul(1_000_000_000)
                .wrapping_add(u64::from(d.subsec_nanos()))
        })
}

/// The decoder's input, the map as raw bytes and its shape: the same
/// whether BTF can render it or not.
fn push_map_input(s: &mut Stack<'_>, v: &MapView) {
    let now = realtime_ns();
    let start = if v.lifetime_start_ns != 0 {
        v.lifetime_start_ns
    } else {
        now
    };
    s.new_table();
    s.push_integer(1);
    s.set_field(-2, c"schema");
    s.push_bytes(cstr(&v.upatch));
    s.set_field(-2, c"upatch");
    s.push_bytes(cstr(&v.name));
    s.set_field(-2, c"map");
    // OTLP wall-clock times, as decimal strings: a Lua number cannot
    // hold nanoseconds since the epoch.
    push_u64_string(s, start);
    s.set_field(-2, c"startTimeUnixNano");
    push_u64_string(s, now);
    s.set_field(-2, c"timeUnixNano");
    push_map_data(s, v);
    s.set_field(-2, c"data");
}

/// The input's `data`: the map's shape, its entries and its serialized
/// pages.
fn push_map_data(s: &mut Stack<'_>, v: &MapView) {
    s.new_table();
    s.push_bytes(cstr(&v.name));
    s.set_field(-2, c"name");
    s.push_bytes(v.type_name.unwrap_or(c"").to_bytes());
    s.set_field(-2, c"type");
    set_number(s, c"max_entries", f64::from(v.max_entries));
    set_number(s, c"n_entries", f64::from(v.n_entries()));
    set_bool(s, c"serialized", v.serialized);
    set_number(s, c"serialized_pages", f64::from(v.n_serial_pages()));
    set_number(s, c"serialized_bytes", v.serial_bytes_total as f64);
    set_number(s, c"key_size", f64::from(v.key_size));
    set_number(s, c"value_size", f64::from(v.value_size));
    set_number(s, c"n_cpus", f64::from(v.n_cpus));
    set_bool(s, c"truncated", v.truncated);
    push_entries(s, v);
    s.set_field(-2, c"entries");
    push_pages(s, v);
    s.set_field(-2, c"pages");
}

/// The entries of the view, each its key and its value on every CPU as
/// hex.
fn push_entries(s: &mut Stack<'_>, v: &MapView) {
    s.new_table();
    for (n, entry) in (1..=c_int::MAX).zip(&v.entries) {
        s.new_table();
        push_hex(s, &entry.key);
        s.set_field(-2, c"key_hex");
        push_hex(s, &entry.value);
        s.set_field(-2, c"value_hex");
        s.raw_set_index(-2, n);
    }
}

/// The serialized pages of the view, each its place, its cursors and
/// flags, and its bytes as hex.
fn push_pages(s: &mut Stack<'_>, v: &MapView) {
    s.new_table();
    for (n, page) in (1..=c_int::MAX).zip(&v.serial_pages) {
        s.new_table();
        set_number(s, c"page_index", f64::from(page.page_index));
        set_number(s, c"cursor", page.cursor as f64);
        set_number(s, c"next_cursor", page.next_cursor as f64);
        set_bool(s, c"done", page.done);
        set_number(s, c"flags", f64::from(page.flags));
        set_number(s, c"chunks", f64::from(page.chunks));
        set_number(s, c"bytes", f64::from(page.bytes()));
        push_hex(s, &page.data);
        s.set_field(-2, c"data_hex");
        s.raw_set_index(-2, n);
    }
}

/// The decoder's entrypoint: a function of the table its chunk returned,
/// the function it returned, or a global of the name.
fn get_entrypoint(s: &mut Stack<'_>, entrypoint: &CStr) -> bool {
    if s.type_of(-1) == LuaType::Table {
        s.get_field(-1, entrypoint);
        if s.type_of(-1) == LuaType::Function {
            s.remove(-2);
            return true;
        }
        s.pop(1);
    }
    if s.type_of(-1) == LuaType::Function {
        return true;
    }
    s.pop(1);
    s.get_global(entrypoint);
    s.type_of(-1) == LuaType::Function
}

/// What the closure a decoder runs in reads and writes.
struct Call<'a, 'b> {
    view: &'a MapView,
    entrypoint: &'a CStr,
    e: &'a mut JsonEmit<'b>,
    otel: bool,
    found: bool,
}

/// The closure the decoder runs in: its entrypoint, found from what its
/// chunk returned, upvalue 2, called with the input of the view of the
/// call, upvalue 1. The lookup, which may run the decoder's metamethods,
/// and the encoding of the result, which may run out of memory, are
/// under the same pcall: an error raised past it ends the process.
unsafe extern "C-unwind" fn call_decoder(l: *mut LuaState) -> c_int {
    // SAFETY: LuaJIT called this C function with the state, and this is
    // the one Stack of its frame.
    let mut s = unsafe { Stack::from_raw(l) };
    // SAFETY: the frame is this C closure's.
    let call = unsafe { s.upvalue_pointer(1) }.cast::<Call<'_, '_>>();
    // SAFETY: decode() made the closure with its call there, which lives
    // across the pcall that runs this and is not used meanwhile.
    let call = unsafe { &mut *call };
    // SAFETY: the frame is this C closure's.
    unsafe { s.push_upvalue(2) };
    call.found = get_entrypoint(&mut s, call.entrypoint);
    if !call.found {
        return 0;
    }
    push_map_input(&mut s, call.view);
    s.call(1, 1);
    if call.otel {
        otel_value(&mut s, -1, call.e, 0);
    } else {
        json_value(&mut s, -1, call.e, 0);
    }
    0
}

fn log_err(text: &[u8]) {
    let text = CString::new(
        text.iter()
            .copied()
            .filter(|&c| c != 0)
            .collect::<Vec<u8>>(),
    )
    .unwrap_or_default();
    crate::log::err(text.to_bytes());
}

/// The error on top of the stack, under `what`. The message is the
/// decoder's and may carry what a map recorded, so it is cut to 255 bytes
/// and its control characters replaced; a number is not shown.
fn report(s: &Stack<'_>, what: &str) {
    let message = (s.type_of(-1) == LuaType::String)
        .then(|| s.to_bytes(-1))
        .flatten()
        .unwrap_or(b"unknown Lua error");
    let message = cstr(message);
    let mut shown = message.get(..255).unwrap_or(message).to_vec();
    crate::text::sanitize(&mut shown, false);
    log_err(&[b"upatch map: ", what.as_bytes(), b": ", &shown].concat());
}

thread_local! {
    /// The instruction budget of the decoder running, in hook calls.
    static BUDGET: Cell<c_int> = const { Cell::new(0) };
}

unsafe extern "C-unwind" fn budget_hook(l: *mut LuaState, _ar: *mut LuaDebug) {
    let left = BUDGET.with(|b| {
        b.set(b.get() - 1);
        b.get()
    });
    if left <= 0 {
        // SAFETY: LuaJIT called this hook with the state, and this is the
        // one Stack of its frame.
        let mut s = unsafe { Stack::from_raw(l) };
        // pcall() catches the error, so once the budget is spent every
        // instruction raises it again: no protected call runs past it.
        // SAFETY: the hook needs no more than the state LuaJIT hooks.
        unsafe { s.set_hook(budget_hook, LUA_MASKCOUNT, 1) };
        s.error(c"decoder instruction limit exceeded");
    }
}

/// Sets the host functions as fields of the table on top.
fn set_functions(s: &mut Stack<'_>, fns: &[(&CStr, LuaCFunction)]) {
    for &(name, f) in fns {
        // SAFETY: a host function needs no more than the state Lua calls
        // it with, and checks its arguments.
        unsafe { s.push_function(f) };
        s.set_field(-2, name);
    }
}

/// The host API: the slot methods and the `shirudo` table, with the
/// globals that reach outside the sandbox or past its budget removed.
/// LuaJIT runs a finalizer with hooks off, so newproxy(), which makes a
/// userdata that takes one, would run code past the budget, and so does
/// the handler xpcall() calls for the error the budget hook raises, from
/// inside the hook. A pattern match is one C call the count hook never
/// interrupts, and backtracks for as long as the subject, a string a map
/// recorded, makes it. print() writes where --json does.
fn install_host_api(s: &mut Stack<'_>) {
    const DENY: [&CStr; 16] = [
        c"io",
        c"os",
        c"package",
        c"require",
        c"debug",
        c"jit",
        c"ffi",
        c"dofile",
        c"loadfile",
        c"load",
        c"loadstring",
        c"module",
        c"collectgarbage",
        c"newproxy",
        c"xpcall",
        c"print",
    ];
    const PATTERNS: [&CStr; 4] = [c"find", c"match", c"gmatch", c"gsub"];
    for name in DENY {
        s.push_nil();
        s.set_global(name);
    }
    s.get_global(c"string");
    for name in PATTERNS {
        s.push_nil();
        s.set_field(-2, name);
    }
    s.pop(1);
    s.new_metatable(SLOT_MT);
    s.new_table();
    set_functions(
        s,
        &[
            (c"u8", slot_u8),
            (c"u16", slot_u16),
            (c"u32", slot_u32),
            (c"u64", slot_u64),
            (c"cstring", slot_cstring),
        ],
    );
    s.set_field(-2, c"__index");
    // A __gc a decoder added to it would run with hooks off.
    s.push_bytes(SLOT_MT.to_bytes());
    s.set_field(-2, c"__metatable");
    s.pop(1);
    s.new_table();
    set_functions(
        s,
        &[
            (c"fixed_records", fixed_records),
            (c"page_slots", page_slots),
            (c"u64_add", u64_add),
            (c"u64_sub", u64_sub),
            (c"hex_u64", hex_u64),
        ],
    );
    s.set_global(c"shirudo");
}

/// Opens the standard libraries, turns the JIT off and installs the
/// host API: -EINVAL when the JIT stays on.
fn open_sandbox(s: &mut Stack<'_>) -> Result<(), c_int> {
    s.open_libs();
    // Instruction hooks must see every instruction: no traces.
    if !s.jit_off() {
        return Err(-EINVAL);
    }
    install_host_api(s);
    Ok(())
}

/// Loads the decoder and calls its entrypoint on the view, the result
/// encoded into `e`: -EINVAL when the decoder fails, -ENOENT without its
/// entrypoint, or the encoder's error, each logged.
fn decode(
    s: &mut Stack<'_>,
    d: &DecoderView,
    v: &MapView,
    otel: bool,
    e: &mut JsonEmit,
) -> Result<(), c_int> {
    let source_name = CString::new(cstr(&d.source_name)).unwrap_or_default();
    let entrypoint = CString::new(cstr(&d.entrypoint)).unwrap_or_default();
    // LuaJIT checks no bytecode it loads: a decoder is source text.
    if !s.load(d.source, &source_name, c"t") || !s.pcall(0, 1) {
        report(s, "decoder load failed");
        return Err(-EINVAL);
    }
    let mut call = Call {
        view: v,
        entrypoint: &entrypoint,
        e,
        otel,
        found: false,
    };
    s.push_pointer(&mut call);
    s.push_value(-2);
    // SAFETY: call_decoder() finds the call, which lives across the pcall
    // below, in its first upvalue, and what the chunk returned in its
    // second.
    unsafe { s.push_closure(call_decoder, 2) };
    s.remove(-2);
    if !s.pcall(0, 0) {
        report(s, "decoder failed");
        return Err(-EINVAL);
    }
    if !call.found {
        log_err(
            &[
                &b"upatch map: decoder entrypoint '"[..],
                entrypoint.to_bytes(),
                b"' not found",
            ]
            .concat(),
        );
        return Err(-ENOENT);
    }
    match call.e.err() {
        0 => Ok(()),
        err => {
            log_err(format!("upatch map: decoder encode failed: {}", text(err)).as_bytes());
            Err(err)
        }
    }
}

/// Runs the decoder on the view: the JSON, or the AnyValue with `otel`,
/// of what it returns, at most `max` bytes.
pub(crate) fn run(d: &DecoderView, v: &MapView, otel: bool, max: usize) -> Result<Vec<u8>, c_int> {
    let native = Lua::new()?;
    let mut memory = Memory {
        inner: native.allocator(),
        used: 0,
    };
    // SAFETY: limited_alloc() takes the memory record it is handed, which
    // the state borrows until it closes, as the record borrows the native
    // state whose allocator it hands out.
    let mut lua = unsafe { Lua::with_allocator(limited_alloc, &mut memory) }?;
    let mut s = lua.stack();
    open_sandbox(&mut s)?;
    BUDGET.with(|b| b.set(INSN_LIMIT / HOOK_COUNT));
    // SAFETY: the hook needs no more than the state LuaJIT hooks.
    unsafe { s.set_hook(budget_hook, LUA_MASKCOUNT, HOOK_COUNT) };
    let mut e = JsonEmit::growing(max);
    decode(&mut s, d, v, otel, &mut e)?;
    e.finish()
}

/// Whether the decoder is a Lua one of API 1 on map input, exporting a
/// log or metrics, for this map.
fn matches(d: &DecoderView, v: &MapView) -> bool {
    // The map alone picks the decoder: the archive it comes from is the
    // upatch these maps belong to, by the payload the pin directory
    // recorded, and its signature covers the decoders. The decoder's
    // upatch field holds 63 of the 255 characters a name may have, or
    // nothing.
    d.language == LANG_LUA
        && d.api_version == 1
        && d.input_format == INPUT_MAP_V1
        && (d.export_signal == EXPORT_LOG || d.export_signal == EXPORT_METRIC)
        && cstr(&d.map) == cstr(&v.name)
}

/// The artifact the decoders come from, opened as sealed state when it
/// is the archive's: an entry there that is not shirudo's own is refused
/// rather than run, signed or not, and so is an archive whose bytes are
/// not the payload the pin directory says was loaded.
fn open_artifact(path: &CStr, archived: bool, v: &MapView) -> Result<Upatch<'static>, c_int> {
    let u = if archived {
        Upatch::read(&File::from(seal::open_read(path.to_bytes())?))?
    } else {
        Upatch::open(path)?
    };
    if archived {
        let loaded = payload_digest(&u).map(|digest| {
            v.has_payload
                && !memneq_explicit(&digest, &v.payload)
                && !memneq_explicit(&u.hdr.payload_sha256, &v.payload)
        })?;
        if !loaded {
            log_err(
                &[
                    &b"upatch map: the archive of "[..],
                    cstr(&v.upatch),
                    b" is not the upatch loaded; its decoders do not run",
                ]
                .concat(),
            );
            return Err(-ESTALE);
        }
    }
    Ok(u)
}

/// The decoders of the open artifact, each as a view, the bad ones left
/// out.
fn decoders<'a>(u: &'a Upatch<'_>) -> impl Iterator<Item = DecoderView<'a>> + 'a {
    u.decoders().filter_map(|d| DecoderView::of(&d))
}

fn decode_open(
    path: &CStr,
    archived: bool,
    v: &MapView,
    otel: bool,
    max: usize,
) -> Result<Vec<u8>, c_int> {
    if !upatch::name_valid(Some(cstr(&v.upatch))) {
        return Err(-EINVAL);
    }
    let u = open_artifact(path, archived, v)?;
    match decoders(&u).find(|d| matches(d, v)) {
        Some(d) => run(&d, v, otel, max),
        None => Err(-ENODATA),
    }
}

fn archive_path(v: &MapView) -> Result<CString, c_int> {
    let path = [UPATCHES_DIR.as_bytes(), b"/", cstr(&v.upatch), b".upatch"].concat();
    if path.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    CString::new(path).map_err(|_| -EINVAL)
}

/// What the decoder makes of the view `v`, at most `max` bytes of it:
/// the signed one in its upatch's archive, or the artifact's at
/// `artifact`; as JSON, or with `otel` as an OTLP AnyValue. -ENODATA
/// without a decoder for the map, or -errno.
pub(crate) fn decode_map(
    v: &MapView,
    artifact: Option<&CStr>,
    otel: bool,
    max: usize,
) -> Result<Vec<u8>, c_int> {
    if max == 0 {
        return Err(-EINVAL);
    }
    match artifact {
        None => decode_open(&archive_path(v)?, true, v, otel, max),
        Some(path) => decode_open(path, false, v, otel, max),
    }
}

/// What the decoder in the upatch's archive makes of the map, as JSON.
pub(crate) fn map_json(v: &MapView) -> Result<Vec<u8>, c_int> {
    decode_map(v, None, false, JSON_MAX)
}

/// The signal the map's decoder exports, from the upatch's archive.
pub(crate) fn signal(v: &MapView) -> Result<u32, c_int> {
    if !upatch::name_valid(Some(cstr(&v.upatch))) {
        return Err(-EINVAL);
    }
    let path = archive_path(v)?;
    let u = open_artifact(&path, true, v)?;
    decoders(&u)
        .find(|d| matches(d, v))
        .map(|d| d.export_signal)
        .ok_or(-ENODATA)
}

#[cfg(shirudo_fuzz)]
mod fuzz;
#[cfg(test)]
mod tests;
