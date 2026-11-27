// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Reading the maps a loaded upatch pins. A map is read generically, an
//! array by index and a hash by its keys, or through the serializer the
//! upatch pins beside it. A serializer is a BPF program that BPF_PROG_TEST_RUN
//! runs a page at a time, writing chunks to the upatch's output map. The
//! maps of one upatch or of all are listed.

use core::ffi::{CStr, c_int, c_long};
use core::sync::atomic::{AtomicU32, Ordering};
use std::ffi::OsStr;
use std::fs;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

use crate::bpf::btf::Btf;
use crate::errno::{
    E2BIG, EBADMSG, EINVAL, EIO, ENAMETOOLONG, ENOENT, ENOMEM, EOPNOTSUPP, EOVERFLOW,
};
use crate::sys::libc::{Zeroed, errno, syscall};
use crate::text::strscpy;
use crate::util::bpf_info::{Info, MAP_INFO_SIZE};
use crate::util::bpf_sys::{
    BPF_ANY, bpf_map_get_next_key, bpf_map_lookup_elem, bpf_map_update_elem, obj_get, prog_test_run,
};
use crate::util::kernel_btf;
use crate::util::map_format::{is_percpu, type_def, type_name, value_stride};
use crate::util::serializer::{SERIAL_CHUNK_PAYLOAD, SERIAL_MAGIC, SERIAL_VERSION};
use crate::util::serializer::{SerialChunk, chunk_validate, new_invocation_id};
use crate::util::upatch::name_from_pin;
use crate::util::upatch_pins::pin_payload;
use crate::util::upatch_resolve::{BPFFS_UPATCHES_DIR, pin_path, resolve_location};

/// UPATCH_NAME_MAX, MAP_NAME_MAX, UPATCH_LOCATION_MAX, MAP_TYPENAME_MAX
/// and MAP_TYPEDEF_MAX.
const UPATCH_NAME_MAX: usize = 256;
const MAP_NAME_MAX: usize = 16;
const UPATCH_LOCATION_MAX: usize = 160;
const MAP_TYPENAME_MAX: usize = 64;
const MAP_TYPEDEF_MAX: usize = 1024;

/// The entries a read returns unless asked for all, which 0 asks.
pub(crate) const MAP_ENTRIES_DEFAULT: u32 = 256;
/// Reads a serializer's interval without taking it from the exporter.
pub(crate) const MAP_READ_PEEK: u32 = 1 << 0;

/// A key and its value, or its values per CPU a value stride apart, as
/// a read copied them.
pub(crate) struct MapEntry {
    pub(crate) key: Vec<u8>,
    pub(crate) value: Vec<u8>,
}

/// One page a serializer handed over.
pub(crate) struct SerialPage {
    pub(crate) page_index: u32,
    pub(crate) cursor: u64,
    pub(crate) next_cursor: u64,
    pub(crate) flags: u32,
    pub(crate) chunks: u32,
    pub(crate) done: bool,
    pub(crate) data: Vec<u8>,
}

impl SerialPage {
    /// The bytes the page holds, which a read bounds well below 4 GiB.
    pub(crate) fn bytes(&self) -> u32 {
        u32::try_from(self.data.len()).unwrap_or(u32::MAX)
    }
}

/// One map's contents, as read() reads them.
pub(crate) struct MapView {
    pub(crate) upatch: [u8; UPATCH_NAME_MAX + 1],
    pub(crate) name: [u8; MAP_NAME_MAX + 1],
    pub(crate) location: [u8; UPATCH_LOCATION_MAX],
    pub(crate) ty: u32,
    pub(crate) type_name: Option<&'static CStr>,
    pub(crate) key_size: u32,
    pub(crate) value_size: u32,
    pub(crate) value_stride: u32,
    pub(crate) max_entries: u32,
    pub(crate) n_cpus: u32,
    pub(crate) lifetime_start_ns: u64,
    /// The pin directory's payload digest, when it has one.
    pub(crate) has_payload: bool,
    pub(crate) payload: [u8; 32],
    pub(crate) truncated: bool,
    pub(crate) n_truncated_at: u32,
    pub(crate) serialized: bool,
    pub(crate) serial_bytes_total: u64,
    pub(crate) serial_pages: Vec<SerialPage>,
    pub(crate) skipped: bool,
    pub(crate) skipped_reason: Option<&'static CStr>,
    pub(crate) btf_key_type: [u8; MAP_TYPENAME_MAX],
    pub(crate) btf_value_type: [u8; MAP_TYPENAME_MAX],
    pub(crate) key_type_def: [u8; MAP_TYPEDEF_MAX],
    pub(crate) value_type_def: [u8; MAP_TYPEDEF_MAX],
    pub(crate) key_type_id: u32,
    pub(crate) value_type_id: u32,
    pub(crate) btf: Option<Btf>,
    pub(crate) entries: Vec<MapEntry>,
}

/// The view of no map, which a read or a test fills in.
impl Default for MapView {
    fn default() -> Self {
        MapView {
            upatch: [0; UPATCH_NAME_MAX + 1],
            name: [0; MAP_NAME_MAX + 1],
            location: [0; UPATCH_LOCATION_MAX],
            ty: 0,
            type_name: None,
            key_size: 0,
            value_size: 0,
            value_stride: 0,
            max_entries: 0,
            n_cpus: 0,
            lifetime_start_ns: 0,
            has_payload: false,
            payload: [0; 32],
            truncated: false,
            n_truncated_at: 0,
            serialized: false,
            serial_bytes_total: 0,
            serial_pages: Vec::new(),
            skipped: false,
            skipped_reason: None,
            btf_key_type: [0; MAP_TYPENAME_MAX],
            btf_value_type: [0; MAP_TYPENAME_MAX],
            key_type_def: [0; MAP_TYPEDEF_MAX],
            value_type_def: [0; MAP_TYPEDEF_MAX],
            key_type_id: 0,
            value_type_id: 0,
            btf: None,
            entries: Vec::new(),
        }
    }
}

impl MapView {
    /// The entries read, as many as a map's u32 count can say.
    pub(crate) fn n_entries(&self) -> u32 {
        u32::try_from(self.entries.len()).unwrap_or(u32::MAX)
    }

    /// The serialized pages read, at most SERIAL_MAX_PAGES.
    pub(crate) fn n_serial_pages(&self) -> u32 {
        u32::try_from(self.serial_pages.len()).unwrap_or(u32::MAX)
    }
}

/// A map an upatch pins, as list() gives it.
pub(crate) struct MapSummary {
    pub(crate) upatch: [u8; UPATCH_NAME_MAX + 1],
    pub(crate) name: [u8; MAP_NAME_MAX + 1],
    pub(crate) type_name: Option<&'static CStr>,
    pub(crate) max_entries: u32,
    pub(crate) n_cpus: u32,
}

/// The summary of no map, which a listing fills in.
impl Default for MapSummary {
    fn default() -> Self {
        MapSummary {
            upatch: [0; UPATCH_NAME_MAX + 1],
            name: [0; MAP_NAME_MAX + 1],
            type_name: None,
            max_entries: 0,
            n_cpus: 0,
        }
    }
}

/// What bpf/lib/serializer.h fixes of the serializer protocol.
const SERIAL_MAP_NAME: &[u8] = b"shirudo_ser";
const SERIAL_MAX_CHUNKS: u32 = 256;
const SERIAL_MAX_PAGES: u32 = 256;
const SERIAL_F_DONE: u32 = 1;
const SERIAL_CTX_F_PEEK: u32 = 1;
const SERIAL_MAX_BYTES: u32 = SERIAL_MAX_CHUNKS * SERIAL_CHUNK_PAYLOAD;
const SERIAL_MAX_TOTAL_BYTES: u64 = SERIAL_MAX_PAGES as u64 * SERIAL_MAX_BYTES as u64;

/// BPF_MAP_TYPE_* the reader tells apart.
const HASH: u32 = 1;
const ARRAY: u32 = 2;
const PROG_ARRAY: u32 = 3;
const PERF_EVENT_ARRAY: u32 = 4;
const PERCPU_HASH: u32 = 5;
const PERCPU_ARRAY: u32 = 6;
const STACK_TRACE: u32 = 7;
const LRU_HASH: u32 = 9;
const LRU_PERCPU_HASH: u32 = 10;
const RINGBUF: u32 = 27;
const ARENA: u32 = 33;

/// `struct bpf_map_info`: where the fields read here sit.
const MAP_TYPE: usize = 0;
const MAP_ID: usize = 4;
const MAP_KEY_SIZE: usize = 8;
const MAP_VALUE_SIZE: usize = 12;
const MAP_MAX_ENTRIES: usize = 16;
const MAP_BTF_ID: usize = 64;
const MAP_BTF_KEY_TYPE_ID: usize = 68;
const MAP_BTF_VALUE_TYPE_ID: usize = 72;

/// The name status and the table give BPF_MAP_TYPE_* `ty`.
pub(crate) fn map_type_name(ty: u32) -> &'static CStr {
    match ty {
        ARRAY => c"array",
        PERCPU_ARRAY => c"percpu_array",
        HASH => c"hash",
        PERCPU_HASH => c"percpu_hash",
        LRU_HASH => c"lru_hash",
        LRU_PERCPU_HASH => c"lru_percpu_hash",
        RINGBUF => c"ringbuf",
        PERF_EVENT_ARRAY => c"perf_event_array",
        STACK_TRACE => c"stack_trace",
        PROG_ARRAY => c"prog_array",
        ARENA => c"arena",
        _ => c"unknown",
    }
}

/// Why a map of type `ty` is not read generically, if it is not.
pub(crate) fn map_skip_reason(ty: u32) -> Option<&'static CStr> {
    match ty {
        RINGBUF => Some(c"use `shirudo upatch ringbuf` (future work)"),
        PERF_EVENT_ARRAY => Some(c"perf-event-array: use `shirudo upatch perfbuf` (future work)"),
        STACK_TRACE => Some(c"stack-trace: use `shirudo upatch stacktrace` (future work)"),
        PROG_ARRAY => Some(c"prog-array carries function pointers; not dumpable"),
        ARENA => Some(c"arena map contents require a serializer"),
        _ => None,
    }
}

/// The bytes a CPU's value takes in a lookup, rounded to 8 per CPU;
/// none for a size that rounds past a u32.
fn stride_of(ty: u32, value_size: u32) -> Option<u32> {
    if is_percpu(ty) {
        value_size.checked_next_multiple_of(8)
    } else {
        Some(value_size)
    }
}

fn is_array(ty: u32) -> bool {
    ty == ARRAY || ty == PERCPU_ARRAY
}

fn is_hash(ty: u32) -> bool {
    matches!(ty, HASH | PERCPU_HASH | LRU_HASH | LRU_PERCPU_HASH)
}

/// The CPUs a per-CPU lookup copies a value for. The kernel keeps the
/// count to itself: sysconf counts the present ones, and the sysfs file
/// libbpf would read is root's to replace in a mount namespace of its
/// own, so either undersizes the buffer the kernel fills. The shortest
/// mask sched_getaffinity accepts is the kernel's own cpumask,
/// nr_cpu_ids bits rounded up, and bounds what a lookup writes.
fn nproc_possible() -> Result<u32, c_int> {
    static CACHED: AtomicU32 = AtomicU32::new(0);
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 0 {
        return Ok(cached);
    }
    let mut mask = [0u8; 1024];
    let mut len = 8;
    while len <= mask.len() {
        match affinity_mask(&mut mask[..len]) {
            Ok(bytes) => {
                let cpus = u32::try_from(bytes * 8).map_err(|_| -E2BIG)?;
                CACHED.store(cpus, Ordering::Relaxed);
                return Ok(cpus);
            }
            Err(e) if e == -EINVAL => len *= 2,
            Err(e) => return Err(e),
        }
    }
    Err(-E2BIG)
}

/// The bytes of this task's CPU mask that sched_getaffinity() writes
/// into `mask`, at most its length: -EINVAL when the kernel's mask is
/// longer.
fn affinity_mask(mask: &mut [u8]) -> Result<usize, c_int> {
    let len = c_long::try_from(mask.len()).map_err(|_| -EINVAL)?;
    // SAFETY: the raw syscall, with room for the mask's bytes.
    let n = unsafe {
        syscall(
            libc::SYS_sched_getaffinity,
            0 as c_long,
            len,
            mask.as_mut_ptr(),
        )
    };
    match usize::try_from(n) {
        Ok(bytes) if bytes > 0 => Ok(bytes.min(mask.len())),
        _ => Err(-errno()),
    }
}

fn os(b: &[u8]) -> &OsStr {
    OsStr::from_bytes(b)
}

/// The pin of map `map` of upatch `upatch`, opened, and its info.
fn open_map_pin(upatch: &[u8], map: &[u8]) -> Result<(OwnedFd, Info<MAP_INFO_SIZE>), c_int> {
    let fd = obj_get(&pin_path(upatch, &[b"maps", map])?)?;
    let mut info = Info::<MAP_INFO_SIZE>::new();
    info.read(fd.as_raw_fd())?;
    Ok((fd, info))
}

/// The serializer upatch `upatch` pins for map `map`, opened.
fn open_serializer_pin(upatch: &[u8], map: &[u8]) -> Result<OwnedFd, c_int> {
    obj_get(&pin_path(upatch, &[b"serializers", map])?)
}

/// A map open for reads, and the sizes of its keys and of the values a
/// lookup writes, which every call on it is held to.
struct Map<'fd> {
    fd: BorrowedFd<'fd>,
    key_size: usize,
    value_size: usize,
}

impl<'fd> Map<'fd> {
    /// The map at `fd` as view `v` reads its entries: keys of the key
    /// size, and values of the value stride for each of the n_cpus CPUs
    /// of a per-CPU map, at least as many as a lookup fills.
    fn entries_of(fd: BorrowedFd<'fd>, v: &MapView) -> Result<Self, c_int> {
        let cpus = if is_percpu(v.ty) {
            v.n_cpus as usize
        } else {
            1
        };
        Ok(Map {
            fd,
            key_size: v.key_size as usize,
            value_size: (value_stride(v) as usize)
                .checked_mul(cpus)
                .ok_or(-EOVERFLOW)?,
        })
    }

    /// The serializers' output map at `fd`, as its info must describe it:
    /// an array of 4-byte keys and chunk values, of at most
    /// SERIAL_MAX_CHUNKS entries.
    fn serial_output(fd: BorrowedFd<'fd>, info: &Info<MAP_INFO_SIZE>) -> Result<Self, c_int> {
        if info.u32_at(MAP_TYPE) != ARRAY
            || info.u32_at(MAP_KEY_SIZE) != 4
            || info.u32_at(MAP_VALUE_SIZE) as usize != size_of::<SerialChunk>()
        {
            return Err(-EINVAL);
        }
        let max = info.u32_at(MAP_MAX_ENTRIES);
        if max == 0 || max > SERIAL_MAX_CHUNKS {
            return Err(-E2BIG);
        }
        Ok(Map {
            fd,
            key_size: 4,
            value_size: size_of::<SerialChunk>(),
        })
    }

    /// -EINVAL unless `key` and `value` are of the map's sizes.
    fn sized(&self, key: &[u8], value: &[u8]) -> Result<(), c_int> {
        if key.len() != self.key_size || value.len() != self.value_size {
            return Err(-EINVAL);
        }
        Ok(())
    }

    /// The value of `key`, into `value`.
    fn lookup(&self, key: &[u8], value: &mut [u8]) -> Result<(), c_int> {
        self.sized(key, value)?;
        // SAFETY: a key and room for a value of the sizes the map reads
        // and writes.
        match unsafe {
            bpf_map_lookup_elem(
                self.fd.as_raw_fd(),
                key.as_ptr().cast(),
                value.as_mut_ptr().cast(),
            )
        } {
            0 => Ok(()),
            e => Err(e),
        }
    }

    /// Sets `key` to `value`.
    fn update(&self, key: &[u8], value: &[u8]) -> Result<(), c_int> {
        self.sized(key, value)?;
        // SAFETY: a key and a value of the sizes the map reads.
        match unsafe {
            bpf_map_update_elem(
                self.fd.as_raw_fd(),
                key.as_ptr().cast(),
                value.as_ptr().cast(),
                BPF_ANY,
            )
        } {
            0 => Ok(()),
            e => Err(e),
        }
    }

    /// Moves `key` on to the key after it, or to the first with `first`:
    /// -ENOENT past the last.
    fn next_key(&self, key: &mut [u8], first: bool) -> Result<(), c_int> {
        if key.len() != self.key_size {
            return Err(-EINVAL);
        }
        let next = key.as_mut_ptr();
        let prev = if first {
            core::ptr::null()
        } else {
            next.cast_const()
        };
        // SAFETY: the key before, or NULL for the first, and room for the
        // next, of the map's key size; the kernel copies the key before in
        // and only then writes the next.
        match unsafe { bpf_map_get_next_key(self.fd.as_raw_fd(), prev.cast(), next.cast()) } {
            0 => Ok(()),
            e => Err(e),
        }
    }
}

/// Zeroes every chunk of the output map before a run.
fn clear_serial_map(output: &Map<'_>, max_entries: u32) -> Result<(), c_int> {
    let zero = vec![0u8; output.value_size];
    for index in 0..max_entries {
        output.update(&index.to_ne_bytes(), &zero)?;
    }
    Ok(())
}

/// The page the serializer wrote: its chunks checked against each other
/// and the request, their payloads joined.
fn read_serial_page(
    output: &Map<'_>,
    max_entries: u32,
    want_page: u32,
    want_cursor: u64,
    invocation_id: u64,
) -> Result<SerialPage, c_int> {
    let mut chunk = Box::new(SerialChunk::zeroed());
    output.lookup(&0u32.to_ne_bytes(), chunk.bytes_mut())?;
    if chunk.magic != SERIAL_MAGIC
        || chunk.version != SERIAL_VERSION
        || chunk.invocation_id != invocation_id
    {
        return Err(-EBADMSG);
    }
    if chunk.status != 0 {
        return Err(if chunk.status < 0 { chunk.status } else { -EIO });
    }
    let (total, bytes_total) = (chunk.total_chunks, chunk.bytes_total);
    let (page_index, cursor, next_cursor, flags) = (
        chunk.page_index,
        chunk.cursor,
        chunk.next_cursor,
        chunk.flags,
    );
    if total == 0
        || total > max_entries
        || total > SERIAL_MAX_CHUNKS
        || bytes_total > SERIAL_MAX_BYTES
        || bytes_total > total.wrapping_mul(SERIAL_CHUNK_PAYLOAD)
    {
        return Err(-EBADMSG);
    }
    if page_index != want_page || cursor != want_cursor || next_cursor < cursor {
        return Err(-EBADMSG);
    }
    let mut data = Vec::with_capacity(bytes_total as usize);
    for key in 0..total {
        if key != 0 {
            output.lookup(&key.to_ne_bytes(), chunk.bytes_mut())?;
        }
        chunk_validate(
            &chunk,
            key,
            total,
            page_index,
            cursor,
            next_cursor,
            invocation_id,
        )?;
        if chunk.status != 0 {
            return Err(if chunk.status < 0 { chunk.status } else { -EIO });
        }
        let n = chunk.bytes_in_chunk;
        if chunk.bytes_total != bytes_total
            || data.len() as u64 + u64::from(n) > u64::from(bytes_total)
        {
            return Err(-EBADMSG);
        }
        data.extend_from_slice(&chunk.data[..n as usize]);
    }
    if data.len() != bytes_total as usize {
        return Err(-EBADMSG);
    }
    Ok(SerialPage {
        page_index,
        cursor,
        next_cursor,
        flags,
        chunks: total,
        done: flags & SERIAL_F_DONE != 0,
        data,
    })
}

/// `struct serialize_ctx` of bpf/lib/serializer.h, which a test run
/// hands the serializer and the kernel writes back.
struct SerializeCtx {
    magic: u32,
    version: u32,
    flags: u32,
    max_chunks: u32,
    chunk_payload_size: u32,
    page_index: u32,
    cursor: u64,
    invocation_id: u64,
}

impl SerializeCtx {
    /// The structure's bytes, its fields one after the other.
    fn to_bytes(&self) -> Vec<u8> {
        [
            &self.magic.to_ne_bytes()[..],
            &self.version.to_ne_bytes(),
            &self.flags.to_ne_bytes(),
            &self.max_chunks.to_ne_bytes(),
            &self.chunk_payload_size.to_ne_bytes(),
            &self.page_index.to_ne_bytes(),
            &self.cursor.to_ne_bytes(),
            &self.invocation_id.to_ne_bytes(),
        ]
        .concat()
    }

    /// The structure `bytes` hold, none when they are too few.
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (magic, rest) = bytes.split_first_chunk()?;
        let (version, rest) = rest.split_first_chunk()?;
        let (flags, rest) = rest.split_first_chunk()?;
        let (max_chunks, rest) = rest.split_first_chunk()?;
        let (chunk_payload_size, rest) = rest.split_first_chunk()?;
        let (page_index, rest) = rest.split_first_chunk()?;
        let (cursor, rest) = rest.split_first_chunk()?;
        let (invocation_id, _) = rest.split_first_chunk()?;
        Some(SerializeCtx {
            magic: u32::from_ne_bytes(*magic),
            version: u32::from_ne_bytes(*version),
            flags: u32::from_ne_bytes(*flags),
            max_chunks: u32::from_ne_bytes(*max_chunks),
            chunk_payload_size: u32::from_ne_bytes(*chunk_payload_size),
            page_index: u32::from_ne_bytes(*page_index),
            cursor: u64::from_ne_bytes(*cursor),
            invocation_id: u64::from_ne_bytes(*invocation_id),
        })
    }
}

/// The map through the serializer upatch `upatch` pins for it, into
/// `out` page by page until the serializer says it is done: whether the
/// map has a serializer.
fn read_serialized(
    upatch: &[u8],
    map: &[u8],
    flags: u32,
    out: &mut MapView,
) -> Result<bool, c_int> {
    if map == SERIAL_MAP_NAME {
        return Ok(false);
    }
    let prog = match open_serializer_pin(upatch, map) {
        Ok(fd) => fd,
        Err(e) if e == -ENOENT => return Ok(false),
        Err(e) => return Err(e),
    };
    let (serial, info) = open_map_pin(upatch, SERIAL_MAP_NAME)?;
    let output = Map::serial_output(serial.as_fd(), &info)?;
    // Clearing, running and reading are one transaction, under a lock
    // keyed by the output map's kernel ID: every process sharing the map
    // contends, and unrelated upatches stay independent.
    let _lock = crate::util::serializer::lock_acquire(info.u32_at(MAP_ID))?;
    let invocation_id = new_invocation_id()?;
    let max = info.u32_at(MAP_MAX_ENTRIES);
    let (mut cursor, mut bytes_total) = (0u64, 0u64);
    for page_index in 0..SERIAL_MAX_PAGES {
        clear_serial_map(&output, max)?;
        let mut ctx = SerializeCtx {
            magic: SERIAL_MAGIC,
            version: SERIAL_VERSION,
            flags: if flags & MAP_READ_PEEK != 0 {
                SERIAL_CTX_F_PEEK
            } else {
                0
            },
            max_chunks: max,
            chunk_payload_size: SERIAL_CHUNK_PAYLOAD,
            page_index,
            cursor,
            invocation_id,
        }
        .to_bytes();
        let retval = prog_test_run(prog.as_raw_fd(), &mut ctx)?;
        // The serializer's return value, a negative errno when it fails.
        let retval = i32::from_ne_bytes(retval.to_ne_bytes());
        if retval < 0 {
            return Err(retval);
        }
        let ctx = SerializeCtx::from_bytes(&ctx).ok_or(-EBADMSG)?;
        if ctx.magic != SERIAL_MAGIC
            || ctx.version != SERIAL_VERSION
            || ctx.page_index != page_index
            || ctx.cursor != cursor
            || ctx.invocation_id != invocation_id
        {
            return Err(-EBADMSG);
        }
        let page = read_serial_page(&output, max, page_index, cursor, invocation_id)?;
        if bytes_total + u64::from(page.bytes()) > SERIAL_MAX_TOTAL_BYTES {
            return Err(-E2BIG);
        }
        bytes_total += u64::from(page.bytes());
        let (done, next) = (page.done, page.next_cursor);
        out.serial_pages.try_reserve(1).map_err(|_| -ENOMEM)?;
        out.serial_pages.push(page);
        if done {
            break;
        }
        if next == cursor {
            return Err(-EBADMSG);
        }
        cursor = next;
    }
    if !out.serial_pages.last().is_some_and(|page| page.done) {
        return Err(-E2BIG);
    }
    out.serialized = true;
    out.serial_bytes_total = bytes_total;
    Ok(true)
}

/// `len` zero bytes, or -ENOMEM.
fn zeroed(len: usize) -> Result<Vec<u8>, c_int> {
    let mut buf = Vec::new();
    buf.try_reserve_exact(len).map_err(|_| -ENOMEM)?;
    buf.resize(len, 0);
    Ok(buf)
}

/// The map's entries, at most `cap` of them or all for 0: an array by
/// index, holes left out, a hash by its keys.
fn read_entries(map: &Map<'_>, v: &mut MapView, cap: u32) -> Result<(), c_int> {
    v.n_truncated_at = cap;
    if is_array(v.ty) {
        read_array(map, v, cap)
    } else if is_hash(v.ty) {
        read_hash(map, v, cap)
    } else {
        Err(-EOPNOTSUPP)
    }
}

/// The array's entries by index, the first `cap` or all for 0: -ENOMEM
/// when a buffer cannot be had.
fn read_array(map: &Map<'_>, v: &mut MapView, cap: u32) -> Result<(), c_int> {
    let mut take = v.max_entries;
    if cap != 0 && take > cap {
        take = cap;
        v.truncated = true;
    }
    v.entries
        .try_reserve_exact(take as usize)
        .map_err(|_| -ENOMEM)?;
    for index in 0..take {
        let mut key = zeroed(map.key_size)?;
        let mut value = zeroed(map.value_size)?;
        key.iter_mut()
            .zip(index.to_ne_bytes())
            .for_each(|(k, b)| *k = b);
        if map.lookup(&key, &mut value).is_err() {
            continue;
        }
        v.entries.push(MapEntry { key, value });
    }
    Ok(())
}

/// The hash's entries in the kernel's order, the first `cap` or all for
/// 0; as many as fit when a buffer cannot be had.
fn read_hash(map: &Map<'_>, v: &mut MapView, cap: u32) -> Result<(), c_int> {
    let mut cursor = zeroed(map.key_size)?;
    let mut first = true;
    while map.next_key(&mut cursor, first).is_ok() {
        first = false;
        let (Ok(mut key), Ok(mut value)) = (zeroed(map.key_size), zeroed(map.value_size)) else {
            break;
        };
        key.copy_from_slice(&cursor);
        if map.lookup(&key, &mut value).is_err() {
            continue;
        }
        if v.entries.try_reserve(1).is_err() {
            break;
        }
        v.entries.push(MapEntry { key, value });
        if cap != 0 && v.n_entries() >= cap {
            v.truncated = true;
            break;
        }
    }
    Ok(())
}

fn fill(dst: &mut [u8], src: &[u8]) -> Result<(), c_int> {
    strscpy(dst, src).map(|_| ()).map_err(|_| -ENAMETOOLONG)
}

/// Map `map` of upatch `upatch`: at most `cap` entries or all for 0,
/// through its serializer if it has one, MAP_READ_PEEK in `flags` to
/// leave the serializer's interval to the exporter.
pub(crate) fn read(upatch: &[u8], map: &[u8], cap: u32, flags: u32) -> Result<MapView, c_int> {
    let mut out = MapView::default();
    fill(&mut out.upatch, upatch)?;
    fill(&mut out.name, map)?;
    let (fd, info) = open_map_pin(upatch, map)?;
    let ty = info.u32_at(MAP_TYPE);
    out.ty = ty;
    out.type_name = Some(map_type_name(ty));
    out.key_size = info.u32_at(MAP_KEY_SIZE);
    out.value_size = info.u32_at(MAP_VALUE_SIZE);
    out.value_stride = stride_of(ty, out.value_size).ok_or(-EOVERFLOW)?;
    out.max_entries = info.u32_at(MAP_MAX_ENTRIES);
    out.n_cpus = if is_percpu(ty) { nproc_possible()? } else { 1 };
    if let Ok(location) = resolve_location(kernel_btf::vmlinux(), upatch) {
        let _ = strscpy(&mut out.location, &location);
    }
    if let Ok(dir) = pin_path(upatch, &[])
        && let Ok(st) = fs::metadata(os(dir.as_bytes()))
    {
        out.lifetime_start_ns = (st.ctime() as u64)
            .wrapping_mul(1_000_000_000)
            .wrapping_add(st.ctime_nsec() as u64);
    }
    // What a decoder export checks the archive against.
    if let Ok(payload) = pin_payload(upatch) {
        out.payload = payload;
        out.has_payload = true;
    }

    if read_serialized(upatch, map, flags, &mut out)? {
        return Ok(out);
    }
    if let Some(reason) = map_skip_reason(ty) {
        out.skipped = true;
        out.skipped_reason = Some(reason);
        return Ok(out);
    }
    let btf_id = info.u32_at(MAP_BTF_ID);
    out.btf = (btf_id != 0)
        .then(|| kernel_btf::by_id(btf_id).ok())
        .flatten();
    if let Some(btf) = &out.btf {
        let (kid, vid) = (
            info.u32_at(MAP_BTF_KEY_TYPE_ID),
            info.u32_at(MAP_BTF_VALUE_TYPE_ID),
        );
        out.key_type_id = kid;
        out.value_type_id = vid;
        type_name(Some(btf), kid, &mut out.btf_key_type);
        type_name(Some(btf), vid, &mut out.btf_value_type);
        type_def(Some(btf), kid, &mut out.key_type_def);
        type_def(Some(btf), vid, &mut out.value_type_def);
    }
    read_entries(&Map::entries_of(fd.as_fd(), &out)?, &mut out, cap)?;
    Ok(out)
}

/// A summary cannot reopen a pin if either name is truncated.
fn summary_names(one: &mut MapSummary, upatch: &[u8], name: &[u8]) -> bool {
    strscpy(&mut one.upatch, upatch).is_ok() && strscpy(&mut one.name, name).is_ok()
}

/// The maps upatch `upatch` pins, onto `list`, in directory order: each
/// that opens, but the serializers' output map.
fn scan(upatch: &[u8], list: &mut Vec<MapSummary>) {
    let Ok(dir) = pin_path(upatch, &[b"maps"]) else {
        return;
    };
    let Ok(entries) = fs::read_dir(os(dir.as_bytes())) else {
        return;
    };
    for e in entries.map_while(Result::ok) {
        let name = e.file_name();
        let name = name.as_bytes();
        if name.first() == Some(&b'.') || name == SERIAL_MAP_NAME {
            continue;
        }
        let Ok((fd, info)) = open_map_pin(upatch, name) else {
            continue;
        };
        drop(fd);
        let ty = info.u32_at(MAP_TYPE);
        let n_cpus = if is_percpu(ty) {
            let Ok(cpus) = nproc_possible() else {
                continue;
            };
            cpus
        } else {
            1
        };
        let mut one = MapSummary {
            type_name: Some(map_type_name(ty)),
            max_entries: info.u32_at(MAP_MAX_ENTRIES),
            n_cpus,
            ..MapSummary::default()
        };
        if !summary_names(&mut one, upatch, name) {
            continue;
        }
        list.push(one);
    }
}

/// The maps upatch `upatch` pins, or with none every loaded upatch's.
pub(crate) fn list(upatch: Option<&[u8]>) -> Vec<MapSummary> {
    let mut list = Vec::new();
    match upatch {
        Some(u) => scan(u, &mut list),
        None => {
            if let Ok(entries) = fs::read_dir(BPFFS_UPATCHES_DIR) {
                for e in entries.map_while(Result::ok) {
                    let pin = e.file_name();
                    let pin = pin.as_bytes();
                    if pin.first() == Some(&b'.') {
                        continue;
                    }
                    if let Some(name) = name_from_pin(pin).filter(|n| n.len() <= 256) {
                        scan(&name, &mut list);
                    }
                }
            }
        }
    }
    list
}

#[cfg(shirudo_fuzz)]
mod fuzz;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_summary_omits_names_that_do_not_fit() {
        let mut summary = MapSummary::default();
        assert!(summary_names(&mut summary, b"patch", b"map"));
        assert_eq!(crate::text::cstr(&summary.name), b"map");
        assert!(!summary_names(
            &mut summary,
            b"patch",
            &[b'm'; MAP_NAME_MAX + 1]
        ));
        assert!(!summary_names(
            &mut summary,
            &[b'p'; UPATCH_NAME_MAX + 1],
            b"map"
        ));
    }
}
