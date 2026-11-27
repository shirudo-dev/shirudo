// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The `.upatch` container parser: the header and
//! the bounds of its sections, the signed sections behind the loader
//! data, the programs' metadata, and the names of upatches.

use core::ffi::{CStr, c_int};
use core::ops::Range;
use std::borrow::Cow;
use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;

use crate::errno::{EFBIG, EINVAL, ENOMEM, EOPNOTSUPP, EOVERFLOW};
use crate::text::cstr;
use crate::util::hex;
use crate::util::io;

pub(crate) const NAME_MAX: usize = 256;
pub(crate) const PAYLOAD_HASH_LEN: usize = 32;
/// The largest container a reader takes; .upatch is small.
pub(crate) const FILE_MAX: usize = 16 * 1024 * 1024;
/// The NAME_MAX of `<limits.h>` a pin directory's name must fit.
const PIN_NAME_MAX: usize = 255;

pub(crate) const MAGIC: u64 = 0x5348_5244_554e_4150;
pub(crate) const VERSION: u32 = 1;
pub(crate) const HEADER_SIZE: usize = 360;
pub(crate) const DIRECTIVE_UNLOAD: u32 = 1;
pub(crate) const TYPE_BPF: u32 = 1;
pub(crate) const TYPE_JAVA: u32 = 2;

pub(crate) const SIGNED_TRAILER_MAGIC: u32 = 0x5254_4753;
pub(crate) const SIGNED_VERSION: u32 = 1;
pub(crate) const SIGNED_SECTIONS_MAX: u32 = 8;
pub(crate) const SECTION_NAME: u32 = 0x454d_414e;
pub(crate) const SECTION_ATTACH: u32 = 0x4d47_5055;
pub(crate) const SECTION_UNLOAD: u32 = 0x444c_4e55;
pub(crate) const SECTION_DECODERS: u32 = 0x4244_4344;
pub(crate) const SECTION_POLICY_LABELS: u32 = 0x4c50_4853;
pub(crate) const SECTION_TYPE: u32 = 0x5059_5450;
pub(crate) const SECTION_JAR: u32 = 0x4156_414a;

pub(crate) const POLICY_LABELS_MAGIC: u32 = 0x4c50_4853;
pub(crate) const POLICY_LABELS_VERSION: u32 = 1;
pub(crate) const MAPS_MAX: u32 = 64;
const POLICY_NAME_MAX: usize = 64;
const POLICY_PATH_MAX: usize = 4096;
const POLICY_PATH_LEN_MAX: usize = 255;

pub(crate) const DECODER_MAGIC: u32 = 0x4244_4344;
pub(crate) const DECODER_VERSION: u32 = 1;

pub(crate) const ATTACH_TARGET_MAX: usize = 128;
pub(crate) const PROG_MAGIC: u32 = 0x4d47_5055;
pub(crate) const PROG_VERSION: u32 = 1;
pub(crate) const PROG_MAP_MAX: usize = 16;
pub(crate) const UPROBE_TARGET_MAGIC: u32 = 0x5455_5055;
pub(crate) const UPROBE_TARGET_VERSION: u32 = 1;
pub(crate) const UPROBE_PATH_MAX: u32 = 4096;
pub(crate) const BUILD_ID_MAX: usize = 64;
const UPROBE_OFFSETS_MAX: u32 = 1 << 20;
pub(crate) const KPROBE_TARGET_MAGIC: u32 = 0x534b_5055;
pub(crate) const KPROBE_TARGET_VERSION: u32 = 1;
pub(crate) const KPROBE_SYM_MAX: usize = 512;
pub(crate) const KPROBE_SYMS_MAX: u32 = 1 << 20;

pub(crate) const ATTACH_RAW_TRACEPOINT: u32 = 0;
pub(crate) const ATTACH_KPROBE: u32 = 1;
pub(crate) const ATTACH_KRETPROBE: u32 = 2;
pub(crate) const ATTACH_CGROUP_SKB_INGRESS: u32 = 3;
pub(crate) const ATTACH_CGROUP_SKB_EGRESS: u32 = 4;
pub(crate) const ATTACH_FMOD_RET: u32 = 5;
pub(crate) const ATTACH_NETFILTER_IPV6_PRE_ROUTING: u32 = 6;
pub(crate) const ATTACH_UPROBE_MULTI: u32 = 7;
pub(crate) const ATTACH_XDP: u32 = 8;
pub(crate) const ATTACH_URETPROBE_MULTI: u32 = 9;
pub(crate) const ATTACH_UPROBE: u32 = 10;
pub(crate) const ATTACH_URETPROBE: u32 = 11;
pub(crate) const ATTACH_KPROBE_MULTI: u32 = 12;
pub(crate) const ATTACH_KRETPROBE_MULTI: u32 = 13;

/// `enum upatch_xdp_device_class`: the classes of device an XDP program
/// attaches to. Bit 4 is none: loopback has no native XDP, so nothing
/// selects it.
pub(crate) const XDP_NETWORK: u32 = 1;
pub(crate) const XDP_VIRTUAL: u32 = 2;
pub(crate) const XDP_VM: u32 = 8;
pub(crate) const XDP_UNKNOWN: u32 = 16;
pub(crate) const XDP_ALL: u32 = XDP_NETWORK | XDP_VIRTUAL | XDP_VM | XDP_UNKNOWN;

pub(crate) const ROLE_ATTACH: u32 = 0;
pub(crate) const ROLE_SERIALIZER: u32 = 1;
pub(crate) const ROLE_TEST_RUN: u32 = 2;

/// The sizes of the records of the .upatch format, which the
/// parser reads at their offsets, little-endian.
pub(crate) const POLICY_LABEL_HEADER: usize = 20;
pub(crate) const POLICY_LABEL_ENTRY: usize = 8 + POLICY_NAME_MAX + POLICY_PATH_MAX;
pub(crate) const SIGNED_SECTION: usize = 16;
pub(crate) const SIGNED_TRAILER: usize = 16;
pub(crate) const DECODER_BLOB: usize = 16;
pub(crate) const DECODER_ENTRY: usize = 16 + 64 + 16 + 64 + 32 + 8;
pub(crate) const PROG_METADATA: usize = 16;
pub(crate) const PROG_ENTRY: usize = 16 + ATTACH_TARGET_MAX + PROG_MAP_MAX;
pub(crate) const UPROBE_TARGETS: usize = 16;
pub(crate) const UPROBE_TARGET: usize = 16;
pub(crate) const KPROBE_TARGETS: usize = 16;
pub(crate) const KPROBE_TARGET: usize = 12;

/// `struct upatch_host_header`: the container's header in host order.
pub struct UpatchHostHeader {
    pub(crate) magic: u64,
    pub(crate) version: u32,
    pub(crate) flags: u32,
    pub(crate) name: [u8; NAME_MAX],
    pub(crate) payload_sha256: [u8; PAYLOAD_HASH_LEN],
    pub(crate) loader_insns_off: u32,
    pub(crate) loader_insns_len: u32,
    pub(crate) signature_off: u32,
    pub(crate) signature_len: u32,
    pub(crate) reserved2: u32,
    pub(crate) reserved3: u32,
    pub(crate) data_off: u32,
    pub(crate) data_len: u32,
    pub(crate) log_buf_sz: u32,
    pub(crate) nr_maps: u32,
    pub(crate) nr_progs: u32,
    pub(crate) rodata_data_off: u32,
    pub(crate) ty: u32,
    pub(crate) reserved1: u32,
}

/// A `.upatch` container opened: its header, its bytes, read from a file
/// into memory of its own or borrowed from the caller, and where the
/// signed sections behind the loader data lie in them, which its methods
/// hand out.
pub(crate) struct Upatch<'a> {
    pub(crate) hdr: UpatchHostHeader,
    bytes: Cow<'a, [u8]>,
    signed: Signed,
}

/// Where the signed sections lie in a container's bytes.
#[derive(Default)]
struct Signed {
    name: Option<Range<usize>>,
    attach: Option<Range<usize>>,
    unload_payload: Option<Range<usize>>,
    decoders: Option<DecodersAt>,
    policy_labels: Option<PolicyLabelsAt>,
    ty: Option<Range<usize>>,
    jar: Option<Range<usize>>,
}

/// The signed DECODERS section, and how many decoders it holds.
struct DecodersAt {
    at: Range<usize>,
    count: u32,
}

/// The signed POLICY_LABELS section, and the two maps it names.
struct PolicyLabelsAt {
    at: Range<usize>,
    map_idx: u32,
    socket_map_idx: u32,
}

/// A decoder of the signed blob, borrowing its source from the container.
pub struct DecoderView<'a> {
    pub(crate) language: u32,
    pub(crate) api_version: u32,
    pub(crate) input_format: u32,
    pub(crate) export_signal: u32,
    pub(crate) map: [u8; 16],
    pub(crate) source_name: [u8; 64],
    pub(crate) entrypoint: [u8; 32],
    pub(crate) source: &'a [u8],
}

impl<'a> DecoderView<'a> {
    /// The view of `d`, none for a source a u32 cannot measure.
    pub(crate) fn of(d: &Decoder<'a>) -> Option<Self> {
        u32::try_from(d.source.len()).ok()?;
        Some(DecoderView {
            language: d.language,
            api_version: d.api_version,
            input_format: d.input_format,
            export_signal: d.export_signal,
            map: *d.map,
            source_name: *d.source_name,
            entrypoint: *d.entrypoint,
            source: d.source,
        })
    }
}

/// A decoder of the signed DECODERS section: what it reads and exports,
/// and its source, all within the container.
pub(crate) struct Decoder<'a> {
    pub(crate) language: u32,
    pub(crate) api_version: u32,
    pub(crate) input_format: u32,
    pub(crate) export_signal: u32,
    pub(crate) upatch: &'a [u8; 64],
    pub(crate) map: &'a [u8; 16],
    pub(crate) source_name: &'a [u8; 64],
    pub(crate) entrypoint: &'a [u8; 32],
    pub(crate) source: &'a [u8],
}

/// The signed POLICY_LABELS section, and the two maps it names.
pub(crate) struct PolicyLabels<'a> {
    pub(crate) labels: &'a [u8],
    pub(crate) map_idx: u32,
    pub(crate) socket_map_idx: u32,
}

/// A parsed program's attach role and target. The path, offsets, and
/// symbol names own their storage for as long as the loader uses them.
pub struct ProgSpec {
    pub(crate) role: u32,
    pub(crate) kind: u32,
    /// An XDP program's: the classes of device it attaches to.
    pub(crate) device_classes: u32,
    pub(crate) offset: u64,
    pub(crate) target: [u8; ATTACH_TARGET_MAX],
    pub(crate) map: [u8; PROG_MAP_MAX],
    pub(crate) uprobe_path: Vec<u8>,
    pub(crate) build_id: [u8; BUILD_ID_MAX],
    pub(crate) build_id_len: u32,
    pub(crate) uprobe_offsets: Vec<u64>,
    pub(crate) nr_uprobe_offsets: u32,
    /// Holds NUL-terminated symbols. Offsets name their starts in this buffer.
    kprobe_sym_buf: Vec<u8>,
    pub(crate) kprobe_sym_offsets: Vec<usize>,
    pub(crate) nr_kprobe_syms: u32,
    pub(crate) target_fd: Option<OwnedFd>,
}

impl ProgSpec {
    /// One NUL-terminated kprobe name at a checked metadata offset.
    pub(crate) fn kprobe_symbol(&self, off: usize) -> Result<&CStr, c_int> {
        let tail = self.kprobe_sym_buf.get(off..).ok_or(-EINVAL)?;
        let end = tail.iter().position(|&byte| byte == 0).ok_or(-EINVAL)?;
        CStr::from_bytes_with_nul(&tail[..=end]).map_err(|_| -EINVAL)
    }

    fn new() -> Self {
        Self {
            role: 0,
            kind: 0,
            device_classes: 0,
            offset: 0,
            target: [0; ATTACH_TARGET_MAX],
            map: [0; PROG_MAP_MAX],
            uprobe_path: Vec::new(),
            build_id: [0; BUILD_ID_MAX],
            build_id_len: 0,
            uprobe_offsets: Vec::new(),
            nr_uprobe_offsets: 0,
            kprobe_sym_buf: Vec::new(),
            kprobe_sym_offsets: Vec::new(),
            nr_kprobe_syms: 0,
            target_fd: None,
        }
    }
}

/// uprobe.multi and uretprobe.multi: a glob over a binary's functions.
pub(crate) fn kind_is_uprobe_multi(kind: u32) -> bool {
    kind == ATTACH_UPROBE_MULTI || kind == ATTACH_URETPROBE_MULTI
}

/// uprobe and uretprobe: one place in a binary.
pub(crate) fn kind_is_uprobe_single(kind: u32) -> bool {
    kind == ATTACH_UPROBE || kind == ATTACH_URETPROBE
}

/// The kinds that attach to a userspace binary named in the UPUT block.
pub(crate) fn kind_has_uprobe_target(kind: u32) -> bool {
    kind_is_uprobe_multi(kind) || kind_is_uprobe_single(kind)
}

/// kprobe.multi and kretprobe.multi: a signed list of kernel functions.
pub(crate) fn kind_is_kprobe_multi(kind: u32) -> bool {
    kind == ATTACH_KPROBE_MULTI || kind == ATTACH_KRETPROBE_MULTI
}

/// A function name accepted by BPF kprobe multi: one to 511 printable
/// ASCII bytes, without list or glob metacharacters.
pub(crate) fn kprobe_sym_valid(sym: &[u8]) -> bool {
    !sym.is_empty()
        && sym.len() < KPROBE_SYM_MAX
        && sym
            .iter()
            .all(|&c| c > b' ' && c < 0x7f && !matches!(c, b',' | b'*' | b'?' | b'|'))
}

/// Every device class an XDP program among the specs selects.
pub(crate) fn specs_xdp_classes(specs: &[ProgSpec]) -> u32 {
    specs
        .iter()
        .filter(|s| s.kind == ATTACH_XDP)
        .fold(0, |classes, s| classes | s.device_classes)
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn le64(b: &[u8], off: usize) -> u64 {
    let mut v = [0u8; 8];

    v.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(v)
}

fn has_nul(b: &[u8]) -> bool {
    b.contains(&0)
}

/// The header at the start of `m`, or -EINVAL.
fn parse_header(m: &[u8]) -> Result<UpatchHostHeader, c_int> {
    if m.len() < HEADER_SIZE {
        return Err(-EINVAL);
    }
    let field = |i: usize| le32(m, 304 + 4 * i);
    let h = UpatchHostHeader {
        magic: le64(m, 0),
        version: le32(m, 8),
        flags: le32(m, 12),
        name: m[16..16 + NAME_MAX].try_into().map_err(|_| -EINVAL)?,
        payload_sha256: m[272..272 + PAYLOAD_HASH_LEN]
            .try_into()
            .map_err(|_| -EINVAL)?,
        loader_insns_off: field(0),
        loader_insns_len: field(1),
        signature_off: field(2),
        signature_len: field(3),
        reserved2: field(4),
        reserved3: field(5),
        data_off: field(6),
        data_len: field(7),
        log_buf_sz: field(8),
        nr_maps: field(9),
        nr_progs: field(10),
        rodata_data_off: field(11),
        ty: field(12),
        reserved1: field(13),
    };
    if h.magic != MAGIC
        || h.version != VERSION
        || !has_nul(&h.name)
        || h.reserved1 != 0
        || h.reserved2 != 0
        || h.reserved3 != 0
    {
        return Err(-EINVAL);
    }
    Ok(h)
}

fn section_inside(off: u32, len: u32, n: usize) -> bool {
    let end = u64::from(off) + u64::from(len);

    if end > n as u64 {
        return false;
    }
    !(len != 0 && (off as usize) < HEADER_SIZE)
}

/// Whether a BPF header's loader-specific fields are valid.
fn validate_bpf_bounds(h: &UpatchHostHeader, n: usize) -> Result<(), c_int> {
    if (h.loader_insns_off as usize) < HEADER_SIZE
        || !h.loader_insns_off.is_multiple_of(8)
        || !h.loader_insns_len.is_multiple_of(8)
        || !section_inside(h.loader_insns_off, h.loader_insns_len, n)
    {
        return Err(-EINVAL);
    }
    if h.rodata_data_off > h.data_len || h.loader_insns_len == 0 {
        return Err(-EINVAL);
    }
    Ok(())
}

/// A Java payload is all signed data: none of the BPF loader fields
/// apply.
fn validate_java_bounds(h: &UpatchHostHeader) -> Result<(), c_int> {
    if h.loader_insns_off != 0
        || h.loader_insns_len != 0
        || h.log_buf_sz != 0
        || h.nr_maps != 0
        || h.nr_progs != 0
        || h.rodata_data_off != 0
        || h.data_len == 0
    {
        return Err(-EINVAL);
    }
    Ok(())
}

/// Whether the header `h` places every section within the `n` bytes of
/// its container and describes one supported payload type.
fn validate_bounds(h: &UpatchHostHeader, n: usize) -> Result<(), c_int> {
    if !section_inside(h.signature_off, h.signature_len, n)
        || !section_inside(h.data_off, h.data_len, n)
        || h.signature_len == 0
    {
        return Err(-EINVAL);
    }
    match h.ty {
        TYPE_BPF => validate_bpf_bounds(h, n),
        TYPE_JAVA => validate_java_bounds(h),
        _ => Err(-EINVAL),
    }
}

/// Whether `path` is an absolute policy-label path of at most 255 bytes
/// that does not end in '/', with '*' and '?' in its last component alone.
pub(crate) fn policy_path_valid(path: &[u8]) -> bool {
    if path.is_empty()
        || path.len() > POLICY_PATH_LEN_MAX
        || path[0] != b'/'
        || path.contains(&0)
        || path.last() == Some(&b'/')
    {
        return false;
    }
    let name = path.iter().rposition(|&c| c == b'/').unwrap_or_default();
    !path[..name].iter().any(|&c| matches!(c, b'*' | b'?'))
}

/// The last component of a valid policy path when it is a filename
/// pattern, or None when the path names one file.
pub(crate) fn policy_path_pattern(path: &[u8]) -> Option<&[u8]> {
    let name = path
        .iter()
        .rposition(|&c| c == b'/')
        .map_or(path, |slash| &path[slash + 1..]);

    name.iter()
        .any(|&c| matches!(c, b'*' | b'?'))
        .then_some(name)
}

/// The policy labels section `p`: its map indexes when it holds `count`
/// well-formed labels for maps the loader has.
fn parse_policy_labels(p: &[u8], nr_maps: u32) -> Option<(u32, u32)> {
    if p.len() < POLICY_LABEL_HEADER {
        return None;
    }
    let count = le32(p, 8);
    let idx = le32(p, 12);
    let socket_idx = le32(p, 16);
    if le32(p, 0) != POLICY_LABELS_MAGIC
        || le32(p, 4) != POLICY_LABELS_VERSION
        || idx >= nr_maps
        || idx >= MAPS_MAX
        || socket_idx >= nr_maps
        || socket_idx >= MAPS_MAX
        || idx == socket_idx
        || count == 0
        || (count as usize)
            .checked_mul(POLICY_LABEL_ENTRY)
            .and_then(|n| n.checked_add(POLICY_LABEL_HEADER))
            != Some(p.len())
    {
        return None;
    }
    for i in 0..count as usize {
        let e = &p[POLICY_LABEL_HEADER + i * POLICY_LABEL_ENTRY..][..POLICY_LABEL_ENTRY];
        let bit = le64(e, 0);
        let policy = &e[8..8 + POLICY_NAME_MAX];
        let path = &e[8 + POLICY_NAME_MAX..];

        if bit == 0
            || bit & (bit - 1) != 0
            || !has_nul(policy)
            || policy[0] == 0
            || !has_nul(path)
            || !policy_path_valid(cstr(path))
        {
            return None;
        }
    }
    Some((idx, socket_idx))
}

/// The DECODERS section `bp`, its entries and their sources within it:
/// how many decoders it holds, or None when it breaks a rule.
fn parse_decoders(bp: &[u8]) -> Option<u32> {
    if bp.len() < DECODER_BLOB || le32(bp, 0) != DECODER_MAGIC || le32(bp, 4) != DECODER_VERSION {
        return None;
    }
    let nr_decoders = le32(bp, 8);
    if nr_decoders == 0 {
        return None;
    }
    let entries_end = DECODER_BLOB as u64 + u64::from(nr_decoders) * DECODER_ENTRY as u64;
    let decoder_len = u32::try_from(bp.len()).ok()?;
    if entries_end > u64::from(decoder_len) {
        return None;
    }
    // The blob sits behind the signature, so entries are unaligned.
    for i in 0..nr_decoders as usize {
        let d = &bp[DECODER_BLOB + i * DECODER_ENTRY..][..DECODER_ENTRY];

        if !has_nul(&d[16..80])
            || !has_nul(&d[80..96])
            || !has_nul(&d[96..160])
            || !has_nul(&d[160..192])
        {
            return None;
        }
        if le32(d, 0) == 0 || le32(d, 4) == 0 || le32(d, 8) == 0 || le32(d, 12) == 0 {
            return None;
        }
        let source_off = le32(d, 192);
        let source_len = le32(d, 196);
        if source_len == 0
            || u64::from(source_off) < entries_end
            || source_off > decoder_len
            || source_len > decoder_len - source_off
        {
            return None;
        }
    }
    Some(nr_decoders)
}

/// The signed sections behind the loader data `data`, which starts at
/// `data_off` in the container. Each lies below the directory, the
/// directory ends where the trailer begins, and each tag appears once; a
/// directory that breaks any of that is taken for none, so a load or
/// unload refuses for what it then lacks.
///
/// The signature covers insns followed by data with nothing between
/// them, while the header that divides the two is unsigned. The trailer
/// is last whichever split the header names. Requiring the directory to
/// end at it makes the directory offset and count bind that split: of
/// all the ways to divide one signed byte string, only the signer's keeps
/// its sections.
fn parse_signed_sections(data: &[u8], data_off: usize, nr_maps: u32) -> Option<Signed> {
    let data_len = data.len();

    if data_len < SIGNED_TRAILER {
        return None;
    }
    let tr = &data[data_len - SIGNED_TRAILER..];
    if le32(tr, 0) != SIGNED_TRAILER_MAGIC || le32(tr, 4) != SIGNED_VERSION {
        return None;
    }
    let dir_off = le32(tr, 8);
    let nr = le32(tr, 12);
    let end = (data_len - SIGNED_TRAILER) as u64;
    if nr == 0
        || nr > SIGNED_SECTIONS_MAX
        || u64::from(dir_off) > end
        || u64::from(nr) * SIGNED_SECTION as u64 != end - u64::from(dir_off)
    {
        return None;
    }
    let mut signed = Signed::default();
    let mut seen = 0u32;
    for i in 0..nr as usize {
        let s = &data[dir_off as usize + i * SIGNED_SECTION..][..SIGNED_SECTION];
        let tag = le32(s, 0);
        let off = le32(s, 8);
        let len = le32(s, 12);

        if le32(s, 4) != 0 || off > dir_off || len > dir_off - off {
            return None;
        }
        let section = &data[off as usize..][..len as usize];
        let at = data_off + off as usize..data_off + off as usize + len as usize;
        let bit = match tag {
            SECTION_NAME => {
                if len as usize != NAME_MAX || !has_nul(section) {
                    return None;
                }
                signed.name = Some(at);
                1
            }
            SECTION_ATTACH => {
                if len == 0 {
                    return None;
                }
                signed.attach = Some(at);
                2
            }
            SECTION_UNLOAD => {
                if len as usize != PAYLOAD_HASH_LEN {
                    return None;
                }
                signed.unload_payload = Some(at);
                4
            }
            SECTION_DECODERS => {
                let count = parse_decoders(section)?;
                signed.decoders = Some(DecodersAt { at, count });
                8
            }
            SECTION_POLICY_LABELS => {
                let (map_idx, socket_map_idx) = parse_policy_labels(section, nr_maps)?;
                signed.policy_labels = Some(PolicyLabelsAt {
                    at,
                    map_idx,
                    socket_map_idx,
                });
                16
            }
            SECTION_TYPE => {
                if len != 4 {
                    return None;
                }
                signed.ty = Some(at);
                32
            }
            SECTION_JAR => {
                if len == 0 {
                    return None;
                }
                signed.jar = Some(at);
                64
            }
            _ => return None,
        };
        if seen & bit != 0 {
            return None;
        }
        seen |= bit;
    }
    Some(signed)
}

impl<'a> Upatch<'a> {
    /// The container in `bytes`, its signed sections found: -EINVAL for
    /// one the parser refuses.
    fn parse(bytes: Cow<'a, [u8]>) -> Result<Self, c_int> {
        if bytes.is_empty() || bytes.len() > FILE_MAX {
            return Err(-EINVAL);
        }
        let hdr = parse_header(&bytes)?;
        validate_bounds(&hdr, bytes.len())?;
        let data = &bytes[hdr.data_off as usize..][..hdr.data_len as usize];
        let signed =
            parse_signed_sections(data, hdr.data_off as usize, hdr.nr_maps).unwrap_or_default();
        let upatch = Upatch { hdr, bytes, signed };
        // The header is unsigned. Its type must be bound by the signed
        // sections before it chooses the verifier. Legacy BPF payloads
        // have no TYPE section and therefore default to BPF.
        if upatch.signed_type() != upatch.hdr.ty {
            return Err(-EINVAL);
        }
        Ok(upatch)
    }

    /// The container in `bytes`, which it borrows: -EINVAL for one the
    /// parser refuses.
    pub(crate) fn from_bytes(bytes: &'a [u8]) -> Result<Self, c_int> {
        Self::parse(Cow::Borrowed(bytes))
    }
}

impl Upatch<'static> {
    /// The container in `bytes`, which it keeps: -EINVAL for one the
    /// parser refuses.
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Result<Self, c_int> {
        Self::parse(Cow::Owned(bytes))
    }

    /// The container in the file at `path`, as [`Upatch::read`] reads
    /// it.
    pub(crate) fn open(path: &CStr) -> Result<Self, c_int> {
        let file = File::open(OsStr::from_bytes(path.to_bytes())).map_err(|e| io::errno_of(&e))?;

        Self::read(&file)
    }

    /// The container in `file`, read from its start into memory of its
    /// own: -EINVAL for what is not a regular file of some bytes, -EFBIG
    /// for one larger than FILE_MAX, or another -errno.
    ///
    /// A copy, not a mapping: a private mapping still shows what is
    /// written to the file after mmap(), so the bytes parsed here, the
    /// ones handed to the kernel and the ones acted on after its
    /// signature check could differ.
    pub(crate) fn read(file: &File) -> Result<Self, c_int> {
        let meta = file.metadata().map_err(|e| io::errno_of(&e))?;
        if !meta.file_type().is_file() || meta.len() == 0 {
            return Err(-EINVAL);
        }
        // Refuse pathologically large inputs; .upatch is small.
        let size = usize::try_from(meta.len())
            .ok()
            .filter(|&size| size <= FILE_MAX)
            .ok_or(-EFBIG)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| -ENOMEM)?;
        bytes.resize(size, 0);
        file.read_exact_at(&mut bytes, 0)
            .map_err(|e| io::errno_of(&e))?;
        Self::from_vec(bytes)
    }
}

impl Upatch<'_> {
    /// The container's bytes, all of them.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The `len` bytes at `off`, which validate_bounds() kept within the
    /// container.
    fn section(&self, off: u32, len: u32) -> &[u8] {
        self.bytes
            .get(off as usize..)
            .and_then(|b| b.get(..len as usize))
            .unwrap_or_default()
    }

    /// The loader's instructions.
    pub(crate) fn loader(&self) -> &[u8] {
        self.section(self.hdr.loader_insns_off, self.hdr.loader_insns_len)
    }

    /// The loader's signature.
    pub(crate) fn signature(&self) -> &[u8] {
        self.section(self.hdr.signature_off, self.hdr.signature_len)
    }

    /// The loader's data, the signed sections behind it.
    pub(crate) fn data(&self) -> &[u8] {
        self.section(self.hdr.data_off, self.hdr.data_len)
    }

    /// The bytes of the signed section at `at`, which
    /// parse_signed_sections() kept within the data.
    fn signed_section(&self, at: Option<&Range<usize>>) -> Option<&[u8]> {
        self.bytes.get(at?.clone())
    }

    /// The header's name, up to its NUL.
    pub(crate) fn name(&self) -> &[u8] {
        cstr(&self.hdr.name)
    }

    /// The signed NAME section, the header's size of a name.
    pub(crate) fn signed_name(&self) -> Option<&[u8; NAME_MAX]> {
        self.signed_section(self.signed.name.as_ref())?
            .try_into()
            .ok()
    }

    /// Whether the header's name is the one the signature covers, every
    /// byte of its field.
    pub(crate) fn name_signed(&self) -> bool {
        self.signed_name() == Some(&self.hdr.name)
    }

    /// The header's name as a program name: up to `out`'s room less one,
    /// any other byte than `[A-Za-z0-9_.]` as '_', and zeros after.
    pub(crate) fn prog_name(&self, out: &mut [u8]) {
        let name = self.name();

        if out.is_empty() {
            return;
        }
        out.fill(0);
        let n = name.len().min(out.len() - 1);
        for (o, &c) in out.iter_mut().zip(&name[..n]) {
            *o = if prog_name_char(c) { c } else { b'_' };
        }
    }

    /// The signed attach metadata.
    pub(crate) fn signed_attach(&self) -> Option<&[u8]> {
        self.signed_section(self.signed.attach.as_ref())
    }

    /// The signed digest of the payload an unload directive unloads.
    pub(crate) fn signed_unload_payload(&self) -> Option<&[u8; PAYLOAD_HASH_LEN]> {
        self.signed_section(self.signed.unload_payload.as_ref())?
            .try_into()
            .ok()
    }

    /// The signed policy labels, which parse_policy_labels() checked.
    pub(crate) fn policy_labels(&self) -> Option<PolicyLabels<'_>> {
        let p = self.signed.policy_labels.as_ref()?;

        Some(PolicyLabels {
            labels: self.signed_section(Some(&p.at))?,
            map_idx: p.map_idx,
            socket_map_idx: p.socket_map_idx,
        })
    }

    pub(crate) fn has_decoders(&self) -> bool {
        self.signed.decoders.is_some()
    }

    /// Decoder `idx` of the signed DECODERS section, which
    /// parse_decoders() checked.
    pub(crate) fn decoder(&self, idx: u32) -> Option<Decoder<'_>> {
        let decoders = self.signed.decoders.as_ref().filter(|d| idx < d.count)?;
        let blob = self.signed_section(Some(&decoders.at))?;
        let d = blob
            .get(DECODER_BLOB + idx as usize * DECODER_ENTRY..)?
            .get(..DECODER_ENTRY)?;
        let source_off = le32(d, 192) as usize;
        let source_len = le32(d, 196) as usize;
        Some(Decoder {
            language: le32(d, 0),
            api_version: le32(d, 4),
            input_format: le32(d, 8),
            export_signal: le32(d, 12),
            upatch: d[16..80].try_into().ok()?,
            map: d[80..96].try_into().ok()?,
            source_name: d[96..160].try_into().ok()?,
            entrypoint: d[160..192].try_into().ok()?,
            source: blob.get(source_off..)?.get(..source_len)?,
        })
    }

    /// The decoders of the signed DECODERS section, in order.
    pub(crate) fn decoders(&self) -> impl Iterator<Item = Decoder<'_>> {
        let count = self.signed.decoders.as_ref().map_or(0, |d| d.count);

        (0..count).filter_map(|i| self.decoder(i))
    }

    pub(crate) fn is_unload(&self) -> bool {
        self.hdr.flags & DIRECTIVE_UNLOAD != 0
    }

    /// The signed payload type, BPF for legacy payloads without a TYPE
    /// section.
    pub(crate) fn signed_type(&self) -> u32 {
        self.signed_section(self.signed.ty.as_ref())
            .map(|ty| le32(ty, 0))
            .unwrap_or(TYPE_BPF)
    }

    /// The signed Java agent jar.
    pub(crate) fn signed_jar(&self) -> Option<&[u8]> {
        self.signed_section(self.signed.jar.as_ref())
    }

    pub(crate) fn is_java(&self) -> bool {
        self.hdr.ty == TYPE_JAVA
    }

    /// What the payload is: a BPF program or a Java agent.
    pub(crate) fn payload_type(&self) -> &'static [u8] {
        if self.is_java() { b"java" } else { b"bpf" }
    }
}

fn prog_name_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'.'
}

/// The bpffs name of upatch `name`: bpffs reserves dots in a path
/// component, so each becomes `~d`, which no name has.
pub(crate) fn pin_name(name: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; name.len().saturating_mul(2)];
    let used = pin_name_into(name, &mut out);
    out.truncate(used);
    out
}

/// Write the pin spelling of `name` into room for twice its length.
fn pin_name_into(name: &[u8], out: &mut [u8]) -> usize {
    let mut used = 0;
    for &byte in name {
        if byte == b'.' {
            out[used] = b'~';
            out[used + 1] = b'd';
            used += 2;
        } else {
            out[used] = byte;
            used += 1;
        }
    }
    used
}

/// The upatch name a bpffs pin spells, `~d` a dot again; none for
/// another `~`.
pub(crate) fn name_from_pin(pin: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![0u8; pin.len()];
    let used = name_from_pin_into(pin, &mut out)?;
    out.truncate(used);
    Some(out)
}

/// Decode into room for every input byte. Return the written length.
fn name_from_pin_into(pin: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut at = 0;
    let mut used = 0;
    while at < pin.len() {
        let byte = pin[at];
        at += 1;
        if byte == b'~' {
            if pin.get(at) != Some(&b'd') {
                return None;
            }
            out[used] = b'.';
            at += 1;
        } else {
            out[used] = byte;
        }
        used += 1;
    }
    Some(used)
}

/// An upatch name: `[A-Za-z0-9._-]+`, not starting with '.', whose pin
/// name, each dot doubled, fits NAME_MAX.
pub(crate) fn name_valid(name: Option<&[u8]>) -> bool {
    let Some(name) = name else {
        return false;
    };
    if name.first().is_none_or(|&c| c == b'.') {
        return false;
    }
    let mut pin = 0;
    for &c in name {
        if !(c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-') {
            return false;
        }
        pin += if c == b'.' { 2 } else { 1 };
        if pin > PIN_NAME_MAX {
            return false;
        }
    }
    true
}

/// A member of a measured set: an upatch name and the hex of a payload
/// digest, two digits a byte.
pub(crate) fn member_valid(name: &[u8], payload_hex: &[u8]) -> bool {
    let mut payload = [0u8; PAYLOAD_HASH_LEN];

    name_valid(Some(name)) && hex::decode(payload_hex, &mut payload).is_ok()
}

/// The spec of a program an attach role gave: its kind, offset and
/// target from its entry `e`, or an XDP program's device classes, each
/// class one program's of the upatch, as `xdp_classes` gathers them: a
/// device runs one native XDP program at a time. Ok(true) for a uprobe,
/// whose binary comes after, or the second true for a kprobe multi whose
/// names come after; Err(()) for an entry that breaks the rules.
fn attach_spec(spec: &mut ProgSpec, e: &[u8], xdp_classes: &mut u32) -> Result<(bool, bool), ()> {
    let kind = le32(e, 4);
    let raw_offset = le64(e, 8);
    let target = &e[16..16 + ATTACH_TARGET_MAX];
    let map = &e[16 + ATTACH_TARGET_MAX..];
    let mut uprobe = false;

    if map[0] != 0 {
        return Err(());
    }
    spec.role = ROLE_ATTACH;
    match kind {
        ATTACH_XDP => {
            let classes = le32(e, 8);
            if classes == 0
                || classes & !XDP_ALL != 0
                || classes & *xdp_classes != 0
                || le32(e, 12) != 0
                || target.iter().any(|&c| c != 0)
                || map.iter().any(|&c| c != 0)
            {
                return Err(());
            }
            *xdp_classes |= classes;
            spec.device_classes = classes;
            spec.kind = kind;
            return Ok((false, false));
        }
        ATTACH_RAW_TRACEPOINT
        | ATTACH_CGROUP_SKB_INGRESS
        | ATTACH_CGROUP_SKB_EGRESS
        | ATTACH_NETFILTER_IPV6_PRE_ROUTING
        | ATTACH_FMOD_RET => {
            spec.kind = kind;
            return if target[0] != 0 || raw_offset != 0 {
                Err(())
            } else {
                Ok((false, false))
            };
        }
        ATTACH_KPROBE_MULTI | ATTACH_KRETPROBE_MULTI => {
            if target[0] != 0 || raw_offset != 0 {
                return Err(());
            }
            spec.kind = kind;
            return Ok((false, true));
        }
        ATTACH_KPROBE | ATTACH_KRETPROBE => {}
        ATTACH_UPROBE_MULTI | ATTACH_URETPROBE_MULTI => {
            if raw_offset != 0 {
                return Err(());
            }
            uprobe = true;
        }
        ATTACH_UPROBE | ATTACH_URETPROBE => uprobe = true,
        _ => return Err(()),
    }
    if !has_nul(target) || target[0] == 0 {
        return Err(());
    }
    spec.kind = kind;
    spec.offset = raw_offset;
    spec.target.copy_from_slice(target);
    spec.target[ATTACH_TARGET_MAX - 1] = 0;
    if (kind == ATTACH_KRETPROBE || kind == ATTACH_URETPROBE) && spec.offset != 0 {
        return Err(());
    }
    let len = spec.target.iter().position(|&c| c == 0).unwrap_or(0);
    if kind_is_uprobe_multi(kind) && spec.target[..len].iter().any(|&c| c == b',' || c == b'|') {
        return Err(());
    }
    Ok((uprobe, false))
}

/// The UPUT block at `cursor` of `m`: a target for each of the
/// `nr_uprobes` programs that attach to a binary, one offset for a single
/// probe, onto their specs. The block's end, or -errno.
fn uprobe_targets(
    m: &[u8],
    mut cursor: usize,
    specs: &mut [ProgSpec],
    nr_uprobes: u32,
) -> Result<usize, c_int> {
    let end = m.len();

    if end - cursor < UPROBE_TARGETS {
        return Err(-EINVAL);
    }
    let targets = &m[cursor..cursor + UPROBE_TARGETS];
    cursor += UPROBE_TARGETS;
    let nr_targets = le32(targets, 8);
    if le32(targets, 0) != UPROBE_TARGET_MAGIC
        || le32(targets, 4) != UPROBE_TARGET_VERSION
        || le32(targets, 12) != 0
        || nr_targets != nr_uprobes
    {
        return Err(-EINVAL);
    }
    for _ in 0..nr_targets {
        if end - cursor < UPROBE_TARGET {
            return Err(-EINVAL);
        }
        let record = &m[cursor..cursor + UPROBE_TARGET];
        cursor += UPROBE_TARGET;
        let prog_idx = le32(record, 0) as usize;
        let path_len = le32(record, 4);
        let build_id_len = le32(record, 8);
        let nr_offsets = le32(record, 12);
        let Some(spec) = specs.get_mut(prog_idx) else {
            return Err(-EINVAL);
        };
        if !kind_has_uprobe_target(spec.kind)
            || !spec.uprobe_path.is_empty()
            || path_len == 0
            || path_len >= UPROBE_PATH_MAX
            || build_id_len == 0
            || build_id_len as usize > BUILD_ID_MAX
            || nr_offsets == 0
            || nr_offsets > UPROBE_OFFSETS_MAX
            || (kind_is_uprobe_single(spec.kind) && nr_offsets != 1)
        {
            return Err(-EINVAL);
        }
        let (path_len, build_id_len) = (path_len as usize, build_id_len as usize);
        let payload_len = path_len + build_id_len + nr_offsets as usize * size_of::<u64>();
        if end - cursor < payload_len || m[cursor] != b'/' || has_nul(&m[cursor..][..path_len]) {
            return Err(-EINVAL);
        }
        spec.uprobe_path
            .try_reserve_exact(path_len + 1)
            .map_err(|_| -ENOMEM)?;
        spec.uprobe_path
            .extend_from_slice(&m[cursor..cursor + path_len]);
        spec.uprobe_path.push(0);
        cursor += path_len;
        spec.build_id[..build_id_len].copy_from_slice(&m[cursor..][..build_id_len]);
        spec.build_id_len = build_id_len as u32;
        cursor += build_id_len;
        spec.uprobe_offsets
            .try_reserve_exact(nr_offsets as usize)
            .map_err(|_| -ENOMEM)?;
        spec.uprobe_offsets.resize(nr_offsets as usize, 0);
        spec.nr_uprobe_offsets = nr_offsets;
        let offsets = &mut spec.uprobe_offsets;
        for j in 0..offsets.len() {
            offsets[j] = le64(m, cursor);
            cursor += size_of::<u64>();
            if j > 0 && offsets[j] <= offsets[j - 1] {
                return Err(-EINVAL);
            }
        }
    }
    if specs
        .iter()
        .any(|s| kind_has_uprobe_target(s.kind) && s.uprobe_path.is_empty())
    {
        return Err(-EINVAL);
    }
    Ok(cursor)
}

/// The signed names of one kprobe multi target into `spec`.
fn kprobe_syms(syms: &[u8], nr_syms: u32, spec: &mut ProgSpec) -> c_int {
    let mut off = 0usize;
    let mut previous: Option<&[u8]> = None;

    for _ in 0..nr_syms {
        if off >= syms.len() {
            return -EINVAL;
        }
        let Some(len) = syms[off..].iter().position(|&c| c == 0) else {
            return -EINVAL;
        };
        let name = &syms[off..off + len];
        if !kprobe_sym_valid(name) || previous.is_some_and(|p| p >= name) {
            return -EINVAL;
        }
        previous = Some(name);
        off += len + 1;
    }
    if off != syms.len() {
        return -EINVAL;
    }

    if spec.kprobe_sym_buf.try_reserve_exact(syms.len()).is_err() {
        return -ENOMEM;
    }
    spec.kprobe_sym_buf.extend_from_slice(syms);
    if spec
        .kprobe_sym_offsets
        .try_reserve_exact(nr_syms as usize)
        .is_err()
    {
        return -ENOMEM;
    }
    spec.nr_kprobe_syms = nr_syms;
    off = 0;
    for _ in 0..nr_syms {
        spec.kprobe_sym_offsets.push(off);
        let Some(len) = syms[off..].iter().position(|&c| c == 0) else {
            return -EINVAL;
        };
        off += len + 1;
    }
    0
}

/// The UPKS block at `cursor`: a sorted name list for each kprobe multi
/// program. The block's end, or -errno.
fn kprobe_targets(
    m: &[u8],
    mut cursor: usize,
    specs: &mut [ProgSpec],
    nr_kprobe_multis: u32,
) -> Result<usize, c_int> {
    if m.len() - cursor < KPROBE_TARGETS {
        return Err(-EINVAL);
    }
    let targets = &m[cursor..cursor + KPROBE_TARGETS];
    cursor += KPROBE_TARGETS;
    if le32(targets, 0) != KPROBE_TARGET_MAGIC
        || le32(targets, 4) != KPROBE_TARGET_VERSION
        || le32(targets, 8) != nr_kprobe_multis
        || le32(targets, 12) != 0
    {
        return Err(-EINVAL);
    }
    for _ in 0..nr_kprobe_multis {
        if m.len() - cursor < KPROBE_TARGET {
            return Err(-EINVAL);
        }
        let record = &m[cursor..cursor + KPROBE_TARGET];
        cursor += KPROBE_TARGET;
        let prog_idx = le32(record, 0) as usize;
        let nr_syms = le32(record, 4);
        let syms_len = le32(record, 8) as usize;
        let Some(spec) = specs.get_mut(prog_idx) else {
            return Err(-EINVAL);
        };
        if !kind_is_kprobe_multi(spec.kind)
            || !spec.kprobe_sym_offsets.is_empty()
            || nr_syms == 0
            || nr_syms > KPROBE_SYMS_MAX
            || syms_len / 2 < nr_syms as usize
            || m.len() - cursor < syms_len
        {
            return Err(-EINVAL);
        }
        let ret = kprobe_syms(&m[cursor..cursor + syms_len], nr_syms, spec);
        if ret != 0 {
            return Err(ret);
        }
        cursor += syms_len;
    }
    if specs
        .iter()
        .any(|s| kind_is_kprobe_multi(s.kind) && s.kprobe_sym_offsets.is_empty())
    {
        return Err(-EINVAL);
    }
    Ok(cursor)
}

/// Fill the programs from signed metadata, or return -errno. Any
/// buffers already filled are dropped with the specs on failure.
fn specs_fill(specs: &mut [ProgSpec], m: &[u8], base_len: usize) -> c_int {
    let (mut nr_uprobes, mut nr_kprobe_multis, mut xdp_classes) = (0u32, 0u32, 0u32);

    for (i, spec) in specs.iter_mut().enumerate() {
        let e = &m[PROG_METADATA + i * PROG_ENTRY..][..PROG_ENTRY];
        let map = &e[16 + ATTACH_TARGET_MAX..];

        match le32(e, 0) {
            ROLE_ATTACH => match attach_spec(spec, e, &mut xdp_classes) {
                Ok((uprobe, kprobe_multi)) => {
                    nr_uprobes += u32::from(uprobe);
                    nr_kprobe_multis += u32::from(kprobe_multi);
                }
                Err(()) => return -EINVAL,
            },
            ROLE_SERIALIZER => {
                if le32(e, 4) != 0 || le64(e, 8) != 0 || e[16] != 0 {
                    return -EINVAL;
                }
                if !has_nul(map) || map[0] == 0 {
                    return -EINVAL;
                }
                spec.role = ROLE_SERIALIZER;
                spec.map.copy_from_slice(map);
                spec.map[PROG_MAP_MAX - 1] = 0;
            }
            ROLE_TEST_RUN => {
                if le32(e, 4) != 0 || le64(e, 8) != 0 || e[16] != 0 || map[0] != 0 {
                    return -EINVAL;
                }
                spec.role = ROLE_TEST_RUN;
            }
            _ => return -EINVAL,
        }
    }
    let mut end = if nr_uprobes != 0 {
        match uprobe_targets(m, base_len, specs, nr_uprobes) {
            Ok(end) => end,
            Err(err) => return err,
        }
    } else {
        base_len
    };
    if nr_kprobe_multis != 0 {
        end = match kprobe_targets(m, end, specs, nr_kprobe_multis) {
            Ok(end) => end,
            Err(err) => return err,
        };
    }
    if end != m.len() { -EINVAL } else { 0 }
}

/// The parsed programs and their owned attach targets.
pub(crate) struct Specs {
    entries: Vec<ProgSpec>,
}

impl Specs {
    /// The specs of the metadata `m`, `nr_progs` of them for a loader of
    /// `nr_maps` maps: -EINVAL for metadata that breaks a rule or counts
    /// others, -EOPNOTSUPP for another version, -EOVERFLOW or -ENOMEM.
    pub(crate) fn parse(m: &[u8], nr_maps: u32, nr_progs: u32) -> Result<Self, c_int> {
        if m.len() < size_of::<u32>() || le32(m, 0) != PROG_MAGIC || m.len() < PROG_METADATA {
            return Err(-EINVAL);
        }
        if le32(m, 4) != PROG_VERSION {
            return Err(-EOPNOTSUPP);
        }
        if le32(m, 8) != nr_progs || le32(m, 12) != nr_maps {
            return Err(-EINVAL);
        }
        let base_len = PROG_METADATA + nr_progs as usize * PROG_ENTRY;
        if base_len > u32::MAX as usize {
            return Err(-EOVERFLOW);
        }
        if m.len() < base_len {
            return Err(-EINVAL);
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(nr_progs as usize)
            .map_err(|_| -ENOMEM)?;
        entries.resize_with(nr_progs as usize, ProgSpec::new);
        let mut specs = Specs { entries };
        match specs_fill(specs.as_mut_slice(), m, base_len) {
            0 => Ok(specs),
            err => Err(err),
        }
    }

    pub(crate) fn as_slice(&self) -> &[ProgSpec] {
        &self.entries
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [ProgSpec] {
        &mut self.entries
    }
}

#[cfg(kani)]
#[path = "upatch/kani.rs"]
mod proofs;
#[cfg(test)]
mod tests;

#[cfg(shirudo_fuzz)]
mod fuzz;
