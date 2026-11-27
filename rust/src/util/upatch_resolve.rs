// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! What the pins of a loaded upatch say about it: its link, the hook it
//! attaches to as a SEC()-style string, when it was loaded and the
//! payload digest bpf2's xattr guard keeps on them.

use core::ffi::{CStr, c_int};
use std::ffi::{CString, OsStr};
use std::fs;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

use crate::bpf::btf::Btf;
use crate::errno::{EINVAL, ENAMETOOLONG, ENOENT};
use crate::sys::libc::if_indextoname;
use crate::text::{strscpy, strsprintf};
use crate::util::bpf_info::{Info, LINK_INFO_SIZE, PROG_INFO_SIZE};
use crate::util::bpf_sys::{self, bpf_prog_get_fd_by_id, prog_type_name};
use crate::util::timefmt::iso8601;
use crate::util::upatch::{NAME_MAX, pin_name};
use crate::util::upatch_pins::{Pins, each_link, pin_payload, xdp_prog_open, xdp_prog_pin};

/// BPFFS_UPATCHES_DIR and XATTR_PAYLOAD of util/paths.h.
pub(crate) const BPFFS_UPATCHES_DIR: &str = "/run/shirudo/bpffs/upatches";
pub(crate) const XATTR_PAYLOAD: &CStr = c"security.bpf.shirudo.payload";
const PATH_MAX: usize = 4096;
const LOCATION_MAX: usize = 160;

/// Where `struct bpf_link_info` and `struct bpf_prog_info` keep the
/// fields read here.
const LINK_TYPE: usize = 0;
const LINK_PROG_ID: usize = 8;
const LINK_TRACING_ATTACH_TYPE: usize = 16;
const LINK_UPROBE_PATH: usize = 16;
const LINK_UPROBE_PATH_SIZE: usize = 48;
const LINK_UPROBE_COUNT: usize = 52;
const LINK_NETFILTER_PF: usize = 16;
const LINK_NETFILTER_HOOKNUM: usize = 20;
const LINK_NETFILTER_PRIORITY: usize = 24;
const LINK_UPROBE_FLAGS: usize = 56;
const LINK_KPROBE_COUNT: usize = 24;
const LINK_KPROBE_FLAGS: usize = 28;
const LINK_KPROBE_MISSED: usize = 32;
const LINK_PERF_KPROBE_MISSED: usize = 48;
const LINK_XDP_IFINDEX: usize = 16;
const LINK_PERF_EVENT_TYPE: usize = 16;
const LINK_PERF_UPROBE_FILE_NAME: usize = 24;
const LINK_PERF_UPROBE_NAME_LEN: usize = 32;
const LINK_PERF_UPROBE_OFFSET: usize = 36;
const PROG_TYPE: usize = 0;
const PROG_ATTACH_BTF_ID: usize = 224;
const PROG_RECURSION_MISSES: usize = 208;

const BPF_LINK_TYPE_RAW_TRACEPOINT: u32 = 1;
const BPF_LINK_TYPE_TRACING: u32 = 2;
const BPF_LINK_TYPE_NETFILTER: u32 = 10;
const BPF_LINK_TYPE_UPROBE_MULTI: u32 = 12;
const BPF_LINK_TYPE_KPROBE_MULTI: u32 = 8;
const BPF_LINK_TYPE_XDP: u32 = 6;
const BPF_LINK_TYPE_PERF_EVENT: u32 = 7;
const BPF_PERF_EVENT_UPROBE: u32 = 1;
const BPF_PERF_EVENT_URETPROBE: u32 = 2;
const BPF_PERF_EVENT_KPROBE: u32 = 3;
const BPF_PERF_EVENT_KRETPROBE: u32 = 4;
const BPF_F_UPROBE_MULTI_RETURN: u32 = 1;
const BPF_F_KPROBE_MULTI_RETURN: u32 = 1;
const BPF_PROG_TYPE_TRACING: u32 = 26;
const BPF_PROG_TYPE_LSM: u32 = 29;
const BPF_PROG_TYPE_NETFILTER: u32 = 32;
const BPF_TRACE_RAW_TP: u32 = 23;
const BPF_TRACE_FENTRY: u32 = 24;
const BPF_TRACE_FEXIT: u32 = 25;
const BPF_MODIFY_RETURN: u32 = 26;
const BPF_LSM_MAC: u32 = 27;
const BPF_TRACE_ITER: u32 = 28;
/// NFPROTO_IPV6, NF_INET_PRE_ROUTING and NF_IP6_PRI_RAW_BEFORE_DEFRAG.
const NFPROTO_IPV6: u32 = 10;
const NF_INET_PRE_ROUTING: u32 = 0;
const NF_IP6_PRI_RAW_BEFORE_DEFRAG: i32 = -450;

/// The pin directory of upatch `name`, and below it each of `parts`;
/// -ENAMETOOLONG for a name or a path too long.
pub(crate) fn pin_path(name: &[u8], parts: &[&[u8]]) -> Result<CString, c_int> {
    if name.len() > NAME_MAX {
        return Err(-ENAMETOOLONG);
    }
    let mut path = [BPFFS_UPATCHES_DIR.as_bytes(), b"/", &pin_name(name)].concat();
    for p in parts {
        path.extend_from_slice(b"/");
        path.extend_from_slice(p);
    }
    if path.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    CString::new(path).map_err(|_| -EINVAL)
}

/// The first link pinned for upatch `name`: "link" for one program,
/// "link_0" of "link_0", "link_1", ... for more. Its descriptor, or
/// the first pin's error when neither is there.
pub(crate) fn open_first_link(name: &[u8]) -> Result<OwnedFd, c_int> {
    let first = pin_path(name, &[b"link"])?;
    let first_error = match bpf_sys::obj_get(&first) {
        Ok(fd) => return Ok(fd),
        Err(err) => err,
    };
    let second = pin_path(name, &[b"link_0"])?;
    match bpf_sys::obj_get(&second) {
        Ok(fd) => Ok(fd),
        Err(err) if err == -ENOENT => Err(first_error),
        Err(err) => Err(err),
    }
}

/// Open the program by id, keeping its descriptor until the caller drops it.
fn open_prog(id: u32) -> Result<OwnedFd, c_int> {
    let fd = bpf_prog_get_fd_by_id(id);
    if fd < 0 {
        return Err(fd);
    }
    // SAFETY: the kernel returned a new descriptor owned here alone.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The SEC() prefix of a program of `prog_type` attached as
/// `attach_type`, where its type alone does not say it.
fn sec_prefix(prog_type: u32, attach_type: u32) -> Option<&'static [u8]> {
    match (prog_type, attach_type) {
        (BPF_PROG_TYPE_LSM, _) => Some(b"lsm"),
        (BPF_PROG_TYPE_NETFILTER, _) => Some(b"netfilter"),
        (BPF_PROG_TYPE_TRACING, BPF_TRACE_FENTRY) => Some(b"fentry"),
        (BPF_PROG_TYPE_TRACING, BPF_TRACE_FEXIT) => Some(b"fexit"),
        (BPF_PROG_TYPE_TRACING, BPF_MODIFY_RETURN) => Some(b"fmod_ret"),
        (BPF_PROG_TYPE_TRACING, BPF_TRACE_RAW_TP) => Some(b"tp_btf"),
        (BPF_PROG_TYPE_TRACING, BPF_TRACE_ITER) => Some(b"iter"),
        _ => None,
    }
}

/// The kind of the program behind a tracing link as a location names it:
/// fentry, fexit, fmod_ret or lsm. None for another link type.
pub(crate) fn tracing_link_kind(info: &Info<LINK_INFO_SIZE>) -> Option<&'static [u8]> {
    if info.u32_at(LINK_TYPE) != BPF_LINK_TYPE_TRACING {
        return None;
    }
    let attach_type = info.u32_at(LINK_TRACING_ATTACH_TYPE);
    let prog_type = if attach_type == BPF_LSM_MAC {
        BPF_PROG_TYPE_LSM
    } else {
        BPF_PROG_TYPE_TRACING
    };
    sec_prefix(prog_type, attach_type)
}

/// A kprobe-multi link's kind and function count.
fn kprobe_multi(info: &Info<LINK_INFO_SIZE>, out: &mut [u8]) -> c_int {
    let kind: &[u8] = if info.u32_at(LINK_KPROBE_FLAGS) & BPF_F_KPROBE_MULTI_RETURN != 0 {
        b"kretprobe.multi"
    } else {
        b"kprobe.multi"
    };
    strsprintf(
        out,
        &[
            kind,
            b" (",
            info.u32_at(LINK_KPROBE_COUNT).to_string().as_bytes(),
            b" funcs)",
        ],
    )
    .map_or_else(|e| e, |_| 0)
}

/// A uprobe-multi link's location: its binary and how many functions.
fn uprobe_multi(link: BorrowedFd<'_>, first: &Info<LINK_INFO_SIZE>, out: &mut [u8]) -> c_int {
    let count = first.u32_at(LINK_UPROBE_COUNT);
    let path_size = first.u32_at(LINK_UPROBE_PATH_SIZE);
    if path_size == 0 || path_size as usize > PATH_MAX {
        return -EINVAL;
    }
    let mut path = vec![0u8; path_size as usize];
    let mut detail = Info::<LINK_INFO_SIZE>::new();
    detail.set(LINK_UPROBE_PATH, &(path.as_mut_ptr() as u64).to_ne_bytes());
    detail.set(LINK_UPROBE_PATH_SIZE, &path_size.to_ne_bytes());
    let ret = detail.read(link.as_raw_fd()).err().unwrap_or(0);
    if ret != 0 {
        return ret;
    }
    let Some(end) = path.iter().position(|&c| c == 0) else {
        return -EINVAL;
    };
    let kind: &[u8] = if first.u32_at(LINK_UPROBE_FLAGS) & BPF_F_UPROBE_MULTI_RETURN != 0 {
        b"uretprobe.multi/"
    } else {
        b"uprobe.multi/"
    };
    strsprintf(
        out,
        &[
            kind,
            &path[..end],
            b" (",
            count.to_string().as_bytes(),
            b" funcs)",
        ],
    )
    .map_or_else(|e| e, |_| 0)
}

/// Calls `cb` with each link of upatch `name`, its index, its pin and what
/// the kernel says of it; a link whose pin cannot be opened or read ends
/// the walk with its -errno.
pub(crate) fn each_link_info(
    name: &[u8],
    cb: &mut dyn FnMut(u32, &CStr, &Info<LINK_INFO_SIZE>) -> c_int,
) -> c_int {
    each_link(name, &mut |index, pin| {
        let fd = match bpf_sys::obj_get(pin) {
            Ok(fd) => fd,
            Err(err) => return err,
        };
        let mut info = Info::<LINK_INFO_SIZE>::new();
        let ret = info.read(fd.as_raw_fd()).err().unwrap_or(0);
        drop(fd);
        if ret != 0 { ret } else { cb(index, pin, &info) }
    })
}

/// The program id of upatch `name`: its first link's, or with no link an
/// XDP program pin's.
pub(crate) fn first_prog_id(name: &[u8]) -> Result<u32, c_int> {
    match open_first_link(name) {
        Ok(fd) => {
            let mut linfo = Info::<LINK_INFO_SIZE>::new();
            let ret = linfo.read(fd.as_raw_fd());
            drop(fd);
            ret?;
            let id = linfo.u32_at(LINK_PROG_ID);
            return if id != 0 { Ok(id) } else { Err(-EINVAL) };
        }
        Err(err) if err == -ENOENT => {}
        Err(err) => return Err(err),
    }
    let pins = Pins::read(name)?;
    if pins.nr_xdp_progs == 0 {
        return Err(-ENOENT);
    }
    let (_, id) = xdp_prog_open(name, pins.first_xdp_prog)?;
    if id != 0 { Ok(id) } else { Err(-EINVAL) }
}

/// Where an XDP upatch runs: the device of its lowest live link, and how
/// many more; the kernel clears a link's ifindex when its device goes.
fn xdp_location(name: &[u8], out: &mut [u8]) -> c_int {
    let (mut lowest, mut live, mut device) = (0u32, 0u32, Vec::new());
    let ret = each_link_info(name, &mut |index, _, info| {
        let ifindex = info.u32_at(LINK_XDP_IFINDEX);
        if info.u32_at(LINK_TYPE) != BPF_LINK_TYPE_XDP || ifindex == 0 {
            return 0;
        }
        if live == 0 || index < lowest {
            lowest = index;
            let mut buf = [0u8; 16];
            // SAFETY: an ifindex and room for a name.
            let named = unsafe { if_indextoname(ifindex, buf.as_mut_ptr().cast()) };
            device = if named.is_null() {
                format!("ifindex:{ifindex}").into_bytes()
            } else {
                crate::text::cstr(&buf).to_vec()
            };
        }
        live += 1;
        0
    });
    if ret != 0 {
        return ret;
    }
    let text = match live {
        0 => b"xdp (waiting for a device)".to_vec(),
        1 => [&b"xdp/"[..], &device].concat(),
        n => format!("xdp/{} (+{})", String::from_utf8_lossy(&device), n - 1).into_bytes(),
    };
    strsprintf(out, &[&text]).map_or_else(|e| e, |_| 0)
}

fn link_is_uprobe(linfo: &Info<LINK_INFO_SIZE>) -> bool {
    linfo.u32_at(LINK_TYPE) == BPF_LINK_TYPE_PERF_EVENT
        && matches!(
            linfo.u32_at(LINK_PERF_EVENT_TYPE),
            BPF_PERF_EVENT_UPROBE | BPF_PERF_EVENT_URETPROBE
        )
}

/// A uprobe or uretprobe link's location: its binary and offset.
fn uprobe_location(link: BorrowedFd<'_>, out: &mut [u8]) -> c_int {
    let mut path = vec![0u8; PATH_MAX];
    let mut linfo = Info::<LINK_INFO_SIZE>::new();
    linfo.set(
        LINK_PERF_UPROBE_FILE_NAME,
        &(path.as_mut_ptr() as u64).to_ne_bytes(),
    );
    linfo.set(LINK_PERF_UPROBE_NAME_LEN, &(PATH_MAX as u32).to_ne_bytes());
    if let Err(err) = linfo.read(link.as_raw_fd()) {
        return err;
    }
    let Some(end) = path.iter().position(|&c| c == 0) else {
        return -EINVAL;
    };
    if !link_is_uprobe(&linfo) {
        return -EINVAL;
    }
    let kind: &[u8] = if linfo.u32_at(LINK_PERF_EVENT_TYPE) == BPF_PERF_EVENT_URETPROBE {
        b"uretprobe/"
    } else {
        b"uprobe/"
    };
    let offset = format!("+0x{:x}", linfo.u32_at(LINK_PERF_UPROBE_OFFSET));
    strsprintf(out, &[kind, &path[..end], offset.as_bytes()]).map_or_else(|e| e, |_| 0)
}

/// A copied location is empty when it does not fit, as formatted ones are.
fn location_copy(out: &mut [u8], text: &[u8]) -> c_int {
    match strscpy(out, text) {
        Ok(_) => 0,
        Err(e) => {
            if let Some(first) = out.first_mut() {
                *first = 0;
            }
            e
        }
    }
}

/// Where one link attaches, using program information already read when
/// provided. The caller keeps `link` open through this call.
fn link_location(
    vbtf: Option<&Btf>,
    link: BorrowedFd<'_>,
    linfo: &Info<LINK_INFO_SIZE>,
    pinfo: Option<&Info<PROG_INFO_SIZE>>,
    out: &mut [u8],
) -> c_int {
    let link_type = linfo.u32_at(LINK_TYPE);
    if link_type == BPF_LINK_TYPE_KPROBE_MULTI {
        return kprobe_multi(linfo, out);
    }
    if link_type == BPF_LINK_TYPE_UPROBE_MULTI {
        return uprobe_multi(link, linfo, out);
    }
    if link_is_uprobe(linfo) {
        return uprobe_location(link, out);
    }
    let attach_type = if link_type == BPF_LINK_TYPE_TRACING {
        linfo.u32_at(LINK_TRACING_ATTACH_TYPE)
    } else {
        0
    };
    if link_type == BPF_LINK_TYPE_NETFILTER
        && linfo.u32_at(LINK_NETFILTER_PF) == NFPROTO_IPV6
        && linfo.u32_at(LINK_NETFILTER_HOOKNUM) == NF_INET_PRE_ROUTING
        && linfo.u32_at(LINK_NETFILTER_PRIORITY) as i32 == NF_IP6_PRI_RAW_BEFORE_DEFRAG
    {
        return location_copy(out, b"netfilter/ipv6-pre-routing");
    }

    let mut read_info = Info::<PROG_INFO_SIZE>::new();
    let info = if let Some(info) = pinfo {
        info
    } else {
        let prog = match open_prog(linfo.u32_at(LINK_PROG_ID)) {
            Ok(prog) => prog,
            Err(err) => return err,
        };
        let ret = read_info.read(prog.as_raw_fd()).err().unwrap_or(0);
        drop(prog);
        if ret != 0 {
            return ret;
        }
        &read_info
    };
    let prog_type = info.u32_at(PROG_TYPE);
    let btf_id = info.u32_at(PROG_ATTACH_BTF_ID);
    let mut attach: &[u8] = vbtf
        .filter(|b| btf_id != 0 && b.has(btf_id))
        .and_then(|b| b.str_at(b.name_off(btf_id)))
        .unwrap_or_default();
    let prefix = sec_prefix(prog_type, attach_type)
        .unwrap_or_else(|| prog_type_name(prog_type).unwrap_or(b"?"));
    // The kernel names an LSM hook's attach point bpf_lsm_<hook>.
    if prog_type == BPF_PROG_TYPE_LSM {
        attach = attach.strip_prefix(b"bpf_lsm_").unwrap_or(attach);
    }
    if attach.is_empty() {
        return location_copy(out, prefix);
    }
    strsprintf(out, &[prefix, b"/", attach]).map_or_else(|e| e, |_| 0)
}

/// The SEC()-style hook and target of upatch `name`, or -errno.
pub(crate) fn resolve_location(vbtf: Option<&Btf>, name: &[u8]) -> Result<Vec<u8>, c_int> {
    let mut out = [0u8; LOCATION_MAX];
    let ret = resolve_location_into(vbtf, name, &mut out);
    if ret != 0 {
        return Err(ret);
    }
    Ok(crate::text::cstr(&out).to_vec())
}

/// Fill the fixed-size location field as the old formatter did.
fn resolve_location_into(vbtf: Option<&Btf>, name: &[u8], out: &mut [u8]) -> c_int {
    if let Some(first) = out.first_mut() {
        *first = 0;
    }
    let pins = match Pins::read(name) {
        Ok(pins) => pins,
        Err(err) => return err,
    };
    if pins.nr_xdp_progs != 0 {
        return xdp_location(name, out);
    }
    let link = match open_first_link(name) {
        Ok(link) => link,
        Err(err) => return err,
    };
    let mut linfo = Info::<LINK_INFO_SIZE>::new();
    match linfo.read(link.as_raw_fd()) {
        Err(err) => err,
        Ok(()) if linfo.u32_at(LINK_PROG_ID) == 0 => -EINVAL,
        Ok(()) => link_location(vbtf, link.as_fd(), &linfo, None, out),
    }
}

/// A counted link's location and the number of runs the kernel skipped.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LinkMisses {
    pub(crate) location: Vec<u8>,
    pub(crate) missed: u64,
}

fn link_is_kprobe(info: &Info<LINK_INFO_SIZE>) -> bool {
    info.u32_at(LINK_TYPE) == BPF_LINK_TYPE_PERF_EVENT
        && matches!(
            info.u32_at(LINK_PERF_EVENT_TYPE),
            BPF_PERF_EVENT_KPROBE | BPF_PERF_EVENT_KRETPROBE
        )
}

/// Whether the kernel counts skipped runs for this link kind.
pub(crate) fn link_counts_misses(info: &Info<LINK_INFO_SIZE>) -> bool {
    match info.u32_at(LINK_TYPE) {
        BPF_LINK_TYPE_KPROBE_MULTI | BPF_LINK_TYPE_RAW_TRACEPOINT => true,
        BPF_LINK_TYPE_PERF_EVENT => link_is_kprobe(info),
        BPF_LINK_TYPE_TRACING => matches!(
            info.u32_at(LINK_TRACING_ATTACH_TYPE),
            BPF_TRACE_FENTRY | BPF_TRACE_FEXIT | BPF_MODIFY_RETURN
        ),
        _ => false,
    }
}

/// A kprobe link also counts misses of the link itself.
pub(crate) fn link_missed(info: &Info<LINK_INFO_SIZE>) -> u64 {
    if info.u32_at(LINK_TYPE) == BPF_LINK_TYPE_KPROBE_MULTI {
        return info.u64_at(LINK_KPROBE_MISSED);
    }
    if link_is_kprobe(info) {
        return info.u64_at(LINK_PERF_KPROBE_MISSED);
    }
    0
}

fn total_link_missed(prog: &Info<PROG_INFO_SIZE>, link: &Info<LINK_INFO_SIZE>) -> u64 {
    prog.u64_at(PROG_RECURSION_MISSES)
        .wrapping_add(link_missed(link))
}

fn read_link_misses(
    vbtf: Option<&Btf>,
    pin: &CStr,
    with_location: bool,
) -> Result<Option<LinkMisses>, c_int> {
    let link = bpf_sys::obj_get(pin)?;
    let mut linfo = Info::<LINK_INFO_SIZE>::new();
    linfo.read(link.as_raw_fd())?;
    if !link_counts_misses(&linfo) {
        return Ok(None);
    }
    let prog = open_prog(linfo.u32_at(LINK_PROG_ID))?;
    let mut pinfo = Info::<PROG_INFO_SIZE>::new();
    pinfo.read(prog.as_raw_fd())?;
    let missed = total_link_missed(&pinfo, &linfo);
    let mut location = [0u8; LOCATION_MAX];
    if with_location {
        let ret = link_location(vbtf, link.as_fd(), &linfo, Some(&pinfo), &mut location);
        if ret != 0 {
            location[0] = 0;
        }
    }
    Ok(Some(LinkMisses {
        location: crate::text::cstr(&location).to_vec(),
        missed,
    }))
}

/// Visit a single `link` pin and every `link_<n>` pin. Links whose kind
/// does not count skipped runs are omitted.
fn walk_link_misses(
    vbtf: Option<&Btf>,
    name: &[u8],
    with_location: bool,
    cb: &mut dyn FnMut(LinkMisses),
) -> Result<(), c_int> {
    let pins = Pins::read(name)?;
    let mut visit = |pin: &CStr| -> c_int {
        match read_link_misses(vbtf, pin, with_location) {
            Ok(Some(m)) => {
                cb(m);
                0
            }
            Ok(None) => 0,
            Err(e) => e,
        }
    };
    if pins.has_link {
        let pin = pin_path(name, &[b"link"])?;
        let ret = visit(&pin);
        if ret != 0 {
            return Err(ret);
        }
    }
    match each_link(name, &mut |_, pin| visit(pin)) {
        0 => Ok(()),
        e => Err(e),
    }
}

/// The counted programs and their locations for `upatch get`.
pub(crate) fn each_link_misses(vbtf: Option<&Btf>, name: &[u8]) -> Result<Vec<LinkMisses>, c_int> {
    let mut links = Vec::new();
    walk_link_misses(vbtf, name, true, &mut |m| links.push(m))?;
    Ok(links)
}

/// Counted links and their total skipped runs for the status table.
pub(crate) fn missed_runs(name: &[u8]) -> Result<(u32, u64), c_int> {
    let mut count = 0u32;
    let mut missed = 0u64;
    walk_link_misses(None, name, false, &mut |m| {
        count = count.wrapping_add(1);
        missed = missed.wrapping_add(m.missed);
    })?;
    Ok((count, missed))
}

/// When upatch `name` was loaded, from its pin directory's change time;
/// empty when unknown. Later XDP links change the directory's ctime, so
/// an XDP upatch uses its first program pin.
pub(crate) fn loaded_at(name: &[u8]) -> Vec<u8> {
    let dir = match Pins::read(name) {
        Ok(p) if p.nr_xdp_progs != 0 => xdp_prog_pin(name, p.first_xdp_prog),
        Ok(_) => pin_path(name, &[]),
        Err(_) => return Vec::new(),
    };
    let Ok(dir) = dir else {
        return Vec::new();
    };
    let Ok(st) = fs::metadata(OsStr::from_bytes(dir.as_bytes())) else {
        return Vec::new();
    };
    let mut out = [0u8; 32];
    iso8601(st.ctime(), &mut out);
    crate::text::cstr(&out).to_vec()
}

/// The hex payload digest on the pins of upatch `name`; empty on any
/// failure.
pub(crate) fn payload_sha256(name: &[u8]) -> Vec<u8> {
    pin_payload(name)
        .map(|raw| crate::util::hex::encode(&raw))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
