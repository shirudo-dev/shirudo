// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Running a loader program: the bpf() attribute the loaders fill by
//! hand, the context a loader reads and writes its map and program
//! descriptors into, and the run of a light skeleton built into the
//! binary, which init loads bpf2 and the seal with.
//!
//! A loader is a BPF_PROG_TYPE_SYSCALL program over a map of its data.
//! Run once, it creates the object's maps and programs from kernel
//! context and leaves their descriptors in its context; it can neither
//! attach nor pin them, which its caller does.
//!
//! A skeleton built into the binary is embedded by the Rust tools/bpf-lskel
//! writes of it (rust/src/skel.rs), with typed handles to its maps and
//! programs, made from the Skeleton loaded here.

use core::ffi::{CStr, c_int};
use core::marker::PhantomData;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};

use crate::bpf::lskel::{Lskel, Program};
use crate::errno::{E2BIG, EINVAL, ENOENT};
use crate::sys::libc::{errno, fcntl};
use crate::util::bpf_sys::{
    Attr, BPF_ANY, BPF_MAP_CREATE, BPF_MAP_FREEZE, BPF_MAP_UPDATE_ELEM, BPF_PROG_LOAD,
    bpf_map_freeze, bpf_map_lookup_elem, bpf_map_update_elem, bpf_obj_pin, link_create,
    prog_test_run,
};

/// The room for the verifier's log.
pub(crate) const VERIFIER_LOG_MAX: usize = 16 * 1024 * 1024;

pub(crate) const MAP_TYPE_ARRAY: u32 = 2;
pub(crate) const PROG_TYPE_SYSCALL: u32 = 31;
pub(crate) const F_SLEEPABLE: u32 = 16;
const F_DUPFD_CLOEXEC: c_int = 1030;

/// `struct loader_ctx` of tools/lib/bpf/skel_internal.h, which the
/// loader reads, and the map and program descriptors after it, which it
/// fills and BPF_PROG_TEST_RUN copies back. Dropped, it closes what they
/// name: the caller's pins keep what was attached.
pub(crate) struct Ctx {
    pub(crate) buf: Vec<u8>,
    pub(crate) nr_maps: u32,
    nr_progs: u32,
}

impl Ctx {
    const HEADER: usize = 24;
    const MAP_DESC: usize = 16;
    const PROG_DESC: usize = 4;

    fn prog_desc_off(nr_maps: u32) -> usize {
        Self::HEADER.saturating_add((nr_maps as usize).saturating_mul(Self::MAP_DESC))
    }

    /// The context of `nr_maps` and `nr_progs`, with room for the
    /// loader's max_ctx_offset beyond the descriptors, which
    /// BPF_PROG_TEST_RUN takes no smaller: None when a syscall program
    /// takes no context that large.
    pub(crate) fn new(nr_maps: u32, nr_progs: u32, vlog: &mut [u8]) -> Option<Self> {
        let size = Self::prog_desc_off(nr_maps)
            .saturating_add((nr_progs as usize).saturating_mul(Self::PROG_DESC))
            .saturating_add(1024);
        if size > usize::from(u16::MAX) {
            return None;
        }
        let mut cx = Ctx {
            buf: vec![0; size],
            nr_maps,
            nr_progs,
        };
        cx.put(0, &(size as u32).to_ne_bytes());
        // Inner verifier diagnostics stay on without the full trace of
        // accepted programs, whose verbose mode can fail a valid payload
        // with -ENOSPC when the log fills.
        cx.put(8, &1u32.to_ne_bytes());
        cx.put(12, &(vlog.len().min(VERIFIER_LOG_MAX) as u32).to_ne_bytes());
        cx.put(16, &(vlog.as_mut_ptr() as u64).to_ne_bytes());
        Some(cx)
    }

    fn put(&mut self, off: usize, v: &[u8]) {
        self.buf[off..off + v.len()].copy_from_slice(v);
    }

    fn i32_at(&self, off: usize) -> i32 {
        let mut v = [0; 4];
        v.copy_from_slice(&self.buf[off..off + 4]);
        i32::from_ne_bytes(v)
    }

    pub(crate) fn map_fd(&self, i: u32) -> c_int {
        self.i32_at(Self::HEADER + i as usize * Self::MAP_DESC)
    }

    pub(crate) fn set_map_fd(&mut self, i: u32, fd: c_int) {
        self.put(
            Self::HEADER + i as usize * Self::MAP_DESC,
            &fd.to_ne_bytes(),
        );
    }

    pub(crate) fn prog_fd(&self, i: u32) -> c_int {
        self.i32_at(Self::prog_desc_off(self.nr_maps) + i as usize * Self::PROG_DESC)
    }

    /// Forgets the descriptors, which a failed loader closed itself: the
    /// numbers left name nothing of ours.
    pub(crate) fn forget(&mut self) {
        self.buf[Self::HEADER..].fill(0);
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        let fds = (0..self.nr_maps)
            .map(|i| self.map_fd(i))
            .chain((0..self.nr_progs).map(|i| self.prog_fd(i)));
        for fd in fds.filter(|&fd| fd > 0) {
            // SAFETY: the context owns loader results and the duplicates transferred
            // after success. Failure paths clear duplicate slots before their owners drop.
            let _ = unsafe { OwnedFd::from_raw_fd(fd) };
        }
    }
}

/// The log the verifier left, up to its NUL.
fn till_nul(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

fn show_log(what: &str, vlog: &[u8]) {
    let log = till_nul(vlog);
    if !log.is_empty() {
        let _ = std::io::stderr().write_all(&[what.as_bytes(), b":\n", log, b"\n"].concat());
    }
}

/// The step of a run that failed, and the negative errno.
pub(crate) type Failed = (&'static str, c_int);

/// Duplicate each reused map before passing it to the loader. On failure,
/// clear the context first so its drop cannot close a duplicate twice.
fn duplicate_shared_maps(
    cx: &mut Ctx,
    maps: impl Iterator<Item = usize>,
    shared: impl Fn(usize) -> Option<c_int>,
) -> Result<Vec<OwnedFd>, Failed> {
    let mut dups = Vec::new();
    for i in maps {
        let Some(fd) = shared(i) else {
            cx.forget();
            return Err(("shared map", -ENOENT));
        };
        // SAFETY: the caller's descriptor is valid for the duration of the call.
        let dup = unsafe { fcntl(fd, F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            let err = -errno();
            cx.forget();
            return Err(("shared map", err));
        }
        // SAFETY: fcntl made a new descriptor, owned until the loader succeeds.
        let dup = unsafe { OwnedFd::from_raw_fd(dup) };
        cx.set_map_fd(i as u32, dup.as_raw_fd());
        dups.push(dup);
    }
    Ok(dups)
}

/// Runs the loader of `skel`, unsigned, giving it for each map it
/// reuses a duplicate of the descriptor `shared` names for it: the
/// context with the descriptors of the maps and programs it made, which
/// closes them when it goes. A failed run made nothing that stays.
pub(crate) fn run(
    skel: &Lskel<'_>,
    shared: impl Fn(usize) -> Option<c_int>,
) -> Result<Ctx, Failed> {
    let fail = |step| move |e: c_int| (step, -e);
    let map_name = *b"__loader.map\0\0\0\0";
    let map = Attr::new()
        .u32(0, MAP_TYPE_ARRAY)
        .u32(4, 4)
        .u32(8, skel.data.len().max(4) as u32)
        .u32(12, 1)
        .put(28, &map_name)
        .fd(BPF_MAP_CREATE)
        .map_err(fail("__loader.map create"))?;
    let (key, zero) = (0u32, [0u8; 4]);
    let value = if skel.data.is_empty() {
        zero.as_ptr()
    } else {
        skel.data.as_ptr()
    };
    Attr::new()
        .u32(0, map.as_raw_fd() as u32)
        .ptr(8, &raw const key)
        .ptr(16, value)
        .run(BPF_MAP_UPDATE_ELEM)
        .map_err(fail("__loader.map update"))?;
    Attr::new()
        .u32(0, map.as_raw_fd() as u32)
        .run(BPF_MAP_FREEZE)
        .map_err(fail("__loader.map freeze"))?;

    let mut vlog = vec![0u8; VERIFIER_LOG_MAX];
    let fd_array = [map.as_raw_fd()];
    let prog = Attr::new()
        .u32(0, PROG_TYPE_SYSCALL)
        .u32(4, (skel.insns.len() / 8) as u32)
        .ptr(8, skel.insns.as_ptr())
        .ptr(16, c"Dual BSD/GPL".as_ptr())
        .u32(24, 1)
        .u32(28, VERIFIER_LOG_MAX as u32)
        .ptr(32, vlog.as_ptr())
        .u32(44, F_SLEEPABLE)
        .put(48, b"__loader.prog")
        .ptr(120, fd_array.as_ptr())
        .fd(BPF_PROG_LOAD);
    let prog = prog.inspect_err(|_| show_log("loader verifier log", &vlog));
    let prog = prog.map_err(fail("BPF_PROG_LOAD (loader)"))?;

    vlog[0] = 0;
    let (nr_maps, nr_progs) = (skel.maps.len() as u32, skel.progs.len() as u32);
    let mut cx = Ctx::new(nr_maps, nr_progs, &mut vlog).ok_or(("loader context", -E2BIG))?;
    let dups = duplicate_shared_maps(
        &mut cx,
        (0..skel.maps.len()).filter(|&i| skel.reuses(i)),
        shared,
    )?;
    let retval = prog_test_run(prog.as_raw_fd(), &mut cx.buf);
    let failed = match retval {
        Ok(r) if (r as i32) >= 0 => None,
        Ok(r) => Some(("loader", r as i32)),
        Err(e) => Some(("BPF_PROG_TEST_RUN", e)),
    };
    if let Some(f) = failed {
        // The loader closed what it made before it failed; the
        // duplicates are ours.
        cx.forget();
        drop(dups);
        show_log("loader runtime log", &vlog);
        return Err(f);
    }
    // The context now owns these descriptors alongside the loader results.
    for dup in dups {
        let _ = dup.into_raw_fd();
    }
    Ok(cx)
}

/// Plain data, which a map's keys and values are.
///
/// # Safety
///
/// Every bit pattern of the type's size is a value of it.
pub(crate) unsafe trait Pod: Copy {}

// SAFETY: an integer, which any bits are a value of.
unsafe impl Pod for u8 {}
// SAFETY: as above.
unsafe impl Pod for i8 {}
// SAFETY: as above.
unsafe impl Pod for u16 {}
// SAFETY: as above.
unsafe impl Pod for i16 {}
// SAFETY: as above.
unsafe impl Pod for u32 {}
// SAFETY: as above.
unsafe impl Pod for i32 {}
// SAFETY: as above.
unsafe impl Pod for u64 {}
// SAFETY: as above.
unsafe impl Pod for i64 {}
// SAFETY: an array of Pod values, each any bits.
unsafe impl<T: Pod, const N: usize> Pod for [T; N] {}

/// A map of `.maps` as its object defines it, which a pinned instance is
/// checked against: its name, its index among the object's maps, and its
/// shape.
#[derive(Clone, Copy)]
pub(crate) struct MapDef {
    pub(crate) name: &'static CStr,
    pub(crate) index: usize,
    pub(crate) map_type: u32,
    pub(crate) key_size: u32,
    pub(crate) value_size: u32,
    pub(crate) max_entries: u32,
    pub(crate) flags: u32,
}

/// A map a skeleton's loader made, of keys `K` and values `V`, the types
/// tools/bpf-lskel wrote from its BTF. The descriptor is the skeleton's.
pub(crate) struct Map<'s, K, V> {
    fd: c_int,
    _of: PhantomData<&'s (K, V)>,
}

impl<K: Pod, V: Pod> Map<'_, K, V> {
    pub(crate) fn fd(&self) -> c_int {
        self.fd
    }

    /// The value of `key`, or -errno.
    pub(crate) fn lookup(&self, key: &K) -> Result<V, c_int> {
        // SAFETY: V is Pod, which all bits zero is a value of.
        let mut value: V = unsafe { core::mem::zeroed() };
        let (k, v) = ((&raw const *key).cast(), (&raw mut value).cast());
        // SAFETY: the map's descriptor, a key and room for a value of
        // the sizes the map was made with, those of K and V.
        match unsafe { bpf_map_lookup_elem(self.fd, k, v) } {
            0 => Ok(value),
            err => Err(err),
        }
    }

    /// Sets `key` to `value`, or -errno.
    pub(crate) fn update(&self, key: &K, value: &V) -> Result<(), c_int> {
        let (k, v) = ((&raw const *key).cast(), (&raw const *value).cast());
        // SAFETY: the map's descriptor, a key and a value of the sizes
        // the map was made with, those of K and V.
        match unsafe { bpf_map_update_elem(self.fd, k, v, BPF_ANY) } {
            0 => Ok(()),
            err => Err(err),
        }
    }

    /// Freezes the map against writes from userspace, or -errno.
    pub(crate) fn freeze(&self) -> Result<(), c_int> {
        match bpf_map_freeze(self.fd) {
            0 => Ok(()),
            err => Err(err),
        }
    }

    /// Pins the map at `path`, or -errno.
    pub(crate) fn pin(&self, path: &CStr) -> Result<(), c_int> {
        pin(self.fd, path)
    }
}

/// Pins the map, program or link `fd` at `path`, or -errno.
pub(crate) fn pin(fd: c_int, path: &CStr) -> Result<(), c_int> {
    // SAFETY: a descriptor and a C string.
    match unsafe { bpf_obj_pin(fd, path.as_ptr()) } {
        0 => Ok(()),
        err => Err(err),
    }
}

/// BPF_PROG_TYPE_LSM and BPF_LSM_MAC.
const PROG_TYPE_LSM: u32 = 29;
const LSM_MAC: u32 = 27;

/// A program a skeleton's loader made. The descriptor is the skeleton's.
pub(crate) struct Prog<'s> {
    fd: c_int,
    prog: Program<'s>,
}

impl Prog<'_> {
    /// Attaches the LSM program at its hook: the link, or -errno; -EINVAL
    /// for a program of another kind.
    pub(crate) fn attach_lsm(&self) -> Result<OwnedFd, c_int> {
        if self.prog.prog_type != PROG_TYPE_LSM || self.prog.attach_type != LSM_MAC {
            return Err(-EINVAL);
        }
        link_create(self.fd, 0, LSM_MAC, |a| a).map_err(|e| -e)
    }
}

/// An object built into the binary, loaded: its skeleton, and the
/// context holding the descriptors of the maps and programs its loader
/// made, which go with it.
pub(crate) struct Skeleton {
    name: &'static [u8],
    skel: Lskel<'static>,
    cx: Ctx,
}

impl Skeleton {
    /// Runs the loader of the skeleton `data`, embedded by the Rust
    /// tools/bpf-lskel wrote with it, the maps it reuses taken from
    /// `shared`.
    pub(crate) fn load(
        name: &'static [u8],
        data: &'static [u8],
        shared: impl Fn(usize) -> Option<c_int>,
    ) -> Result<Self, Failed> {
        let skel = Lskel::parse(data).ok_or(("embedded skeleton", -EINVAL))?;
        let cx = run(&skel, shared)?;
        Ok(Skeleton { name, skel, cx })
    }

    pub(crate) fn name(&self) -> &'static [u8] {
        self.name
    }

    /// The descriptor of map `i`, which a table of maps names by index.
    pub(crate) fn map_fd(&self, i: usize) -> c_int {
        self.cx.map_fd(i as u32)
    }

    /// Map `i` as one of keys `K` and values `V`.
    ///
    /// # Safety
    ///
    /// `K` and `V` are of the sizes of the map's keys and values.
    pub(crate) unsafe fn map<K, V>(&self, i: usize) -> Map<'_, K, V> {
        Map {
            fd: self.map_fd(i),
            _of: PhantomData,
        }
    }

    /// The program named `name`, which a table of guards names.
    pub(crate) fn prog(&self, name: &[u8]) -> Option<Prog<'_>> {
        let (i, &prog) = self.skel.prog(name)?;
        Some(Prog {
            fd: self.cx.prog_fd(i as u32),
            prog,
        })
    }
}
