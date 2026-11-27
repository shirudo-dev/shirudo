// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! What the pin directory of a loaded upatch holds: which links, which
//! XDP program pins, the payload hash a load set on it; and the upatches
//! that have one.

use core::ffi::{CStr, c_int};
use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

use crate::errno::{EINVAL, EIO, ENAMETOOLONG, ENOENT, ESTALE};
use crate::sys::libc::{errno, getxattr};
use crate::util::bpf_info::{Info, PROG_INFO_SIZE};
use crate::util::bpf_sys::bpf_obj_get;
use crate::util::upatch::{NAME_MAX, pin_name};
use crate::util::upatch_resolve::{BPFFS_UPATCHES_DIR, XATTR_PAYLOAD, pin_path};

/// `UPATCH_PAYLOAD_HASH_LEN`.
pub(crate) const PAYLOAD_HASH_LEN: usize = 32;
const BPF_PROG_TYPE_XDP: u32 = 6;
/// Where `struct bpf_prog_info` keeps its type and id.
const PROG_TYPE: usize = 0;
const PROG_ID: usize = 4;

/// `LINK_PIN_PREFIX` and `XDP_PROG_PIN_PREFIX` of util/paths.h.
pub(crate) const LINK_PIN_PREFIX: &[u8] = b"link_";
pub(crate) const XDP_PROG_PIN_PREFIX: &[u8] = b"xdp_prog_";

/// `struct upatch_pins`: the pins of an upatch's directory, as far as
/// whether it is loaded, and whole, goes: `link` of a single attach
/// program, the numbered links, lowest and highest, and the XDP program
/// pins, lowest first.
#[derive(Clone, Copy, Debug, Default)]
pub struct Pins {
    pub(crate) has_link: bool,
    pub(crate) nr_links: u32,
    pub(crate) first_link: u32,
    pub(crate) last_link: u32,
    pub(crate) nr_xdp_progs: u32,
    pub(crate) first_xdp_prog: u32,
}

/// The index of a `<prefix><n>` pin: n in decimal, without a leading
/// zero, within u32.
fn pin_index(entry: &[u8], prefix: &[u8]) -> Option<u32> {
    let digits = entry.strip_prefix(prefix)?;

    if digits.is_empty()
        || (digits[0] == b'0' && digits.len() > 1)
        || !digits.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    core::str::from_utf8(digits).ok()?.parse().ok()
}

fn io_errno(error: io::Error) -> c_int {
    -error.raw_os_error().unwrap_or(EIO)
}

/// Visit names from one directory, including a read error after earlier names.
fn each_name(
    entries: impl IntoIterator<Item = io::Result<OsString>>,
    mut visit: impl FnMut(&OsStr) -> c_int,
) -> c_int {
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => return io_errno(error),
        };
        let ret = visit(entry.as_os_str());
        if ret != 0 {
            return ret;
        }
    }
    0
}

impl Pins {
    /// One entry of the directory taken into account.
    pub(crate) fn note(&mut self, entry: &[u8]) {
        if entry == b"link" {
            self.has_link = true;
        } else if let Some(index) = pin_index(entry, LINK_PIN_PREFIX) {
            if self.nr_links == 0 || index < self.first_link {
                self.first_link = index;
            }
            if self.nr_links == 0 || index > self.last_link {
                self.last_link = index;
            }
            self.nr_links += 1;
        } else if let Some(index) = pin_index(entry, XDP_PROG_PIN_PREFIX) {
            if self.nr_xdp_progs == 0 || index < self.first_xdp_prog {
                self.first_xdp_prog = index;
            }
            self.nr_xdp_progs += 1;
        }
    }

    /// Only link_0 stands for the numbered links: a non-XDP upatch that
    /// has lost it must still read as not loaded, where restore calls
    /// that tampering. XDP link pins come and go with devices, so its
    /// program pin says it is loaded.
    pub(crate) fn loaded(&self) -> bool {
        self.has_link || (self.nr_links != 0 && self.first_link == 0) || self.nr_xdp_progs != 0
    }

    /// Whether the pins are the links of an upatch of `nr_attach`
    /// non-XDP programs: link alone for one, link_0 to link_<n-1> for
    /// more.
    pub(crate) fn complete(&self, nr_attach: u32) -> bool {
        match nr_attach {
            0 => true,
            1 => self.has_link,
            n => self.nr_links == n && self.first_link == 0 && self.last_link == n - 1,
        }
    }

    /// The pins of the directory of upatch `name`: -ENOENT without one.
    pub(crate) fn read(name: &[u8]) -> Result<Self, c_int> {
        let dir = [BPFFS_UPATCHES_DIR.as_bytes(), b"/", &pin_name(name)].concat();
        let entries = std::fs::read_dir(OsStr::from_bytes(&dir)).map_err(io_errno)?;
        read_entries(entries.map(|entry| entry.map(|entry| entry.file_name())))
    }
}

fn read_entries(entries: impl IntoIterator<Item = io::Result<OsString>>) -> Result<Pins, c_int> {
    let mut pins = Pins::default();
    let ret = each_name(entries, |name| {
        pins.note(name.as_bytes());
        0
    });
    if ret == 0 { Ok(pins) } else { Err(ret) }
}

/// Whether upatch `name` is loaded, by its pins alone, so a caller
/// without the task mark adds no denied BPF_OBJ_GET to the tamper
/// counters.
pub(crate) fn loaded_pins(name: &[u8]) -> Result<bool, c_int> {
    loaded_from_pins(Pins::read(name))
}

fn loaded_from_pins(read: Result<Pins, c_int>) -> Result<bool, c_int> {
    match read {
        Ok(pins) => Ok(pins.loaded()),
        Err(err) if err == -ENOENT => Ok(false),
        Err(err) => Err(err),
    }
}

/// The pin that keeps XDP program `index` of upatch `name` loaded.
pub(crate) fn xdp_prog_pin(name: &[u8], index: u32) -> Result<CString, c_int> {
    let entry = [XDP_PROG_PIN_PREFIX, index.to_string().as_bytes()].concat();

    pin_path(name, &[&entry]).map_err(|_| -ENAMETOOLONG)
}

/// XDP program `index` pinned for upatch `name`, and its id; -ESTALE when
/// the pin holds a program that is not XDP.
pub(crate) fn xdp_prog_open(name: &[u8], index: u32) -> Result<(OwnedFd, u32), c_int> {
    let pin = xdp_prog_pin(name, index)?;
    // SAFETY: a C string.
    let fd = unsafe { bpf_obj_get(pin.as_ptr()) };
    if fd < 0 {
        return Err(-errno());
    }
    // SAFETY: the descriptor bpf_obj_get() opened, owned from here.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut info = Info::<PROG_INFO_SIZE>::new();
    info.read(std::os::fd::AsRawFd::as_raw_fd(&fd))?;
    if info.u32_at(PROG_TYPE) != BPF_PROG_TYPE_XDP {
        return Err(-ESTALE);
    }
    Ok((fd, info.u32_at(PROG_ID)))
}

/// The payload hash a load set on the pin directory of upatch `name`:
/// -ENAMETOOLONG, -EINVAL when it is not a hash, or the -errno of the
/// read.
pub(crate) fn pin_payload(name: &[u8]) -> Result<[u8; PAYLOAD_HASH_LEN], c_int> {
    let dir = pin_path(name, &[]).map_err(|_| -ENAMETOOLONG)?;
    let mut out = [0u8; PAYLOAD_HASH_LEN];
    // SAFETY: two C strings and room for the hash.
    let n = unsafe {
        getxattr(
            dir.as_ptr(),
            XATTR_PAYLOAD.as_ptr(),
            out.as_mut_ptr().cast(),
            out.len(),
        )
    };
    if n < 0 {
        return Err(-errno());
    }
    if n as usize != PAYLOAD_HASH_LEN {
        return Err(-EINVAL);
    }
    Ok(out)
}

/// Calls `cb` with each `link_<n>` pin of upatch `name`, in directory
/// order, and stops at the first nonzero return, which it returns.
pub(crate) fn each_link(name: &[u8], cb: &mut dyn FnMut(u32, &CStr) -> c_int) -> c_int {
    let Ok(dir) = pin_path(name, &[]) else {
        return -ENAMETOOLONG;
    };
    let entries = match std::fs::read_dir(OsStr::from_bytes(dir.as_bytes())) {
        Ok(entries) => entries,
        Err(error) => return io_errno(error),
    };
    each_link_from(
        &dir,
        entries.map(|entry| entry.map(|entry| entry.file_name())),
        cb,
    )
}

fn each_link_from(
    dir: &CStr,
    entries: impl IntoIterator<Item = io::Result<OsString>>,
    cb: &mut dyn FnMut(u32, &CStr) -> c_int,
) -> c_int {
    each_name(entries, |file| {
        let Some(index) = pin_index(file.as_bytes(), LINK_PIN_PREFIX) else {
            return 0;
        };
        let pin = [dir.to_bytes(), b"/", file.as_bytes()].concat();
        let Ok(pin) = CString::new(pin) else {
            return -ENAMETOOLONG;
        };
        cb(index, &pin)
    })
}

/// Calls `cb` with the name of each upatch that has a pin directory and
/// stops at the first nonzero return, which it returns. No directory at
/// all is 0, any other failure to read it -errno.
pub(crate) fn each_pinned(cb: &mut dyn FnMut(&[u8]) -> c_int) -> c_int {
    let entries = match std::fs::read_dir(BPFFS_UPATCHES_DIR) {
        Ok(entries) => entries,
        Err(error) if error.raw_os_error() == Some(ENOENT) => return 0,
        Err(error) => return io_errno(error),
    };
    each_pinned_from(
        entries.map(|entry| entry.map(|entry| entry.file_name())),
        cb,
    )
}

fn each_pinned_from(
    entries: impl IntoIterator<Item = io::Result<OsString>>,
    cb: &mut dyn FnMut(&[u8]) -> c_int,
) -> c_int {
    each_name(entries, |entry| {
        let mut name = [0u8; NAME_MAX + 1];
        if crate::util::measured::name_from_bpffs(&mut name, entry.as_bytes()) != 0 {
            return 0;
        }
        cb(crate::text::cstr(&name))
    })
}

#[cfg(test)]
mod tests;
