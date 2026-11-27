// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The bootstrap file: where the runtime
//! and config images and the config's verification keys are, the runtime
//! image's root hash and the PCR the config is measured into.

use core::ffi::{CStr, c_int};

use super::config_measure::pcr_valid;
use crate::errno::{E2BIG, EEXIST, EINVAL, EIO, ENAMETOOLONG, EPERM};
use crate::sys::libc::{F_DUPFD_CLOEXEC, PATH_MAX, errno, fcntl};
use crate::text::{contains, cstr, parse_u64, strscpy, trim_blanks};
use crate::util::hex::decode;
use crate::util::keys::KEYS_MAX;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

const RUNTIME_DIR_PREFIX: &[u8] = b"/run/shirudo/runtime/";
/// `TPM_CONFIG_NVPCR_INDEX` and `_NAME` in include/shirudo/tpm.h.
const CONFIG_NVPCR_INDEX: u32 = 0x0181_8e04;
const CONFIG_NVPCR_NAME: &[u8] = b"shirudo-config";

/// `struct image_bootstrap`.
#[repr(C)]
pub struct ImageBootstrap {
    pub(crate) runtime: [u8; PATH_MAX],
    pub(crate) config: [u8; PATH_MAX],
    pub(crate) certificates: [[u8; PATH_MAX]; KEYS_MAX],
    pub(crate) n_certificates: usize,
    pub(crate) runtime_root: [u8; 32],
    pub(crate) pcr: u32,
    pub(crate) have_root: bool,
    pub(crate) have_pcr: bool,
}

const _: () = assert!(size_of::<ImageBootstrap>() == 73776);

impl ImageBootstrap {
    /// An empty bootstrap file before its fields are parsed.
    pub(crate) const fn empty() -> Self {
        Self {
            runtime: [0; PATH_MAX],
            config: [0; PATH_MAX],
            certificates: [[0; PATH_MAX]; KEYS_MAX],
            n_certificates: 0,
            runtime_root: [0; 32],
            pcr: 0,
            have_root: false,
            have_pcr: false,
        }
    }
}

/// An absolute path without `.` or `..` components or empty ones, and
/// not `/`.
pub(crate) fn path_valid(path: &[u8]) -> bool {
    path.first() == Some(&b'/')
        && !contains(path, b"/../")
        && !contains(path, b"/./")
        && !contains(path, b"//")
        && path != b"/"
        && (path.len() < 3 || !path.ends_with(b"/.."))
}

/// One more config verification certificate, a file of the runtime
/// image named once.
fn add_certificate(boot: &mut ImageBootstrap, path: &[u8]) -> c_int {
    let n = boot.n_certificates;

    if !path.starts_with(RUNTIME_DIR_PREFIX) || !path_valid(path) {
        return -EPERM;
    }
    if n == KEYS_MAX {
        return -E2BIG;
    }
    if boot.certificates[..n].iter().any(|c| cstr(c) == path) {
        return -EEXIST;
    }
    if strscpy(&mut boot.certificates[n], path).is_err() {
        return -ENAMETOOLONG;
    }
    boot.n_certificates += 1;
    0
}

/// One `key = value` line, cut in place, into `boot`.
fn apply(boot: &mut ImageBootstrap, key: &[u8], value: &CStr, initial: bool) -> c_int {
    let v = value.to_bytes();

    match key {
        b"runtime.root_hash" => {
            if !initial || boot.have_root {
                return -EINVAL;
            }
            if decode(value.to_bytes(), &mut boot.runtime_root).is_err() {
                return -EINVAL;
            }
            boot.have_root = true;
            0
        }
        b"runtime.image" if initial => {
            if !path_valid(v) || boot.runtime[0] != 0 {
                -EINVAL
            } else if strscpy(&mut boot.runtime, v).is_err() {
                -ENAMETOOLONG
            } else {
                0
            }
        }
        b"config.image" => {
            if !path_valid(v) {
                -EINVAL
            } else if strscpy(&mut boot.config, v).is_err() {
                -ENAMETOOLONG
            } else {
                0
            }
        }
        b"config.verification_key" => add_certificate(boot, v),
        b"config.pcr" => match parse_u64(v, 23) {
            Ok(pcr) if pcr_valid(pcr as u32) == 0 => {
                boot.pcr = pcr as u32;
                boot.have_pcr = true;
                0
            }
            _ => -EINVAL,
        },
        b"config.nvpcr" => {
            if v != CONFIG_NVPCR_NAME {
                -EINVAL
            } else {
                boot.pcr = CONFIG_NVPCR_INDEX;
                boot.have_pcr = true;
                0
            }
        }
        _ if key.starts_with(b"config.") || key.starts_with(b"runtime.") => -EINVAL,
        _ => 0,
    }
}

/// The lines of `text` into `boot`, each as getline() gave it, its
/// newline included; only the `initial` read takes the runtime image and
/// its root.
fn parse(text: &[u8], boot: &mut ImageBootstrap, initial: bool) -> c_int {
    for line in text.split_inclusive(|&c| c == b'\n') {
        if line.contains(&0) {
            return -EINVAL;
        }
        if line.strip_suffix(b"\n").unwrap_or(line).len() > PATH_MAX + 127 {
            return -E2BIG;
        }
        // The line as the C string the C trimmed in place.
        let mut buf = [line, b"\0"].concat();
        let (ls, le) = trim_blanks(&mut buf, 0, line.len());
        if ls == le || buf[ls] == b'#' {
            continue;
        }
        let Some(eq) = buf[ls..le].iter().position(|&c| c == b'=').map(|i| ls + i) else {
            return -EINVAL;
        };
        buf[eq] = 0;
        let (ks, ke) = trim_blanks(&mut buf, ls, eq);
        let (vs, _) = trim_blanks(&mut buf, eq + 1, le);
        let value = CStr::from_bytes_until_nul(&buf[vs..]).unwrap_or(c"");
        let ret = apply(boot, &buf[ks..ke], value, initial);
        if ret != 0 {
            return ret;
        }
    }
    0
}

/// The bootstrap file at `path` into `boot`.
pub(crate) fn read(path: &CStr, boot: &mut ImageBootstrap, initial: bool) -> c_int {
    match std::fs::read(OsStr::from_bytes(path.to_bytes())) {
        Ok(text) => parse(&text, boot, initial),
        Err(e) => -e.raw_os_error().unwrap_or(EIO),
    }
}

/// The bootstrap file open at `fd`, from its start, into `boot`, through
/// a copy of the fd: the caller keeps its own.
pub(crate) fn read_fd(fd: c_int, boot: &mut ImageBootstrap, initial: bool) -> c_int {
    // SAFETY: the caller's fd, and a minimum.
    let copy = unsafe { fcntl(fd, F_DUPFD_CLOEXEC, 3) };
    if copy < 0 {
        return -errno();
    }
    // SAFETY: the copy fcntl() gave, owned from here.
    let mut f = File::from(unsafe { OwnedFd::from_raw_fd(copy) });
    let mut text = Vec::new();
    match f
        .seek(SeekFrom::Start(0))
        .and_then(|_| f.read_to_end(&mut text))
    {
        Ok(_) => parse(&text, boot, initial),
        Err(e) => -e.raw_os_error().unwrap_or(EIO),
    }
}

#[cfg(shirudo_fuzz)]
mod fuzz;

#[cfg(test)]
mod tests;
