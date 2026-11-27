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
fn add_certificate(boot: &mut ImageBootstrap, path: &[u8]) -> Result<(), c_int> {
    let n = boot.n_certificates;

    if !path.starts_with(RUNTIME_DIR_PREFIX) || !path_valid(path) {
        return Err(-EPERM);
    }
    if n == KEYS_MAX {
        return Err(-E2BIG);
    }
    if boot.certificates[..n].iter().any(|c| cstr(c) == path) {
        return Err(-EEXIST);
    }
    strscpy(&mut boot.certificates[n], path).map_err(|_| -ENAMETOOLONG)?;
    boot.n_certificates += 1;
    Ok(())
}

/// One `key = value` line, cut in place, into `boot`.
fn apply(boot: &mut ImageBootstrap, key: &[u8], value: &CStr, initial: bool) -> Result<(), c_int> {
    let v = value.to_bytes();

    match key {
        b"runtime.root_hash" => {
            if !initial || boot.have_root {
                return Err(-EINVAL);
            }
            decode(v, &mut boot.runtime_root).map_err(|_| -EINVAL)?;
            boot.have_root = true;
            Ok(())
        }
        b"runtime.image" if initial => {
            if !path_valid(v) || boot.runtime[0] != 0 {
                return Err(-EINVAL);
            }
            strscpy(&mut boot.runtime, v).map_err(|_| -ENAMETOOLONG)?;
            Ok(())
        }
        b"config.image" => {
            if !path_valid(v) {
                return Err(-EINVAL);
            }
            strscpy(&mut boot.config, v).map_err(|_| -ENAMETOOLONG)?;
            Ok(())
        }
        b"config.verification_key" => add_certificate(boot, v),
        b"config.pcr" => {
            let pcr = parse_u64(v, 23).map_err(|_| -EINVAL)?;
            let pcr = u32::try_from(pcr).map_err(|_| -EINVAL)?;
            if pcr_valid(pcr) != 0 {
                return Err(-EINVAL);
            }
            boot.pcr = pcr;
            boot.have_pcr = true;
            Ok(())
        }
        b"config.nvpcr" => {
            if v != CONFIG_NVPCR_NAME {
                return Err(-EINVAL);
            }
            boot.pcr = CONFIG_NVPCR_INDEX;
            boot.have_pcr = true;
            Ok(())
        }
        _ if key.starts_with(b"config.") || key.starts_with(b"runtime.") => Err(-EINVAL),
        _ => Ok(()),
    }
}

/// The lines of `text` into `boot`, each as getline() gave it, its
/// newline included; only the `initial` read takes the runtime image and
/// its root.
fn parse(text: &[u8], boot: &mut ImageBootstrap, initial: bool) -> Result<(), c_int> {
    for line in text.split_inclusive(|&c| c == b'\n') {
        if line.contains(&0) {
            return Err(-EINVAL);
        }
        if line.strip_suffix(b"\n").unwrap_or(line).len() > PATH_MAX + 127 {
            return Err(-E2BIG);
        }
        // The line as the C string the C trimmed in place.
        let mut buf = [line, b"\0"].concat();
        let (ls, le) = trim_blanks(&mut buf, 0, line.len());
        if ls == le || buf[ls] == b'#' {
            continue;
        }
        let Some(eq) = buf[ls..le].iter().position(|&c| c == b'=').map(|i| ls + i) else {
            return Err(-EINVAL);
        };
        buf[eq] = 0;
        let (ks, ke) = trim_blanks(&mut buf, ls, eq);
        let (vs, _) = trim_blanks(&mut buf, eq + 1, le);
        let value = CStr::from_bytes_until_nul(&buf[vs..]).unwrap_or(c"");
        apply(boot, &buf[ks..ke], value, initial)?;
    }
    Ok(())
}

/// The bootstrap file at `path` into `boot`.
pub(crate) fn read(path: &CStr, boot: &mut ImageBootstrap, initial: bool) -> Result<(), c_int> {
    let text = std::fs::read(OsStr::from_bytes(path.to_bytes()))
        .map_err(|e| -e.raw_os_error().unwrap_or(EIO))?;
    parse(&text, boot, initial)
}

/// The bootstrap file open at `fd`, from its start, into `boot`, through
/// a copy of the fd: the caller keeps its own.
pub(crate) fn read_fd(fd: c_int, boot: &mut ImageBootstrap, initial: bool) -> Result<(), c_int> {
    // SAFETY: the caller's fd, and a minimum.
    let copy = unsafe { fcntl(fd, F_DUPFD_CLOEXEC, 3) };
    if copy < 0 {
        return Err(-errno());
    }
    // SAFETY: the copy fcntl() gave, owned from here.
    let mut f = File::from(unsafe { OwnedFd::from_raw_fd(copy) });
    let mut text = Vec::new();
    f.seek(SeekFrom::Start(0))
        .and_then(|_| f.read_to_end(&mut text))
        .map_err(|e| -e.raw_os_error().unwrap_or(EIO))?;
    parse(&text, boot, initial)
}

#[cfg(shirudo_fuzz)]
mod fuzz;

#[cfg(test)]
mod tests;
