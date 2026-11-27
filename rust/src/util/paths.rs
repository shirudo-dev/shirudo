// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The paths of the signing keys: the keys directory a command names, the
//! environment's, or the default, and the key and certificate under it.
//! upatch_pin_path() is in upatch_resolve.rs.

use core::ffi::{CStr, c_int};
use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;

use crate::errno::{EINVAL, ENAMETOOLONG};
use crate::sys::libc::env;

/// The default keys directory, the variable that overrides it, and the
/// two files in one.
const KEYS_DIR: &CStr = c"/var/lib/shirudo/keys";
const KEYS_DIR_ENV: &CStr = c"SHIRUDO_KEYS_DIR";
const SIGNING_KEY_FILE: &CStr = c"signing_key.pem";
const CERT_FILE: &CStr = c"cert.der";

/// The longest path the kernel takes, its NUL included.
const PATH_MAX: usize = 4096;

/// POLICY_PIN and SOCKET_POLICY_PIN of util/paths.h, the task and socket
/// policy maps the upatch loader pins, and XATTR_POLICY, the label an
/// executable carries its policy bits in.
pub(crate) const POLICY_PIN: &CStr = c"/run/shirudo/bpffs/task_policy";
pub(crate) const SOCKET_POLICY_PIN: &CStr = c"/run/shirudo/bpffs/socket_policy";
pub(crate) const XATTR_POLICY: &CStr = c"security.bpf.shirudo.policy";

/// The keys directory: `arg`, else $SHIRUDO_KEYS_DIR, else the default.
pub(crate) fn keys_dir(arg: Option<&CStr>) -> &CStr {
    arg.or_else(|| env(KEYS_DIR_ENV)).unwrap_or(KEYS_DIR)
}

/// `file` under `dir`, a slash between unless `dir` ends in one:
/// -EINVAL for an empty directory or one with a NUL, -ENAMETOOLONG when
/// the path and its NUL pass PATH_MAX.
pub(crate) fn key_file(dir: &[u8], file: &CStr) -> Result<CString, c_int> {
    let file = file.to_bytes();
    let mut path = vec![0u8; key_file_size(dir, file)?];
    key_file_into(dir, file, &mut path)?;
    CString::new(path).map_err(|_| -EINVAL)
}

/// The space needed for a key file, preserving the error order of key_file.
fn key_file_size(dir: &[u8], file: &[u8]) -> Result<usize, c_int> {
    if dir.is_empty() {
        return Err(-EINVAL);
    }
    let separator = usize::from(!dir.ends_with(b"/"));
    let size = dir
        .len()
        .checked_add(separator)
        .and_then(|n| n.checked_add(file.len()))
        .ok_or(-ENAMETOOLONG)?;
    if size >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    if dir.contains(&0) {
        return Err(-EINVAL);
    }
    Ok(size)
}

/// Write the directory, one separator when needed, and the file name.
fn key_file_into(dir: &[u8], file: &[u8], out: &mut [u8]) -> Result<(), c_int> {
    if out.len() != key_file_size(dir, file)? {
        return Err(-EINVAL);
    }
    out[..dir.len()].copy_from_slice(dir);
    let mut at = dir.len();
    if !dir.ends_with(b"/") {
        out[at] = b'/';
        at += 1;
    }
    out[at..].copy_from_slice(file);
    Ok(())
}

/// The signing key and the certificate under `dir`, as [`key_file`]
/// spells them.
pub(crate) fn key_files(dir: &[u8]) -> Result<(CString, CString), c_int> {
    Ok((key_file(dir, SIGNING_KEY_FILE)?, key_file(dir, CERT_FILE)?))
}

/// Whether stat() finds `path`.
pub(crate) fn path_exists(path: &CStr) -> bool {
    std::fs::metadata(OsStr::from_bytes(path.to_bytes())).is_ok()
}

#[cfg(test)]
mod tests;
