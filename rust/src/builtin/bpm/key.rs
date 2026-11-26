// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Package signing certificates: fingerprinting one, installing it as
//! the node's package signer, and listing those installed.

use core::ffi::CStr;
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::os::fd::{AsFd, BorrowedFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;

use super::{CERT_PATH, KEYS_DIR, Result, last_err, message, os_err, path, print, remove, status};
use crate::errno::{EEXIST, EKEYREJECTED, ENOENT, EPERM};
use crate::sys::libc::{O_CREAT, O_EXCL, O_WRONLY, close};
use crate::text::name_has_suffix;
use crate::util::bpm_package::read_member_fd;
use crate::util::crypto_openssl::{Cert, cert_pubkey_digest, cert_read_file, cert_read_memory};
use crate::util::json::JsonEmit;
use crate::util::keys::{DER_MAX, read_der, read_der_fd};
use crate::util::seal;

fn os(path: &CStr) -> &OsStr {
    OsStr::from_bytes(path.to_bytes())
}

/// The SHA-256 of the SPKI of the DER or PEM certificate `der`.
fn pubkey_digest(der: &[u8]) -> Result<[u8; 32]> {
    let mut cert = Cert::new();
    let mut digest = [0; 32];

    let mut ret = cert_read_memory(der, &mut cert);
    if ret == 0 {
        // SAFETY: the certificate read and room for the digest.
        ret = unsafe { cert_pubkey_digest(&cert, digest.as_mut_ptr()) };
    }
    status(ret).map(|()| digest)
}

/// The SHA-256 of the SPKI of the node's active certificate.
fn active_digest() -> Result<[u8; 32]> {
    let mut cert = Cert::new();
    let mut digest = [0; 32];

    // SAFETY: a C string and a certificate to fill.
    let mut ret = unsafe { cert_read_file(CERT_PATH.as_ptr(), &mut cert) };
    if ret == 0 {
        // SAFETY: the certificate read and room for the digest.
        ret = unsafe { cert_pubkey_digest(&cert, digest.as_mut_ptr()) };
    }
    status(ret).map(|()| digest)
}

/// Whether the certificate `der` has the key of the node's active
/// certificate.
fn matches_active(der: &[u8]) -> bool {
    matches!((pubkey_digest(der), active_digest()), (Ok(a), Ok(b)) if a == b)
}

/// Whether the certificate already open in an extracted package has
/// the key of the node's active certificate.
pub(super) fn fd_matches_active(fd: BorrowedFd<'_>) -> bool {
    read_der_fd(fd).is_ok_and(|der| matches_active(&der))
}

/// The lowercase hex fingerprint of the certificate `der`.
fn fingerprint(der: &[u8]) -> Result<[u8; 64]> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = pubkey_digest(der)?;
    let mut hex = [0; 64];

    for (i, b) in digest.iter().enumerate() {
        hex[2 * i] = HEX[usize::from(b >> 4)];
        hex[2 * i + 1] = HEX[usize::from(b & 0xf)];
    }
    Ok(hex)
}

/// [`fingerprint`] of the key file at `path`.
fn file_fingerprint(path: &CStr) -> Result<[u8; 64]> {
    fingerprint(&read_der(path)?)
}

/// A new key file of `der`: created, never one replaced, and synced.
fn write_key(dst: &CStr, der: &[u8]) -> Result {
    let mut file = fs::File::from(seal::open(
        dst.to_bytes(),
        O_WRONLY | O_CREAT | O_EXCL,
        0o644,
    )?);
    let mut ret = file
        .write_all(der)
        .and_then(|()| file.sync_all())
        .map_err(os_err);
    // SAFETY: the file's fd, closed once.
    if unsafe { close(file.into_raw_fd()) } != 0 && ret.is_ok() {
        ret = Err(last_err());
    }
    if ret.is_err() {
        remove(dst);
    }
    ret
}

/// Installs the certificate `der` under its fingerprint, and as the
/// active certificate when the node has none yet; one with another key
/// than an active certificate's is refused.
fn install(der: &[u8]) -> Result {
    let hex = fingerprint(der)?;

    seal::mkdir_p(KEYS_DIR.as_bytes(), 0o700)?;
    let active = match fs::symlink_metadata(os(CERT_PATH)) {
        Ok(_) => true,
        Err(e) if e.raw_os_error() == Some(ENOENT) => false,
        Err(e) => return Err(os_err(e)),
    };
    if active && !matches_active(der) {
        return Err(-EPERM);
    }
    let dst = path(&[KEYS_DIR.as_bytes(), b"/", &hex, b".der"])?;
    let made = match fs::symlink_metadata(os(&dst)) {
        Ok(m) => {
            if !m.file_type().is_file() || file_fingerprint(&dst).ok() != Some(hex) {
                return Err(-EKEYREJECTED);
            }
            false
        }
        Err(e) if e.raw_os_error() == Some(ENOENT) => {
            write_key(&dst, der)?;
            true
        }
        Err(e) => return Err(os_err(e)),
    };
    if active {
        return Ok(());
    }
    let ret = match std::os::unix::fs::symlink(os(&dst), os(CERT_PATH)) {
        Ok(()) => seal::inherit_path(CERT_PATH),
        Err(e) if e.raw_os_error() != Some(EEXIST) => Err(os_err(e)),
        Err(_) if matches_active(der) => Ok(()),
        Err(_) => Err(-EPERM),
    };
    if ret.is_err() && made {
        remove(&dst);
    }
    ret
}

/// The DER certificate a key command takes, read once so that the key
/// installed is the one fingerprinted: the file named, or the cert.der
/// of a package, a download read in memory.
fn source_read(source: &[u8]) -> Result<Vec<u8>> {
    if !source.starts_with(b"oci://") && !name_has_suffix(source, b".bee") {
        return read_der(&message(&[source]));
    }
    let fd = super::fetch::package_source_open(source)?;
    let cert = read_member_fd(fd.as_fd(), b"cert.der", None, None, DER_MAX)?;
    Ok(cert.bytes().to_vec())
}

/// The fingerprints of the certificates installed, each a regular file
/// named after its own fingerprint.
fn installed() -> Result<Vec<[u8; 64]>> {
    let mut found = Vec::new();
    let entries = match fs::read_dir(KEYS_DIR) {
        Ok(entries) => entries,
        Err(e) if e.raw_os_error() == Some(ENOENT) => return Ok(found),
        Err(e) => return Err(os_err(e)),
    };

    for entry in entries {
        let name = entry.map_err(os_err)?.file_name();
        let name = name.as_bytes();

        if name.len() != 68
            || !name[64..].eq_ignore_ascii_case(b".der")
            || !name[..64].iter().all(u8::is_ascii_hexdigit)
        {
            continue;
        }
        let Ok(p) = path(&[KEYS_DIR.as_bytes(), b"/", name]) else {
            continue;
        };
        if !fs::symlink_metadata(os(&p)).is_ok_and(|m| m.file_type().is_file()) {
            continue;
        }
        match file_fingerprint(&p) {
            Ok(hex) if name[..64].eq_ignore_ascii_case(&hex) => found.push(hex),
            _ => continue,
        }
    }
    found.sort();
    Ok(found)
}

pub(super) fn list(json: bool) -> Result {
    let found = installed()?;

    if json {
        let mut buf = [0u8; 8192];
        let mut e = JsonEmit::fixed(&mut buf);

        e.obj_open();
        e.kv_int(b"schema", 1);
        e.arr_open(b"fingerprints");
        for hex in &found {
            e.str(hex);
        }
        e.arr_close();
        e.obj_close();
        if e.err() != 0 {
            return Err(e.err());
        }
        print(&[e.output(), b"\n"].concat());
        return Ok(());
    }
    print(b"Package certificates:\n");
    if found.is_empty() {
        print(b"  none\n");
    }
    for hex in &found {
        print(&[b"  ", &hex[..], b"\n"].concat());
    }
    Ok(())
}

/// `bpm key add` or `bpm key fingerprint` of `source`: its fingerprint
/// printed, once add installed it.
pub(super) fn show(source: &[u8], add: bool) -> Result {
    let der = source_read(source)?;
    let hex = fingerprint(&der)?;

    if add {
        install(&der)?;
    }
    print(&[&hex[..], b"\n"].concat());
    Ok(())
}
