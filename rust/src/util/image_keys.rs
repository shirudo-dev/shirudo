// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The trusted key set a config image carries: certificates under
//! keys/trusted/, each vouched for by a signer the runtime trusts, and
//! revocations under keys/revoked/, each named by the fingerprint of the
//! certificate it holds. Validation only reads; applying revokes.

use core::ffi::{CStr, c_int};
use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};

use crate::errno::{EINVAL, EKEYREJECTED, ENOENT, ENOKEY, last_errno, text};
use crate::sys::libc::{
    O_CLOEXEC, O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK, S_IFMT, S_IFREG, closedir, fdopendir, openat,
    readdir, set_errno,
};
use crate::util::image_config;
use crate::util::io::stat_fd;
use crate::util::keyring;
use crate::util::keys::{TrustedSet, cert_der, digest_der, load_image_root, members, read_der_fd};

/// KEYS_DER_MAX: the largest certificate a key file holds.
const DER_MAX: u64 = 1024 * 1024;
/// The runtime's certificate, the set's initial signer.
pub(crate) const RUNTIME_CERT_PATH: &CStr = c"/run/shirudo/runtime/keys/cert.der";

const O_RDONLY: c_int = 0;

fn error(text: String) {
    let text = CString::new(text).unwrap_or_default();

    crate::log::err(text.to_bytes());
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// The fingerprint a revocation's name spells: 64 lowercase hex digits
/// and `.der`, nothing else.
fn revoked_fingerprint(name: &[u8]) -> Option<[u8; 32]> {
    let hex = name.strip_suffix(b".der").filter(|h| h.len() == 64)?;
    let mut out = [0u8; 32];
    for (o, pair) in out.iter_mut().zip(hex.chunks(2)) {
        *o = hex_digit(pair[0])? << 4 | hex_digit(pair[1])?;
    }
    // One certificate, one name: uppercase would let a second file
    // revoke the same certificate past the last-signer check.
    (!hex.iter().any(u8::is_ascii_uppercase)).then_some(out)
}

fn open_dir(at: c_int, name: &CStr) -> Result<Option<OwnedFd>, c_int> {
    // SAFETY: an open directory and a C string.
    let fd = unsafe {
        openat(
            at,
            name.as_ptr(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW,
        )
    };
    if fd >= 0 {
        // SAFETY: the fd openat() just gave, owned from here.
        return Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }));
    }
    match last_errno() {
        e if e == -ENOENT => Ok(None),
        e => Err(e),
    }
}

/// One revocation under `dir`: its certificate, whose fingerprint must
/// be the name's, from a regular file on the image's device.
fn revoked_cert(dir: c_int, name: &CStr, dev: (u32, u32)) -> Result<Vec<u8>, c_int> {
    let expected = revoked_fingerprint(name.to_bytes()).ok_or(-EINVAL)?;
    // SAFETY: the open directory and an entry's name.
    let fd = unsafe {
        openat(
            dir,
            name.as_ptr(),
            O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(last_errno());
    }
    // SAFETY: the fd openat() just gave, owned from here.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let st = stat_fd(fd.as_fd())?;
    if st.stx_mode & S_IFMT != S_IFREG
        || (st.stx_dev_major, st.stx_dev_minor) != dev
        || st.stx_size == 0
        || st.stx_size > DER_MAX
    {
        return Err(-EINVAL);
    }
    let bytes = read_der_fd(fd.as_fd());
    drop(fd);
    let bytes = bytes?;
    if digest_der(&bytes)?.fingerprint != expected {
        return Err(-EKEYREJECTED);
    }
    Ok(bytes)
}

/// Checks every revocation of the image at `root_fd`, in directory
/// order, and with `apply` revokes each from the kernel. Returns the
/// number of records or the first error. An image without keys/revoked/
/// revokes nothing.
fn revocations(root_fd: c_int, apply: bool, boot: bool) -> Result<usize, c_int> {
    // SAFETY: the caller's root fd, open for the call, which
    // validate_set() had image_config::validate() stat first.
    let root = stat_fd(unsafe { BorrowedFd::borrow_raw(root_fd) })?;
    let dev = (root.stx_dev_major, root.stx_dev_minor);
    let keys = match open_dir(root_fd, c"keys") {
        Ok(Some(fd)) => fd,
        Ok(None) => return Ok(0),
        Err(err) => return Err(err),
    };
    let revoked = match open_dir(keys.as_raw_fd(), c"revoked") {
        Ok(Some(fd)) => fd,
        Ok(None) => return Ok(0),
        Err(err) => return Err(err),
    };
    drop(keys);
    let dir_fd = revoked.as_raw_fd();
    // SAFETY: the open directory, whose fd the stream takes over.
    let dir = unsafe { fdopendir(dir_fd) };
    if dir.is_null() {
        return Err(last_errno());
    }
    let _ = revoked.into_raw_fd();

    let mut ret = 0;
    let mut records = 0;
    loop {
        // The end of the stream tells from an error by errno alone.
        set_errno(0);
        // SAFETY: the open stream.
        let entry = unsafe { readdir(dir) };
        if entry.is_null() {
            let err = last_errno();
            if err != 0 {
                ret = err;
            }
            break;
        }
        // SAFETY: the entry readdir() gave, its name a C string.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr().cast()) };
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let result = revoked_cert(dir_fd, name, dev);
        ret = match result {
            Ok(der) if apply => crate::builtin::keys::revoke_image(&der, boot),
            Ok(_) => 0,
            Err(err) => err,
        };
        if ret != 0 {
            break;
        }
        records += 1;
    }
    // SAFETY: the stream, closed once with its fd.
    unsafe { closedir(dir) };
    if ret == 0 { Ok(records) } else { Err(ret) }
}

/// The trust set of the config image at `root_fd`: its config, its
/// revocations and its certificates checked, without changing anything,
/// with `primary` the signer the vouches lead back to. A set without a
/// certificate or with an unvouched one is refused.
pub(crate) fn validate_set(primary: &CStr, root_fd: c_int, set: &mut TrustedSet) -> c_int {
    let ret = image_config::validate(root_fd);
    if ret != 0 {
        error(format!(
            "image trust set: validate config image: {}",
            text(ret)
        ));
        return ret;
    }
    if let Err(ret) = revocations(root_fd, false, false) {
        error(format!(
            "image trust set: validate revocations: {}",
            text(ret)
        ));
        return ret;
    }
    *set = match load_image_root(primary, root_fd, true) {
        Ok(loaded) => loaded,
        Err(ret) => {
            error(format!("image trust set: load certificates: {}", text(ret)));
            return ret;
        }
    };
    if set.len() == 0 || set.n_unvouched() != 0 {
        error(format!(
            "image trust set: reject set with {} certificates and {} unvouched",
            set.len(),
            set.n_unvouched()
        ));
        return -EKEYREJECTED;
    }
    0
}

/// Whether `holds` finds every certificate of `set`: 0, -ENOKEY for one
/// it does not, or its error. A key set takes effect only at boot, when
/// the kernel enrols its certificates, so a live update can only use the
/// signers the kernel already holds.
pub(crate) fn check_set_with(set: &TrustedSet, mut holds: impl FnMut(&[u8]) -> c_int) -> c_int {
    for cert in members(set) {
        let der = match cert_der(cert) {
            Ok(der) => der,
            Err(ret) => return ret,
        };
        let ret = holds(der);
        if ret != 1 {
            return if ret < 0 { ret } else { -ENOKEY };
        }
    }
    0
}

/// [`check_set_with`] the BPF keyring: keys_check_image_set().
pub(crate) fn check_set(set: &TrustedSet) -> c_int {
    let ring = keyring::bpf_serial();
    if ring < 0 {
        return ring;
    }
    check_set_with(set, |der| keyring::holds_cert(ring, der))
}

/// Validates the trust set of the image at `root_fd`, from the runtime's
/// signer, and checks the kernel holds all of it.
pub(crate) fn validate(root_fd: c_int) -> c_int {
    let mut set = TrustedSet::default();
    let ret = validate_set(RUNTIME_CERT_PATH, root_fd, &mut set);
    if ret != 0 { ret } else { check_set(&set) }
}

/// Check stored archives only when this image has a revocation record.
pub(crate) fn check_purge(root_fd: c_int) -> c_int {
    match revocations(root_fd, false, false) {
        Ok(0) => 0,
        Ok(_) => crate::builtin::keys::revoke_check(),
        Err(err) => err,
    }
}

/// Validates the trust set of the image at `root_fd`, then revokes what
/// it revokes, as a boot or a live update records it.
pub(crate) fn apply(root_fd: c_int, boot: bool) -> c_int {
    let ret = validate(root_fd);
    if ret != 0 {
        return ret;
    }
    let ret = check_purge(root_fd);
    if ret != 0 {
        return ret;
    }
    revocations(root_fd, true, boot).err().unwrap_or(0)
}
