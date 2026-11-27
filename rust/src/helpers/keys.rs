// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-keys: the trusted certificate set driven: a keys directory
//! loaded and its members or the digest the init event covers printed,
//! a signature verified against it, or a upatch's signer named.
//!
//!   test-keys load|digest|reject <keys dir> [primary]
//!   test-keys image <image keys dir>
//!   test-keys verify-signature <keys dir> <payload> <signature>
//!   test-keys signer <upatch> <cert.der>

use core::ffi::{CStr, c_int};
use std::ffi::{CString, OsStr};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;

use super::{err, helper_main, out};
use crate::errno::{EFBIG, EINVAL, EIO};
use crate::util::crypto_openssl::{Cert, cert_read_file, cms_signed_by};
use crate::util::hex::encode;
use crate::util::keys::{TrustedSet, cert_path, load, load_image_at, members, verify_signature};
use crate::util::upatch::Upatch;

helper_main!(shirudo_helper_test_keys, run);

fn hex(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&encode(bytes)).into_owned()
}

/// The set of the image keys directory `dir`, its primary cert.der in
/// it; None when the directory does not open.
fn load_image(dir: &CStr) -> Option<Result<TrustedSet, c_int>> {
    let root = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(OsStr::from_bytes(dir.to_bytes()))
        .ok()?;
    let primary = CString::new([dir.to_bytes(), b"/cert.der"].concat()).ok()?;

    Some(load_image_at(&primary, Some(root.as_fd()), true))
}

/// The file at `path`, of at most `max` bytes.
fn read(path: &CStr, max: usize) -> Result<Vec<u8>, c_int> {
    match std::fs::read(OsStr::from_bytes(path.to_bytes())) {
        Ok(b) if b.len() <= max => Ok(b),
        Ok(_) => Err(-EFBIG),
        Err(e) => Err(-e.raw_os_error().unwrap_or(EIO)),
    }
}

/// The payload at `payload` verified against `set` with the signature
/// at `signature`: its signer's fingerprint.
fn verified(set: &TrustedSet, payload: &CStr, signature: &CStr) -> Result<[u8; 32], c_int> {
    let payload = read(payload, 1024 * 1024)?;
    let signature = read(signature, 65536)?;

    verify_signature(set, &payload, &signature)
}

fn verify(dir: &CStr, payload: &CStr, signature: &CStr) -> c_int {
    let Some(loaded) = load_image(dir) else {
        return 1;
    };
    let ret = match loaded.and_then(|set| verified(&set, payload, signature)) {
        Ok(signer) => {
            out(&format!("{}\n", hex(&signer)));
            0
        }
        Err(err) => err,
    };
    out(&format!("rc={ret}\n"));
    c_int::from(ret != 0)
}

/// Whether `cert` signed the upatch at `upatch`: yes, no or error.
fn signer(upatch: &CStr, cert_file: &CStr) -> c_int {
    let Ok(u) = Upatch::open(upatch) else {
        err("usage: signer <upatch> <cert.der>\n");
        return 2;
    };
    let mut cert = Cert::new();
    // SAFETY: a C string and room for the certificate.
    if unsafe { cert_read_file(cert_file.as_ptr(), &mut cert) } != 0 {
        return 2;
    }
    let sig = u.signature();
    let ret = cms_signed_by(sig, &cert);
    out(match ret {
        1 => "yes\n",
        0 => "no\n",
        _ => "error\n",
    });
    c_int::from(ret < 0)
}

fn run(args: &[&CStr]) -> c_int {
    if args.len() < 3 {
        let me = args
            .first()
            .map_or("test-keys".into(), |a| a.to_string_lossy());
        err(&format!(
            "usage: {me} load|digest|reject <keys-dir> [primary] | signer <upatch> <cert.der>\n"
        ));
        return 2;
    }
    let how = args[1].to_bytes();
    match how {
        b"verify-signature" => {
            return if args.len() == 5 {
                verify(args[2], args[3], args[4])
            } else {
                2
            };
        }
        b"signer" if args.len() >= 4 => return signer(args[2], args[3]),
        b"signer" => {
            err("usage: signer <upatch> <cert.der>\n");
            return 2;
        }
        _ => {}
    }
    let loaded = if how == b"image" {
        match load_image(args[2]) {
            Some(loaded) => loaded,
            None => return 1,
        }
    } else {
        let with_trusted = args.get(3).is_none_or(|a| a.to_bytes() != b"primary");
        load(args[2], None, with_trusted)
    };
    if how == b"reject" {
        return c_int::from(loaded.err() != Some(-EINVAL));
    }
    let set = match loaded {
        Ok(set) => set,
        Err(ret) => {
            out(&format!("rc={ret}\n"));
            return 1;
        }
    };
    match how {
        b"load" | b"image" => {
            out(&format!(
                "n={} revoked={} unvouched={}\n",
                set.len(),
                set.n_revoked(),
                set.n_unvouched()
            ));
            for c in members(&set) {
                out(&format!(
                    "{} {} {} {}\n",
                    hex(c.sha256()),
                    hex(c.fingerprint()),
                    if c.primary() { "primary" } else { "trusted" },
                    String::from_utf8_lossy(cert_path(c))
                ));
            }
            0
        }
        b"digest" => {
            let digest = set.digest().unwrap_or([0; 32]);
            out(&format!("{}\n", hex(&digest)));
            0
        }
        _ => {
            err("unknown subcommand\n");
            2
        }
    }
}
