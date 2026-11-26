// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo-build keys vouch`: the operator key signs a vouch for
//! another certificate, which `shirudo keys add --vouch` takes on the
//! targets that enrol this key.

use core::ffi::{CStr, c_int};
use std::ffi::CString;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::IntoRawFd;

use super::{KeyFiles, error, hex, info, last_err, print, strerr};
use crate::errno::{EINVAL, EIO, EKEYREJECTED};
use crate::sys::libc::close;
use crate::util::crypto_openssl::{Cert, cert_key_algorithm, cert_read_der};
use crate::util::help::{Help, HelpSection};
use crate::util::keys::{digest_der, read_der, vouch_payload};
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptParser, OptSpec};

/// The room a vouch's CMS signature gets.
const SIG_MAX: usize = 64 * 1024;
const PATH_MAX: usize = 4096;

/// Whether the certificate's key is ML-DSA-87, the one algorithm
/// shirudo accepts.
fn algorithm_ok(der: &[u8], what: &CStr) -> c_int {
    let mut cert = Cert::new();
    let mut name = [0u8; 64];

    // SAFETY: the DER and the cert to fill.
    let ret = unsafe { cert_read_der(der.as_ptr(), der.len(), &mut cert) };
    if ret != 0 {
        error(&[what.to_bytes(), b" is not a certificate"].concat());
        return ret;
    }
    // SAFETY: the certificate read above and room for the name.
    let ret = unsafe { cert_key_algorithm(&cert, name.as_mut_ptr().cast(), name.len()) };
    let name = crate::text::cstr(&name);
    if ret != 0 || name != b"ML-DSA-87" {
        let alg: &[u8] = if ret != 0 {
            b"of an unknown algorithm"
        } else {
            name
        };
        error(
            &[
                what.to_bytes(),
                b" is ",
                alg,
                b"; shirudo accepts only ML-DSA-87",
            ]
            .concat(),
        );
        return -EKEYREJECTED;
    }
    0
}

/// `data` at `path`, created or truncated, mode 0644; removed again if
/// any of it fails, its close included.
fn write_file(path: &CStr, data: &[u8]) -> c_int {
    let p = super::path(path.to_bytes());
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(p);
    let mut file = match file {
        Ok(f) => f,
        Err(e) => return -e.raw_os_error().unwrap_or(EIO),
    };
    let mut ret = match file.write_all(data) {
        Ok(()) => 0,
        Err(e) => -e.raw_os_error().unwrap_or(EIO),
    };
    // SAFETY: the descriptor the file gives up.
    if unsafe { close(file.into_raw_fd()) } != 0 && ret == 0 {
        ret = last_err();
    }
    if ret != 0 {
        let _ = std::fs::remove_file(p);
    }
    ret
}

/// The fingerprint of the certificate's key.
fn fingerprint(der: &[u8]) -> Result<[u8; 32], c_int> {
    digest_der(der).map(|d| d.fingerprint)
}

fn vouch(input: &CStr, output: &CStr, keys: &KeyFiles) -> c_int {
    let der = match read_der(input) {
        Ok(d) => d,
        Err(err) => {
            error(&[b"keys vouch: read ", input.to_bytes(), b": ", strerr(-err)].concat());
            return err;
        }
    };
    let Ok(fp) = fingerprint(&der) else {
        error(&[b"keys vouch: ", input.to_bytes(), b" is not a certificate"].concat());
        return 1;
    };
    let ret = algorithm_ok(&der, input);
    if ret != 0 {
        return ret;
    }
    let own = match read_der(&keys.cert) {
        Ok(d) => d,
        Err(err) => {
            error(
                &[
                    b"keys vouch: read ",
                    keys.cert.to_bytes(),
                    b": ",
                    strerr(-err),
                ]
                .concat(),
            );
            return err;
        }
    };
    let Ok(own_fp) = fingerprint(&own) else {
        error(
            &[
                b"keys vouch: ",
                keys.cert.to_bytes(),
                b" is not a certificate",
            ]
            .concat(),
        );
        return 1;
    };
    if fp == own_fp {
        error(
            &[
                b"keys vouch: ",
                input.to_bytes(),
                b" holds the signing key itself; a key cannot vouch for its own certificate",
            ]
            .concat(),
        );
        return -EINVAL;
    }
    let payload = match vouch_payload(&der) {
        Ok(payload) => payload,
        Err(ret) => return ret,
    };
    let signature = match super::sign::cms_sign(&payload, &[], SIG_MAX, &keys.pkey, &keys.cert) {
        Ok((signature, _)) => signature,
        Err(ret) => {
            error(&[b"keys vouch: sign: ", strerr(-ret)].concat());
            return ret;
        }
    };
    let ret = write_file(output, &signature);
    if ret != 0 {
        error(
            &[
                b"keys vouch: write ",
                output.to_bytes(),
                b": ",
                strerr(-ret),
            ]
            .concat(),
        );
        return ret;
    }
    let (fp_hex, own_hex) = (hex(&fp), hex(&own_fp));
    info(
        &[
            b"keys vouch: ",
            &fp_hex[..],
            b" vouched for by ",
            &own_hex,
            b", written to ",
            output.to_bytes(),
        ]
        .concat(),
    );
    print(true, &[&fp_hex[..], b"\n"].concat());
    0
}

const VOUCH_OUTPUT: c_int = 0;
const VOUCH_KEYS_DIR: c_int = 1;
const VOUCH_KEY: c_int = 2;
const VOUCH_CERT: c_int = 3;

static VOUCH_OPTS: [OptSpec; 4] = [
    OptSpec::new(
        c"--output",
        b'o',
        0,
        Some(c"<file>"),
        c"where to write the vouch (default <cert.der>.vouch)",
    ),
    OptSpec::new(
        c"--keys-dir",
        0,
        0,
        Some(c"<dir>"),
        c"read signing_key.pem and cert.der from <dir>",
    ),
    OptSpec::new(
        c"--key",
        0,
        0,
        Some(c"<signing_key.pem>"),
        c"the signing key (overrides --keys-dir)",
    ),
    OptSpec::new(
        c"--cert",
        0,
        0,
        Some(c"<cert.der>"),
        c"the signing certificate (overrides --keys-dir)",
    ),
];

static VOUCH_SECTIONS: [HelpSection; 1] = [HelpSection::options(c"options:", &VOUCH_OPTS)];

static VOUCH_HELP: Help = Help::new(
    c"shirudo keys vouch <cert.der> [-o <file>] [--keys-dir <dir>]\n                          \
      [--key <signing_key.pem>] [--cert <cert.der>]",
    Some(
        c"Sign a vouch for another operator's certificate with this operator's key,\n\
          for `shirudo keys add --vouch` on the targets that enrol this key.\n\
          Prints the vouched certificate's fingerprint.",
    ),
    &VOUCH_SECTIONS,
    None,
);

/// `shirudo-build keys vouch`, from `vouch` on.
pub(super) fn run(args: &[&CStr]) -> c_int {
    let mut p = OptParser::new(c"keys vouch", &VOUCH_OPTS, Some(&VOUCH_HELP), args, 1);
    let mut keys = KeyFiles::default();
    let (mut input, mut output): (Option<&CStr>, Option<&CStr>) = (None, None);
    let mut keys_dir = None;

    loop {
        let opt = p.next();
        let value = p.value();
        match opt {
            OPT_END => break,
            VOUCH_OUTPUT => output = value,
            VOUCH_KEYS_DIR => keys_dir = value,
            VOUCH_KEY => keys.set_pkey(value.unwrap_or_default()),
            VOUCH_CERT => keys.set_cert(value.unwrap_or_default()),
            OPT_ARG => {
                if input.is_some() {
                    p.usage_arg(b"unexpected argument ");
                    return EXIT_USAGE;
                }
                input = value;
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    let Some(input) = input else {
        p.usage(b"takes <cert.der>");
        return EXIT_USAGE;
    };
    if let Err((dir, _)) = keys.resolve(keys_dir) {
        error(&[b"invalid keys dir ", &dir[..]].concat());
        return 2;
    }
    if super::check_keys(&keys.pkey, &keys.cert) != 0 {
        return 1;
    }
    let derived;
    let output = match output {
        Some(o) => o,
        None => {
            let path = [input.to_bytes(), b".vouch"].concat();
            if path.len() >= PATH_MAX {
                error(b"keys vouch: output path too long");
                return 2;
            }
            derived = CString::new(path).unwrap_or_default();
            &derived
        }
    };
    if vouch(input, output, &keys) != 0 {
        1
    } else {
        0
    }
}
