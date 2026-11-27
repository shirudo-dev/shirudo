// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! A package's identity: the name and version its build environment
//! records, and the signer of the certificate it carries.

use core::ffi::{CStr, c_int};

use openssl::x509::{X509, X509Ref};

use super::PackageInfo;
use super::facade::read_member_in;
use crate::errno::{EINVAL, EKEYREJECTED};
use crate::text::cstr;
use crate::util::bpm_oci::{MAX_DIGEST, MAX_NAME, copy_string, package_name_ok, version_ok};
use crate::util::crypto_openssl::{pubkey_digest, x509_from_der_bio};
use crate::util::hex::encode;
use crate::util::json::{JsonField, parse_schema};

/// The most a package's build environment or certificate may hold.
const MEMBER_MAX: usize = 4 * 1024 * 1024;

/// What build-environment.json says of the package.
struct Parsed {
    name: [u8; MAX_NAME],
    version: [u8; MAX_NAME],
    signer: [u8; MAX_DIGEST],
}

/// The certificate in `body`, DER or PEM; none when it holds neither.
fn read_x509_memory(body: &[u8]) -> Option<X509> {
    if c_int::try_from(body.len()).is_err() {
        return None;
    }
    x509_from_der_bio(body)
        .or_else(|_| X509::from_pem(body))
        .ok()
}

/// The name, version and signer of the `.bee` at `archive` into `info`,
/// with the certificate that signed it.
pub(crate) fn load_info(archive: &CStr, info: &mut PackageInfo) -> c_int {
    let environment =
        match read_member_in(archive, b"build-environment.json", None, None, MEMBER_MAX) {
            Ok(member) => member,
            Err(err) => return err,
        };
    let ret = identify(archive, environment.bytes(), info);
    if ret != 0 {
        info.cert = None;
    }
    ret
}

fn identify(archive: &CStr, environment: &[u8], info: &mut PackageInfo) -> c_int {
    let mut parsed = Parsed {
        name: [0; MAX_NAME],
        version: [0; MAX_NAME],
        signer: [0; MAX_DIGEST],
    };
    let package_fields = [
        JsonField::string(c"name", |p: &mut Parsed| &mut p.name),
        JsonField::string(c"version", |p| &mut p.version),
    ];
    let shirudo_fields = [JsonField::string(
        c"spki_sha256_fingerprint",
        |p: &mut Parsed| &mut p.signer,
    )];
    let root = [
        JsonField::object(c"package", &package_fields),
        JsonField::object(c"shirudo", &shirudo_fields),
    ];
    let ret = parse_schema(environment, &root, &mut parsed);

    if ret.is_err()
        || !root[0].seen()
        || parsed.name[0] == 0
        || parsed.version[0] == 0
        || !package_name_ok(cstr(&parsed.name))
        || !version_ok(cstr(&parsed.version))
    {
        return -EINVAL;
    }
    let member = match read_member_in(archive, b"cert.der", None, None, MEMBER_MAX) {
        Ok(member) => member,
        Err(err) => return err,
    };
    let cert = read_x509_memory(member.bytes());
    info.cert = Some(member);

    signed_by(cert.as_deref(), &parsed, info)
}

/// The signer `cert` names, checked against the one the build
/// environment records, and the identity into `info`.
fn signed_by(cert: Option<&X509Ref>, parsed: &Parsed, info: &mut PackageInfo) -> c_int {
    let Some(Ok(digest)) = cert.map(pubkey_digest) else {
        return -EINVAL;
    };
    let hex = encode(&digest);
    let hex = hex.as_slice();
    if parsed.signer[0] != 0 && !cstr(&parsed.signer).eq_ignore_ascii_case(hex) {
        crate::log::err(
            &[
                &b"bpm: package signer fingerprint mismatch: certificate="[..],
                hex,
                b" build-environment.json=",
                cstr(&parsed.signer),
            ]
            .concat(),
        );
        return -EKEYREJECTED;
    }
    copy_string(&mut info.name, cstr(&parsed.name));
    copy_string(&mut info.version, cstr(&parsed.version));
    copy_string(&mut info.signer, hex);
    0
}
