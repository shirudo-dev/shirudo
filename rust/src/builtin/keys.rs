// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo keys`: the key material a host holds, the operator's
//! certificate and signing key on disk, the trusted set a target enrols
//! and the kernel keyrings init filled, and adding a vouched certificate
//! to the set. Revoking goes through a signed config image, vouching
//! through shirudo-build.

use core::ffi::{CStr, c_int};
use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::os::fd::{FromRawFd, OwnedFd};

use foreign_types::ForeignTypeRef;
use openssl::asn1::Asn1TimeRef;
use openssl::hash::MessageDigest;
use openssl::pkey::{HasPublic, PKey, PKeyRef, Private};
use openssl::x509::{X509, X509NameRef};

use crate::builtin::upatch::{
    UPATCH_PURGE_NO_ARCHIVE, UPATCH_PURGE_NO_SIGNER, UPATCH_PURGE_OTHER_SIGNER,
};
use crate::errno::{EACCES, EINVAL, EIO, EKEYREJECTED, ENODEV, ENOENT, ENOKEY};
use crate::ffi;
use crate::sys::identity::Identity;
use crate::sys::libc::{O_CLOEXEC, O_RDONLY, PATH_MAX, errno, fwrite, open, stdout, strerror};
use crate::sys::openssl::{EVP_PKEY_get_base_id, X509_NAME_oneline};
use crate::text::{cstr, name_has_suffix};
use crate::util::chain;
use crate::util::crypto_openssl::{
    Cert, cert_key_algorithm, cert_read_der, complain_stack, key_type_name, openssl_complain,
    sha256, utc, x509_from_der_bio,
};
use crate::util::eventlog;
use crate::util::format::fputs_sanitized;
use crate::util::help::{
    Help, HelpItem, HelpSection, is_help, is_list_cmds, print_help, print_subcmd_list,
    resolve_subcommand,
};
use crate::util::identity;
use crate::util::image_config;
use crate::util::io::{dir_names, open_trusted};
use crate::util::json::JsonEmit;
use crate::util::keyring;
use crate::util::keys::{
    KEYS_MAX, TrustedSet, digest_der, install, is_revoked, load, members, read_der, verify_vouch,
};
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptParser, OptSpec};
use crate::util::paths::{key_files, keys_dir, path_exists};
use crate::util::upatch::name_valid;

const KEYS_DIR: &CStr = c"/var/lib/shirudo/keys";
const RUNTIME_KEYS_DIR: &CStr = c"/run/shirudo/runtime/keys";
const UPATCHES_DIR: &str = "/var/lib/shirudo/upatches";
/// `SIG_KEYRING_BPF`: the keyring type init records for the .bpf ring.
const SIG_KEYRING_BPF: u32 = 5;
const IDENTITY_KEYS_MAX: u32 = 16;
const EVP_PKEY_RSA: c_int = 6;
const EVP_PKEY_EC: c_int = 408;

fn print(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stdout.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stdout) };
}

fn message(parts: &[&[u8]]) -> CString {
    let mut text = parts.concat();

    if let Some(nul) = text.iter().position(|&c| c == 0) {
        text.truncate(nul);
    }
    CString::new(text).unwrap_or_default()
}

fn error(parts: &[&[u8]]) {
    let msg = message(parts);
    crate::log::err(msg.to_bytes());
}

fn warn(parts: &[&[u8]]) {
    let msg = message(parts);
    crate::log::warn(msg.to_bytes());
}

fn info(parts: &[&[u8]]) {
    let msg = message(parts);
    crate::log::info(msg.to_bytes());
}

fn audit(parts: &[&[u8]]) {
    let msg = message(parts);
    crate::log::audit(msg.to_bytes());
}

fn strerr(err: c_int) -> &'static [u8] {
    // SAFETY: strerror() gives a C string that outlives the message.
    unsafe { ffi::c_str(strerror(err)) }
}

fn hex(bytes: &[u8; 32]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0; 64];

    for (i, b) in bytes.iter().enumerate() {
        out[2 * i] = HEX[usize::from(b >> 4)];
        out[2 * i + 1] = HEX[usize::from(b & 0xf)];
    }
    out
}

/// `s` left-justified in `width` bytes, as printf's "%-*s".
fn padded(s: &[u8], width: usize) -> Vec<u8> {
    let mut out = s.to_vec();

    out.resize(width.max(s.len()), b' ');
    out
}

/// A label line of the text output: two spaces and the label in 22.
fn line(label: &[u8], value: &[u8]) {
    print(&[b"  ", &padded(label, 22)[..], b" ", value, b"\n"].concat());
}

fn complain(what: &CStr) {
    openssl_complain(what);
}

/// The bytes of the file at `path`, checked first when `trusted`; none,
/// logged, when it cannot be opened or read. They are read unbuffered,
/// and the allocator scrubs them when they go, so that a key read this
/// way leaves no copy behind.
fn read_file(path: &CStr, trusted: bool) -> Option<Vec<u8>> {
    let opened = if trusted {
        open_trusted(path, O_RDONLY)
    } else {
        // SAFETY: a C string and flags without a mode.
        let fd = unsafe { open(path.as_ptr(), O_RDONLY | O_CLOEXEC) };

        if fd < 0 {
            Err(-errno())
        } else {
            // SAFETY: open() just returned this owned fd.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    };
    let fd = match opened {
        Ok(fd) => fd,
        Err(ret) => {
            error(&[b"open ", path.to_bytes(), b": ", strerr(-ret)]);
            return None;
        }
    };
    let file = File::from(fd);
    let mut text = Vec::new();

    if let Err(e) = (&file).read_to_end(&mut text) {
        error(&[
            b"read ",
            path.to_bytes(),
            b": ",
            strerr(e.raw_os_error().unwrap_or(EIO)),
        ]);
        return None;
    }
    Some(text)
}

fn read_cert_der(path: &CStr) -> Option<X509> {
    let der = read_file(path, true)?;

    x509_from_der_bio(&der)
        .map_err(|e| complain_stack(c"d2i_X509_bio", &e))
        .ok()
}

/// The private key PEM at `path`.
fn read_priv_pem(path: &CStr) -> Option<PKey<Private>> {
    let pem = read_file(path, false)?;

    PKey::private_key_from_pem(&pem)
        .map_err(|e| complain_stack(c"PEM_read_bio_PrivateKey", &e))
        .ok()
}

fn name_text(name: &X509NameRef) -> Vec<u8> {
    let mut buf = [0u8; 256];

    // SAFETY: a name and the room for its line.
    let line =
        unsafe { X509_NAME_oneline(name.as_ptr(), buf.as_mut_ptr().cast(), buf.len() as c_int) };
    if line.is_null() {
        return b"(parse error)".to_vec();
    }
    cstr(&buf).to_vec()
}

/// The time as strftime()'s "%Y-%m-%dT%H:%M:%SZ" writes it.
fn time_text(t: &Asn1TimeRef) -> Vec<u8> {
    match utc(t) {
        None => b"(unparseable)".to_vec(),
        Some(t) => format!(
            "{}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            t.year, t.month, t.day, t.hour, t.minute, t.second
        )
        .into_bytes(),
    }
}

fn cert_fpr(c: &X509) -> Option<[u8; 32]> {
    let fpr = c
        .digest(MessageDigest::sha256())
        .map_err(|e| complain_stack(c"X509_digest", &e))
        .ok()?;

    (*fpr).try_into().ok()
}

/// SHA-256 over the SPKI, comparable across a certificate and its key.
fn spki_fpr<T: HasPublic>(pkey: &PKeyRef<T>) -> Option<[u8; 32]> {
    let der = pkey
        .public_key_to_der()
        .map_err(|e| complain_stack(c"i2d_PUBKEY", &e))
        .ok()?;

    sha256(&der).map_err(|_| complain(c"EVP_Digest")).ok()
}

/// Format a provider name, with a bit count for classical keys, into
/// the 63 bytes available for display.
fn format_algorithm(name: &[u8], bits: Option<u32>) -> Vec<u8> {
    let algorithm = match bits {
        Some(bits) => [name, b"-", bits.to_string().as_bytes()].concat(),
        None => name.to_vec(),
    };

    if algorithm.len() < 64 {
        algorithm
    } else {
        b"?".to_vec()
    }
}

/// "RSA-2048" or "EC-256" for the classical families, else the
/// provider's own name, "ML-DSA-87", whose parameter set says what a bit
/// count would.
fn pkey_algorithm<T: HasPublic>(pkey: &PKeyRef<T>) -> Vec<u8> {
    let name = key_type_name(pkey);
    let name = name.as_deref().map_or(&b"unknown"[..], CStr::to_bytes);
    // SAFETY: the key.
    let id = unsafe { EVP_PKEY_get_base_id(pkey.as_ptr()) };
    let bits = (id == EVP_PKEY_RSA || id == EVP_PKEY_EC).then(|| pkey.bits());

    format_algorithm(name, bits)
}

fn print_fpr(label: &[u8], fpr: &[u8; 32]) {
    print(&[b"  ", &padded(label, 22)[..], b" SHA256:", &hex(fpr), b"\n"].concat());
}

/// Where the material goes: text to stdout, or the JSON being built.
type Out<'a> = Option<&'a mut JsonEmit<'a>>;

fn dump_cert(out: &mut Out, cert: &X509, path: &CStr, spki: &[u8; 32]) {
    let (subj, iss) = (cert.subject_name(), cert.issuer_name());
    let pubkey = cert.public_key().ok();
    let (subj_s, iss_s, nb_s) = (
        name_text(subj),
        name_text(iss),
        time_text(cert.not_before()),
    );
    let self_signed = subj.try_cmp(iss).is_ok_and(|o| o.is_eq());

    if let Some(e) = out {
        e.obj_open_key(b"cert");
        e.kv_string(b"path", path.to_bytes());
        e.kv_string(b"subject", &subj_s);
        e.kv_string(b"issuer", &iss_s);
        e.kv_bool(b"self_signed", self_signed);
        match &pubkey {
            None => e.kv_null(b"algorithm"),
            Some(k) => e.kv_string(b"algorithm", &pkey_algorithm(k)),
        }
        match cert_fpr(cert) {
            Some(fpr) => e.kv_string(b"fingerprint", &hex(&fpr)),
            None => e.kv_null(b"fingerprint"),
        }
        e.kv_string(b"spki_fingerprint", &hex(spki));
        e.kv_string(b"not_before", &nb_s);
        e.obj_close();
        return;
    }
    print(&[b"Certificate (", path.to_bytes(), b"):\n"].concat());
    line(b"Subject:", &subj_s);
    line(
        b"Issuer:",
        &[
            &iss_s[..],
            if self_signed { b"  (self-signed)" } else { b"" },
        ]
        .concat(),
    );
    if let Some(k) = &pubkey {
        line(b"Public key:", &pkey_algorithm(k));
    }
    if let Some(fpr) = cert_fpr(cert) {
        print_fpr(b"Fingerprint:", &fpr);
    }
    print_fpr(b"SPKI fingerprint:", spki);
    line(b"Issued:", &nb_s);
}

/// The signing key beside the certificate, if any: whether it is the
/// certificate's. Err for one that cannot be read or is not.
fn dump_signing_key(out: &mut Out, pkey_path: &CStr, spki: &[u8; 32]) -> Result<(), ()> {
    if !path_exists(pkey_path) {
        if let Some(e) = out {
            e.obj_open_key(b"signing_key");
            e.kv_string(b"path", pkey_path.to_bytes());
            e.kv_bool(b"present", false);
            e.obj_close();
            return Ok(());
        }
        print(&[b"Signing key (", pkey_path.to_bytes(), b"):\n"].concat());
        line(b"Present:", b"no, a target holds no private key");
        return Ok(());
    }
    let priv_key = read_priv_pem(pkey_path).ok_or(())?;
    let alg = pkey_algorithm(&priv_key);
    match out {
        Some(e) => {
            e.obj_open_key(b"signing_key");
            e.kv_string(b"path", pkey_path.to_bytes());
            e.kv_bool(b"present", true);
            e.kv_string(b"algorithm", &alg);
        }
        None => {
            print(&[b"Signing key (", pkey_path.to_bytes(), b"):\n"].concat());
            line(b"Present:", b"yes");
            line(b"Algorithm:", &alg);
        }
    }
    let ret = match spki_fpr(&priv_key) {
        None => Err(()),
        Some(fpr) => {
            let matches = fpr == *spki;

            match out {
                Some(e) => {
                    e.kv_string(b"spki_fingerprint", &hex(&fpr));
                    e.kv_bool(b"matches_cert", matches);
                }
                None => {
                    print_fpr(b"SPKI fingerprint:", &fpr);
                    line(
                        b"Matches cert:",
                        if matches {
                            b"yes"
                        } else {
                            b"no, the private key is not the certificate's"
                        },
                    );
                }
            }
            if matches {
                Ok(())
            } else {
                warn(&[b"keys: private key and cert have different public keys"]);
                Err(())
            }
        }
    };
    if let Some(e) = out {
        e.obj_close();
    }
    ret
}

/// The certificate and signing key on disk: 0, or 1 when either is bad.
fn dump_disk_material(out: &mut Out, cert_path: &CStr, pkey_path: &CStr) -> c_int {
    let Some(cert) = read_cert_der(cert_path) else {
        return 1;
    };
    let Ok(pubkey) = cert.public_key() else {
        return 1;
    };
    let Some(spki) = spki_fpr(&pubkey) else {
        return 1;
    };
    dump_cert(out, &cert, cert_path, &spki);
    if out.is_none() {
        print(b"\n");
    }
    match dump_signing_key(out, pkey_path, &spki) {
        Ok(()) => 0,
        Err(()) => 1,
    }
}

/// A keyring init froze: its serial and the keys it recorded in it.
struct Anchor<'a> {
    label: &'a [u8],
    serial: fn() -> i32,
    frozen: i32,
    keys: &'a [i32],
}

impl Anchor<'_> {
    fn holds(&self, key: i32) -> bool {
        self.keys.contains(&key)
    }
}

/// A member of a keyring: its serial, and its type and description
/// unless describing it failed with `err`.
struct Member {
    serial: i32,
    err: c_int,
    ty: Vec<u8>,
    description: Vec<u8>,
}

/// The members of `ring`, as keyring::links() gives them.
fn links(ring: i32) -> Result<Vec<Member>, c_int> {
    Ok(keyring::links(ring)?
        .into_iter()
        .map(|l| Member {
            serial: l.serial,
            err: l.err,
            ty: l.ty,
            description: l.description,
        })
        .collect())
}

fn list_keyring(out: &mut Out, ring: i32, a: &Anchor, id_rc: c_int) -> c_int {
    let frozen = id_rc == 0 && a.frozen > 0;

    if let Some(e) = out {
        e.obj_open();
        e.kv_string(b"name", a.label);
        e.kv_bool(b"present", true);
        e.kv_int(b"serial", ring.into());
        if frozen {
            e.kv_int(b"frozen_serial", a.frozen.into());
        } else {
            e.kv_null(b"frozen_serial");
        }
        let listed = links(ring);
        e.arr_open(b"members");
        for m in listed.as_deref().unwrap_or(&[]) {
            e.obj_open();
            e.kv_int(b"serial", m.serial.into());
            if m.err != 0 {
                e.kv_null(b"type");
                e.kv_null(b"description");
            } else {
                e.kv_string(b"type", &m.ty);
                e.kv_string(b"description", &m.description);
            }
            if frozen {
                e.kv_bool(b"frozen", a.holds(m.serial));
            } else {
                e.kv_null(b"frozen");
            }
            e.obj_close();
        }
        e.arr_close();
        e.obj_close();
        if let Err(err) = listed {
            error(&[b"keyring list: ", strerr(-err)]);
            return 1;
        }
        return 0;
    }
    print(&[b"Keyring (", a.label, b"):\n"].concat());
    line(b"Serial:", ring.to_string().as_bytes());
    if frozen {
        let same = a.frozen == ring;
        line(
            b"Frozen serial:",
            &[
                a.frozen.to_string().as_bytes(),
                b"  (",
                if same { b"matches" } else { b"swapped" },
                b")",
            ]
            .concat(),
        );
        if !same {
            warn(&[
                a.label,
                b" keyring serial ",
                ring.to_string().as_bytes(),
                b" is not the frozen ",
                a.frozen.to_string().as_bytes(),
                b": swapped",
            ]);
        }
    } else if id_rc == 0 || id_rc == -ENOENT {
        line(b"Frozen serial:", b"(none this boot)");
    } else {
        print(
            &[
                b"  ",
                &padded(b"Frozen serial:", 22)[..],
                b" unreadable: ",
                strerr(-id_rc),
                b"\n",
            ]
            .concat(),
        );
    }
    let listed = match links(ring) {
        Ok(listed) => listed,
        Err(err) => {
            error(&[b"keyring list: ", strerr(-err)]);
            return 1;
        }
    };
    print(&[b"  Members (", listed.len().to_string().as_bytes(), b"):\n"].concat());
    if listed.is_empty() {
        print(b"    (empty)\n");
    }
    for m in &listed {
        let (serial, err, desc) = (&m.serial, &m.err, &m.description);
        let ty: &[u8] = if *err != 0 { b"?" } else { &m.ty };
        print(
            &[
                b"    serial=",
                &padded(serial.to_string().as_bytes(), 10)[..],
                b"  type=",
                &padded(ty, 10),
                b"  ",
            ]
            .concat(),
        );
        if *err != 0 {
            print(&[b"(cannot describe: ", strerr(-err), b")"].concat());
        } else {
            // SAFETY: the description, to the C library's stdout.
            unsafe { fputs_sanitized(desc, stdout) };
        }
        if frozen {
            print(if a.holds(*serial) {
                b"  (frozen)"
            } else {
                b"  (not frozen)"
            });
        }
        print(b"\n");
    }
    0
}

fn keyring_absent(out: &mut Out, a: &Anchor, ret: i32, id_rc: c_int) {
    let frozen = id_rc == 0 && a.frozen > 0;
    let reason: Vec<u8> = if ret != -ENOKEY {
        [b"lookup error: ", strerr(-ret)].concat()
    } else if frozen {
        [
            b"gone, init froze serial ",
            a.frozen.to_string().as_bytes(),
            b" this boot",
        ]
        .concat()
    } else if id_rc == 0 || id_rc == -ENOENT {
        b"absent before init".to_vec()
    } else {
        [b"frozen identity unreadable: ", strerr(-id_rc)].concat()
    };
    let reason = if reason.len() >= 128 {
        b"?".to_vec()
    } else {
        reason
    };

    if let Some(e) = out {
        e.obj_open();
        e.kv_string(b"name", a.label);
        e.kv_bool(b"present", false);
        e.kv_null(b"serial");
        if frozen {
            e.kv_int(b"frozen_serial", a.frozen.into());
        } else {
            e.kv_null(b"frozen_serial");
        }
        e.kv_string(b"reason", &reason);
        e.obj_close();
        return;
    }
    print(&[b"Keyring (", a.label, b"):\n"].concat());
    print(
        &[
            b"  ",
            &padded(b"Present:", 22)[..],
            b" no, ",
            &reason,
            b"\n",
        ]
        .concat(),
    );
}

static SUBCMDS: [HelpItem; 3] = [
    HelpItem::new(
        c"add",
        c"trust a certificate an enrolled key vouched for (target)",
    ),
    HelpItem::new(
        c"revoke",
        c"stop trusting a certificate now and for good (target)",
    ),
    HelpItem::new(c"vouch", c"sign a vouch for a certificate (operator)"),
];

const KEYS_KEYS_DIR: c_int = 0;
const KEYS_JSON: c_int = 1;

static OPTS: [OptSpec; 2] = [
    OptSpec::new(
        c"--keys-dir",
        0,
        0,
        Some(c"<dir>"),
        c"read signing_key.pem and cert.der from <dir>",
    ),
    OptSpec::new(c"--json", 0, 0, None, c"print the key material as JSON"),
];

static SECTIONS: [HelpSection; 2] = [
    HelpSection::items(c"subcommands:", &SUBCMDS),
    HelpSection::options(c"options:", &OPTS),
];

static HELP: Help = Help::new(
    c"shirudo keys [--keys-dir <dir>] [--json]\n       \
      shirudo keys add <cert.der> --vouch <file>\n       \
      shirudo keys revoke\n       \
      shirudo keys vouch <cert.der> [-o <file>]",
    Some(
        c"Inspect the shirudo key material this host holds: the on-disk cert and\n\
          signing key (if present), the trusted set a target enrols, and the kernel\n\
          keyring holding it (if init'd). Local-only on either side.",
    ),
    &SECTIONS,
    Some(
        c"Default paths:\n  /var/lib/shirudo/keys/cert.der\n  \
          /var/lib/shirudo/keys/signing_key.pem\n\n\
          Or set the SHIRUDO_KEYS_DIR environment variable.",
    ),
);

const KEYS_ADD_VOUCH: c_int = 0;
const KEYS_ADD_KEYS_DIR: c_int = 1;

static ADD_OPTS: [OptSpec; 2] = [
    OptSpec::new(
        c"--vouch",
        0,
        0,
        Some(c"<file>"),
        c"the vouch an enrolled key signed for the certificate",
    ),
    OptSpec::new(
        c"--keys-dir",
        0,
        0,
        Some(c"<dir>"),
        c"the keys directory (default /var/lib/shirudo/keys)",
    ),
];

static ADD_SECTIONS: [HelpSection; 1] = [HelpSection::options(c"options:", &ADD_OPTS)];

static ADD_HELP: Help = Help::new(
    c"shirudo keys add <cert.der> --vouch <file> [--keys-dir <dir>]",
    Some(
        c"Add a certificate to the trusted set this target enrols at its next boot.\n\
          The vouch must verify under a certificate already in the set; regenerate\n\
          the initrd afterwards (shirudo-gen-initrd). Prints the fingerprint.",
    ),
    &ADD_SECTIONS,
    None,
);

static REVOKE_HELP: Help = Help::new(
    c"shirudo keys revoke",
    Some(
        c"Local revocation is disabled. Publish revocation records in a signed config \
          image and activate it with image update.",
    ),
    &[],
    None,
);

/// The public key must be one the kernel verifies loaders with.
fn check_cert_algorithm(der: &[u8], what: &[u8]) -> c_int {
    let mut cert = Cert::new();
    let mut name = [0u8; 64];

    // SAFETY: the bytes and a certificate to fill.
    let ret = unsafe { cert_read_der(der.as_ptr(), der.len(), &mut cert) };
    if ret != 0 {
        error(&[b"keys add: ", what, b" is not a certificate"]);
        return ret;
    }
    // SAFETY: the certificate and room for its algorithm's name.
    let ret = unsafe { cert_key_algorithm(&cert, name.as_mut_ptr().cast(), name.len()) };
    if ret != 0 || cstr(&name) != b"ML-DSA-87" {
        let what_alg: &[u8] = if ret != 0 {
            b"of an unknown algorithm"
        } else {
            cstr(&name)
        };
        error(&[
            b"keys add: ",
            what,
            b" is ",
            what_alg,
            b"; shirudo accepts only ML-DSA-87",
        ]);
        return -EKEYREJECTED;
    }
    0
}

/// The vouching certificate must be one the kernel verifies against
/// right now, not only one on disk, when the live target's set is the
/// one being extended.
fn check_voucher_live(set: &TrustedSet, voucher: &[u8; 32]) -> c_int {
    let Ok(id) = identity::read() else {
        return 0;
    };
    if id.keyring_type != SIG_KEYRING_BPF {
        return 0;
    }
    let ring = keyring::bpf_serial();
    if ring <= 0 {
        return 0;
    }
    let Some(c) = members(set).iter().find(|c| c.fingerprint() == voucher) else {
        return -ENOKEY;
    };
    let der = match crate::util::keys::cert_der(c) {
        Ok(der) => der,
        Err(ret) => return ret,
    };
    let ret = keyring::holds_cert(ring, der);
    if ret < 0 {
        return ret;
    }
    if ret != 0 { 0 } else { -ENOKEY }
}

fn keys_add(args: &[&CStr]) -> c_int {
    let (mut keys_dir_arg, mut vouch_path, mut cert) = (None, None, None);
    let mut p = OptParser::new(c"keys add", &ADD_OPTS, Some(&ADD_HELP), args, 1);

    loop {
        let opt = p.next();
        let value = || p.value().map(CStr::to_bytes);
        match opt {
            OPT_END => break,
            KEYS_ADD_VOUCH => vouch_path = value(),
            KEYS_ADD_KEYS_DIR => keys_dir_arg = value(),
            OPT_ARG => {
                if cert.is_some() {
                    p.usage_arg(b"unexpected argument ");
                    return EXIT_USAGE;
                }
                cert = value();
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    let (Some(cert), Some(vouch_path)) = (cert, vouch_path) else {
        p.usage(b"takes <cert.der> and --vouch <file>");
        return EXIT_USAGE;
    };
    if image_config::active() {
        error(&[b"target: add vouched BPF signers to the signed config selected for boot and reboot to enroll them"]);
        return 1;
    }
    let keys_dir_arg = keys_dir_arg.map(|d| message(&[d]));
    let keys_dir = keys_dir(keys_dir_arg.as_deref());
    let revoked = [keys_dir.to_bytes(), b"/revoked"].concat();
    if revoked.len() >= PATH_MAX {
        error(&[b"keys add: keys directory path too long"]);
        return 2;
    }
    let revoked = message(&[&revoked]);
    let cert_c = message(&[cert]);
    let der = match read_der(&cert_c) {
        Ok(der) => der,
        Err(err) => {
            error(&[b"keys add: read ", cert, b": ", strerr(-err)]);
            return 1;
        }
    };
    let Ok(digests) = digest_der(&der) else {
        error(&[b"keys add: ", cert, b" is not a certificate"]);
        return 1;
    };
    let fp = digests.fingerprint;
    if check_cert_algorithm(&der, cert) != 0 {
        return 1;
    }
    let fp_hex = hex(&fp);
    let set = match load(keys_dir, None, true) {
        Ok(set) => set,
        Err(ret) => {
            error(&[
                b"keys add: no trusted set under ",
                keys_dir.to_bytes(),
                b": ",
                strerr(-ret),
                b" (install the primary certificate first)",
            ]);
            return 1;
        }
    };
    if is_revoked(&revoked, &fp) {
        error(&[b"keys add: ", &fp_hex, b" was revoked on this target"]);
        return 1;
    }
    let vouch_c = message(&[vouch_path]);
    let sig = match read_der(&vouch_c) {
        Ok(sig) => sig,
        Err(err) => {
            error(&[b"keys add: read ", vouch_path, b": ", strerr(-err)]);
            return 1;
        }
    };
    let Ok(by) = verify_vouch(&set, &der, &sig) else {
        let n = set.len();
        error(&[
            b"keys add: ",
            vouch_path,
            b" does not vouch for ",
            &fp_hex,
            b" under any of the ",
            n.to_string().as_bytes(),
            b" trusted certificate",
            if n == 1 { b"" } else { b"s" },
        ]);
        return 1;
    };
    let by_hex = hex(&by);
    if keys_dir == KEYS_DIR {
        let ret = check_voucher_live(&set, &by);
        if ret != 0 {
            let why: Vec<u8> = if ret == -ENOKEY {
                Vec::new()
            } else {
                [b": ", strerr(-ret)].concat()
            };
            error(&[
                b"keys add: the vouching certificate ",
                &by_hex,
                b" is not in the bpf keyring this boot",
                &why,
            ]);
            return 1;
        }
    }
    if members(&set).iter().any(|c| *c.fingerprint() == fp) {
        info(&[b"keys add: ", &fp_hex, b" is already trusted"]);
        print(&[&fp_hex[..], b"\n"].concat());
        return 0;
    }
    // A set past the limit would fail to load at all, init included.
    if set.len() >= KEYS_MAX {
        error(&[
            b"keys add: the trusted set holds ",
            KEYS_MAX.to_string().as_bytes(),
            b" certificates, the most a target enrols",
        ]);
        return 1;
    }
    let installed = match install(keys_dir, &der, &sig) {
        Ok(path) => path,
        Err(ret) => {
            error(&[
                b"keys add: install under ",
                keys_dir.to_bytes(),
                b"/trusted: ",
                strerr(-ret),
            ]);
            return 1;
        }
    };
    audit(&[
        b"keys add: fingerprint=",
        &fp_hex,
        b" vouched_by=",
        &by_hex,
        b" path=",
        installed.to_bytes(),
    ]);
    info(&[
        b"keys add: ",
        &fp_hex,
        b" joins the set at the next boot; regenerate the initrd (shirudo-gen-initrd)",
    ]);
    print(&[&fp_hex[..], b"\n"].concat());
    0
}

fn format_key_event(
    ty: &CStr,
    fp_hex: &[u8],
    sha256: &[u8; 32],
    event: &[u8; 32],
) -> Result<([u8; 1024], usize), c_int> {
    let mut buf = [0u8; 1024];
    let mut e = JsonEmit::fixed(&mut buf);

    eventlog::record_open(&mut e, ty.to_bytes(), event);
    e.obj_open_key(b"key");
    e.kv_string(b"fingerprint", fp_hex);
    e.kv_string(b"cert_sha256", &hex(sha256));
    e.obj_close();
    e.obj_close();
    if e.err() != 0 {
        error(&[
            b"eventlog: ",
            ty.to_bytes(),
            b" entry encode failed: ",
            strerr(-e.err()),
        ]);
        return Err(e.err());
    }
    let len = e.written();
    Ok((buf, len))
}

/// The register learns of the revocation before anything else changes
/// in the archive, so evidence taken at any point names it. As for an
/// upatch event, no TPM is an error, not an unmeasured success.
fn measure_revoke_locked(sha256: &[u8; 32], fp_hex: &[u8]) -> c_int {
    let mut chain = [0u8; 32];

    let event = match chain::key_event(c"shirudo-key-revoke", sha256) {
        Ok(event) => event,
        Err(ret) => {
            error(&[
                b"keys revoke: cannot hash the revocation event: ",
                strerr(-ret),
                b"; the key is revoked but the revocation is NOT measured; operator must reconcile",
            ]);
            return ret;
        }
    };
    // An encoding failure must be found before the register moves.
    let (record, record_len) = match format_key_event(c"key_revoke", fp_hex, sha256, &event) {
        Ok(record) => record,
        Err(err) => {
            error(&[b"keys revoke: cannot write the record of the revocation; the key is revoked but the revocation is NOT measured; operator must reconcile"]);
            return err;
        }
    };
    let ret = chain::extend(&event, Some(&mut chain));
    if ret != 0 {
        let (what, category): (&[u8], &[u8]) = match ret {
            r if r == -ENODEV => (b"unavailable", b"tpm_error"),
            r if r == -EACCES => (b"is not the one init bound", b"tampered"),
            _ => (b"extend failed", b"tpm_error"),
        };
        error(&[
            b"keys revoke: register ",
            what,
            b" (category: ",
            category,
            b"); the key is revoked but the revocation is NOT measured; operator must reconcile",
        ]);
        return ret;
    }
    let ret = eventlog::append(&record[..record_len]);
    if ret != 0 {
        error(&[b"keys revoke: eventlog append failed after the extend: register and log disagree; the operator must reconcile"]);
        return ret;
    }
    audit(&[
        b"key revoke measured: fingerprint=",
        fp_hex,
        b" chain=",
        &hex(&chain),
    ]);
    0
}

fn measure_revoke(sha256: &[u8; 32], fp_hex: &[u8]) -> c_int {
    let lock = match eventlog::lock() {
        Ok(lock) => lock,
        Err(err) => {
            error(&[
                b"keys revoke: cannot take the register lock: ",
                strerr(-err),
                b"; the revocation is NOT measured",
            ]);
            return err;
        }
    };
    let ret = measure_revoke_locked(sha256, fp_hex);
    drop(lock);
    ret
}

/// A revocation cannot safely start while any stored archive has no signer.
pub(crate) fn revoke_check() -> c_int {
    let files = match dir_names(UPATCHES_DIR.as_bytes(), |n| name_has_suffix(n, b".upatch")) {
        Ok(files) => files,
        Err(err) => return if err == -ENOENT { 0 } else { err },
    };
    let mut ret = 0;
    for file in &files {
        let name = file.strip_suffix(b".upatch").unwrap_or(file);
        let err = if !name_valid(Some(name)) {
            error(&[b"keys revoke: invalid archive filename"]);
            -EINVAL
        } else {
            let name_c = message(&[name]);
            let err = crate::builtin::upatch::purge_check(&name_c);
            if err == UPATCH_PURGE_NO_ARCHIVE {
                0
            } else {
                if err != 0 {
                    error(&[
                        b"keys revoke: ",
                        name,
                        b".upatch names no signer: ",
                        strerr(-err),
                        b"; nothing revoked",
                    ]);
                }
                err
            }
        };
        if ret == 0 && err != 0 {
            ret = err;
        }
    }
    ret
}

/// Every archived upatch the revoked certificate signed goes: the kernel
/// would refuse to restore it at the next boot, and keeping it loaded
/// would keep running what a key nobody trusts any more authorised. The
/// At boot, an archive with no readable signer is left for restore to
/// ignore if nothing runs under its name. The rest are still tried when
/// one fails. How many went, or the last error.
fn purge_signed_by(der: &[u8], boot: bool) -> c_int {
    let mut cert = Cert::new();
    let (mut ret, mut purged) = (0, 0);

    // SAFETY: the bytes and a certificate to fill.
    if unsafe { cert_read_der(der.as_ptr(), der.len(), &mut cert) } != 0 {
        return -EINVAL;
    }
    let files = match dir_names(UPATCHES_DIR.as_bytes(), |n| name_has_suffix(n, b".upatch")) {
        Ok(files) => files,
        Err(err) => {
            return if err == -ENOENT { 0 } else { err };
        }
    };
    for file in &files {
        let Some(name) = file.strip_suffix(b".upatch") else {
            continue;
        };
        if !name_valid(Some(name)) {
            error(&[b"keys revoke: invalid archive filename"]);
            ret = -EINVAL;
            continue;
        }
        let name_c = message(&[name]);
        let prc = crate::builtin::upatch::purge(&name_c, &cert, c"key_revoke");
        if prc == UPATCH_PURGE_OTHER_SIGNER || prc == UPATCH_PURGE_NO_ARCHIVE {
            continue;
        }
        if prc == UPATCH_PURGE_NO_SIGNER && boot {
            warn(&[
                b"keys revoke: ",
                name,
                b".upatch is left for boot-restore to ignore",
            ]);
            continue;
        }
        let prc = if prc == UPATCH_PURGE_NO_SIGNER {
            -crate::errno::EBADMSG
        } else {
            prc
        };
        if prc < 0 {
            error(&[b"keys revoke: purge ", name, b": ", strerr(-prc)]);
            ret = prc;
            continue;
        }
        let what: &[u8] = if prc != 0 {
            b"unloaded and purged"
        } else {
            b"purged from the archive"
        };
        info(&[b"keys revoke: ", name, b" ", what]);
        purged += 1;
    }
    if ret != 0 { ret } else { purged }
}

/// Revokes the certificate `der` of a config image: out of the .bpf
/// keyring, measured unless at boot, and what it signed purged.
pub(crate) fn revoke_image(der: &[u8], boot: bool) -> c_int {
    let ring = keyring::bpf_serial();

    if ring < 0 {
        return ring;
    }
    let key = keyring::find_cert(ring, der);
    if key != -ENOKEY && key < 0 {
        return key;
    }
    if key >= 0 {
        let ret = keyring::unlink_key(ring, key);
        if ret != 0 {
            return ret;
        }
        if !boot {
            let digests = match digest_der(der) {
                Ok(d) => d,
                Err(ret) => return ret,
            };
            let ret = measure_revoke(&digests.sha256, &hex(&digests.fingerprint));
            if ret != 0 {
                return ret;
            }
        }
    }
    purge_signed_by(der, boot).min(0)
}

fn keys_show(args: &[&CStr]) -> c_int {
    let mut keys_dir_arg = None;
    let mut json = false;
    let mut p = OptParser::new(c"keys", &OPTS, Some(&HELP), args, 1);

    loop {
        match p.next() {
            OPT_END => break,
            KEYS_KEYS_DIR => keys_dir_arg = p.value().map(CStr::to_bytes),
            KEYS_JSON => json = true,
            OPT_ARG => {
                p.usage_arg(b"unexpected argument ");
                return EXIT_USAGE;
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    let keys_dir_arg = keys_dir_arg.map(|d| message(&[d]));
    let keys_dir: &CStr = if image_config::active() {
        RUNTIME_KEYS_DIR
    } else {
        keys_dir(keys_dir_arg.as_deref())
    };
    let (pkey_path, cert_path) = match key_files(keys_dir.to_bytes()) {
        Ok(paths) => paths,
        Err(ret) => {
            error(&[
                b"keys: invalid keys dir ",
                keys_dir.to_bytes(),
                b": ",
                strerr(-ret),
            ]);
            return 2;
        }
    };
    // Both roles can coexist on one host, so report whatever is present:
    // the on-disk cert and signing key, then the kernel keyrings once
    // `shirudo init` has filled them.
    let mut buf = if json { vec![0u8; 65536] } else { Vec::new() };
    let mut emitter = json.then(|| JsonEmit::fixed(&mut buf));
    let mut out: Out = emitter.as_mut();
    let (mut shown, mut ret) = (false, 0);

    if let Some(e) = &mut out {
        e.obj_open();
        e.kv_int(b"schema", 1);
    }
    if path_exists(&cert_path) {
        if dump_disk_material(&mut out, &cert_path, &pkey_path) != 0 {
            ret = 1;
        }
        shown = true;
    } else if let Some(e) = &mut out {
        e.kv_null(b"cert");
        e.kv_null(b"signing_key");
    }
    let loaded = load(keys_dir, None, true);
    let have_set = loaded.is_ok();
    let set = loaded.unwrap_or_default();
    if let Some(e) = &mut out {
        e.arr_open(b"trusted_set");
    }
    if have_set
        && (out.is_some() || set.len() > 1 || set.n_revoked() != 0 || set.n_unvouched() != 0)
    {
        if out.is_none() {
            let n = set.len();
            print(
                &[
                    if shown { &b"\n"[..] } else { b"" },
                    b"Trusted set (",
                    n.to_string().as_bytes(),
                    b" member",
                    if n == 1 { b"" } else { b"s" },
                    b", ",
                    set.n_revoked().to_string().as_bytes(),
                    b" revoked, ",
                    set.n_unvouched().to_string().as_bytes(),
                    b" unvouched):\n",
                ]
                .concat(),
            );
        }
        for c in members(&set) {
            let (fp, sha) = (hex(c.fingerprint()), hex(c.sha256()));
            let voucher = c.voucher().map(hex);

            if let Some(e) = &mut out {
                e.obj_open();
                e.kv_string(b"fingerprint", &fp);
                e.kv_string(b"sha256", &sha);
                e.kv_bool(b"primary", c.primary());
                match &voucher {
                    Some(voucher) => e.kv_string(b"voucher", voucher),
                    None => e.kv_null(b"voucher"),
                }
                e.obj_close();
                continue;
            }
            print(
                &[
                    &b"  "[..],
                    &fp[..],
                    if c.primary() {
                        &b"  (primary)"[..]
                    } else {
                        b""
                    },
                    b"\n    sha256 ",
                    &sha,
                    b"\n",
                ]
                .concat(),
            );
            if let Some(voucher) = &voucher {
                print(&[b"    vouched by ", &voucher[..], b"\n"].concat());
            }
        }
        if out.is_none() {
            shown = true;
        }
    }
    if let Some(e) = &mut out {
        e.arr_close();
    }
    let (id, id_rc) = match identity::read() {
        Ok(id) => (id, 0),
        Err(err) => (Identity::zeroed(), err),
    };
    let n_keys = id.n_keys.min(IDENTITY_KEYS_MAX) as usize;
    let n_dm_keys = (id.n_dm_verity_keys as usize).min(IDENTITY_KEYS_MAX as usize);
    let anchors = [
        Anchor {
            label: b".bpf",
            serial: keyring::bpf_serial,
            frozen: id.keyring_serial,
            keys: &id.key_serials[..n_keys],
        },
        Anchor {
            label: b".dm-verity",
            serial: keyring::dm_verity_serial,
            frozen: id.dm_verity_ring,
            keys: &id.dm_verity_keys[..n_dm_keys],
        },
    ];
    if let Some(e) = &mut out {
        e.arr_open(b"keyrings");
    }
    for a in &anchors {
        let ring = if id_rc != 0 { -ENOKEY } else { (a.serial)() };

        if ring >= 0 {
            if shown && out.is_none() {
                print(b"\n");
            }
            if list_keyring(&mut out, ring, a, id_rc) != 0 {
                ret = 1;
            }
            shown = true;
        } else if ring == -ENOKEY && id_rc != 0 {
            if shown || out.is_some() {
                if out.is_none() {
                    print(b"\n");
                }
                keyring_absent(&mut out, a, ring, id_rc);
            }
        } else {
            if shown && out.is_none() {
                print(b"\n");
            }
            keyring_absent(&mut out, a, ring, id_rc);
            shown = true;
            ret = 1;
        }
    }
    if let Some(e) = &mut out {
        e.arr_close();
        e.obj_close();
        if e.err() != 0 {
            error(&[b"keys: json encode failed"]);
            ret = 1;
        } else {
            let n = e.written();
            print(&[&buf[..n], b"\n"].concat());
        }
    }
    if !shown {
        error(&[
            b"no shirudo key material on this host: no ",
            cert_path.to_bytes(),
            b" and no .bpf kernel keyring; run shirudo genkey on an operator or shirudo init on a target",
        ]);
        ret = 1;
    }
    ret
}

/// `shirudo keys`, on `args` from its name on.
pub(crate) fn cmd_keys(args: &[&CStr]) -> c_int {
    let word = |i: usize| args.get(i).map(|a| a.to_bytes());

    if is_help(word(1)) {
        print_help(&HELP);
        return 0;
    }
    if is_list_cmds(word(1)) {
        print_subcmd_list(&SUBCMDS);
        return 0;
    }
    let Some(typed) = args.get(1).filter(|a| a.to_bytes().first() != Some(&b'-')) else {
        return keys_show(args);
    };
    let Some(sub) = resolve_subcommand(c"shirudo keys", typed, &SUBCMDS) else {
        return 2;
    };
    match sub.to_bytes() {
        b"add" => keys_add(&args[1..]),
        b"revoke" => {
            if args.len() == 3 && is_help(word(2)) {
                print_help(&REVOKE_HELP);
                return 0;
            }
            error(&[b"keys revoke: put revocation records in a signed config image, then run `shirudo image update`"]);
            1
        }
        _ => super::build::forward(c"keys vouch", &[c"keys", c"vouch"], &args[2..]),
    }
}

#[cfg(test)]
mod algorithm_tests {
    use super::format_algorithm;

    #[test]
    fn algorithm_that_fits_is_complete() {
        assert_eq!(format_algorithm(b"RSA", Some(2048)), b"RSA-2048");
        assert_eq!(format_algorithm(&[b'x'; 63], None), &[b'x'; 63]);
    }

    #[test]
    fn algorithm_that_does_not_fit_is_unknown() {
        assert_eq!(format_algorithm(&[b'x'; 64], None), b"?");
        assert_eq!(format_algorithm(&[b'x'; 63], Some(1)), b"?");
    }
}

#[cfg(test)]
mod event_record_tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore = "gmtime_r is a foreign call")]
    fn key_record_is_complete_before_the_register_extends() {
        let (line, len) =
            format_key_event(c"key_revoke", b"fingerprint", &[0x12; 32], &[0x34; 32]).unwrap();
        assert!(crate::util::json::parse_schema(&line[..len], &[], &mut ()).is_ok());
        let certificate_hex = b"12".repeat(32);
        assert!(
            line[..len]
                .windows(64)
                .any(|part| part == certificate_hex.as_slice())
        );
        assert!(format_key_event(c"key_revoke", &[0xff], &[0x12; 32], &[0x34; 32]).is_err());
    }
}
