// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The crypto on libcrypto, linked into both profiles:
//! SHA-256, HMAC and AES, base64, the P-256 and RSA-OAEP operations of
//! the TPM's protocol, and the X.509 certificates and CMS signatures a
//! target trusts. Every key algorithm the kernel verifies comes from one
//! implementation.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::marker::PhantomData;
use core::ptr::{self, NonNull};
use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::os::fd::BorrowedFd;

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::base64;
use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;
use openssl::cms::{CMSOptions, CmsContentInfo};
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::hash::{Hasher, MessageDigest, hash};
use openssl::md::Md;
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Public};
use openssl::pkey_ctx::PkeyCtx;
use openssl::rsa::{Padding, Rsa};
use openssl::sign::Signer;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::{X509, X509Ref, X509StoreContext};
use openssl_sys as ffi;

use crate::errno::{
    EBADMSG, EINVAL, EIO, EKEYREJECTED, ENAMETOOLONG, ENOMEM, ENOPKG, EPROTONOSUPPORT,
};
use crate::ffi::slice;
use crate::sys::libc::O_RDONLY;
use crate::sys::openssl as more;
use crate::text::strscpy;
use crate::util::io::{open_trusted, read_whole};

pub(crate) const SHA256_LEN: usize = 32;

/// The largest certificate read.
const KEYS_DER_MAX: usize = 1024 * 1024;

/// An optional X.509 certificate. The owned OpenSSL value frees itself.
pub struct Cert {
    imp: Option<X509>,
}

impl Cert {
    pub(crate) const fn new() -> Self {
        Cert { imp: None }
    }

    /// Replace the certificate this value holds.
    fn hold(&mut self, x509: X509) {
        self.imp = Some(x509);
    }
}

/// The certificate a cert holds, or none.
///
/// # Safety
///
/// `cert` is NULL or points to a cert, which outlives what this gives.
unsafe fn x509_of<'a>(cert: *const Cert) -> Option<&'a X509Ref> {
    // SAFETY: the caller passes NULL or a cert that outlives the result.
    unsafe { cert.as_ref() }.and_then(|c| c.imp.as_deref())
}

/// `struct sha256_ctx`: a digest under way, which sha256_final() or
/// sha256_free() releases.
#[repr(C)]
pub struct Sha256Ctx {
    imp: Option<Box<Hasher>>,
}

impl Sha256Ctx {
    pub(crate) const fn new() -> Self {
        Sha256Ctx { imp: None }
    }
}

/// `struct cert_pubkey`.
#[repr(C)]
pub struct CertPubkey {
    pub(crate) rsa: bool,
    pub(crate) n: [u8; 512],
    pub(crate) n_len: usize,
    pub(crate) e: u32,
    pub(crate) x: [u8; 32],
    pub(crate) y: [u8; 32],
}

impl CertPubkey {
    #[cfg(shirudo_fuzz)]
    const fn empty() -> Self {
        Self {
            rsa: false,
            n: [0; 512],
            n_len: 0,
            e: 0,
            x: [0; 32],
            y: [0; 32],
        }
    }
}

const _: () = assert!(size_of::<CertPubkey>() == 600);
const _: () = assert!(size_of::<Sha256Ctx>() == size_of::<*mut c_void>());

/// Drops what libcrypto queued for this thread, the ERR_clear_error()
/// of the calls the crate does not make itself.
fn clear_errors() {
    drop(ErrorStack::get());
}

/// The certificate DER `der` begins with, read as d2i_X509_bio() reads
/// a file: one object, as long as its header says, and libcrypto's
/// reasons when it is not one.
pub(crate) fn x509_from_der_bio(der: &[u8]) -> Result<X509, ErrorStack> {
    let bio = MemBio::from_slice(der)?;
    // SAFETY: the BIO holds the DER bytes until this call returns.
    let x509 = unsafe { ffi::d2i_X509_bio(bio.0, ptr::null_mut()) };
    if x509.is_null() {
        return Err(ErrorStack::get());
    }
    // SAFETY: d2i_X509_bio returned a new X509 owned by this value.
    Ok(unsafe { X509::from_ptr(x509) })
}

/// The certificate at `path`, PEM or DER, from a file only root may
/// write: -EINVAL for one that does not parse, or -errno.
fn read_x509(path: &CStr) -> Result<X509, c_int> {
    let fd = open_trusted(path, O_RDONLY)?;
    let mut text = Vec::new();

    File::from(fd).read_to_end(&mut text).map_err(|_| -EINVAL)?;
    X509::from_pem(&text)
        .or_else(|_| x509_from_der_bio(&text))
        .map_err(|_| -EINVAL)
}

/// SHA-256 of `data`: -EIO when libcrypto fails.
pub(crate) fn sha256(data: &[u8]) -> Result<[u8; SHA256_LEN], c_int> {
    let digest = hash(MessageDigest::sha256(), data).map_err(|_| -EIO)?;

    (*digest).try_into().map_err(|_| -EIO)
}

/// # Safety
///
/// `ctx` is NULL or points to a context.
pub(crate) unsafe fn sha256_init(ctx: *mut Sha256Ctx) -> c_int {
    // SAFETY: the caller passes NULL or a context.
    let Some(ctx) = (unsafe { ctx.as_mut() }) else {
        return -EINVAL;
    };

    ctx.imp = None;
    match Hasher::new(MessageDigest::sha256()) {
        Ok(h) => {
            ctx.imp = Some(Box::new(h));
            0
        }
        Err(_) => -EIO,
    }
}

/// # Safety
///
/// `ctx` is NULL or points to a context, and `data` holds `len` bytes.
pub(crate) unsafe fn sha256_update(ctx: *mut Sha256Ctx, data: *const c_void, len: usize) -> c_int {
    // SAFETY: the caller passes NULL or a context.
    let Some(h) = (unsafe { ctx.as_mut() }).and_then(|c| c.imp.as_deref_mut()) else {
        return -EINVAL;
    };

    if len != 0 && data.is_null() {
        return -EINVAL;
    }
    // SAFETY: the caller's data.
    if h.update(unsafe { slice(data.cast::<u8>(), len) }).is_ok() {
        0
    } else {
        -EIO
    }
}

/// # Safety
///
/// `ctx` is NULL or points to a context, and `out` is NULL or has room
/// for 32 bytes.
pub(crate) unsafe fn sha256_final(ctx: *mut Sha256Ctx, out: *mut u8) -> c_int {
    // SAFETY: the caller passes NULL or a context.
    let Some(ctx) = (unsafe { ctx.as_mut() }) else {
        return -EINVAL;
    };
    if out.is_null() {
        return -EINVAL;
    }
    let Some(mut h) = ctx.imp.take() else {
        return -EINVAL;
    };

    match h.finish() {
        Ok(d) if d.len() == SHA256_LEN => {
            // SAFETY: the caller's room for the digest.
            unsafe { ptr::copy_nonoverlapping(d.as_ptr(), out, SHA256_LEN) };
            0
        }
        _ => -EIO,
    }
}

/// # Safety
///
/// `ctx` is NULL or points to a context.
pub(crate) unsafe fn sha256_free(ctx: *mut Sha256Ctx) {
    // SAFETY: the caller passes NULL or a context.
    if let Some(ctx) = unsafe { ctx.as_mut() } {
        ctx.imp = None;
    }
}

/// SHA-256 of `data` into `out`, zeros when it fails, as
/// sha256_buffer().
pub(crate) fn sha256_into(data: &[u8], out: &mut [u8; 32]) -> c_int {
    match sha256(data) {
        Ok(d) => {
            *out = d;
            0
        }
        Err(err) => {
            *out = [0; 32];
            err
        }
    }
}

/// SHA-256 of the `len` bytes at `data` into `out`; where it fails, a
/// zeroed digest, so that no caller reads a stale one.
///
/// # Safety
///
/// `data` holds `len` bytes, and `out` is NULL or has room for 32.
pub(crate) unsafe fn sha256_buffer(data: *const c_void, len: usize, out: *mut u8) -> c_int {
    if out.is_null() {
        return -EINVAL;
    }
    let digest = if len != 0 && data.is_null() {
        Err(-EINVAL)
    } else {
        // SAFETY: the caller's data.
        sha256(unsafe { slice(data.cast::<u8>(), len) })
    };
    let (d, ret) = match digest {
        Ok(d) => (d, 0),
        Err(err) => ([0; SHA256_LEN], err),
    };
    // SAFETY: the caller's room for the digest.
    unsafe { ptr::copy_nonoverlapping(d.as_ptr(), out, SHA256_LEN) };
    ret
}

/// `data` in padded base64 on one line: -EINVAL for more bytes than an
/// int counts.
pub(crate) fn base64(data: &[u8]) -> Result<Vec<u8>, c_int> {
    if data.len() > c_int::MAX as usize {
        return Err(-EINVAL);
    }
    let text = base64::encode_block(data);
    if text.len() != 4 * data.len().div_ceil(3) {
        return Err(-EIO);
    }
    Ok(text.into_bytes())
}

/// # Safety
///
/// `data` is NULL or holds `len` bytes, and `out` is NULL or has room
/// for `out_sz`.
pub(crate) unsafe fn base64_encode(
    data: *const u8,
    len: usize,
    out: *mut c_char,
    out_sz: usize,
) -> c_int {
    if data.is_null() || out.is_null() || len > c_int::MAX as usize {
        return -EINVAL;
    }
    let need = 4 * len.div_ceil(3) + 1;

    if out_sz < need {
        return -EINVAL;
    }
    // SAFETY: the caller's data.
    let text = match base64(unsafe { slice(data, len) }) {
        Ok(text) => text,
        Err(err) => return err,
    };
    // SAFETY: the caller's room for need bytes.
    unsafe { ptr::copy_nonoverlapping(text.as_ptr(), out.cast(), text.len()) };
    // SAFETY: need - 1 lies within the caller's output room.
    unsafe { *out.add(need - 1) = 0 };
    0
}

/// The P-256 public key at the point (x, y), or none for one not on the
/// curve.
fn p256_public_key(x: &[u8; 32], y: &[u8; 32]) -> Option<PKey<Public>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).ok()?;
    let (x, y) = (BigNum::from_slice(x).ok()?, BigNum::from_slice(y).ok()?);
    let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y).ok()?;

    PKey::from_ec_key(key).ok()
}

/// 0 when (r, s) is the ECDSA P-256 signature of the digest by the key
/// at (x, y), -EKEYREJECTED when not, -EINVAL for a key off the curve.
pub(crate) fn ecdsa_p256_verify(
    x: &[u8; 32],
    y: &[u8; 32],
    digest: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
) -> c_int {
    let Some(key) = p256_public_key(x, y) else {
        clear_errors();
        return -EINVAL;
    };
    let verified = (|| -> Result<Result<bool, ErrorStack>, ErrorStack> {
        let sig =
            EcdsaSig::from_private_components(BigNum::from_slice(r)?, BigNum::from_slice(s)?)?;
        let der = sig.to_der()?;
        let mut ctx = PkeyCtx::new(&key)?;

        ctx.verify_init()?;
        ctx.set_signature_md(Md::sha256())?;
        Ok(ctx.verify(digest, &der))
    })();

    clear_errors();
    match verified {
        Ok(Ok(true)) => 0,
        Ok(_) => -EKEYREJECTED,
        Err(_) => -EIO,
    }
}

/// The certificate `der` holds, as cert_read_der() reads it: -EINVAL
/// for one that does not parse.
pub(crate) fn x509_from_der(der: &[u8]) -> Result<X509, c_int> {
    if der.len() > c_long::MAX as usize {
        return Err(-EINVAL);
    }
    X509::from_der(der).map_err(|_| -EINVAL)
}

/// The provider's name for the certificate's key, as
/// cert_key_algorithm() gives it into `room` bytes: -ENOPKG without one,
/// -ENAMETOOLONG for one that does not fit.
pub(crate) fn key_algorithm(x509: &X509Ref, room: usize) -> Result<CString, c_int> {
    let Some(name) = x509.public_key().ok().and_then(|k| key_type_name(&k)) else {
        clear_errors();
        return Err(-ENOPKG);
    };
    if name.as_bytes().len() >= room {
        return Err(-ENAMETOOLONG);
    }
    Ok(name)
}

/// The certificate in `der` into `cert`: 0 or -EINVAL.
///
/// # Safety
///
/// `der` holds `len` bytes, and `cert` points to a cert.
pub(crate) unsafe fn cert_read_der(der: *const u8, len: usize, cert: *mut Cert) -> c_int {
    if der.is_null() || cert.is_null() || len > c_long::MAX as usize {
        return -EINVAL;
    }
    // SAFETY: the caller's cert.
    let cert = unsafe { &mut *cert };

    cert.imp = None;
    // SAFETY: the caller's DER bytes.
    match X509::from_der(unsafe { slice(der, len) }) {
        Ok(x509) => {
            cert.hold(x509);
            0
        }
        Err(_) => -EINVAL,
    }
}

/// A DER or a PEM certificate in `buf`, as cert_read_file() takes one
/// from a file, into `cert`: 0 or -EINVAL.
pub(crate) fn cert_read_memory(buf: &[u8], cert: &mut Cert) -> c_int {
    cert.imp = None;
    if buf.len() > c_int::MAX as usize {
        return -EINVAL;
    }
    match X509::from_der(buf).or_else(|_| X509::from_pem(buf)) {
        Ok(x509) => {
            cert.hold(x509);
            0
        }
        Err(_) => -EINVAL,
    }
}

/// # Safety
///
/// `path` is NULL or a C string, and `cert` NULL or points to a cert.
pub(crate) unsafe fn cert_read_file(path: *const c_char, cert: *mut Cert) -> c_int {
    if path.is_null() || cert.is_null() {
        return -EINVAL;
    }
    // SAFETY: the caller's cert.
    let cert = unsafe { &mut *cert };

    cert.imp = None;
    // SAFETY: the caller's C string.
    match read_x509(unsafe { CStr::from_ptr(path) }) {
        Ok(x509) => {
            cert.hold(x509);
            0
        }
        Err(err) => err,
    }
}

/// # Safety
///
/// `cert` is NULL or points to a cert.
pub(crate) unsafe fn cert_read_fd(fd: BorrowedFd<'_>, cert: *mut Cert) -> c_int {
    if cert.is_null() {
        return -EINVAL;
    }
    let der = match read_whole(fd, KEYS_DER_MAX) {
        Ok(der) => der,
        Err(err) => return err,
    };
    // SAFETY: the certificate's bytes, and the caller's room.
    unsafe { cert_read_der(der.as_ptr(), der.len(), cert) }
}

/// The DER SubjectPublicKeyInfo of the certificate as it holds it.
fn spki_der(x509: &X509Ref) -> Option<Vec<u8>> {
    // SAFETY: the public key belongs to the live certificate.
    let spki = unsafe { more::X509_get_X509_PUBKEY(x509.as_ptr()) };
    if spki.is_null() {
        return None;
    }
    // SAFETY: the public key is live; a null output asks for its size.
    let len = unsafe { more::i2d_X509_PUBKEY(spki, ptr::null_mut()) };
    if len <= 0 {
        return None;
    }
    let mut der = vec![0u8; usize::try_from(len).ok()?];
    let mut p = der.as_mut_ptr();
    // SAFETY: der has the size the same public key just reported.
    let written = unsafe { more::i2d_X509_PUBKEY(spki, &mut p) };
    (written == len).then_some(der)
}

/// SHA-256 over the DER SubjectPublicKeyInfo, the bytes Go's
/// x509.MarshalPKIXPublicKey writes; X509_pubkey_digest() hashes only the
/// key's bit string, which is easy to mistake for it. Re-encoding the
/// certificate's own X509_PUBKEY keeps the value identical for every key
/// algorithm the X.509 parser accepts, including ML-DSA keys libcrypto
/// cannot otherwise marshal as a bare EVP_PKEY on older releases.
pub(crate) fn pubkey_digest(x509: &X509Ref) -> Result<[u8; SHA256_LEN], c_int> {
    let der = spki_der(x509).ok_or(-EINVAL)?;

    sha256(&der).map_err(|_| -EINVAL)
}

/// # Safety
///
/// `cert` is NULL or points to a cert, and `out` NULL or room for 32.
pub(crate) unsafe fn cert_pubkey_digest(cert: *const Cert, out: *mut u8) -> c_int {
    // SAFETY: the caller passes NULL or a cert.
    let Some(x509) = (unsafe { x509_of(cert) }).filter(|_| !out.is_null()) else {
        return -EINVAL;
    };
    match pubkey_digest(x509) {
        Ok(d) => {
            // SAFETY: the caller's room for the digest.
            unsafe { ptr::copy_nonoverlapping(d.as_ptr(), out, SHA256_LEN) };
            0
        }
        Err(err) => err,
    }
}

/// The provider's name for the key's algorithm, "ML-DSA-87".
pub(crate) fn key_type_name<T>(key: &PKeyRef<T>) -> Option<CString> {
    // SAFETY: the key, whose type's name is NULL or a C string of
    // libcrypto's.
    let name = unsafe { more::EVP_PKEY_get0_type_name(key.as_ptr()) };

    // SAFETY: a C string, copied before the key can go.
    (!name.is_null()).then(|| unsafe { CStr::from_ptr(name) }.to_owned())
}

/// The provider's name for the cert's public key, "ML-DSA-87".
///
/// # Safety
///
/// `cert` is NULL or points to a cert, and `out` NULL or room for
/// `out_sz`.
pub(crate) unsafe fn cert_key_algorithm(
    cert: *const Cert,
    out: *mut c_char,
    out_sz: usize,
) -> c_int {
    // SAFETY: the caller passes NULL or a cert.
    let Some(x509) = (unsafe { x509_of(cert) }).filter(|_| !out.is_null() && out_sz != 0) else {
        return -EINVAL;
    };
    let Some(name) = x509.public_key().ok().and_then(|k| key_type_name(&k)) else {
        clear_errors();
        return -ENOPKG;
    };
    // SAFETY: the caller's room.
    let out = unsafe { crate::ffi::bytes_mut(out.cast(), out_sz) };
    if strscpy(out, name.to_bytes()).is_err() {
        return -ENAMETOOLONG;
    }
    0
}

/// A memory BIO, freed when it goes. An input BIO borrows its bytes.
struct MemBio<'a>(*mut ffi::BIO, PhantomData<&'a [u8]>);

impl MemBio<'static> {
    fn new() -> Option<Self> {
        // SAFETY: BIO_s_mem takes no pointer.
        let method = unsafe { ffi::BIO_s_mem() };
        // SAFETY: method is the memory BIO type from libcrypto.
        let bio = unsafe { ffi::BIO_new(method) };

        (!bio.is_null()).then_some(MemBio(bio, PhantomData))
    }
}

impl<'a> MemBio<'a> {
    fn from_slice(bytes: &'a [u8]) -> Result<Self, ErrorStack> {
        let len = c_int::try_from(bytes.len()).map_err(|_| ErrorStack::get())?;
        // SAFETY: bytes stay live while this BIO borrows them.
        let bio = unsafe { ffi::BIO_new_mem_buf(bytes.as_ptr().cast(), len) };
        if bio.is_null() {
            return Err(ErrorStack::get());
        }
        Ok(MemBio(bio, PhantomData))
    }

    /// What was written to it.
    fn data(&self) -> &[u8] {
        let mut text: *mut c_char = ptr::null_mut();
        // SAFETY: the BIO, asked where its bytes are, BIO_get_mem_data().
        let len = unsafe { ffi::BIO_ctrl(self.0, ffi::BIO_CTRL_INFO, 0, (&raw mut text).cast()) };

        if len <= 0 || text.is_null() {
            return &[];
        }
        // SAFETY: the len bytes the BIO holds, while it lives unwritten.
        unsafe { core::slice::from_raw_parts(text.cast(), len as usize) }
    }
}

impl Drop for MemBio<'_> {
    fn drop(&mut self) {
        // SAFETY: this BIO came from new() or from_slice() and is freed once.
        unsafe { ffi::BIO_free_all(self.0) };
    }
}

/// The subject on one line, "O=Example, CN=fleet", control bytes
/// escaped.
///
/// # Safety
///
/// `cert` is NULL or points to a cert, and `out` NULL or room for
/// `out_sz`.
pub(crate) unsafe fn cert_subject(cert: *const Cert, out: *mut c_char, out_sz: usize) -> c_int {
    // SAFETY: the caller passes NULL or a cert.
    let Some(x509) = (unsafe { x509_of(cert) }).filter(|_| !out.is_null() && out_sz != 0) else {
        return -EINVAL;
    };
    let Some(bio) = MemBio::new() else {
        return -ENOMEM;
    };
    let flags = more::XN_FLAG_ONELINE & !more::XN_FLAG_SPC_EQ;
    // SAFETY: the BIO and the certificate's own subject.
    if unsafe { more::X509_NAME_print_ex(bio.0, x509.subject_name().as_ptr(), 0, flags) } < 0 {
        return -EINVAL;
    }
    let text = bio.data();
    if text.len() >= out_sz {
        return -ENAMETOOLONG;
    }
    // SAFETY: text fits in the caller's output room.
    unsafe { ptr::copy_nonoverlapping(text.as_ptr(), out.cast(), text.len()) };
    // SAFETY: text.len() leaves one byte for the terminator.
    unsafe { *out.add(text.len()) = 0 };
    0
}

/// A UTC time, as `struct tm` holds one: the year whole, the month
/// from 1.
pub(crate) struct Utc {
    pub(crate) year: i64,
    pub(crate) month: u32,
    pub(crate) day: u32,
    pub(crate) hour: u32,
    pub(crate) minute: u32,
    pub(crate) second: u32,
}

/// The time an ASN1_TIME holds, as ASN1_TIME_to_tm() reads it: from its
/// distance to the epoch, which libcrypto parses the same way.
pub(crate) fn utc(t: &Asn1TimeRef) -> Option<Utc> {
    let epoch = Asn1Time::from_unix(0).ok()?;
    let diff = epoch.diff(t).ok()?;
    let secs = i64::from(diff.days) * 86_400 + i64::from(diff.secs);
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Days since 1970-01-01 to the proleptic Gregorian date, after
    // Howard Hinnant's civil_from_days().
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);

    Some(Utc {
        year,
        month: month as u32,
        day: day as u32,
        hour: (rest / 3600) as u32,
        minute: (rest / 60 % 60) as u32,
        second: (rest % 60) as u32,
    })
}

/// The start of the validity period as a UTC date, YYYY-MM-DD.
///
/// # Safety
///
/// `cert` is NULL or points to a cert, and `out` has room for 11 bytes.
pub(crate) unsafe fn cert_not_before(cert: *const Cert, out: *mut c_char) -> c_int {
    // SAFETY: the caller passes NULL or a cert.
    let Some(x509) = (unsafe { x509_of(cert) }) else {
        return -EINVAL;
    };
    let Some(t) = utc(x509.not_before()) else {
        return -EINVAL;
    };
    // strftime()'s "%Y" has four digits from year 1000 to 9999 alone.
    if !(1000..=9999).contains(&t.year) {
        return -EINVAL;
    }
    let text = format!("{:04}-{:02}-{:02}\0", t.year, t.month, t.day);
    // SAFETY: the caller's room for the 11 bytes.
    unsafe { ptr::copy_nonoverlapping(text.as_ptr(), out.cast(), 11) };
    0
}

/// A CMS signature needs at least one signer, and every signer needs an
/// identifier that can be attributed to a certificate.
fn cms_has_signers(cms: &CmsContentInfo) -> bool {
    // SAFETY: cms owns its signer info stack.
    let signers = unsafe { more::CMS_get0_SignerInfos(cms.as_ptr()) };
    if signers.is_null() {
        return false;
    }
    // SAFETY: the stack belongs to cms.
    let count = unsafe { ffi::OPENSSL_sk_num(signers) };
    if count <= 0 {
        return false;
    }
    for i in 0..count {
        // SAFETY: i is within the stack.
        let si = unsafe { ffi::OPENSSL_sk_value(signers, i) }.cast::<more::CmsSignerInfo>();
        if si.is_null() {
            return false;
        }
        let (mut key, mut issuer, mut serial) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        // SAFETY: si belongs to cms; the pointers borrow its signer identifier.
        let ok =
            unsafe { more::CMS_SignerInfo_get0_signer_id(si, &mut key, &mut issuer, &mut serial) };
        if ok == 0 {
            return false;
        }
        if !key.is_null() {
            // SAFETY: key borrows an ASN.1 string from si.
            if unsafe { ffi::ASN1_STRING_length(key.cast()) } <= 0 {
                return false;
            }
        } else if issuer.is_null() || serial.is_null() {
            return false;
        }
    }
    true
}

/// Parse a complete CMS envelope with at least one signer.
fn read_cms(signature: &[u8]) -> Option<CmsContentInfo> {
    let len = c_long::try_from(signature.len())
        .ok()
        .filter(|&n| n > 0 && n <= c_int::MAX.into())?;
    let mut next = signature.as_ptr();
    // SAFETY: the slice holds len bytes and next receives the parse end.
    let cms = unsafe { ffi::d2i_CMS_ContentInfo(ptr::null_mut(), &mut next, len) };
    if cms.is_null() {
        return None;
    }
    // SAFETY: the structure d2i made, owned from here.
    let cms = unsafe { CmsContentInfo::from_ptr(cms) };
    // SAFETY: d2i leaves next within the input slice after success.
    let consumed = usize::try_from(unsafe { next.offset_from(signature.as_ptr()) }).ok()?;
    let suffix = signature.get(consumed..)?;
    if !suffix.is_empty() || !cms_has_signers(&cms) {
        return None;
    }
    Some(cms)
}

/// Check a new artifact before handing its signature to the kernel.
pub(crate) fn cms_check_signers(signature: &[u8]) -> c_int {
    if read_cms(signature).is_some() {
        0
    } else {
        clear_errors();
        -EBADMSG
    }
}

/// Whether `signature` is a detached CMS signature of `payload` by the
/// cert. The algorithm comes from the SignerInfo, so an ML-DSA
/// signature, with signedAttrs and SHA-512 or bare on OpenSSL 4, and an
/// RSA one verify through one call; ML-DSA needs libcrypto >= 3.5.
pub(crate) fn verify_detached(payload: &[u8], signature: &[u8], cert: &Cert) -> c_int {
    let Some(x509) = cert.imp.as_deref() else {
        return -EINVAL;
    };
    verify_detached_x509(payload, signature, x509)
}

/// Whether `signature` is a detached CMS signature of `payload` by
/// `x509`: 0 or -EINVAL, as verify_detached() answers.
pub(crate) fn verify_detached_x509(payload: &[u8], signature: &[u8], x509: &X509Ref) -> c_int {
    if payload.len() > c_int::MAX as usize || signature.len() > c_int::MAX as usize {
        return -EINVAL;
    }
    let verified = (|| -> Result<(), ErrorStack> {
        let mut store = X509StoreBuilder::new()?;
        store.add_cert(x509.to_owned())?;
        store.set_flags(X509VerifyFlags::NO_CHECK_TIME)?;
        let store = store.build();
        let mut signers = Stack::new()?;
        signers.push(x509.to_owned())?;
        let Some(mut cms) = read_cms(signature) else {
            return Err(ErrorStack::get());
        };
        cms.verify(
            Some(&signers),
            Some(&store),
            Some(payload),
            None,
            CMSOptions::BINARY | CMSOptions::DETACHED | CMSOptions::NOINTERN,
        )
    })();

    if verified.is_ok() {
        0
    } else {
        clear_errors();
        -EINVAL
    }
}

/// Match a parsed signer identifier to this certificate without verifying
/// the signature itself.
fn signer_matches(signature: &[u8], x509: &X509Ref) -> c_int {
    let Some(cms) = read_cms(signature) else {
        clear_errors();
        return -EINVAL;
    };
    // SAFETY: cms owns the signer stack until this function returns.
    let sis = unsafe { more::CMS_get0_SignerInfos(cms.as_ptr()) };
    // cms_has_signers already checked the nonempty stack.
    // SAFETY: sis belongs to cms.
    let named = (0..unsafe { ffi::OPENSSL_sk_num(sis) }).any(|i| {
        // SAFETY: i is within the stack.
        let si = unsafe { ffi::OPENSSL_sk_value(sis, i) };
        // SAFETY: si belongs to cms and x509 is a live certificate.
        unsafe { more::CMS_SignerInfo_cert_cmp(si.cast(), x509.as_ptr()) == 0 }
    });
    c_int::from(named)
}

/// Attribute a complete CMS signature to a certificate.
pub(crate) fn cms_signed_by(signature: &[u8], cert: &Cert) -> c_int {
    let Some(x509) = cert.imp.as_deref() else {
        return -EINVAL;
    };
    signer_matches(signature, x509)
}

/// HMAC-SHA-256 of `data` under `key`.
pub(crate) fn hmac(key: &[u8], data: &[u8]) -> Result<[u8; SHA256_LEN], ErrorStack> {
    // libcrypto makes no HMAC key of no bytes. HMAC pads a key shorter
    // than the hash's block with zeros, so one zero byte is the same key.
    let key = PKey::hmac(if key.is_empty() { &[0] } else { key })?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;

    signer.update(data)?;
    let mac = signer.sign_to_vec()?;
    mac.try_into().map_err(|_| ErrorStack::get())
}

/// # Safety
///
/// `key` holds `key_len` bytes, `data` `len`, and `out` has room for 32.
pub(crate) unsafe fn hmac_sha256(
    key: *const u8,
    key_len: usize,
    data: *const c_void,
    len: usize,
    out: *mut u8,
) -> c_int {
    if key.is_null() || (len != 0 && data.is_null()) || out.is_null() {
        return -EIO;
    }
    // SAFETY: the caller's key and data.
    match hmac(unsafe { slice(key, key_len) }, unsafe {
        slice(data.cast::<u8>(), len)
    }) {
        Ok(mac) => {
            // SAFETY: the caller's room for the MAC.
            unsafe { ptr::copy_nonoverlapping(mac.as_ptr(), out, SHA256_LEN) };
            0
        }
        Err(_) => -EIO,
    }
}

/// AES-128 in CFB mode with a zero IV and no padding, of `data` in
/// place.
pub(crate) fn aes128_cfb(key: &[u8; 16], data: &mut [u8]) -> Result<(), ErrorStack> {
    let input = data.to_vec();
    let mut ctx = CipherCtx::new()?;
    let mut tail = [0u8; 16];

    ctx.encrypt_init(Some(Cipher::aes_128_cfb128()), Some(key), Some(&[0u8; 16]))?;
    ctx.set_padding(false);
    let n = ctx.cipher_update(&input, Some(data))?;
    let rest = ctx.cipher_final(&mut tail)?;
    if n + rest != data.len() {
        return Err(ErrorStack::get());
    }
    data[n..].copy_from_slice(&tail[..rest]);
    Ok(())
}

/// AES-128 in CFB mode with a zero IV and no padding.
///
/// # Safety
///
/// `key` holds 16 bytes, `inp` `len`, and `out` has room for `len`; the
/// two are the same bytes or apart.
pub(crate) unsafe fn aes128_cfb_encrypt(
    key: *const u8,
    inp: *const u8,
    len: usize,
    out: *mut u8,
) -> c_int {
    if key.is_null() || len > c_int::MAX as usize || (len != 0 && (inp.is_null() || out.is_null()))
    {
        return -EIO;
    }
    let mut data = vec![0u8; len];
    // SAFETY: the caller's key and input.
    let key: &[u8; 16] = unsafe { &*key.cast() };
    // SAFETY: the caller's input.
    data.copy_from_slice(unsafe { slice(inp, len) });
    if aes128_cfb(key, &mut data).is_err() {
        return -EIO;
    }
    if len != 0 {
        // SAFETY: the caller's room for len bytes.
        unsafe { ptr::copy_nonoverlapping(data.as_ptr(), out, len) };
    }
    0
}

/// An OAEP label allocated by OpenSSL until the key context takes it.
struct OpenSslLabel(NonNull<c_void>);

impl OpenSslLabel {
    fn copy_from(label: &[u8]) -> Result<Self, ErrorStack> {
        // SAFETY: OpenSSL allocates room for the label's bytes.
        let p = unsafe { ffi::OPENSSL_malloc(label.len()) };
        let p = NonNull::new(p).ok_or_else(ErrorStack::get)?;
        // SAFETY: p holds label.len() bytes and does not overlap label.
        unsafe { ptr::copy_nonoverlapping(label.as_ptr(), p.as_ptr().cast(), label.len()) };
        Ok(Self(p))
    }

    fn install(self, ctx: &mut PkeyCtx<Public>, len: c_int) -> Result<(), ErrorStack> {
        // SAFETY: the label is live; libcrypto takes it only on success.
        let ret =
            unsafe { more::EVP_PKEY_CTX_set0_rsa_oaep_label(ctx.as_ptr(), self.0.as_ptr(), len) };
        if ret > 0 {
            core::mem::forget(self);
            Ok(())
        } else {
            Err(ErrorStack::get())
        }
    }
}

impl Drop for OpenSslLabel {
    fn drop(&mut self) {
        // SAFETY: this allocation was not handed to libcrypto.
        unsafe { ffi::OPENSSL_free(self.0.as_ptr()) };
    }
}

/// Hands `label` to `ctx` as its OAEP label through libcrypto's own
/// EVP_PKEY_CTX_set0_rsa_oaep_label(), which takes the allocation over.
/// openssl-sys sends it through EVP_PKEY_CTX_ctrl(), as the macro before
/// OpenSSL 3 did, and libcrypto 3 copies what arrives that way and never
/// frees the crate's allocation.
fn set_oaep_label(ctx: &mut PkeyCtx<Public>, label: &[u8]) -> Result<(), ErrorStack> {
    let len = c_int::try_from(label.len()).map_err(|_| ErrorStack::get())?;
    OpenSslLabel::copy_from(label)?.install(ctx, len)
}

/// RSA-OAEP with SHA-256, MGF1-SHA-256 and the label, to the modulus `n`
/// with the public exponent `e`, 0 for 65537. Returns the ciphertext length.
pub(crate) fn rsa_oaep_encrypt(
    n: &[u8],
    e: u32,
    label: &[u8],
    inp: &[u8],
    out: &mut [u8],
) -> Result<usize, c_int> {
    if n.len() > c_int::MAX as usize || label.len() > c_int::MAX as usize {
        return Err(-EINVAL);
    }
    let key = (|| {
        let e = BigNum::from_u32(if e != 0 { e } else { 65537 })?;
        PKey::from_rsa(Rsa::from_public_components(BigNum::from_slice(n)?, e)?)
    })()
    .map_err(|_| -EINVAL)?;
    (|| {
        let mut ctx = PkeyCtx::new(&key)?;

        ctx.encrypt_init()?;
        ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
        ctx.set_rsa_oaep_md(Md::sha256())?;
        ctx.set_rsa_mgf1_md(Md::sha256())?;
        // An empty label is libcrypto's own, and an allocation of none
        // cannot be handed over.
        if !label.is_empty() {
            set_oaep_label(&mut ctx, label)?;
        }
        ctx.encrypt(inp, Some(out))
    })()
    .map_err(|_| -EIO)
}

/// `n` as the 32 bytes of a P-256 coordinate.
fn coordinate(n: &BigNumRef) -> Option<[u8; 32]> {
    n.to_vec_padded(32).ok()?.try_into().ok()
}

/// One ephemeral P-256 ECDH against the point (x, y): the ephemeral
/// public point and the shared secret's x coordinate.
pub(crate) fn ecdh_p256_ephemeral(
    x: &[u8; 32],
    y: &[u8; 32],
    eph_x: &mut [u8; 32],
    eph_y: &mut [u8; 32],
    z: &mut [u8; 32],
) -> c_int {
    let Some(peer) = p256_public_key(x, y) else {
        clear_errors();
        return -EINVAL;
    };
    let agreed = (|| -> Result<Option<()>, ErrorStack> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let eph = EcKey::generate(&group)?;
        let (mut bx, mut by) = (BigNum::new()?, BigNum::new()?);
        let mut bn = BigNumContext::new()?;

        eph.public_key()
            .affine_coordinates(&group, &mut bx, &mut by, &mut bn)?;
        let (Some(ex), Some(ey)) = (coordinate(&bx), coordinate(&by)) else {
            return Ok(None);
        };
        let eph = PKey::from_ec_key(eph)?;
        let mut deriver = Deriver::new(&eph)?;
        deriver.set_peer(&peer)?;
        if deriver.derive(z)? != 32 {
            return Ok(None);
        }
        *eph_x = ex;
        *eph_y = ey;
        Ok(Some(()))
    })();

    match agreed {
        Ok(Some(())) => 0,
        _ => -EIO,
    }
}

/// Owns the libcrypto base64 decoder until this value drops.
struct DecodeCtx(NonNull<more::EvpEncodeCtx>);

impl DecodeCtx {
    fn new() -> Option<Self> {
        // SAFETY: EVP_ENCODE_CTX_new takes no arguments.
        NonNull::new(unsafe { more::EVP_ENCODE_CTX_new() }).map(Self)
    }
}

impl Drop for DecodeCtx {
    fn drop(&mut self) {
        // SAFETY: this context came from EVP_ENCODE_CTX_new and is freed once.
        unsafe { more::EVP_ENCODE_CTX_free(self.0.as_ptr()) };
    }
}

/// Decode base64 into `out`, returning the number of bytes written.
/// Keep libcrypto's whitespace and padding rules.
pub(crate) fn base64_decode(inp: &[u8], out: &mut [u8]) -> Result<usize, c_int> {
    let in_len = c_int::try_from(inp.len()).map_err(|_| -EINVAL)?;
    if out.len() < 3 * inp.len().div_ceil(4) {
        return Err(-EINVAL);
    }
    let ctx = DecodeCtx::new().ok_or(-EINVAL)?;
    let mut n = 0;
    let mut fin = 0;

    // SAFETY: the context belongs to this call.
    unsafe { more::EVP_DecodeInit(ctx.0.as_ptr()) };
    // SAFETY: inp and out are live slices and out has the maximum decoded size.
    if unsafe {
        more::EVP_DecodeUpdate(
            ctx.0.as_ptr(),
            out.as_mut_ptr(),
            &mut n,
            inp.as_ptr(),
            in_len,
        )
    } < 0
    {
        return Err(-EINVAL);
    }
    let n = usize::try_from(n).map_err(|_| -EINVAL)?;
    let remaining = out.get_mut(n..).ok_or(-EINVAL)?;
    // SAFETY: remaining is the output room after DecodeUpdate.
    if unsafe { more::EVP_DecodeFinal(ctx.0.as_ptr(), remaining.as_mut_ptr(), &mut fin) } < 0 {
        return Err(-EINVAL);
    }
    let fin = usize::try_from(fin).map_err(|_| -EINVAL)?;
    n.checked_add(fin)
        .filter(|&len| len <= out.len())
        .ok_or(-EINVAL)
}

/// The cert's RSA modulus and exponent, or its P-256 point:
/// -EPROTONOSUPPORT for another key.
///
/// # Safety
///
/// `cert` is NULL or points to a cert, and `out` to room for a
/// cert_pubkey.
pub(crate) unsafe fn cert_pubkey(cert: *const Cert, out: *mut CertPubkey) -> c_int {
    // SAFETY: the caller's room for the whole output value.
    unsafe { out.write_bytes(0, 1) };
    // SAFETY: the caller's output value remains live and unique.
    let out = unsafe { &mut *out };
    // SAFETY: the caller passes NULL or a cert.
    let Some(key) = (unsafe { x509_of(cert) }).and_then(|x| x.public_key().ok()) else {
        clear_errors();
        return -EINVAL;
    };
    // SAFETY: the key.
    let id = unsafe { more::EVP_PKEY_get_base_id(key.as_ptr()) };
    let ret = if id == ffi::EVP_PKEY_RSA {
        key.rsa().ok().map_or(-EINVAL, |rsa| {
            let (n, e) = (rsa.n().to_vec(), rsa.e().to_vec());
            if n.len() > out.n.len() || e.len() > 4 {
                return -EINVAL;
            }
            out.rsa = true;
            out.n[..n.len()].copy_from_slice(&n);
            out.n_len = n.len();
            out.e = e.iter().fold(0, |acc, &b| acc << 8 | u32::from(b));
            0
        })
    } else if id == ffi::EVP_PKEY_EC {
        let point = (|| -> Option<([u8; 32], [u8; 32])> {
            let ec = key.ec_key().ok()?;
            let group = ec.group();
            if group.curve_name() != Some(Nid::X9_62_PRIME256V1) {
                return None;
            }
            let (mut bx, mut by) = (BigNum::new().ok()?, BigNum::new().ok()?);
            let mut bn = BigNumContext::new().ok()?;
            ec.public_key()
                .affine_coordinates(group, &mut bx, &mut by, &mut bn)
                .ok()?;
            Some((coordinate(&bx)?, coordinate(&by)?))
        })();
        point.map_or(-EINVAL, |(x, y)| {
            out.x = x;
            out.y = y;
            0
        })
    } else {
        -EPROTONOSUPPORT
    };
    clear_errors();
    ret
}

/// Chains the cert to the PEM bundle of trusted issuers at the path, an
/// intermediate in it a trust anchor too: 0, -EKEYREJECTED with libcrypto's
/// static explanation, or -EINVAL when the bundle cannot be loaded.
///
/// # Safety
///
/// `cert` is NULL or points to a cert, `bundle_path` is NULL or a C
/// string, and `reason` points to where the reason goes.
pub(crate) unsafe fn cert_verify_chain(
    cert: *const Cert,
    bundle_path: *const c_char,
    reason: *mut *const c_char,
) -> c_int {
    // SAFETY: the caller's place for the reason.
    unsafe { *reason = c"".as_ptr() };
    // SAFETY: the caller passes NULL or a cert.
    let Some(x509) = (unsafe { x509_of(cert) }).filter(|_| !bundle_path.is_null()) else {
        return -EINVAL;
    };
    let Ok(mut store) = X509StoreBuilder::new() else {
        return -ENOMEM;
    };
    // SAFETY: the store and the caller's C string.
    if unsafe { more::X509_STORE_load_file(store.as_ptr(), bundle_path) } != 1 {
        return -EINVAL;
    }
    if store.set_flags(X509VerifyFlags::PARTIAL_CHAIN).is_err() {
        return -EIO;
    }
    let store = store.build();
    let (Ok(mut ctx), Ok(untrusted)) = (X509StoreContext::new(), Stack::new()) else {
        return -EIO;
    };
    let verified = ctx.init(&store, x509, &untrusted, |ctx| {
        Ok((ctx.verify_cert(), ctx.error()))
    });
    match verified {
        Ok((Ok(true), _)) => 0,
        Ok((_, err)) => {
            // SAFETY: libcrypto returns a static explanation for this error.
            let text = unsafe { ffi::X509_verify_cert_error_string(c_long::from(err.as_raw())) };
            // SAFETY: the caller's place for the reason remains live.
            unsafe { *reason = text };
            -EKEYREJECTED
        }
        Err(_) => -EIO,
    }
}

/// Logs libcrypto's error `code` under `where_`, as ERR_error_string_n()
/// writes it.
fn complain_code(where_: &CStr, code: core::ffi::c_ulong) {
    let mut buf = [0u8; 256];

    // SAFETY: the room of buf, which OpenSSL fills with a C string.
    unsafe { more::ERR_error_string_n(code, buf.as_mut_ptr().cast(), buf.len()) };
    crate::log::err(
        &[
            b"openssl: ",
            where_.to_bytes(),
            b": ",
            crate::text::cstr(&buf),
        ]
        .concat(),
    );
}

/// Logs the first of the errors a call of the crate's took from
/// libcrypto under `where_`, as openssl_complain() logs what is queued.
pub(crate) fn complain_stack(where_: &CStr, errors: &ErrorStack) {
    complain_code(where_, errors.errors().first().map_or(0, |e| e.code()));
}

/// Logs libcrypto's last error under `where_`.
pub(crate) fn openssl_complain(where_: &CStr) {
    // SAFETY: a call that takes no pointer.
    complain_code(where_, unsafe { ffi::ERR_get_error() });
}

#[cfg(shirudo_fuzz)]
mod fuzz;
#[cfg(test)]
mod tests;
