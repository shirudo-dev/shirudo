// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! TPM 2.0 wire-format helpers that need no TPM:
//! policy digests, NV and object names, the key
//! derivations and credential protection, and the attestation
//! structures a verifier parses from evidence.

#[cfg(shirudo_fuzz)]
mod fuzz;
mod kdf;
mod parse;
mod policy;

pub(crate) use kdf::{credential_protect, kdfe};
pub(crate) use parse::{attest_parse, ecc_public_parse, public_marshal, public_parse};
pub(crate) use policy::{
    EK_POLICY, RegisterPolicy, nv_extend_cphash, nv_name, object_name, policy_nv_written,
    policy_or, register_policy, register_policy_final, writer_auth_hash, writer_public,
};
/// The rest of what test-tpm-wire drives.
#[cfg(feature = "test-helpers")]
pub(crate) use {
    kdf::{HmacKey, kdfa},
    parse::ecdsa_signature_parse,
    policy::{policy_command_code, policy_pcr, policy_signed},
};

use core::ffi::c_int;

use crate::errno::{EBADMSG, EINVAL, EKEYREJECTED};
use crate::util::chain::memneq_explicit;
use crate::util::crypto_openssl::{ecdsa_p256_verify, sha256};

pub(crate) const DIGEST_LEN: usize = 32;
/// nameAlg and a SHA-256.
pub(crate) const NAME_LEN: usize = 2 + DIGEST_LEN;
pub(crate) const NV_RSA_BYTES: usize = 384;
pub(crate) const NV_RSA_PUBLIC_AREA_LEN: usize = 24 + NV_RSA_BYTES;
pub(crate) const CREDENTIAL_LEN: usize = 32;
pub(crate) const ID_OBJECT_LEN: usize = 2 + 32 + 2 + CREDENTIAL_LEN;

pub(crate) const ALG_RSA: u16 = 0x0001;
const ALG_AES: u16 = 0x0006;
pub(crate) const ALG_SHA256: u16 = 0x000B;
pub(crate) const ALG_ECC: u16 = 0x0023;
pub(crate) const ALG_ECDSA: u16 = 0x0018;
const ALG_RSASSA: u16 = 0x0014;
const ALG_NULL: u16 = 0x0010;
const ALG_CFB: u16 = 0x0043;
pub(crate) const ECC_NIST_P256: u16 = 0x0003;
pub(crate) const ST_ATTEST_NV: u16 = 0x8014;
pub(crate) const ST_ATTEST_QUOTE: u16 = 0x8018;
const GENERATED: u32 = 0xFF54_4347;
const PCR_SELECT_LEN: usize = 3;
const PCR_SELECTION_LEN: usize = 7 + PCR_SELECT_LEN;
const NV_POLICY_REF: &[u8] = b"shirudo-nv-writer-v1";
const WRITER_ATTRS: u32 = 0x0004_0072;
const CC_NV_EXTEND: u32 = 0x0000_0136;
/// `TPM_RH_ENDORSEMENT`: the endorsement hierarchy.
pub(crate) const RH_ENDORSEMENT: u32 = 0x4000_000B;

/// `struct tpm_public`: a TPMT_PUBLIC of the shapes shirudo makes or
/// checks.
#[derive(Clone, Copy)]
pub struct TpmPublic {
    pub(crate) ty: u16,
    pub(crate) attrs: u32,
    pub(crate) policy_len: usize,
    pub(crate) policy: [u8; DIGEST_LEN],
    pub(crate) sym_alg: u16,
    pub(crate) sym_bits: u16,
    pub(crate) sym_mode: u16,
    pub(crate) scheme: u16,
    pub(crate) scheme_hash: u16,
    pub(crate) curve: u16,
    pub(crate) x: [u8; 32],
    pub(crate) y: [u8; 32],
    pub(crate) rsa_bits: u16,
    pub(crate) rsa_exponent: u32,
    pub(crate) n_len: usize,
    pub(crate) n: [u8; 256],
}

/// `struct tpm_ecc_public`.
pub struct TpmEccPublic {
    pub(crate) attrs: u32,
    pub(crate) scheme: u16,
    pub(crate) hash: u16,
    pub(crate) curve: u16,
    pub(crate) x: [u8; 32],
    pub(crate) y: [u8; 32],
}

/// `struct tpm_attest`: a TPMS_ATTEST, its pointers into the buffer it
/// was parsed from.
pub struct TpmAttest {
    pub(crate) ty: u16,
    pub(crate) signer: [u8; NAME_LEN],
    pub(crate) signer_len: usize,
    pub(crate) extra: *const u8,
    pub(crate) extra_len: usize,
    pub(crate) clock: u64,
    pub(crate) reset_count: u32,
    pub(crate) restart_count: u32,
    pub(crate) safe: bool,
    pub(crate) firmware_version: u64,
    pub(crate) pcr_mask: u32,
    pub(crate) pcr_digest: [u8; DIGEST_LEN],
    pub(crate) index_name: [u8; NAME_LEN],
    pub(crate) index_name_len: usize,
    pub(crate) offset: u16,
    pub(crate) nv_data: *const u8,
    pub(crate) nv_len: usize,
}

impl TpmEccPublic {
    pub(crate) const fn zeroed() -> Self {
        TpmEccPublic {
            attrs: 0,
            scheme: 0,
            hash: 0,
            curve: 0,
            x: [0; 32],
            y: [0; 32],
        }
    }
}

impl TpmAttest {
    /// One parsed from nothing yet, its pointers null.
    pub(crate) const fn zeroed() -> Self {
        TpmAttest {
            ty: 0,
            signer: [0; NAME_LEN],
            signer_len: 0,
            extra: core::ptr::null(),
            extra_len: 0,
            clock: 0,
            reset_count: 0,
            restart_count: 0,
            safe: false,
            firmware_version: 0,
            pcr_mask: 0,
            pcr_digest: [0; DIGEST_LEN],
            index_name: [0; NAME_LEN],
            index_name_len: 0,
            offset: 0,
            nv_data: core::ptr::null(),
            nv_len: 0,
        }
    }

    /// The extra data, read from `buf`, the bytes attest_parse() parsed
    /// this from; none for other bytes.
    pub(crate) fn extra_in<'a>(&self, buf: &'a [u8]) -> Option<&'a [u8]> {
        span_in(buf, self.extra, self.extra_len)
    }

    /// The certified NV contents, read from `buf` likewise.
    pub(crate) fn nv_data_in<'a>(&self, buf: &'a [u8]) -> Option<&'a [u8]> {
        span_in(buf, self.nv_data, self.nv_len)
    }
}

/// The `len` bytes at `p` as the part of `buf` they are, where `buf`
/// holds them all.
fn span_in(buf: &[u8], p: *const u8, len: usize) -> Option<&[u8]> {
    let start = p.addr().checked_sub(buf.as_ptr().addr())?;

    buf.get(start..start.checked_add(len)?)
}

impl TpmPublic {
    pub(crate) const fn zeroed() -> Self {
        TpmPublic {
            ty: 0,
            attrs: 0,
            policy_len: 0,
            policy: [0; DIGEST_LEN],
            sym_alg: 0,
            sym_bits: 0,
            sym_mode: 0,
            scheme: 0,
            scheme_hash: 0,
            curve: 0,
            x: [0; 32],
            y: [0; 32],
            rsa_bits: 0,
            rsa_exponent: 0,
            n_len: 0,
            n: [0; 256],
        }
    }
}

/// Big-endian fields off the front of a buffer: a read takes them, or
/// fails with -EINVAL when the buffer holds too few.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn left(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], c_int> {
        if self.left() < n {
            return Err(-EINVAL);
        }
        let s = &self.buf[self.pos..self.pos + n];

        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, c_int> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, c_int> {
        let b = self.take(2)?;

        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, c_int> {
        let b = self.take(4)?;

        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, c_int> {
        let hi = self.u32()?;
        let lo = self.u32()?;

        Ok((u64::from(hi) << 32) | u64::from(lo))
    }

    /// A TPM2B of at most `max` bytes.
    fn sized(&mut self, max: usize) -> Result<&'a [u8], c_int> {
        let n = usize::from(self.u16()?);

        if n > self.left() || n > max {
            return Err(-EINVAL);
        }
        self.take(n)
    }

    /// A TPM2B of exactly `out.len()` bytes into `out`.
    fn sized_into(&mut self, out: &mut [u8]) -> Result<(), c_int> {
        let d = self.sized(out.len())?;

        if d.len() != out.len() {
            return Err(-EINVAL);
        }
        out.copy_from_slice(d);
        Ok(())
    }
}

/// The 0 or negative errno a C function returns for `r`.
fn errno(r: Result<(), c_int>) -> c_int {
    r.err().unwrap_or(0)
}

/// A TPM2B: the size, then the bytes, at the front of `out`; how many
/// bytes that took.
fn put_sized(out: &mut [u8], data: &[u8]) -> usize {
    out[..2].copy_from_slice(&(data.len() as u16).to_be_bytes());
    out[2..2 + data.len()].copy_from_slice(data);
    2 + data.len()
}

// The two checks of an attestation that attest verify and the keepalive
// quote checker make, here once so that neither gains one the other
// lacks. What each asks of the key stays with it.

/// Whether the TPM named the key of `ak_name`, an endorsement primary,
/// as the signer of `a`; the error of the qualified name where it has
/// none.
pub(crate) fn attest_signer(a: &TpmAttest, ak_name: &[u8; NAME_LEN]) -> Result<bool, c_int> {
    let mut qualified = [0u8; NAME_LEN];

    match policy::qualified_name(RH_ENDORSEMENT, ak_name, &mut qualified) {
        0 => Ok(a.signer_len == NAME_LEN && !memneq_explicit(&a.signer, &qualified)),
        err => Err(err),
    }
}

/// The ECDSA signature `sig`, a TPMT_SIGNATURE, over the SHA-256 of
/// `attest` by the P-256 point `x`, `y`: 0 where it verifies,
/// -EKEYREJECTED where it does not, a point off the curve among them,
/// and -EBADMSG where `sig` does not parse.
pub(crate) fn attest_verify(attest: &[u8], sig: &[u8], x: &[u8; 32], y: &[u8; 32]) -> c_int {
    let (mut r, mut s) = ([0u8; 32], [0u8; 32]);

    if parse::ecdsa_signature_parse(sig, &mut r, &mut s) != 0 {
        return -EBADMSG;
    }
    let ret = match sha256(attest) {
        Ok(digest) => ecdsa_p256_verify(x, y, &digest, &r, &s),
        Err(err) => err,
    };
    if ret == -EINVAL { -EKEYREJECTED } else { ret }
}
