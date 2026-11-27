// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::util::crypto_openssl::sha256;
use crate::util::tpm_wire::{
    ALG_ECC, ALG_ECDSA, ALG_RSA, ALG_SHA256, DIGEST_LEN, ECC_NIST_P256, NAME_LEN, RH_ENDORSEMENT,
    ST_ATTEST_NV, ST_ATTEST_QUOTE, TpmPublic, object_name, public_marshal,
};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::Private;
use std::sync::OnceLock;

const ALG_NULL: u16 = 0x0010;
const ECC_NIST_P384: u16 = 0x0004;
const AK_ATTRS: u32 = 0x0005_0072;
const GENERATED: u32 = 0xFF54_4347;
const PCR_SELECT_LEN: u8 = 3;
const ATTEST_CLOCK_OFF: usize = 4 + 2 + 2 + NAME_LEN + 2 + DIGEST_LEN;
const SIG_R_OFF: usize = 2 + 2 + 2;
const SIG_S_OFF: usize = SIG_R_OFF + 32 + 2;
const QUOTE_CLOCK: u64 = 0xfedc_ba98_7654_3210;
const QUOTE_RESET_COUNT: u32 = 0x89ab_cdef;
const QUOTE_RESTART_COUNT: u32 = 3;
const QUOTE_FIRMWARE: u64 = 0x2026_1111_0000_0001;
const KEEPALIVE_BODY: &[u8] = br#"{"schema":"shirudo.keepalive/1"}"#;

/// The attestation key of every quote here, made in software.
fn software_ak() -> &'static EcKey<Private> {
    static KEY: OnceLock<EcKey<Private>> = OnceLock::new();
    KEY.get_or_init(|| {
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap()
    })
}

/// What a test sets before sign() makes the bytes of a row from it.
struct Quote {
    ak: TpmPublic,
    signer_is_plain_name: bool,
    extra: Vec<u8>,
    pcr_mask: u32,
    certifies_nv: bool,
    ak_public: Vec<u8>,
    attest: Vec<u8>,
    sig: Vec<u8>,
    body_sha256: Vec<u8>,
}

fn put2b(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

impl Quote {
    /// A quote of no PCR over the body's SHA-256, by an endorsement
    /// primary.
    fn new() -> Self {
        let mut ak = TpmPublic::zeroed();
        let key = software_ak();
        let (mut x, mut y) = (BigNum::new().unwrap(), BigNum::new().unwrap());
        let mut ctx = BigNumContext::new().unwrap();

        key.public_key()
            .affine_coordinates(key.group(), &mut x, &mut y, &mut ctx)
            .unwrap();
        ak.ty = ALG_ECC;
        ak.attrs = AK_ATTRS;
        ak.sym_alg = ALG_NULL;
        ak.scheme = ALG_ECDSA;
        ak.scheme_hash = ALG_SHA256;
        ak.curve = ECC_NIST_P256;
        ak.x.copy_from_slice(&x.to_vec_padded(32).unwrap());
        ak.y.copy_from_slice(&y.to_vec_padded(32).unwrap());
        let extra = sha256(KEEPALIVE_BODY).unwrap().to_vec();
        let body_sha256 = crate::util::hex::encode(&extra);
        Quote {
            ak,
            signer_is_plain_name: false,
            extra,
            pcr_mask: 0,
            certifies_nv: false,
            ak_public: Vec::new(),
            attest: Vec::new(),
            sig: Vec::new(),
            body_sha256,
        }
    }

    fn marshal_attest(&mut self, signer: &[u8]) {
        let digest = [&[0xe3u8, 0xb0, 0xc4][..], &[0; DIGEST_LEN - 3]].concat();
        let a = &mut self.attest;

        a.clear();
        a.extend_from_slice(&GENERATED.to_be_bytes());
        a.extend_from_slice(
            &if self.certifies_nv {
                ST_ATTEST_NV
            } else {
                ST_ATTEST_QUOTE
            }
            .to_be_bytes(),
        );
        put2b(a, signer);
        put2b(a, &self.extra);
        a.extend_from_slice(&QUOTE_CLOCK.to_be_bytes());
        a.extend_from_slice(&QUOTE_RESET_COUNT.to_be_bytes());
        a.extend_from_slice(&QUOTE_RESTART_COUNT.to_be_bytes());
        a.push(1);
        a.extend_from_slice(&QUOTE_FIRMWARE.to_be_bytes());
        if self.certifies_nv {
            put2b(a, signer);
            a.extend_from_slice(&0u16.to_be_bytes());
            put2b(a, &digest);
            return;
        }
        a.extend_from_slice(&1u32.to_be_bytes());
        a.extend_from_slice(&ALG_SHA256.to_be_bytes());
        a.push(PCR_SELECT_LEN);
        a.extend_from_slice(&self.pcr_mask.to_le_bytes()[..3]);
        put2b(a, &digest);
    }

    fn sign(&mut self) {
        let mut public = [0u8; PUBLIC_MAX];
        let mut len = 0;
        let mut name = [0u8; NAME_LEN];

        assert_eq!(public_marshal(&self.ak, &mut public, &mut len), 0);
        self.ak_public = public[..len].to_vec();
        assert_eq!(object_name(&self.ak_public, &mut name), 0);
        // nameAlg || SHA-256(hierarchy || name).
        let qualified = [
            &ALG_SHA256.to_be_bytes()[..],
            &sha256(&[&RH_ENDORSEMENT.to_be_bytes()[..], &name].concat()).unwrap(),
        ]
        .concat();
        self.marshal_attest(if self.signer_is_plain_name {
            &name
        } else {
            &qualified
        });
        let sig = EcdsaSig::sign(&sha256(&self.attest).unwrap(), software_ak()).unwrap();
        self.sig.clear();
        self.sig.extend_from_slice(&ALG_ECDSA.to_be_bytes());
        self.sig.extend_from_slice(&ALG_SHA256.to_be_bytes());
        put2b(&mut self.sig, &sig.r().to_vec_padded(32).unwrap());
        put2b(&mut self.sig, &sig.s().to_vec_padded(32).unwrap());
    }

    /// The row: attest, signature and key in base64, and the body's
    /// SHA-256, apart by tabs.
    fn row(&self) -> Vec<u8> {
        [
            base64_encode(&self.attest),
            base64_encode(&self.sig),
            base64_encode(&self.ak_public),
            self.body_sha256.clone(),
        ]
        .join(&b'\t')
    }

    fn signed() -> Self {
        let mut q = Quote::new();
        q.sign();
        q
    }
}

fn checked(row: &[u8]) -> QuoteResult {
    let mut res = QuoteResult::malformed();
    assert_eq!(row_check(row, &mut res), Ok(()));
    res
}

fn verdict(row: &[u8]) -> c_int {
    checked(row).verdict
}

/// A quote made by `f` from a fresh one, its verdict.
fn verdict_of(f: impl FnOnce(&mut Quote)) -> c_int {
    let mut q = Quote::new();
    f(&mut q);
    q.sign();
    verdict(&q.row())
}

/// A quote signed, then changed by `f`, its verdict.
fn verdict_after(f: impl FnOnce(&mut Quote)) -> c_int {
    let mut q = Quote::signed();
    f(&mut q);
    verdict(&q.row())
}

fn line(row: &[u8]) -> Vec<u8> {
    let res = checked(row);
    let mut buf = [0u8; LINE_MAX];
    let mut e = JsonEmit::fixed(&mut buf);
    assert_eq!(row_emit(&res, &mut e), 0);
    let n = e.written();
    buf[..n].to_vec()
}

#[test]
fn good_row_is_accepted() {
    let q = Quote::signed();
    let res = checked(&q.row());
    let name = [
        &ALG_SHA256.to_be_bytes()[..],
        &sha256(&q.ak_public).unwrap(),
    ]
    .concat();

    assert_eq!(res.verdict, QUOTE_OK);
    assert_eq!(res.ak_name[..], name[..]);
    assert_eq!(res.ak_public[..res.ak_public_len], q.ak_public[..]);
    assert_eq!(
        (res.reset_count, res.clock),
        (QUOTE_RESET_COUNT, QUOTE_CLOCK)
    );
    let want = format!(
        r#"{{"ok":1,"ak_name":"{}","ak_public":"{}","reset_count":{QUOTE_RESET_COUNT},"clock":{QUOTE_CLOCK}}}"#,
        String::from_utf8(crate::util::hex::encode(&name)).unwrap(),
        String::from_utf8(base64_encode(&q.ak_public)).unwrap()
    );
    assert_eq!(line(&q.row()), want.as_bytes());
}

#[test]
fn rejects_are_one_reason_each() {
    assert_eq!(line(b""), br#"{"ok":0,"reason":"malformed"}"#);
    let mut q = Quote::new();
    q.signer_is_plain_name = true;
    q.sign();
    assert_eq!(line(&q.row()), br#"{"ok":0,"reason":"bad_signature"}"#);
    let mut q = Quote::signed();
    q.body_sha256[0] = if q.body_sha256[0] == b'0' { b'1' } else { b'0' };
    assert_eq!(line(&q.row()), br#"{"ok":0,"reason":"body_mismatch"}"#);
}

#[test]
fn changed_attest_or_signature_is_a_bad_signature() {
    assert_eq!(
        verdict_after(|q| q.attest[ATTEST_CLOCK_OFF + 7] ^= 1),
        QUOTE_BAD_SIGNATURE
    );
    assert_eq!(
        verdict_after(|q| q.sig[SIG_R_OFF + 31] ^= 1),
        QUOTE_BAD_SIGNATURE
    );
    assert_eq!(
        verdict_after(|q| q.sig[SIG_S_OFF + 31] ^= 1),
        QUOTE_BAD_SIGNATURE
    );
}

#[test]
fn changed_magic_or_signature_header_is_malformed() {
    assert_eq!(verdict_after(|q| q.attest[0] ^= 1), QUOTE_MALFORMED);
    assert_eq!(verdict_after(|q| q.sig[1] ^= 1), QUOTE_MALFORMED);
}

#[test]
fn other_body_sha256_is_a_body_mismatch() {
    assert_eq!(
        verdict_after(|q| q.body_sha256[63] = if q.body_sha256[63] == b'f' {
            b'e'
        } else {
            b'f'
        }),
        QUOTE_BODY_MISMATCH
    );
}

#[test]
fn signed_extra_of_another_body_is_a_body_mismatch() {
    assert_eq!(verdict_of(|q| q.extra[0] ^= 1), QUOTE_BODY_MISMATCH);
    assert_eq!(verdict_of(|q| q.extra.truncate(20)), QUOTE_BODY_MISMATCH);
    assert_eq!(verdict_of(|q| q.extra.clear()), QUOTE_BODY_MISMATCH);
}

#[test]
fn plain_name_as_signer_is_a_bad_signature() {
    assert_eq!(
        verdict_of(|q| q.signer_is_plain_name = true),
        QUOTE_BAD_SIGNATURE
    );
}

#[test]
fn quote_over_pcrs_is_malformed() {
    assert_eq!(
        verdict_of(|q| q.pcr_mask = 1 << 9 | 1 << 11),
        QUOTE_MALFORMED
    );
    assert_eq!(verdict_of(|q| q.pcr_mask = 1 << 23), QUOTE_MALFORMED);
}

#[test]
fn nv_certification_is_malformed() {
    assert_eq!(verdict_of(|q| q.certifies_nv = true), QUOTE_MALFORMED);
}

#[test]
fn key_that_is_not_p256_ecdsa_is_malformed() {
    assert_eq!(verdict_of(|q| q.ak.curve = ECC_NIST_P384), QUOTE_MALFORMED);
    assert_eq!(verdict_of(|q| q.ak.scheme = ALG_NULL), QUOTE_MALFORMED);
    assert_eq!(
        verdict_of(|q| {
            q.ak.ty = ALG_RSA;
            q.ak.scheme = ALG_NULL;
            q.ak.rsa_bits = 2048;
            q.ak.n_len = 256;
            q.ak.n[0] = 0x80;
        }),
        QUOTE_MALFORMED
    );
}

#[test]
fn key_off_the_curve_is_a_bad_signature() {
    assert_eq!(verdict_of(|q| q.ak.x[31] ^= 1), QUOTE_BAD_SIGNATURE);
}

/// Where field `n` of `row` starts, by the tabs before it.
fn field(row: &[u8], n: usize) -> usize {
    row.iter()
        .enumerate()
        .filter(|&(_, &c)| c == b'\t')
        .nth(n.wrapping_sub(1))
        .map_or(0, |(i, _)| i + 1)
}

#[test]
fn base64_that_is_not_standard_is_malformed() {
    let q = Quote::signed();
    let mut row = q.row();

    assert_eq!(verdict(&row), QUOTE_OK);
    for n in 0..3 {
        let at = field(&row, n);
        let was = row[at];
        for c in *b"* -" {
            row[at] = c;
            assert_eq!(verdict(&row), QUOTE_MALFORMED, "{n} {c}");
        }
        row[at] = was;
    }
    assert_eq!(verdict(&row), QUOTE_OK);
    // The signature is 72 bytes, so nothing pads it: cut one digit.
    let mut cut = q.row();
    cut.remove(field(&cut, 2) - 2);
    assert_eq!(verdict(&cut), QUOTE_MALFORMED);
    let mut newline = q.row();
    let at = field(&newline, 2) - 1;
    newline.insert(at, b'\n');
    assert_eq!(verdict(&newline), QUOTE_MALFORMED);
    // The key is 88 bytes: its last digit holds two bits of it and four
    // that a decoder drops, so the next digit decodes the same.
    let mut row = q.row();
    let pad = field(&row, 2)
        + row[field(&row, 2)..]
            .iter()
            .position(|&c| c == b'=')
            .unwrap();
    assert_eq!(&row[pad..pad + 3], b"==\t");
    row[pad - 1] += 1;
    assert_eq!(verdict(&row), QUOTE_MALFORMED);
}

#[test]
fn row_that_does_not_split_is_malformed() {
    let q = Quote::signed();
    let row = q.row();
    let malformed = |row: &[u8]| {
        assert_eq!(
            verdict(row),
            QUOTE_MALFORMED,
            "{:?}",
            String::from_utf8_lossy(row)
        )
    };

    malformed(&[&row[..], b"\t"].concat());
    malformed(&[&row[..], b"\n"].concat());
    malformed(&row[..row.len() - 1]);
    let mut g = row.clone();
    *g.last_mut().unwrap() = b'g';
    malformed(&g);
    let mut space = row.clone();
    let tab = space.iter().position(|&c| c == b'\t').unwrap();
    space[tab] = b' ';
    malformed(&space);
    malformed(b"");
    malformed(b"\t\t\t");
    malformed(b"\t\t\t\t");
}

#[test]
fn field_longer_than_its_structure_is_malformed() {
    let row = Quote::signed().row();
    let rest = &row[row.iter().position(|&c| c == b'\t').unwrap()..];
    let long = [&vec![b'A'; base64_len(ATTEST_MAX) + 4][..], rest].concat();

    assert_eq!(verdict(&long), QUOTE_MALFORMED);
}
