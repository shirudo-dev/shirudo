// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;

#[test]
fn sha256_matches_fips_180_vector() {
    let d = sha256(b"abc").unwrap();

    assert_eq!(
        crate::util::hex::encode(&d),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn sha256_buffer_zeroes_a_failed_digest() {
    let mut out = [0xffu8; SHA256_LEN];

    // SAFETY: no bytes, which it refuses, and room for a digest.
    let ret = unsafe { sha256_buffer(core::ptr::null(), 3, out.as_mut_ptr()) };
    assert_ne!(ret, 0);
    assert_eq!(out, [0; SHA256_LEN]);
}

#[test]
fn signers_need_a_complete_envelope() {
    let corpus = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testing/fuzz/corpus/cms/cert-and-signature"
    ))
    .expect("CMS corpus entry");
    assert!(corpus.len() > 2);
    let der_len = usize::from(u16::from_le_bytes([corpus[0], corpus[1]]));
    assert!(der_len < corpus.len() - 2);
    let der = &corpus[2..2 + der_len];
    let mut signature = corpus[2 + der_len..].to_vec();
    let mut cert = Cert::new();

    // SAFETY: der holds a complete certificate and cert receives it.
    let read = unsafe { cert_read_der(der.as_ptr(), der.len(), &mut cert) };
    assert_eq!(read, 0);
    assert_eq!(cms_check_signers(&signature), 0);
    // SAFETY: the signature bytes and the live certificate remain valid.
    let signed_by = unsafe { cms_signed_by(signature.as_ptr(), signature.len(), &cert) };
    assert_eq!(signed_by, 1);

    signature.push(0);
    assert_eq!(cms_check_signers(&signature), -EBADMSG);
    // SAFETY: the signature bytes and the live certificate remain valid.
    let signed_by = unsafe { cms_signed_by(signature.as_ptr(), signature.len(), &cert) };
    assert_eq!(signed_by, -EINVAL);
}

#[test]
fn certificate_owner_clears_on_reparse() {
    let corpus = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testing/fuzz/corpus/cms/cert-and-signature"
    ))
    .expect("CMS corpus entry");
    let der_len = usize::from(u16::from_le_bytes([corpus[0], corpus[1]]));
    let der = &corpus[2..2 + der_len];
    let mut cert = Cert::new();

    assert_eq!(cert_read_memory(der, &mut cert), 0);
    assert!(cert.imp.is_some());
    assert_eq!(cert_read_memory(b"not a certificate", &mut cert), -EINVAL);
    assert!(cert.imp.is_none());
}

#[test]
fn der_bio_reads_one_certificate_and_rejects_bad_input() {
    let corpus = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testing/fuzz/corpus/cms/cert-and-signature"
    ))
    .expect("CMS corpus entry");
    let der_len = usize::from(u16::from_le_bytes([corpus[0], corpus[1]]));
    let mut der = corpus[2..2 + der_len].to_vec();

    der.extend_from_slice(b"trailing bytes");
    assert!(x509_from_der_bio(&der).is_ok());
    assert!(x509_from_der_bio(b"not DER").is_err());
}

#[test]
fn base64_decode_keeps_libcrypto_input_rules() {
    let mut out = [0u8; 6];

    assert_eq!(base64_decode(b"YQ==\n", &mut out), Ok(1));
    assert_eq!(&out[..1], b"a");
    assert_eq!(base64_decode(b"Y@==", &mut out), Err(-EINVAL));
    assert_eq!(base64_decode(b"YQ==", &mut out[..2]), Err(-EINVAL));
}
