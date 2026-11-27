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
    let signed_by = cms_signed_by(&signature, &cert);
    assert_eq!(signed_by, 1);

    signature.push(0);
    assert_eq!(cms_check_signers(&signature), -EBADMSG);
    let signed_by = cms_signed_by(&signature, &cert);
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
#[cfg_attr(miri, ignore = "uses OpenSSL to generate and decrypt an RSA key")]
fn oaep_encryption_uses_the_supplied_label() {
    let rsa = Rsa::generate(2048).expect("RSA key");
    let n = rsa.n().to_vec();
    let key = PKey::from_rsa(rsa).expect("private key");
    let mut encrypted = [0u8; 256];
    let mut plain = [0u8; 256];

    let len =
        rsa_oaep_encrypt(&n, 0, b"shirudo\0", b"seed", &mut encrypted).expect("encrypt with label");
    assert_eq!(len, encrypted.len());
    let mut decrypt = PkeyCtx::new(&key).expect("decrypt context");
    decrypt.decrypt_init().expect("decrypt init");
    decrypt.set_rsa_padding(Padding::PKCS1_OAEP).expect("OAEP");
    decrypt.set_rsa_oaep_md(Md::sha256()).expect("OAEP digest");
    decrypt.set_rsa_mgf1_md(Md::sha256()).expect("MGF1 digest");
    assert!(
        decrypt
            .decrypt(&encrypted[..len], Some(&mut plain))
            .is_err()
    );
    clear_errors();

    let len = rsa_oaep_encrypt(&n, 0, b"", b"seed", &mut encrypted).expect("encrypt without label");
    let mut decrypt = PkeyCtx::new(&key).expect("decrypt context");
    decrypt.decrypt_init().expect("decrypt init");
    decrypt.set_rsa_padding(Padding::PKCS1_OAEP).expect("OAEP");
    decrypt.set_rsa_oaep_md(Md::sha256()).expect("OAEP digest");
    decrypt.set_rsa_mgf1_md(Md::sha256()).expect("MGF1 digest");
    let written = decrypt
        .decrypt(&encrypted[..len], Some(&mut plain))
        .expect("decrypt without label");
    assert_eq!(&plain[..written], b"seed");
}

#[test]
fn base64_decode_keeps_libcrypto_input_rules() {
    let mut out = [0u8; 6];

    assert_eq!(base64_decode(b"YQ==\n", &mut out), Ok(1));
    assert_eq!(&out[..1], b"a");
    assert_eq!(base64_decode(b"Y@==", &mut out), Err(-EINVAL));
    assert_eq!(base64_decode(b"YQ==", &mut out[..2]), Err(-EINVAL));
}
