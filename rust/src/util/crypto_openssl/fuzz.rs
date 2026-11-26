// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-cms: a certificate, its digests and public key, a detached CMS
//! signature over it, and base64: a signature that verifies is one the
//! certificate made, and base64 never decodes to more than it spans.
//!
//! The input is the certificate's length, two bytes little-endian, the
//! certificate, then the signature.

use super::{
    Cert, CertPubkey, base64_decode, cert_pubkey, cert_read_der, cms_signed_by, verify_detached,
};
use crate::fuzzing::fuzz_target;
use crate::util::keys::digest_der;

fuzz_target!(shirudo_fuzz_cms, shirudo_fuzz_cms_init, |data| {
    let [l0, l1, rest @ ..] = data else {
        return;
    };
    let der_len = usize::from(*l0) | usize::from(*l1) << 8;
    let Some((der, sig)) = rest.split_at_checked(der_len) else {
        return;
    };
    let _ = digest_der(der);
    let mut cert = Cert::new();
    // SAFETY: the certificate's bytes, the signature's, and the
    // certificate read, freed once.
    unsafe {
        if cert_read_der(der.as_ptr(), der.len(), &mut cert) == 0 {
            let signed_by = cms_signed_by(sig.as_ptr(), sig.len(), &cert);
            if verify_detached(der.as_ptr(), der.len(), sig.as_ptr(), sig.len(), &cert) == 0
                && signed_by != 1
            {
                std::process::abort();
            }
            let mut public: CertPubkey = core::mem::zeroed();
            if cert_pubkey(&cert, &mut public) == 0 && public.n_len > public.n.len() {
                std::process::abort();
            }
        }
    }
    let mut raw = vec![0u8; sig.len() + 1];
    let mut n = 0;
    // SAFETY: the signature's bytes and room for what they decode to.
    if unsafe {
        base64_decode(
            sig.as_ptr().cast(),
            sig.len(),
            raw.as_mut_ptr(),
            raw.len(),
            &mut n,
        )
    } == 0
        && n > sig.len()
    {
        std::process::abort();
    }
});
