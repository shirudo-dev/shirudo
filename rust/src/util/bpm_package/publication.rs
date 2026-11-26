// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Signed payloads: a detached CMS signature checked against a
//! certificate, and the signed tree publication a registry holds.

use core::ffi::{CStr, c_int};
use std::os::fd::BorrowedFd;

use crate::errno::{EBADMSG, EINVAL, ENAMETOOLONG, ENOMEM};
use crate::sys::libc::PATH_MAX;
use crate::text::{contains, cstr, strsprintf};
use crate::util::bpm_oci::{
    BpmBuffer, Descriptor, EMPTY_CONFIG_MEDIA, MANIFEST_MEDIA, MAX_ENTRIES, OciClient,
    TREE_ARTIFACT, TREE_MEDIA, TREE_SIG_MEDIA, buffer_free, emit_descriptor, get_memory,
    get_signed, parse_manifest, sha256_hex, url,
};
use crate::util::crypto_openssl::{Cert, cert_read_fd, cert_read_file, verify_detached};
use crate::util::json::JsonEmit;
use crate::util::keys::{TrustedSet, verify_signature};

/// A signed payload: the bytes and the signature as the caller holds
/// them, NULL pointers included, which `verify_detached()` refuses.
pub(super) struct Signed {
    pub payload: *const u8,
    pub payload_len: usize,
    pub sig: *const u8,
    pub sig_len: usize,
}

/// 0 when `s` verifies against the certificate `read` fills, -EINVAL when
/// there is none.
fn verify_with(s: &Signed, read: impl FnOnce(&mut Cert) -> c_int) -> c_int {
    let mut cert = Cert::new();
    let mut ret = -EINVAL;

    if read(&mut cert) == 0 {
        // SAFETY: the payload and signature as the caller lends them,
        // and the cert just read.
        ret = unsafe { verify_detached(s.payload, s.payload_len, s.sig, s.sig_len, &cert) };
    }
    ret
}

/// Against the certificate in the file at `cert_path`.
pub(super) fn verify_cms(s: &Signed, cert_path: &CStr) -> c_int {
    // SAFETY: cert_read_file() takes the caller's path as it is.
    verify_with(s, |cert| unsafe {
        cert_read_file(cert_path.as_ptr(), cert)
    })
}

/// Against the certificate the open `cert_fd` reads.
pub(super) fn verify_cms_fd(s: &Signed, cert_fd: BorrowedFd<'_>) -> c_int {
    // SAFETY: an fd and a cert to fill.
    verify_with(s, |cert| unsafe { cert_read_fd(cert_fd, cert) })
}

/// `BPM_TREE_MANIFEST_CAP`: room for the manifest of a publication.
pub(crate) const TREE_MANIFEST_CAP: usize = 8192;

/// The manifest of a tree publication whose payload and signature are
/// the layers `payload` and `sig`, as bpm tree append writes it.
pub(crate) fn tree_manifest(payload: &Descriptor, sig: &Descriptor) -> Result<Vec<u8>, c_int> {
    let mut out = vec![0u8; TREE_MANIFEST_CAP];
    let len = emit_tree_manifest(payload, sig, &mut out)?;

    out.truncate(len);
    Ok(out)
}

/// [`tree_manifest`] into `out`, its length then, -E2BIG where it does
/// not fit.
pub(super) fn emit_tree_manifest(
    payload: &Descriptor,
    sig: &Descriptor,
    out: &mut [u8],
) -> Result<usize, c_int> {
    let mut hex = [0u8; 65];

    if sha256_hex(b"{}", &mut hex) != 0 {
        return Err(-EINVAL);
    }
    let config = Descriptor::of(EMPTY_CONFIG_MEDIA, &[b"sha256:", cstr(&hex)].concat(), 2);
    let mut e = JsonEmit::fixed(&mut *out);
    e.obj_open();
    e.kv_int(b"schemaVersion", 2);
    e.kv_string(b"mediaType", MANIFEST_MEDIA.to_bytes());
    e.kv_string(b"artifactType", TREE_ARTIFACT);
    emit_descriptor(&mut e, Some(b"config"), &config, None);
    e.arr_open(b"layers");
    emit_descriptor(&mut e, None, payload, None);
    emit_descriptor(&mut e, None, sig, None);
    e.arr_close();
    e.obj_close();
    if e.err() != 0 {
        return Err(e.err());
    }
    Ok(e.written())
}

/// A registry may serve the signed layers under a manifest of its own
/// making: the manifest digest a node records and a successor names as
/// its parent would then be of bytes no signature covers, and a node
/// that recorded one form refuses the other for good. Only the form the
/// publisher writes is taken: -EBADMSG for another.
fn tree_manifest_canonical(manifest: &[u8], layers: &[Descriptor]) -> c_int {
    let [payload, sig] = layers else {
        return -EBADMSG;
    };
    if payload.media() != TREE_MEDIA || sig.media() != TREE_SIG_MEDIA {
        return -EBADMSG;
    }
    match tree_manifest(payload, sig) {
        Ok(want) if want == manifest => 0,
        Ok(_) => -EBADMSG,
        Err(err) => err,
    }
}

/// What a tree fetch holds until it ends.
struct Fetch {
    manifest: BpmBuffer,
    sig: BpmBuffer,
    layers: Vec<Descriptor>,
}

/// The signed tree publication at `repository:reference`, a tag or a
/// manifest digest, its manifest exactly [`tree_manifest`] of its two
/// layers, every layer checked against its descriptor and the payload
/// against `trusted`, or `cert_path` without one: its bytes into
/// `payload`, freed on an error, and the manifest's digest. -ENOENT when
/// the reference does not exist yet.
pub(crate) fn fetch_document(
    c: &mut OciClient,
    repository: &[u8],
    reference: &[u8],
    cert_path: Option<&CStr>,
    trusted: Option<&TrustedSet>,
    payload: &mut BpmBuffer,
    manifest_digest: &mut [u8],
) -> c_int {
    let ret = fetch_checked(
        c,
        repository,
        reference,
        cert_path,
        trusted,
        payload,
        manifest_digest,
    );
    if ret != 0 {
        buffer_free(payload);
    }
    ret
}

fn fetch_checked(
    c: &mut OciClient,
    repository: &[u8],
    reference: &[u8],
    cert_path: Option<&CStr>,
    trusted: Option<&TrustedSet>,
    payload: &mut BpmBuffer,
    manifest_digest: &mut [u8],
) -> c_int {
    let mut manifest_url = [0u8; PATH_MAX];
    let mut hex = [0u8; 65];
    let mut nl = 0;

    if reference.is_empty()
        || reference.iter().any(|&ch| matches!(ch, b'/' | b'?' | b'#'))
        || contains(reference, b"..")
    {
        return -EINVAL;
    }
    let ret = url(c, repository, b"manifests", reference, &mut manifest_url);
    if ret != 0 {
        return ret;
    }
    let Ok(manifest_url) = CStr::from_bytes_until_nul(&manifest_url) else {
        return -EINVAL;
    };
    let mut f = Fetch {
        manifest: BpmBuffer::new(),
        sig: BpmBuffer::new(),
        layers: Vec::new(),
    };
    let ret = get_memory(
        c,
        manifest_url,
        Some(MANIFEST_MEDIA),
        &mut f.manifest,
        false,
    );
    if ret != 0 {
        return ret;
    }
    if manifest_digest.len() < 72 {
        return -ENAMETOOLONG;
    }
    let manifest = f.manifest.bytes();
    if sha256_hex(manifest, &mut hex) != 0 {
        return -EINVAL;
    }
    if strsprintf(manifest_digest, &[b"sha256:", cstr(&hex)]).is_err() {
        return -ENAMETOOLONG;
    }
    if f.layers.try_reserve_exact(MAX_ENTRIES).is_err() {
        return -ENOMEM;
    }
    f.layers.resize_with(MAX_ENTRIES, Descriptor::new);
    let ret = parse_manifest(manifest, &mut f.layers, &mut nl, None);
    if ret != 0 {
        return ret;
    }
    let Ok(n) = usize::try_from(nl) else {
        return -EINVAL;
    };
    if n > MAX_ENTRIES {
        return -EINVAL;
    }
    let layers = &f.layers[..n];
    let ret = tree_manifest_canonical(manifest, layers);
    if ret != 0 {
        return ret;
    }
    let ret = get_signed(
        c,
        repository,
        layers,
        TREE_MEDIA,
        TREE_SIG_MEDIA,
        payload,
        &mut f.sig,
    );
    if ret != 0 {
        return ret;
    }
    match trusted {
        Some(set) => verify_signature(set, payload.bytes(), f.sig.bytes())
            .err()
            .unwrap_or(0),
        None => match cert_path {
            Some(cert_path) => verify_cms(
                &Signed {
                    payload: payload.as_ptr(),
                    payload_len: payload.bytes().len(),
                    sig: f.sig.as_ptr(),
                    sig_len: f.sig.bytes().len(),
                },
                cert_path,
            ),
            None => -EINVAL,
        },
    }
}
