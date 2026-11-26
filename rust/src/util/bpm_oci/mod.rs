// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The OCI distribution client: libcurl carries
//! HTTP and TLS, this module owns registry auth, blob and manifest
//! transfer, and reference parsing.

mod auth;
mod client;
mod http;
mod manifest;
pub(crate) use manifest::emit_descriptor;
mod refs;

use core::ffi::{CStr, c_char, c_long};

pub(crate) use client::{Buffer, Client, manifest_layers};
pub(crate) use http::{buffer_free, get_memory, get_signed, push_blob, put_manifest, sha256_hex};
pub(crate) use manifest::parse_manifest;
pub(crate) use refs::url;

use crate::errno::E2BIG;
use crate::sys::libc::PATH_MAX;
use crate::text::{at, contains, cstr, find, strscpy, strsprintf};

pub(crate) const MAX_NAME: usize = 128;
pub(crate) const MAX_ENDPOINT: usize = 512;
const MAX_MEDIA: usize = 192;
pub(crate) const MAX_DIGEST: usize = 128;
pub(crate) const MAX_ENTRIES: usize = 512;
/// The largest response read into memory, an upatch artifact.
const MAX_HTTP_BODY: usize = 16 * 1024 * 1024;
pub(crate) const MAX_PACKAGE_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const MAX_PACKAGE_ENTRIES: u32 = 4096;
pub(crate) const MANIFEST_MEDIA: &CStr = c"application/vnd.oci.image.manifest.v1+json";
pub(crate) const TREE_MEDIA: &[u8] = b"application/vnd.shirudo.upatch.tree.v1+json";
pub(crate) const TREE_SIG_MEDIA: &[u8] = b"application/vnd.shirudo.upatch.tree.signature.v1";
pub(crate) const TREE_ARTIFACT: &[u8] = b"application/vnd.shirudo.upatch.tree.v1";
pub(crate) const EMPTY_CONFIG_MEDIA: &[u8] = b"application/vnd.oci.empty.v1+json";
const USERNAME_SIZE: usize = 256;
const PASSWORD_SIZE: usize = 4096;
const TOKEN_SIZE: usize = 4096;
const BASIC_RAW_SIZE: usize = USERNAME_SIZE + PASSWORD_SIZE;
const BASIC_ENCODED_SIZE: usize = 4 * BASIC_RAW_SIZE.div_ceil(3) + 1;
const AUTH_VALUE_SIZE: usize = BASIC_ENCODED_SIZE + "Basic ".len() + 1;
const BASIC_HEADER_SIZE: usize = AUTH_VALUE_SIZE + "Authorization: ".len();

/// A downloaded body. The final byte is NUL when the body was fetched.
pub struct BpmBuffer {
    pub(super) data: Vec<u8>,
}

struct HttpResponse {
    body: BpmBuffer,
    www_auth: [u8; 2048],
    location: [u8; PATH_MAX],
    status: c_long,
}

/// `struct bpm_oci_client`.
#[repr(C)]
pub struct OciClient {
    base_url: [u8; MAX_ENDPOINT],
    registry: [u8; MAX_ENDPOINT],
    username: [u8; USERNAME_SIZE],
    password: [u8; PASSWORD_SIZE],
    token: [u8; TOKEN_SIZE],
    ca_file: [u8; PATH_MAX],
}

/// `struct bpm_descriptor`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Descriptor {
    media: [u8; MAX_MEDIA],
    digest: [u8; MAX_DIGEST],
    title: [u8; PATH_MAX],
    size: i64,
}

const _: () = assert!(size_of::<OciClient>() == 13568);
const _: () = assert!(size_of::<Descriptor>() == 4424);

impl BpmBuffer {
    pub(crate) const fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub(crate) fn has_data(&self) -> bool {
        !self.data.is_empty()
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        if self.data.is_empty() {
            &[]
        } else {
            &self.data[..self.data.len() - 1]
        }
    }

    pub(crate) fn as_ptr(&self) -> *const u8 {
        if self.has_data() {
            self.data.as_ptr()
        } else {
            core::ptr::null()
        }
    }
}

impl HttpResponse {
    const fn new() -> Self {
        HttpResponse {
            body: BpmBuffer::new(),
            www_auth: [0; 2048],
            location: [0; PATH_MAX],
            status: 0,
        }
    }
}

impl Descriptor {
    /// A blob's descriptor: its media type, digest and size.
    pub(crate) fn of(media: &[u8], digest: &[u8], size: i64) -> Self {
        let mut d = Descriptor::new();

        copy_string(&mut d.media, media);
        copy_string(&mut d.digest, digest);
        d.size = size;
        d
    }

    pub(crate) const fn new() -> Self {
        Descriptor {
            media: [0; MAX_MEDIA],
            digest: [0; MAX_DIGEST],
            title: [0; PATH_MAX],
            size: 0,
        }
    }
}

/// isspace() in the C locale, vertical tab included.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// bpm_copy_string(): `src` cut to the room of `dst`, terminated.
pub(crate) fn copy_string(dst: &mut [u8], src: &[u8]) {
    let Some(room) = dst.len().checked_sub(1) else {
        return;
    };
    let n = src.len().min(room);

    dst[..n].copy_from_slice(&src[..n]);
    dst[n] = 0;
}

/// A name or version: alphanumerics, `-`, `_`, `.` and with `plus` `+`,
/// not starting with a dot and shorter than `BPM_MAX_NAME`.
fn component_ok(s: &[u8], plus: bool) -> bool {
    if s.is_empty() || s.len() >= MAX_NAME || s[0] == b'.' {
        return false;
    }
    s.iter().all(|&c| {
        c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.') || (plus && c == b'+')
    })
}

pub(crate) fn name_ok(s: &[u8]) -> bool {
    component_ok(s, false)
}

pub(crate) fn version_ok(s: &[u8]) -> bool {
    component_ok(s, true)
}

pub(crate) fn package_name_ok(s: &[u8]) -> bool {
    if !s.first().is_some_and(u8::is_ascii_alphanumeric) {
        return false;
    }
    s.iter()
        .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        && s.len() < MAX_NAME
}

/// Where the text of `s` starts and ends with the blanks around it gone.
fn trim_range(s: &[u8]) -> (usize, usize) {
    let start = s.iter().position(|&c| !is_space(c)).unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|&c| !is_space(c))
        .map_or(start, |i| i + 1);

    (start, end)
}

/// Blanks trimmed off both ends of `s` into `out`; -E2BIG when `out` had
/// to cut it, as strscpy() does.
pub(crate) fn trim(s: &[u8], out: &mut [u8]) -> Result<(), i32> {
    let Some(room) = out.len().checked_sub(1) else {
        return Err(-E2BIG);
    };
    let (start, end) = trim_range(s);
    let mut text = &s[start..end];
    let mut ret = Ok(());

    if text.len() > room {
        text = &text[..room];
        ret = Err(-E2BIG);
    }
    out[..text.len()].copy_from_slice(text);
    out[text.len()] = 0;
    ret
}

/// `want` is `sha256:` and the hex of `hex` in either case.
pub(crate) fn digest_matches(want: &[u8], hex: &[u8]) -> bool {
    want.strip_prefix(b"sha256:")
        .is_some_and(|w| w.eq_ignore_ascii_case(hex))
}

/// A pointer for C to a NUL-terminated buffer.
fn c_ptr(buf: &[u8]) -> *const c_char {
    buf.as_ptr().cast()
}

#[cfg(shirudo_fuzz)]
mod fuzz;
#[cfg(test)]
mod tests;
