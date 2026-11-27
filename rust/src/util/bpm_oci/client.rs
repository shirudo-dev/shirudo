// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The client as Rust code holds it: owned, scrubbed when it goes, with
//! what it fetches owned too.

use core::ffi::{CStr, c_int};
use std::ffi::CString;

use super::{BpmBuffer, Descriptor, MAX_ENDPOINT, MAX_NAME, OciClient, http, manifest, refs};
use crate::errno::EINVAL;
use crate::sys::libc::{PATH_MAX, explicit_bzero};
use crate::text::cstr;

/// A negative errno.
type Result<T> = core::result::Result<T, c_int>;

fn status(ret: c_int) -> Result<()> {
    if ret == 0 { Ok(()) } else { Err(ret) }
}

/// An OCI client, scrubbed when it goes as `bpm_oci_client_clear()`
/// scrubs a C caller's.
pub(crate) struct Client(Box<OciClient>);

impl Client {
    pub(crate) fn new() -> Self {
        Client(Box::new(OciClient::empty()))
    }

    pub(crate) fn as_mut(&mut self) -> &mut OciClient {
        &mut self.0
    }

    /// The registry an endpoint or reference named.
    pub(crate) fn registry(&self) -> &[u8] {
        cstr(&self.0.registry)
    }

    pub(crate) fn parse_endpoint(&mut self, endpoint: &[u8]) -> Result<()> {
        status(refs::parse_endpoint(endpoint, &mut self.0))
    }

    /// The repository and tag of a pull reference.
    pub(crate) fn parse_pull_ref(&mut self, raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut repository = [0; MAX_ENDPOINT];
        let mut tag = [0; MAX_NAME];

        status(refs::parse_pull_ref(
            raw,
            &mut self.0,
            &mut repository,
            &mut tag,
        ))?;
        Ok((cstr(&repository).to_vec(), cstr(&tag).to_vec()))
    }

    /// The repository a push reference names.
    pub(crate) fn parse_push_repo(&mut self, raw: &[u8]) -> Result<Vec<u8>> {
        let mut repository = [0; MAX_ENDPOINT];

        status(refs::parse_push_repo(raw, &mut self.0, &mut repository))?;
        Ok(cstr(&repository).to_vec())
    }

    /// The repository a tree endpoint names.
    pub(crate) fn parse_tree_repo(&mut self, raw: &[u8]) -> Result<Vec<u8>> {
        let mut repository = [0; MAX_ENDPOINT];

        status(refs::parse_tree_repo(raw, &mut self.0, &mut repository))?;
        Ok(cstr(&repository).to_vec())
    }

    /// The URL of the `kind` ("manifests" or "blobs") `reference` of
    /// `repo`.
    pub(crate) fn url(&self, repo: &[u8], kind: &[u8], reference: &[u8]) -> Result<CString> {
        let mut out = [0; PATH_MAX];

        status(refs::url(&self.0, repo, kind, reference, &mut out))?;
        CString::new(cstr(&out)).map_err(|_| -EINVAL)
    }

    /// The body at `url`, as `bpm_oci_get_memory()` gets a manifest, or
    /// with `blob` as `bpm_oci_get_blob()` gets a blob.
    pub(crate) fn get(&mut self, url: &CStr, accept: &CStr, blob: bool) -> Result<Buffer> {
        let mut body = Buffer(BpmBuffer::new());

        status(http::get_memory(
            &mut self.0,
            url,
            Some(accept),
            &mut body.0,
            blob,
        ))?;
        Ok(body)
    }

    /// The blob at `url` into the file open on `fd`, of `size` bytes when
    /// not negative.
    pub(crate) fn get_file(
        &mut self,
        url: &CStr,
        accept: &CStr,
        fd: c_int,
        size: i64,
    ) -> Result<()> {
        status(http::get_file(&mut self.0, url, Some(accept), fd, size))
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // SAFETY: the client's own bytes.
        unsafe { explicit_bzero((&raw mut *self.0).cast(), size_of::<OciClient>()) };
    }
}

/// A body the client fetched.
pub(crate) struct Buffer(BpmBuffer);

impl Buffer {
    /// Whether the fetch allocated a body at all.
    pub(crate) fn has_data(&self) -> bool {
        self.0.has_data()
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.0.bytes()
    }
}

impl Descriptor {
    pub(crate) fn media(&self) -> &[u8] {
        cstr(&self.media)
    }

    pub(crate) fn digest(&self) -> &[u8] {
        cstr(&self.digest)
    }

    pub(crate) fn title(&self) -> &[u8] {
        cstr(&self.title)
    }

    pub(crate) fn size(&self) -> i64 {
        self.size
    }
}

/// The layers of a manifest, at most `max`, and the package name its
/// annotations give, at most `MAX_NAME - 1` bytes, when `with_name`.
pub(crate) fn manifest_layers(
    body: &[u8],
    max: usize,
    with_name: bool,
) -> Result<(Vec<Descriptor>, Vec<u8>)> {
    let mut layers = vec![Descriptor::new(); max];
    let mut name = [0; MAX_NAME];
    let mut n = 0;

    status(manifest::parse_manifest(
        body,
        &mut layers,
        &mut n,
        with_name.then_some(&mut name[..]),
    ))?;
    layers.truncate(usize::try_from(n).unwrap_or(0));
    Ok((layers, cstr(&name).to_vec()))
}
