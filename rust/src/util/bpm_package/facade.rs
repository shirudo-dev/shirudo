// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The package reader as Rust code calls it, with what it reads owned.

use core::ffi::{CStr, c_char, c_int};
use std::os::fd::BorrowedFd;

use super::archive::{self, Found};
use super::publication::{self, Signed};
use super::{IndexEntry, index};
use crate::errno::EINVAL;
use crate::util::bpm_oci::{Client, MAX_ENTRIES};
use crate::util::bpm_tree::TreePublication;

/// A negative errno.
type Result<T> = core::result::Result<T, c_int>;

/// A member's bytes and their trailing NUL, owned by this value.
pub(crate) struct Member {
    data: Vec<u8>,
}

impl Member {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.data[..self.data.len() - 1]
    }

    /// The bytes, writable, as text_sanitize() takes them.
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        let len = self.data.len() - 1;
        &mut self.data[..len]
    }
}

/// `member` of the package `archive`, in its directory `package_dir`
/// when given, at most `max` bytes; `found_dir` takes the directory it
/// was found in.
pub(crate) fn read_member_in(
    archive: &CStr,
    member: &[u8],
    package_dir: Option<&[u8]>,
    found_dir: Option<&mut [u8]>,
    max: usize,
) -> Result<Member> {
    let mut read = None;
    let mut found = Found {
        out: &mut read,
        dir: found_dir,
    };

    match archive::read_member_in(archive, Some(member), package_dir, &mut found, max) {
        0 => read.map(|data| Member { data }).ok_or(-EINVAL),
        err => Err(err),
    }
}

/// [`read_member_in`] of the package from the start of `fd`, which it
/// leaves open.
pub(crate) fn read_member_fd(
    fd: std::os::fd::BorrowedFd<'_>,
    member: &[u8],
    package_dir: Option<&[u8]>,
    found_dir: Option<&mut [u8]>,
    max: usize,
) -> Result<Member> {
    let mut read = None;
    let mut found = Found {
        out: &mut read,
        dir: found_dir,
    };

    match archive::read_member_fd(fd, Some(member), package_dir, &mut found, max) {
        0 => read.map(|data| Member { data }).ok_or(-EINVAL),
        err => Err(err),
    }
}

/// [`visit_members`] of the package from the start of `fd`, which it
/// leaves open.
pub(crate) fn visit_members_fd(
    fd: std::os::fd::BorrowedFd<'_>,
    package_dir: Option<&[u8]>,
    visit: &mut dyn FnMut(&CStr, c_char) -> c_int,
) -> c_int {
    archive::visit_members_fd(fd, package_dir, Some(visit))
}

pub(crate) fn extract_fd(archive: BorrowedFd<'_>, dest: BorrowedFd<'_>) -> c_int {
    archive::extract_fd(archive, dest)
}

fn signed<'a>(payload: &'a [u8], sig: &'a [u8]) -> Signed<'a> {
    Signed {
        payload: (!payload.is_empty()).then_some(payload),
        sig: (!sig.is_empty()).then_some(sig),
    }
}

/// Whether `sig` is a CMS signature over `payload` by the certificate
/// at `cert_path`: 0 or -errno.
pub(crate) fn verify_cms(payload: &[u8], sig: &[u8], cert_path: &CStr) -> c_int {
    publication::verify_cms(&signed(payload, sig), cert_path)
}

/// As [`verify_cms`], with the certificate open on `cert_fd`.
pub(crate) fn verify_cms_fd(payload: &[u8], sig: &[u8], cert_fd: BorrowedFd<'_>) -> c_int {
    publication::verify_cms_fd(&signed(payload, sig), cert_fd)
}

/// The entries of a signed repository index.
pub(crate) fn index_parse(body: &[u8]) -> Result<Vec<IndexEntry>> {
    let mut entries = vec![IndexEntry::new(); MAX_ENTRIES];
    let mut n = 0;

    match index::index_parse(body, &mut entries, &mut n) {
        0 => {
            entries.truncate(usize::try_from(n).map_err(|_| -EINVAL)?);
            Ok(entries)
        }
        err => Err(err),
    }
}

/// The checked bytes of the tree publication at `repository:reference`,
/// against `trusted`, or the certificate at `cert_path` without one, and
/// its manifest's digest.
pub(crate) fn fetch_document(
    client: &mut Client,
    repository: &[u8],
    reference: &[u8],
    cert_path: Option<&CStr>,
    trusted: Option<&crate::util::keys::TrustedSet>,
) -> core::result::Result<(Vec<u8>, Vec<u8>), c_int> {
    let mut payload = crate::util::bpm_oci::BpmBuffer::new();
    let mut digest = [0u8; 128];
    let ret = publication::fetch_document(
        client.as_mut(),
        repository,
        reference,
        cert_path,
        trusted,
        &mut payload,
        &mut digest,
    );
    if ret != 0 {
        return Err(ret);
    }
    let document = payload.bytes().to_vec();
    Ok((document, crate::text::cstr(&digest).to_vec()))
}

/// The tree publication at `repository:reference`, checked as
/// [`fetch_document`] checks it, and its manifest's digest.
pub(crate) fn fetch_publication(
    client: &mut Client,
    repository: &[u8],
    reference: &[u8],
    cert_path: &CStr,
    trusted: Option<&crate::util::keys::TrustedSet>,
) -> Result<(TreePublication, Vec<u8>)> {
    let (document, digest) =
        fetch_document(client, repository, reference, Some(cert_path), trusted)?;

    Ok((TreePublication::parse(&document)?, digest))
}
