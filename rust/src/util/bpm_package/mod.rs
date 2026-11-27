// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `.bee` archives, signed repository indexes and tree publications:
//! the index a target picks a package from,
//! the order of versions, the ustar members of a package, and the signed
//! tree it fetches.

mod archive;
mod facade;
mod index;
mod info;
mod publication;
mod semver;
mod tar;

pub(crate) use facade::{
    Member, extract_fd, fetch_document, fetch_publication, index_parse, read_member_fd,
    read_member_in, verify_cms, verify_cms_fd, visit_members_fd,
};
pub(crate) use info::load_info;
pub(crate) use publication::tree_manifest;
pub(crate) use semver::{compare as semver_compare, valid as semver_valid};
pub(crate) use tar::{archive_rel_ok, upatch_member, upatch_pair};

use super::bpm_oci::{MAX_DIGEST, MAX_ENDPOINT, MAX_NAME};

/// `struct bpm_index_entry`.
#[derive(Clone, Copy)]
pub struct IndexEntry {
    pub(crate) name: [u8; MAX_NAME],
    pub(crate) version: [u8; MAX_NAME],
    pub(crate) repository: [u8; MAX_ENDPOINT],
    pub(crate) manifest_digest: [u8; MAX_DIGEST],
    pub(crate) package_digest: [u8; MAX_DIGEST],
    pub(crate) signer: [u8; MAX_DIGEST],
    pub(crate) package_size: i64,
}

/// A package's identity and its signer's certificate.
pub struct PackageInfo {
    pub(crate) name: [u8; MAX_NAME],
    pub(crate) version: [u8; MAX_NAME],
    pub(crate) signer: [u8; MAX_DIGEST],
    pub(crate) cert: Option<facade::Member>,
}

impl PackageInfo {
    pub(crate) fn new() -> Self {
        Self {
            name: [0; MAX_NAME],
            version: [0; MAX_NAME],
            signer: [0; MAX_DIGEST],
            cert: None,
        }
    }
}

/// `enum bpm_upatch_member`: what a file of a package's upatches/ is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UpatchMember {
    Other = 0,
    Load = 1,
    Unload = 2,
}

impl IndexEntry {
    pub(crate) const fn new() -> Self {
        IndexEntry {
            name: [0; MAX_NAME],
            version: [0; MAX_NAME],
            repository: [0; MAX_ENDPOINT],
            manifest_digest: [0; MAX_DIGEST],
            package_digest: [0; MAX_DIGEST],
            signer: [0; MAX_DIGEST],
            package_size: 0,
        }
    }
}

#[cfg(shirudo_fuzz)]
mod fuzz;
#[cfg(test)]
pub(crate) mod test_archive;
#[cfg(test)]
mod tests;
