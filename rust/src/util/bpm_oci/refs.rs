// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Registry endpoints, the references that name a package, a repository
//! or a tree on one, and the URLs built from them.

use core::ffi::c_int;

use super::auth::load_registry_auth;
use super::{
    MAX_ENDPOINT, OciClient, PATH_MAX, at, c_ptr, contains, copy_string, cstr, package_name_ok,
    strscpy, strsprintf, trim, version_ok,
};
use crate::errno::{EINVAL, ENAMETOOLONG, EPERM};
use crate::sys::libc::Zeroed;
use crate::sys::libc::{self, AT_FDCWD, S_IFMT, S_IFREG, STATX_SIZE, STATX_TYPE, Statx};
use crate::util::crypto_openssl::{Cert, cert_read_file};

/// `oci://host[:port]` into the client, with the transport
/// BPM_OCI_SCHEME picks, the CA file BPM_OCI_CA_FILE names and the
/// registry's credentials.
pub(super) fn parse_endpoint(endpoint: &[u8], c: &mut OciClient) -> c_int {
    let scheme = libc::env(c"BPM_OCI_SCHEME").map(|s| s.to_bytes());
    let mut transport: &[u8] = b"https";

    let Some(p) = endpoint.strip_prefix(b"oci://") else {
        return -EINVAL;
    };
    if p.is_empty() || p.iter().any(|c| matches!(c, b'/' | b'?' | b'#' | b'@')) {
        return -EINVAL;
    }
    if let Some(scheme) = scheme.filter(|s| !s.is_empty()) {
        if scheme != b"https" && scheme != b"http" {
            crate::log::err(b"bpm OCI: BPM_OCI_SCHEME must be https or http");
            return -EINVAL;
        }
        transport = scheme;
    }
    if strscpy(&mut c.registry, p).is_err() {
        return -ENAMETOOLONG;
    }
    if strsprintf(&mut c.base_url, &[transport, b"://", p]).is_err() {
        return -ENAMETOOLONG;
    }
    if let Some(ca_file) = libc::env(c"BPM_OCI_CA_FILE") {
        let mut ca = Cert::new();

        if ca_file.to_bytes().len() >= c.ca_file.len() {
            return -ENAMETOOLONG;
        }
        copy_string(&mut c.ca_file, ca_file.to_bytes());
        // SAFETY: a C string path and a cert to fill.
        if unsafe { cert_read_file(c_ptr(&c.ca_file), &mut ca) } != 0 {
            crate::log::err(b"bpm OCI: BPM_OCI_CA_FILE is not a readable certificate");
            return -EINVAL;
        }
    }
    if c.ca_file[0] != 0 && !regular_nonempty(&c.ca_file) {
        crate::log::err(b"bpm OCI: BPM_OCI_CA_FILE must name a non-empty regular PEM file");
        return -EINVAL;
    }
    let registry = c.registry;
    load_registry_auth(cstr(&registry), c)
}

/// stat() the path names a regular file of at least a byte.
fn regular_nonempty(path: &[u8]) -> bool {
    let mut stx = Statx::zeroed();

    // SAFETY: a C string path and a struct statx to fill.
    if unsafe { libc::statx(AT_FDCWD, c_ptr(path), 0, STATX_TYPE | STATX_SIZE, &mut stx) } != 0 {
        return false;
    }
    stx.stx_mode & S_IFMT == S_IFREG && stx.stx_size > 0
}

/// Each `/`-separated part of `repo` is a name: not empty, not `..`, and
/// with `no_dot` not `.` either. A trailing `/` ends the walk without a
/// part after it, which the package name check then refuses.
fn parts_ok(repo: &[u8], no_dot: bool) -> bool {
    let mut start = 0;

    while start < repo.len() {
        let end = repo[start..]
            .iter()
            .position(|&c| c == b'/')
            .map_or(repo.len(), |i| start + i);
        let part = &repo[start..end];

        if part.is_empty() || part == b".." || (no_dot && part == b".") {
            return false;
        }
        start = if end < repo.len() { end + 1 } else { end };
    }
    true
}

/// The package a repository names: its last part.
fn last_part(repo: &[u8]) -> &[u8] {
    repo.rsplit(|&c| c == b'/').next().unwrap_or(repo)
}

/// The endpoint `oci://host` of `oci://host/...` into `endpoint`.
fn endpoint_of(host: &[u8], endpoint: &mut [u8; MAX_ENDPOINT]) {
    endpoint[..6].copy_from_slice(b"oci://");
    endpoint[6..6 + host.len()].copy_from_slice(host);
    endpoint[6 + host.len()] = 0;
}

/// `oci://host/repository:tag` into the client, `repository` and `tag`.
pub(super) fn parse_pull_ref(
    raw: &[u8],
    c: &mut OciClient,
    repository: &mut [u8],
    tag: &mut [u8],
) -> c_int {
    let mut normalized = [0u8; PATH_MAX];
    let mut endpoint = [0u8; MAX_ENDPOINT];

    if raw.len() >= normalized.len() {
        return -EINVAL;
    }
    let _ = trim(raw, &mut normalized);
    let Some(p) = cstr(&normalized).strip_prefix(b"oci://") else {
        return -EINVAL;
    };
    if p.is_empty() || p.iter().any(|c| matches!(c, b'@' | b'?' | b'#')) {
        return -EINVAL;
    }
    let slash = match p.iter().position(|&c| c == b'/') {
        Some(slash) if slash > 0 => slash,
        _ => return -EINVAL,
    };
    let last_slash = p.iter().rposition(|&c| c == b'/').unwrap_or(slash);
    let colon = match p.iter().rposition(|&c| c == b':') {
        Some(colon) if colon > last_slash + 1 && colon + 1 < p.len() => colon,
        _ => return -EINVAL,
    };
    if slash >= endpoint.len() - 6
        || colon - slash > repository.len()
        || p.len() - colon > tag.len()
    {
        return -ENAMETOOLONG;
    }
    endpoint_of(&p[..slash], &mut endpoint);
    let repo = &p[slash + 1..colon];
    repository[..repo.len()].copy_from_slice(repo);
    repository[repo.len()] = 0;
    copy_string(tag, &p[colon + 1..]);
    if contains(repo, b"//")
        || repo.iter().any(|c| matches!(c, b'?' | b'#' | b':'))
        || !parts_ok(repo, false)
    {
        return -EINVAL;
    }
    let tag = cstr(tag);
    if !package_name_ok(last_part(repo)) || !version_ok(tag) || !at(tag, 0).is_ascii_alphanumeric()
    {
        return -EINVAL;
    }
    parse_endpoint(cstr(&endpoint), c)
}

/// `oci://host/repository` to push to into the client and `repository`.
pub(super) fn parse_push_repo(raw: &[u8], c: &mut OciClient, repository: &mut [u8]) -> c_int {
    let mut normalized = [0u8; PATH_MAX];
    let mut endpoint = [0u8; MAX_ENDPOINT];

    if raw.len() >= normalized.len() {
        return -EINVAL;
    }
    let _ = trim(raw, &mut normalized);
    let Some(p) = cstr(&normalized).strip_prefix(b"oci://") else {
        return -EINVAL;
    };
    let slash = match p.iter().position(|&c| c == b'/') {
        Some(slash) if slash > 0 && slash + 1 < p.len() => slash,
        _ => return -EINVAL,
    };
    if p.iter().any(|c| matches!(c, b'@' | b'?' | b'#')) {
        return -EINVAL;
    }
    if slash >= endpoint.len() - 6 || p.len() - slash > repository.len() {
        return -ENAMETOOLONG;
    }
    endpoint_of(&p[..slash], &mut endpoint);
    copy_string(repository, &p[slash + 1..]);
    let repo = cstr(repository);
    if repo.contains(&b':')
        || contains(repo, b"//")
        || contains(repo, b"..")
        || !parts_ok(repo, true)
    {
        return -EINVAL;
    }
    if !package_name_ok(last_part(repo)) {
        return -EINVAL;
    }
    parse_endpoint(cstr(&endpoint), c)
}

/// An upatch tree's `oci://host/repository`, which names no tag.
pub(super) fn parse_tree_repo(raw: &[u8], c: &mut OciClient, repository: &mut [u8]) -> c_int {
    let mut endpoint = [0u8; MAX_ENDPOINT];

    let Some(p) = raw.strip_prefix(b"oci://") else {
        return -EINVAL;
    };
    let slash = match p.iter().position(|&c| c == b'/') {
        Some(slash) if slash > 0 && slash + 1 < p.len() => slash,
        _ => return -EINVAL,
    };
    if p.iter().any(|c| matches!(c, b'?' | b'#' | b'@')) {
        return -EINVAL;
    }
    if slash + 6 >= endpoint.len() || p.len() - slash > repository.len() {
        return -ENAMETOOLONG;
    }
    endpoint_of(&p[..slash], &mut endpoint);
    copy_string(repository, &p[slash + 1..]);
    let repo = cstr(repository);
    if contains(repo, b"..") || contains(repo, b"//") || repo.contains(&b':') {
        return -EINVAL;
    }
    parse_endpoint(cstr(&endpoint), c)
}

/// `<base_url>/v2/<repo>/<kind>/<reference>` into `out`.
pub(crate) fn url(
    c: &OciClient,
    repo: &[u8],
    kind: &[u8],
    reference: &[u8],
    out: &mut [u8],
) -> c_int {
    if contains(repo, b"..")
        || contains(repo, b"//")
        || repo.iter().any(|c| matches!(c, b'?' | b'#'))
        || contains(reference, b"..")
        || reference.iter().any(|c| matches!(c, b'/' | b'?' | b'#'))
    {
        return -EINVAL;
    }
    match strsprintf(
        out,
        &[
            cstr(&c.base_url),
            b"/v2/",
            repo,
            b"/",
            kind,
            b"/",
            reference,
        ],
    ) {
        Ok(_) => 0,
        Err(_) => -ENAMETOOLONG,
    }
}

/// The upload URL a registry's Location names: a path on it, or a URL
/// under its base and nowhere else.
pub(super) fn upload_location(c: &OciClient, location: &[u8], out: &mut [u8]) -> c_int {
    let base = cstr(&c.base_url);

    if location.is_empty() {
        return -EINVAL;
    }
    if location[0] == b'/' {
        return match strsprintf(out, &[base, location]) {
            Ok(_) => 0,
            Err(_) => -ENAMETOOLONG,
        };
    }
    if !location.starts_with(base) || location.get(base.len()) != Some(&b'/') {
        return -EPERM;
    }
    if location.len() >= out.len() {
        return -ENAMETOOLONG;
    }
    copy_string(out, location);
    0
}
