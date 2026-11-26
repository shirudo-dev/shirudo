// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The repositories a target installs from, registered under
//! /etc/shirudo/bpm/registries.d or held by the config image, and the
//! tree it syncs.

use core::ffi::c_int;
use std::ffi::CString;
use std::os::fd::{AsFd, FromRawFd, IntoRawFd, OwnedFd};

use super::{
    BPM_KEYS_DIR, DirStream, INDEX_REPOSITORY_NAME, REGISTRIES_DIR, Result, Stream, TREE_ETC_PATH,
    error, path, print, remove, status,
};
use crate::errno::{E2BIG, EINVAL, ENAMETOOLONG};
use crate::sys::libc::{O_DIRECTORY, O_RDONLY, PATH_MAX};
use crate::text::{contains, cstr, name_has_suffix, strscpy, strsprintf};
use crate::util::bpm_oci::{Client, MAX_DIGEST, MAX_ENDPOINT, MAX_NAME, name_ok};
use crate::util::bpm_package::{verify_cms, verify_cms_fd};
use crate::util::bpm_source_config::{parse_source_line, parse_tree_line};
use crate::util::crypto_openssl::{Cert, cert_read_file};
use crate::util::image_config::{self, REGISTRIES, TREE_CONF};
use crate::util::io::open_trusted;
use crate::util::json::JsonEmit;
use crate::util::seal;

/// `BPM_MAX_KEY`: the longest key file path, its NUL included.
const MAX_KEY: usize = 256;

/// A registered repository: where it is, the index it publishes and the
/// certificate that signs that index.
pub(super) struct Source {
    name: [u8; MAX_NAME],
    endpoint: [u8; MAX_ENDPOINT],
    index_repository: [u8; MAX_ENDPOINT],
    key_file: [u8; MAX_KEY],
}

impl Source {
    pub(super) fn new() -> Self {
        Source {
            name: [0; MAX_NAME],
            endpoint: [0; MAX_ENDPOINT],
            index_repository: [0; MAX_ENDPOINT],
            key_file: [0; MAX_KEY],
        }
    }

    /// The source a direct reference installs from: its registry alone.
    pub(super) fn direct(endpoint: &[u8]) -> Self {
        let mut s = Source::new();

        let _ = strscpy(&mut s.name, b"direct");
        let _ = strscpy(&mut s.endpoint, endpoint);
        s
    }

    pub(super) fn endpoint(&self) -> &[u8] {
        cstr(&self.endpoint)
    }

    pub(super) fn index_repository(&self) -> &[u8] {
        cstr(&self.index_repository)
    }

    fn key_file(&self) -> &[u8] {
        cstr(&self.key_file)
    }

    /// The key file, open as verification reads it: from the config
    /// image's root when one is active.
    pub(super) fn key_open(&self) -> c_int {
        let Ok(key) = CString::new(self.key_file()) else {
            return -EINVAL;
        };

        if image_config::active() {
            return image_config::open_relative(&key, O_RDONLY);
        }
        // SAFETY: a C string.
        let fd = unsafe { crate::sys::libc::open(key.as_ptr(), O_RDONLY) };
        if fd < 0 { super::last_err() } else { fd }
    }

    /// Whether `sig` signs `data` with the source's certificate: 0 or
    /// -errno.
    pub(super) fn verify(&self, data: &[u8], sig: &[u8]) -> c_int {
        if !image_config::active() {
            let Ok(key) = CString::new(self.key_file()) else {
                return -EINVAL;
            };
            return verify_cms(data, sig, &key);
        }
        let fd = self.key_open();
        if fd < 0 {
            return fd;
        }
        // SAFETY: the fd key_open() just gave, owned from here.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        verify_cms_fd(data, sig, fd.as_fd())
    }
}

/// The registration file of source `name`.
fn source_path(name: &[u8]) -> Result<CString> {
    if !name_ok(name) {
        return Err(-EINVAL);
    }
    path(&[REGISTRIES_DIR.as_bytes(), b"/", name, b".conf"])
}

/// The registrations, from the config image when one is active.
pub(super) fn registries() -> Result<DirStream> {
    if image_config::active() {
        return DirStream::from_fd(image_config::open(REGISTRIES, O_RDONLY | O_DIRECTORY));
    }
    DirStream::open(&message_path(REGISTRIES_DIR))
}

fn message_path(p: &str) -> CString {
    super::message(&[p.as_bytes()])
}

/// The name a registration file gives its source, when it is one.
pub(super) fn registered_name(file: &[u8]) -> Option<&[u8]> {
    name_has_suffix(file, b".conf").then(|| &file[..file.len() - 5])
}

/// That the index repository of a source is `<namespace>/bpm-index` and
/// stays that once parsed against its endpoint.
fn index_repository_valid(endpoint: &[u8], repository: &[u8]) -> Result {
    match repository.iter().rposition(|&c| c == b'/') {
        Some(slash) if slash > 0 && &repository[slash + 1..] == INDEX_REPOSITORY_NAME => {}
        _ => return Err(-EINVAL),
    }
    let raw = [endpoint, b"/", repository].concat();
    if raw.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    if Client::new().parse_push_repo(&raw)? != repository {
        return Err(-EINVAL);
    }
    Ok(())
}

/// Registered source `name`.
pub(super) fn load(name: &[u8]) -> Result<Source> {
    let file = source_path(name)?;
    let mut stream = if image_config::active() {
        Stream::from_fd(image_config::open_relative(
            &CString::new(&file.to_bytes()[1..]).map_err(|_| -EINVAL)?,
            O_RDONLY,
        ))?
    } else {
        Stream::from_fd(open_trusted(&file, O_RDONLY)?.into_raw_fd())?
    };
    let mut s = Source::new();

    strscpy(&mut s.name, name).map_err(|_| -ENAMETOOLONG)?;
    stream.lines(|line| {
        status(parse_source_line(
            line,
            &mut s.endpoint,
            &mut s.index_repository,
            &mut s.key_file,
        ))
    })?;
    drop(stream);
    if s.endpoint[0] == 0 || s.key_file[0] == 0 {
        return Err(-EINVAL);
    }
    if s.index_repository[0] == 0 {
        strsprintf(
            &mut s.index_repository,
            &[name, b"/", INDEX_REPOSITORY_NAME],
        )
        .map_err(|_| -E2BIG)?;
    }
    index_repository_valid(s.endpoint(), s.index_repository())?;
    // With a config image the key file is the image's, named from its
    // root.
    if image_config::active() {
        if s.key_file().starts_with(b"/etc/shirudo/bpm/keys/") {
            s.key_file.copy_within(1.., 0);
        }
        if s.key_file[0] == b'/' || contains(s.key_file(), b"..") {
            return Err(-EINVAL);
        }
    }
    Ok(s)
}

fn save(s: &Source) -> Result {
    let file = source_path(cstr(&s.name))?;
    let data = [
        b"endpoint = ",
        s.endpoint(),
        b"\nindex_repository = ",
        s.index_repository(),
        b"\nkey_file = ",
        s.key_file(),
        b"\n",
    ]
    .concat();

    if data.len() >= 2 * PATH_MAX {
        return Err(-E2BIG);
    }
    seal::write_file(file.to_bytes(), &data, 0o644)
}

/// `bpm config register list`.
pub(super) fn list(json: bool) -> c_int {
    let mut buf = [0u8; 8192];
    let mut e = JsonEmit::fixed(&mut buf);
    let mut count = 0;

    if json {
        e.obj_open();
        e.kv_int(b"schema", 1);
        e.arr_open(b"sources");
    } else {
        print(b"Registered sources:\n");
    }
    for file in registries().into_iter().flatten() {
        let Some(name) = registered_name(&file) else {
            continue;
        };
        if name.len() > 255 {
            continue;
        }
        if json {
            e.str(name);
        } else {
            print(&[b"  ", name, b"\n"].concat());
        }
        count += 1;
    }
    if json {
        e.arr_close();
        e.obj_close();
        if e.err() != 0 {
            return 1;
        }
        print(&[e.output(), b"\n"].concat());
    } else if count == 0 {
        print(b"  none\n");
    }
    0
}

/// `bpm config register remove`.
pub(super) fn unregister(name: &[u8]) -> c_int {
    let Ok(file) = source_path(name) else {
        return 2;
    };

    if let Ok(s) = load(name)
        && s.key_file[0] != 0
    {
        remove(&super::message(&[s.key_file()]));
    }
    // SAFETY: a C string.
    if unsafe { crate::sys::libc::unlink(file.as_ptr()) } != 0
        && crate::sys::libc::errno() != crate::errno::ENOENT
    {
        return 1;
    }
    if let Ok(key) = path(&[BPM_KEYS_DIR.as_bytes(), b"/", name, b".der"]) {
        remove(&key);
    }
    0
}

/// Whether a source's name and endpoint fit its record.
pub(super) fn fits(name: &[u8], endpoint: &[u8]) -> bool {
    let s = Source::new();

    name.len() < s.name.len() && endpoint.len() < s.endpoint.len()
}

/// `bpm config register add`: the source `name` at `endpoint`, its
/// index at `index_repository` or else <name>/bpm-index, signed for the
/// certificate at `cert`.
pub(super) fn register(
    name: &[u8],
    endpoint: &[u8],
    cert: &[u8],
    index_repository: Option<&[u8]>,
) -> c_int {
    let mut s = Source::new();

    if strscpy(&mut s.name, name).is_err() || strscpy(&mut s.endpoint, endpoint).is_err() {
        return 2;
    }
    let indexed = match index_repository {
        Some(repo) => strscpy(&mut s.index_repository, repo).is_ok(),
        None => strsprintf(
            &mut s.index_repository,
            &[name, b"/", INDEX_REPOSITORY_NAME],
        )
        .is_ok(),
    };
    if !indexed {
        return 2;
    }
    let key = super::message(&[cert]);
    let mut read = Cert::new();
    // SAFETY: a C string and a certificate to fill.
    let cert_ok = unsafe { cert_read_file(key.as_ptr(), &mut read) } == 0;
    let valid = cert_ok
        && name_ok(cstr(&s.name))
        && Client::new().parse_endpoint(s.endpoint()).is_ok()
        && index_repository_valid(s.endpoint(), s.index_repository()).is_ok();
    if !valid {
        error(&[
            b"bpm: register add requires a valid endpoint, index repository and --cert certificate",
        ]);
        return 2;
    }
    for dir in [REGISTRIES_DIR, BPM_KEYS_DIR] {
        if seal::mkdir_p(dir.as_bytes(), 0o700).is_err() {
            return 1;
        }
    }
    let Ok(managed) = path(&[BPM_KEYS_DIR.as_bytes(), b"/", cstr(&s.name), b".der"]) else {
        return 1;
    };
    if super::package::copy_file(&key, &managed, 0o644, false).is_err() {
        return 1;
    }
    if strscpy(&mut s.key_file, managed.to_bytes()).is_err() {
        return 1;
    }
    if save(&s).is_err() { 1 } else { 0 }
}

/// Where the tree is published: the endpoint of its repository and the
/// reference of its publication.
pub(super) struct TreeConfig {
    pub(super) endpoint: [u8; MAX_ENDPOINT],
    pub(super) reference: [u8; MAX_DIGEST],
}

/// The tree configuration, from the config image when one is active:
/// -ENOENT without one.
pub(super) fn load_tree() -> Result<TreeConfig> {
    let mut stream = if image_config::active() {
        Stream::from_fd(image_config::open(TREE_CONF, O_RDONLY))?
    } else {
        Stream::from_fd(open_trusted(TREE_ETC_PATH, O_RDONLY)?.into_raw_fd())?
    };
    let mut cfg = TreeConfig {
        endpoint: [0; MAX_ENDPOINT],
        reference: [0; MAX_DIGEST],
    };

    stream
        .lines(|line| status(parse_tree_line(line, &mut cfg.endpoint, &mut cfg.reference)))
        .map_err(|_| -EINVAL)?;
    if cfg.endpoint[0] == 0 || cfg.reference[0] == 0 {
        return Err(-EINVAL);
    }
    Ok(cfg)
}
