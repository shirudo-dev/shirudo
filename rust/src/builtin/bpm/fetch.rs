// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! What bpm fetches from registries: packages, repository indexes and
//! the tree's artifacts, each checked against the digest that names it.

use core::ffi::{CStr, c_int};
use std::ffi::{CString, OsStr};
use std::fs;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

use super::source::{self, Source};
use super::{
    INDEX_MEDIA, INDEX_SIG_MEDIA, INDEX_TAG, PACKAGE_MEDIA, REPOS_DIR, Result, TREE_ARTIFACTS_DIR,
    UPATCH_MEDIA, curl_ready, fail, finish, lock, os_err, path, remove, status,
};
use crate::errno::{EINVAL, EIO, EKEYREJECTED, ENAMETOOLONG, ENOENT};
use crate::sys::libc::{O_CREAT, O_EXCL, O_RDWR, R_OK, access, pread};
use crate::text::{cstr, strscpy};
use crate::util::bpm_oci::{
    Buffer, Client, Descriptor, MANIFEST_MEDIA, MAX_ENTRIES, MAX_NAME, digest_matches,
    manifest_layers, name_ok, package_name_ok, sha256_hex, trim,
};
use crate::util::bpm_package::{IndexEntry, index_parse, semver_compare};
use crate::util::bpm_tree::TreeOperation;
use crate::util::crypto_openssl::{
    Sha256Ctx, sha256_final, sha256_free, sha256_init, sha256_update,
};
use crate::util::io::{self, memfd};
use crate::util::seal;
use crate::util::upatch::Upatch;

/// The most layers a package manifest names that bpm reads.
const LAYERS_MAX: usize = 8;

/// The hex SHA-256 of the bytes of `fd` from its start, whatever its
/// offset.
pub(super) fn sha256_fd(fd: BorrowedFd<'_>) -> Result<[u8; 64]> {
    let mut ctx = Sha256Ctx::new();
    let mut digest = [0; 32];
    let mut hex = [0; 65];

    // SAFETY: a context to set up, freed below.
    if unsafe { sha256_init(&mut ctx) } != 0 {
        return Err(-EINVAL);
    }
    let ret = (|| {
        let mut buf = vec![0u8; 65536];
        let mut at = 0i64;

        loop {
            // SAFETY: the caller's descriptor and room for the bytes.
            let n = unsafe { pread(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), at) };
            if n < 0 {
                return Err(-EIO);
            }
            if n == 0 {
                break;
            }
            // SAFETY: the context and n bytes read.
            if unsafe { sha256_update(&mut ctx, buf.as_ptr().cast(), n as usize) } != 0 {
                return Err(-EIO);
            }
            at += n as i64;
        }
        // SAFETY: the context and room for the digest.
        if unsafe { sha256_final(&mut ctx, digest.as_mut_ptr()) } != 0 {
            return Err(-EIO);
        }
        Ok(())
    })();
    // SAFETY: the context set up above.
    unsafe { sha256_free(&mut ctx) };
    ret?;
    sha256_hex_of(&digest, &mut hex);
    let mut out = [0; 64];
    out.copy_from_slice(&hex[..64]);
    Ok(out)
}

/// The lowercase hex of `digest`, NUL-terminated.
fn sha256_hex_of(digest: &[u8; 32], hex: &mut [u8; 65]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    for (i, b) in digest.iter().enumerate() {
        hex[2 * i] = HEX[usize::from(b >> 4)];
        hex[2 * i + 1] = HEX[usize::from(b & 0xf)];
    }
    hex[64] = 0;
}

/// The hex SHA-256 of `data`.
pub(super) fn sha256_of(data: &[u8]) -> Result<[u8; 64]> {
    let mut hex = [0; 65];
    let mut out = [0; 64];

    status(sha256_hex(data, &mut hex))?;
    out.copy_from_slice(&hex[..64]);
    Ok(out)
}

/// The manifest at `reference` of `repository`.
pub(super) fn manifest(c: &mut Client, repository: &[u8], reference: &[u8]) -> Result<Buffer> {
    let url = c.url(repository, b"manifests", reference)?;

    c.get(&url, MANIFEST_MEDIA, false)
}

/// The registry names the layer without a signature, so its title names
/// the file only when it is a package name ending in .bee: never a path,
/// a hidden file, an option or a terminal control sequence.
fn bee_title_ok(title: &[u8]) -> bool {
    package_name_ok(title) && crate::text::name_has_suffix(title, b".bee")
}

/// The last component of a repository.
fn base(repository: &[u8]) -> &[u8] {
    repository
        .iter()
        .rposition(|&c| c == b'/')
        .map_or(repository, |slash| &repository[slash + 1..])
}

/// The layer's title, else <package>-<tag>.bee.
fn pull_filename(
    repository: &[u8],
    tag: &[u8],
    package_name: &[u8],
    title: &[u8],
) -> Result<CString> {
    if bee_title_ok(title) {
        return Ok(super::message(&[title]));
    }
    let base = if package_name.is_empty() {
        base(repository)
    } else {
        package_name
    };
    if !package_name_ok(base) {
        return Err(-EINVAL);
    }
    path(&[base, b"-", tag, b".bee"])
}

/// The package of the OCI reference `raw`, into `into` when given, or
/// else into a new file in the working directory named after the
/// package, and checked as written, read back from the descriptor that
/// wrote it. The registry picks that name, so it is created, never an
/// existing file replaced, and opened as output root may ask for: never
/// a sealed file nor one reached through a link.
pub(super) fn download(raw: &[u8], into: Option<BorrowedFd<'_>>) -> Result {
    let mut c = Client::new();
    let (repository, tag) = c.parse_pull_ref(raw)?;
    let body = manifest(&mut c, &repository, &tag)?;
    let (layers, package_name) = manifest_layers(body.bytes(), LAYERS_MAX, true)?;
    let mut name = [0; MAX_NAME];

    let _ = trim(&package_name, &mut name);
    let package_name = cstr(&name);
    let Some(layer) = layers
        .iter()
        .find(|l| l.media() == PACKAGE_MEDIA.to_bytes())
    else {
        return Err(-EINVAL);
    };
    let url = c.url(&repository, b"blobs", layer.digest())?;
    let mut title = [0; crate::sys::libc::PATH_MAX];
    // A cut title would name another file; fall back to the package name.
    if trim(layer.title(), &mut title).is_err() {
        title[0] = 0;
    }
    let made = match into {
        Some(_) => None,
        None => {
            let filename = pull_filename(&repository, &tag, package_name, cstr(&title))?;
            let fd = seal::output_open(filename.to_bytes(), O_RDWR | O_CREAT | O_EXCL, 0o644)?;
            Some((filename, fd))
        }
    };
    let fd = into.unwrap_or_else(|| made.as_ref().map(|(_, f)| f.as_fd()).expect("made"));
    let mut ret = c.get_file(&url, PACKAGE_MEDIA, fd.as_raw_fd(), layer.size());
    if ret.is_ok() && !checked(fd, layer) {
        ret = Err(-EKEYREJECTED);
    }
    if let Some((filename, file)) = made {
        drop(file);
        if ret.is_err() {
            remove(&filename);
        }
    }
    ret
}

/// Whether the bytes of `fd` are the blob `layer` describes: its
/// digest, and its size when the layer gives one.
fn checked(fd: BorrowedFd<'_>, layer: &Descriptor) -> bool {
    let digest_ok = sha256_fd(fd).is_ok_and(|hex| digest_matches(layer.digest(), &hex));
    let size_ok = || {
        fd.try_clone_to_owned()
            .map(fs::File::from)
            .and_then(|f| f.metadata())
            .is_ok_and(|m| i64::try_from(m.len()) == Ok(layer.size()))
    };

    digest_ok && (layer.size() < 0 || size_ok())
}

/// A package the operator names, open for reading: the local file, or
/// the download in memory. Never a file of /tmp, which root can bind to
/// a sealed directory for shirudo to create a labeled file in.
pub(super) fn package_source_open(source: &[u8]) -> Result<OwnedFd> {
    if !source.starts_with(b"oci://") {
        return fs::File::open(OsStr::from_bytes(source))
            .map(OwnedFd::from)
            .map_err(os_err);
    }
    let fd = memfd(c"shirudo-bpm-package")?;
    download(source, Some(fd.as_fd()))?;
    Ok(fd)
}

/// The source and index entry a direct OCI reference installs.
pub(super) fn direct(raw: &[u8]) -> Result<(Source, IndexEntry)> {
    let mut c = Client::new();
    let (repository, tag) = c.parse_pull_ref(raw)?;
    let body = manifest(&mut c, &repository, &tag)?;
    let (_, package_name) = manifest_layers(body.bytes(), LAYERS_MAX, true)?;
    let name = if package_name.is_empty() {
        base(&repository)
    } else {
        &package_name
    };
    // The name is the C's, cut to its room.
    let name = &name[..name.len().min(MAX_NAME - 1)];

    if !package_name_ok(name) {
        return Err(-EINVAL);
    }
    let endpoint = [b"oci://", c.registry()].concat();
    if endpoint.len() >= crate::util::bpm_oci::MAX_ENDPOINT {
        return Err(-ENAMETOOLONG);
    }
    let mut entry = IndexEntry::new();
    let _ = strscpy(&mut entry.name, name);
    let _ = strscpy(&mut entry.version, &tag);
    let _ = strscpy(&mut entry.repository, &repository);
    // package_install treats a non-digest reference as a tag.
    let _ = strscpy(&mut entry.manifest_digest, &tag);
    entry.package_size = -1;
    Ok((Source::direct(&endpoint), entry))
}

/// The first layer of `media`, fetched and checked against its digest;
/// None when the manifest names none.
fn layer_blob(
    c: &mut Client,
    repository: &[u8],
    layers: &[Descriptor],
    media: &CStr,
) -> Result<Option<Buffer>> {
    let Some(layer) = layers.iter().find(|l| l.media() == media.to_bytes()) else {
        return Ok(None);
    };
    let url = c.url(repository, b"blobs", layer.digest())?;
    let blob = c.get(&url, media, true)?;
    if !digest_matches(layer.digest(), &sha256_of(blob.bytes())?) {
        return Err(-EKEYREJECTED);
    }
    Ok(Some(blob))
}

/// The cached index of source `name`.
fn cache_path(name: &[u8]) -> Result<CString> {
    if !name_ok(name) {
        return Err(-EINVAL);
    }
    path(&[REPOS_DIR.as_bytes(), b"/", name, b"/index.json"])
}

/// Fetches the signed index of source `name`, verifies it with the
/// source's certificate and caches it.
fn update_one(name: &[u8]) -> Result {
    let s = source::load(name)?;
    let mut c = Client::new();

    c.parse_endpoint(s.endpoint())?;
    let body = manifest(&mut c, s.index_repository(), INDEX_TAG)?;
    let (layers, _) = manifest_layers(body.bytes(), LAYERS_MAX, false)?;
    if layers.len() < 2 {
        return Err(-EINVAL);
    }
    let index = layer_blob(&mut c, s.index_repository(), &layers, INDEX_MEDIA)?;
    let Some(sig) = layer_blob(&mut c, s.index_repository(), &layers, INDEX_SIG_MEDIA)?
        .filter(Buffer::has_data)
    else {
        return Err(-EINVAL);
    };
    let index = index.as_ref().map_or(&[][..], |b| b.bytes());
    if s.verify(index, sig.bytes()) != 0 {
        return Err(-EKEYREJECTED);
    }
    index_parse(index).map_err(|_| -EINVAL)?;
    let dir = path(&[super::REPOS_DIR.as_bytes(), b"/", name])?;
    seal::mkdir_p(dir.to_bytes(), 0o700)?;
    let cache = cache_path(name)?;
    seal::write_file(cache.to_bytes(), index, 0o600)
}

/// `shirudo bpm repo update [<source>]`.
/// `bpm repo update` of the source `named`, or of every one.
pub(super) fn repo_update(named: Option<&[u8]>) -> c_int {
    if !curl_ready() {
        return fail(b"initialize curl", -EIO);
    }
    let held = match lock() {
        Ok(held) => held,
        Err(err) => return finish(None, Err(err), b"lock"),
    };
    let mut ret = Ok(());
    if let Some(name) = named {
        ret = update_one(name);
    } else {
        let registries = match source::registries() {
            Ok(d) => Some(d),
            Err(err) if err == -ENOENT => None,
            Err(err) => {
                ret = Err(err);
                None
            }
        };
        // One unreachable registry must not hold back the others.
        for file in registries.into_iter().flatten() {
            let Some(name) = source::registered_name(&file) else {
                continue;
            };
            if name.len() >= MAX_NAME {
                ret = Err(-ENAMETOOLONG);
                continue;
            }
            if update_one(name).is_err() {
                ret = Err(-EIO);
            }
        }
    }
    finish(Some(held), ret, b"repo update")
}

/// The entries of the cached index of source `name`.
pub(super) fn cached_index(name: &[u8]) -> Result<Vec<IndexEntry>> {
    let cache = cache_path(name)?;
    let body = io::read(&cache, 64 << 20)?;
    index_parse(&body)
}

/// The entry of `name` in `entries`: of `version` when given, else the
/// newest, the first of equal versions.
pub(super) fn find_entry(
    entries: &[IndexEntry],
    name: &[u8],
    version: Option<&[u8]>,
) -> Result<IndexEntry> {
    let mut found: Option<&IndexEntry> = None;

    for e in entries {
        if cstr(&e.name) != name || version.is_some_and(|v| cstr(&e.version) != v) {
            continue;
        }
        if found.is_none_or(|f| {
            version.is_none() && semver_compare(cstr(&f.version), cstr(&e.version)) < 0
        }) {
            found = Some(e);
        }
    }
    found.copied().ok_or(-ENOENT)
}

/// That the upatch at `path` carries the expected payload digest, the
/// operation's name when given and the kind it says.
fn verify_upatch(path: &CStr, expected: &[u8], id: Option<&[u8]>, unload: bool) -> Result {
    let u = Upatch::open(path)?;
    let mut actual = [0; 65];

    sha256_hex_of(&u.hdr.payload_sha256, &mut actual);
    if !digest_matches(expected, cstr(&actual))
        || id.is_some_and(|id| u.name() != id)
        || u.is_unload() != unload
    {
        return Err(-EKEYREJECTED);
    }
    Ok(())
}

/// The artifact of a tree operation: cached by the digest of the blob as
/// fetched, which names it as the payload digest would not, since
/// equally built upatches published under different names share that.
pub(super) fn tree_artifact(op: &TreeOperation) -> Result<CString> {
    let a = &op.artifact;
    let layer_digest = cstr(&a.layer_digest);
    let unload = cstr(&op.op) == b"delete";

    if crate::util::bpm_tree::digest_bytes(&a.layer_digest).is_none() {
        return Err(-EINVAL);
    }
    let cache = path(&[
        TREE_ARTIFACTS_DIR.as_bytes(),
        b"/",
        &layer_digest[b"sha256:".len()..],
        b".upatch",
    ])?;
    let expected = cstr(&a.payload_sha256);
    let id = Some(cstr(&op.id));
    // SAFETY: a C string.
    if unsafe { access(cache.as_ptr(), R_OK) } == 0 {
        verify_upatch(&cache, expected, id, unload)?;
        return Ok(cache);
    }
    let mut c = Client::new();
    let repository = c.parse_tree_repo(cstr(&a.repository))?;
    let body = manifest(&mut c, &repository, cstr(&a.manifest_digest))?;
    if !digest_matches(cstr(&a.manifest_digest), &sha256_of(body.bytes())?) {
        return Err(-EKEYREJECTED);
    }
    let (layers, _) = manifest_layers(body.bytes(), MAX_ENTRIES, false)?;
    let Some(layer) = layers
        .iter()
        .find(|l| l.digest() == layer_digest && l.media() == UPATCH_MEDIA.to_bytes())
    else {
        return Err(-ENOENT);
    };
    let url = c.url(&repository, b"blobs", layer.digest())?;
    let blob = c.get(&url, UPATCH_MEDIA, true)?;
    let data = blob.bytes();
    if !digest_matches(layer.digest(), &sha256_of(data)?)
        || (layer.size() >= 0 && i64::try_from(data.len()) != Ok(layer.size()))
    {
        return Err(-EKEYREJECTED);
    }
    seal::mkdir_p(TREE_ARTIFACTS_DIR.as_bytes(), 0o700)?;
    seal::write_file(cache.to_bytes(), data, 0o600)?;
    verify_upatch(&cache, expected, id, unload)?;
    Ok(cache)
}
