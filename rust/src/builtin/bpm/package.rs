// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Installed packages: installing one from a repository or an OCI
//! reference, upgrading to newer cached versions, uninstalling and
//! listing them.

use core::ffi::{CStr, c_int};
use std::ffi::{CString, OsStr};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

use super::cleanup;
use super::fetch;
use super::source::{self, Source};
use super::{
    PACKAGE_MEDIA, PACKAGES_DIR, Result, curl_ready, error, fail, finish, lock, needs_enforcement,
    os_err, path, print, remove, status,
};
use crate::errno::{E2BIG, EEXIST, EINVAL, EIO, EKEYREJECTED, ENAMETOOLONG, ENOENT};
use crate::sys::libc::{O_CREAT, O_EXCL, O_TRUNC, O_WRONLY};
use crate::text::{cstr, strscpy, strsprintf};
use crate::util::bpm_oci::{
    Client, MAX_NAME, digest_matches, manifest_layers, name_ok, version_ok,
};
use crate::util::bpm_package::{IndexEntry, semver_compare};
use crate::util::bpm_state::{self, BpmStateEntry};
use crate::util::format::name_column_width;
use crate::util::json::JsonEmit;
use crate::util::seal;

/// `BPM_MAX_STATE`: the most packages the state records.
const MAX_STATE: usize = 256;

fn os(path: &CStr) -> &OsStr {
    OsStr::from_bytes(path.to_bytes())
}

/// Copies the file at `src` to `dst`, created as output to /var/lib may
/// be, with `mode`: exclusive, or replacing what is there. A copy onto
/// itself is a copy already made, or -EEXIST when exclusive.
pub(super) fn copy_file(src: &CStr, dst: &CStr, mode: u32, exclusive: bool) -> Result {
    let mut input = fs::File::open(os(src)).map_err(os_err)?;
    let same = match (input.metadata(), fs::metadata(os(dst))) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    };

    // O_TRUNC on a destination that is the source would empty both.
    if same {
        return if exclusive { Err(-EEXIST) } else { Ok(()) };
    }
    let flags = O_WRONLY | O_CREAT | if exclusive { O_EXCL } else { O_TRUNC };
    let mut output = fs::File::from(seal::open(dst.to_bytes(), flags, mode)?);
    let mut buf = vec![0u8; 65536];
    let mut ret = Ok(());
    loop {
        match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if let Err(e) = output.write_all(&buf[..n]) {
                    ret = Err(os_err(e));
                    break;
                }
            }
            Err(e) => {
                ret = Err(os_err(e));
                break;
            }
        }
    }
    if let Err(e) = output.sync_all() {
        ret = ret.and(Err(os_err(e)));
    }
    drop(output);
    if ret.is_err() {
        remove(dst);
    }
    ret
}

/// Fetch and install the package version through one opened archive and
/// directories beneath this boot's checked state root.
pub(super) fn package_install(
    s: &Source,
    entry: &IndexEntry,
    old_version: Option<&[u8]>,
) -> Result {
    let mut c = Client::new();
    let name = cstr(&entry.name);
    let version = cstr(&entry.version);
    let repository = if entry.repository[0] != 0 {
        cstr(&entry.repository)
    } else {
        name
    };
    let reference = cstr(&entry.manifest_digest);

    c.parse_endpoint(s.endpoint())?;
    let body = fetch::manifest(&mut c, repository, reference)?;
    if reference.starts_with(b"sha256:")
        && !fetch::sha256_of(body.bytes()).is_ok_and(|hex| digest_matches(reference, &hex))
    {
        return Err(-EKEYREJECTED);
    }
    let (layers, _) = manifest_layers(body.bytes(), 8, false)?;
    let Some(layer) = layers
        .iter()
        .find(|l| l.media() == PACKAGE_MEDIA.to_bytes())
    else {
        return Err(-EINVAL);
    };
    if entry.package_digest[0] != 0 && cstr(&entry.package_digest) != layer.digest() {
        return Err(-EKEYREJECTED);
    }
    if entry.package_size > 0 && entry.package_size != layer.size() {
        return Err(-EKEYREJECTED);
    }
    let url = c.url(repository, b"blobs", layer.digest())?;
    let mut install = super::install::Install::open(name, version)?;
    let result = (|| {
        c.get_file(
            &url,
            PACKAGE_MEDIA,
            install.archive().as_raw_fd(),
            layer.size(),
        )?;
        if !fetch::sha256_fd(install.archive())
            .is_ok_and(|hex| digest_matches(layer.digest(), &hex))
        {
            return Err(-EKEYREJECTED);
        }
        install.extract()?;
        if !install.cert_matches_active()? {
            return Err(-EKEYREJECTED);
        }
        install.load(old_version)
    })();
    install.finish(result)
}

/// Detach the current version and remove its package through the state
/// directory init recorded for this boot.
fn package_uninstall(st: &BpmStateEntry) -> Result {
    cleanup::uninstall(st)
}

/// `<source>/<name>[@<version>]`.
fn parse_ref(raw: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
    let slash = raw
        .iter()
        .position(|&c| c == b'/')
        .filter(|&slash| slash > 0)
        .ok_or(-EINVAL)?;
    let (source, rest) = (&raw[..slash], &raw[slash + 1..]);
    let (name, version) = match rest.iter().position(|&c| c == b'@') {
        Some(at) => (&rest[..at], &rest[at + 1..]),
        None => (rest, &b""[..]),
    };

    if source.len() >= MAX_NAME || name.len() >= MAX_NAME || version.len() >= MAX_NAME {
        return Err(-ENAMETOOLONG);
    }
    if name_ok(source) && name_ok(name) && (version.is_empty() || version_ok(version)) {
        Ok((source, name, version))
    } else {
        Err(-EINVAL)
    }
}

fn package_path(name: &[u8], version: &[u8]) -> Result<Vec<u8>> {
    path(&[PACKAGES_DIR.as_bytes(), b"/", name, b"/", version]).map(CString::into_bytes)
}

fn set(field: &mut [u8], value: &[u8]) {
    let _ = strscpy(field, value);
}

/// `shirudo bpm install <package>`: idempotent by package name, so that
/// an active package is not even looked up; `bpm upgrade` changes
/// versions.
pub(super) fn install(reference: &[u8]) -> c_int {
    let ret = needs_enforcement(b"install");
    if ret != 0 {
        return ret;
    }
    if !curl_ready() {
        return fail(b"initialize curl", -EIO);
    }
    let held = match lock() {
        Ok(held) => held,
        Err(err) => return finish(None, Err(err), b"lock"),
    };
    let direct = reference.starts_with(b"oci://");
    let picked = if direct {
        fetch::direct(reference).map(|(s, e)| (Some((s, e)), None))
    } else {
        parse_ref(reference).map(|r| (None, Some(r)))
    };
    let (prepared, named) = match picked {
        Ok(p) => p,
        Err(err) => return finish(Some(held), Err(err), b"install"),
    };
    let mut state = match bpm_state::read_all() {
        Ok(state) => state,
        Err(err) => return finish(Some(held), Err(err), b"install"),
    };
    let name: Vec<u8> = match (&prepared, named) {
        (Some((_, entry)), _) => cstr(&entry.name).to_vec(),
        (None, Some((_, name, _))) => name.to_vec(),
        (None, None) => unreachable!(),
    };
    if state.iter().any(|st| cstr(&st.name) == name) {
        return finish(Some(held), Ok(()), b"install");
    }
    let chosen = match (prepared, named) {
        (Some(p), _) => Ok(p),
        (None, Some((src, name, version))) => source::load(src).and_then(|s| {
            let entries = fetch::cached_index(src)?;
            let entry =
                fetch::find_entry(&entries, name, (!version.is_empty()).then_some(version))?;
            Ok((s, entry))
        }),
        (None, None) => unreachable!(),
    };
    let (s, entry) = match chosen {
        Ok(c) => c,
        Err(err) => return finish(Some(held), Err(err), b"install"),
    };
    if state.len() >= MAX_STATE {
        return finish(Some(held), Err(-E2BIG), b"install");
    }
    if let Err(err) = package_install(&s, &entry, None) {
        return finish(Some(held), Err(err), b"install");
    }
    let mut added = BpmStateEntry::new();
    set(&mut added.name, &name);
    set(&mut added.version, cstr(&entry.version));
    let src = match named {
        Some((src, _, _)) => src,
        None => b"direct",
    };
    set(&mut added.source, src);
    let Ok(dir) = package_path(&name, cstr(&entry.version)) else {
        return finish(Some(held), Err(-ENAMETOOLONG), b"install");
    };
    if strsprintf(&mut added.path, &[&dir]).is_err() {
        return finish(Some(held), Err(-ENAMETOOLONG), b"install");
    }
    state.push(added);
    let ret = status(bpm_state::write(&state));
    if ret.is_err() {
        // Unlisted, the package could never be removed.
        if package_uninstall(&added).is_err() {
            error(&[b"bpm install: ", &name, b" stays installed but unlisted"]);
        } else {
            error(&[
                b"bpm install: ",
                &name,
                b" removed again, the state could not be written",
            ]);
        }
    }
    finish(Some(held), ret, b"write state")
}

/// `shirudo bpm upgrade`: each package of a repository to the newest
/// version its cached index lists. Packages upgraded before a failure
/// stay on record.
pub(super) fn upgrade() -> c_int {
    let ret = needs_enforcement(b"upgrade");
    if ret != 0 {
        return ret;
    }
    if !curl_ready() {
        return fail(b"initialize curl", -EIO);
    }
    let held = match lock() {
        Ok(held) => held,
        Err(err) => return finish(None, Err(err), b"lock"),
    };
    let mut state = match bpm_state::read_all() {
        Ok(state) => state,
        Err(err) => return finish(Some(held), Err(err), b"read state"),
    };
    let mut ret = Ok(());
    for st in &mut state {
        if cstr(&st.source) == b"direct" {
            continue;
        }
        let src = cstr(&st.source).to_vec();
        let newest = source::load(&src).and_then(|s| {
            let entries = fetch::cached_index(&src)?;
            Ok((s, fetch::find_entry(&entries, cstr(&st.name), None)?))
        });
        let (s, entry) = match newest {
            Ok(found) => found,
            Err(err) if err == -ENOENT => continue,
            Err(err) => {
                ret = Err(err);
                break;
            }
        };
        if semver_compare(cstr(&entry.version), cstr(&st.version)) <= 0 {
            continue;
        }
        if let Err(err) = package_install(&s, &entry, Some(cstr(&st.version))) {
            ret = Err(err);
            break;
        }
        set(&mut st.version, cstr(&entry.version));
        match package_path(cstr(&st.name), cstr(&entry.version)) {
            Ok(dir) => set(&mut st.path, &dir),
            Err(err) => {
                ret = Err(err);
                break;
            }
        }
    }
    let written = status(bpm_state::write(&state));
    match ret {
        Err(_) => finish(Some(held), ret, b"upgrade"),
        Ok(()) => finish(Some(held), written, b"write state"),
    }
}

/// `s` left-justified in `width` bytes, as printf's "%-*s".
fn padded(s: &[u8], width: usize) -> Vec<u8> {
    let mut out = s.to_vec();

    out.resize(width.max(s.len()), b' ');
    out
}

/// `shirudo bpm list [--json]`.
pub(super) fn list(json: bool) -> c_int {
    let state = match bpm_state::read_all() {
        Ok(state) => state,
        Err(err) => return fail(b"list", err),
    };
    if json {
        let mut buf = vec![0u8; 256 + state.len() * 3 * MAX_NAME];
        let mut e = JsonEmit::fixed(&mut buf);

        e.obj_open();
        e.kv_int(b"schema", 1);
        e.arr_open(b"packages");
        for st in &state {
            e.obj_open();
            e.kv_string(b"name", cstr(&st.name));
            e.kv_string(b"version", cstr(&st.version));
            e.kv_string(b"source", cstr(&st.source));
            e.obj_close();
        }
        e.arr_close();
        e.obj_close();
        if e.err() != 0 {
            return fail(b"list", e.err());
        }
        print(&[e.output(), b"\n"].concat());
        return 0;
    }
    let width = name_column_width(state.iter().map(|st| cstr(&st.name)));
    print(b"Installed packages:\n");
    if state.is_empty() {
        print(b"  none\n");
    } else {
        print(
            &[
                b"  ",
                &padded(b"NAME", width)[..],
                b"  ",
                &padded(b"VERSION", 12),
                b"  SOURCE\n",
            ]
            .concat(),
        );
    }
    for st in &state {
        print(
            &[
                b"  ",
                &padded(cstr(&st.name), width)[..],
                b"  ",
                &padded(cstr(&st.version), 12),
                b"  ",
                cstr(&st.source),
                b"\n",
            ]
            .concat(),
        );
    }
    0
}

/// `shirudo bpm uninstall <package>`.
pub(super) fn uninstall(name: &[u8]) -> c_int {
    if !name_ok(name) {
        return fail(b"uninstall", -EINVAL);
    }
    let ret = needs_enforcement(b"uninstall");
    if ret != 0 {
        return ret;
    }
    let held = match lock() {
        Ok(held) => held,
        Err(err) => return finish(None, Err(err), b"lock"),
    };
    let ret = bpm_state::read_all().and_then(|mut state| {
        let i = state
            .iter()
            .position(|st| cstr(&st.name) == name)
            .ok_or(-ENOENT)?;
        package_uninstall(&state[i])?;
        state.remove(i);
        status(bpm_state::write(&state))
    });
    finish(Some(held), ret, b"uninstall")
}
