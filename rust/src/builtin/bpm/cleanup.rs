// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Remove package files beneath the state directory init recorded at boot.
//! Every traversal holds a directory open and stays on its mount.

use core::ffi::{CStr, c_int};
use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use super::{Result, error, path};
use crate::errno::{E2BIG, EINVAL, EIO, ENAMETOOLONG, ENODATA, ENODEV, ENOENT, ENOTDIR};
use crate::sys::libc::{
    AT_REMOVEDIR, O_DIRECTORY, O_NONBLOCK, O_RDONLY, S_IFMT, S_IFREG, errno, unlinkat,
};
use crate::text::cstr;
use crate::util::bpm_oci::{name_ok, version_ok};
use crate::util::bpm_package::{UpatchMember, upatch_member, upatch_pair};
use crate::util::bpm_state::BpmStateEntry;
use crate::util::{identity, io, seal};

const MAX_DEPTH: u32 = 256;
const MAX_UPATCHES: usize = 128;

fn child_name(name: &[u8]) -> Result<CString> {
    CString::new(name).map_err(|_| -EINVAL)
}

fn unlink(parent: BorrowedFd<'_>, name: &CStr, flags: c_int) -> Result {
    // SAFETY: an open directory and a NUL-terminated child name.
    if unsafe { unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) } != 0 {
        return Err(-errno());
    }
    Ok(())
}

fn remove_entry(parent: BorrowedFd<'_>, name: &CStr, depth: u32) -> Result {
    if depth > MAX_DEPTH {
        return Err(-ENAMETOOLONG);
    }
    match seal::open_child(parent, name, O_RDONLY | O_DIRECTORY) {
        Ok(dir) => remove_dir(parent, name, dir, depth),
        Err(err) if err == -ENOTDIR && depth > 0 => unlink(parent, name, 0),
        Err(err) => Err(err),
    }
}

fn empty_dir(dir: BorrowedFd<'_>, depth: u32, directives: bool) -> Result {
    let names = io::dir_names_at(dir, |_| true)?;
    for bytes in names {
        if (upatch_member(&bytes) == UpatchMember::Unload) != directives {
            continue;
        }
        let name = child_name(&bytes)?;
        match remove_entry(dir, &name, depth + 1) {
            Err(err) if err == -ENOENT => {}
            ret => ret?,
        }
    }
    Ok(())
}

fn remove_dir(parent: BorrowedFd<'_>, name: &CStr, dir: OwnedFd, depth: u32) -> Result {
    empty_dir(dir.as_fd(), depth, false)?;
    // Keep unload directives until all load members have gone. A retry
    // can then still detach a load if removal stopped partway through.
    empty_dir(dir.as_fd(), depth, true)?;
    unlink(parent, name, AT_REMOVEDIR)
}

pub(super) fn remove_partial_version(name: &[u8], version: &[u8]) -> Result {
    let store = package_store_open()?;
    let package = seal::open_child(store.as_fd(), &child_name(name)?, O_RDONLY | O_DIRECTORY)?;
    remove_entry(package.as_fd(), &child_name(version)?, 0)
}

fn package_store_open() -> Result<OwnedFd> {
    // Missing init pins are not a missing package or version.
    let state =
        identity::state_root_open().map_err(|err| if err == -ENOENT { -ENODEV } else { err })?;
    let bpm = seal::open_child(state.as_fd(), c"bpm", O_RDONLY | O_DIRECTORY)?;
    seal::open_child(bpm.as_fd(), c"packages", O_RDONLY | O_DIRECTORY)
}

// A package ships each load member with the directive that undoes it.
fn check_load_directive(dir: BorrowedFd<'_>, name: &CStr) -> Result {
    let mut pair = [0u8; 256];
    let ret = upatch_pair(name.to_bytes(), &mut pair);
    if ret != 0 {
        return Err(ret);
    }
    let pair = child_name(cstr(&pair))?;
    match seal::open_child(dir, &pair, O_RDONLY | O_NONBLOCK) {
        Ok(_) => Ok(()),
        Err(err) if err == -ENOENT => {
            error(&[
                b"bpm uninstall: ",
                name.to_bytes(),
                b" is missing ",
                pair.to_bytes(),
            ]);
            Err(-ENODATA)
        }
        Err(err) => Err(err),
    }
}

struct Directive {
    path: CString,
    file: OwnedFd,
}

fn open_directives(dir: BorrowedFd<'_>, version_path: &[u8]) -> Result<Vec<Directive>> {
    let mut unloads = Vec::new();
    for bytes in io::dir_names_at(dir, |_| true)? {
        let kind = upatch_member(&bytes);
        if kind == UpatchMember::Other {
            continue;
        }
        let name = child_name(&bytes)?;
        if kind == UpatchMember::Load {
            check_load_directive(dir, &name)?;
            continue;
        }
        if unloads.len() == MAX_UPATCHES {
            return Err(-E2BIG);
        }
        let member_path = path(&[version_path, b"/upatches/", &bytes])?;
        let file = seal::open_child(dir, &name, O_RDONLY | O_NONBLOCK)?;
        let st = io::stat_fd(file.as_fd())?;
        if st.stx_mode & S_IFMT != S_IFREG {
            return Err(-EINVAL);
        }
        unloads.push(Directive {
            path: member_path,
            file,
        });
    }
    unloads.sort_by(|a, b| b.path.cmp(&a.path));
    Ok(unloads)
}

fn unload_version(
    version: BorrowedFd<'_>,
    version_path: &[u8],
    remove: &impl Fn(&CStr, BorrowedFd<'_>) -> c_int,
) -> Result {
    let dir = match seal::open_child(version, c"upatches", O_RDONLY | O_DIRECTORY) {
        Ok(dir) => dir,
        Err(err) if err == -ENOENT => return Ok(()),
        Err(err) => return Err(err),
    };
    let unloads = open_directives(dir.as_fd(), version_path)?;
    for directive in &unloads {
        if remove(&directive.path, directive.file.as_fd()) != 0 {
            error(&[
                b"bpm uninstall: unload ",
                directive.path.to_bytes(),
                b" failed",
            ]);
            return Err(-EIO);
        }
    }
    Ok(())
}

/// Detach the current version, then remove every version of this package.
pub(super) fn uninstall(st: &BpmStateEntry) -> Result {
    let store = package_store_open()?;
    uninstall_at(store.as_fd(), st, &crate::builtin::upatch::remove_fd)
}

fn uninstall_at(
    store: BorrowedFd<'_>,
    st: &BpmStateEntry,
    remove: &impl Fn(&CStr, BorrowedFd<'_>) -> c_int,
) -> Result {
    let name = cstr(&st.name);
    let version = cstr(&st.version);
    if !name_ok(name) || !version_ok(version) {
        return Err(-EINVAL);
    }
    let package_name = child_name(name)?;
    let package = match seal::open_child(store, &package_name, O_RDONLY | O_DIRECTORY) {
        Ok(package) => package,
        Err(err) if err == -ENOENT => return Ok(()),
        Err(err) => return Err(err),
    };
    match seal::open_child(
        package.as_fd(),
        &child_name(version)?,
        O_RDONLY | O_DIRECTORY,
    ) {
        Ok(current) => unload_version(current.as_fd(), cstr(&st.path), remove)?,
        Err(err) if err == -ENOENT => {}
        Err(err) => return Err(err),
    }
    remove_dir(store, &package_name, package, 0)
}

#[cfg(test)]
mod tests;
