// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Install one package using directories opened below this boot's state
//! root. The archive that is checked is the one extracted and installed.

use core::ffi::CStr;
use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use super::{PACKAGES_DIR, Result, STAGING_DIR, cleanup, key, path, strerr, warn};
use crate::errno::{E2BIG, EINVAL, EIO, ENODEV, ENOENT};
use crate::sys::libc::{
    AT_SYMLINK_NOFOLLOW, O_CREAT, O_DIRECTORY, O_NONBLOCK, O_RDONLY, O_RDWR, O_TRUNC, S_IFMT,
    S_IFREG, renameat, unlinkat,
};
use crate::text::cstr;
use crate::util::bpm_oci::{name_ok, version_ok};
use crate::util::bpm_package::{UpatchMember, extract_fd, upatch_member, upatch_pair};
use crate::util::{identity, io, seal};

const MAX_UPATCHES: usize = 128;

/// The directories and archive held for one install. Drop closes them
/// after finish has kept or removed what the install staged.
pub(super) struct Install {
    name: CString,
    version: CString,
    package: OwnedFd,
    staging: OwnedFd,
    archive: OwnedFd,
    archive_name: CString,
    dir: Option<OwnedFd>,
}

fn bpm_dir(root: BorrowedFd<'_>, name: &CStr) -> Result<OwnedFd> {
    let bpm = seal::mkdir_child(root, c"bpm", 0o700, false)?;
    seal::mkdir_child(bpm.as_fd(), name, 0o700, false)
}

impl Install {
    /// Open this boot's package directory and a staged archive. The
    /// version is created only after its digest is checked.
    pub(super) fn open(name: &[u8], version: &[u8]) -> Result<Self> {
        let root = identity::state_root_open()
            .map_err(|err| if err == -ENOENT { -ENODEV } else { err })?;
        Self::open_at(root.as_fd(), name, version)
    }

    /// The same open below a state root supplied by the caller.
    fn open_at(root: BorrowedFd<'_>, name: &[u8], version: &[u8]) -> Result<Self> {
        if !name_ok(name) || !version_ok(version) {
            return Err(-EINVAL);
        }
        let name = CString::new(name).map_err(|_| -EINVAL)?;
        let version = CString::new(version).map_err(|_| -EINVAL)?;
        let archive_name = path(&[name.to_bytes(), b"-", version.to_bytes(), b".bee"])?;
        let store = bpm_dir(root, c"packages")?;
        let package = seal::mkdir_child(store.as_fd(), &name, 0o700, false)?;
        let staging = bpm_dir(root.as_fd(), c"staging")?;
        let archive = seal::create_child(
            staging.as_fd(),
            &archive_name,
            O_RDWR | O_CREAT | O_TRUNC,
            0o600,
        )?;
        Ok(Self {
            name,
            version,
            package,
            staging,
            archive,
            archive_name,
            dir: None,
        })
    }

    pub(super) fn archive(&self) -> BorrowedFd<'_> {
        self.archive.as_fd()
    }

    /// Extract a checked archive into a new version directory.
    pub(super) fn extract(&mut self) -> Result {
        let dir = seal::mkdir_child(self.package.as_fd(), &self.version, 0o700, true)?;
        let ret = extract_fd(self.archive.as_fd(), dir.as_fd());
        self.dir = Some(dir);
        if ret == 0 { Ok(()) } else { Err(ret) }
    }

    pub(super) fn cert_matches_active(&self) -> Result<bool> {
        let dir = self.dir.as_ref().ok_or(-EINVAL)?;
        let fd = seal::open_child(dir.as_fd(), c"cert.der", O_RDONLY | O_NONBLOCK)?;
        Ok(key::fd_matches_active(fd.as_fd()))
    }

    /// Every certificate failure rejects the package as an untrusted key.
    pub(super) fn check_cert(&self) -> Result {
        if self.cert_matches_active().unwrap_or(false) {
            Ok(())
        } else {
            Err(-crate::errno::EKEYREJECTED)
        }
    }

    /// Unload the old version in reverse name order, then load the new
    /// one in name order. On failure undo the changes made in this call.
    pub(super) fn load(&self, old_version: Option<&[u8]>) -> Result {
        self.load_with(old_version, &mut |path, fd, load| {
            if load {
                crate::builtin::upatch::install_fd(path, fd)
            } else {
                crate::builtin::upatch::remove_fd(path, fd)
            }
        })
    }

    /// The callback is the upatch loader. Tests supply one that records
    /// which opened file was handed to it.
    fn load_with<F>(&self, old_version: Option<&[u8]>, apply: &mut F) -> Result
    where
        F: FnMut(&CStr, BorrowedFd<'_>, bool) -> i32,
    {
        let version = self.dir.as_ref().ok_or(-EINVAL)?;
        let new_dir = seal::open_child(version.as_fd(), c"upatches", O_RDONLY | O_DIRECTORY)?;
        let loads = members(new_dir.as_fd(), UpatchMember::Load)?;
        if loads.is_empty() {
            return Err(-EINVAL);
        }
        let old_dir = self.old_upatches(old_version)?;
        let unloads = match old_dir.as_ref() {
            Some(dir) => members(dir.as_fd(), UpatchMember::Unload)?,
            None => Vec::new(),
        };
        let mut removed = Vec::new();
        if let (Some(dir), Some(version)) = (old_dir.as_ref(), old_version) {
            for name in unloads.iter().rev() {
                if let Err(err) = self.member_apply(dir.as_fd(), version, name, false, apply) {
                    self.restore_old(old_dir.as_ref(), old_version, &removed, apply);
                    return Err(err);
                }
                removed.push(name.as_slice());
            }
        }
        for (active, name) in loads.iter().enumerate() {
            if let Err(err) =
                self.member_apply(new_dir.as_fd(), self.version.to_bytes(), name, true, apply)
            {
                for loaded in loads[..active].iter().rev() {
                    self.pair_apply(
                        new_dir.as_fd(),
                        self.version.to_bytes(),
                        loaded,
                        false,
                        apply,
                    )
                    .ok();
                }
                self.restore_old(old_dir.as_ref(), old_version, &removed, apply);
                return Err(err);
            }
        }
        Ok(())
    }

    fn old_upatches(&self, old_version: Option<&[u8]>) -> Result<Option<OwnedFd>> {
        let Some(old_version) = old_version.filter(|version| !version.is_empty()) else {
            return Ok(None);
        };
        let old_version = CString::new(old_version).map_err(|_| -EINVAL)?;
        let version =
            match seal::open_child(self.package.as_fd(), &old_version, O_RDONLY | O_DIRECTORY) {
                Ok(version) => version,
                Err(err) if err == -ENOENT => return Ok(None),
                Err(err) => return Err(err),
            };
        match seal::open_child(version.as_fd(), c"upatches", O_RDONLY | O_DIRECTORY) {
            Ok(dir) => Ok(Some(dir)),
            Err(err) if err == -ENOENT => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn restore_old<F>(
        &self,
        old_dir: Option<&OwnedFd>,
        old_version: Option<&[u8]>,
        removed: &[&[u8]],
        apply: &mut F,
    ) where
        F: FnMut(&CStr, BorrowedFd<'_>, bool) -> i32,
    {
        let (Some(dir), Some(version)) = (old_dir, old_version) else {
            return;
        };
        for name in removed.iter().rev() {
            self.pair_apply(dir.as_fd(), version, name, true, apply)
                .ok();
        }
    }

    fn member_apply<F>(
        &self,
        dir: BorrowedFd<'_>,
        version: &[u8],
        name: &[u8],
        load: bool,
        apply: &mut F,
    ) -> Result
    where
        F: FnMut(&CStr, BorrowedFd<'_>, bool) -> i32,
    {
        let path = path(&[
            PACKAGES_DIR.as_bytes(),
            b"/",
            self.name.to_bytes(),
            b"/",
            version,
            b"/upatches/",
            name,
        ])?;
        let name = CString::new(name).map_err(|_| -EINVAL)?;
        let fd = seal::open_child(dir, &name, O_RDONLY | O_NONBLOCK)?;
        let st = io::stat_fd(fd.as_fd())?;
        if st.stx_mode & S_IFMT != S_IFREG {
            return Err(-EINVAL);
        }
        let ret = apply(&path, fd.as_fd(), load);
        if ret == 0 { Ok(()) } else { Err(-EIO) }
    }

    fn pair_apply<F>(
        &self,
        dir: BorrowedFd<'_>,
        version: &[u8],
        name: &[u8],
        load: bool,
        apply: &mut F,
    ) -> Result
    where
        F: FnMut(&CStr, BorrowedFd<'_>, bool) -> i32,
    {
        let mut pair = [0u8; 256];
        if upatch_pair(name, &mut pair) != 0 {
            return Err(-EINVAL);
        }
        self.member_apply(dir, version, cstr(&pair), load, apply)
    }

    /// End the install. A successful rename keeps the archive beside
    /// the version. A failed install removes its archive and version.
    pub(super) fn finish(self, result: Result) -> Result {
        if result.is_ok() {
            // SAFETY: both opened directories and a NUL-terminated child name.
            let ret = unsafe {
                renameat(
                    self.staging.as_raw_fd(),
                    self.archive_name.as_ptr(),
                    self.package.as_raw_fd(),
                    self.archive_name.as_ptr(),
                )
            };
            if ret != 0 {
                warn(&[
                    b"bpm: cannot keep ",
                    STAGING_DIR.as_bytes(),
                    b"/",
                    self.archive_name.to_bytes(),
                    b"; dropping it",
                ]);
                self.remove_archive();
            }
        } else {
            self.remove_archive();
            if self.dir.is_some() {
                let ret = cleanup::remove_partial_version_at(self.package.as_fd(), &self.version);
                if let Err(err) = ret
                    && err != -ENOENT
                {
                    warn(&[
                        b"bpm install: could not clean up ",
                        PACKAGES_DIR.as_bytes(),
                        b"/",
                        self.name.to_bytes(),
                        b"/",
                        self.version.to_bytes(),
                        b": ",
                        strerr(-err),
                    ]);
                }
            }
        }
        result
    }

    fn remove_archive(&self) {
        // SAFETY: the opened staging directory and a NUL-terminated name.
        unsafe { unlinkat(self.staging.as_raw_fd(), self.archive_name.as_ptr(), 0) };
    }
}

/// Names of one kind of upatch in the opened directory, sorted as in
/// the C locale. A load must be a regular file.
fn members(dir: BorrowedFd<'_>, kind: UpatchMember) -> Result<Vec<Vec<u8>>> {
    let mut names = Vec::new();
    for bytes in io::dir_names_at(dir, |_| true)? {
        if upatch_member(&bytes) != kind {
            continue;
        }
        if kind == UpatchMember::Load && !regular_at(dir, &bytes) {
            continue;
        }
        if names.len() == MAX_UPATCHES {
            return Err(-E2BIG);
        }
        names.push(bytes);
    }
    Ok(names)
}

fn regular_at(dir: BorrowedFd<'_>, name: &[u8]) -> bool {
    let Ok(name) = CString::new(name) else {
        return false;
    };
    let mut st = core::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: an opened directory, a NUL-terminated name and room for stat.
    let ret = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            st.as_mut_ptr(),
            AT_SYMLINK_NOFOLLOW,
        )
    };
    if ret != 0 {
        return false;
    }
    // SAFETY: fstatat filled st when it returned zero.
    let st = unsafe { st.assume_init() };
    st.st_mode & libc::S_IFMT == libc::S_IFREG
}

#[cfg(test)]
mod tests;
