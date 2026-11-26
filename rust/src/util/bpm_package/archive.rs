// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Reading a `.bee`, a gzip'd ustar archive of one top-level directory:
//! one member, the names of all, or all of it unpacked.

use core::ffi::{CStr, c_char, c_int};
use std::ffi::CString;
use std::io::Write;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;

use super::tar::{
    BLOCK, NAME, PREFIX, SIZE, TYPEFLAG, archive_rel_ok, header_ok, octal, package_member_name_ok,
    padding,
};
use crate::errno::{E2BIG, EFBIG, EINVAL, EIO, ENOENT, ENOMEM, EPERM};
use crate::sys::libc::{O_CREAT, O_EXCL, O_WRONLY, errno};
use crate::text::{at, cstr};
use crate::util::bpm_oci::{MAX_PACKAGE_BYTES, MAX_PACKAGE_ENTRIES};
use crate::util::gzip::{GzRead, Z_OK};
use crate::util::seal;

/// The most a read asks zlib for at once.
const CHUNK: usize = 65536;

/// The room for the top-level directory's name.
const ROOT_MAX: usize = 256;

/// What a member walk calls with each package-relative name and its
/// type: 0 to go on, anything else to stop the walk with it.
pub(super) type Visit<'a> = &'a mut dyn FnMut(&CStr, c_char) -> c_int;

/// A gzip file open for reading, as zlib's gzopen() opens it.
struct Gz(GzRead);

impl Gz {
    /// `path` opened; None, with errno set, when it cannot be.
    fn open(path: &CStr) -> Option<Gz> {
        match GzRead::open(std::path::Path::new(std::ffi::OsStr::from_bytes(
            path.to_bytes(),
        ))) {
            Ok(gz) => Some(Gz(gz)),
            Err(err) => {
                crate::sys::libc::set_errno(err);
                None
            }
        }
    }

    /// The stream from the start of `fd`, on a descriptor of its own;
    /// None, with errno set, when it cannot be.
    fn open_fd(fd: std::os::fd::BorrowedFd<'_>) -> Option<Gz> {
        use std::os::fd::AsRawFd;

        // SAFETY: the caller's descriptor.
        if unsafe { crate::sys::libc::lseek(fd.as_raw_fd(), 0, crate::sys::libc::SEEK_SET) } < 0 {
            return None;
        }
        match fd.try_clone_to_owned() {
            Ok(copy) => Some(Gz(GzRead::from_file(std::fs::File::from(copy)))),
            Err(e) => {
                crate::sys::libc::set_errno(e.raw_os_error().unwrap_or(EIO));
                None
            }
        }
    }

    /// Whether the file is read as it is, it not being gzip.
    fn direct(&mut self) -> bool {
        self.0.direct()
    }

    /// Up to `buf.len()` bytes, at most `CHUNK`: how many, 0 at the end,
    /// below 0 on an error.
    fn read(&mut self, buf: &mut [u8]) -> c_int {
        debug_assert!(buf.len() <= CHUNK);
        self.0.read(buf)
    }

    /// Z_OK, or what went wrong reading the file, its trailer included.
    fn close(self) -> c_int {
        self.0.close()
    }
}

/// `n` bytes read and dropped in pieces of `buf`; false when the archive
/// ends or fails first.
fn skip(gz: &mut Gz, mut n: u64, buf: &mut [u8]) -> bool {
    while n != 0 {
        let want = n.min(buf.len() as u64) as usize;
        let got = gz.read(&mut buf[..want]);

        if got <= 0 {
            return false;
        }
        n -= got as u64;
    }
    true
}

/// The next header, None at the end: the end of the file or a zero block.
fn next_header(gz: &mut Gz, h: &mut [u8; BLOCK]) -> Result<Option<()>, c_int> {
    let n = gz.read(h);

    if n == 0 {
        return Ok(None);
    }
    if n != BLOCK as c_int {
        return Err(-EINVAL);
    }
    if h.iter().all(|&c| c == 0) {
        return Ok(None);
    }
    Ok(Some(()))
}

/// The name a header holds, which must end within its field.
fn header_name(h: &[u8; BLOCK]) -> Option<&[u8]> {
    h[NAME].contains(&0).then(|| cstr(&h[NAME]))
}

/// What `read_member_in()` fills on success.
pub(super) struct Found<'a> {
    pub out: &'a mut Option<Vec<u8>>,
    pub dir: Option<&'a mut [u8]>,
}

/// One member of a gzip'd ustar `.bee` into an owned buffer.
/// `member` is relative to the single top-level
/// package directory; `package_dir` pins that directory when known, the
/// found directory reports it otherwise.
pub(super) fn read_member_in(
    archive: &CStr,
    member: Option<&[u8]>,
    package_dir: Option<&[u8]>,
    found: &mut Found<'_>,
    max: usize,
) -> c_int {
    read_member_gz(Gz::open(archive), member, package_dir, found, max)
}

/// [`read_member_in`] of the archive from the start of `fd`, which it
/// leaves open.
pub(super) fn read_member_fd(
    fd: std::os::fd::BorrowedFd<'_>,
    member: Option<&[u8]>,
    package_dir: Option<&[u8]>,
    found: &mut Found<'_>,
    max: usize,
) -> c_int {
    read_member_gz(Gz::open_fd(fd), member, package_dir, found, max)
}

/// Takes `gz` over, and its open's errno when it is None.
fn read_member_gz(
    gz: Option<Gz>,
    member: Option<&[u8]>,
    package_dir: Option<&[u8]>,
    found: &mut Found<'_>,
    max: usize,
) -> c_int {
    let Some(mut gz) = gz else {
        return -errno();
    };
    if gz.direct() {
        gz.close();
        return -EINVAL;
    }
    let ret = find_member(&mut gz, member, package_dir, found, max);

    if gz.close() != Z_OK && ret == 0 {
        *found.out = None;
        return -EINVAL;
    }
    ret
}

fn find_member(
    gz: &mut Gz,
    member: Option<&[u8]>,
    package_dir: Option<&[u8]>,
    found: &mut Found<'_>,
    max: usize,
) -> c_int {
    let mut h = [0u8; BLOCK];
    let mut discard = [0u8; CHUNK];

    loop {
        match next_header(gz, &mut h) {
            Ok(Some(())) => {}
            Ok(None) => return -ENOENT,
            Err(e) => return e,
        }
        let Some(name) = header_name(&h).filter(|_| header_ok(&h)) else {
            return -EINVAL;
        };
        let Ok(size) = octal(&h[SIZE]) else {
            return -EINVAL;
        };
        if package_member_name_ok(name, member) {
            let dir_len = name.iter().position(|&c| c == b'/').unwrap_or(0);

            if package_dir.is_none_or(|d| &name[..dir_len] == d) {
                return take_member(gz, &h, &name[..dir_len], size, found, max);
            }
        }
        if !skip(gz, size, &mut discard) || !skip(gz, padding(size), &mut discard) {
            return -EINVAL;
        }
    }
}

/// The data of the member `h` heads, of the package directory `dir`.
fn take_member(
    gz: &mut Gz,
    h: &[u8; BLOCK],
    dir: &[u8],
    size: u64,
    found: &mut Found<'_>,
    max: usize,
) -> c_int {
    if (h[TYPEFLAG] != 0 && h[TYPEFLAG] != b'0')
        || h[PREFIX] != 0
        || found.dir.as_ref().is_some_and(|d| dir.len() >= d.len())
    {
        return -EINVAL;
    }
    if size > max as u64 {
        return -E2BIG;
    }
    let Some(alloc) = size.checked_add(1).and_then(|a| usize::try_from(a).ok()) else {
        return -E2BIG;
    };
    let size = alloc - 1;
    let mut body = Vec::new();
    if body.try_reserve_exact(alloc).is_err() {
        return -ENOMEM;
    }
    body.resize(alloc, 0);
    let mut done = 0;

    while done < size {
        let want = (size - done).min(CHUNK);
        let n = gz.read(&mut body[done..done + want]);

        if n <= 0 {
            return -EINVAL;
        }
        done += n as usize;
    }
    *found.out = Some(body);
    if let Some(d) = found.dir.as_deref_mut() {
        d[..dir.len()].copy_from_slice(dir);
        d[dir.len()] = 0;
    }
    0
}

/// [`visit_members`] of the archive from the start of `fd`, which it
/// leaves open.
pub(super) fn visit_members_fd(
    fd: std::os::fd::BorrowedFd<'_>,
    package_dir: Option<&[u8]>,
    visit: Option<Visit<'_>>,
) -> c_int {
    visit_members_gz(Gz::open_fd(fd), package_dir, visit)
}

/// Takes `gz` over, and its open's errno when it is None.
fn visit_members_gz(gz: Option<Gz>, package_dir: Option<&[u8]>, visit: Option<Visit<'_>>) -> c_int {
    let Some(mut gz) = gz else {
        return -errno();
    };
    if gz.direct() {
        gz.close();
        return -EINVAL;
    }
    let ret = walk_members(&mut gz, package_dir, visit);

    if gz.close() != Z_OK && ret == 0 {
        return -EINVAL;
    }
    ret
}

fn walk_members(gz: &mut Gz, package_dir: Option<&[u8]>, mut visit: Option<Visit<'_>>) -> c_int {
    let mut h = [0u8; BLOCK];
    let mut discard = [0u8; CHUNK];
    let mut root = [0u8; ROOT_MAX];
    let mut root_len = 0;
    let mut rel = [0u8; NAME.end + 1];

    let ret = loop {
        match next_header(gz, &mut h) {
            Ok(Some(())) => {}
            Ok(None) => break 0,
            Err(e) => break e,
        }
        let Some(mut name) = header_name(&h).filter(|_| header_ok(&h) && h[PREFIX] == 0) else {
            break -EINVAL;
        };
        let Ok(size) = octal(&h[SIZE]) else {
            break -EINVAL;
        };
        let ty = if h[TYPEFLAG] != 0 { h[TYPEFLAG] } else { b'0' };
        if ty == b'5' && name.last() == Some(&b'/') {
            name = &name[..name.len() - 1];
        }
        if !archive_rel_ok(name) {
            break -EINVAL;
        }
        if root_len == 0 {
            let slash = name.iter().position(|&c| c == b'/');
            let len = slash.unwrap_or(name.len());

            if (slash.is_none() && ty != b'5') || slash == Some(0) || len >= ROOT_MAX {
                break -EINVAL;
            }
            root[..len].copy_from_slice(&name[..len]);
            root_len = len;
        }
        let root = &root[..root_len];
        if !name.starts_with(root) || !matches!(at(name, root_len), 0 | b'/') {
            break -EINVAL;
        }
        if package_dir.is_some_and(|d| d != root) {
            break -EINVAL;
        }
        if ty != b'0' && ty != b'5' {
            break -EPERM;
        }
        let r = &name[root_len + usize::from(at(name, root_len) == b'/')..];
        if r.is_empty() {
            if ty != b'5' {
                break -EINVAL;
            }
        } else if !archive_rel_ok(r) {
            break -EINVAL;
        } else if let Some(visit) = visit.as_mut() {
            rel[..r.len()].copy_from_slice(r);
            rel[r.len()] = 0;
            let Ok(r) = CStr::from_bytes_until_nul(&rel) else {
                break -EINVAL;
            };
            let ret = visit(r, ty as c_char);
            if ret != 0 {
                break ret;
            }
        }
        if !skip(gz, size, &mut discard) || !skip(gz, padding(size), &mut discard) {
            return -EINVAL;
        }
    };
    if root_len == 0 { -EINVAL } else { ret }
}

/// Unpack the regular files and directories under one top-level directory
/// from the archive already open as `archive` into the opened `dest`.
pub(super) fn extract_fd(archive: BorrowedFd<'_>, dest: BorrowedFd<'_>) -> c_int {
    let Some(mut gz) = Gz::open_fd(archive) else {
        return -EINVAL;
    };
    let (ret, rooted) = unpack(&mut gz, dest);
    if gz.close() != Z_OK && ret == 0 {
        return -EINVAL;
    }
    if ret != 0 {
        return ret;
    }
    if rooted { 0 } else { -EINVAL }
}

/// Make each directory in `rel` below an opened directory, without
/// following a mount or a link placed in the way.
fn extract_dir(dest: BorrowedFd<'_>, rel: &[u8]) -> Result<OwnedFd, c_int> {
    let mut dir = dest
        .try_clone_to_owned()
        .map_err(|e| crate::util::io::errno_of(&e))?;
    for comp in rel.split(|&b| b == b'/').filter(|comp| !comp.is_empty()) {
        let name = CString::new(comp).map_err(|_| -EINVAL)?;
        dir = seal::mkdir_child(dir.as_fd(), &name, 0o700, false)?;
    }
    Ok(dir)
}

/// The members of `gz` under `dest`, and whether there was a top-level
/// directory.
fn unpack(gz: &mut Gz, dest: BorrowedFd<'_>) -> (c_int, bool) {
    let mut h = [0u8; BLOCK];
    let mut buf = [0u8; CHUNK];
    let mut root = [0u8; ROOT_MAX];
    let mut root_len = 0;
    let mut total = 0u64;
    let mut entries = 0u32;

    let ret = loop {
        match next_header(gz, &mut h) {
            Ok(Some(())) => {}
            Ok(None) => break 0,
            Err(e) => break e,
        }
        // A ustar prefix would make the member another reader's
        // prefix/name.
        let Some(name) = header_name(&h).filter(|_| header_ok(&h) && h[PREFIX] == 0) else {
            break -EINVAL;
        };
        if !archive_rel_ok(name) {
            break -EINVAL;
        }
        let Ok(size) = octal(&h[SIZE]) else {
            break -EINVAL;
        };
        let ty = if h[TYPEFLAG] != 0 { h[TYPEFLAG] } else { b'0' };
        entries += 1;
        if entries > MAX_PACKAGE_ENTRIES || size > MAX_PACKAGE_BYTES - total {
            break -EFBIG;
        }
        total += size;
        if root_len == 0 {
            match name.iter().position(|&c| c == b'/') {
                Some(slash) if slash != 0 && slash < ROOT_MAX => {
                    root[..slash].copy_from_slice(&name[..slash]);
                    root_len = slash;
                }
                _ => break -EINVAL,
            }
        }
        if !name.starts_with(&root[..root_len]) || at(name, root_len) != b'/' {
            break -EINVAL;
        }
        let rel = &name[root_len + 1..];
        if (rel.is_empty() && ty != b'5') || (!rel.is_empty() && !archive_rel_ok(rel)) {
            break -EINVAL;
        }
        let ret = match ty {
            b'5' => make_dir(gz, dest, rel, size, &mut buf),
            b'0' => write_file(gz, dest, rel, size, &mut buf),
            _ => -EPERM,
        };
        if ret != 0 {
            break ret;
        }
        if !skip(gz, padding(size), &mut buf) {
            break -EINVAL;
        }
    };
    (ret, root_len != 0)
}

/// A directory member, its data read as the other walkers do, whatever
/// the directory carries.
fn make_dir(gz: &mut Gz, dest: BorrowedFd<'_>, rel: &[u8], size: u64, buf: &mut [u8]) -> c_int {
    if let Err(ret) = extract_dir(dest, rel) {
        return ret;
    }
    if !skip(gz, size, buf) {
        return -EIO;
    }
    0
}

/// A regular member under the directories it needs.
fn write_file(gz: &mut Gz, dest: BorrowedFd<'_>, rel: &[u8], size: u64, buf: &mut [u8]) -> c_int {
    let (parent, name) = match rel.iter().rposition(|&b| b == b'/') {
        Some(slash) => (&rel[..slash], &rel[slash + 1..]),
        None => (&b""[..], rel),
    };
    let dir = match extract_dir(dest, parent) {
        Ok(dir) => dir,
        Err(err) => return err,
    };
    let name = match CString::new(name) {
        Ok(name) => name,
        Err(_) => return -EINVAL,
    };
    let mut out = match seal::create_child(dir.as_fd(), &name, O_WRONLY | O_CREAT | O_EXCL, 0o644) {
        Ok(fd) => std::fs::File::from(fd),
        Err(err) => return err,
    };
    let mut remain = size;
    while remain != 0 {
        let want = remain.min(CHUNK as u64) as usize;
        let n = gz.read(&mut buf[..want]);
        let Some(chunk) = usize::try_from(n)
            .ok()
            .filter(|&n| n != 0)
            .and_then(|n| buf.get(..n))
        else {
            return -EIO;
        };
        if out.write_all(chunk).is_err() {
            return -EIO;
        }
        remain -= chunk.len() as u64;
    }
    match out.set_permissions(std::fs::Permissions::from_mode(0o644)) {
        Ok(()) => 0,
        Err(e) => -e.raw_os_error().unwrap_or(EIO),
    }
}
