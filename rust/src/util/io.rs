// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The file helpers: whole writes and reads, the log
//! records an append keeps whole, opens beneath a directory, text lines,
//! and whether a file may steer what shirudo trusts.

use core::ffi::{CStr, c_char, c_int};

use crate::errno::{
    EFBIG, EINTR, EINVAL, EIO, EISDIR, ELOOP, ENAMETOOLONG, ENOENT, ENOTDIR, EPERM, ESTALE,
};
use crate::sys::libc::Zeroed;
use crate::sys::libc::{
    AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW, Dir, LOCK_EX, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL,
    O_NOFOLLOW, O_NONBLOCK, O_PATH, O_RDONLY, PATH_MAX, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, S_ISVTX,
    STATX_ATTR_MOUNT_ROOT, STATX_BASIC_STATS, Statfs, Statx, close, closedir, errno, fdopendir,
    flock, fstatfs, fsync, ftruncate, geteuid, open, openat, pread, readdir, readlinkat, set_errno,
    statx, syscall, write,
};
use crate::util::seal;
use core::ptr::NonNull;
use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

/// `ETC_DIR` of util/paths.h.
const ETC_DIR: &CStr = c"/etc/shirudo";
/// `VAR_LIB` of util/paths.h.
const VAR_LIB: &CStr = c"/var/lib/shirudo";
/// `BPF_FS_MAGIC` of <linux/magic.h>.
const BPF_FS_MAGIC: i64 = 0xcafe_4a11;
/// openat2(2), the same number on every architecture.
const SYS_OPENAT2: core::ffi::c_long = 437;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
/// As many links as the kernel follows on the way to one file.
const TRUSTED_LINKS_MAX: usize = 40;
/// Reopens after the first open of a trusted name.
const TRUSTED_REOPENS: usize = 3;

const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_BENEATH: u64 = 0x08;

/// `struct open_how`.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// The negative errno of `err`, or -EIO when it has no OS error.
pub(crate) fn errno_of(err: &std::io::Error) -> core::ffi::c_int {
    -err.raw_os_error().unwrap_or(EIO)
}

/// Close `fd`, returning the error instead of hiding it in Drop.
pub(crate) fn close_checked(fd: OwnedFd) -> Result<(), core::ffi::c_int> {
    // SAFETY: the descriptor, which the close takes over.
    if unsafe { close(fd.into_raw_fd()) } != 0 {
        return Err(-errno());
    }
    Ok(())
}

/// All of `buf` to `fd`, through short writes and signals: -EIO for a
/// write of nothing, or -errno.
pub(crate) fn write_complete(fd: BorrowedFd<'_>, buf: &[u8]) -> Result<(), c_int> {
    let mut rest = buf;

    while !rest.is_empty() {
        // SAFETY: the caller's fd, and the bytes left of buf.
        let n = unsafe { write(fd.as_raw_fd(), rest.as_ptr().cast(), rest.len()) };

        if n < 0 {
            if errno() == EINTR {
                continue;
            }
            return Err(-errno());
        }
        if n == 0 {
            return Err(-EIO);
        }
        rest = rest.get(n as usize..).ok_or(-EIO)?;
    }
    Ok(())
}

/// The offset after the last newline in one chunk, or 0 for none.
fn last_newline_end(chunk: &[u8]) -> usize {
    chunk.iter().rposition(|&c| c == b'\n').map_or(0, |i| i + 1)
}

/// The offset after the last newline of the `size` bytes of `fd`, read
/// back from its end a chunk at a time, or 0 for none.
fn last_line_end(fd: BorrowedFd<'_>, size: i64) -> Result<i64, c_int> {
    let mut chunk = [0u8; 4096];
    let step = chunk.len() as i64;
    let mut off = size;

    while off > 0 {
        let n = off.min(step) as usize;
        let start = off - n as i64;
        // SAFETY: the caller's fd and room for n bytes.
        let got = unsafe { pread(fd.as_raw_fd(), chunk.as_mut_ptr().cast(), n, start) };

        if got < 0 && errno() == EINTR {
            continue;
        }
        if got < 0 {
            return Err(-errno());
        }
        if got as usize != n {
            return Err(-EIO);
        }
        let end = last_newline_end(&chunk[..n]);
        if end != 0 {
            return Ok(start + end as i64);
        }
        off = start;
    }
    Ok(0)
}

/// The file open on `fd` cut to `len` bytes: -errno.
fn truncate_to(fd: BorrowedFd<'_>, len: i64) -> Result<(), c_int> {
    // SAFETY: the caller's fd.
    if unsafe { ftruncate(fd.as_raw_fd(), len) } != 0 {
        return Err(-errno());
    }
    Ok(())
}

/// fsync() of the file open on `fd`: -errno.
fn sync(fd: BorrowedFd<'_>) -> Result<(), c_int> {
    // SAFETY: the caller's fd.
    if unsafe { fsync(fd.as_raw_fd()) } != 0 {
        return Err(-errno());
    }
    Ok(())
}

/// The names of the directory at `dir` that `keep` keeps, in the order
/// alphasort() gives them in the C locale shirudo runs in: bytewise.
/// "." and ".." are no entry. -errno when the directory cannot be read.
pub(crate) fn dir_names(dir: &[u8], keep: impl Fn(&[u8]) -> bool) -> Result<Vec<Vec<u8>>, c_int> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let errno = |e: std::io::Error| -e.raw_os_error().unwrap_or(crate::errno::EIO);
    let mut names = Vec::new();
    for entry in std::fs::read_dir(std::ffi::OsStr::from_bytes(dir)).map_err(errno)? {
        let name = entry.map_err(errno)?.file_name().into_vec();
        if keep(&name) {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// [`dir_names`] of the directory open as `dir`, read through a
/// descriptor of its own, as scandirat(dir, ".") reads it.
pub(crate) fn dir_names_at(
    dir: BorrowedFd<'_>,
    keep: impl Fn(&[u8]) -> bool,
) -> Result<Vec<Vec<u8>>, c_int> {
    let mut stream = DirStream::open_at(dir)?;
    let mut names = Vec::new();

    while let Some(name) = stream.next_name()? {
        if name != b"." && name != b".." && keep(&name) {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// A directory stream, closed with its descriptor when it goes.
struct DirStream(NonNull<Dir>);

impl DirStream {
    /// A stream on the directory open as `dir`, through a descriptor of
    /// its own: -errno.
    fn open_at(dir: BorrowedFd<'_>) -> Result<Self, c_int> {
        // SAFETY: the caller's fd, a C string and flags.
        let fd = unsafe {
            openat(
                dir.as_raw_fd(),
                c".".as_ptr(),
                O_RDONLY | O_DIRECTORY | O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(-errno());
        }
        // SAFETY: the fd openat() just gave, owned from here.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: the fd, which the stream owns once fdopendir() takes it.
        let stream = NonNull::new(unsafe { fdopendir(fd.as_raw_fd()) }).ok_or_else(|| -errno())?;
        let _ = fd.into_raw_fd();
        Ok(DirStream(stream))
    }

    /// The name of the next entry, None at the end, or -errno.
    fn next_name(&mut self) -> Result<Option<Vec<u8>>, c_int> {
        // The end of the stream tells from an error by errno alone.
        set_errno(0);
        // SAFETY: the stream's own DIR.
        let entry = unsafe { readdir(self.0.as_ptr()) };
        if entry.is_null() {
            return match errno() {
                0 => Ok(None),
                err => Err(-err),
            };
        }
        // SAFETY: the entry readdir() gave, whose name is a C string,
        // copied before the stream reads on.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        Ok(Some(name.to_bytes().to_vec()))
    }
}

impl Drop for DirStream {
    fn drop(&mut self) {
        // SAFETY: the stream, closed once with its fd.
        unsafe { closedir(self.0.as_ptr()) };
    }
}

/// The status of the open `fd`, as fstat() gives it: -errno.
pub(crate) fn stat_fd(fd: BorrowedFd<'_>) -> Result<Statx, c_int> {
    let mut st = Statx::zeroed();
    let fd = fd.as_raw_fd();

    // SAFETY: the caller's fd, an empty path, and room for its status.
    if unsafe { statx(fd, c"".as_ptr(), AT_EMPTY_PATH, STATX_BASIC_STATS, &mut st) } != 0 {
        return Err(-errno());
    }
    Ok(st)
}

/// Accept one line, allowing one final newline and no embedded NUL.
fn append_text(line: &[u8]) -> Result<&[u8], c_int> {
    let text = line.strip_suffix(b"\n").unwrap_or(line);
    if text.contains(&b'\n') || text.contains(&0) {
        return Err(-EINVAL);
    }
    Ok(text)
}

/// `line` and its newline appended to the log open on `fd` at `path`,
/// after a torn tail is dropped; the log taken back to its last record
/// when the append fails.
pub(crate) fn append_line(fd: BorrowedFd<'_>, path: &CStr, line: &[u8]) -> Result<(), c_int> {
    let text = append_text(line)?;
    let size = stat_fd(fd)?.stx_size as i64;
    let end = last_line_end(fd, size)?;
    if end != size {
        truncate_to(fd, end)?;
        crate::log::warn(
            &[
                path.to_bytes(),
                b": dropped ",
                format!("{}", size - end).as_bytes(),
                b" bytes at its end, an append that did not finish",
            ]
            .concat(),
        );
    }
    let record = [text, b"\n"].concat();
    let appended = write_complete(fd, &record).and_then(|()| sync(fd));
    let Err(ret) = appended else {
        return Ok(());
    };
    if let Err(err) = truncate_to(fd, end) {
        crate::log::warn(
            &[
                path.to_bytes(),
                b": could not roll back a partial append: ",
                crate::errno::text(err).as_bytes(),
            ]
            .concat(),
        );
    }
    Err(ret)
}

/// `rel` opened beneath the directory open as `dirfd`, with `flags` and
/// close-on-exec, through no symlink, no magic link and nothing outside
/// it: -EINVAL for an empty or absolute `rel`, or -errno.
pub(crate) fn open_beneath(dirfd: c_int, rel: &CStr, flags: c_int) -> Result<OwnedFd, c_int> {
    open_resolved(dirfd, rel, flags, 0, 0)
}

/// As open_beneath, also refusing a mount or bind mount below dirfd.
pub(crate) fn open_beneath_same_mount(
    dirfd: c_int,
    rel: &CStr,
    flags: c_int,
) -> Result<OwnedFd, c_int> {
    open_resolved(dirfd, rel, flags, 0, RESOLVE_NO_XDEV)
}

/// A new file under `dirfd`, on its mount and with `mode`. The name must
/// not already exist.
pub(crate) fn create_beneath_same_mount(
    dirfd: c_int,
    rel: &CStr,
    flags: c_int,
    mode: u32,
) -> Result<OwnedFd, c_int> {
    open_resolved(dirfd, rel, flags | O_CREAT | O_EXCL, mode, RESOLVE_NO_XDEV)
}

fn open_resolved(
    dirfd: c_int,
    rel: &CStr,
    flags: c_int,
    mode: u32,
    resolve: u64,
) -> Result<OwnedFd, c_int> {
    let how = OpenHow {
        flags: flags as u64 | O_CLOEXEC as u64,
        mode: if flags & O_CREAT != 0 { mode.into() } else { 0 },
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | resolve,
    };

    if dirfd < 0 || matches!(rel.to_bytes().first(), None | Some(b'/')) {
        return Err(-EINVAL);
    }
    // SAFETY: the caller's fd and C string, and the open_how and its size.
    let fd = unsafe {
        syscall(
            SYS_OPENAT2,
            dirfd,
            rel.as_ptr(),
            &raw const how,
            size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(-errno());
    }
    // SAFETY: the fd openat2() just gave, owned from here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as c_int) })
}

/// The whole regular file behind `fd`, from its start, of at most `max`
/// bytes.
pub(crate) fn read_whole(fd: BorrowedFd<'_>, max: usize) -> Result<Vec<u8>, c_int> {
    let st = stat_fd(fd)?;

    if st.stx_mode & S_IFMT != S_IFREG {
        return Err(-EINVAL);
    }
    let size = usize::try_from(st.stx_size)
        .ok()
        .filter(|&size| size <= max)
        .ok_or(-EFBIG)?;
    let mut buf = vec![0u8; size];
    let mut done = 0usize;
    while done < size {
        // SAFETY: the caller's fd, and the room left in buf.
        let n = unsafe {
            pread(
                fd.as_raw_fd(),
                buf[done..].as_mut_ptr().cast(),
                size - done,
                done as i64,
            )
        };

        if n < 0 && errno() == EINTR {
            continue;
        }
        if n <= 0 {
            return Err(if n < 0 { -errno() } else { -EIO });
        }
        done += n as usize;
    }
    Ok(buf)
}

/// Whether `p` names something beneath the directory `dir`.
fn under_dir(p: &[u8], dir: &CStr) -> bool {
    let d = dir.to_bytes();

    p.starts_with(d) && p.get(d.len()) == Some(&b'/')
}

/// `path` opened with `flags` and close-on-exec.
fn open_path(path: &CStr, flags: c_int) -> Result<OwnedFd, c_int> {
    // SAFETY: a C string and flags without a mode.
    let fd = unsafe { open(path.as_ptr(), flags | O_CLOEXEC) };

    if fd < 0 {
        return Err(-errno());
    }
    // SAFETY: the fd open() just gave, owned from here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// A regular file for [`read`], with sealed state under /var/lib/shirudo.
fn open_regular(path: &CStr, flags: c_int) -> Result<OwnedFd, c_int> {
    let fd = if under_dir(path.to_bytes(), VAR_LIB) {
        seal::open_read(path.to_bytes())?
    } else {
        // O_NONBLOCK makes a FIFO fail the regular-file check instead of
        // waiting for a writer.
        open_path(path, flags | O_NONBLOCK)?
    };
    let st = stat_fd(fd.as_fd())?;

    if st.stx_mode & S_IFMT != S_IFREG {
        return Err(-EINVAL);
    }
    Ok(fd)
}

/// The regular file at `path`, of at most `max` bytes; one under
/// /var/lib/shirudo opened through its seal.
pub(crate) fn read(path: &CStr, max: usize) -> Result<Vec<u8>, c_int> {
    let fd = open_checked(path, O_RDONLY, trusted_dirs(), open_regular)?;

    read_whole(fd.as_fd(), max)
}

const TRUSTED_DIRS: [&CStr; 2] = [ETC_DIR, VAR_LIB];

fn trusted_dirs() -> &'static [&'static CStr] {
    &TRUSTED_DIRS
}

fn trusted_owner(uid: u32) -> bool {
    // SAFETY: a call that takes nothing.
    uid == 0 || uid == unsafe { geteuid() }
}

fn trusted_place(path: &CStr, dirs: &[&CStr]) -> bool {
    dirs.iter().any(|dir| under_dir(path.to_bytes(), dir))
}

/// What `fd` is open on, named for a message.
fn opened_path(fd: BorrowedFd<'_>) -> Vec<u8> {
    let link = format!("/proc/self/fd/{}", fd.as_raw_fd());

    std::fs::read_link(link)
        .ok()
        .map(|path| path.as_os_str().as_bytes().to_vec())
        .filter(|path| path.len() < PATH_MAX)
        .unwrap_or_else(|| b"?".to_vec())
}

struct TrustedWalk<'a> {
    path: &'a CStr,
    rest: Vec<u8>,
    dir: OwnedFd,
    links: usize,
}

impl<'a> TrustedWalk<'a> {
    fn new(path: &'a CStr) -> Result<Self, c_int> {
        if path.to_bytes().len() >= PATH_MAX {
            return Err(-ENAMETOOLONG);
        }
        Ok(Self {
            path,
            rest: path.to_bytes().to_vec(),
            dir: open_path(c"/", O_PATH | O_DIRECTORY)?,
            links: 0,
        })
    }

    fn check_dir(&self) -> Result<(), c_int> {
        let st = stat_fd(self.dir.as_fd())?;
        let mode = st.stx_mode;

        if mode & S_IFMT != S_IFDIR {
            return Err(-ENOTDIR);
        }
        let sticky_root = mode & S_ISVTX != 0 && st.stx_uid == 0;
        if trusted_owner(st.stx_uid) && (mode & 0o22 == 0 || sticky_root) {
            return Ok(());
        }
        let name = opened_path(self.dir.as_fd());
        crate::log::err(
            &[
                self.path.to_bytes(),
                b": directory ",
                &name,
                b", owner ",
                format!("{}", st.stx_uid).as_bytes(),
                b", mode ",
                format!("{:04o}", u32::from(mode & 0o7777)).as_bytes(),
                b": refusing a file another user could replace",
            ]
            .concat(),
        );
        Err(-EPERM)
    }

    fn open_name(&self, name: &[u8]) -> Result<OwnedFd, c_int> {
        let name = CString::new(name).map_err(|_| -EINVAL)?;
        // SAFETY: the checked directory, one C-string component and flags.
        let fd = unsafe {
            openat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                O_PATH | O_NOFOLLOW | O_CLOEXEC,
            )
        };

        if fd < 0 {
            return Err(-errno());
        }
        // SAFETY: openat() just returned this owned fd.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn follow_link(&mut self, link: BorrowedFd<'_>, owner: u32, left: &[u8]) -> Result<(), c_int> {
        if !trusted_owner(owner) {
            let name = opened_path(link);
            crate::log::err(
                &[
                    self.path.to_bytes(),
                    b": link ",
                    &name,
                    b", owner ",
                    format!("{owner}").as_bytes(),
                    b": refusing a file another user could replace",
                ]
                .concat(),
            );
            return Err(-EPERM);
        }
        self.links += 1;
        if self.links > TRUSTED_LINKS_MAX {
            return Err(-ELOOP);
        }
        let mut target = [0u8; PATH_MAX];
        // SAFETY: an O_PATH descriptor for the link, an empty path, and
        // the room in target.
        let n = unsafe {
            readlinkat(
                link.as_raw_fd(),
                c"".as_ptr(),
                target.as_mut_ptr().cast(),
                target.len(),
            )
        };
        if n < 0 {
            return Err(-errno());
        }
        let n = n as usize;
        if n >= target.len() {
            return Err(-ENAMETOOLONG);
        }
        let absolute = target.first() == Some(&b'/');
        let len = n
            .checked_add(1)
            .and_then(|len| len.checked_add(left.len()))
            .filter(|&len| len < PATH_MAX)
            .ok_or(-ENAMETOOLONG)?;
        let mut rest = Vec::with_capacity(len);

        rest.extend_from_slice(&target[..n]);
        rest.push(b'/');
        rest.extend_from_slice(left);
        self.rest = rest;
        if absolute {
            self.dir = open_path(c"/", O_PATH | O_DIRECTORY)?;
        }
        Ok(())
    }

    /// Resolve one name at a time through checked directory descriptors,
    /// and finish at the same inode as `file`.
    fn finish_at(mut self, file: &Statx) -> Result<(), c_int> {
        loop {
            self.check_dir()?;
            let start = self
                .rest
                .iter()
                .position(|&c| c != b'/')
                .unwrap_or(self.rest.len());
            if start == self.rest.len() {
                return Err(-EISDIR);
            }
            let end = self.rest[start..]
                .iter()
                .position(|&c| c == b'/')
                .map_or(self.rest.len(), |end| start + end);
            let name = self.rest[start..end].to_vec();
            let left = self.rest[end..].to_vec();
            let fd = self.open_name(&name)?;
            let st = stat_fd(fd.as_fd())?;

            match st.stx_mode & S_IFMT {
                S_IFDIR => {
                    self.dir = fd;
                    self.rest = left;
                }
                S_IFLNK => self.follow_link(fd.as_fd(), st.stx_uid, &left)?,
                _ => {
                    if left.iter().any(|&c| c != b'/') {
                        return Err(-ENOTDIR);
                    }
                    return if st.stx_dev_major == file.stx_dev_major
                        && st.stx_dev_minor == file.stx_dev_minor
                        && st.stx_ino == file.stx_ino
                    {
                        Ok(())
                    } else {
                        Err(-ESTALE)
                    };
                }
            }
        }
    }
}

/// Check the file by itself, whatever path led to it.
fn trusted_file(fd: BorrowedFd<'_>, path: &CStr, secret: bool) -> Result<Statx, c_int> {
    let st = stat_fd(fd)?;

    if st.stx_mode & S_IFMT == S_IFREG
        && trusted_owner(st.stx_uid)
        && st.stx_mode & if secret { 0o77 } else { 0o22 } == 0
    {
        return Ok(st);
    }
    let could: &[u8] = if secret { b"read or change" } else { b"change" };
    crate::log::err(
        &[
            path.to_bytes(),
            b": owner ",
            format!("{}", st.stx_uid).as_bytes(),
            b", mode ",
            format!("{:04o}", u32::from(st.stx_mode & 0o7777)).as_bytes(),
            b": refusing a file another user could ",
            could,
        ]
        .concat(),
    );
    Err(-EPERM)
}

/// The trusted-file check without the final stale report, so a caller can
/// absorb a rename by opening the name again.
fn trusted_check(fd: BorrowedFd<'_>, path: &CStr, dirs: &[&CStr]) -> Result<(), c_int> {
    if !trusted_place(path, dirs) {
        return Ok(());
    }
    let file = trusted_file(fd, path, false)?;

    TrustedWalk::new(path)?.finish_at(&file)
}

fn report_stale(path: &CStr) {
    crate::log::err(
        &[
            path.to_bytes(),
            b": names another file than the one opened; refusing it",
        ]
        .concat(),
    );
}

fn check_trusted_in(fd: BorrowedFd<'_>, path: &CStr, dirs: &[&CStr]) -> c_int {
    match trusted_check(fd, path, dirs) {
        Ok(()) => 0,
        Err(ret) => {
            if ret == -ESTALE {
                report_stale(path);
            }
            ret
        }
    }
}

/// Whether the file open on `fd` at `path` may steer what shirudo
/// trusts. A path outside the installed trusted directories is the
/// caller's to vouch for. 0, -EPERM or -ESTALE logged, or -errno.
pub(crate) fn check_trusted(fd: BorrowedFd<'_>, path: &CStr) -> c_int {
    check_trusted_in(fd, path, trusted_dirs())
}

/// Read an opened regular file only after checking its owner, mode and
/// path. The directory list lets tests use their own trusted tree.
pub(crate) fn read_fd_in(
    fd: BorrowedFd<'_>,
    label: &CStr,
    max: usize,
    dirs: &[&CStr],
) -> Result<Vec<u8>, c_int> {
    let st = stat_fd(fd)?;
    if st.stx_mode & S_IFMT != S_IFREG {
        return Err(-EINVAL);
    }
    let ret = check_trusted_in(fd, label, dirs);
    if ret != 0 {
        return Err(ret);
    }
    read_whole(fd, max)
}

/// Read the file held by `fd` under its trusted path `label`.
pub(crate) fn read_fd(fd: BorrowedFd<'_>, label: &CStr, max: usize) -> Result<Vec<u8>, c_int> {
    read_fd_in(fd, label, max, trusted_dirs())
}

fn check_secret_in(fd: BorrowedFd<'_>, path: &CStr, dirs: &[&CStr]) -> c_int {
    if !trusted_place(path, dirs) {
        return 0;
    }
    trusted_file(fd, path, true).map_or_else(|ret| ret, |_| 0)
}

/// Whether a trusted file may hold a secret: nobody but its owner may
/// read it. The path already passed check_trusted() and is not walked
/// again. 0 or -EPERM logged.
pub(crate) fn check_secret(fd: BorrowedFd<'_>, path: &CStr) -> c_int {
    check_secret_in(fd, path, trusted_dirs())
}

/// Open and fully check one descriptor at a time. A trusted name renamed
/// over during its check is opened again up to three times.
fn open_checked<F>(
    path: &CStr,
    flags: c_int,
    dirs: &[&CStr],
    mut opener: F,
) -> Result<OwnedFd, c_int>
where
    F: FnMut(&CStr, c_int) -> Result<OwnedFd, c_int>,
{
    for attempt in 0..=TRUSTED_REOPENS {
        let fd = opener(path, flags)?;

        match trusted_check(fd.as_fd(), path, dirs) {
            Ok(()) => return Ok(fd),
            Err(ret) if ret == -ESTALE && attempt < TRUSTED_REOPENS => {}
            Err(ret) => {
                if ret == -ESTALE {
                    report_stale(path);
                }
                return Err(ret);
            }
        }
    }
    unreachable!()
}

/// A descriptor on `path` opened with `flags` that passed the trusted
/// check, with bounded retries when a trusted writer renames over it.
pub(crate) fn open_trusted(path: &CStr, flags: c_int) -> Result<OwnedFd, c_int> {
    open_checked(path, flags, trusted_dirs(), open_path)
}

/// A st_dev or st_rdev as the kernel encodes the dev_t in s_dev.
pub(crate) fn kernel_dev(dev: u64) -> u32 {
    let major = ((dev >> 8) & 0xfff) as u32 | ((dev >> 32) as u32 & !0xfff);
    let minor = (dev & 0xff) as u32 | ((dev >> 12) as u32 & !0xff);

    major << 20 | (minor & 0xfffff)
}

/// 1 when `path` is the root of a bpf file system mount, 0 when it is
/// not or there is no such path, else -errno.
///
/// # Safety
///
/// `path` is a C string.
pub(crate) unsafe fn bpffs_mounted_at(path: *const c_char) -> c_int {
    let mut stx = Statx::zeroed();
    let mut fs = Statfs::zeroed();

    // SAFETY: the caller's C string.
    let fd = unsafe { open(path, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) };
    if fd < 0 {
        return if errno() == ENOENT { 0 } else { -errno() };
    }
    // SAFETY: the path's fd, an empty path, and room for both statuses.
    let failed = unsafe {
        fstatfs(fd, &mut fs) != 0
            || statx(
                fd,
                c"".as_ptr(),
                AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW,
                0,
                &mut stx,
            ) != 0
    };
    let ret = if failed {
        -errno()
    } else {
        c_int::from(
            fs.f_type == BPF_FS_MAGIC
                && stx.stx_attributes_mask & STATX_ATTR_MOUNT_ROOT != 0
                && stx.stx_attributes & STATX_ATTR_MOUNT_ROOT != 0,
        )
    };
    // SAFETY: the path's fd, closed once.
    unsafe { close(fd) };
    ret
}

/// An exclusive flock() on `fd`, waited for through signals, held until
/// the file is closed or unlocked: -errno.
pub(crate) fn lock_exclusive(fd: BorrowedFd<'_>) -> Result<(), c_int> {
    // SAFETY: the caller's fd.
    while unsafe { flock(fd.as_raw_fd(), LOCK_EX) } != 0 {
        if errno() != EINTR {
            return Err(-errno());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

/// An anonymous file in memory, named `name` where /proc shows its
/// descriptors, closed on exec: what a download is kept in rather than a
/// file of /tmp.
pub(crate) fn memfd(name: &core::ffi::CStr) -> Result<std::os::fd::OwnedFd, core::ffi::c_int> {
    // SAFETY: a C string and flags.
    let fd =
        unsafe { crate::sys::libc::memfd_create(name.as_ptr(), crate::sys::libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(-crate::sys::libc::errno());
    }
    // SAFETY: the descriptor memfd_create() gave, owned from here.
    Ok(unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) })
}
