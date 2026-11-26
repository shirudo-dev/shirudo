// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The labels of the filesystem seal. bpf/seal.c denies every task but
//! shirudo the inodes that carry its label, so shirudo's state is the
//! labelled tree under /var/lib/shirudo, and what shirudo makes there it
//! labels as it makes it. An entry under a labelled directory without
//! the label came from someone else: it is refused, never followed or
//! read as shirudo's own. Output a command writes for its caller is the
//! other way round: it must carry no label, so root cannot point shirudo
//! at sealed state to overwrite.

use core::ffi::{CStr, c_int};
use std::ffi::{CString, OsStr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

use crate::errno::{
    EEXIST, EINVAL, ELOOP, ENAMETOOLONG, ENODATA, ENOENT, ENOTDIR, EOPNOTSUPP, EPERM, ERANGE,
    EXDEV, text,
};
use crate::sys::libc::{
    AT_FDCWD, AT_SYMLINK_NOFOLLOW, O_APPEND, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW,
    O_NONBLOCK, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, S_IFMT, S_IFREG, STATX_BASIC_STATS, Statx,
    fchmod, fgetxattr, fsetxattr, fstatfs, fsync, ftruncate, lgetxattr, lsetxattr, mkdirat, openat,
    renameat, statx, unlinkat,
};
use crate::sys::libc::{Statfs, Zeroed};
use crate::util::io::{
    append_line, close_checked, create_beneath_same_mount, lock_exclusive, open_beneath_same_mount,
    stat_fd, write_complete,
};

/// XATTR_SEAL: the attribute bpf/seal.c reads.
pub(crate) const XATTR: &CStr = c"security.bpf.shirudo";
/// SEAL_LABEL: the label's value.
pub(crate) const LABEL: &CStr = c"94442b45cfcdc59aabc2a91364ed2ae129418e05a5c1985231b9c032e673f469";
const LABEL_LEN: usize = LABEL.to_bytes().len();
/// VAR_LIB: the root of shirudo's sealed state.
const VAR_LIB: &CStr = c"/var/lib/shirudo";
const BPF_FS_MAGIC: i64 = 0xcafe_4a11;
const PATH_MAX: usize = 4096;
const NAME_MAX: usize = 255;

/// The label's value as an inode carries it.
type Label = [u8; LABEL_LEN];

fn say(level: fn(&[u8]), text: String) {
    let text = CString::new(text).unwrap_or_default();

    level(text.to_bytes());
}

fn error(text: String) {
    say(crate::log::err, text);
}

fn warn(text: String) {
    say(crate::log::warn, text);
}

fn errno() -> c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(EINVAL)
}

fn shown(p: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(p)
}

/// `name` opened in the directory `dir`, or in the working directory
/// for none.
fn open_at(
    dir: Option<BorrowedFd<'_>>,
    name: &CStr,
    flags: c_int,
    mode: u32,
) -> Result<OwnedFd, c_int> {
    let dfd = dir.map_or(AT_FDCWD, |dir| dir.as_raw_fd());
    // SAFETY: an open directory or AT_FDCWD, and a C string.
    let fd = unsafe { openat(dfd, name.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(-errno());
    }
    // SAFETY: the descriptor openat() just gave, owned from here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The directory `name` made in `dir`: whether it was, false for one
/// already there.
fn mkdir_at(dir: BorrowedFd<'_>, name: &CStr, mode: u32) -> Result<bool, c_int> {
    // SAFETY: an open directory and a C string.
    if unsafe { mkdirat(dir.as_raw_fd(), name.as_ptr(), mode) } == 0 {
        return Ok(true);
    }
    match errno() {
        EEXIST => Ok(false),
        e => Err(-e),
    }
}

/// `name` in `dir` removed, whatever comes of it: the leftover of an
/// operation that failed.
fn unlink_at(dir: BorrowedFd<'_>, name: &CStr) {
    // SAFETY: an open directory and a C string.
    unsafe { unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
}

fn rename_at(dir: BorrowedFd<'_>, from: &CStr, to: &CStr) -> Result<(), c_int> {
    // SAFETY: an open directory and two C strings.
    if unsafe { renameat(dir.as_raw_fd(), from.as_ptr(), dir.as_raw_fd(), to.as_ptr()) } != 0 {
        return Err(-errno());
    }
    Ok(())
}

fn sync(fd: BorrowedFd<'_>) -> Result<(), c_int> {
    // SAFETY: an open descriptor.
    if unsafe { fsync(fd.as_raw_fd()) } != 0 {
        return Err(-errno());
    }
    Ok(())
}

fn truncate(fd: BorrowedFd<'_>) -> Result<(), c_int> {
    // SAFETY: an open descriptor.
    if unsafe { ftruncate(fd.as_raw_fd(), 0) } != 0 {
        return Err(-errno());
    }
    Ok(())
}

/// The status of `name` in `dir` itself, a symbolic link's own.
fn stat_at(dir: BorrowedFd<'_>, name: &CStr) -> Result<Statx, c_int> {
    let mut st = Statx::zeroed();
    // SAFETY: an open directory, a C string and room for its status.
    let ret = unsafe {
        statx(
            dir.as_raw_fd(),
            name.as_ptr(),
            AT_SYMLINK_NOFOLLOW,
            STATX_BASIC_STATS,
            &mut st,
        )
    };
    if ret != 0 {
        return Err(-errno());
    }
    Ok(st)
}

/// XATTR_ANCESTOR: the mark of a directory above the state root.
const XATTR_ANCESTOR: &CStr = c"security.bpf.shirudo.ancestor";

/// The attribute `name` of the inode behind `fd` set to `value`.
fn fset(fd: BorrowedFd<'_>, name: &CStr, value: &[u8]) -> Result<(), c_int> {
    // SAFETY: an open descriptor, a C string and the value's bytes.
    let ret = unsafe {
        fsetxattr(
            fd.as_raw_fd(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if ret != 0 {
        return Err(-errno());
    }
    Ok(())
}

/// The seal's attribute of `path` itself, a symbolic link's own inode
/// rather than its target's, set to `value`.
fn lset(path: &CStr, value: &[u8]) -> Result<(), c_int> {
    // SAFETY: a C string, the attribute and the value's bytes.
    let ret = unsafe {
        lsetxattr(
            path.as_ptr(),
            XATTR.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if ret != 0 {
        return Err(-errno());
    }
    Ok(())
}

/// What a read of the label into `value` returned, as the seal takes it:
/// the label, None for none or one of another size, or -errno.
fn label_read(n: isize, value: Label) -> Result<Option<Label>, c_int> {
    if let Ok(len) = usize::try_from(n) {
        return Ok((len == LABEL_LEN).then_some(value));
    }
    match errno() {
        ENODATA | EOPNOTSUPP | ERANGE => Ok(None),
        e => Err(-e),
    }
}

/// The label of the inode behind `fd`.
fn fget(fd: BorrowedFd<'_>) -> Result<Option<Label>, c_int> {
    let mut value = [0; LABEL_LEN];
    // SAFETY: an open descriptor, the attribute and room for its value.
    let n = unsafe {
        fgetxattr(
            fd.as_raw_fd(),
            XATTR.as_ptr(),
            value.as_mut_ptr().cast(),
            LABEL_LEN,
        )
    };
    label_read(n, value)
}

/// The label of `path` itself, a symbolic link's own inode rather than
/// its target's.
fn lget(path: &CStr) -> Result<Option<Label>, c_int> {
    let mut value = [0; LABEL_LEN];
    // SAFETY: a C string, the attribute and room for its value.
    let n = unsafe {
        lgetxattr(
            path.as_ptr(),
            XATTR.as_ptr(),
            value.as_mut_ptr().cast(),
            LABEL_LEN,
        )
    };
    label_read(n, value)
}

/// The parent of directory `dir`, opened, and its status.
fn open_dir_parent(dir: &std::fs::File) -> Result<(std::fs::File, std::fs::Metadata), c_int> {
    let parent = open_at(
        Some(dir.as_fd()),
        c"..",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC,
        0,
    )
    .map(std::fs::File::from)?;
    let st = parent
        .metadata()
        .map_err(|e| -e.raw_os_error().unwrap_or(EINVAL))?;
    Ok((parent, st))
}

/// Marks each directory above the state root at `root`, up to the root
/// of its file system, so that the seal refuses to rename them. A
/// directory whose parent is another file system, or itself, is the root
/// of its own: renaming it does not move the state tree off the device
/// the next boot mounts there.
pub(crate) fn mark_ancestors(root: &[u8]) -> Result<(), c_int> {
    use std::os::unix::fs::OpenOptionsExt;

    let io = |e: std::io::Error| -e.raw_os_error().unwrap_or(EINVAL);
    let root = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW)
        .open(OsStr::from_bytes(root))
        .map_err(io)?;
    let dev = root.metadata().map_err(io)?.dev();
    let (mut dir, mut cur) = open_dir_parent(&root)?;
    drop(root);
    while cur.dev() == dev {
        let (parent, up) = open_dir_parent(&dir)?;
        if up.dev() != cur.dev() || up.ino() == cur.ino() {
            break;
        }
        fset(dir.as_fd(), XATTR_ANCESTOR, b"1")?;
        (dir, cur) = (parent, up);
    }
    Ok(())
}

/// Labels `path` itself, a symbolic link's own inode rather than its
/// target's.
pub(crate) fn label(path: &CStr) -> Result<(), c_int> {
    lset(path, LABEL.to_bytes())
}

/// The walk of [`label_tree`].
struct Walk {
    dev: u64,
    first: bool,
}

impl Walk {
    /// One entry: from the first init on, everything shirudo makes is
    /// labelled as it is made, so an entry without the label, or of a
    /// kind shirudo never makes, came from someone else and is left
    /// alone. Err stops the walk.
    fn visit(&self, path: &[u8], st: &std::fs::Metadata) -> Result<(), c_int> {
        // Another filesystem, the bpffs mount, is bpf2's: a label there
        // would make the seal contend for its inodes.
        if st.dev() != self.dev {
            return Ok(());
        }
        if !st.is_file() && !st.is_dir() {
            warn(format!(
                "seal: {} is not a file or directory of shirudo's (foreign entry); ignored",
                shown(path)
            ));
            return Ok(());
        }
        let c = CString::new(path).map_err(|_| -EINVAL)?;
        if !self.first {
            if !matches!(lget(&c), Ok(Some(_))) {
                warn(format!(
                    "seal: {} carries no label (foreign entry); ignored",
                    shown(path)
                ));
            }
            return Ok(());
        }
        label(&c).inspect_err(|&ret| {
            error(format!("seal: label {}: {}", shown(path), text(ret)));
        })
    }

    /// `path` and, a directory, what it holds, in directory order and
    /// on its own filesystem, links not followed.
    fn walk(&self, path: &[u8], st: &std::fs::Metadata) -> Result<(), c_int> {
        self.visit(path, st)?;
        if !st.is_dir() {
            return Ok(());
        }
        let entries = match std::fs::read_dir(OsStr::from_bytes(path)) {
            Ok(entries) => entries,
            // nftw() hands an unreadable directory to the visit alone.
            Err(e) if e.raw_os_error() == Some(crate::errno::EACCES) => return Ok(()),
            Err(e) => return Err(-e.raw_os_error().unwrap_or(EINVAL)),
        };
        for entry in entries {
            let entry = entry.map_err(|e| -e.raw_os_error().unwrap_or(EINVAL))?;
            let child = [path, b"/", entry.file_name().as_bytes()].concat();
            // An entry gone or unreadable since the directory was read,
            // nftw() leaves to a visit with no state; it is skipped.
            let st = match std::fs::symlink_metadata(OsStr::from_bytes(&child)) {
                Ok(st) => st,
                Err(e) if matches!(e.raw_os_error(), Some(ENOENT | crate::errno::EACCES)) => {
                    continue;
                }
                Err(e) => return Err(-e.raw_os_error().unwrap_or(EINVAL)),
            };
            if st.dev() != self.dev {
                continue;
            }
            self.walk(&child, &st)?;
        }
        Ok(())
    }
}

/// Labels shirudo's state tree, or with it labelled, checks it. The
/// first labelling is the bootstrap's alone, before enforcement is live
/// (`allow_first`): with the hooks attached, a state root without the
/// label is not the one init sealed but a tree bound over its path, and
/// labelling it would hand root inodes the seal takes for shirudo's.
pub(crate) fn label_tree(allow_first: bool) -> Result<(), c_int> {
    let io = |e: std::io::Error| -e.raw_os_error().unwrap_or(EINVAL);
    let root = VAR_LIB.to_bytes();
    let st = std::fs::metadata(OsStr::from_bytes(root)).map_err(io)?;
    let first = !matches!(lget(VAR_LIB), Ok(Some(_)));
    if first && !allow_first {
        error(format!(
            "seal: {} carries no label with enforcement live (foreign state tree); refusing",
            shown(root)
        ));
        return Err(-EPERM);
    }
    let walk = Walk {
        dev: st.dev(),
        first,
    };
    let top = std::fs::symlink_metadata(OsStr::from_bytes(root)).map_err(io)?;
    walk.walk(root, &top)
}

/// Whether the inode behind `fd` carries the label of the directory open
/// as `dir`: under a labelled directory an entry must, so one renamed or
/// linked in, or made while the seal could not label it, is refused.
/// Ok when it does or the directory carries none, -EPERM when not.
fn same(dir: BorrowedFd<'_>, fd: BorrowedFd<'_>) -> Result<(), c_int> {
    let Some(parent) = fget(dir)? else {
        return Ok(());
    };
    if fget(fd)? == Some(parent) {
        Ok(())
    } else {
        Err(-EPERM)
    }
}

/// Gives the inode behind `fd` the label of its directory, open as
/// `dir`.
pub(crate) fn inherit(dir: BorrowedFd<'_>, fd: BorrowedFd<'_>) -> Result<(), c_int> {
    let Some(parent) = fget(dir)? else {
        return Ok(());
    };
    if fget(fd)? == Some(parent) {
        return Ok(());
    }
    fset(fd, XATTR, &parent)
}

/// Gives `path` itself, a symbolic link's own inode rather than its
/// target's, the label of the directory it is in.
pub(crate) fn inherit_path(path: &CStr) -> Result<(), c_int> {
    let (dir, _) = open_parent(path.to_bytes())?;
    let parent = fget(dir.as_fd());
    drop(dir);
    let Some(parent) = parent? else {
        return Ok(());
    };
    if lget(path)? == Some(parent) {
        return Ok(());
    }
    lset(path, &parent)
}

/// The directory at `path`, opened a component at a time, following no
/// symbolic link and taking no foreign entry for shirudo's own; with
/// `create`, what is missing made, labelled as its parent is.
fn open_dir(path: &[u8], create: bool, mode: u32) -> Result<OwnedFd, c_int> {
    if path.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    let start = if path.first() == Some(&b'/') {
        c"/"
    } else {
        c"."
    };
    let mut dir = open_at(None, start, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0)?;
    for comp in path.split(|&c| c == b'/').filter(|c| !c.is_empty()) {
        let name = CString::new(comp).map_err(|_| -EINVAL)?;
        let created = create && mkdir_at(dir.as_fd(), &name, mode)?;
        let next = open_at(
            Some(dir.as_fd()),
            &name,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
            0,
        )
        .inspect_err(|&err| {
            if err == -ELOOP || err == -ENOTDIR {
                error(format!(
                    "{}: {} is not a directory of shirudo's (foreign entry in sealed state)",
                    shown(path),
                    shown(comp)
                ));
            }
        })?;
        let labelled = if created {
            inherit(dir.as_fd(), next.as_fd())
        } else {
            same(dir.as_fd(), next.as_fd())
        };
        if labelled == Err(-EPERM) {
            error(format!(
                "{}: {} carries no label (foreign entry in sealed state); refusing",
                shown(path),
                shown(comp)
            ));
        }
        dir = next;
        labelled?;
    }
    Ok(dir)
}

/// The sealed state root itself. The initrd may bind this directory
/// across file systems, so only the opened root is checked here.
pub(crate) fn open_state_root() -> Result<OwnedFd, c_int> {
    let fd = open_dir(VAR_LIB.to_bytes(), false, 0)?;
    let mut fs = Statfs::zeroed();
    // SAFETY: the opened directory and room for its file system status.
    if unsafe { fstatfs(fd.as_raw_fd(), &mut fs) } != 0 {
        return Err(-errno());
    }
    if fs.f_type == BPF_FS_MAGIC {
        return Err(-EXDEV);
    }
    if fget(fd.as_fd())?.is_none_or(|value| value.as_slice() != LABEL.to_bytes()) {
        return Err(-EPERM);
    }
    Ok(fd)
}

fn child_name_ok(name: &CStr) -> bool {
    !name.to_bytes().is_empty()
        && !name.to_bytes().contains(&b'/')
        && !matches!(name.to_bytes(), b"." | b"..")
}

/// One named child on the same mount, bearing the parent's seal.
pub(crate) fn open_child(
    parent: BorrowedFd<'_>,
    name: &CStr,
    flags: c_int,
) -> Result<OwnedFd, c_int> {
    if !child_name_ok(name) {
        return Err(-EINVAL);
    }
    let fd = open_beneath_same_mount(parent.as_raw_fd(), name, flags)?;
    same(parent, fd.as_fd())?;
    Ok(fd)
}

/// Make one direct child directory or take the existing one. The opened
/// directory stays on `parent`'s mount and must carry its seal.
pub(crate) fn mkdir_child(
    parent: BorrowedFd<'_>,
    name: &CStr,
    mode: u32,
    exclusive: bool,
) -> Result<OwnedFd, c_int> {
    if !child_name_ok(name) {
        return Err(-EINVAL);
    }
    let created = mkdir_at(parent, name, mode)?;
    if !created && exclusive {
        return Err(-EEXIST);
    }
    let fd = open_beneath_same_mount(parent.as_raw_fd(), name, O_RDONLY | O_DIRECTORY)?;
    if created {
        inherit(parent, fd.as_fd())?;
    } else {
        same(parent, fd.as_fd())?;
    }
    Ok(fd)
}

/// Create a direct child directory if missing, then open only a sealed
/// child on this mount. With enforcement active, inode_init_security gives
/// new children the parent's label.
pub(crate) fn open_or_create_child_dir(
    parent: BorrowedFd<'_>,
    name: &CStr,
    mode: u32,
) -> Result<OwnedFd, c_int> {
    if !child_name_ok(name) {
        return Err(-EINVAL);
    }
    mkdir_at(parent, name, mode)?;
    open_child(parent, name, O_RDONLY | O_DIRECTORY)
}

/// Open one regular child file, making and labelling it when requested.
/// An existing file is checked before it can be truncated.
pub(crate) fn create_child(
    parent: BorrowedFd<'_>,
    name: &CStr,
    flags: c_int,
    mode: u32,
) -> Result<OwnedFd, c_int> {
    if !child_name_ok(name) {
        return Err(-EINVAL);
    }
    let existing = open_beneath_same_mount(
        parent.as_raw_fd(),
        name,
        O_NONBLOCK | (flags & !(O_CREAT | O_EXCL | O_TRUNC)),
    );
    match existing {
        Ok(_) if flags & O_EXCL != 0 => Err(-EEXIST),
        Ok(fd) => {
            regular(fd.as_fd())?;
            same(parent, fd.as_fd())?;
            if flags & O_TRUNC != 0 {
                truncate(fd.as_fd())?;
            }
            Ok(fd)
        }
        Err(err) if err == -ENOENT && flags & O_CREAT != 0 => {
            let fd = create_beneath_same_mount(parent.as_raw_fd(), name, flags, mode)?;
            inherit(parent, fd.as_fd())?;
            Ok(fd)
        }
        Err(err) => Err(err),
    }
}

/// The directory that holds `path`, opened as [`open_dir`] does, and the
/// name in it.
fn open_parent(path: &[u8]) -> Result<(OwnedFd, &[u8]), c_int> {
    let (dir, name) = match path.iter().rposition(|&c| c == b'/') {
        None => (
            open_at(None, c".", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0)?,
            path,
        ),
        Some(slash) => {
            let len = if slash == 0 { 1 } else { slash };
            if len >= PATH_MAX {
                return Err(-ENAMETOOLONG);
            }
            (open_dir(&path[..len], false, 0)?, &path[slash + 1..])
        }
    };
    if name.is_empty() {
        return Err(-EINVAL);
    }
    Ok((dir, name))
}

/// A FIFO planted before the seal was live would hold its opener
/// forever: the open does not wait, and what is not a regular file is
/// refused.
fn regular(fd: BorrowedFd<'_>) -> Result<(), c_int> {
    if stat_fd(fd)?.stx_mode & S_IFMT == S_IFREG {
        Ok(())
    } else {
        Err(-EINVAL)
    }
}

/// Whether the inode behind `fd` carries a label of any size.
fn sealed(fd: BorrowedFd<'_>) -> Result<bool, c_int> {
    // SAFETY: an open descriptor and the attribute, its size only.
    if unsafe { fgetxattr(fd.as_raw_fd(), XATTR.as_ptr(), core::ptr::null_mut(), 0) } >= 0 {
        return Ok(true);
    }
    match errno() {
        ENODATA | EOPNOTSUPP => Ok(false),
        e => Err(-e),
    }
}

/// Output a command writes for its caller: a regular file that carries
/// no label, not under a labelled directory, not reached through a
/// symbolic link, truncated only once it is checked. The file, its
/// directory and its name there.
fn output_in_dir(
    path: &[u8],
    flags: c_int,
    mode: u32,
) -> Result<(OwnedFd, OwnedFd, CString), c_int> {
    let (dir, name) = open_parent(path)?;
    let name = CString::new(name).map_err(|_| -EINVAL)?;
    match unsealed_output(dir.as_fd(), &name, flags, mode)? {
        Some(fd) => Ok((fd, dir, name)),
        None => {
            error(format!("{}: refusing to write sealed state", shown(path)));
            Err(-EPERM)
        }
    }
}

/// The output `name` in `dir` opened and checked as [`output_in_dir`]
/// says, None when it or its directory is sealed state.
fn unsealed_output(
    dir: BorrowedFd<'_>,
    name: &CStr,
    flags: c_int,
    mode: u32,
) -> Result<Option<OwnedFd>, c_int> {
    if sealed(dir)? {
        return Ok(None);
    }
    let fd = open_at(
        Some(dir),
        name,
        (flags & !O_TRUNC) | O_NOFOLLOW | O_CLOEXEC,
        mode,
    )?;
    regular(fd.as_fd())?;
    if sealed(fd.as_fd())? {
        return Ok(None);
    }
    if flags & O_TRUNC != 0 {
        truncate(fd.as_fd())?;
    }
    Ok(Some(fd))
}

/// The output at `path`, opened with `flags` and `mode` and checked as
/// [`output_in_dir`] says.
pub(crate) fn output_open(path: &[u8], flags: c_int, mode: u32) -> Result<OwnedFd, c_int> {
    output_in_dir(path, flags, mode).map(|(fd, _, _)| fd)
}

/// A document a command writes for its caller: created by
/// [`Output::create`], written whole by [`Output::commit`].
pub(crate) struct Output {
    file: OwnedFd,
    dir: OwnedFd,
    name: CString,
}

impl Output {
    /// The output at `path`, created with `mode` or emptied, and checked
    /// as [`output_open`] does.
    pub(crate) fn create(path: &[u8], mode: u32) -> Result<Output, c_int> {
        let (file, dir, name) = output_in_dir(path, O_WRONLY | O_CREAT | O_TRUNC, mode)?;
        Ok(Output { file, dir, name })
    }

    /// `doc` and its newline written, and the file closed. A file the
    /// write does not complete is removed, through the directory it was
    /// opened in and only while its name still holds the inode written:
    /// root, who picks the path and can make the write fail, could
    /// otherwise point it at sealed state to remove.
    pub(crate) fn commit(self, doc: &[u8]) -> Result<(), c_int> {
        let Output { file, dir, name } = self;
        let newline = |()| write_complete(file.as_fd(), b"\n");
        let written = write_complete(file.as_fd(), doc).and_then(newline);
        let wrote = stat_fd(file.as_fd()).ok();
        let committed = written.and(close_checked(file));
        if let (Err(_), Some(wrote)) = (committed, wrote) {
            let inode = |st: &Statx| (st.stx_dev_major, st.stx_dev_minor, st.stx_ino);
            if stat_at(dir.as_fd(), &name).is_ok_and(|named| inode(&named) == inode(&wrote)) {
                unlink_at(dir.as_fd(), &name);
            }
        }
        committed
    }
}

/// open(2) under the seal: an existing file must be a regular one that
/// carries its directory's label; one it creates takes that label.
pub(crate) fn open(path: &[u8], flags: c_int, mode: u32) -> Result<OwnedFd, c_int> {
    let (dir, name) = open_parent(path)?;
    let name = CString::new(name).map_err(|_| -EINVAL)?;
    let opened = open_at(
        Some(dir.as_fd()),
        &name,
        (flags & !(O_CREAT | O_TRUNC)) | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
        mode,
    );
    match opened {
        Ok(_) if flags & O_EXCL != 0 => Err(-EEXIST),
        Ok(fd) => {
            let owned = regular(fd.as_fd()).and_then(|()| same(dir.as_fd(), fd.as_fd()));
            if owned == Err(-EPERM) {
                error(format!(
                    "{}: carries no label (foreign entry in sealed state); refusing",
                    shown(path)
                ));
            }
            owned?;
            if flags & O_TRUNC != 0 {
                truncate(fd.as_fd())?;
            }
            Ok(fd)
        }
        Err(err) if err == -ENOENT && flags & O_CREAT != 0 => {
            let fd = open_at(
                Some(dir.as_fd()),
                &name,
                flags | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode,
            )?;
            inherit(dir.as_fd(), fd.as_fd())?;
            Ok(fd)
        }
        Err(err) => {
            if err == -ELOOP {
                error(format!(
                    "{}: is a symbolic link (foreign entry in sealed state); refusing",
                    shown(path)
                ));
            }
            Err(err)
        }
    }
}

/// A file of shirudo's own, opened to be read.
pub(crate) fn open_read(path: &[u8]) -> Result<OwnedFd, c_int> {
    open_file(path, false)
}

/// [`open_read`] of an entry whose directory must carry the label: one of
/// root's making, which no task without authority can label, holds
/// nothing shirudo takes for its own. -EPERM when it does not.
pub(crate) fn open_sealed(path: &[u8]) -> Result<OwnedFd, c_int> {
    open_file(path, true)
}

/// Whether the directory `path` names an entry of carries the label.
pub(crate) fn parent_labeled(path: &[u8]) -> bool {
    open_parent(path).is_ok_and(|(dir, _)| matches!(fget(dir.as_fd()), Ok(Some(_))))
}

fn open_file(path: &[u8], in_sealed_dir: bool) -> Result<OwnedFd, c_int> {
    let (dir, name) = open_parent(path)?;
    if in_sealed_dir && !matches!(fget(dir.as_fd()), Ok(Some(_))) {
        error(format!(
            "{}: its directory is not sealed state; refusing to read it",
            shown(path)
        ));
        return Err(-EPERM);
    }
    let name = CString::new(name).map_err(|_| -EINVAL)?;
    let opened = open_at(
        Some(dir.as_fd()),
        &name,
        O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
        0,
    )
    .and_then(|fd| {
        regular(fd.as_fd())?;
        same(dir.as_fd(), fd.as_fd())?;
        Ok(fd)
    });
    if matches!(opened, Err(err) if err == -EPERM || err == -ELOOP) {
        error(format!(
            "{}: not shirudo's own (foreign entry in sealed state); refusing to read it",
            shown(path)
        ));
    }
    opened
}

/// The lock file at `path`, created sealed when missing, held
/// exclusively until its fd is closed.
pub(crate) fn lock(path: &[u8]) -> Result<OwnedFd, c_int> {
    let fd = open(path, O_RDWR | O_CREAT, 0o600)?;

    lock_exclusive(fd.as_fd())?;
    Ok(fd)
}

/// `line` appended as one record to the sealed log at `path`, under the
/// lock that keeps its appenders apart.
pub(crate) fn append(path: &CStr, line: &[u8]) -> Result<(), c_int> {
    let fd = open(path.to_bytes(), O_RDWR | O_CREAT | O_APPEND, 0o600)?;
    let appended = lock_exclusive(fd.as_fd()).and_then(|()| append_line(fd.as_fd(), path, line));

    appended.and(close_checked(fd))
}

/// mkdir -p, every directory it makes labelled as its parent is.
pub(crate) fn mkdir_p(path: &[u8], mode: u32) -> Result<(), c_int> {
    open_dir(path, true, mode).map(drop)
}

/// Write to a temporary child, seal it, then atomically replace `name`.
/// An exclusive write discards a previous temporary file while the caller
/// holds the directory lock.
fn write_file_at(
    dir: BorrowedFd<'_>,
    name: &CStr,
    data: &[u8],
    mode: u32,
    exact: bool,
    exclusive: bool,
) -> Result<(), c_int> {
    let tmp = [name.to_bytes(), b".tmp"].concat();
    if tmp.len() > NAME_MAX {
        return Err(-ENAMETOOLONG);
    }
    let tmp = CString::new(tmp).map_err(|_| -EINVAL)?;
    if exclusive {
        // SAFETY: the open directory and a NUL-terminated child name.
        if unsafe { unlinkat(dir.as_raw_fd(), tmp.as_ptr(), 0) } != 0 {
            let err = errno();
            if err != ENOENT {
                return Err(-err);
            }
        }
    }
    let flags =
        O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW | if exclusive { O_EXCL } else { O_TRUNC };
    let fd = open_at(Some(dir), &tmp, flags, mode)?;
    let written = inherit(dir, fd.as_fd())
        .and_then(|()| {
            if !exact {
                return Ok(());
            }
            // SAFETY: the open temporary file and its requested mode.
            if unsafe { fchmod(fd.as_raw_fd(), mode) } != 0 {
                return Err(-errno());
            }
            Ok(())
        })
        .and_then(|()| write_complete(fd.as_fd(), data))
        .and_then(|()| sync(fd.as_fd()));
    let placed = written
        .and(close_checked(fd))
        .and_then(|()| rename_at(dir, &tmp, name))
        .and_then(|()| sync(dir));
    if placed.is_err() {
        unlink_at(dir, &tmp);
    }
    placed
}

/// Replace one named child while the caller holds the directory lock.
pub(crate) fn replace_locked_at(
    parent: BorrowedFd<'_>,
    name: &CStr,
    data: &[u8],
    mode: u32,
) -> Result<(), c_int> {
    if !child_name_ok(name) {
        return Err(-EINVAL);
    }
    write_file_at(parent, name, data, mode, false, true)
}

/// `data` written whole to `path` through a labelled temporary file,
/// synced and renamed into place.
fn write_file_inner(path: &[u8], data: &[u8], mode: u32, exact: bool) -> Result<(), c_int> {
    let (dir, name) = open_parent(path)?;
    let name = CString::new(name).map_err(|_| -EINVAL)?;
    write_file_at(dir.as_fd(), &name, data, mode, exact, false)
}

/// As [`write_file`], forcing the final file to carry exactly `mode`,
/// even when its temporary file already existed or the process has a
/// restrictive umask.
pub(crate) fn write_file_mode(path: &[u8], data: &[u8], mode: u32) -> Result<(), c_int> {
    write_file_inner(path, data, mode, true)
}

/// `data` written whole to `path` through a labelled temporary file,
/// synced and renamed into place.
pub(crate) fn write_file(path: &[u8], data: &[u8], mode: u32) -> Result<(), c_int> {
    write_file_inner(path, data, mode, false)
}

#[cfg(test)]
mod tests;
