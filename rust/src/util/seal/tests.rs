// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::errno::{EEXIST, EINVAL, EISDIR, ELOOP, ENOENT, ENOTDIR, EXDEV};
use crate::testutil::TempDir;
use std::fs::{self, File};
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::fs::symlink;

fn root(dir: &TempDir) -> File {
    File::open(dir.join("")).unwrap()
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn mkdir_child_makes_or_takes_one_directory() {
    let dir = TempDir::new();
    let parent = root(&dir);
    mkdir_child(parent.as_fd(), c"made", 0o700, true).unwrap();
    assert!(matches!(
        mkdir_child(parent.as_fd(), c"made", 0o700, true),
        Err(err) if err == -EEXIST
    ));
    mkdir_child(parent.as_fd(), c"made", 0o700, false).unwrap();

    for name in [c"made/below", c"..", c""] {
        assert!(matches!(
            mkdir_child(parent.as_fd(), name, 0o700, false),
            Err(err) if err == -EINVAL
        ));
    }
    File::create(dir.join("file")).unwrap();
    assert!(matches!(
        mkdir_child(parent.as_fd(), c"file", 0o700, false),
        Err(err) if err == -ENOTDIR
    ));
    symlink("made", dir.join("link")).unwrap();
    assert!(matches!(
        mkdir_child(parent.as_fd(), c"link", 0o700, false),
        Err(err) if err == -ELOOP
    ));
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn create_child_makes_or_takes_one_regular_file() {
    let dir = TempDir::new();
    let parent = root(&dir);
    assert!(matches!(
        create_child(parent.as_fd(), c"file", O_RDWR, 0o600),
        Err(err) if err == -ENOENT
    ));
    let mut file = File::from(
        create_child(parent.as_fd(), c"file", O_WRONLY | O_CREAT | O_EXCL, 0o600).unwrap(),
    );
    file.write_all(b"abc").unwrap();
    drop(file);
    assert!(matches!(
        create_child(parent.as_fd(), c"file", O_WRONLY | O_CREAT | O_EXCL, 0o600),
        Err(err) if err == -EEXIST
    ));
    assert_eq!(fs::metadata(dir.join("file")).unwrap().len(), 3);
    create_child(parent.as_fd(), c"file", O_RDWR | O_CREAT, 0o600).unwrap();
    assert_eq!(fs::metadata(dir.join("file")).unwrap().len(), 3);
    create_child(parent.as_fd(), c"file", O_RDWR | O_CREAT | O_TRUNC, 0o600).unwrap();
    assert_eq!(fs::metadata(dir.join("file")).unwrap().len(), 0);
    assert!(matches!(
        create_child(parent.as_fd(), c"a/b", O_RDWR | O_CREAT, 0o600),
        Err(err) if err == -EINVAL
    ));
    assert!(matches!(
        create_child(parent.as_fd(), c".", O_RDONLY, 0o600),
        Err(err) if err == -EINVAL
    ));
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn create_child_takes_only_a_regular_file() {
    let dir = TempDir::new();
    let parent = root(&dir);
    fs::create_dir(dir.join("sub")).unwrap();
    assert!(matches!(
        create_child(parent.as_fd(), c"sub", O_RDONLY, 0o600),
        Err(err) if err == -EINVAL
    ));
    assert!(matches!(
        create_child(parent.as_fd(), c"sub", O_RDWR | O_CREAT, 0o600),
        Err(err) if err == -EISDIR
    ));
    // SAFETY: an open directory, a NUL-terminated child name and a mode.
    let ret = unsafe { libc::mkfifoat(parent.as_raw_fd(), c"fifo".as_ptr(), 0o600) };
    assert_eq!(ret, 0);
    assert!(matches!(
        create_child(parent.as_fd(), c"fifo", O_RDONLY | O_CREAT | O_TRUNC, 0o600),
        Err(err) if err == -EINVAL
    ));
    fs::write(dir.join("target"), b"abc").unwrap();
    symlink("target", dir.join("link")).unwrap();
    assert!(matches!(
        create_child(parent.as_fd(), c"link", O_RDWR | O_CREAT | O_TRUNC, 0o600),
        Err(err) if err == -ELOOP
    ));
    assert_eq!(fs::metadata(dir.join("target")).unwrap().len(), 3);
    symlink("missing", dir.join("dangling")).unwrap();
    assert!(matches!(
        create_child(parent.as_fd(), c"dangling", O_RDWR | O_CREAT, 0o600),
        Err(err) if err == -ELOOP
    ));
    assert!(!dir.join("missing").exists());
}

#[test]
#[cfg_attr(miri, ignore = "mount namespace and openat2 are unavailable in Miri")]
fn a_child_on_another_mount_is_refused() {
    // SAFETY: a query that takes no pointer.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: bind mount test needs root");
        return;
    }
    // SAFETY: unshare changes only this test thread's mount namespace.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        eprintln!("skipped: bind mount test cannot create a mount namespace");
        return;
    }
    // SAFETY: the root mount and constant flags; no data argument.
    let ret = unsafe {
        libc::mount(
            core::ptr::null(),
            c"/".as_ptr(),
            core::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            core::ptr::null(),
        )
    };
    assert_eq!(ret, 0);
    let dir = TempDir::new();
    fs::create_dir(dir.join("source")).unwrap();
    fs::create_dir(dir.join("alias")).unwrap();
    let parent = root(&dir);
    let source = dir.cpath("source");
    let alias = dir.cpath("alias");
    // SAFETY: two existing directory paths and constant bind flags.
    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            alias.as_ptr(),
            core::ptr::null(),
            libc::MS_BIND,
            core::ptr::null(),
        )
    };
    assert_eq!(ret, 0);
    assert!(matches!(
        mkdir_child(parent.as_fd(), c"alias", 0o700, false),
        Err(err) if err == -EXDEV
    ));
    assert!(matches!(
        mkdir_child(parent.as_fd(), c"alias", 0o700, true),
        Err(err) if err == -EEXIST
    ));
    // SAFETY: the bind mount made above in this test thread's namespace.
    assert_eq!(unsafe { libc::umount2(alias.as_ptr(), 0) }, 0);

    fs::write(dir.join("one"), b"").unwrap();
    fs::write(dir.join("two"), b"").unwrap();
    let source = dir.cpath("one");
    let target = dir.cpath("two");
    // SAFETY: two existing file paths and constant bind flags.
    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            core::ptr::null(),
            libc::MS_BIND,
            core::ptr::null(),
        )
    };
    assert_eq!(ret, 0);
    assert!(matches!(
        create_child(parent.as_fd(), c"two", O_RDWR | O_CREAT | O_TRUNC, 0o600),
        Err(err) if err == -EXDEV
    ));
    assert!(matches!(
        open_child(parent.as_fd(), c"two", O_RDONLY),
        Err(err) if err == -EXDEV
    ));
    // SAFETY: the bind mount made above in this test thread's namespace.
    assert_eq!(unsafe { libc::umount2(target.as_ptr(), 0) }, 0);
}
