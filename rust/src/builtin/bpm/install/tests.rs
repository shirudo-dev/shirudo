// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::testutil::TempDir;
use crate::util::bpm_package::test_archive;
use std::fs::{self, File};
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::fs::{FileExt, PermissionsExt, symlink};

const NEW: &[test_archive::Member<'_>] = &[
    ("sample-2/", b'5', b""),
    ("sample-2/cert.der", b'0', b"C"),
    ("sample-2/upatches/b.upatch", b'0', b"b"),
    ("sample-2/upatches/b.unload.upatch", b'0', b"B"),
    ("sample-2/upatches/a.upatch", b'0', b"a"),
    ("sample-2/upatches/a.unload.upatch", b'0', b"A"),
    ("sample-2/doc/notes/readme", b'0', b"n"),
];

fn open(dir: &TempDir) -> Install {
    let root = File::open(dir.join("")).unwrap();
    let install = Install::open_at(root.as_fd(), b"sample", b"2").unwrap();
    assert!(dir.join("bpm/staging/sample-2.bee").exists());
    install
}

fn fill(install: &Install) {
    let mut archive = File::from(install.archive.try_clone().unwrap());
    archive.write_all(&test_archive::archive(NEW)).unwrap();
}

fn prepared(dir: &TempDir) -> Install {
    let mut install = open(dir);
    fill(&install);
    install.extract().unwrap();
    install
}

fn old_version(dir: &TempDir) {
    let path = dir.join("bpm/packages/sample/1/upatches");
    fs::create_dir_all(&path).unwrap();
    for (name, body) in [
        ("a.upatch", b"p"),
        ("a.unload.upatch", b"P"),
        ("c.upatch", b"q"),
        ("c.unload.upatch", b"Q"),
    ] {
        fs::write(path.join(name), body).unwrap();
    }
}

fn record(order: &mut String, refuse: u8, fd: BorrowedFd<'_>, load: bool) -> i32 {
    let file = File::from(fd.try_clone_to_owned().unwrap());
    let mut byte = [0];
    assert_eq!(file.read_at(&mut byte, 0).unwrap(), 1);
    order.push(if load { '+' } else { '-' });
    order.push(char::from(byte[0]));
    i32::from(byte[0] == refuse)
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn install_loads_in_name_order_and_keeps_the_archive() {
    let dir = TempDir::new();
    let install = prepared(&dir);
    assert_eq!(
        fs::read(dir.join("bpm/packages/sample/2/doc/notes/readme")).unwrap(),
        b"n"
    );
    let note = fs::metadata(dir.join("bpm/packages/sample/2/doc/notes/readme")).unwrap();
    assert_eq!(note.permissions().mode() & 0o7777, 0o644);
    assert_eq!(note.len(), 1);
    assert_eq!(
        fs::read(dir.join("bpm/packages/sample/2/cert.der")).unwrap(),
        b"C"
    );
    assert_eq!(install.cert_matches_active(), Ok(false));
    let mut order = String::new();
    assert_eq!(
        install.load_with(None, &mut |_, fd, load| record(&mut order, 0, fd, load)),
        Ok(())
    );
    assert_eq!(order, "+a+b");
    assert_eq!(install.finish(Ok(())), Ok(()));
    assert!(dir.join("bpm/packages/sample/sample-2.bee").exists());
    assert!(!dir.join("bpm/staging/sample-2.bee").exists());
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn existing_version_is_left_alone() {
    let dir = TempDir::new();
    fs::create_dir_all(dir.join("bpm/packages/sample/2")).unwrap();
    fs::write(dir.join("bpm/packages/sample/2/keep"), b"k").unwrap();
    let mut install = open(&dir);
    fill(&install);
    assert_eq!(install.extract(), Err(-crate::errno::EEXIST));
    assert_eq!(
        install.finish(Err(-crate::errno::EEXIST)),
        Err(-crate::errno::EEXIST)
    );
    assert_eq!(
        fs::read(dir.join("bpm/packages/sample/2/keep")).unwrap(),
        b"k"
    );
    assert!(!dir.join("bpm/staging/sample-2.bee").exists());
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn invalid_names_do_not_create_state() {
    let dir = TempDir::new();
    let root = File::open(dir.join("")).unwrap();
    assert!(matches!(
        Install::open_at(root.as_fd(), b"..", b"2"),
        Err(err) if err == -EINVAL
    ));
    assert!(matches!(
        Install::open_at(root.as_fd(), b"sample", b"../2"),
        Err(err) if err == -EINVAL
    ));
    assert!(matches!(
        Install::open_at(root.as_fd(), b"sample/name", b"2"),
        Err(err) if err == -EINVAL
    ));
    assert!(!dir.join("bpm").exists());
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn refused_load_is_undone_and_version_removed() {
    let dir = TempDir::new();
    let install = prepared(&dir);
    let mut order = String::new();
    assert_eq!(
        install.load_with(None, &mut |_, fd, load| record(&mut order, b'b', fd, load)),
        Err(-EIO)
    );
    assert_eq!(order, "+a+b-A");
    assert_eq!(install.finish(Err(-EIO)), Err(-EIO));
    assert!(!dir.join("bpm/packages/sample/2").exists());
    assert!(!dir.join("bpm/staging/sample-2.bee").exists());
    assert!(dir.join("bpm/packages/sample").exists());
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn missing_certificate_rejects_key_and_removes_version() {
    let dir = TempDir::new();
    let install = prepared(&dir);
    fs::remove_file(dir.join("bpm/packages/sample/2/cert.der")).unwrap();
    assert_eq!(install.cert_matches_active(), Err(-ENOENT));
    assert_eq!(install.check_cert(), Err(-crate::errno::EKEYREJECTED));
    assert_eq!(
        install.finish(Err(-crate::errno::EKEYREJECTED)),
        Err(-crate::errno::EKEYREJECTED)
    );
    assert!(!dir.join("bpm/packages/sample/2").exists());
    assert!(!dir.join("bpm/staging/sample-2.bee").exists());
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn successful_upgrade_keeps_old_version_and_new_archive() {
    let dir = TempDir::new();
    old_version(&dir);
    let install = prepared(&dir);
    let mut order = String::new();
    assert_eq!(
        install.load_with(Some(b"1"), &mut |_, fd, load| record(
            &mut order, 0, fd, load
        )),
        Ok(())
    );
    assert_eq!(order, "-Q-P+a+b");
    assert_eq!(install.finish(Ok(())), Ok(()));
    assert!(dir.join("bpm/packages/sample/1/upatches/a.upatch").exists());
    assert!(dir.join("bpm/packages/sample/2/upatches/a.upatch").exists());
    assert!(dir.join("bpm/packages/sample/sample-2.bee").exists());
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn upgrade_unloads_old_version_first_and_restores_on_error() {
    let dir = TempDir::new();
    old_version(&dir);
    let install = prepared(&dir);
    let mut order = String::new();
    assert_eq!(
        install.load_with(Some(b"1"), &mut |_, fd, load| record(
            &mut order, 0, fd, load
        )),
        Ok(())
    );
    assert_eq!(order, "-Q-P+a+b");
    order.clear();
    assert_eq!(
        install.load_with(Some(b"0"), &mut |_, fd, load| record(
            &mut order, 0, fd, load
        )),
        Ok(())
    );
    assert_eq!(order, "+a+b");
    order.clear();
    assert_eq!(
        install.load_with(Some(b"1"), &mut |_, fd, load| record(
            &mut order, b'b', fd, load
        )),
        Err(-EIO)
    );
    assert_eq!(order, "-Q-P+a+b-A+p+q");
    order.clear();
    assert_eq!(
        install.load_with(Some(b"1"), &mut |_, fd, load| record(
            &mut order, b'P', fd, load
        )),
        Err(-EIO)
    );
    assert_eq!(order, "-Q-P+q");
    assert_eq!(install.finish(Err(-EIO)), Err(-EIO));
    assert!(dir.join("bpm/packages/sample/1/upatches/a.upatch").exists());
    assert!(!dir.join("bpm/packages/sample/2").exists());
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn symbolic_links_are_not_followed() {
    let dir = TempDir::new();
    fs::create_dir(dir.join("elsewhere")).unwrap();
    fs::create_dir(dir.join("bpm")).unwrap();
    symlink("../elsewhere", dir.join("bpm/staging")).unwrap();
    let root = File::open(dir.join("")).unwrap();
    assert!(
        matches!(Install::open_at(root.as_fd(), b"sample", b"2"), Err(err) if err == -crate::errno::ELOOP)
    );
    fs::remove_file(dir.join("bpm/staging")).unwrap();
    fs::create_dir(dir.join("bpm/staging")).unwrap();
    fs::write(dir.join("elsewhere/archive"), b"x").unwrap();
    symlink(
        "../../elsewhere/archive",
        dir.join("bpm/staging/sample-2.bee"),
    )
    .unwrap();
    assert!(
        matches!(Install::open_at(root.as_fd(), b"sample", b"2"), Err(err) if err == -crate::errno::ELOOP)
    );
    assert_eq!(fs::read(dir.join("elsewhere/archive")).unwrap(), b"x");
    assert!(
        fs::symlink_metadata(dir.join("bpm/staging/sample-2.bee"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
#[cfg_attr(miri, ignore = "mount namespace and openat2 are unavailable in Miri")]
fn bind_mounts_below_the_state_root_are_refused() {
    // SAFETY: geteuid takes no pointer.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: bind mount test needs root");
        return;
    }
    // SAFETY: unshare changes only this test thread mount namespace.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        eprintln!("skipped: bind mount test cannot create a mount namespace");
        return;
    }
    // SAFETY: the root mount and constant flags, with no data argument.
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
    fs::create_dir_all(dir.join("elsewhere/upatches")).unwrap();
    fs::write(dir.join("elsewhere/upatches/z.upatch"), b"z").unwrap();
    fs::create_dir_all(dir.join("bpm/staging")).unwrap();
    let root = File::open(dir.join("")).unwrap();
    let bind = |from: &str, to: &str| {
        let source = dir.cpath(from);
        let target = dir.cpath(to);
        // SAFETY: both paths exist and bind flags take no mount data.
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
    };
    let unbind = |to: &str| {
        let target = dir.cpath(to);
        // SAFETY: target names the bind mount made above.
        assert_eq!(unsafe { libc::umount2(target.as_ptr(), 0) }, 0);
    };
    bind("elsewhere", "bpm/staging");
    assert!(
        matches!(Install::open_at(root.as_fd(), b"sample", b"2"), Err(err) if err == -crate::errno::EXDEV)
    );
    unbind("bpm/staging");
    assert!(!dir.join("elsewhere/sample-2.bee").exists());

    let install = prepared(&dir);
    bind("elsewhere/upatches", "bpm/packages/sample/2/upatches");
    let mut order = String::new();
    assert_eq!(
        install.load_with(None, &mut |_, fd, load| record(&mut order, 0, fd, load)),
        Err(-crate::errno::EXDEV)
    );
    assert!(order.is_empty());
    unbind("bpm/packages/sample/2/upatches");

    bind(
        "elsewhere/upatches/z.upatch",
        "bpm/packages/sample/2/upatches/b.upatch",
    );
    assert_eq!(
        install.load_with(None, &mut |_, fd, load| record(&mut order, 0, fd, load)),
        Err(-crate::errno::EXDEV)
    );
    assert_eq!(order, "+a-A");
    unbind("bpm/packages/sample/2/upatches/b.upatch");
    assert_eq!(
        install.finish(Err(-crate::errno::EXDEV)),
        Err(-crate::errno::EXDEV)
    );
    assert!(!dir.join("bpm/packages/sample/2").exists());
}
