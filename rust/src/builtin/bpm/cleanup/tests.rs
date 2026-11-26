// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use std::cell::{Cell, RefCell};
use std::fs::{self, File};
use std::os::unix::fs::{FileExt, PermissionsExt, symlink};

use crate::testutil::TempDir;

struct Package {
    tmp: TempDir,
    store: File,
    state: BpmStateEntry,
}

impl Package {
    fn new() -> Self {
        let tmp = TempDir::new();
        fs::create_dir_all(tmp.join("sample/1/upatches")).unwrap();
        let store = File::open(tmp.join("")).unwrap();
        let mut state = BpmStateEntry::new();
        state.name[..6].copy_from_slice(b"sample");
        state.version[0] = b'1';
        let version_path = tmp.cpath("sample/1");
        state.path[..version_path.to_bytes().len()].copy_from_slice(version_path.to_bytes());
        Self { tmp, store, state }
    }

    fn put(&self, name: &str, byte: u8) {
        fs::write(self.tmp.join(name), [byte]).unwrap();
    }

    fn gone(&self) {
        assert!(!self.tmp.join("sample").exists());
    }
}

fn removed(_: &CStr, _: BorrowedFd<'_>) -> c_int {
    0
}

fn first(fd: BorrowedFd<'_>) -> u8 {
    let file = File::from(fd.try_clone_to_owned().unwrap());
    let mut byte = [0];
    assert_eq!(file.read_at(&mut byte, 0).unwrap(), 1);
    byte[0]
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn uninstall_detaches_before_removing_all_versions() {
    let p = Package::new();
    p.put("sample/1/upatches/a.unload.upatch", b'a');
    p.put("sample/1/upatches/z.unload.upatch", b'z');
    p.put("sample/sample-1.bee", b'x');
    fs::create_dir(p.tmp.join("sample/2")).unwrap();
    p.put("sample/2/old", b'k');
    let refuse = Cell::new(true);
    let order = RefCell::new(Vec::new());
    let remove = |_: &CStr, fd: BorrowedFd<'_>| {
        order.borrow_mut().push(first(fd));
        i32::from(refuse.get())
    };

    assert_eq!(uninstall_at(p.store.as_fd(), &p.state, &remove), Err(-EIO));
    assert!(p.tmp.join("sample/1/upatches/a.unload.upatch").exists());
    assert!(p.tmp.join("sample/sample-1.bee").exists());
    refuse.set(false);
    order.borrow_mut().clear();
    assert_eq!(uninstall_at(p.store.as_fd(), &p.state, &remove), Ok(()));
    assert_eq!(*order.borrow(), b"za");
    p.gone();
    assert_eq!(uninstall_at(p.store.as_fd(), &p.state, &remove), Ok(()));
    assert_eq!(*order.borrow(), b"za");
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn unload_uses_the_file_opened_before_a_path_replacement() {
    let p = Package::new();
    let rel = "sample/1/upatches/a.unload.upatch";
    p.put(rel, b'a');
    let seen = Cell::new(0);
    let remove = |_: &CStr, fd: BorrowedFd<'_>| {
        fs::remove_file(p.tmp.join(rel)).unwrap();
        p.put(rel, b'x');
        seen.set(first(fd));
        0
    };

    assert_eq!(uninstall_at(p.store.as_fd(), &p.state, &remove), Ok(()));
    assert_eq!(seen.get(), b'a');
    p.gone();
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn load_without_directive_stops_uninstall() {
    let p = Package::new();
    p.put("sample/1/upatches/a.upatch", b'l');
    p.put("sample/1/upatches/a.unload.upatch", b'a');
    p.put("sample/1/upatches/b.upatch", b'l');
    let order = RefCell::new(Vec::new());
    let remove = |_: &CStr, fd: BorrowedFd<'_>| {
        order.borrow_mut().push(first(fd));
        0
    };

    assert_eq!(
        uninstall_at(p.store.as_fd(), &p.state, &remove),
        Err(-ENODATA)
    );
    assert!(order.borrow().is_empty());
    assert!(p.tmp.join("sample/1/upatches/a.upatch").exists());
    assert!(p.tmp.join("sample/1/upatches/b.upatch").exists());

    p.put("sample/1/upatches/b.unload.upatch", b'b');
    assert_eq!(uninstall_at(p.store.as_fd(), &p.state, &remove), Ok(()));
    assert_eq!(*order.borrow(), b"ba");
    p.gone();
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn retry_finishes_partly_removed_package() {
    let p = Package::new();
    p.put("sample/1/upatches/notes", b'n');
    let calls = Cell::new(0);
    let remove = |_: &CStr, _: BorrowedFd<'_>| {
        calls.set(calls.get() + 1);
        0
    };
    assert_eq!(uninstall_at(p.store.as_fd(), &p.state, &remove), Ok(()));
    assert_eq!(calls.get(), 0);
    p.gone();

    let p = Package::new();
    fs::remove_dir(p.tmp.join("sample/1/upatches")).unwrap();
    assert_eq!(uninstall_at(p.store.as_fd(), &p.state, &removed), Ok(()));
    p.gone();
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn world_writable_held_directive_keeps_the_package() {
    let p = Package::new();
    let directive = "sample/1/upatches/z.unload.upatch";
    p.put(directive, b'z');
    fs::set_permissions(p.tmp.join(directive), fs::Permissions::from_mode(0o666)).unwrap();
    let trusted = p.tmp.cpath("sample");
    let remove = |path: &CStr, fd: BorrowedFd<'_>| {
        io::read_fd_in(fd, path, 128, &[trusted.as_c_str()])
            .map(|_| 0)
            .unwrap_or_else(|err| err)
    };

    assert_eq!(uninstall_at(p.store.as_fd(), &p.state, &remove), Err(-EIO));
    assert!(p.tmp.join(directive).exists());
    assert!(p.tmp.join("sample/1").exists());
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn cleanup_requires_one_child_directory() {
    let p = Package::new();
    for name in [c".", c"../1", c"sample/1/upatches"] {
        assert_eq!(remove_entry(p.store.as_fd(), name, 0), Err(-EINVAL));
    }
    symlink("sample", p.tmp.join("alias")).unwrap();
    assert!(remove_entry(p.store.as_fd(), c"alias", 0).is_err());
    assert!(p.tmp.join("sample/1/upatches").exists());
    fs::remove_file(p.tmp.join("alias")).unwrap();
    assert_eq!(remove_entry(p.store.as_fd(), c"sample", 0), Ok(()));
    p.gone();
}
