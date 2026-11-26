// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::errno::{EINVAL, EIO, EISDIR, ELOOP, ENOTDIR, EPERM, ESTALE};
use crate::sys::libc::O_WRONLY;
use crate::testutil::TempDir;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

#[test]
#[cfg_attr(miri, ignore = "needs procfs and openat2")]
fn open_beneath_same_mount_stops_at_proc() {
    let root = File::open("/").unwrap();
    assert!(open_beneath(root.as_raw_fd(), c"proc", O_RDONLY | O_DIRECTORY).is_ok());
    assert!(matches!(
        open_beneath_same_mount(root.as_raw_fd(), c"proc", O_RDONLY | O_DIRECTORY),
        Err(err) if err == -crate::errno::EXDEV
    ));
}

#[test]
#[cfg_attr(miri, ignore = "needs mount namespaces and openat2")]
fn open_beneath_same_mount_refuses_a_bind() {
    // This case runs only when the test process can make a private mount
    // namespace; an unprivileged host run leaves the other cases active.
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
    std::fs::create_dir(dir.join("source")).unwrap();
    std::fs::create_dir(dir.join("alias")).unwrap();
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
    let root = File::open(dir.join("")).unwrap();
    assert!(open_beneath(root.as_raw_fd(), c"alias", O_RDONLY | O_DIRECTORY).is_ok());
    assert!(matches!(
        open_beneath_same_mount(root.as_raw_fd(), c"alias", O_RDONLY | O_DIRECTORY),
        Err(err) if err == -crate::errno::EXDEV
    ));
    // SAFETY: the bind mount made above, in this test thread's namespace.
    assert_eq!(unsafe { libc::umount2(alias.as_ptr(), 0) }, 0);
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn create_beneath_same_mount_makes_one_new_file() {
    let dir = TempDir::new();
    let parent = File::open(dir.join("")).unwrap();
    let made = create_beneath_same_mount(parent.as_raw_fd(), c"new", O_WRONLY, 0o600).unwrap();
    assert_eq!(
        File::from(made).metadata().unwrap().permissions().mode() & 0o7777,
        0o600
    );
    assert!(matches!(
        create_beneath_same_mount(parent.as_raw_fd(), c"new", O_WRONLY, 0o600),
        Err(err) if err == -crate::errno::EEXIST
    ));
    assert!(matches!(
        create_beneath_same_mount(parent.as_raw_fd(), c"../new", O_WRONLY, 0o600),
        Err(err) if err == -crate::errno::EXDEV
    ));
    symlink("missing", dir.join("link")).unwrap();
    assert!(matches!(
        create_beneath_same_mount(parent.as_raw_fd(), c"link", O_WRONLY, 0o600),
        Err(err) if err == -crate::errno::EEXIST
    ));
    assert!(!dir.join("missing").exists());
}

#[test]
fn errno_of_uses_the_os_error_or_eio() {
    assert_eq!(
        super::errno_of(&std::io::Error::from_raw_os_error(EINVAL)),
        -EINVAL
    );
    assert_eq!(super::errno_of(&std::io::Error::other("no OS error")), -EIO);
}

/// A log of `text` in `dir`, open to append to.
fn log_with(dir: &TempDir, text: &[u8]) -> File {
    let mut f = OpenOptions::new()
        .read(true)
        .append(true)
        .create_new(true)
        .open(dir.join("log"))
        .unwrap();

    f.write_all(text).unwrap();
    f
}

/// What the log holds.
fn log_of(dir: &TempDir) -> Vec<u8> {
    std::fs::read(dir.join("log")).unwrap()
}

/// append_line() of `line` to the log `f`.
fn append(f: &File, line: &[u8]) -> Result<(), c_int> {
    append_line(f.as_fd(), c"log", line)
}

#[test]
fn append_line_adds_one_record() {
    let dir = TempDir::new();
    let f = log_with(&dir, b"");

    assert_eq!(append(&f, b"x"), Ok(()));
    assert_eq!(append(&f, b"y\n"), Ok(()));
    assert_eq!(log_of(&dir), b"x\ny\n");
}

/// A record killed before its newline would run into the next one on
/// its line, and every reader after would refuse the log.
#[test]
fn append_line_drops_what_did_not_finish() {
    let long = [&b"x\n"[..], &[b'a'; 11998]].concat();

    for (text, want) in [
        (&b"x\n{\"half\":"[..], &b"x\nz\n"[..]),
        (b"{\"whole\":1}", b"z\n"),
        (&long, b"x\nz\n"),
    ] {
        let dir = TempDir::new();
        let f = log_with(&dir, text);

        assert_eq!(append(&f, b"z"), Ok(()));
        assert_eq!(log_of(&dir), want);
    }
}

#[test]
fn append_line_takes_one_line_alone() {
    let dir = TempDir::new();
    let f = log_with(&dir, b"x\n");

    assert_eq!(append(&f, b"a\nb"), Err(-EINVAL));
    assert_eq!(append(&f, b"a\0b"), Err(-EINVAL));
    assert_eq!(log_of(&dir), b"x\n");
}

#[test]
fn lock_exclusive_keeps_others_out() {
    let dir = TempDir::new();
    let f = log_with(&dir, b"");
    let other = File::open(dir.join("log")).unwrap();

    assert_eq!(lock_exclusive(f.as_fd()), Ok(()));
    // SAFETY: an open descriptor.
    let ret = unsafe { libc::flock(other.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(ret, -1);
    assert_eq!(errno(), libc::EWOULDBLOCK);
    drop(f);
    assert_eq!(lock_exclusive(other.as_fd()), Ok(()));
}

#[test]
fn kernel_dev_is_major_over_20_minor_bits() {
    assert_eq!(kernel_dev(libc::makedev(8, 1)), 0x800001);
    assert_eq!(kernel_dev(libc::makedev(253, 0x12345)), 253 << 20 | 0x12345);
    assert_eq!(kernel_dev(libc::makedev(0xfff, 0xfffff)), 0xffffffff);
}

#[test]
fn bpffs_mounted_at_wants_the_root_of_a_bpffs() {
    let dir = TempDir::new();
    let mounted = |path: &CStr| {
        // SAFETY: a C string.
        unsafe { bpffs_mounted_at(path.as_ptr()) }
    };

    assert_eq!(mounted(&dir.cpath("")), 0);
    assert_eq!(mounted(c"/"), 0);
    assert_eq!(mounted(c"/nonexistent/shirudo"), 0);
    assert_eq!(mounted(c"/dev/null"), -ENOTDIR);
}

#[test]
fn dir_names_at_reads_as_dir_names_does() {
    let dir = TempDir::new();
    for name in ["b.der", "a.der", ".der", "c.vouch", "Z.der"] {
        File::create(dir.join(name)).unwrap();
    }
    std::fs::create_dir(dir.join("d.der")).unwrap();
    let is_der = |n: &[u8]| crate::text::name_has_suffix(n, b".der");
    let open = File::open(dir.join("")).unwrap();
    let names = dir_names_at(open.as_fd(), is_der).unwrap();

    assert_eq!(names, [&b"Z.der"[..], b"a.der", b"b.der", b"d.der"]);
    assert_eq!(
        dir_names(dir.join("").as_os_str().as_encoded_bytes(), is_der),
        Ok(names)
    );
    assert_eq!(
        dir_names_at(File::open("/dev/null").unwrap().as_fd(), is_der),
        Err(-ENOTDIR)
    );
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn euid() -> u32 {
    // SAFETY: a call that takes no arguments.
    unsafe { libc::geteuid() }
}

fn set_fd_mode(file: &File, mode: u32) {
    // SAFETY: the file's live descriptor and a mode.
    assert_eq!(unsafe { libc::fchmod(file.as_raw_fd(), mode) }, 0);
}

fn give_link(tree: &TempDir, name: &str, uid: u32) {
    let path = tree.cpath(name);

    // SAFETY: a C string and numeric owners, without following the link.
    assert_eq!(unsafe { libc::lchown(path.as_ptr(), uid, uid) }, 0);
}

fn make_dirs(tree: &TempDir, name: &str, mode: u32) {
    let mut path = tree.join("");
    for component in Path::new(name).components() {
        path.push(component);
        if !path.exists() {
            std::fs::create_dir(&path).unwrap();
        }
        chmod(&path, mode);
    }
}

fn make_file(tree: &TempDir, name: &str, text: &[u8], mode: u32) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tree.join(name))
        .unwrap();

    file.write_all(text).unwrap();
    drop(file);
    chmod(&tree.join(name), mode);
}

fn replace_mode(tree: &TempDir, name: &str, text: &[u8], mode: u32) {
    let tmp = format!("{name}.tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(tree.join(&tmp))
        .unwrap();

    file.write_all(text).unwrap();
    drop(file);
    chmod(&tree.join(&tmp), mode);
    std::fs::rename(tree.join(&tmp), tree.join(name)).unwrap();
}

fn make_link(tree: &TempDir, target: impl AsRef<Path>, name: &str) {
    symlink(target, tree.join(name)).unwrap();
}

fn make_abs_link(tree: &TempDir, target: &str, name: &str) {
    make_link(tree, tree.join(target), name);
}

fn trusted(tree: &TempDir, prefix: &str, opened: &str, asked: &str, secret: bool) -> c_int {
    let file = File::open(tree.join(opened)).unwrap();
    let path = tree.cpath(asked);
    let prefix = tree.cpath(prefix);
    let dirs = [prefix.as_c_str()];
    let ret = check_trusted_in(file.as_fd(), &path, &dirs);

    if ret == 0 && secret {
        check_secret_in(file.as_fd(), &path, &dirs)
    } else {
        ret
    }
}

fn trusted_fd(tree: &TempDir, prefix: &str, fd: BorrowedFd<'_>, asked: &str) -> c_int {
    let path = tree.cpath(asked);
    let prefix = tree.cpath(prefix);

    check_trusted_in(fd, &path, &[prefix.as_c_str()])
}

fn open_racing(
    tree: &TempDir,
    prefix: &str,
    name: &str,
    mode: u32,
    renames: usize,
) -> (Result<OwnedFd, c_int>, usize) {
    let path = tree.cpath(name);
    let prefix = tree.cpath(prefix);
    let dirs = [prefix.as_c_str()];
    let mut opens = 0usize;
    let opened = open_checked(&path, O_RDONLY, &dirs, |path, flags| {
        let fd = open_path(path, flags)?;

        opens += 1;
        if opens <= renames {
            replace_mode(tree, name, b"b\n", mode);
        }
        Ok(fd)
    });

    (opened, opens)
}

fn fd_contents(fd: OwnedFd) -> Vec<u8> {
    let mut file = File::from(fd);
    let mut body = Vec::new();

    file.read_to_end(&mut body).unwrap();
    body
}

#[test]
#[cfg_attr(miri, ignore = "uses host filesystem and libc")]
fn state_descriptor_read_refuses_a_world_writable_file() {
    let tree = TempDir::new();
    make_dirs(&tree, "trusted/bpm", 0o700);
    make_file(&tree, "trusted/bpm/state.json", b"state", 0o666);
    let path = tree.cpath("trusted/bpm/state.json");
    let prefix = tree.cpath("trusted");
    let file = File::open(tree.join("trusted/bpm/state.json")).unwrap();

    assert_eq!(
        read_fd_in(file.as_fd(), &path, 128, &[prefix.as_c_str()]),
        Err(-EPERM)
    );
}

#[test]
#[cfg_attr(miri, ignore = "uses host filesystem and libc")]
fn trusted_file_and_secret_modes_are_checked() {
    let tree = TempDir::new();
    make_dirs(&tree, "trusted/keys", 0o755);
    make_file(&tree, "trusted/keys/cert.der", b"cert", 0o644);

    assert_eq!(
        trusted(
            &tree,
            "trusted",
            "trusted/keys/cert.der",
            "trusted/keys/cert.der",
            false,
        ),
        0
    );
    assert_eq!(
        trusted(
            &tree,
            "trusted",
            "trusted/keys/cert.der",
            "trusted/keys//./cert.der",
            false,
        ),
        0
    );
    assert_eq!(
        trusted(
            &tree,
            "trusted",
            "trusted/keys/cert.der",
            "trusted/keys/../keys/cert.der",
            false,
        ),
        0
    );
    assert_eq!(
        trusted(
            &tree,
            "trusted",
            "trusted/keys/cert.der",
            "trusted/keys/cert.der",
            true,
        ),
        -EPERM
    );

    chmod(&tree.join("trusted/keys/cert.der"), 0o600);
    assert_eq!(
        trusted(
            &tree,
            "trusted",
            "trusted/keys/cert.der",
            "trusted/keys/cert.der",
            true,
        ),
        0
    );
    chmod(&tree.join("trusted/keys/cert.der"), 0o664);
    assert_eq!(
        trusted(
            &tree,
            "trusted",
            "trusted/keys/cert.der",
            "trusted/keys/cert.der",
            false,
        ),
        -EPERM
    );
}

#[test]
#[cfg_attr(miri, ignore = "uses host filesystem and libc")]
fn trusted_path_refuses_writable_directories() {
    let tree = TempDir::new();
    make_dirs(&tree, "trusted/keys", 0o755);
    make_file(&tree, "trusted/keys/cert.der", b"cert", 0o644);
    chmod(&tree.join("trusted/keys"), 0o775);

    assert_eq!(
        trusted(
            &tree,
            "trusted",
            "trusted/keys/cert.der",
            "trusted/keys/cert.der",
            false,
        ),
        -EPERM
    );

    chmod(&tree.join("trusted/keys"), 0o1777);
    let sticky = if euid() == 0 { 0 } else { -EPERM };
    assert_eq!(
        trusted(
            &tree,
            "trusted",
            "trusted/keys/cert.der",
            "trusted/keys/cert.der",
            false,
        ),
        sticky
    );
}

#[test]
#[cfg_attr(miri, ignore = "uses host filesystem and libc")]
fn trusted_path_follows_owned_links() {
    let tree = TempDir::new();
    make_dirs(&tree, "trusted/keys", 0o700);
    make_file(&tree, "trusted/keys/0a.der", b"cert", 0o644);

    make_abs_link(&tree, "trusted/keys/0a.der", "trusted/keys/cert.der");
    assert_eq!(
        trusted(
            &tree,
            "trusted",
            "trusted/keys/0a.der",
            "trusted/keys/cert.der",
            false,
        ),
        0
    );
    make_link(&tree, "../keys/0a.der", "trusted/keys/up.der");
    assert_eq!(
        trusted(
            &tree,
            "trusted",
            "trusted/keys/0a.der",
            "trusted/keys/up.der",
            false,
        ),
        0
    );
    make_link(&tree, "keys", "trusted/current");
    assert_eq!(
        trusted(
            &tree,
            "trusted",
            "trusted/keys/0a.der",
            "trusted/current/cert.der",
            false,
        ),
        0
    );
    make_link(&tree, "loop.der", "trusted/keys/loop.der");
    assert_eq!(
        trusted(
            &tree,
            "trusted",
            "trusted/keys/0a.der",
            "trusted/keys/loop.der",
            false,
        ),
        -ELOOP
    );
    make_link(&tree, "0a.der/more", "trusted/keys/past.der");
    assert_eq!(
        trusted(
            &tree,
            "trusted",
            "trusted/keys/0a.der",
            "trusted/keys/past.der",
            false,
        ),
        -ENOTDIR
    );
}

#[test]
#[cfg_attr(miri, ignore = "uses host filesystem and libc")]
fn trusted_path_wants_the_opened_inode() {
    let tree = TempDir::new();
    make_dirs(&tree, "trusted/keys", 0o700);
    make_dirs(&tree, "open", 0o777);
    make_file(&tree, "trusted/keys/cert.der", b"a", 0o644);
    make_file(&tree, "open/cert.der", b"b", 0o644);

    assert_eq!(
        trusted(
            &tree,
            "trusted",
            "open/cert.der",
            "trusted/keys/cert.der",
            false,
        ),
        -ESTALE
    );
    assert_eq!(
        trusted(
            &tree,
            "trusted",
            "trusted/keys/cert.der",
            "trusted/keys",
            false,
        ),
        -EISDIR
    );
}

#[test]
#[cfg_attr(miri, ignore = "uses host filesystem and libc")]
fn secret_check_only_asks_the_open_file() {
    let tree = TempDir::new();
    make_dirs(&tree, "trusted/keys", 0o700);
    make_file(&tree, "trusted/keys/auth.conf", b"a\n", 0o600);
    let file = File::open(tree.join("trusted/keys/auth.conf")).unwrap();
    let path = tree.cpath("trusted/keys/auth.conf");
    let prefix = tree.cpath("trusted");
    let dirs = [prefix.as_c_str()];

    assert_eq!(check_trusted_in(file.as_fd(), &path, &dirs), 0);
    replace_mode(&tree, "trusted/keys/auth.conf", b"b\n", 0o600);
    assert_eq!(check_trusted_in(file.as_fd(), &path, &dirs), -ESTALE);
    assert_eq!(check_secret_in(file.as_fd(), &path, &dirs), 0);
    set_fd_mode(&file, 0o640);
    assert_eq!(check_secret_in(file.as_fd(), &path, &dirs), -EPERM);
    assert_eq!(check_secret_in(file.as_fd(), c"/tmp/elsewhere", &dirs), 0);
}

#[test]
#[cfg_attr(miri, ignore = "uses host filesystem and libc")]
fn checked_open_retries_only_stale_files() {
    let tree = TempDir::new();
    make_dirs(&tree, "trusted/keys", 0o755);
    make_file(&tree, "trusted/keys/cert.der", b"a\n", 0o644);

    let (opened, opens) = open_racing(&tree, "trusted", "trusted/keys/cert.der", 0o644, 1);
    assert_eq!(opens, 2);
    assert_eq!(fd_contents(opened.unwrap()), b"b\n");

    let (opened, opens) = open_racing(
        &tree,
        "trusted",
        "trusted/keys/cert.der",
        0o644,
        TRUSTED_REOPENS,
    );
    assert!(opened.is_ok());
    assert_eq!(opens, TRUSTED_REOPENS + 1);

    let (opened, opens) = open_racing(
        &tree,
        "trusted",
        "trusted/keys/cert.der",
        0o644,
        TRUSTED_REOPENS + 1,
    );
    assert!(matches!(opened, Err(err) if err == -ESTALE));
    assert_eq!(opens, TRUSTED_REOPENS + 1);

    let (opened, opens) = open_racing(&tree, "trusted", "trusted/keys/cert.der", 0o664, 1);
    assert!(matches!(opened, Err(err) if err == -EPERM));
    assert_eq!(opens, 2);

    let (opened, opens) = open_racing(&tree, "trusted", "trusted/keys/cert.der", 0o644, 0);
    assert!(matches!(opened, Err(err) if err == -EPERM));
    assert_eq!(opens, 1);
}

#[test]
#[cfg_attr(miri, ignore = "uses host filesystem and libc")]
fn trusted_path_follows_link_chains_outside_prefix() {
    let tree = TempDir::new();
    make_dirs(&tree, "etc/shirudo/bpm", 0o755);
    make_dirs(&tree, "srv", 0o755);
    make_file(&tree, "srv/shirudo.conf", b"config", 0o644);

    make_link(&tree, "../../srv/shirudo.conf", "etc/shirudo/relative.conf");
    assert_eq!(
        trusted(
            &tree,
            "etc/shirudo",
            "srv/shirudo.conf",
            "etc/shirudo/relative.conf",
            false,
        ),
        0
    );
    make_abs_link(&tree, "srv/shirudo.conf", "etc/shirudo/absolute.conf");
    assert_eq!(
        trusted(
            &tree,
            "etc/shirudo",
            "srv/shirudo.conf",
            "etc/shirudo/absolute.conf",
            false,
        ),
        0
    );
    make_link(&tree, "relative.conf", "etc/shirudo/shirudo.conf");
    make_abs_link(
        &tree,
        "etc/shirudo/shirudo.conf",
        "etc/shirudo/bpm/chain.conf",
    );
    assert_eq!(
        trusted(
            &tree,
            "etc/shirudo",
            "srv/shirudo.conf",
            "etc/shirudo/bpm/chain.conf",
            false,
        ),
        0
    );
}

#[test]
#[cfg_attr(miri, ignore = "uses host filesystem and libc")]
fn trusted_path_follows_distribution_ca_links() {
    {
        let tree = TempDir::new();
        make_dirs(&tree, "etc/shirudo/bpm", 0o755);
        make_dirs(&tree, "etc/ssl/certs", 0o755);
        make_dirs(&tree, "usr/share/ca-certificates/mozilla", 0o755);
        make_file(
            &tree,
            "usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt",
            b"cert",
            0o644,
        );
        make_abs_link(
            &tree,
            "usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt",
            "etc/ssl/certs/ISRG_Root_X1.pem",
        );
        make_abs_link(
            &tree,
            "etc/ssl/certs/ISRG_Root_X1.pem",
            "etc/shirudo/bpm/ca.pem",
        );

        assert_eq!(
            trusted(
                &tree,
                "etc/shirudo",
                "usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt",
                "etc/shirudo/bpm/ca.pem",
                false,
            ),
            0
        );
    }

    {
        let tree = TempDir::new();
        make_dirs(&tree, "etc/shirudo/bpm", 0o755);
        make_dirs(&tree, "etc/pki/tls/certs", 0o755);
        make_dirs(&tree, "etc/pki/ca-trust/extracted/pem", 0o755);
        make_file(
            &tree,
            "etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
            b"cert",
            0o444,
        );
        make_link(
            &tree,
            "../../ca-trust/extracted/pem/tls-ca-bundle.pem",
            "etc/pki/tls/certs/ca-bundle.crt",
        );
        make_dirs(&tree, "etc/ssl", 0o755);
        make_link(&tree, "../pki/tls/certs", "etc/ssl/certs");
        make_abs_link(
            &tree,
            "etc/ssl/certs/ca-bundle.crt",
            "etc/shirudo/bpm/ca.pem",
        );

        assert_eq!(
            trusted(
                &tree,
                "etc/shirudo",
                "etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
                "etc/shirudo/bpm/ca.pem",
                false,
            ),
            0
        );
    }
}

#[test]
#[cfg_attr(miri, ignore = "uses host filesystem and libc")]
fn trusted_prefix_may_be_a_link_elsewhere() {
    let tree = TempDir::new();
    make_dirs(&tree, "etc", 0o755);
    make_dirs(&tree, "mnt/state/etc-shirudo", 0o755);
    make_file(
        &tree,
        "mnt/state/etc-shirudo/shirudo.conf",
        b"config",
        0o644,
    );
    make_abs_link(&tree, "mnt/state/etc-shirudo", "etc/shirudo");

    assert_eq!(
        trusted(
            &tree,
            "etc/shirudo",
            "mnt/state/etc-shirudo/shirudo.conf",
            "etc/shirudo/shirudo.conf",
            false,
        ),
        0
    );
    std::fs::remove_file(tree.join("etc/shirudo")).unwrap();
    make_link(&tree, "../mnt/state/etc-shirudo", "etc/shirudo");
    assert_eq!(
        trusted(
            &tree,
            "etc/shirudo",
            "mnt/state/etc-shirudo/shirudo.conf",
            "etc/shirudo/shirudo.conf",
            false,
        ),
        0
    );

    chmod(&tree.join("etc"), 0o775);
    assert_eq!(
        trusted(
            &tree,
            "etc/shirudo",
            "mnt/state/etc-shirudo/shirudo.conf",
            "etc/shirudo/shirudo.conf",
            false,
        ),
        -EPERM
    );
    chmod(&tree.join("etc"), 0o755);
    chmod(&tree.join("mnt"), 0o777);
    assert_eq!(
        trusted(
            &tree,
            "etc/shirudo",
            "mnt/state/etc-shirudo/shirudo.conf",
            "etc/shirudo/shirudo.conf",
            false,
        ),
        -EPERM
    );
}

#[test]
#[cfg_attr(miri, ignore = "uses host filesystem and libc")]
fn trusted_path_follows_nixos_switches() {
    let tree = TempDir::new();
    make_dirs(&tree, "etc", 0o755);
    make_dirs(&tree, "nix/store/b-etc/etc/shirudo", 0o755);
    make_file(&tree, "nix/store/a-shirudo.conf", b"a\n", 0o444);
    make_abs_link(
        &tree,
        "nix/store/a-shirudo.conf",
        "nix/store/b-etc/etc/shirudo/shirudo.conf",
    );
    make_abs_link(&tree, "nix/store/b-etc/etc", "etc/static");
    make_abs_link(&tree, "etc/static/shirudo", "etc/shirudo");

    if euid() == 0 {
        chmod(&tree.join("nix/store"), 0o1775);
    }
    let old = File::open(tree.join("etc/shirudo/shirudo.conf")).unwrap();
    assert_eq!(
        trusted_fd(
            &tree,
            "etc/shirudo",
            old.as_fd(),
            "etc/shirudo/shirudo.conf",
        ),
        0
    );

    make_dirs(&tree, "nix/store/d-etc/etc/shirudo", 0o755);
    make_file(&tree, "nix/store/c-shirudo.conf", b"c\n", 0o444);
    make_abs_link(
        &tree,
        "nix/store/c-shirudo.conf",
        "nix/store/d-etc/etc/shirudo/shirudo.conf",
    );
    make_abs_link(&tree, "nix/store/d-etc/etc", "etc/.static.tmp");
    std::fs::rename(tree.join("etc/.static.tmp"), tree.join("etc/static")).unwrap();

    assert_eq!(
        trusted_fd(
            &tree,
            "etc/shirudo",
            old.as_fd(),
            "etc/shirudo/shirudo.conf",
        ),
        -ESTALE
    );
    let new = File::open(tree.join("etc/shirudo/shirudo.conf")).unwrap();
    assert_eq!(
        trusted_fd(
            &tree,
            "etc/shirudo",
            new.as_fd(),
            "etc/shirudo/shirudo.conf",
        ),
        0
    );

    chmod(&tree.join("nix/store"), 0o775);
    assert_eq!(
        trusted(
            &tree,
            "etc/shirudo",
            "nix/store/c-shirudo.conf",
            "etc/shirudo/shirudo.conf",
            false,
        ),
        -EPERM
    );
}

#[test]
#[cfg_attr(miri, ignore = "uses host filesystem and libc")]
fn trusted_path_detects_config_manager_rename() {
    let tree = TempDir::new();
    make_dirs(&tree, "etc/shirudo", 0o755);
    make_file(
        &tree,
        "etc/shirudo/shirudo.conf",
        b"eventlog.max_bytes = 1048576\n",
        0o644,
    );
    let old = File::open(tree.join("etc/shirudo/shirudo.conf")).unwrap();

    assert_eq!(
        trusted_fd(
            &tree,
            "etc/shirudo",
            old.as_fd(),
            "etc/shirudo/shirudo.conf",
        ),
        0
    );
    replace_mode(
        &tree,
        "etc/shirudo/shirudo.conf",
        b"eventlog.max_bytes = 2097152\n",
        0o644,
    );
    assert_eq!(
        trusted_fd(
            &tree,
            "etc/shirudo",
            old.as_fd(),
            "etc/shirudo/shirudo.conf",
        ),
        -ESTALE
    );
    let new = File::open(tree.join("etc/shirudo/shirudo.conf")).unwrap();
    assert_eq!(
        trusted_fd(
            &tree,
            "etc/shirudo",
            new.as_fd(),
            "etc/shirudo/shirudo.conf",
        ),
        0
    );
}

#[test]
#[cfg_attr(miri, ignore = "uses host filesystem and libc")]
fn trusted_path_refuses_links_owned_by_another_user() {
    if euid() != 0 {
        return;
    }

    let tree = TempDir::new();
    make_dirs(&tree, "etc/shirudo/bpm", 0o755);
    make_dirs(&tree, "etc/ssl/certs", 0o755);
    make_dirs(&tree, "srv/ca", 0o755);
    make_file(&tree, "srv/ca/ca.pem", b"cert", 0o644);
    make_abs_link(&tree, "srv/ca/ca.pem", "etc/shirudo/bpm/ca.pem");

    assert_eq!(
        trusted(
            &tree,
            "etc/shirudo",
            "srv/ca/ca.pem",
            "etc/shirudo/bpm/ca.pem",
            false,
        ),
        0
    );
    give_link(&tree, "etc/shirudo/bpm/ca.pem", 65534);
    assert_eq!(
        trusted(
            &tree,
            "etc/shirudo",
            "srv/ca/ca.pem",
            "etc/shirudo/bpm/ca.pem",
            false,
        ),
        -EPERM
    );

    make_link(&tree, "../../srv/ca", "etc/shirudo/ca");
    give_link(&tree, "etc/shirudo/ca", 65534);
    assert_eq!(
        trusted(
            &tree,
            "etc/shirudo",
            "srv/ca/ca.pem",
            "etc/shirudo/ca/ca.pem",
            false,
        ),
        -EPERM
    );

    make_abs_link(&tree, "srv/ca/ca.pem", "etc/ssl/certs/ca.pem");
    give_link(&tree, "etc/ssl/certs/ca.pem", 65534);
    make_abs_link(&tree, "etc/ssl/certs/ca.pem", "etc/shirudo/bpm/chain.pem");
    assert_eq!(
        trusted(
            &tree,
            "etc/shirudo",
            "srv/ca/ca.pem",
            "etc/shirudo/bpm/chain.pem",
            false,
        ),
        -EPERM
    );
}

#[test]
#[cfg_attr(miri, ignore = "uses a host filesystem race")]
fn checked_read_takes_one_complete_renamed_file() {
    let tree = TempDir::new();
    make_dirs(&tree, "trusted", 0o755);
    make_file(&tree, "trusted/config", b"a\n", 0o644);
    let path = tree.cpath("trusted/config");
    let prefix = tree.cpath("trusted");
    let dirs = [prefix.as_c_str()];
    let file = tree.join("trusted/config");
    let tmp = tree.join("trusted/config.tmp");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let renamer_stop = std::sync::Arc::clone(&stop);
    let renamer = std::thread::spawn(move || {
        let mut second = false;

        while !renamer_stop.load(std::sync::atomic::Ordering::Relaxed) {
            std::fs::write(&tmp, if second { b"b\n" } else { b"a\n" }).unwrap();
            chmod(&tmp, 0o644);
            std::fs::rename(&tmp, &file).unwrap();
            second = !second;
            std::thread::sleep(std::time::Duration::from_micros(100));
        }
    });
    let mut refused = 0usize;
    let mut other = 0usize;

    for _ in 0..20_000 {
        match open_checked(&path, O_RDONLY, &dirs, open_path) {
            Ok(fd) => {
                let body = fd_contents(fd);

                if body != b"a\n" && body != b"b\n" {
                    other += 1;
                }
            }
            Err(err) if err == -ESTALE => refused += 1,
            Err(_) => other += 1,
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    renamer.join().unwrap();

    assert_eq!(other, 0);
    assert!(refused <= 20_000);
    let final_fd = open_checked(&path, O_RDONLY, &dirs, open_path).unwrap();
    let body = fd_contents(final_fd);
    assert!(body == b"a\n" || body == b"b\n");
}
