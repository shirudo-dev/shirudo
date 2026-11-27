// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The C library, through the rust-lang libc crate: its bindings under
//! the names the tree's Rust takes them by, the few glibc symbols the
//! crate does not bind, and helpers over errno and the environment.

use core::ffi::{CStr, c_char, c_int, c_long, c_ulong};

#[cfg(not(miri))]
pub use libc::explicit_bzero;
pub use libc::{
    _exit, AT_REMOVEDIR, access, calloc, close, closedir, execv, execvp, faccessat, fchmod, fclose,
    fcntl, fdopen, fdopendir, ferror, fgetxattr, flock, fputc, fputs, free, fsetxattr, fstatfs,
    fstatvfs, fsync, ftruncate, fwrite, getenv, geteuid, gethostname, getline, getrandom,
    getsockopt, getxattr, gmtime_r, if_indextoname, ioctl, lgetxattr, link, lseek, lsetxattr,
    memfd_create, mkdirat, mkdtemp, mknod, mkstemp, mkstemps, mlockall, mount, open, openat,
    opendir, openlog, personality, posix_memalign, prctl, pread, printf, putchar, read, readdir,
    readlinkat, recvmsg, renameat, rmdir, sendto, setenv, setitimer, setrlimit, setsockopt,
    setxattr, snprintf, socket, statfs, statvfs, statx, strcasecmp, strerror, strftime, strlen,
    strptime, syscall, sysconf, syslog, timegm, umount2, uname, unlink, unlinkat, unsetenv, write,
};

/// explicit_bzero(3), for Miri, which cannot call the C library: the `n`
/// bytes at `s` zeroed by writes the compiler keeps.
///
/// # Safety
///
/// `s` is valid for writes of `n` bytes.
#[cfg(miri)]
pub unsafe fn explicit_bzero(s: *mut core::ffi::c_void, n: usize) {
    for i in 0..n {
        // SAFETY: the caller's n bytes at s.
        unsafe { s.cast::<u8>().add(i).write_volatile(0) };
    }
}
pub use libc::{
    AF_INET, AF_NETLINK, AF_UNIX, AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW, F_DUPFD_CLOEXEC,
    F_GETFD, F_OK, F_SETFD, ITIMER_PROF, ITIMER_REAL, ITIMER_VIRTUAL, LOCK_EX, LOCK_NB, LOCK_UN,
    MCL_CURRENT, MCL_FUTURE, MFD_CLOEXEC, MSG_CTRUNC, MSG_TRUNC, O_APPEND, O_CLOEXEC, O_CREAT,
    O_DIRECT, O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_NONBLOCK, O_PATH, O_RDONLY, O_RDWR, O_TRUNC,
    O_WRONLY, PR_SET_DUMPABLE, PR_SET_NO_NEW_PRIVS, PR_SET_PTRACER, R_OK, RLIM_INFINITY,
    RLIMIT_CORE, RLIMIT_CPU, RLIMIT_FSIZE, SEEK_SET, SO_RCVTIMEO, SOCK_CLOEXEC, SOCK_DGRAM,
    SOCK_RAW, SOL_SOCKET, STATX_BASIC_STATS, STATX_MNT_ID_UNIQUE, STATX_SIZE, STATX_TYPE, W_OK,
    X_OK,
};

pub type Dir = libc::DIR;
pub type File = libc::FILE;
pub type Iovec = libc::iovec;
pub type Itimerval = libc::itimerval;
pub type Msghdr = libc::msghdr;
pub type Rlimit = libc::rlimit;
pub type SockaddrNl = libc::sockaddr_nl;
pub type Statfs = libc::statfs;
pub type Statvfs = libc::statvfs;
pub type Statx = libc::statx;
pub type Timeval = libc::timeval;
pub type Tm = libc::tm;
pub type Utsname = libc::utsname;

/// The constants the tree takes in another type or under another name
/// than the crate's.
pub const PATH_MAX: usize = libc::PATH_MAX as usize;
pub const SC_NPROCESSORS_ONLN: c_int = libc::_SC_NPROCESSORS_ONLN;
pub const STATX_ATTR_MOUNT_ROOT: u64 = libc::STATX_ATTR_MOUNT_ROOT as u64;
/// The file type and mode bits, as `struct statx` holds them.
pub const S_IFMT: u16 = libc::S_IFMT as u16;
pub const S_IFREG: u16 = libc::S_IFREG as u16;
pub const S_IFDIR: u16 = libc::S_IFDIR as u16;
pub const S_IFLNK: u16 = libc::S_IFLNK as u16;
pub const S_IFCHR: u16 = libc::S_IFCHR as u16;
pub const S_IFBLK: u16 = libc::S_IFBLK as u16;
pub const S_ISVTX: u16 = libc::S_ISVTX as u16;
/// The system calls the C library does not wrap.
pub const SYS_ADD_KEY: c_long = libc::SYS_add_key;
pub const SYS_KEYCTL: c_long = libc::SYS_keyctl;
pub const SYS_PIDFD_OPEN: c_long = libc::SYS_pidfd_open;
/// `PER_LINUX` of sys/personality.h, which the crate does not name.
pub const PER_LINUX: c_ulong = 0;

/// A plain C struct of the crate, all of whose bits zeroed are a value:
/// its empty one, as the C's `= {}` makes it.
pub trait Zeroed: Sized {
    fn zeroed() -> Self {
        // SAFETY: implemented only for plain data, of integers, arrays
        // and pointers, which zeroed bits make valid.
        unsafe { core::mem::zeroed() }
    }
}

impl Zeroed for Statfs {}
impl Zeroed for Statvfs {}
impl Zeroed for Statx {}
impl Zeroed for Tm {}
impl Zeroed for Utsname {}
impl Zeroed for Msghdr {}

/// The kernel's netlink address.
pub fn netlink_kernel() -> SockaddrNl {
    let mut a: SockaddrNl = {
        // SAFETY: plain data, which zeroed bits make the empty address.
        unsafe { core::mem::zeroed() }
    };
    a.nl_family = AF_NETLINK as u16;
    a
}

// glibc's symbols the crate does not bind.
unsafe extern "C" {
    pub fn strerrorname_np(errnum: c_int) -> *const c_char;
    pub fn __nss_configure_lookup(db: *const c_char, service: *const c_char) -> c_int;
    pub static mut stdout: *mut File;
    pub static mut stderr: *mut File;
}

/// The bytes of a C character array of the crate's structs.
pub fn bytes(a: &[c_char]) -> &[u8] {
    // SAFETY: c_char and u8 have one size and alignment, and the bytes
    // are the array's.
    unsafe { core::slice::from_raw_parts(a.as_ptr().cast(), a.len()) }
}

pub fn set_errno(e: c_int) {
    // SAFETY: glibc gives each thread its errno, valid while it runs.
    unsafe { *libc::__errno_location() = e };
}

pub fn errno() -> c_int {
    // SAFETY: glibc gives each thread its errno, valid while it runs.
    unsafe { *libc::__errno_location() }
}

pub fn env(name: &CStr) -> Option<&'static CStr> {
    // SAFETY: a C string; nothing in shirudo changes the environment, so
    // what getenv() returns stays valid.
    let value = unsafe { getenv(name.as_ptr()) };

    if value.is_null() {
        return None;
    }
    // SAFETY: getenv() returns a C string.
    Some(unsafe { CStr::from_ptr(value) })
}

pub fn scrub(buf: &mut [u8]) {
    // SAFETY: buf is buf.len() writable bytes.
    unsafe { explicit_bzero(buf.as_mut_ptr().cast(), buf.len()) };
}
