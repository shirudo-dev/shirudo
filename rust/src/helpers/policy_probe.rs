// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! shirudo-policy-probe: the fixture the runtime image carries, static,
//! that the target tests run as a trusted or untrusted process: it reads
//! its own authority and policy from shirudo's pinned maps, sets and
//! removes policy labels, makes the filesystem changes and mappings the
//! seal and W^X guards judge, forks and execs as the inheritance tests
//! need, and waits with a word others try to write into.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::sync::atomic::{AtomicU64, Ordering};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

use super::out;
use crate::skel::bpf2::{TaskAuthority, TaskPolicy};
use crate::sys::identity::Identity;
use crate::util::bpf_sys::Attr;
use crate::util::paths::{POLICY_PIN, SOCKET_POLICY_PIN, XATTR_POLICY};

/// The word the process-tamper tests try to write into a waiting probe.
#[used]
static PROBE_WORD: AtomicU64 = AtomicU64::new(0x0053_4849_5255_444f);

const BPF_MAP_LOOKUP_ELEM: c_long = 1;
const BPF_OBJ_GET: c_long = 7;
const BPF_F_RDONLY: u32 = 1 << 3;

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// The map pinned at `pin`, open read-only, or the errno.
fn pin_open(pin: &CStr) -> Result<OwnedFd, c_int> {
    Attr::new()
        .ptr(0, pin.as_ptr())
        .u32(12, BPF_F_RDONLY)
        .fd(BPF_OBJ_GET)
}

/// The value of `key` in the map at `fd`, into `value`, or the errno.
fn lookup<K, V>(fd: &OwnedFd, key: &K, value: &mut V) -> Result<(), c_int> {
    Attr::new()
        .u32(0, fd.as_raw_fd() as u32)
        .ptr(8, key as *const K)
        .ptr(16, value as *mut V as *const V)
        .run(BPF_MAP_LOOKUP_ELEM)
        .map(drop)
}

/// This process, by a pidfd: the key of the task storage maps.
fn self_pidfd() -> Result<OwnedFd, c_int> {
    // SAFETY: pidfd_open(2) of this process.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
    if fd < 0 {
        return Err(errno());
    }
    // SAFETY: the descriptor just made, owned here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as c_int) })
}

/// Whether this task's authority in the map at `pin` is `expected`: 0,
/// or 1 when not. Only a task with authority may open the pin at all.
fn check_mark(pin: &CStr, expected: bool) -> c_int {
    let Ok(pidfd) = self_pidfd() else {
        return 1;
    };
    let fd = match pin_open(pin) {
        Ok(fd) => fd,
        Err(e) => return c_int::from(e != libc::EACCES || expected),
    };
    let mut authority = TaskAuthority::zeroed();
    match lookup(&fd, &pidfd.as_raw_fd(), &mut authority) {
        Err(e) if e != libc::ENOENT => 1,
        _ => c_int::from((authority.trusted != 0) != expected),
    }
}

/// This task's active policy bits in the map at `pin`.
fn read_policy(pin: &CStr) -> Result<u64, c_int> {
    let pidfd = self_pidfd()?;
    let fd = pin_open(pin)?;
    let mut policy = TaskPolicy::zeroed();
    lookup(&fd, &pidfd.as_raw_fd(), &mut policy)?;
    Ok(policy.active)
}

/// The policy bits of the socket at `socket`, 0 for none.
fn read_socket_policy(socket: c_int) -> Result<u64, c_int> {
    let fd = pin_open(SOCKET_POLICY_PIN)?;
    let mut value = 0u64;
    match lookup(&fd, &socket, &mut value) {
        Err(e) if e != libc::ENOENT => Err(e),
        _ => Ok(value),
    }
}

fn check_socket_policy(socket: c_int, expected: u64) -> c_int {
    c_int::from(read_socket_policy(socket) != Ok(expected))
}

/// As strtoull() of base 0, the whole text a number.
fn parse_policy(text: &[u8]) -> Option<u64> {
    let t = std::str::from_utf8(text).ok()?;
    let (radix, digits) = match t.as_bytes() {
        [b'0', b'x' | b'X', ..] => (16, &t[2..]),
        [b'0', _, ..] => (8, &t[1..]),
        _ => (10, t),
    };
    u64::from_str_radix(digits, radix).ok()
}

fn env(name: &str) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStringExt;
    std::env::var_os(name).map(|v| v.into_vec())
}

fn set_env(name: &str, value: &str) {
    // SAFETY: the environment, which this one thread alone touches.
    unsafe { std::env::set_var(name, value) };
}

/// The child the socket test execs: its policy, and the one of the
/// connection it accepts on the listener it inherited.
fn accept_child() -> c_int {
    let (Some(listener), Some(task), Some(socket)) = (
        env("SHIRUDO_TEST_LISTENER"),
        env("SHIRUDO_TEST_TASK_BITS"),
        env("SHIRUDO_TEST_SOCKET_BITS"),
    ) else {
        return 1;
    };
    let (Some(task_bits), Some(socket_bits)) = (parse_policy(&task), parse_policy(&socket)) else {
        return 1;
    };
    let Some(listener) = std::str::from_utf8(&listener)
        .ok()
        .and_then(|l| l.parse::<c_int>().ok())
        .filter(|&l| l >= 0)
    else {
        return 1;
    };
    if read_policy(POLICY_PIN) != Ok(task_bits) {
        return 1;
    }
    // SAFETY: the inherited listener, and no room for the peer.
    let accepted = unsafe { libc::accept(listener, core::ptr::null_mut(), core::ptr::null_mut()) };
    if accepted < 0 {
        return 1;
    }
    check_socket_policy(accepted, socket_bits)
}

fn setxattr_policy(path: &CStr, value: u64) -> bool {
    // SAFETY: a C string, the attribute's name and its 8 bytes.
    unsafe {
        libc::setxattr(
            path.as_ptr(),
            XATTR_POLICY.as_ptr(),
            (&raw const value).cast(),
            8,
            0,
        ) == 0
    }
}

/// A listener of this task's policy, an acceptor script beside `script`
/// labelled with `extra`, which it execs, and a connection it accepts,
/// which must carry the listener's policy alone.
fn socket_inheritance(script: &CStr, extra: u64) -> c_int {
    let active = match read_policy(POLICY_PIN) {
        Ok(a) if a != 0 => a,
        _ => return 1,
    };
    // SAFETY: socket(2) of numbers.
    let listener = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if listener < 0 || check_socket_policy(listener, active) != 0 {
        return 1;
    }
    // SAFETY: an address of zeros, set to the loopback, any port.
    let mut addr: libc::sockaddr_in = unsafe { core::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::LOCALHOST).to_be();
    let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let sa = (&raw mut addr).cast::<libc::sockaddr>();
    // SAFETY: the listener and its address, of its size.
    if unsafe {
        libc::bind(listener, sa, len) != 0
            || libc::listen(listener, 1) != 0
            || libc::getsockname(listener, sa, &mut len) != 0
    } {
        return 1;
    }
    let Ok(acceptor) = CString::new([script.to_bytes(), b".acceptor"].concat()) else {
        return 1;
    };
    let acceptor_path = std::path::Path::new(std::ffi::OsStr::from_bytes(acceptor.to_bytes()));
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o700)
            .open(acceptor_path)
            .and_then(|mut f| {
                f.write_all(b"#!/run/shirudo/runtime/usr/bin/shirudo-policy-probe accept-child\n")
            });
        if written.is_err() || !setxattr_policy(&acceptor, extra) {
            return 1;
        }
    }
    set_env("SHIRUDO_TEST_LISTENER", &listener.to_string());
    set_env("SHIRUDO_TEST_TASK_BITS", &format!("0x{:x}", active | extra));
    set_env("SHIRUDO_TEST_SOCKET_BITS", &format!("0x{active:x}"));
    // SAFETY: a fork of this one-threaded process; the child execs the
    // acceptor or exits.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return 1;
    }
    if child == 0 {
        let argv = [acceptor.as_ptr(), core::ptr::null()];
        // SAFETY: the acceptor and its argument vector, then the exit.
        unsafe {
            libc::execv(acceptor.as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }
    // SAFETY: a socket of numbers, connected to the listener's address.
    let client = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if client < 0 {
        return 1;
    }
    // SAFETY: the client and the listener's address.
    if unsafe {
        libc::connect(
            client,
            sa,
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    } != 0
    {
        return 1;
    }
    let mut status = 0;
    // SAFETY: the client, closed; the child and room for its status; the
    // listener, closed.
    unsafe {
        libc::close(client);
        if libc::waitpid(child, &mut status, 0) != child {
            return 1;
        }
        libc::close(listener);
    }
    let _ = std::fs::remove_file(acceptor_path);
    c_int::from(!libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0)
}

fn set_policy(path: &CStr, text: &CStr) -> c_int {
    match parse_policy(text.to_bytes()) {
        Some(v) => c_int::from(!setxattr_policy(path, v)),
        None => 2,
    }
}

fn remove_policy(path: &CStr) -> c_int {
    let mut value = 0u64;
    // SAFETY: a C string and the attribute's name, and room for its value.
    unsafe {
        if libc::removexattr(path.as_ptr(), XATTR_POLICY.as_ptr()) != 0 {
            return 1;
        }
        let n = libc::getxattr(
            path.as_ptr(),
            XATTR_POLICY.as_ptr(),
            (&raw mut value).cast(),
            8,
        );
        c_int::from(!(n < 0 && errno() == libc::ENODATA))
    }
}

fn check_policy(text: &[u8]) -> c_int {
    match (parse_policy(text), read_policy(POLICY_PIN)) {
        (Some(expected), Ok(active)) => c_int::from(active != expected),
        _ => 1,
    }
}

fn check_policy_env() -> c_int {
    env("SHIRUDO_EXPECTED_POLICY").map_or(1, |e| check_policy(&e))
}

/// A child execed with its expected policy in the environment, after
/// this task's own is checked.
fn fork_exec_policy_env() -> c_int {
    let (Some(path), Some(parent), Some(expected)) = (
        env("SHIRUDO_POLICY_CHILD"),
        env("SHIRUDO_POLICY_PARENT"),
        env("SHIRUDO_POLICY_CHILD_EXPECTED"),
    ) else {
        return 1;
    };
    if check_policy(&parent) != 0 {
        return 1;
    }
    let (Ok(path), Ok(expected)) = (CString::new(path), String::from_utf8(expected)) else {
        return 1;
    };
    // SAFETY: a fork of this one-threaded process; the child execs or
    // exits.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return 1;
    }
    if child == 0 {
        set_env("SHIRUDO_EXPECTED_POLICY", &expected);
        let argv = [path.as_ptr(), core::ptr::null()];
        // SAFETY: the program and its argument vector, then the exit.
        unsafe {
            libc::execv(path.as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }
    let mut status = 0;
    // SAFETY: the child and room for its status.
    if unsafe { libc::waitpid(child, &mut status, 0) } != child {
        return 1;
    }
    c_int::from(!libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0)
}

fn print_identity(pin: &CStr, field: &[u8]) -> c_int {
    let Ok(fd) = pin_open(pin) else {
        return 1;
    };
    let mut id = Identity::zeroed();
    if lookup(&fd, &0u32, &mut id).is_err() {
        return 1;
    }
    let hex = |b: &[u8]| String::from_utf8_lossy(&crate::util::hex::encode(b)).into_owned();
    match field {
        b"runtime_root" => out(&format!("{}\n", hex(&id.runtime_root))),
        b"nv_writer_public" => out(&format!("{}\n", hex(&id.nv_writer_public))),
        b"nv_index" => out(&format!("{}\n", id.nv_index)),
        b"config_pcr" => out(&format!("{}\n", id.config_pcr)),
        _ => return 2,
    }
    0
}

/// mmap(2), MAP_FAILED as None with errno kept.
fn map(len: usize, prot: c_int, flags: c_int, fd: c_int) -> Option<*mut c_void> {
    // SAFETY: a new mapping, of nothing of this process's.
    let m = unsafe { libc::mmap(core::ptr::null_mut(), len, prot, flags, fd, 0) };
    (m != libc::MAP_FAILED).then_some(m)
}

/// Whether mprotect(2) of `m` to `prot` is refused with EACCES.
fn protect_refused(m: *mut c_void, len: usize, prot: c_int) -> bool {
    // SAFETY: the caller's mapping of len bytes.
    unsafe { libc::mprotect(m, len, prot) != 0 && errno() == libc::EACCES }
}

fn unmap(m: *mut c_void, len: usize) {
    // SAFETY: the caller's mapping, unmapped once.
    unsafe { libc::munmap(m, len) };
}

/// W^X as the guards keep it: no executable anonymous memory, no file
/// mapped executable from outside the trusted image, and no mapping of a
/// trusted file made writable then executable.
fn check_mappings(trusted: &CStr, outside: &CStr) -> c_int {
    use libc::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};
    // SAFETY: sysconf(3) of a number.
    let len = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let checks = || -> Option<()> {
        if map(len, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1).is_some()
            || errno() != libc::EACCES
        {
            return None;
        }
        let m = map(len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1)?;
        if !protect_refused(m, len, PROT_READ | PROT_EXEC) {
            return None;
        }
        unmap(m, len);
        let outside = std::fs::File::open(std::ffi::OsStr::from_bytes(outside.to_bytes())).ok()?;
        let refused = map(len, PROT_READ | PROT_EXEC, MAP_PRIVATE, outside.as_raw_fd()).is_none()
            && errno() == libc::EACCES;
        drop(outside);
        if !refused {
            return None;
        }
        let trusted = std::fs::File::open(std::ffi::OsStr::from_bytes(trusted.to_bytes())).ok()?;
        let m = map(len, PROT_READ | PROT_EXEC, MAP_PRIVATE, trusted.as_raw_fd())?;
        if !protect_refused(m, len, PROT_READ | PROT_WRITE) {
            return None;
        }
        unmap(m, len);
        let m = map(
            len,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE,
            trusted.as_raw_fd(),
        )?;
        drop(trusted);
        // SAFETY: the mapping just made.
        if unsafe { libc::mprotect(m, len, PROT_READ) } != 0
            || !protect_refused(m, len, PROT_READ | PROT_EXEC)
        {
            return None;
        }
        unmap(m, len);
        Some(())
    };
    c_int::from(checks().is_none())
}

/// As atoi(): the leading decimal number, 0 for none.
fn atoi(text: &[u8]) -> i64 {
    let (neg, rest) = match text {
        [b'-', rest @ ..] => (true, rest),
        [b'+', rest @ ..] => (false, rest),
        _ => (false, text),
    };
    let n = rest.iter().take_while(|c| c.is_ascii_digit()).count();
    let v: i64 = std::str::from_utf8(&rest[..n])
        .ok()
        .and_then(|d| d.parse().ok())
        .unwrap_or(0);
    if neg { -v } else { v }
}

fn wait(ready: &CStr) -> c_int {
    use std::io::Write;
    let line = format!(
        "{} {:x}\n",
        std::process::id(),
        (&raw const PROBE_WORD) as usize
    );
    let written = std::fs::File::create(std::ffi::OsStr::from_bytes(ready.to_bytes()))
        .and_then(|mut f| f.write_all(line.as_bytes()));
    if written.is_err() {
        return 1;
    }
    let _ = PROBE_WORD.load(Ordering::Relaxed);
    loop {
        // SAFETY: a wait for a signal.
        unsafe { libc::pause() };
    }
}

/// # Safety
///
/// The arguments the C runtime passes main().
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shirudo_helper_shirudo_policy_probe(
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // SAFETY: main()'s arguments.
    let args = unsafe { crate::ffi::args(argc, argv) };
    let n = args.len();
    let how = args.get(1).map_or(&b""[..], |a| a.to_bytes());
    let a = |i: usize| args[i];
    match (how, n) {
        // As a script's interpreter the script's path follows the mode.
        (b"secure", _) => {
            // SAFETY: getauxval(3) of a number.
            out(&format!("{}\n", unsafe {
                libc::getauxval(libc::AT_SECURE)
            }));
            0
        }
        (b"set-policy", 4) => set_policy(a(2), a(3)),
        (b"remove-policy", 3) => remove_policy(a(2)),
        (b"check-policy", _) => check_policy_env(),
        (b"fork-exec-policy", _) => fork_exec_policy_env(),
        (b"socket-inherit", 3..) => socket_inheritance(a(2), 2),
        (b"accept-child", _) => accept_child(),
        (_, 0..=2) => 2,
        (b"unlink", _) => {
            c_int::from(std::fs::remove_file(std::ffi::OsStr::from_bytes(a(2).to_bytes())).is_err())
        }
        // SAFETY: a C string and a mode.
        (b"mkdir", _) => c_int::from(unsafe { libc::mkdir(a(2).as_ptr(), 0o700) } != 0),
        (b"rmdir", _) => {
            c_int::from(std::fs::remove_dir(std::ffi::OsStr::from_bytes(a(2).to_bytes())).is_err())
        }
        // SAFETY: two C strings.
        (b"symlink", 4) => c_int::from(unsafe { libc::symlink(a(2).as_ptr(), a(3).as_ptr()) } != 0),
        (b"create", _) => {
            use std::os::unix::fs::OpenOptionsExt;
            let made = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(std::ffi::OsStr::from_bytes(a(2).to_bytes()));
            c_int::from(made.is_err())
        }
        (b"wait", _) => wait(a(2)),
        (b"identity", 4) => print_identity(a(2), a(3).to_bytes()),
        (b"mark", 4) => check_mark(a(2), atoi(a(3).to_bytes()) != 0),
        (b"failed-exec", _) => {
            let (target, want) = if n == 4 {
                (a(3), libc::ENOEXEC)
            } else {
                (c"/no-such-shirudo-test-executable", libc::ENOENT)
            };
            let argv = [c"missing".as_ptr(), core::ptr::null()];
            // SAFETY: a C string and an argument vector ending in NULL.
            unsafe { libc::execv(target.as_ptr(), argv.as_ptr()) };
            if errno() != want {
                return 1;
            }
            check_mark(a(2), true)
        }
        (b"fork", _) => {
            // SAFETY: a fork of this one-threaded process; the child
            // checks its mark and exits.
            let child = unsafe { libc::fork() };
            if child < 0 {
                return 1;
            }
            if child == 0 {
                // SAFETY: the child gone with its answer.
                unsafe { libc::_exit(check_mark(a(2), true)) };
            }
            let mut status = 0;
            // SAFETY: the child and room for its status.
            if unsafe { libc::waitpid(child, &mut status, 0) } != child {
                return 1;
            }
            c_int::from(!libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0)
        }
        (b"exec", 5) => {
            let next = [
                a(3).as_ptr(),
                c"mark".as_ptr(),
                a(2).as_ptr(),
                a(4).as_ptr(),
                core::ptr::null(),
            ];
            // SAFETY: a C string and an argument vector ending in NULL.
            unsafe { libc::execv(a(3).as_ptr(), next.as_ptr()) };
            1
        }
        (b"mappings", 4) => check_mappings(a(2), a(3)),
        _ => 2,
    }
}
