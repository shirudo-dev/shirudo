// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! tpmsim-cmd: a TPM 2.0 of libtpms for tss2's "cmd" TCTI: commands on
//! stdin, responses on stdout, its state kept in the directory named.
//!
//!   tpmsim-cmd <state dir>
//!
//! make links it with libtpms; the other helpers drop this module.

use core::ffi::{CStr, c_int, c_void};
use core::sync::atomic::{AtomicI32, Ordering};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;

use super::{err, helper_main, perror};

helper_main!(shirudo_helper_tpmsim_cmd, run);

type TpmResult = u32;
const TPM_SUCCESS: TpmResult = 0;
/// TPMLIB_TPM_VERSION_2, TPMLIB_STATE_PERMANENT and _VOLATILE.
const TPM_VERSION_2: c_int = 1;
const STATE_PERMANENT: c_int = 1;
const STATE_VOLATILE: c_int = 2;
const SIM_CMD_MAX: usize = 64 * 1024;

unsafe extern "C" {
    fn TPMLIB_ChooseTPMVersion(version: c_int) -> TpmResult;
    fn TPMLIB_SetState(st: c_int, buffer: *const u8, len: u32) -> TpmResult;
    fn TPMLIB_GetState(st: c_int, buffer: *mut *mut u8, len: *mut u32) -> TpmResult;
    fn TPMLIB_MainInit() -> TpmResult;
    fn TPMLIB_Process(
        resp: *mut *mut u8,
        resp_size: *mut u32,
        resp_cap: *mut u32,
        command: *mut u8,
        len: u32,
    ) -> TpmResult;
    fn TPMLIB_Terminate();
}

/// TPM2_Startup(TPM_SU_CLEAR): sent when no volatile state was restored.
const STARTUP_CLEAR: [u8; 12] = [
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
];

/// The write end of the pipe SIGTERM writes to.
static SHUTDOWN: AtomicI32 = AtomicI32::new(-1);

/// tss2's "cmd" TCTI reaps this process with SIGTERM before it closes
/// stdin, so a read never sees the EOF that would have the state saved.
/// The signal goes through a pipe and is taken as EOF instead.
extern "C" fn request_shutdown(_: c_int) {
    let byte = 0u8;
    // SAFETY: one byte to the pipe, which write() alone touches in a
    // handler.
    unsafe {
        libc::write(
            SHUTDOWN.load(Ordering::Relaxed),
            (&raw const byte).cast(),
            1,
        )
    };
}

/// The pipe's read end, with SIGTERM routed to it.
fn install_shutdown_handler() -> Option<OwnedFd> {
    let mut fds = [0; 2];
    // SAFETY: room for the pipe, its write end made non-blocking, and a
    // handler that only writes to it.
    unsafe {
        if libc::pipe(fds.as_mut_ptr()) != 0
            || libc::fcntl(fds[1], libc::F_SETFL, libc::O_NONBLOCK) != 0
        {
            return None;
        }
        SHUTDOWN.store(fds[1], Ordering::Relaxed);
        // SAFETY: a zeroed sigaction has a null handler and empty mask.
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = request_shutdown as extern "C" fn(c_int) as usize;
        if libc::sigaction(libc::SIGTERM, &sa, core::ptr::null_mut()) != 0 {
            return None;
        }
        Some(OwnedFd::from_raw_fd(fds[0]))
    }
}

/// Whether a command is on stdin: Some(true), or Some(false) for a
/// shutdown asked for; None on an error.
fn wait_for_command(shutdown: &OwnedFd) -> Option<bool> {
    let mut pfd = [
        libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: shutdown.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: the two descriptors to wait on.
        let ret = unsafe { libc::poll(pfd.as_mut_ptr(), pfd.len() as libc::nfds_t, -1) };
        if ret >= 0 {
            return Some(pfd[1].revents & libc::POLLIN == 0);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return None;
        }
    }
}

/// The state directory held for as long as this instance runs: a caller
/// that exits, or whose shell stays between it and this process, goes on
/// before the state is saved, and the next instance would load what this
/// one has not written yet.
fn lock_state() -> Option<std::fs::File> {
    let dir = std::fs::File::open(".").ok()?;
    loop {
        // SAFETY: the directory's descriptor.
        if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Some(dir);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return None;
        }
    }
}

/// A saved state blob of 1 byte to 16 MiB.
fn load_blob(path: &str) -> Option<Vec<u8>> {
    let blob = std::fs::read(path).ok()?;
    (!blob.is_empty() && blob.len() <= 16 * 1024 * 1024).then_some(blob)
}

/// `blob` written to a new file and moved over `path`.
fn store_blob(path: &str, blob: &[u8]) -> bool {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = format!("{path}.tmp");
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(blob))
        .and_then(|()| std::fs::rename(&tmp, path))
        .is_ok()
}

/// The response libtpms keeps, which it grows as it needs.
struct Response {
    buf: *mut u8,
    size: u32,
    cap: u32,
}

impl Response {
    fn process(&mut self, command: &mut [u8]) -> Option<&[u8]> {
        // SAFETY: libtpms's response buffer, which it reallocates, and the
        // command's bytes.
        let r = unsafe {
            TPMLIB_Process(
                &mut self.buf,
                &mut self.size,
                &mut self.cap,
                command.as_mut_ptr(),
                command.len() as u32,
            )
        };
        // SAFETY: the response's size bytes, which libtpms wrote.
        (r == TPM_SUCCESS).then(|| unsafe { crate::ffi::slice(self.buf, self.size as usize) })
    }
}

impl Drop for Response {
    fn drop(&mut self) {
        // SAFETY: the buffer libtpms allocated with malloc(), or NULL.
        unsafe { libc::free(self.buf.cast::<c_void>()) };
    }
}

fn save_state() -> bool {
    let mut ok = true;
    for (st, name) in [(STATE_PERMANENT, "permanent"), (STATE_VOLATILE, "volatile")] {
        let (mut blob, mut len): (*mut u8, u32) = (core::ptr::null_mut(), 0);
        // SAFETY: rooms for the blob libtpms allocates, freed once.
        unsafe {
            if TPMLIB_GetState(st, &mut blob, &mut len) != TPM_SUCCESS || blob.is_null() {
                ok = false;
                continue;
            }
            ok &= store_blob(name, crate::ffi::slice(blob, len as usize));
            libc::free(blob.cast());
        }
    }
    ok
}

/// The commands of stdin answered until EOF or SIGTERM: 0, or 1 for a
/// malformed or failed command.
fn serve(shutdown: &OwnedFd, resp: &mut Response) -> c_int {
    // Unbuffered, as poll() must see every byte not yet read, and each
    // response must go out before the next command comes.
    // SAFETY: the process's standard streams, borrowed and not closed.
    let (mut stdin, mut stdout) = unsafe {
        (
            core::mem::ManuallyDrop::new(std::fs::File::from_raw_fd(libc::STDIN_FILENO)),
            core::mem::ManuallyDrop::new(std::fs::File::from_raw_fd(libc::STDOUT_FILENO)),
        )
    };
    let mut cmd = vec![0u8; SIM_CMD_MAX];
    loop {
        match wait_for_command(shutdown) {
            None => return 1,
            Some(false) => return 0,
            Some(true) => {}
        }
        if stdin.read_exact(&mut cmd[..10]).is_err() {
            return 0;
        }
        let len = u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]) as usize;
        if !(10..=SIM_CMD_MAX).contains(&len)
            || (len > 10 && stdin.read_exact(&mut cmd[10..len]).is_err())
        {
            return 1;
        }
        match resp.process(&mut cmd[..len]) {
            Some(r) if stdout.write_all(r).is_ok() => {}
            _ => return 1,
        }
    }
}

fn run(args: &[&CStr]) -> c_int {
    let [_, dir] = args else {
        err("usage: tpmsim-cmd <state-dir>\n");
        return 2;
    };
    let dir = std::path::Path::new(std::ffi::OsStr::from_bytes(dir.to_bytes()));
    let made = std::fs::DirBuilder::new().mode(0o700).create(dir);
    if matches!(made, Err(ref e) if e.kind() != std::io::ErrorKind::AlreadyExists)
        || std::env::set_current_dir(dir).is_err()
    {
        perror("tpmsim-cmd: state directory");
        return 1;
    }
    let Some(_lock) = lock_state() else {
        perror("tpmsim-cmd: state lock");
        return 1;
    };
    let Some(shutdown) = install_shutdown_handler() else {
        perror("tpmsim-cmd: shutdown handler");
        return 1;
    };
    // SAFETY: the environment, which this one thread alone touches.
    unsafe { std::env::set_var("TPM_PATH", ".") };
    // SAFETY: libtpms's calls, on its state blobs, made in its order.
    unsafe {
        if TPMLIB_ChooseTPMVersion(TPM_VERSION_2) != TPM_SUCCESS {
            err("tpmsim-cmd: TPM 2.0 unsupported by libtpms\n");
            return 1;
        }
        let permanent = load_blob("permanent");
        if let Some(p) = &permanent
            && TPMLIB_SetState(STATE_PERMANENT, p.as_ptr(), p.len() as u32) != TPM_SUCCESS
        {
            err("tpmsim-cmd: permanent state rejected\n");
            return 1;
        }
        let volatile = permanent.as_ref().and_then(|_| load_blob("volatile"));
        if let Some(v) = &volatile
            && TPMLIB_SetState(STATE_VOLATILE, v.as_ptr(), v.len() as u32) != TPM_SUCCESS
        {
            err("tpmsim-cmd: volatile state rejected\n");
            return 1;
        }
        if TPMLIB_MainInit() != TPM_SUCCESS {
            err("tpmsim-cmd: TPMLIB_MainInit failed\n");
            return 1;
        }
        let mut resp = Response {
            buf: core::ptr::null_mut(),
            size: 0,
            cap: 0,
        };
        // No volatile state means a power cycle: PCRs and STCLEAR reset.
        if volatile.is_none() && resp.process(&mut STARTUP_CLEAR.clone()).is_none() {
            err("tpmsim-cmd: TPM2_Startup failed\n");
            return 1;
        }
        let mut ret = serve(&shutdown, &mut resp);
        if !save_state() {
            err("tpmsim-cmd: saving TPM state failed\n");
            ret = 1;
        }
        TPMLIB_Terminate();
        ret
    }
}
