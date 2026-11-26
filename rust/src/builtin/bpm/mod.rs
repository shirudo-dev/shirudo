// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo bpm`: signed target-local packages from OCI repositories,
//! their signing certificates and the signed upatch tree a target
//! syncs. What only an operator runs goes to shirudo-build.

mod cleanup;
mod cli;
mod fetch;
mod info;
mod install;
mod key;
mod package;
mod source;
mod tree;

use core::ffi::{CStr, c_int};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

use crate::errno::{EINVAL, EIO, ENAMETOOLONG};
use crate::ffi;
use crate::sys::curl::{CURL_GLOBAL_DEFAULT, CURLE_OK, curl_global_cleanup, curl_global_init};
use crate::sys::libc::{
    Dir, LOCK_UN, PATH_MAX, closedir, errno, fdopendir, flock, fwrite, opendir, readdir, stdout,
    strerror, unlink,
};
use crate::util::identity;
use crate::util::io::lock_exclusive;
use crate::util::seal;

/// A negative errno, or a command's own non-zero status.
type Result<T = ()> = core::result::Result<T, c_int>;

const KEYS_DIR: &str = "/var/lib/shirudo/keys";
const CERT_PATH: &CStr = c"/var/lib/shirudo/keys/cert.der";
const LOCKS_DIR: &CStr = c"/var/lib/shirudo/locks";
const LOCK_PATH: &CStr = c"/var/lib/shirudo/locks/bpm.lock";
const REGISTRIES_DIR: &str = "/etc/shirudo/bpm/registries.d";
const BPM_KEYS_DIR: &str = "/etc/shirudo/bpm/keys";
const REPOS_DIR: &str = "/var/lib/shirudo/bpm/repos";
const PACKAGES_DIR: &str = "/var/lib/shirudo/bpm/packages";
const STAGING_DIR: &str = "/var/lib/shirudo/bpm/staging";
const TREE_ETC_PATH: &CStr = c"/etc/shirudo/bpm/upatch-tree.conf";
const TREE_PENDING_PATH: &CStr = c"/var/lib/shirudo/bpm/upatch-tree/pending.json";
const TREE_ARTIFACTS_DIR: &str = "/var/lib/shirudo/bpm/upatch-tree/artifacts";
const TREE_STATUS_DIR: &str = "/var/lib/shirudo/bpm/upatch-tree/status";
const INDEX_REPOSITORY_NAME: &[u8] = b"bpm-index";
const INDEX_TAG: &[u8] = b"stable";
const INDEX_MEDIA: &CStr = c"application/vnd.shirudo.bpm.index.v1+json";
const INDEX_SIG_MEDIA: &CStr = c"application/vnd.shirudo.bpm.index.signature.v1";
const PACKAGE_MEDIA: &CStr = c"application/vnd.shirudo.bpm.package.v1+gzip";
const UPATCH_MEDIA: &CStr = c"application/vnd.shirudo.upatch.v1";

/// A path of `parts` one after another, as C takes one: shorter than
/// PATH_MAX, or -ENAMETOOLONG.
fn path(parts: &[&[u8]]) -> Result<CString> {
    let joined = parts.concat();

    if joined.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    CString::new(joined).map_err(|_| -EINVAL)
}

/// The errno of an I/O error, negated.
fn os_err(e: io::Error) -> c_int {
    -e.raw_os_error().unwrap_or(EIO)
}

/// The last errno, negated.
fn last_err() -> c_int {
    -errno()
}

fn status(ret: c_int) -> Result {
    if ret == 0 { Ok(()) } else { Err(ret) }
}

/// The text of errno `err`.
fn strerr(err: c_int) -> &'static [u8] {
    // SAFETY: strerror() gives a C string that outlives the message.
    unsafe { ffi::c_str(strerror(err)) }
}

/// Bytes to the stdio stdout the rest of shirudo prints through.
fn print(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stdout.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stdout) };
}

/// A C string of `parts`, a NUL among them cutting it short.
fn message(parts: &[&[u8]]) -> CString {
    let mut text = parts.concat();

    if let Some(nul) = text.iter().position(|&c| c == 0) {
        text.truncate(nul);
    }
    CString::new(text).unwrap_or_default()
}

/// An error, logged and escaped.
fn error(parts: &[&[u8]]) {
    let msg = message(parts);

    crate::log::err(msg.to_bytes());
}

fn warn(parts: &[&[u8]]) {
    let msg = message(parts);

    crate::log::warn(msg.to_bytes());
}

/// What a failed bpm command says: 1.
fn fail(action: &[u8], ret: c_int) -> c_int {
    if ret < 0 {
        error(&[b"bpm ", action, b": ", strerr(-ret)]);
    } else {
        error(&[b"bpm ", action, b" failed"]);
    }
    1
}

/// A package changes state only where Shirudo enforces policy.
fn needs_enforcement(action: &[u8]) -> c_int {
    let active = identity::enforcement_active();
    if active > 0 {
        return 0;
    }
    if active < 0 {
        return fail(action, active);
    }
    error(&[
        b"bpm ",
        action,
        b": enforcement is not active; run shirudo init first",
    ]);
    1
}

/// The bpm lock, held until it goes.
struct Lock(OwnedFd);

impl Drop for Lock {
    fn drop(&mut self) {
        // SAFETY: the lock's own fd, which closes after.
        unsafe { flock(self.0.as_raw_fd(), LOCK_UN) };
    }
}

fn lock() -> Result<Lock> {
    let active = identity::enforcement_active();
    if active < 0 {
        return Err(active);
    }
    if active == 0 {
        seal::mkdir_p(LOCKS_DIR.to_bytes(), 0o700)?;
        return seal::lock(LOCK_PATH.to_bytes()).map(Lock);
    }
    let fd = identity::state_root_open()?;
    lock_exclusive(fd.as_fd())?;
    Ok(Lock(fd))
}

/// The end of a command that set curl up: the lock released, curl torn
/// down and a failure said.
fn finish(lock: Option<Lock>, ret: Result, action: &[u8]) -> c_int {
    drop(lock);
    // SAFETY: curl's global state, set up before.
    unsafe { curl_global_cleanup() };
    match ret {
        Ok(()) => 0,
        Err(err) => fail(action, err),
    }
}

fn curl_ready() -> bool {
    // SAFETY: curl's global set-up, which a command runs once.
    unsafe { curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK }
}

fn remove(path: &CStr) {
    // SAFETY: a C string.
    unsafe { unlink(path.as_ptr()) };
}

/// A file of source or tree settings, read one line at a time.
struct Stream(BufReader<File>);

impl Stream {
    /// A stream on `fd`, which it takes over, or the -errno `fd` is.
    fn from_fd(fd: c_int) -> Result<Stream> {
        if fd < 0 {
            return Err(fd);
        }
        // SAFETY: an fd the caller hands over.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Stream(BufReader::new(File::from(fd))))
    }

    /// Each line of at most PATH_MAX - 1 bytes to `each`, including its
    /// newline and a final NUL. A NUL in the file is invalid.
    fn lines(&mut self, mut each: impl FnMut(&mut [u8]) -> Result) -> Result {
        let mut line = Vec::new();

        loop {
            line.clear();
            let n = (&mut self.0)
                .take(PATH_MAX as u64 + 1)
                .read_until(b'\n', &mut line)
                .map_err(|e| -e.raw_os_error().unwrap_or(EIO))?;
            if n == 0 {
                return Ok(());
            }
            if line.contains(&0) {
                return Err(-EINVAL);
            }
            if n == PATH_MAX + 1 && line.last() != Some(&b'\n') {
                return Err(-crate::errno::E2BIG);
            }
            let text_len = n - usize::from(line.last() == Some(&b'\n'));
            if text_len > PATH_MAX - 1 {
                return Err(-crate::errno::E2BIG);
            }
            line.try_reserve(1).map_err(|_| -crate::errno::ENOMEM)?;
            line.push(0);
            each(&mut line)?;
        }
    }
}

/// A directory stream, closed when it goes.
struct DirStream(*mut Dir);

impl DirStream {
    fn open(path: &CStr) -> Result<DirStream> {
        // SAFETY: a C string.
        let d = unsafe { opendir(path.as_ptr()) };
        if d.is_null() {
            return Err(last_err());
        }
        Ok(DirStream(d))
    }

    /// A stream on `fd`, which it takes over, or the -errno `fd` is.
    fn from_fd(fd: c_int) -> Result<DirStream> {
        if fd < 0 {
            return Err(fd);
        }
        // SAFETY: an fd the caller hands over.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: the fd, which the stream owns once open.
        let d = unsafe { fdopendir(fd.as_raw_fd()) };
        if d.is_null() {
            return Err(last_err());
        }
        core::mem::forget(fd);
        Ok(DirStream(d))
    }
}

impl Iterator for DirStream {
    type Item = Vec<u8>;

    /// The next name, ".", ".." and all, until the end or an error.
    fn next(&mut self) -> Option<Vec<u8>> {
        // SAFETY: the stream's own DIR.
        let e = unsafe { readdir(self.0) };
        if e.is_null() {
            return None;
        }
        // SAFETY: readdir() gives an entry whose name is a C string.
        Some(unsafe { ffi::c_str((*e).d_name.as_ptr()) }.to_vec())
    }
}

impl Drop for DirStream {
    fn drop(&mut self) {
        // SAFETY: the stream's own DIR.
        unsafe { closedir(self.0) };
    }
}

/// `shirudo bpm`, on `args` from its name on.
pub(crate) fn cmd_bpm(args: &[&CStr]) -> c_int {
    cli::run(args)
}

/// For the image CLI test: the key file registered source `name`
/// verifies with, open as `bpm repo update` opens it, or -errno.
#[cfg(feature = "test-helpers")]
pub(crate) fn source_key_open(name: &[u8]) -> c_int {
    match source::load(name) {
        Ok(s) => s.key_open(),
        Err(err) => err,
    }
}

#[cfg(test)]
mod line_tests {
    use super::{PATH_MAX, Result, Stream};
    use crate::errno::{E2BIG, EINVAL};
    use std::io::Write;
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;

    fn read_lines(text: &[u8]) -> Result<Vec<Vec<u8>>> {
        let (read, mut write) = UnixStream::pair().unwrap();
        write.write_all(text).unwrap();
        drop(write);
        let mut stream = Stream::from_fd(read.into_raw_fd())?;
        let mut lines = Vec::new();
        stream.lines(|line| {
            lines.push(line.to_vec());
            Ok(())
        })?;
        Ok(lines)
    }

    #[test]
    fn keeps_newline_and_nul_terminator() {
        assert_eq!(
            read_lines(b"one\r\ntwo").unwrap(),
            vec![b"one\r\n\0".to_vec(), b"two\0".to_vec()]
        );
        assert!(read_lines(b"").unwrap().is_empty());
    }

    #[test]
    fn rejects_nul_and_long_lines() {
        assert_eq!(read_lines(b"a\0b\n"), Err(-EINVAL));
        let mut longest = vec![b'a'; PATH_MAX - 1];
        longest.push(b'\n');
        assert_eq!(read_lines(&longest).unwrap()[0].len(), PATH_MAX + 1);
        let mut too_long = vec![b'a'; PATH_MAX];
        too_long.push(b'\n');
        assert_eq!(read_lines(&too_long), Err(-E2BIG));
    }
}
