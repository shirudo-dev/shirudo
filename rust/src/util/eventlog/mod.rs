// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The eventlog: one JSON line per register
//! extension, appended only after the extend succeeded, so that a replay
//! reproduces the live value. A walk reads the log and the record the
//! initrd left pending, and hands each line on, terminated in place as
//! strtok_r() left it.

#[cfg(shirudo_fuzz)]
mod fuzz;
mod records;

#[cfg(test)]
pub(crate) use records::UPATCH_LOAD;
pub(crate) use records::upatch_record;
pub(crate) use records::{
    EventlogInit, UPATCH_INIT, UPATCH_UNLOAD, UpatchFn, boot_init, boot_lines, replay,
    tree_op_measured, upatch_kind_parse, upatch_record_parse, upatches, upatches_record,
};

use core::ffi::{CStr, c_int};

use crate::errno::{EFBIG, EINVAL, ENAMETOOLONG, ENOENT, text};
use crate::sys::libc::Zeroed;
use crate::sys::libc::{
    AT_FDCWD, F_OK, O_CLOEXEC, O_RDONLY, PATH_MAX, STATX_SIZE, Statx, access, close, env, errno,
    open, read, statx, unlink,
};
use crate::text::cstr;
use crate::util::crypto_openssl::sha256_into;
use crate::util::hex::encode;
use crate::util::identity;
use crate::util::image_config;
use crate::util::io::lock_exclusive;
use crate::util::json::{JsonEmit, JsonField, MAX_BYTES, parse_schema};
use crate::util::seal;
use crate::util::timefmt::iso8601;

/// The most bytes one record takes.
const LINE_MAX: u64 = 4096;
const DEFAULT_PATH: &CStr = c"/var/lib/shirudo/eventlog";
const DEFAULT_PENDING_PATH: &CStr = c"/run/shirudo/eventlog.pending";
/// The register's NV index, `NV_INDEX` of util/paths.h, which asserts
/// that the two agree.
pub(crate) const NV_INDEX: u32 = 0x0181_8E00;

/// The path `var` names, unless a config image fixes the paths, or
/// `default`.
fn path_from(var: &CStr, default: &'static CStr) -> &'static CStr {
    if image_config::active() {
        return default;
    }
    env(var).filter(|v| !v.is_empty()).unwrap_or(default)
}

#[cfg(test)]
std::thread_local! {
    /// A test's own log and pending record, in place of the environment's,
    /// which every thread of the test binary shares.
    static TEST_PATHS: core::cell::Cell<Option<(&'static CStr, &'static CStr)>> =
        const { core::cell::Cell::new(None) };
}

pub(crate) fn path() -> &'static CStr {
    #[cfg(test)]
    if let Some((log, _)) = TEST_PATHS.get() {
        return log;
    }
    path_from(c"SHIRUDO_EVENTLOG_PATH", DEFAULT_PATH)
}

pub(crate) fn pending_path() -> &'static CStr {
    #[cfg(test)]
    if let Some((_, pending)) = TEST_PATHS.get() {
        return pending;
    }
    path_from(c"SHIRUDO_EVENTLOG_PENDING_PATH", DEFAULT_PENDING_PATH)
}

/// `line` appended to the log at `path` whole, or nothing of it: a line
/// cut short would join the next record and fail every reader on it.
pub(crate) fn append_to(path: &CStr, line: &[u8]) -> c_int {
    let Err(ret) = seal::append(path, line) else {
        return 0;
    };

    crate::log::err(
        &[
            &b"eventlog: append to "[..],
            path.to_bytes(),
            b": ",
            text(ret).as_bytes(),
        ]
        .concat(),
    );
    ret
}

/// `line` appended to the log, after the init record the initrd left
/// pending, which opens this boot's part of it: a line appended ahead of
/// that record would drop out of every replay.
pub(crate) fn append(line: &[u8]) -> c_int {
    let ret = adopt_pending();
    if ret != 0 {
        return ret;
    }
    append_to(path(), line)
}

/// Whether one more record could take the log past `max` bytes; never
/// for 0, no limit.
pub(crate) fn would_exceed(max: u64) -> bool {
    let mut st = Statx::zeroed();
    let mut cur = 0;

    if max == 0 {
        return false;
    }
    // SAFETY: a C string and a statx to fill.
    if unsafe { statx(AT_FDCWD, path().as_ptr(), 0, STATX_SIZE, &mut st) } == 0 {
        cur = st.stx_size;
    }
    cur.wrapping_add(LINE_MAX) > max
}

/// A file read whole, and a NUL after its bytes.
struct FileBuf {
    buf: Vec<u8>,
}

impl FileBuf {
    fn of(read: Result<Vec<u8>, c_int>) -> Result<FileBuf, c_int> {
        let mut buf = read?;
        buf.push(0);
        Ok(FileBuf { buf })
    }

    fn read(path: &CStr) -> Result<FileBuf, c_int> {
        Self::of(crate::util::io::read(path, MAX_BYTES))
    }

    /// The file open at `fd`, read whole.
    fn read_fd(fd: std::os::fd::OwnedFd) -> Result<FileBuf, c_int> {
        Self::of(crate::util::io::read_whole(
            std::os::fd::AsFd::as_fd(&fd),
            MAX_BYTES,
        ))
    }

    /// The bytes and the NUL after them.
    fn bytes(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    /// How many bytes the file had.
    fn len(&self) -> usize {
        self.buf.len() - 1
    }

    /// The records of the file: a NUL would end every walk there and hide
    /// the records after it, and a last line without its newline is no
    /// record yet, so the string ends after the last newline.
    fn records(&mut self) -> c_int {
        let len = self.len();
        let buf = self.bytes();

        if buf[..len].contains(&0) {
            return -EINVAL;
        }
        let n = buf[..len]
            .iter()
            .rposition(|&c| c == b'\n')
            .map_or(0, |i| i + 1);
        buf[n] = 0;
        0
    }
}

/// The log and the pending record together, as one C string.
enum Log {
    File(FileBuf),
    Joined(Vec<u8>),
}

impl Log {
    fn bytes(&mut self) -> &mut [u8] {
        match self {
            Log::File(f) => f.bytes(),
            Log::Joined(buf) => buf,
        }
    }
}

/// The record the initrd left in /run/shirudo, as sealed state where the
/// log is: a /run of root's making, in a mount namespace of its own,
/// would otherwise hand each reader records the register never saw, and
/// have the next append adopt them into the sealed log. A host without
/// the seal, as the register tests run on, labels neither.
fn read_pending() -> Result<FileBuf, c_int> {
    let pending = pending_path();

    if pending != DEFAULT_PENDING_PATH {
        return FileBuf::read(pending);
    }
    let fd = if seal::parent_labeled(path().to_bytes()) {
        seal::open_sealed(pending.to_bytes())?
    } else {
        seal::open_read(pending.to_bytes())?
    };
    FileBuf::read_fd(fd)
}

/// The sealed log and the pending record after it, for a reader that
/// checks each record against the register: the bytes up to the last
/// record's newline.
pub(crate) fn read_records() -> Result<Vec<u8>, c_int> {
    let mut log = read_log()?;

    Ok(cstr(log.bytes()).to_vec())
}

fn read_log() -> Result<Log, c_int> {
    let base = match FileBuf::read(path()) {
        Err(e) if e != -ENOENT => return Err(e),
        r => r,
    };
    let pending = match read_pending() {
        Err(e) if e != -ENOENT => return Err(e),
        r => r,
    };
    let (mut base, mut pending) = match (base, pending) {
        (Err(_), Err(_)) => return Err(-ENOENT),
        (Ok(mut base), Err(_)) => {
            if base.records() != 0 {
                return Err(-EINVAL);
            }
            return Ok(Log::File(base));
        }
        (Err(_), Ok(mut pending)) => {
            if pending.records() != 0 {
                return Err(-EINVAL);
            }
            return Ok(Log::File(pending));
        }
        (Ok(base), Ok(pending)) => (base, pending),
    };
    if base.records() != 0 || pending.records() != 0 {
        return Err(-EINVAL);
    }
    if base.len() + pending.len() > MAX_BYTES {
        return Err(-EFBIG);
    }
    let mut out = vec![0u8; base.len() + pending.len() + 1];
    let (a, b) = (cstr(base.bytes()).len(), cstr(pending.bytes()).len());

    out[..a].copy_from_slice(&base.bytes()[..a]);
    out[a..a + b].copy_from_slice(&pending.bytes()[..b]);
    Ok(Log::Joined(out))
}

/// `f` on each line of the C string in `buf`, terminated in place as
/// strtok_r() leaves it, until it returns other than 0.
fn each_line(buf: &mut [u8], mut f: impl FnMut(&CStr) -> c_int) -> c_int {
    let n = cstr(buf).len();
    let mut start = 0;

    while start < n {
        if buf[start] == b'\n' {
            start += 1;
            continue;
        }
        let end = buf[start..n]
            .iter()
            .position(|&c| c == b'\n')
            .map_or(n, |i| start + i);
        if end < n {
            buf[end] = 0;
        }
        let Ok(line) = CStr::from_bytes_until_nul(&buf[start..]) else {
            return -EINVAL;
        };
        let ret = f(line);
        if ret != 0 {
            return ret;
        }
        start = end + 1;
    }
    0
}

/// What a walk calls with each line and whether it is an init record.
type Walk<'a> = &'a mut dyn FnMut(&CStr, bool) -> c_int;

/// What a walk reads of each line: the boot that wrote it and its type.
struct LineHead {
    boot_id: [u8; 64],
    ty: [u8; 32],
}

/// This boot's records from its last init line on, or with `all` every
/// record; the callback learns which line is an init record so that a
/// replay can start over. -ENOENT for a boot without an init record.
fn walk_lines(buf: &mut [u8], all: bool, cb: Walk<'_>) -> c_int {
    let mut boot_id = [0u8; 64];
    let mut in_boot = false;

    read_boot_id(&mut boot_id);
    let boot = cstr(&boot_id);
    let ret = each_line(buf, |line| {
        let mut head = LineHead {
            boot_id: [0; 64],
            ty: [0; 32],
        };
        let f = [
            JsonField::string(c"boot_id", |h: &mut LineHead| &mut h.boot_id),
            JsonField::string(c"type", |h| &mut h.ty),
        ];
        if parse_schema(line.to_bytes(), &f, &mut head).is_err() {
            return -EINVAL;
        }
        if !all && (!f[0].seen() || boot.is_empty() || cstr(&head.boot_id) != boot) {
            return 0;
        }
        let is_init = f[1].seen() && cstr(&head.ty) == b"init";
        if is_init {
            in_boot = true;
        }
        if !all && !in_boot {
            return 0;
        }
        cb(line, is_init)
    });
    if !all && ret == 0 && !in_boot {
        return -ENOENT;
    }
    ret
}

fn walk_log(all: bool, cb: Walk<'_>) -> c_int {
    match read_log() {
        Ok(mut log) => walk_lines(log.bytes(), all, cb),
        Err(e) => e,
    }
}

fn walk_boot(cb: Walk<'_>) -> c_int {
    walk_log(false, cb)
}

/// Whether this boot's part of the log holds `line`: 1 or 0.
fn log_holds(line: &[u8]) -> c_int {
    let mut found = false;
    let mut buf = match FileBuf::read(path()) {
        Ok(buf) => buf,
        Err(e) if e == -ENOENT => return 0,
        Err(e) => return e,
    };
    let mut ret = buf.records();

    if ret == 0 {
        ret = walk_lines(buf.bytes(), false, &mut |l, _| {
            if l.to_bytes() == line {
                found = true;
            }
            0
        });
    }
    if ret != 0 && ret != -ENOENT {
        return ret;
    }
    c_int::from(found)
}

/// The records the initrd left pending appended to the log, each one
/// the log does not hold yet, and the pending file gone.
fn adopt_pending() -> c_int {
    let pending = pending_path();
    let mut buf = match read_pending() {
        Ok(buf) => buf,
        Err(e) if e == -ENOENT => return 0,
        Err(e) => return e,
    };
    let mut ret = buf.records();

    if ret == 0 {
        ret = each_line(buf.bytes(), |line| {
            let held = log_holds(line.to_bytes());

            match held {
                0 => append_to(path(), line.to_bytes()),
                n if n > 0 => 0,
                e => e,
            }
        });
    }
    drop(buf);
    if ret != 0 {
        return ret;
    }
    // SAFETY: a C string.
    if unsafe { unlink(pending.as_ptr()) } != 0 && errno() != ENOENT {
        return -errno();
    }
    0
}

/// The one lock for all register extends and eventlog appends. The
/// private bpffs root is the same inode in every mount namespace, so a
/// covered log path cannot give another command a different lock.
pub(crate) struct Lock {
    _fd: std::os::fd::OwnedFd,
}

pub(crate) fn lock() -> Result<Lock, c_int> {
    if path() == DEFAULT_PATH {
        let fd = identity::bpffs_root_open()?;
        lock_exclusive(std::os::fd::AsFd::as_fd(&fd))?;
        return Ok(Lock { _fd: fd });
    }

    // An overridden log path is for a host without a configured image.
    let lock_path = [path().to_bytes(), b".lock"].concat();
    if lock_path.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    seal::lock(&lock_path).map(|fd| Lock { _fd: fd })
}

/// The pending record adopted under the lock: init adopts it while a
/// command may append, and both would find it missing and append it.
/// Without a record there is nothing to adopt, nor yet a state directory
/// for the lock on a first boot.
pub(crate) fn adopt_pending_locked() -> c_int {
    // SAFETY: a C string.
    if unsafe { access(pending_path().as_ptr(), F_OK) } != 0 && errno() == ENOENT {
        return 0;
    }
    let lock = match lock() {
        Ok(lock) => lock,
        Err(err) => return err,
    };
    let ret = adopt_pending();

    drop(lock);
    ret
}

/// The time now as ISO-8601 UTC into `out`.
pub(crate) fn timestamp(out: &mut [u8]) {
    iso8601(crate::util::timefmt::now(), out);
}

/// This boot's ID from /proc, without its newline, or empty.
pub(crate) fn read_boot_id(out: &mut [u8]) {
    out[0] = 0;
    // SAFETY: a C string and flags without a mode.
    let fd = unsafe {
        open(
            c"/proc/sys/kernel/random/boot_id".as_ptr(),
            O_RDONLY | O_CLOEXEC,
        )
    };
    if fd < 0 {
        return;
    }
    // SAFETY: room for all but the NUL at out, from the fd open() gave,
    // which is closed once, here.
    let n = unsafe {
        let n = read(fd, out.as_mut_ptr().cast(), out.len() - 1);
        close(fd);
        n
    };
    if n <= 0 {
        out[0] = 0;
        return;
    }
    let mut n = n as usize;
    out[n] = 0;
    while n > 0 && matches!(out[n - 1], b'\n' | b'\r') {
        n -= 1;
        out[n] = 0;
    }
}

/// The fields every record opens with, into `e`.
pub(crate) fn record_open(e: &mut JsonEmit, ty: &[u8], digest: &[u8; 32]) {
    let mut ts = [0u8; 32];
    let mut boot_id = [0u8; 64];
    let digest_hex = encode(digest);
    let mut nv_index = *b"0x00000000";

    timestamp(&mut ts);
    read_boot_id(&mut boot_id);
    for (i, d) in nv_index[2..].iter_mut().enumerate() {
        *d = b"0123456789ABCDEF"[((NV_INDEX >> (28 - 4 * i)) & 0xf) as usize];
    }
    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_string(b"ts", cstr(&ts));
    e.kv_string(b"nv_index", &nv_index);
    e.kv_string(b"alg", b"sha256");
    e.kv_string(b"digest", cstr(&digest_hex));
    e.kv_string(b"type", ty);
    e.kv_string(b"boot_id", cstr(&boot_id));
}

#[cfg(test)]
mod tests;
