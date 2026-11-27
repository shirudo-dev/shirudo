// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The config activation journal: the
//! state file of the selection a target runs, the events file of every
//! selection measured into the config PCR, and the steps from one to
//! the next, under the journal's lock, through the operations the
//! caller supplies.

use core::ffi::{CStr, c_int};
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;

use crate::errno::{
    EBADMSG, EBUSY, EINPROGRESS, EINVAL, EIO, ENODATA, ENOENT, EOVERFLOW, EPERM, ESTALE, EUCLEAN,
    text,
};
use crate::sys::libc::{
    LOCK_EX, LOCK_NB, O_APPEND, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_NONBLOCK,
    O_RDONLY, O_RDWR, O_WRONLY, S_IFMT, S_IFREG, Statx, errno, flock, fsync, ftruncate, geteuid,
    openat, renameat, unlinkat,
};
use crate::text::cstr;
use crate::util::chain::fold;
use crate::util::config_measure::{self, EVENT_BOOT, EVENT_UPDATE};
use crate::util::hex;
use crate::util::io::{self, close_checked, stat_fd};
use crate::util::json::{JsonEmit, JsonField, parse_schema};

/// `CONFIG_UPDATE_PREFIX_MAX`.
const PREFIX_MAX: usize = 4096;
/// `RECORD_MAX`: the longest record either file holds.
const RECORD_MAX: usize = 2 * PREFIX_MAX + 1024;
/// EWOULDBLOCK, which is EAGAIN.
const EWOULDBLOCK: c_int = crate::errno::EAGAIN;

/// Where a caller may stop the protocol, numbered as the checkpoints
/// test-config-update's SHIRUDO_TEST_CONFIG_CRASH and _FAIL name.
#[derive(Clone, Copy)]
pub(crate) enum Checkpoint {
    PendingSync = 1,
    Extend = 2,
    EventSync = 3,
    Activate = 4,
    CompleteSync = 5,
    StateWrite = 6,
    StateRename = 7,
    EventWrite = 8,
}

/// A config image's mapping prefix and its dm-verity root.
#[derive(Clone, Copy)]
pub(crate) struct ConfigUpdateTarget {
    pub(crate) prefix: [u8; PREFIX_MAX],
    pub(crate) root_hash: [u8; 32],
}

/// The state file's selection, or an event, which carries no prefix and
/// is never pending.
#[derive(Clone, Copy)]
pub(crate) struct ConfigUpdateRecord {
    pub(crate) target: ConfigUpdateTarget,
    pub(crate) initial_pcr: [u8; 32],
    pub(crate) sequence: u64,
    pub(crate) reset_count: u32,
    pub(crate) restart_count: u32,
    pub(crate) pcr: u32,
    pub(crate) kind: c_int,
    pub(crate) pending: bool,
}

impl ConfigUpdateTarget {
    pub(crate) const fn zeroed() -> Self {
        ConfigUpdateTarget {
            prefix: [0; PREFIX_MAX],
            root_hash: [0; 32],
        }
    }
}

impl ConfigUpdateRecord {
    pub(crate) const fn zeroed() -> Self {
        ConfigUpdateRecord {
            target: ConfigUpdateTarget::zeroed(),
            initial_pcr: [0; 32],
            sequence: 0,
            reset_count: 0,
            restart_count: 0,
            pcr: 0,
            kind: 0,
            pending: false,
        }
    }
}

/// The TPM boot a reading was made in: the TPM's reset and restart
/// counts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct BootIdentity {
    pub(crate) reset: u32,
    pub(crate) restart: u32,
}

/// What the caller does for the protocol: the TPM's boot and a PCR read,
/// a PCR extended, a config prepared and activated, the journal's files
/// sealed, and the protocol stopped at a checkpoint where a test asks.
pub(crate) trait ConfigUpdateOps {
    fn boot_identity(&self) -> Result<BootIdentity, c_int>;

    fn pcr_read(&self, pcr: u32) -> Result<[u8; 32], c_int>;

    fn pcr_extend(&self, pcr: u32, event: &[u8; 32]) -> Result<(), c_int>;

    /// `target` made ready to activate, or refused before anything is
    /// measured.
    fn prepare(&self, target: &ConfigUpdateTarget) -> Result<(), c_int>;

    /// `target`, prepared, made the config in force, with `journal`
    /// holding its selection pending.
    fn activate(
        &self,
        journal: &ConfigUpdate<'_>,
        target: &ConfigUpdateTarget,
    ) -> Result<(), c_int>;

    /// The seal's label on the journal's directory or a file it makes.
    fn seal(&self, fd: BorrowedFd<'_>) -> Result<(), c_int>;

    /// Whether the protocol goes on past `point`.
    fn checkpoint(&self, _point: Checkpoint) -> Result<(), c_int> {
        Ok(())
    }
}

/// An open journal: its directory, and its lock, held until the journal
/// is dropped; the operations it calls are borrowed for as long.
pub(crate) struct ConfigUpdate<'o> {
    ops: &'o dyn ConfigUpdateOps,
    /// Held for its flock(), which its close releases.
    _lock: OwnedFd,
    dir: OwnedFd,
    boot_pending: bool,
}

/// `name` in the directory `dir`, opened with `flags`, and `mode` for a
/// file it creates.
fn open_at(dir: BorrowedFd<'_>, name: &CStr, flags: c_int, mode: u32) -> Result<OwnedFd, c_int> {
    // SAFETY: an open directory, a C string, flags and a mode.
    let fd = unsafe { openat(dir.as_raw_fd(), name.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(-errno());
    }
    // SAFETY: the fd openat() gave, owned from here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn unlink_at(dir: BorrowedFd<'_>, name: &CStr) -> Result<(), c_int> {
    // SAFETY: an open directory and a C string.
    if unsafe { unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(-errno());
    }
    Ok(())
}

fn rename_at(dir: BorrowedFd<'_>, from: &CStr, to: &CStr) -> Result<(), c_int> {
    // SAFETY: an open directory and two C strings.
    if unsafe { renameat(dir.as_raw_fd(), from.as_ptr(), dir.as_raw_fd(), to.as_ptr()) } != 0 {
        return Err(-errno());
    }
    Ok(())
}

/// fsync(2) of `fd`, which, unlike File::sync_all(), gives up on EINTR.
fn sync(fd: BorrowedFd<'_>) -> Result<(), c_int> {
    // SAFETY: an open fd.
    if unsafe { fsync(fd.as_raw_fd()) } != 0 {
        return Err(-errno());
    }
    Ok(())
}

fn truncate(fd: BorrowedFd<'_>, length: u64) -> Result<(), c_int> {
    let length = i64::try_from(length).map_err(|_| -EINVAL)?;

    // SAFETY: an open fd.
    if unsafe { ftruncate(fd.as_raw_fd(), length) } != 0 {
        return Err(-errno());
    }
    Ok(())
}

/// `write` on `file`, which is closed after whatever it returned: the
/// error of the write, else the close's.
fn closed_after(file: File, write: impl FnOnce(&File) -> Result<(), c_int>) -> Result<(), c_int> {
    let written = write(&file);
    let closed = close_checked(file.into());

    written.and(closed)
}

/// All of `bytes` to `file`, through short writes and signals: -EIO for
/// a write of nothing.
fn write_all(mut file: &File, bytes: &[u8]) -> Result<(), c_int> {
    file.write_all(bytes).map_err(|e| io::errno_of(&e))
}

fn euid() -> u32 {
    // SAFETY: a call that takes nothing.
    unsafe { geteuid() }
}

fn target_valid(target: &ConfigUpdateTarget) -> bool {
    let prefix = cstr(&target.prefix);

    prefix.len() < PREFIX_MAX
        && prefix.starts_with(b"/")
        && !prefix.iter().any(u8::is_ascii_control)
}

/// `record` as one JSON line in `out`, with the prefix and whether it is
/// pending for the state file: the line, or the emitter's error.
fn record_encode<'o>(
    record: &ConfigUpdateRecord,
    state: bool,
    out: &'o mut [u8; RECORD_MAX],
) -> Result<&'o [u8], c_int> {
    let (body, _) = out.split_at_mut(RECORD_MAX - 1);
    let mut emit = JsonEmit::fixed(body);
    let root = hex::encode(&record.target.root_hash);
    let initial = hex::encode(&record.initial_pcr);

    emit.obj_open();
    emit.kv_int(b"schema", 1);
    emit.kv_int(b"sequence", record.sequence as i64);
    emit.kv_int(b"reset_count", i64::from(record.reset_count));
    emit.kv_int(b"restart_count", i64::from(record.restart_count));
    emit.kv_int(b"pcr", i64::from(record.pcr));
    emit.kv_int(b"kind", i64::from(record.kind));
    emit.kv_string(b"root_hash", &root);
    emit.kv_string(b"initial_pcr", &initial);
    if state {
        emit.kv_string(b"prefix", cstr(&record.target.prefix));
        emit.kv_bool(b"pending", record.pending);
    }
    emit.obj_close();
    if emit.err() != 0 {
        return Err(emit.err());
    }
    let n = emit.written();

    out[n] = b'\n';
    Ok(&out[..=n])
}

/// What a record's JSON gives before it is checked.
struct RecordJson {
    schema: i64,
    sequence: i64,
    reset: i64,
    restart: i64,
    pcr: i64,
    kind: i64,
    root: [u8; 65],
    initial: [u8; 65],
    prefix: [u8; PREFIX_MAX],
    pending: bool,
}

/// The record `data` holds, with the prefix and whether it is pending
/// for the state file: -EBADMSG for one that is not a record, or the
/// parser's error.
fn record_decode(data: &[u8], state: bool) -> Result<ConfigUpdateRecord, c_int> {
    let mut json = RecordJson {
        schema: 0,
        sequence: 0,
        reset: 0,
        restart: 0,
        pcr: 0,
        kind: 0,
        root: [0; 65],
        initial: [0; 65],
        prefix: [0; PREFIX_MAX],
        pending: false,
    };
    let fields = [
        JsonField::int(c"schema", |j: &mut RecordJson| &mut j.schema),
        JsonField::int(c"sequence", |j| &mut j.sequence),
        JsonField::int(c"reset_count", |j| &mut j.reset),
        JsonField::int(c"restart_count", |j| &mut j.restart),
        JsonField::int(c"pcr", |j| &mut j.pcr),
        JsonField::int(c"kind", |j| &mut j.kind),
        JsonField::string(c"root_hash", |j| &mut j.root),
        JsonField::string(c"initial_pcr", |j| &mut j.initial),
        JsonField::string(c"prefix", |j| &mut j.prefix),
        JsonField::boolean(c"pending", |j| &mut j.pending),
    ];
    parse_schema(data, &fields, &mut json)?;
    let required = fields.len() - if state { 0 } else { 2 };
    if fields[..required].iter().any(|f| !f.seen()) {
        return Err(-EBADMSG);
    }
    let mut record = ConfigUpdateRecord::zeroed();
    record.target.prefix = json.prefix;
    if json.schema != 1
        || json.sequence <= 0
        || !(0..=i64::from(u32::MAX)).contains(&json.reset)
        || !(0..=i64::from(u32::MAX)).contains(&json.restart)
        || !(0..=i64::from(u32::MAX)).contains(&json.pcr)
        || config_measure::pcr_valid(json.pcr as u32) != 0
        || (json.kind != i64::from(EVENT_BOOT) && json.kind != i64::from(EVENT_UPDATE))
        || hex::decode(cstr(&json.root), &mut record.target.root_hash).is_err()
        || hex::decode(cstr(&json.initial), &mut record.initial_pcr).is_err()
        || (state && !target_valid(&record.target))
    {
        return Err(-EBADMSG);
    }
    record.sequence = json.sequence as u64;
    record.reset_count = json.reset as u32;
    record.restart_count = json.restart as u32;
    record.pcr = json.pcr as u32;
    record.kind = json.kind as c_int;
    record.pending = json.pending;
    Ok(record)
}

/// The status of `fd` when it is a regular file of one link, the
/// effective user's, that no one else may read or write: -EPERM when it
/// is not.
fn regular_file(fd: BorrowedFd<'_>) -> Result<Statx, c_int> {
    let st = stat_fd(fd)?;

    if st.stx_mode & S_IFMT != S_IFREG || st.stx_nlink != 1 {
        return Err(-EPERM);
    }
    if st.stx_uid != euid() || st.stx_mode & 0o77 != 0 {
        return Err(-EPERM);
    }
    Ok(st)
}

/// The journal's lock taken, waiting up to `wait_ms` for another
/// command's, as the keepalive and map-export timers take turns.
fn lock_wait(fd: BorrowedFd<'_>, wait_ms: u32) -> Result<(), c_int> {
    let pause = std::time::Duration::from_millis(100);
    let mut told = false;
    let mut waited: u32 = 0;

    loop {
        // SAFETY: the lock file's fd.
        if unsafe { flock(fd.as_raw_fd(), LOCK_EX | LOCK_NB) } == 0 {
            return Ok(());
        }
        let err = errno();

        if err != EWOULDBLOCK || waited >= wait_ms {
            return Err(-err);
        }
        if !told && waited >= 1000 {
            crate::log::info(
                b"image: waiting for another shirudo command to release the config operation lock",
            );
            told = true;
        }
        std::thread::sleep(pause);
        waited = waited.wrapping_add(100);
    }
}

impl<'o> ConfigUpdate<'o> {
    /// The journal in `directory`, its lock taken, waiting up to
    /// `lock_wait_ms` for another command's, and the directory and the
    /// lock file sealed through `ops` and synced: -EPERM where the
    /// directory is another user's or others may write it, or the lock
    /// file is not a regular file of the user's alone, and -EAGAIN when
    /// another command still holds the lock.
    pub(crate) fn open(
        directory: &CStr,
        ops: &'o dyn ConfigUpdateOps,
        lock_wait_ms: u32,
    ) -> Result<Self, c_int> {
        let dir: OwnedFd = OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW)
            .open(OsStr::from_bytes(directory.to_bytes()))
            .map_err(|e| io::errno_of(&e))?
            .into();
        let st = stat_fd(dir.as_fd())?;
        if st.stx_uid != euid() || st.stx_mode & 0o22 != 0 {
            return Err(-EPERM);
        }
        ops.seal(dir.as_fd())?;
        let lock = open_at(
            dir.as_fd(),
            c"lock",
            O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
            0o600,
        )?;
        regular_file(lock.as_fd())?;
        lock_wait(lock.as_fd(), lock_wait_ms).inspect_err(|&err| {
            if err == -EWOULDBLOCK {
                crate::log::err(
                    &[
                        &b"image: another shirudo command still holds the config operation lock "[..],
                        directory.to_bytes(),
                        b"/lock after ",
                        format!("{}", lock_wait_ms / 1000).as_bytes(),
                        b" seconds",
                    ]
                    .concat(),
                );
            }
        })?;
        ops.seal(lock.as_fd())?;
        sync(lock.as_fd())?;
        sync(dir.as_fd())?;
        Ok(ConfigUpdate {
            ops,
            _lock: lock,
            dir,
            boot_pending: false,
        })
    }

    /// The operations the journal calls from here.
    pub(crate) fn set_ops(&mut self, ops: &'o dyn ConfigUpdateOps) {
        self.ops = ops;
    }
}

/// The selection record in the file `name` of the journal directory
/// `dir`: `state`, the one in force, or `next-boot`, one staged for the
/// boot after this.
fn selection_read(dir: BorrowedFd<'_>, name: &CStr) -> Result<ConfigUpdateRecord, c_int> {
    let mut wire = [0u8; RECORD_MAX];
    let mut file = File::from(open_at(
        dir,
        name,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
        0,
    )?);
    let st = regular_file(file.as_fd())?;
    let size = usize::try_from(st.stx_size)
        .ok()
        .filter(|&size| size != 0 && size < wire.len())
        .ok_or(-EBADMSG)?;
    let line = &mut wire[..size];

    file.read_exact(line).map_err(|e| io::errno_of(&e))?;
    record_decode(line, true)
}

fn same_boot(a: &ConfigUpdateRecord, b: &ConfigUpdateRecord) -> bool {
    a.reset_count == b.reset_count
}

fn same_target(a: &ConfigUpdateTarget, b: &ConfigUpdateTarget) -> bool {
    cstr(&a.prefix) == cstr(&b.prefix) && a.root_hash == b.root_hash
}

fn same_event(a: &ConfigUpdateRecord, b: &ConfigUpdateRecord) -> bool {
    same_boot(a, b)
        && a.sequence == b.sequence
        && a.pcr == b.pcr
        && a.kind == b.kind
        && a.initial_pcr == b.initial_pcr
        && a.target.root_hash == b.target.root_hash
}

/// Whether `record` may follow `previous`: -EUCLEAN where it may not.
fn event_follows(previous: &ConfigUpdateRecord, record: &ConfigUpdateRecord) -> Result<(), c_int> {
    if record.sequence != previous.sequence.wrapping_add(1) {
        return Err(-EUCLEAN);
    }
    if previous.sequence == 0 || !same_boot(previous, record) {
        return if record.kind == EVENT_BOOT {
            Ok(())
        } else {
            Err(-EUCLEAN)
        };
    }
    if record.kind != EVENT_UPDATE
        || previous.pcr != record.pcr
        || previous.initial_pcr != record.initial_pcr
    {
        return Err(-EUCLEAN);
    }
    Ok(())
}

/// The next line of `bytes` in `line`, its newline with it, or None at
/// the end: -ENODATA for a last line without one, which only a later
/// trusted boot may discard, -EBADMSG for a NUL or a line too long, or
/// -EIO where the read fails.
fn read_line<'l>(
    bytes: &mut impl Iterator<Item = std::io::Result<u8>>,
    line: &'l mut [u8],
) -> Result<Option<&'l [u8]>, c_int> {
    let mut length = 0;

    for byte in bytes {
        let c = byte.map_err(|_| -EIO)?;
        let Some(slot) = line.get_mut(length).filter(|_| c != 0) else {
            return Err(-EBADMSG);
        };

        *slot = c;
        length += 1;
        if c == b'\n' {
            return Ok(Some(&line[..length]));
        }
    }
    if length != 0 { Err(-ENODATA) } else { Ok(None) }
}

/// What the events replay to: the last event, the PCR value its boot's
/// initial value and the events since fold to, and the offset after the
/// last whole line.
struct Replay {
    last: ConfigUpdateRecord,
    value: [u8; 32],
    end: u64,
}

/// The events file of the journal directory `dir` replayed: each event
/// decoded, checked to follow the one before, folded into the PCR value
/// from its boot's initial value, and handed to `consume`; `partial`
/// forgives a torn last line. A journal without one replays to nothing.
fn events_scan(
    dir: BorrowedFd<'_>,
    partial: bool,
    mut consume: impl FnMut(&ConfigUpdateRecord) -> Result<(), c_int>,
) -> Result<Replay, c_int> {
    let mut replay = Replay {
        last: ConfigUpdateRecord::zeroed(),
        value: [0; 32],
        end: 0,
    };
    let mut wire = [0u8; RECORD_MAX];
    let file = match open_at(
        dir,
        c"events",
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
        0,
    ) {
        Ok(fd) => File::from(fd),
        Err(err) if err == -ENOENT => return Ok(replay),
        Err(err) => return Err(err),
    };
    regular_file(file.as_fd())?;
    let mut bytes = BufReader::new(file).bytes();
    loop {
        let line = match read_line(&mut bytes, &mut wire) {
            Ok(Some(line)) => line,
            Ok(None) => return Ok(replay),
            Err(err) if err == -ENODATA && partial => return Ok(replay),
            Err(err) => return Err(err),
        };
        let record = record_decode(line, false)?;
        event_follows(&replay.last, &record)?;
        if record.kind == EVENT_BOOT {
            replay.value = record.initial_pcr;
        }
        let event = config_measure::event(record.kind, &record.target.root_hash)?;
        fold(&mut replay.value, &event)?;
        consume(&record)?;
        replay.last = record;
        replay.end += line.len() as u64;
    }
}

impl ConfigUpdate<'_> {
    fn dir(&self) -> BorrowedFd<'_> {
        self.dir.as_fd()
    }

    /// The selection in force, from the state file.
    pub(crate) fn read_state(&self) -> Result<ConfigUpdateRecord, c_int> {
        selection_read(self.dir(), c"state")
    }

    /// The selection staged for the next boot.
    pub(crate) fn read_staged(&self) -> Result<ConfigUpdateRecord, c_int> {
        selection_read(self.dir(), c"next-boot")
    }

    /// Each event handed to `consume` in turn, once it is checked to
    /// follow the one before and folded into the PCR value: the error of
    /// an event that does not, or the one `consume` returns.
    pub(crate) fn events(
        &self,
        consume: impl FnMut(&ConfigUpdateRecord) -> Result<(), c_int>,
    ) -> Result<(), c_int> {
        events_scan(self.dir(), false, consume).map(|_| ())
    }

    /// The selection file `name` replaced by `record`, through the sealed
    /// temporary file `temporary` renamed over it; `inject` lets the
    /// caller's checkpoints stop it.
    fn selection_save(
        &self,
        record: &ConfigUpdateRecord,
        name: &CStr,
        temporary: &CStr,
        inject: bool,
    ) -> Result<(), c_int> {
        let mut wire = [0u8; RECORD_MAX];
        let line = record_encode(record, true, &mut wire)?;
        let dir = self.dir();

        if let Err(err) = unlink_at(dir, temporary)
            && err != -ENOENT
        {
            return Err(err);
        }
        let file = File::from(open_at(
            dir,
            temporary,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0o600,
        )?);
        let saved = closed_after(file, |file| {
            self.ops.seal(file.as_fd())?;
            write_all(file, line)?;
            if inject {
                self.ops.checkpoint(Checkpoint::StateWrite)?;
            }
            sync(file.as_fd())
        })
        .and_then(|()| {
            rename_at(dir, temporary, name)?;
            if inject {
                self.ops.checkpoint(Checkpoint::StateRename)?;
            }
            sync(dir)
        });
        if saved.is_err() {
            // The next save unlinks a temporary file this leaves.
            let _ = unlink_at(dir, temporary);
        }
        saved
    }

    /// The state file replaced by `record`.
    fn state_save(&self, record: &ConfigUpdateRecord, inject: bool) -> Result<(), c_int> {
        self.selection_save(record, c"state", c".state.tmp", inject)
    }

    /// `record` appended to the events file after the last whole line,
    /// once it follows the last event.
    fn event_append(&self, record: &ConfigUpdateRecord) -> Result<(), c_int> {
        let mut wire = [0u8; RECORD_MAX];
        let dir = self.dir();
        let replay = events_scan(dir, record.kind == EVENT_BOOT, |_| Ok(()))?;
        event_follows(&replay.last, record)?;
        let line = record_encode(record, false, &mut wire)?;
        let file = File::from(open_at(
            dir,
            c"events",
            O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
            0o600,
        )?);
        closed_after(file, |file| {
            regular_file(file.as_fd())?;
            self.ops.seal(file.as_fd())?;
            truncate(file.as_fd(), replay.end)?;
            write_all(file, line)?;
            self.ops.checkpoint(Checkpoint::EventWrite)?;
            sync(file.as_fd())
        })?;
        sync(dir)
    }

    /// The PCR's value between two readings of the TPM's boot, which
    /// must agree, or -ESTALE.
    fn live_read(&self, pcr: u32) -> Result<(BootIdentity, [u8; 32]), c_int> {
        let boot = self.ops.boot_identity()?;
        let value = self.ops.pcr_read(pcr)?;

        if self.ops.boot_identity()? != boot {
            return Err(-ESTALE);
        }
        Ok((boot, value))
    }

    /// Whether `record` is the last event, of this TPM boot, and the PCR
    /// holds what the events replay to.
    fn check_record(&self, record: &ConfigUpdateRecord) -> Result<(), c_int> {
        let replay = events_scan(self.dir(), false, |_| Ok(()))?;
        if !same_event(record, &replay.last) {
            return Err(-EUCLEAN);
        }
        let (boot, value) = self.live_read(record.pcr)?;
        if boot.reset != record.reset_count {
            return Err(-ESTALE);
        }
        if value != replay.value {
            return Err(-EUCLEAN);
        }
        Ok(())
    }

    /// The selection in force, once it is complete, the last event, of
    /// this TPM boot, and the PCR holds what the events replay to:
    /// -EINPROGRESS while it is pending, -ESTALE in another TPM boot,
    /// -EUCLEAN where the events or the PCR disagree.
    pub(crate) fn check(&self) -> Result<ConfigUpdateRecord, c_int> {
        let record = self.read_state()?;
        if record.pending {
            return Err(-EINPROGRESS);
        }
        self.check_record(&record)?;
        Ok(record)
    }

    /// The pending selection marked done, or put back if that fails.
    fn complete(&self) -> Result<(), c_int> {
        let mut record = self.read_state()?;
        self.check_record(&record)?;
        record.pending = false;
        let completed = self
            .state_save(&record, true)
            .and_then(|()| self.ops.checkpoint(Checkpoint::CompleteSync));
        if completed.is_err() {
            record.pending = true;
            if let Err(restore) = self.state_save(&record, false) {
                crate::log::err(
                    format!("image: cannot restore pending selection: {}", text(restore))
                        .as_bytes(),
                );
            }
        }
        completed
    }

    /// The selection of `target` after `previous`: saved pending,
    /// measured into the PCR, appended to the events and activated, for
    /// the caller to complete.
    fn begin_event(
        &self,
        target: &ConfigUpdateTarget,
        previous: &ConfigUpdateRecord,
        pcr: u32,
        kind: c_int,
    ) -> Result<(), c_int> {
        if previous.sequence == i64::MAX as u64 {
            return Err(-EOVERFLOW);
        }
        self.ops.prepare(target)?;
        let (boot, before) = self.live_read(pcr)?;
        let mut record = ConfigUpdateRecord::zeroed();
        record.target = *target;
        record.sequence = previous.sequence + 1;
        record.pcr = pcr;
        record.kind = kind;
        record.pending = true;
        record.reset_count = boot.reset;
        record.restart_count = boot.restart;
        record.initial_pcr = if kind == EVENT_BOOT {
            before
        } else {
            previous.initial_pcr
        };
        event_follows(previous, &record)?;
        let event = config_measure::event(kind, &target.root_hash)?;
        let mut expected = before;
        fold(&mut expected, &event)?;
        self.state_save(&record, true)?;
        self.ops.checkpoint(Checkpoint::PendingSync)?;
        self.ops.pcr_extend(pcr, &event)?;
        self.ops.checkpoint(Checkpoint::Extend)?;
        let (after, value) = self.live_read(pcr)?;
        if after != boot || value != expected {
            return Err(-EUCLEAN);
        }
        self.event_append(&record)?;
        self.ops.checkpoint(Checkpoint::EventSync)?;
        self.ops.activate(self, target)?;
        self.ops.checkpoint(Checkpoint::Activate)
    }

    /// No selection staged for the next boot.
    pub(crate) fn clear_staged(&self) -> Result<(), c_int> {
        match unlink_at(self.dir(), c"next-boot") {
            Ok(()) => sync(self.dir()),
            Err(err) if err == -ENOENT => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// `target` staged for the next boot, in the selection record format:
    /// its target the candidate, its sequence and TPM counts those of the
    /// selection it was staged from.
    pub(crate) fn stage(&self, target: &ConfigUpdateTarget) -> Result<(), c_int> {
        if !target_valid(target) {
            return Err(-EINVAL);
        }
        let mut record = self.check()?;
        record.target = *target;
        self.selection_save(&record, c"next-boot", c".next-boot.tmp", false)
    }

    /// The staged target when the boot with `reset` after `previous` takes
    /// it, or None to keep the selection in force.
    pub(crate) fn staged(
        &self,
        previous: &ConfigUpdateRecord,
        reset: u32,
    ) -> Result<Option<ConfigUpdateTarget>, c_int> {
        let staged = match self.read_staged() {
            Ok(staged) => staged,
            Err(err) if err == -ENOENT => return Ok(None),
            Err(err) => return Err(err),
        };
        if staged.pending {
            return Err(-EBADMSG);
        }
        if staged.reset_count == reset || same_target(&staged.target, &previous.target) {
            return Ok(None);
        }
        if staged.sequence != previous.sequence || !same_boot(&staged, previous) {
            crate::log::warn(b"image: ignoring staged config because the active selection changed");
            return Ok(None);
        }
        Ok(Some(staged.target))
    }

    /// A staged selection the boot in force came from goes with it.
    fn complete_staged(&self) -> Result<(), c_int> {
        let staged = match self.read_staged() {
            Ok(staged) => staged,
            Err(err) if err == -ENOENT => return Ok(()),
            Err(err) => return Err(err),
        };
        if same_boot(&self.read_state()?, &staged) {
            return Ok(());
        }
        self.clear_staged()
    }

    /// `target` activated live on the config PCR `pcr`, over a selection
    /// complete and checked.
    pub(crate) fn begin(&self, target: &ConfigUpdateTarget, pcr: u32) -> Result<(), c_int> {
        if !target_valid(target) || config_measure::pcr_valid(pcr) != 0 {
            return Err(-EINVAL);
        }
        let previous = self.check()?;
        if pcr != previous.pcr {
            return Err(-EPERM);
        }
        if target.root_hash == previous.target.root_hash {
            return Ok(());
        }
        self.begin_event(target, &previous, pcr, EVENT_UPDATE)?;
        self.complete()?;
        if let Err(err) = self.clear_staged() {
            crate::log::warn(
                format!("image: cannot remove obsolete staged config: {}", text(err)).as_bytes(),
            );
        }
        Ok(())
    }

    /// `target` selected by this TPM boot on the config PCR `pcr`, left
    /// pending for complete_boot(): -EINPROGRESS while a selection of
    /// this TPM boot is pending.
    pub(crate) fn boot(&mut self, target: &ConfigUpdateTarget, pcr: u32) -> Result<(), c_int> {
        if !target_valid(target) || config_measure::pcr_valid(pcr) != 0 {
            return Err(-EINVAL);
        }
        self.boot_pending = false;
        let previous = match self.read_state() {
            Ok(previous) => previous,
            Err(err) if err == -ENOENT => ConfigUpdateRecord::zeroed(),
            Err(err) => return Err(err),
        };
        let boot = self.ops.boot_identity()?;
        if previous.sequence != 0 && previous.reset_count == boot.reset {
            if previous.pending {
                return Err(-EINPROGRESS);
            }
            if previous.pcr != pcr || target.root_hash != previous.target.root_hash {
                return Err(-EBUSY);
            }
            return self.check().map(|_| ());
        }
        if previous.sequence != 0 && !same_target(target, &previous.target) {
            match self.staged(&previous, boot.reset)? {
                Some(next) if same_target(target, &next) => {}
                _ => return Err(-EUCLEAN),
            }
        }
        let last = events_scan(self.dir(), previous.pending, |_| Ok(()))?.last;
        if previous.sequence == 0 && last.sequence != 0 {
            return Err(-EUCLEAN);
        }
        if previous.sequence != 0
            && !(same_event(&previous, &last)
                || (previous.pending && event_follows(&last, &previous).is_ok()))
        {
            return Err(-EUCLEAN);
        }
        self.begin_event(target, &last, pcr, EVENT_BOOT)?;
        self.boot_pending = true;
        Ok(())
    }

    /// The boot's selection completed, or the selection in force
    /// checked, and a staged selection it came from removed.
    pub(crate) fn complete_boot(&mut self) -> Result<(), c_int> {
        if self.boot_pending {
            self.boot_pending = false;
            self.complete()?;
        } else {
            self.check()?;
        }
        self.complete_staged()
    }
}

#[cfg(test)]
mod tests;

#[cfg(shirudo_fuzz)]
mod fuzz;
