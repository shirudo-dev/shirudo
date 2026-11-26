// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo upatch load` and `unload`, and the installs, removals and
//! purges of bpm and keys, which take the same path: the operations that
//! move the measurement register.
//!
//! An operation stages the operator's file, so that what is measured,
//! loaded and archived all come from one read. It checks the target
//! against the caller's expectations and the anchor init froze, and
//! takes the register lock. Under the lock it undoes whatever an
//! earlier, stopped operation left that this boot's records do not
//! cover. The signed loader then loads or verifies.
//! A load archives before it extends the register, and is undone when
//! either fails, so that nothing runs unmeasured. An unload extends
//! before it detaches, so that the register never misses a detach.

use core::ffi::{CStr, c_char, c_int};
use std::ffi::CString;
use std::ffi::OsStr;
use std::fs;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

use super::list::{BPFFS_UPATCHES_DIR, UPATCHES_DIR};
use super::{hex, log_audit, log_err, log_info, log_warn, strerr};
use crate::errno::{
    EACCES, EBADMSG, EINVAL, ENAMETOOLONG, ENODEV, ENOENT, ENOSPC, EOPNOTSUPP, EPERM, EPROTO,
    ESTALE,
};
use crate::heap::xfree;
use crate::sys::libc::{O_DIRECTORY, O_RDONLY, close, errno, getxattr};
use crate::sys::upatch::UPATCH_INSTALL_TARGET_MISSING;
use crate::sys::version::shirudo_version_id;
use crate::text::cstr;
use crate::util::bpf_sys::bpf_obj_get;
use crate::util::chain::{self, memneq_explicit};
use crate::util::config::{self, Scrubbed};
use crate::util::crypto_openssl::{Cert, cms_check_signers, cms_signed_by};
use crate::util::eventlog;
use crate::util::help::{Help, HelpSection};
use crate::util::hex::hex_decode;
use crate::util::identity;
use crate::util::io::{open_beneath_same_mount, read_fd, read_file};
use crate::util::java_agent;
use crate::util::json::JsonEmit;
use crate::util::kernel_abi;
use crate::util::measured::MeasuredSet;
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptParser, OptSpec};
use crate::util::report::{OpReport, report_emit};
use crate::util::seal;
use crate::util::upatch::{TYPE_BPF, TYPE_JAVA, Upatch, name_valid, pin_name};
use crate::util::upatch_resolve::XATTR_PAYLOAD;
use crate::util::upatch_verify::{archive_verify, loaded_payload};

/// LSM_LINK_PIN and XATTR_PAYLOAD of util/paths.h, and the most a
/// .upatch file holds.
const UPATCHES_DIR_C: &CStr = c"/var/lib/shirudo/upatches";
pub(super) const LSM_LINK_PIN: &CStr = c"/run/shirudo/bpffs/lsm_link";
pub(crate) const UPATCH_PURGE_OTHER_SIGNER: c_int = 2;
pub(crate) const UPATCH_PURGE_NO_ARCHIVE: c_int = 3;
const UPATCH_FILE_MAX: usize = 16 * 1024 * 1024;
const DIGEST_LEN: usize = 32;
const KERNEL_ABI_DETAIL_MAX: usize = 256;
/// Private bpffs directory requests from include/shirudo/enforcement.h.
const PIN_GRANT_BEGIN: libc::c_ulong = 0x5352_0002;
const PIN_GRANT_END: libc::c_ulong = 0x5352_0003;
const PIN_GRANT_ACK: c_int = 1003;
const BPFFS_REL_PREFIX: &[u8] = b"/run/shirudo/bpffs/";

/// What a load or an unload is asked to do.
#[derive(Default)]
struct OpArgs<'a> {
    file: Option<&'a CStr>,
    expect_chain: Option<&'a CStr>,
    expect_version_id: Option<&'a CStr>,
    report: Option<&'a CStr>,
    no_precheck: bool,
    no_version_check: bool,
    /// An install of the very payload loaded is done.
    loaded_is_done: bool,
}

const OP_EXPECT_CHAIN: c_int = 0;
const OP_EXPECT_VERSION_ID: c_int = 1;
const OP_NO_PRECHECK: c_int = 2;
const OP_NO_VERSION_CHECK: c_int = 3;
const OP_REPORT: c_int = 4;

static OP_OPTS: [OptSpec; 5] = [
    OptSpec::new(
        c"--expect-chain",
        0,
        0,
        Some(c"<hex>"),
        c"refuse unless the register holds this value before",
    ),
    OptSpec::new(
        c"--expect-version-id",
        0,
        0,
        Some(c"<hex>"),
        c"refuse unless this binary's SHIRUDO_VERSION_ID is this",
    ),
    OptSpec::new(
        c"--no-precheck",
        0,
        0,
        None,
        c"skip the pre-flight checks, --expect-chain included",
    ),
    OptSpec::new(
        c"--no-version-check",
        0,
        0,
        None,
        c"skip the --expect-version-id comparison",
    ),
    OptSpec::new(
        c"--report",
        0,
        0,
        Some(c"<path>"),
        c"write the JSON report there, - for standard output",
    ),
];

static OP_SECTIONS: [HelpSection; 1] = [HelpSection::options(c"options:", &OP_OPTS)];

static LOAD_HELP: Help = Help::new(
    c"shirudo upatch load [--expect-chain=<hex>] [--expect-version-id=<hex>]\n                       \
      [--no-precheck] [--no-version-check] [--report=<path>]\n                       \
      <file.upatch>",
    Some(
        c"Load a signed LOAD .upatch into the target kernel: verify the\n\
          signature, run the loader, pin the resulting link, and extend this\n\
          boot's TPM measurement register. Target-only.",
    ),
    &OP_SECTIONS,
    Some(
        c"Examples:\n  shirudo upatch load cve-2026-31431.upatch\n  \
          shirudo upatch load --expect-chain=$(...) foo.upatch\n  \
          shirudo upatch load --report=- foo.upatch | jq",
    ),
);

static UNLOAD_HELP: Help = Help::new(
    c"shirudo upatch unload [--expect-chain=<hex>] [--expect-version-id=<hex>]\n                       \
      [--no-precheck] [--no-version-check] [--report=<path>]\n                       \
      <unload-directive.upatch>",
    Some(
        c"Apply a signed UNLOAD directive: detach the named upatch,\n\
          remove its pin, and extend the TPM measurement register (unloads\n\
          move the register forward, never roll it back). Target-only.",
    ),
    &OP_SECTIONS,
    Some(
        c"Examples:\n  shirudo upatch unload cve-2026-31431.unload.upatch\n  \
          shirudo upatch unload --report=- foo.unload.upatch | jq",
    ),
);

/// The options and the file of a load or an unload, or how the command
/// exits without running: 0 after help.
fn parse<'a>(args: &'a [&'a CStr], unload: bool) -> Result<OpArgs<'a>, c_int> {
    let (command, help) = if unload {
        (c"upatch unload", &UNLOAD_HELP)
    } else {
        (c"upatch load", &LOAD_HELP)
    };
    let mut p = OptParser::new(command, &OP_OPTS, Some(help), args, 1);
    let mut o = OpArgs::default();

    loop {
        let opt = p.next();
        let value = p.value();
        match opt {
            OPT_END => break,
            OP_EXPECT_CHAIN => {
                if value.and_then(decode_chain).is_none() {
                    p.usage(
                        format!(
                            "--expect-chain must be {} hexadecimal characters",
                            2 * DIGEST_LEN
                        )
                        .as_bytes(),
                    );
                    return Err(EXIT_USAGE);
                }
                o.expect_chain = value;
            }
            OP_EXPECT_VERSION_ID => o.expect_version_id = value,
            OP_NO_PRECHECK => o.no_precheck = true,
            OP_NO_VERSION_CHECK => o.no_version_check = true,
            OP_REPORT => o.report = value,
            OPT_ARG => {
                if o.file.is_some() {
                    p.usage_arg(b"unexpected argument ");
                    return Err(EXIT_USAGE);
                }
                o.file = value;
            }
            OPT_DONE => return Err(0),
            _ => return Err(EXIT_USAGE),
        }
    }
    if o.file.is_none() {
        p.usage(b"takes the .upatch file");
        return Err(EXIT_USAGE);
    }
    Ok(o)
}

/// The register value a caller expects, as hex_decode() reads it.
fn decode_chain(hex: &CStr) -> Option<[u8; DIGEST_LEN]> {
    let mut want = [0u8; DIGEST_LEN];
    // SAFETY: a C string and room for the digest.
    (unsafe { hex_decode(hex.as_ptr(), want.as_mut_ptr(), DIGEST_LEN) } == 0).then_some(want)
}

/// Keep a clipped report message visibly clipped, as the C report did.
fn copy_report_message(dst: &mut [c_char], message: &[u8]) {
    let Some(room) = dst.len().checked_sub(1) else {
        return;
    };
    let n = message.len().min(room);
    for (d, &s) in dst.iter_mut().zip(&message[..n]) {
        *d = c_char::from_ne_bytes([s]);
    }
    dst[n] = 0;
    if message.len() > room && dst.len() >= 4 {
        let suffix = dst.len() - 4;
        for (d, &s) in dst[suffix..].iter_mut().zip(b"...\0") {
            *d = c_char::from_ne_bytes([s]);
        }
    }
}

/// Records a failure in the report.
pub(super) fn fail(
    rep: &mut OpReport,
    phase: &'static CStr,
    category: &'static CStr,
    err: c_int,
    message: &[u8],
) {
    rep.ok = false;
    rep.phase = phase;
    rep.category = Some(category);
    rep.err = err.abs();
    copy_report_message(&mut rep.message, message);
}

fn category_is(rep: &OpReport, category: &[u8]) -> bool {
    rep.category.is_some_and(|c| c.to_bytes() == category)
}

/// The version gate, which runs first: a caller built from other sources
/// than this target makes every later comparison meaningless.
fn version_gate(a: &OpArgs, rep: &mut OpReport, op: &[u8]) -> Result<(), ()> {
    let Some(want) = a.expect_version_id.filter(|_| !a.no_version_check) else {
        return Ok(());
    };
    // SAFETY: the build's version ID, a C string.
    let have = unsafe { CStr::from_ptr(&raw const shirudo_version_id) };
    if want == have {
        return Ok(());
    }
    log_err(
        &[
            b"upatch ",
            op,
            b": version mismatch, the operator expects ",
            want.to_bytes(),
            b" and the target is ",
            have.to_bytes(),
            b"; deploy a matching shirudo or pass --no-version-check",
        ]
        .concat(),
    );
    fail(
        rep,
        c"pre_flight",
        c"version_mismatch",
        EPERM,
        b"SHIRUDO_VERSION_ID mismatch (operator vs target)",
    );
    Err(())
}

/// The file at `path`, at most UPATCH_FILE_MAX bytes of it, or -errno.
fn read(path: &CStr) -> Result<Vec<u8>, c_int> {
    let (mut buf, mut len): (*mut u8, usize) = (core::ptr::null_mut(), 0);
    // SAFETY: a C string and room for the buffer and its length.
    let ret = unsafe {
        read_file(
            path.as_ptr(),
            UPATCH_FILE_MAX,
            (&raw mut buf).cast(),
            &mut len,
        )
    };
    if ret != 0 {
        return Err(ret);
    }
    // SAFETY: the len bytes read.
    let data = unsafe { crate::ffi::slice(buf, len) }.to_vec();
    // SAFETY: the buffer and its NUL, freed once.
    unsafe { xfree(buf.cast(), len + 1) };
    Ok(data)
}

fn archive_path(name: &[u8]) -> CString {
    CString::new([UPATCHES_DIR.as_bytes(), b"/", name, b".upatch"].concat()).unwrap_or_default()
}

/// Archives the bytes a load read for boot restore: 0 or -errno.
fn persist(data: &[u8], name: &[u8]) -> c_int {
    if let Err(ret) = seal::mkdir_p(UPATCHES_DIR_C.to_bytes(), 0o700) {
        log_err(&[b"mkdir ", UPATCHES_DIR.as_bytes(), b": ", strerr(-ret)].concat());
        return ret;
    }
    seal::write_file(archive_path(name).to_bytes(), data, 0o644)
        .err()
        .unwrap_or(0)
}

fn os(b: &[u8]) -> &OsStr {
    OsStr::from_bytes(b)
}

fn io_err(e: &std::io::Error) -> c_int {
    -e.raw_os_error().unwrap_or(crate::errno::EIO)
}

// A sync failure leaves jars or options temporarily out of step. It
// refuses no operation: the next upatch command and init retry it.
fn java_options_sync(op: &[u8]) {
    if let Err(err) = java_agent::sync() {
        log_warn(
            &[
                &b"upatch "[..],
                op,
                b": cannot update /run/environment.d/shirudo.conf: ",
                strerr(-err),
                b"; JVMs started now do not see the change",
            ]
            .concat(),
        );
    }
}

/// The pin directory of upatch `name`.
fn pin_dir(name: &[u8]) -> Vec<u8> {
    [BPFFS_UPATCHES_DIR.as_bytes(), b"/", &pin_name(name)].concat()
}

/// Whether the upatch has its pin directory, loaded or part way there.
/// An error other than absence is kept: an unreadable directory may hold
/// a live link and must never be taken for none.
fn pinned(name: &[u8]) -> Result<bool, c_int> {
    match fs::metadata(os(&pin_dir(name))) {
        Ok(_) => Ok(true),
        Err(e) if e.raw_os_error() == Some(ENOENT) => Ok(false),
        Err(e) => Err(io_err(&e)),
    }
}

/// A task-local permission to delete pins below one open upatch directory.
/// The descriptor keeps its inode number from being reused until release.
pub(super) struct PinGrant(OwnedFd);

impl PinGrant {
    pub(super) fn open(name: &[u8]) -> Result<Self, c_int> {
        let path = crate::util::upatch_resolve::pin_path(name, &[])?;
        let rel = path
            .to_bytes()
            .strip_prefix(BPFFS_REL_PREFIX)
            .ok_or(-EINVAL)?;
        let rel = CString::new(rel).map_err(|_| -EINVAL)?;
        let root =
            identity::bpffs_root_open().map_err(|e| if e == -ENOENT { -ENODEV } else { e })?;
        let fd = open_beneath_same_mount(root.as_raw_fd(), &rel, O_RDONLY | O_DIRECTORY)?;
        Self::request(fd.as_fd(), PIN_GRANT_BEGIN)?;
        Ok(Self(fd))
    }

    fn request(fd: BorrowedFd<'_>, command: libc::c_ulong) -> Result<(), c_int> {
        // SAFETY: the descriptor is an open directory and the request has no pointer argument.
        let ret = unsafe { libc::ioctl(fd.as_raw_fd(), command, 0) };
        if ret >= 0 {
            return Err(-EPROTO);
        }
        let err = errno();
        if err == PIN_GRANT_ACK {
            Ok(())
        } else {
            Err(-err)
        }
    }
}

impl Drop for PinGrant {
    fn drop(&mut self) {
        if Self::request(self.0.as_fd(), PIN_GRANT_END).is_err() {
            log_err(b"upatch: cannot release pin deletion authority; terminating");
            // SAFETY: an unreleased task grant must not survive this process.
            unsafe { libc::_exit(1) };
        }
    }
}

/// Removes the entries of `dir`, none a directory, and then `dir`.
fn wipe(dir: &[u8]) -> c_int {
    let entries = match fs::read_dir(os(dir)) {
        Ok(d) => d,
        Err(e) => return io_err(&e),
    };
    for e in entries.map_while(Result::ok) {
        if let Err(e) = fs::remove_file(e.path())
            && e.raw_os_error() != Some(ENOENT)
        {
            return io_err(&e);
        }
    }
    match fs::remove_dir(os(dir)) {
        Err(e) if e.raw_os_error() != Some(ENOENT) => io_err(&e),
        _ => 0,
    }
}

/// Removes the pins of upatch `name`. Unlinking the link pin drops its
/// last reference, which detaches.
pub(super) fn remove_pins(name: &[u8]) -> c_int {
    let dir = pin_dir(name);
    let _grant = match PinGrant::open(name) {
        Ok(grant) => grant,
        Err(err) => return err,
    };
    for sub in [&b"/maps"[..], b"/serializers"] {
        let sub = [&dir[..], sub].concat();
        if fs::metadata(os(&sub)).is_ok() {
            let ret = wipe(&sub);
            if ret != 0 {
                return ret;
            }
        }
    }
    wipe(&dir)
}

/// The payload digest recorded on the pins of upatch `name`, the value
/// bpf2's xattr guard keeps unforgeable, or -errno.
fn pin_payload(name: &[u8]) -> Result<[u8; DIGEST_LEN], c_int> {
    let dir = CString::new(pin_dir(name)).map_err(|_| -EINVAL)?;
    let mut out = [0u8; DIGEST_LEN];
    // SAFETY: two C strings and room for the digest.
    let n = unsafe {
        getxattr(
            dir.as_ptr(),
            XATTR_PAYLOAD.as_ptr(),
            out.as_mut_ptr().cast(),
            DIGEST_LEN,
        )
    };
    match n {
        n if n < 0 => Err(-errno()),
        32 => Ok(out),
        _ => Err(-EINVAL),
    }
}

fn refuse_loaded(rep: &mut OpReport, name: &[u8], missing: &[u8]) -> c_int {
    log_err(
        &[
            b"upatch load: ",
            name,
            b" is already loaded",
            missing,
            b"; unload it with its signed directive first",
        ]
        .concat(),
    );
    fail(
        rep,
        c"pin",
        c"already_loaded",
        crate::errno::EEXIST,
        b"upatch already loaded",
    );
    1
}

/// Takes a load the register did not record back out: pins or jar, then
/// archive.
fn undo_load(name: &[u8], ty: u32) -> c_int {
    let ret = if ty == TYPE_JAVA {
        java_agent::retire(name).err().unwrap_or(0)
    } else {
        remove_pins(name)
    };
    if ret != 0 {
        return ret;
    }
    match fs::remove_file(os(archive_path(name).to_bytes())) {
        Err(e) if e.raw_os_error() != Some(ENOENT) => io_err(&e),
        _ => 0,
    }
}

fn unload_unmeasured(name: &[u8], ty: u32) {
    match undo_load(name, ty) {
        0 => log_err(
            &[
                b"upatch load: ",
                name,
                b" was not measured; the load was undone",
            ]
            .concat(),
        ),
        err => log_err(
            &[
                b"upatch load: ",
                name,
                b" is loaded but not measured and could not be undone: ",
                strerr(-err),
                b"; operator must reconcile",
            ]
            .concat(),
        ),
    }
}

/// An undo pass callback: the rest are still undone when one fails, and
/// `failed` keeps the first error.
fn undo_pin(name: &[u8], failed: &mut c_int) -> c_int {
    match undo_load(name, TYPE_BPF) {
        0 => log_audit(
            &[
                b"upatch: ",
                name,
                b" was pinned without a record of this boot; the load was undone",
            ]
            .concat(),
        ),
        err => {
            log_err(
                &[
                    b"upatch: ",
                    name,
                    b" is pinned without a record of this boot and could not be undone: ",
                    strerr(-err),
                    b"; operator must reconcile",
                ]
                .concat(),
            );
            if *failed == 0 {
                *failed = err;
            }
        }
    }
    0
}

/// As [`undo_pin`], for an archive no record covers.
fn undo_archive(name: &[u8], path: &[u8], failed: &mut c_int) -> c_int {
    match fs::remove_file(os(path)) {
        Err(e) if e.raw_os_error() != Some(ENOENT) => {
            let err = io_err(&e);
            log_err(
                &[
                    b"upatch: ",
                    name,
                    b" is archived without a record of its load and could not be removed: ",
                    strerr(-err),
                    b"; operator must reconcile",
                ]
                .concat(),
            );
            if *failed == 0 {
                *failed = err;
            }
        }
        _ => log_audit(
            &[
                b"upatch: ",
                name,
                b" was archived without a record of its load; the archive was removed",
            ]
            .concat(),
        ),
    }
    0
}

/// Undoes what earlier operations left that this boot's records do not
/// cover: a load a signal stopped between its pins and its extend, an
/// unload stopped between its append and its detach, an archive brought
/// back after its unload. It runs under the register lock a load holds
/// from before its pins to its append, so that it never takes a load in
/// flight for a stopped one. An operation whose pass fails refuses: a
/// load beside such pins could share their directory under one name.
fn undo_unmeasured(rep: &mut OpReport, op: &[u8]) -> Result<(), ()> {
    let set = match MeasuredSet::boot() {
        Ok(set) => set,
        // The records count only as the register vouches for them: the
        // eventlog and the boot ID are paths root can bind over in a
        // namespace of its own.
        Err(ret) if ret == -EBADMSG => {
            log_err(
            &[
                b"upatch ",
                op,
                b": this boot's eventlog records do not fold to the measurement register; refused, nothing changed",
            ]
            .concat(),
        );
            fail(
                rep,
                c"tpm_extend",
                c"tampered",
                ret,
                b"this boot's records do not fold to the register",
            );
            return Err(());
        }
        Err(ret) => {
            log_err(
                &[
                    b"upatch ",
                    op,
                    b": cannot read this boot's records: ",
                    strerr(-ret),
                    b"; refused, nothing changed",
                ]
                .concat(),
            );
            fail(
                rep,
                c"tpm_extend",
                c"tpm_error",
                ret,
                b"cannot read this boot's records",
            );
            return Err(());
        }
    };
    let mut failed: c_int = 0;
    let mut ret = set.unmeasured_pins(|name| undo_pin(name, &mut failed));
    if ret >= 0 {
        ret = set.unmeasured_archives(|name, path| undo_archive(name, path, &mut failed));
    }
    drop(set);
    if ret >= 0 && failed == 0 {
        java_options_sync(op);
        return Ok(());
    }
    let ret = if ret < 0 { ret } else { failed };
    log_err(
        &[
            b"upatch ",
            op,
            b": cannot undo what this boot's records do not cover: ",
            strerr(-ret),
            b"; refused",
        ]
        .concat(),
    );
    fail(
        rep,
        c"tpm_extend",
        c"tpm_error",
        ret,
        b"cannot undo what this boot's records do not cover",
    );
    Err(())
}

/// The tamper gate before any BPF_PROG_LOAD: a kernel whose ABI shirudo
/// does not know, a detached LSM, a missing anchor, or a concurrent
/// operator who advanced the register surface here, before any kernel
/// state changes.
fn preflight(expect_chain: Option<&CStr>, rep: &mut OpReport) -> Result<(), ()> {
    let mut detail = [0u8; KERNEL_ABI_DETAIL_MAX];
    if kernel_abi::check_into(&mut detail) != 0 {
        let detail = cstr(&detail);
        log_err(
            &[
                b"upatch: pre-flight refused (category: kernel_abi_unsupported, message: ",
                detail,
                b")",
            ]
            .concat(),
        );
        fail(
            rep,
            c"pre_flight",
            c"kernel_abi_unsupported",
            EOPNOTSUPP,
            detail,
        );
        return Err(());
    }
    if super::loader::trust_anchor(Some(&mut *rep)).is_err() {
        return Err(());
    }
    // SAFETY: a C string.
    let fd = unsafe { bpf_obj_get(LSM_LINK_PIN.as_ptr()) };
    if fd < 0 {
        let err = errno();
        let category = super::pin_category(err);
        let detached: &[u8] = if err == ENOENT {
            b", message: lsm_detached"
        } else {
            b""
        };
        log_err(
            &[
                b"upatch: pre-flight refused (category: ",
                category.to_bytes(),
                detached,
                b"): open ",
                LSM_LINK_PIN.to_bytes(),
                b": ",
                strerr(err),
            ]
            .concat(),
        );
        fail(
            rep,
            c"pre_flight",
            category,
            err,
            b"cannot open the LSM link pin",
        );
        return Err(());
    }
    // SAFETY: the pin opened above.
    unsafe { close(fd) };

    let Some(expect) = expect_chain else {
        return Ok(());
    };
    let Some(want) = decode_chain(expect) else {
        log_err(b"upatch load: --expect-chain must be 64 hex chars");
        return Err(());
    };
    let mut have = [0u8; DIGEST_LEN];
    match chain::read(&mut have) {
        0 => {}
        r if r == -ENODEV => {
            log_err(b"upatch load: pre-flight refused (category: tampered, message: chain_drift): register unreadable, cannot confirm --expect-chain");
            return Err(());
        }
        r => {
            log_err(&[b"upatch load: chain read failed: ", strerr(-r)].concat());
            return Err(());
        }
    }
    if memneq_explicit(&want, &have) {
        log_err(
            &[
                b"upatch load: pre-flight refused (category: tampered, message: chain_drift): live register ",
                &hex(&have)[..],
                b" is not the expected one; run status and pass the refreshed value",
            ]
            .concat(),
        );
        return Err(());
    }
    Ok(())
}

/// The prechecks, or the warning that they were skipped.
fn precheck(a: &OpArgs, rep: &mut OpReport, op: &[u8]) -> Result<(), ()> {
    if a.no_precheck {
        log_warn(
            &[
                b"upatch ",
                op,
                b": --no-precheck, pre-flight state check skipped",
            ]
            .concat(),
        );
        return Ok(());
    }
    preflight(a.expect_chain, rep).inspect_err(|()| {
        if rep.category.is_none() {
            fail(
                rep,
                c"pre_flight",
                c"tampered",
                EPERM,
                b"pre-flight check failed",
            );
        }
    })
}

/// Refuses an operation whose event the log could not take: the
/// register and the log advance together.
fn eventlog_room(rep: &mut OpReport, op: &[u8]) -> Result<(), ()> {
    let mut cfg = Scrubbed::new();
    let loaded = config::load(&mut cfg);
    if loaded != 0 {
        log_err(
            &[
                b"upatch ",
                op,
                b": configuration unreadable: ",
                strerr(-loaded),
                b"; refused, nothing loaded or extended",
            ]
            .concat(),
        );
        fail(
            rep,
            c"pre_flight",
            c"unknown",
            loaded,
            b"configuration unreadable",
        );
        return Err(());
    }
    let max = cfg.eventlog_max_bytes;
    if !eventlog::would_exceed(max) {
        return Ok(());
    }
    let path = eventlog::path().to_bytes();
    log_err(
        &[
            b"upatch ",
            op,
            b": eventlog ",
            path,
            b" would exceed eventlog.max_bytes ",
            max.to_string().as_bytes(),
            b"; refused, nothing loaded or extended",
        ]
        .concat(),
    );
    fail(
        rep,
        c"pre_flight",
        c"eventlog_full",
        ENOSPC,
        b"eventlog would exceed eventlog.max_bytes",
    );
    Err(())
}

/// The register lock, or its failure logged and reported.
fn take_lock(rep: &mut OpReport, op: &[u8], nothing: &[u8]) -> Result<eventlog::Lock, ()> {
    eventlog::lock().map_err(|err| {
        log_err(
            &[
                b"upatch ",
                op,
                b": cannot take the register lock: ",
                strerr(-err),
                b" (category: tpm_error); ",
                nothing,
            ]
            .concat(),
        );
        fail(
            rep,
            c"tpm_extend",
            c"tpm_error",
            err,
            b"cannot take the register lock",
        );
    })
}

/// The eventlog entry `ty` that mirrors the extend `event`, or -errno.
fn event_record(
    ty: &[u8],
    name: &[u8],
    payload: &[u8; DIGEST_LEN],
    event: &[u8; DIGEST_LEN],
    reason: Option<&[u8]>,
) -> Result<Vec<u8>, c_int> {
    let mut buf = vec![0u8; 4096];
    let mut e = JsonEmit::fixed(&mut buf);
    eventlog::record_open(&mut e, ty, event);
    e.obj_open_key(b"upatch");
    e.kv_string(b"name", name);
    e.kv_string(b"payload_sha256", &hex(payload));
    e.obj_close();
    if let Some(r) = reason {
        e.kv_string(b"reason", r);
    }
    e.obj_close();
    if e.err() != 0 {
        log_err(
            &[
                b"eventlog: ",
                ty,
                b" entry encode failed: ",
                strerr(-e.err()),
            ]
            .concat(),
        );
        return Err(e.err());
    }
    let len = e.written();
    buf.truncate(len);
    Ok(buf)
}

/// One operator operation, measured: its own register event, where boot
/// restore coalesces into one, and the eventlog entry after it. A
/// missing TPM or register is an error, never an unmeasured success.
/// The register value after it goes into `out_chain`; the error, and
/// whether the register moved before it, come back.
#[allow(clippy::too_many_arguments)]
fn measure(
    payload_type: u32,
    load: bool,
    op: &[u8],
    name: &[u8],
    payload: &[u8; DIGEST_LEN],
    reason: Option<&[u8]>,
    out_chain: Option<&mut [c_char; 65]>,
) -> (c_int, bool) {
    let (mut event, mut chain) = ([0u8; DIGEST_LEN], [0u8; DIGEST_LEN]);
    let Some(tag) = chain::upatch_tag(payload_type, load) else {
        log_err(&[b"upatch ", op, b": invalid payload type"].concat());
        return (-EINVAL, false);
    };
    let Some(record) = eventlog::upatch_record(payload_type, load) else {
        log_err(&[b"upatch ", op, b": invalid event record type"].concat());
        return (-EINVAL, false);
    };
    let ret = chain::upatch_event(tag, name, payload, &mut event);
    if ret != 0 {
        log_err(
            &[
                b"upatch ",
                op,
                b": cannot hash the event (category: tpm_error)",
            ]
            .concat(),
        );
        return (ret, false);
    }
    // Prepare the full record before the irreversible register extend.
    let line = match event_record(record, name, payload, &event, reason) {
        Ok(line) => line,
        Err(err) => return (err, false),
    };
    let ret = chain::extend(&event, Some(&mut chain));
    if ret != 0 {
        let why: &[u8] = match ret {
            r if r == -ENODEV => b": TPM register unavailable (category: tpm_error): not measured; shirudo needs the register init bound this boot",
            r if r == -EACCES => b": register is not the one init bound (category: tampered): not measured; the operator must reconcile",
            // A lost answer or a failed read back: the register may have moved.
            _ => b": register extend failed (category: tpm_error): the TPM may have taken the event without its record; the operator must reconcile",
        };
        log_err(&[b"upatch ", op, why].concat());
        return (ret, false);
    }
    let append_err = eventlog::append(&line);
    if append_err != 0 {
        log_err(
            &[b"upatch ", op, b": eventlog append failed after the extend: register and log disagree; the operator must reconcile"]
                .concat(),
        );
        return (append_err, true);
    }
    let chain_hex = hex(&chain);
    if let Some(out) = out_chain {
        for (d, &s) in out.iter_mut().zip(chain_hex.iter().chain(&[0])) {
            *d = s as c_char;
        }
    }
    log_audit(
        &[
            b"upatch ",
            op,
            b": ",
            name,
            b" measured, register ",
            &chain_hex,
        ]
        .concat(),
    );
    (0, true)
}

/// A register other than the one init set up is a verdict, not a TPM
/// fault.
fn chain_category(err: c_int, measured: bool) -> &'static CStr {
    if !measured && err == -EACCES {
        c"tampered"
    } else {
        c"tpm_error"
    }
}

/// The operator's file, read once into memory and parsed there, or why
/// not reported: the name and payload measured, the program loaded and
/// the copy archived all come from that one read. A copy on disk, under
/// a name another command can take, or a file read again, could set them
/// apart.
fn read_artifact(
    file: &CStr,
    fd: Option<BorrowedFd<'_>>,
    rep: &mut OpReport,
    op: &[u8],
) -> Result<Upatch<'static>, ()> {
    let opened = match fd {
        Some(fd) => read_fd(fd, file, UPATCH_FILE_MAX).and_then(Upatch::from_vec),
        None => read(file).and_then(Upatch::from_vec),
    };
    opened.map_err(|err| {
        log_err(
            &[
                b"upatch ",
                op,
                b": read ",
                file.to_bytes(),
                b": ",
                strerr(-err),
            ]
            .concat(),
        );
        fail(
            rep,
            c"parse",
            c"parser_rejected",
            err,
            b"cannot read .upatch",
        );
    })
}

fn set_payload_hex(rep: &mut OpReport, payload: &[u8]) {
    for (d, &s) in rep
        .payload_hex
        .iter_mut()
        .zip(hex(payload).iter().chain(&[0]))
    {
        *d = s as c_char;
    }
}

/// Emits the report a caller asked for, and frees it.
pub(super) fn finish(rep: &mut OpReport, report: Option<&CStr>) {
    if let Some(path) = report {
        report_emit(path, rep);
    }
}

/// A load, after its arguments: 0, 1, or UPATCH_INSTALL_TARGET_MISSING
/// for a kprobe target whose module is not loaded.
fn load(a: &OpArgs) -> c_int {
    let file = a.file.unwrap_or(c"");
    let mut rep = OpReport::new(c"upatch_load");
    rep.path = Some(file.to_owned());
    let mut name = CString::default();
    let mut ret = load_steps(a, file, &mut rep, &mut name);
    if ret == 1 && category_is(&rep, b"attach_target_missing") {
        ret = UPATCH_INSTALL_TARGET_MISSING;
    }
    finish(&mut rep, a.report);
    ret
}

fn load_steps(a: &OpArgs, file: &CStr, rep: &mut OpReport, name_out: &mut CString) -> c_int {
    if version_gate(a, rep, b"load").is_err() {
        return 1;
    }
    let Ok(u) = read_artifact(file, None, rep, b"load") else {
        return 1;
    };
    let name = u.name().to_vec();
    let payload = u.hdr.payload_sha256;
    let payload_type = u.hdr.ty;
    set_payload_hex(rep, &payload);
    *name_out = CString::new(name.clone()).unwrap_or_default();
    rep.name = Some(name_out.clone());

    if precheck(a, rep, b"load").is_err() || eventlog_room(rep, b"load").is_err() {
        return 1;
    }
    if !name_valid(Some(&name)) {
        log_err(
            &[
                b"upatch load: refusing unsafe upatch name '",
                &name[..],
                b"'",
            ]
            .concat(),
        );
        fail(rep, c"parse", c"parser_rejected", 0, b"unsafe upatch name");
        return 1;
    }
    let Ok(_lock) = take_lock(rep, b"load", b"nothing loaded") else {
        return 1;
    };
    if undo_unmeasured(rep, b"load").is_err() {
        return 1;
    }
    // Past the undo pass a payload on the pins is a load this boot's
    // records hold, and only an unload removes it. A load over a live
    // upatch would rebind its serializer pins to maps nothing reads, and
    // an undo of it would take the live one's pins and archive with it.
    // An install of the very payload loaded is done: bpm retries one that
    // a stop cut off between this load and its own record.
    let state = loaded_payload(&name);
    if let Ok(live) = state
        && a.loaded_is_done
        && live == payload
    {
        log_info(
            &[
                b"upatch load: ",
                &name[..],
                b" is already loaded with this payload",
            ]
            .concat(),
        );
        rep.ok = true;
        rep.category = Some(c"already_loaded");
        return 0;
    }
    match state {
        Ok(_) => return refuse_loaded(rep, &name, b""),
        Err(err) if err == -ESTALE => {
            return refuse_loaded(rep, &name, b", without the jar it archived");
        }
        Err(err) if err != -ENOENT => {
            log_err(
                &[
                    &b"upatch load: cannot tell whether "[..],
                    &name,
                    b" is loaded: ",
                    strerr(-err),
                    b"; nothing loaded",
                ]
                .concat(),
            );
            fail(
                rep,
                c"pin",
                c"unknown",
                -err,
                b"cannot tell whether the upatch is loaded",
            );
            return 1;
        }
        Err(_) => {}
    }
    if super::loader::apply(&u, file, false, Some(&mut *rep)).is_err() {
        return 1;
    }

    // Archived before it is measured: the archive is the intent boot
    // restore replays, and an event for an upatch that will not survive
    // a reboot would drift from it. A load whose archive or extend fails
    // is undone, pins and archive, so that no upatch runs unmeasured; a
    // caller who stops this process first gets the same from the next
    // upatch command, and from the next init.
    let err = persist(u.bytes(), &name);
    if err != 0 {
        log_err(
            &[
                b"upatch load: loaded but not archived under ",
                UPATCHES_DIR.as_bytes(),
                b": ",
                strerr(-err),
                b"; not measured",
            ]
            .concat(),
        );
        unload_unmeasured(&name, payload_type);
        fail(
            rep,
            c"persist",
            c"unknown",
            err,
            b"persist failed; the load was undone",
        );
        return 1;
    }
    let (err, measured) = measure(
        payload_type,
        true,
        b"load",
        &name,
        &payload,
        None,
        Some(&mut rep.chain_after),
    );
    if err != 0 {
        if !measured {
            unload_unmeasured(&name, payload_type);
        }
        let msg: &[u8] = if measured {
            b"eventlog append failed after the extend"
        } else {
            b"chain extend failed; the load was undone"
        };
        fail(rep, c"tpm_extend", chain_category(err, measured), err, msg);
        return 1;
    }
    if payload_type == TYPE_JAVA {
        java_options_sync(b"load");
    }
    rep.ok = true;
    rep.phase = c"done";
    rep.tpm_present = rep.chain_after[0] != 0;
    0
}

/// `upatch load`, from `load` on.
pub(super) fn run_load(args: &[&CStr]) -> c_int {
    match parse(args, false) {
        Ok(a) => load(&a),
        Err(code) => code,
    }
}

/// `upatch unload`, from `unload` on.
pub(super) fn run_unload(args: &[&CStr]) -> c_int {
    run_unload_fd(args, None)
}

fn run_unload_fd(args: &[&CStr], fd: Option<BorrowedFd<'_>>) -> c_int {
    let a = match parse(args, true) {
        Ok(a) => a,
        Err(code) => return code,
    };
    let file = a.file.unwrap_or(c"");
    let mut rep = OpReport::new(c"upatch_unload");
    rep.path = Some(file.to_owned());
    let mut name = CString::default();
    let ret = unload_steps(&a, file, fd, &mut rep, &mut name);
    if ret != 0 {
        let message = cstr(bytes_of(&rep.message));
        log_err(
            &[
                &b"upatch unload failed: name="[..],
                if name.is_empty() {
                    b"(unknown)"
                } else {
                    name.to_bytes()
                },
                b" phase=",
                rep.phase.to_bytes(),
                b" category=",
                rep.category.map_or(&b"(unknown)"[..], CStr::to_bytes),
                b" err=",
                rep.err.to_string().as_bytes(),
                b" (",
                if rep.err != 0 {
                    strerr(rep.err)
                } else {
                    b"none"
                },
                b") message=",
                if message.is_empty() {
                    b"(none)"
                } else {
                    message
                },
            ]
            .concat(),
        );
    }
    finish(&mut rep, a.report);
    ret
}

fn bytes_of(a: &[c_char]) -> &[u8] {
    // SAFETY: c_char and u8 have one size and alignment.
    unsafe { core::slice::from_raw_parts(a.as_ptr().cast(), a.len()) }
}

fn java_unload_mismatch(archived: &CStr, rep: &mut OpReport, err: c_int) -> c_int {
    log_err(
        &[
            b"upatch unload: payload_mismatch, ",
            archived.to_bytes(),
            b" is not the Java upatch the directive expects; refused",
        ]
        .concat(),
    );
    fail(
        rep,
        c"pin",
        c"payload_mismatch",
        if err == -ESTALE { EPERM } else { -err },
        b"archived payload does not match directive",
    );
    1
}

fn java_unload_locked(
    name: &[u8],
    payload: &[u8; DIGEST_LEN],
    archived: &CStr,
    rep: &mut OpReport,
) -> c_int {
    match archive_verify(name, payload) {
        Ok(u) if u.hdr.ty == TYPE_JAVA => {}
        Err(err) if err == -ESTALE && fs::metadata(os(archived.to_bytes())).is_err() => {
            log_info(&[b"upatch unload: ", name, b" already unloaded (no archive)"].concat());
            java_options_sync(b"unload");
            rep.ok = true;
            rep.category = Some(c"already_unloaded");
            fail_message(rep, b"already unloaded");
            return 0;
        }
        Ok(_) => return java_unload_mismatch(archived, rep, -ESTALE),
        Err(err) => return java_unload_mismatch(archived, rep, err),
    }
    let (err, _) = measure(
        TYPE_JAVA,
        false,
        b"unload",
        name,
        payload,
        None,
        Some(&mut rep.chain_after),
    );
    if err != 0 {
        fail(
            rep,
            c"tpm_extend",
            chain_category(err, false),
            err,
            b"chain extend failed; nothing removed",
        );
        return 1;
    }
    let mut err = java_agent::retire(name).err().unwrap_or(0);
    if err == 0
        && let Err(e) = fs::remove_file(os(archived.to_bytes()))
        && e.raw_os_error() != Some(ENOENT)
    {
        err = io_err(&e);
    }
    if err != 0 {
        log_err(
            &[
                b"upatch unload: measured, but failed to remove ",
                name,
                b": ",
                strerr(-err),
                b"; repeat the unload",
            ]
            .concat(),
        );
        fail(
            rep,
            c"pin",
            c"detach_failed",
            err,
            b"removal failed after the event was measured",
        );
        return 1;
    }
    java_options_sync(b"unload");
    log_info(&[b"upatch unload: ", name, b" removed"].concat());
    rep.ok = true;
    rep.phase = c"done";
    rep.tpm_present = rep.chain_after[0] != 0;
    0
}

fn unload_steps(
    a: &OpArgs,
    file: &CStr,
    fd: Option<BorrowedFd<'_>>,
    rep: &mut OpReport,
    name_out: &mut CString,
) -> c_int {
    if version_gate(a, rep, b"unload").is_err() {
        return 1;
    }
    // Read once, as a load is: the target and the payload the kernel's
    // signature check covers must be the bytes acted on after it, and a
    // file of root's is root's to rewrite between the two.
    let Ok(u) = read_artifact(file, fd, rep, b"unload") else {
        return 1;
    };
    if !u.is_unload() {
        log_err(
            &[
                b"upatch unload: ",
                file.to_bytes(),
                b" is a LOAD upatch; use `shirudo upatch load`",
            ]
            .concat(),
        );
        fail(rep, c"parse", c"parser_rejected", 0, b"is a LOAD upatch");
        return 1;
    }
    // The target's name and the payload it is expected to carry are the
    // directive's signed sections; the header's name must be the same,
    // since status and the package tooling read it.
    let payload = match u.signed_unload_payload().filter(|_| u.name_signed()) {
        Some(&p) => p,
        None => {
            log_err(
                &[
                    b"upatch unload: the target of ",
                    file.to_bytes(),
                    b" is not signature-covered or differs from the header; rebuild the directive",
                ]
                .concat(),
            );
            fail(
                rep,
                c"parse",
                c"parser_rejected",
                0,
                b"directive target not signed",
            );
            return 1;
        }
    };
    let name = u.name().to_vec();
    *name_out = CString::new(name.clone()).unwrap_or_default();
    rep.name = Some(name_out.clone());
    set_payload_hex(rep, &payload);

    if !name_valid(Some(&name)) {
        log_err(
            &[
                b"upatch unload: refusing unsafe upatch name '",
                &name[..],
                b"'",
            ]
            .concat(),
        );
        fail(rep, c"parse", c"parser_rejected", 0, b"unsafe upatch name");
        return 1;
    }
    let archived = archive_path(&name);
    if precheck(a, rep, b"unload").is_err() || eventlog_room(rep, b"unload").is_err() {
        return 1;
    }
    let Ok(_lock) = take_lock(rep, b"unload", b"nothing detached") else {
        return 1;
    };
    if undo_unmeasured(rep, b"unload").is_err() {
        return 1;
    }
    // A bad signature fails here, before anything is removed.
    if super::loader::apply(&u, file, true, Some(&mut *rep)).is_err() {
        log_err(b"upatch unload: signature verification failed; refusing");
        return 1;
    }
    if u.hdr.ty == TYPE_JAVA {
        return java_unload_locked(&name, &payload, &archived, rep);
    }

    // The live value is the xattr bpf2 guards; the expected one is
    // signed, so a directive detaches the upatch its signer made it for
    // and nothing else. A pin whose value cannot be read is refused; no
    // pin at all is the already-unloaded case below.
    match pin_payload(&name) {
        Ok(live) if memneq_explicit(&live, &payload) => {
            log_err(
                &[
                    b"upatch unload: payload_mismatch, the upatch loaded under '",
                    &name[..],
                    b"' is not what the directive expects; refused",
                ]
                .concat(),
            );
            fail(
                rep,
                c"pin",
                c"payload_mismatch",
                EPERM,
                b"loaded payload does not match directive",
            );
            return 1;
        }
        Ok(_) => log_info(
            &[
                b"upatch unload: ",
                &name[..],
                b" carries the directive's payload",
            ]
            .concat(),
        ),
        Err(err) if err != -ENOENT => {
            log_err(
                &[
                    b"upatch unload: cannot read the payload recorded for '",
                    &name[..],
                    b"': ",
                    strerr(-err),
                    b"; refusing",
                ]
                .concat(),
            );
            fail(
                rep,
                c"pin",
                c"payload_mismatch",
                err,
                b"payload xattr unreadable",
            );
            return 1;
        }
        Err(_) => {}
    }

    let unarchive = || {
        if let Err(e) = fs::remove_file(os(archived.to_bytes()))
            && e.raw_os_error() != Some(ENOENT)
        {
            log_warn(
                &[
                    b"upatch unload: could not remove ",
                    archived.to_bytes(),
                    b": ",
                    strerr(-io_err(&e)),
                ]
                .concat(),
            );
        }
    };
    // An archive with no pins is one init could not restore, or one an
    // interrupted unload left: the directive removes it only when it is
    // the payload the directive names, as it would its pins.
    let pinned = match pinned(&name) {
        Ok(pinned) => pinned,
        Err(err) => {
            log_err(
                &[
                    &b"upatch unload: cannot look at the pins of "[..],
                    &name,
                    b": ",
                    strerr(-err),
                    b"; nothing detached",
                ]
                .concat(),
            );
            fail(rep, c"pin", c"unknown", err, b"pin directory unreadable");
            return 1;
        }
    };
    if !pinned {
        match archive_verify(&name, &payload) {
            Ok(u) if u.hdr.ty == TYPE_BPF => unarchive(),
            Ok(_) => {
                log_err(
                    &[
                        b"upatch unload: payload_mismatch, ",
                        archived.to_bytes(),
                        b" is not the upatch the directive expects; it stays",
                    ]
                    .concat(),
                );
                fail(
                    rep,
                    c"pin",
                    c"payload_mismatch",
                    EPERM,
                    b"archived payload does not match directive",
                );
                return 1;
            }
            Err(err) if err != -ESTALE || fs::metadata(os(archived.to_bytes())).is_ok() => {
                log_err(
                    &[
                        b"upatch unload: payload_mismatch, ",
                        archived.to_bytes(),
                        b" is not the upatch the directive expects; it stays",
                    ]
                    .concat(),
                );
                fail(
                    rep,
                    c"pin",
                    c"payload_mismatch",
                    if err == -ESTALE { EPERM } else { -err },
                    b"archived payload does not match directive",
                );
                return 1;
            }
            Err(_) => {}
        }
        log_info(&[b"upatch unload: ", &name[..], b" already unloaded (no pin)"].concat());
        log_audit(&[b"upatch unload: name=", &name[..], b" already_unloaded"].concat());
        rep.ok = true;
        rep.phase = c"done";
        rep.category = Some(c"already_unloaded");
        fail_message(rep, b"already unloaded");
        return 0;
    }

    // Measured before it happens: a detach the register does not know is
    // what a caller who stops this process at the right moment would get.
    // The other way round, a detach that fails after the event leaves a
    // shield the register says is gone, which the next status reports and
    // the operator can repeat.
    let (err, _) = measure(
        TYPE_BPF,
        false,
        b"unload",
        &name,
        &payload,
        None,
        Some(&mut rep.chain_after),
    );
    if err != 0 {
        fail(
            rep,
            c"tpm_extend",
            chain_category(err, false),
            err,
            b"chain extend failed; nothing detached",
        );
        return 1;
    }
    let err = remove_pins(&name);
    if err != 0 {
        log_err(
            &[
                b"upatch unload: measured, but failed to remove the pin for ",
                &name[..],
                b": ",
                strerr(-err),
                b"; repeat the unload",
            ]
            .concat(),
        );
        fail(
            rep,
            c"pin",
            c"detach_failed",
            err,
            b"pin removal failed after the event was measured",
        );
        return 1;
    }
    log_info(&[b"upatch unload: ", &name[..], b" detached and unpinned"].concat());
    unarchive();
    rep.ok = true;
    rep.phase = c"done";
    rep.tpm_present = rep.chain_after[0] != 0;
    0
}

/// The report's message alone.
fn fail_message(rep: &mut OpReport, message: &[u8]) {
    copy_report_message(&mut rep.message, message);
}

/// An install from a package: a load without the prechecks, done when
/// the payload is already the one loaded.
pub(crate) fn install(path: &CStr) -> c_int {
    load(&OpArgs {
        file: Some(path),
        no_precheck: true,
        loaded_is_done: true,
        ..OpArgs::default()
    })
}

/// A removal from a package: the unload directive at `path`.
pub(crate) fn remove(path: &CStr) -> c_int {
    run_unload_fd(&[c"unload", c"--no-precheck", path], None)
}

/// Remove a package member through the file already checked and held open.
pub(crate) fn remove_fd(path: &CStr, fd: BorrowedFd<'_>) -> c_int {
    run_unload_fd(&[c"unload", c"--no-precheck", path], Some(fd))
}

/// Detaches, unpins and unarchives upatch `name` without a directive,
/// because the key that signed it was revoked. It holds the register
/// lock from the archive read to its unlink, as a load and an unload do,
/// and checks the signer on what that read finds: an upgrade may have
/// replaced the upatch since the caller's scan with one another key
/// signed. 1 when the unload was measured, 0 when only the archive went,
/// UPATCH_PURGE_OTHER_SIGNER when another key signed the archive,
/// UPATCH_PURGE_NO_ARCHIVE when it has gone, or -errno on failure.
/// -ENOENT from the register lock or a pin is a failure.
pub(crate) fn purge(name: &CStr, signer: *const Cert, reason: &CStr) -> c_int {
    if !name_valid(Some(name.to_bytes())) {
        return -EINVAL;
    }
    let _lock = match eventlog::lock() {
        Ok(lock) => lock,
        Err(err) => {
            log_err(
                &[
                    b"upatch purge: cannot take the register lock: ",
                    strerr(-err),
                    b" (category: tpm_error); nothing measured or detached",
                ]
                .concat(),
            );
            return err;
        }
    };
    purge_locked(name.to_bytes(), signer, reason.to_bytes())
}

fn purge_is_loaded(name: &[u8], payload_type: u32) -> Result<bool, c_int> {
    if payload_type != TYPE_JAVA {
        return pinned(name);
    }
    match java_agent::payload(name) {
        Ok(_) => Ok(true),
        Err(err) if err == -ESTALE || err == -ENOENT => Ok(false),
        Err(err) => Err(err),
    }
}

fn purge_archive(name: &[u8]) -> Result<Option<Upatch<'static>>, c_int> {
    let archived = archive_path(name);
    if archived.as_bytes().len() >= 4096 {
        return Err(-ENAMETOOLONG);
    }
    let fd = match seal::open_read(archived.as_bytes()) {
        Ok(fd) => fd,
        Err(err) if err == -ENOENT => return Ok(None),
        Err(err) => return Err(err),
    };
    let u = Upatch::read(&fs::File::from(fd))?;
    if !u.name_signed() || u.name() != name {
        return Err(-EBADMSG);
    }
    Ok(Some(u))
}

/// Check one archive under the register lock before any key is revoked.
/// Returns 0 when its signer can be read, UPATCH_PURGE_NO_ARCHIVE when
/// it has gone, or -errno for a bad archive or lock failure.
pub(crate) fn purge_check(name: &CStr) -> c_int {
    if !name_valid(Some(name.to_bytes())) {
        return -EINVAL;
    }
    let _lock = match eventlog::lock() {
        Ok(lock) => lock,
        Err(err) => return err,
    };
    let u = match purge_archive(name.to_bytes()) {
        Ok(Some(u)) => u,
        Ok(None) => return UPATCH_PURGE_NO_ARCHIVE,
        Err(err) => return err,
    };
    cms_check_signers(u.signature())
}

fn purge_locked(name: &[u8], signer: *const Cert, reason: &[u8]) -> c_int {
    let u = match purge_archive(name) {
        Ok(Some(u)) => u,
        Ok(None) => return UPATCH_PURGE_NO_ARCHIVE,
        Err(err) => return err,
    };
    let archived = archive_path(name);
    let sig = u.signature();
    // SAFETY: the archive's signature and the caller's certificate.
    let ret = unsafe { cms_signed_by(sig.as_ptr(), sig.len(), signer) };
    let payload = u.hdr.payload_sha256;
    let payload_type = u.hdr.ty;
    drop(u);
    if ret != 1 {
        return if ret < 0 {
            ret
        } else {
            UPATCH_PURGE_OTHER_SIGNER
        };
    }

    // As for unload: the event first, then the detach it describes.
    let loaded = match purge_is_loaded(name, payload_type) {
        Ok(loaded) => loaded,
        Err(err) => return err,
    };
    if loaded {
        let (ret, _) = measure(
            payload_type,
            false,
            b"purge",
            name,
            &payload,
            Some(reason),
            None,
        );
        if ret != 0 {
            return ret;
        }
        let ret = if payload_type == TYPE_JAVA {
            java_agent::retire(name).err().unwrap_or(0)
        } else {
            remove_pins(name)
        };
        if ret != 0 {
            log_err(
                &[
                    b"upatch purge: measured, but failed to remove the pin for ",
                    name,
                    b": ",
                    strerr(-ret),
                ]
                .concat(),
            );
            return ret;
        }
    }
    if let Err(e) = fs::remove_file(os(archived.to_bytes()))
        && e.raw_os_error() != Some(ENOENT)
    {
        let err = io_err(&e);
        log_err(
            &[
                b"upatch purge: could not remove ",
                archived.to_bytes(),
                b": ",
                strerr(-err),
            ]
            .concat(),
        );
        return err;
    }
    if payload_type == TYPE_JAVA {
        java_options_sync(b"purge");
    }
    let how: &[u8] = if loaded { b"detached" } else { b"archive_only" };
    log_audit(&[b"upatch purge: name=", name, b" reason=", reason, b" ", how].concat());
    c_int::from(loaded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_report_message_ends_with_ellipsis() {
        let mut out = [0 as c_char; 8];
        copy_report_message(&mut out, b"fine");
        assert_eq!(
            &out[..5],
            &[
                b'f' as c_char,
                b'i' as c_char,
                b'n' as c_char,
                b'e' as c_char,
                0
            ]
        );
        copy_report_message(&mut out, b"a message too long");
        assert_eq!(
            &out,
            &[
                b'a' as c_char,
                b' ' as c_char,
                b'm' as c_char,
                b'e' as c_char,
                b'.' as c_char,
                b'.' as c_char,
                b'.' as c_char,
                0
            ]
        );
    }
}
