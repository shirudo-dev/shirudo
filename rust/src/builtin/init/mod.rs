// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo init`: bootstraps enforcement on a target. It enrols the
//! trusted certificates in the bpf keyring and seals it, mounts the
//! private bpffs, seals the writable state, brings the LSM up, restores
//! the archived upatches and binds this boot's TPM register to what it
//! restored. Idempotent: a re-run finds each phase done and leaves it.

mod lsm;
mod restore;

use core::ffi::{CStr, c_int};
use core::{mem, ptr};
use std::ffi::{CString, OsStr};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

use crate::errno::{EEXIST, EIO, EKEYREJECTED, ENAMETOOLONG, ENOENT, ENOKEY, ENOTBLK, EROFS};
use crate::ffi;
use crate::sys::libc::Zeroed;
use crate::sys::libc::{
    Statfs, Statvfs, fwrite, mount, statfs, statvfs, stdout, strerror, umount2,
};
use crate::text::cstr;
use crate::util::chain;
use crate::util::eventlog::{self, EventlogInit};
use crate::util::help::{Help, HelpSection};
use crate::util::identity;
use crate::util::image_runtime;
use crate::util::initrd;
use crate::util::io::bpffs_mounted_at;
use crate::util::java_agent;
use crate::util::json::JsonEmit;
use crate::util::keyring;
use crate::util::keys::{self, TrustedSet};
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptParser, OptSpec};
use crate::util::preflight::{self, PreflightResult};
use crate::util::seal;

const VAR_LIB: &CStr = c"/var/lib/shirudo";
const RUN_DIR: &CStr = c"/run/shirudo";
const BPFFS_DIR: &CStr = c"/run/shirudo/bpffs";
const RUNTIME_KEYS_DIR: &CStr = c"/run/shirudo/runtime/keys";
const KEYS_REVOKED_DIR: &CStr = c"/var/lib/shirudo/keys/revoked";
/// The register's NV index.
const NV_INDEX: u32 = 0x0181_8E00;
/// `SIG_KEYRING_BPF`: the kind of keyring a signed load names.
const SIG_KEYRING_BPF: u32 = 5;
const PATH_MAX: usize = 4096;
const TMPFS_MAGIC: i64 = 0x0102_1994;
const RAMFS_MAGIC: i64 = 0x8584_58f6;
const MS_NOSUID: u64 = 2;
const MS_NODEV: u64 = 4;
const MS_NOEXEC: u64 = 8;
const MS_BIND: u64 = 4096;
const MS_REC: u64 = 16384;
const MS_PRIVATE: u64 = 1 << 18;
const MNT_DETACH: c_int = 2;
const ST_RDONLY: u64 = 1;

/// A part of a log line: bytes as they are, numbers as `%d` prints them.
pub(super) trait Part {
    fn put(&self, out: &mut Vec<u8>);
}

impl Part for [u8] {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

impl<const N: usize> Part for [u8; N] {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

impl Part for str {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }
}

impl Part for Vec<u8> {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

impl Part for CStr {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.to_bytes());
    }
}

macro_rules! number_part {
    ($($t:ty),*) => {$(
        impl Part for $t {
            fn put(&self, out: &mut Vec<u8>) {
                let _ = write!(out, "{self}");
            }
        }
    )*};
}
number_part!(i32, u32, i64, u64, usize);

impl<T: Part + ?Sized> Part for &T {
    fn put(&self, out: &mut Vec<u8>) {
        (**self).put(out);
    }
}

/// The parts, one after the other.
macro_rules! cat {
    ($($p:expr),* $(,)?) => {{
        let mut out: Vec<u8> = Vec::new();
        $( $crate::builtin::init::Part::put(&$p, &mut out); )*
        out
    }};
}
pub(super) use cat;

fn say(level: fn(&[u8]), text: &[u8]) {
    let msg = CString::new(cstr(text).to_vec()).unwrap_or_default();

    level(msg.to_bytes());
}

pub(super) fn error(text: &[u8]) {
    say(crate::log::err, text);
}

pub(super) fn warn(text: &[u8]) {
    say(crate::log::warn, text);
}

pub(super) fn info(text: &[u8]) {
    say(crate::log::info, text);
}

pub(super) fn strerr(err: c_int) -> &'static [u8] {
    // SAFETY: strerror() gives a C string that outlives the message.
    unsafe { ffi::c_str(strerror(err)) }
}

/// The errno of the call that just failed, as -errno.
pub(super) fn last_err() -> c_int {
    -std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(EIO)
}

pub(super) fn hex(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    bytes
        .iter()
        .flat_map(|b| [HEX[usize::from(b >> 4)], HEX[usize::from(b & 0xf)]])
        .collect()
}

fn print(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stdout.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stdout) };
}

pub(super) fn path(p: &[u8]) -> &OsStr {
    OsStr::from_bytes(p)
}

/// What a run of init carries from one phase to the next.
struct Init {
    /// Runs from the initrd.
    initrd: bool,
    /// The trusted certificates the bpf keyring was given.
    enrolled: TrustedSet,
}

fn print_preflight(r: &PreflightResult) {
    let n = usize::try_from(r.n).unwrap_or(0);

    print(b"Pre-flight checks:\n");
    for c in &r.checks[..n] {
        let detail = cstr(&c.detail);
        let status: &[u8] = if c.ok { b"OK  " } else { b"FAIL" };
        // SAFETY: a check's name, a static C string.
        let name = unsafe { ffi::c_str(c.name) };
        let sep: &[u8] = if detail.is_empty() { b"" } else { b": " };
        print(&cat!("  ", status, "  ", name, sep, detail, "\n"));
    }
    print(&cat!(r.n - r.n_failed, " of ", r.n, " passed\n"));
}

fn print_preflight_json(r: &PreflightResult) -> c_int {
    let n = usize::try_from(r.n).unwrap_or(0);
    let mut buf = [0u8; 8192];
    let mut e = JsonEmit::fixed(&mut buf);

    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_int(b"passed", (r.n - r.n_failed).into());
    e.kv_int(b"failed", r.n_failed.into());
    e.arr_open(b"checks");
    for c in &r.checks[..n] {
        e.obj_open();
        // SAFETY: a check's name, a static C string.
        e.kv_string(b"name", unsafe { ffi::c_str(c.name) });
        e.kv_bool(b"ok", c.ok);
        match cstr(&c.detail) {
            [] => e.kv_null(b"detail"),
            d => e.kv_string(b"detail", d),
        }
        e.obj_close();
    }
    e.arr_close();
    e.obj_close();
    if e.err() != 0 {
        return e.err();
    }
    let len = e.written();
    print(&cat!(&buf[..len], "\n"));
    0
}

/// Enrols the trusted certificates in the bpf keyring and seals it; on
/// a re-run, checks that the anchor init froze is still this keyring.
fn init_keyring(init: &mut Init) -> c_int {
    let ring = keyring::bpf_serial();
    if ring <= 0 {
        let ret = if ring != 0 { ring } else { -ENOKEY };
        error(&cat!("bpf keyring lookup: ", strerr(-ret)));
        return ret;
    }
    if let Ok(id) = identity::read() {
        let same = id.keyring_type == SIG_KEYRING_BPF
            && id.keyring_serial == ring
            && image_runtime::runtime_root() == Some(id.runtime_root);
        return if same { 0 } else { -EKEYREJECTED };
    }
    let mut set = TrustedSet::default();
    let ret = image_runtime::boot_keys(&mut set);
    if ret != 0 {
        return ret;
    }
    let ret = keyring::seal_bpf_set(ring, &set);
    if ret != 0 && ret != -EEXIST {
        return ret;
    }
    init.enrolled = set;
    0
}

fn mkdir_sealed(dir: &CStr, label: &[u8]) -> c_int {
    let Err(ret) = seal::mkdir_p(dir.to_bytes(), 0o700) else {
        return 0;
    };
    error(&cat!(label, "mkdir ", dir, ": ", strerr(-ret)));
    ret
}

fn label(dir: &CStr) -> c_int {
    seal::label(dir).err().unwrap_or(0)
}

fn mounted_bpffs() -> c_int {
    // SAFETY: a C string.
    unsafe { bpffs_mounted_at(BPFFS_DIR.as_ptr()) }
}

fn dev_of(p: &CStr) -> Result<u64, c_int> {
    std::fs::metadata(path(p.to_bytes()))
        .map(|m| m.dev())
        .map_err(|e| -e.raw_os_error().unwrap_or(EIO))
}

/// A private bpffs under a private /run/shirudo, its own tmpfs unless
/// /run/shirudo already is one.
fn init_bpffs() -> c_int {
    let mut ret = mkdir_sealed(VAR_LIB, b"");
    if ret == 0 {
        ret = mkdir_sealed(RUN_DIR, b"");
    }
    if ret != 0 {
        return ret;
    }
    match mounted_bpffs() {
        r if r < 0 => return r,
        0 => {}
        _ => return 0,
    }
    let (parent, run) = match (dev_of(RUN_DIR), dev_of(c"/run")) {
        (Ok(p), Ok(r)) => (p, r),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    if parent == run {
        let ret = label(RUN_DIR);
        if ret != 0 {
            return ret;
        }
        // SAFETY: C strings.
        let failed = unsafe {
            mount(
                c"tmpfs".as_ptr(),
                RUN_DIR.as_ptr(),
                c"tmpfs".as_ptr(),
                MS_NOSUID | MS_NODEV | MS_NOEXEC,
                c"mode=0700,size=16M".as_ptr().cast(),
            )
        } != 0;
        if failed {
            return last_err();
        }
    }
    // SAFETY: a C string.
    if unsafe {
        mount(
            ptr::null(),
            RUN_DIR.as_ptr(),
            ptr::null(),
            MS_PRIVATE | MS_REC,
            ptr::null(),
        )
    } != 0
    {
        return last_err();
    }
    // So that the init record left here is sealed from its creation.
    let ret = label(RUN_DIR);
    if ret != 0 {
        return ret;
    }
    let ret = mkdir_sealed(BPFFS_DIR, b"");
    if ret != 0 {
        return ret;
    }
    match mounted_bpffs() {
        r if r < 0 => {
            error(&cat!("check the bpffs at ", BPFFS_DIR, ": ", strerr(-r)));
            return r;
        }
        0 => {}
        _ => {
            info(&cat!("bpffs already mounted at ", BPFFS_DIR));
            return 0;
        }
    }
    // SAFETY: C strings.
    let failed = unsafe {
        mount(
            c"bpf".as_ptr(),
            BPFFS_DIR.as_ptr(),
            c"bpf".as_ptr(),
            MS_NOSUID | MS_NODEV | MS_NOEXEC,
            c"mode=0700".as_ptr().cast(),
        )
    } != 0;
    if failed {
        let err = last_err();
        error(&cat!("mount bpffs at ", BPFFS_DIR, ": ", strerr(-err)));
        return err;
    }
    info(&cat!(
        "mounted private bpffs at ",
        BPFFS_DIR,
        " (mode=0700,nosuid,nodev,noexec)"
    ));
    0
}

/// The initrd phase reads the root's state tree: the archived upatches
/// to restore, the eventlog to continue, the keys to compare. A
/// recursive writable bind of <sysroot>/var/lib/shirudo keeps every
/// path the same and lets config recovery record its selection
/// durably. The bind is detached when init leaves. The private bpffs is
/// under /run, which systemd carries across the switch.
/// Where the state tree is on the root file system, which the initrd
/// binds.
fn state_source(initrd: bool) -> Vec<u8> {
    if initrd {
        cat!(initrd::sysroot().to_bytes(), VAR_LIB)
    } else {
        VAR_LIB.to_bytes().to_vec()
    }
}

fn initrd_enter() -> c_int {
    let mut root = Statfs::zeroed();

    // /etc/initrd-release is root's to create on the root file system;
    // the initramfs is not. Binding a tree of root's over the state
    // directory is what a run from the root file system would do here.
    // SAFETY: a C string and the room for its file system.
    if unsafe { statfs(c"/".as_ptr(), &mut root) } != 0 {
        return last_err();
    }
    if root.f_type != TMPFS_MAGIC && root.f_type != RAMFS_MAGIC {
        error(b"initrd: the root file system is not an initramfs");
        return -ENOTBLK;
    }
    let sysroot = initrd::sysroot().to_bytes();
    let src = state_source(true);
    if src.len() >= PATH_MAX {
        return -ENAMETOOLONG;
    }
    if !std::fs::metadata(path(&src)).is_ok_and(|m| m.is_dir()) {
        error(&cat!(
            "initrd: ",
            &src,
            " is not a directory; the root file system must be mounted at ",
            sysroot,
            " with /var on it or mounted there (x-initrd.mount)"
        ));
        return -ENOENT;
    }
    let ret = mkdir_sealed(VAR_LIB, b"initrd: ");
    if ret != 0 {
        return ret;
    }
    let src_c = CString::new(src.clone()).unwrap_or_default();
    // SAFETY: C strings.
    if unsafe {
        mount(
            src_c.as_ptr(),
            VAR_LIB.as_ptr(),
            ptr::null(),
            MS_BIND | MS_REC,
            ptr::null(),
        )
    } != 0
    {
        let err = last_err();
        error(&cat!(
            "initrd: bind ",
            &src,
            " at ",
            VAR_LIB,
            ": ",
            strerr(-err)
        ));
        return err;
    }
    // SAFETY: an all-zero statvfs is room for one.
    let mut state: Statvfs = unsafe { mem::zeroed() };
    // SAFETY: a C string and the room.
    let ret = if unsafe { statvfs(VAR_LIB.as_ptr(), &mut state) } != 0 {
        let err = last_err();
        error(&cat!("initrd: statvfs ", &src, ": ", strerr(-err)));
        err
    } else if state.f_flag & ST_RDONLY != 0 {
        error(&cat!("initrd: ", &src, " is read-only"));
        -EROFS
    } else {
        0
    };
    if ret != 0 {
        initrd_leave();
        return ret;
    }
    info(&cat!(
        "initrd: ",
        &src,
        " bound writable at ",
        VAR_LIB,
        " for config recovery"
    ));
    0
}

fn initrd_leave() {
    // SAFETY: a C string.
    if unsafe { umount2(VAR_LIB.as_ptr(), MNT_DETACH) } != 0 {
        let err = last_err();
        warn(&cat!("initrd: detach ", VAR_LIB, ": ", strerr(-err)));
    }
}

fn phase(ret: c_int, what: &str) -> c_int {
    if ret != 0 {
        error(&cat!("init: ", what, " failed: ", strerr(-ret)));
    }
    ret
}

fn run(init: &mut Init) -> c_int {
    // Only the run that brings enforcement up may label an unlabelled
    // tree.
    let active = identity::enforcement_active();
    if active < 0 {
        return phase(active, "reading the enforcement state");
    }
    let bootstrap = active == 0;
    let ret = init_bpffs();
    if ret != 0 {
        return phase(ret, "private bpffs setup");
    }
    if let Err(ret) = java_agent::dir_prepare() {
        return phase(ret, "Java agent directory setup");
    }
    let ret = init_keyring(init);
    if ret != 0 {
        return phase(ret, "BPF keyring initialization");
    }
    let ret = image_runtime::boot_keys_close();
    if ret != 0 {
        return phase(ret, "closing the boot key image");
    }
    // Seal writable state before the hooks attach, then adopt the
    // initrd's log.
    if let Err(ret) = seal::label_tree(bootstrap) {
        return phase(ret, "sealing persistent state");
    }
    if bootstrap {
        let src = state_source(init.initrd);
        let ret = if src.len() >= PATH_MAX {
            -ENAMETOOLONG
        } else {
            seal::mark_ancestors(&src).err().unwrap_or(0)
        };
        if ret != 0 {
            return phase(ret, "marking the directories above the state root");
        }
    }
    let ret = eventlog::adopt_pending_locked();
    if ret != 0 {
        return phase(ret, "adopting the pending eventlog");
    }
    let ret = lsm::attach();
    if ret != 0 {
        return phase(ret, "loading enforcement");
    }
    if let Err(ret) = seal::label_tree(bootstrap) {
        return phase(ret, "sealing initialized state");
    }
    let ret = image_runtime::runtime_mount();
    if ret != 0 {
        return phase(ret, "mounting the authenticated runtime");
    }
    let ret = image_runtime::boot();
    if ret != 0 {
        return phase(ret, "loading authenticated boot settings");
    }
    init.enrolled = match keys::load(RUNTIME_KEYS_DIR, Some(KEYS_REVOKED_DIR), true) {
        Ok(set) => set,
        Err(ret) => return phase(ret, "loading trusted keys"),
    };

    // The record is the eventlog's, which root can hide behind a mount;
    // the register is the TPM's, written once this boot by whoever bound
    // it. Either says the restore has happened.
    // SAFETY: an all-zero record is room for one.
    let mut rec: EventlogInit = unsafe { mem::zeroed() };
    let ret = eventlog::boot_init(&mut rec);
    if ret != 0 && ret != -ENOENT {
        let log = eventlog::path().to_bytes();
        error(&cat!("init: eventlog ", log, " unreadable: ", strerr(-ret)));
        return ret;
    }
    let recorded = ret == 0 || chain::bound();
    let mut set = match restore::boot_restore(recorded) {
        Ok(set) => set,
        Err(ret) => {
            error(b"init: boot-restore failed; further changes and attestation remain blocked");
            return phase(ret, "restoring boot upatches");
        }
    };
    let ret = restore::bind_register(init, &mut set);
    if ret != 0 {
        error(b"init: incomplete: LSM active and upatches loaded, but the TPM register did not advance");
        return phase(ret, "binding the TPM register");
    }
    let ret = image_runtime::boot_complete();
    if ret != 0 {
        return phase(ret, "completing authenticated boot");
    }
    info(b"init: complete (LSM active, writable state sealed)");
    0
}

const INIT_CHECK_ONLY: c_int = 0;
const INIT_JSON: c_int = 1;

static OPTS: [OptSpec; 2] = [
    OptSpec::new(
        c"--check-only",
        0,
        0,
        None,
        c"run the pre-flight only; never touch kernel state",
    ),
    OptSpec::new(
        c"--json",
        0,
        0,
        None,
        c"with --check-only, print the checks as JSON",
    ),
];

static SECTIONS: [HelpSection; 1] = [HelpSection::options(c"options:", &OPTS)];

static HELP: Help = Help::new(
    c"shirudo init [--check-only [--json]]",
    Some(
        c"Bootstrap enforcement on this target. Idempotent; safe to re-run.\n\
          The pinned link survives the process exit.",
    ),
    &SECTIONS,
    None,
);

/// The command on `args`, its name first.
pub(super) fn cmd_init(args: &[&CStr]) -> c_int {
    let (mut check_only, mut json) = (false, false);
    let mut p = OptParser::new(c"init", &OPTS, Some(&HELP), args, 1);

    loop {
        match p.next() {
            OPT_END => break,
            INIT_CHECK_ONLY => check_only = true,
            INIT_JSON => json = true,
            OPT_ARG => {
                p.usage_arg(b"unexpected argument ");
                return EXIT_USAGE;
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    let mut init = Init {
        initrd: initrd::in_initrd(),
        enrolled: TrustedSet::default(),
    };
    let ret = image_runtime::bootstrap_load();
    if ret < 0 {
        error(&cat!("init: authenticated image settings: ", strerr(-ret)));
        return 1;
    }
    if json && !check_only {
        p.usage(b"--json takes --check-only");
        return EXIT_USAGE;
    }
    // SAFETY: an all-zero result is room for one.
    let mut res: Box<PreflightResult> = Box::new(unsafe { mem::zeroed() });
    preflight::run(&mut res);
    if json {
        if print_preflight_json(&res) != 0 {
            return 1;
        }
    } else {
        print_preflight(&res);
    }
    if res.n_failed > 0 {
        error(&cat!(
            "init: pre-flight failed, ",
            res.n_failed,
            " of ",
            res.n,
            " checks"
        ));
        return 1;
    }
    if check_only {
        return 0;
    }
    if init.initrd && initrd_enter() != 0 {
        return 1;
    }
    let ret = run(&mut init);
    image_runtime::leave();
    if init.initrd {
        initrd_leave();
    }
    if ret != 0 { 1 } else { 0 }
}
