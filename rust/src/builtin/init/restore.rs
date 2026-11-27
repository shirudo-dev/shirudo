// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The boot restore, which re-applies the upatches shirudo archived, and
//! the binding of this boot's register to what it restored: one init
//! event, extended once and recorded in the eventlog.

use core::ffi::c_int;
use std::ffi::CString;
use std::fs::File;

use super::{Init, cat, error, hex, info, strerr, warn};
use crate::builtin::upatch::loader;
use crate::errno::{EACCES, EEXIST, EINVAL, ENAMETOOLONG, ENODEV, ENOENT, ENOSPC, EPERM, ESTALE};
use crate::sys::libc::explicit_bzero;
use crate::text::{cstr, name_has_suffix};
use crate::util::bpm_tree_state::state_read;
use crate::util::chain::{self, ChainInitInfo, MeasuredUpatch};
use crate::util::config::{self, Config};
use crate::util::eventlog;
use crate::util::java_agent;
use crate::util::json::JsonEmit;
use crate::util::keys;
use crate::util::measured::{MeasuredSet, upatch_of};
use crate::util::seal;
use crate::util::upatch::{TYPE_JAVA, Upatch};
use crate::util::upatch_pins::loaded_pins;
use crate::util::upatch_resolve;
use crate::util::upatch_verify::links_complete;

const UPATCHES_DIR: &str = "/var/lib/shirudo/upatches";
const BPM_TREE_STATE_PATH: &str = "/var/lib/shirudo/bpm/upatch-tree/state.json";
const CHAIN_PCR: u32 = 9;
const CHAIN_PHASE_PCR: u32 = 11;
const PATH_MAX: usize = 4096;
/// `UPATCH_NAME_MAX`.
const NAME_MAX: usize = 256;
/// `TPM_NAME_LEN`: the register's name, as the eventlog records it.
const TPM_NAME_LEN: usize = 34;
const NV_INDEX_TEXT: &str = "0x01818E00";

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "es" }
}

/// The archived upatches, in alphasort() order: None when there is no
/// archive, or the error that kept it from being listed.
fn archived() -> Result<Option<Vec<Vec<u8>>>, c_int> {
    use std::os::unix::ffi::OsStrExt;

    let entries = match std::fs::read_dir(UPATCHES_DIR) {
        Ok(entries) => entries,
        Err(e) if e.raw_os_error() == Some(ENOENT) => return Ok(None),
        Err(e) => return Err(-e.raw_os_error().unwrap_or(crate::errno::EIO)),
    };
    let mut names = Vec::new();
    for e in entries {
        let e = e.map_err(|e| -e.raw_os_error().unwrap_or(crate::errno::EIO))?;
        let name = e.file_name().as_bytes().to_vec();
        if name_has_suffix(&name, b".upatch") {
            names.push(name);
        }
    }
    names.sort();
    Ok(Some(names))
}

fn java_restore(name: &[u8], file: &CString, u: &Upatch, recorded: bool) -> Result<(), c_int> {
    match java_agent::payload(name) {
        Ok(_) => {
            info(&cat!("boot-restore: ", name, " already installed"));
            return Ok(());
        }
        Err(err) if err == -ESTALE => {}
        Err(err) => {
            error(&cat!(
                "boot-restore: cannot tell whether ",
                name,
                " is installed: ",
                strerr(-err)
            ));
            return Err(err);
        }
    }
    if recorded {
        error(&cat!(
            "boot-restore: the jar of ",
            name,
            " is missing or another after the register was bound this boot (tampered); unload it or reboot"
        ));
        return Err(-EPERM);
    }
    if loader::apply(u, file, false, None).is_err() {
        error(&cat!("boot-restore: failed to install ", name));
        return Err(-EINVAL);
    }
    Ok(())
}

/// Re-applies one archived upatch: Ok(Some(member)) when it counts,
/// Ok(None) when it is not shirudo's to restore, or the error.
fn restore_one(
    name: &[u8],
    measured: &MeasuredSet,
    recorded: bool,
) -> Result<Option<MeasuredUpatch>, c_int> {
    let file = cat!(UPATCHES_DIR, "/", name);
    if file.len() >= PATH_MAX {
        error(&cat!("boot-restore: path too long: ", name));
        return Err(-ENAMETOOLONG);
    }
    let file = CString::new(file).unwrap_or_default();
    let Ok(archive) = seal::open_read(file.to_bytes()) else {
        warn(&cat!(
            "boot-restore: ",
            name,
            " is not shirudo's own (foreign entry); ignored"
        ));
        return Ok(None);
    };
    let Ok(u) = Upatch::read(&File::from(archive)) else {
        warn(&cat!(
            "boot-restore: ",
            name,
            " is not an artifact shirudo archived (foreign entry); ignored"
        ));
        return Ok(None);
    };
    let e = upatch_of(&u);
    let upatch = cstr(&e.name);
    if !measured.holds(cstr(&e.name), cstr(&e.payload_hex)) {
        warn(&cat!(
            "boot-restore: ",
            name,
            " is archived without a record of its load (returned or foreign entry); ignored"
        ));
        return Ok(None);
    }
    if e.ty == TYPE_JAVA {
        java_restore(upatch, &file, &u, recorded)?;
        return Ok(Some(e));
    }
    // By the pins' names alone: an XDP upatch with no device yet has its
    // program pin and no link.
    let loaded = loaded_pins(upatch).inspect_err(|&err| {
        error(&cat!(
            "boot-restore: cannot read the pins of ",
            upatch,
            ": ",
            strerr(-err)
        ));
    })?;
    if loaded {
        let pinned = upatch_resolve::payload_sha256(upatch);
        if pinned != cstr(&e.payload_hex) {
            error(&cat!(
                "boot-restore: ",
                upatch,
                " is loaded with a payload other than the archived one (tampered)"
            ));
            return Err(-EINVAL);
        }
        if links_complete(upatch, &u) != 1 {
            error(&cat!(
                "boot-restore: ",
                upatch,
                " is loaded without every link its signed metadata implies (tampered); unload it or reboot"
            ));
            return Err(-EPERM);
        }
        info(&cat!("boot-restore: ", upatch, " already loaded"));
        return Ok(Some(e));
    }
    if recorded {
        error(&cat!(
            "boot-restore: ",
            name,
            " is archived but not loaded after the register was bound this boot (tampered); unload it or reboot"
        ));
        return Err(-EPERM);
    }
    if loader::apply(&u, &file, false, None).is_err() {
        error(&cat!("boot-restore: failed to apply ", name));
        return Err(-EINVAL);
    }
    Ok(Some(e))
}

/// All or nothing: one failure leaves init incomplete and the register
/// unextended. The eventlog says which archives are shirudo's to
/// restore: those whose load it records without a later unload. One it
/// does not, an archive root brought back through a hard link after its
/// unload or one a stopped load left without a record, carries the
/// label and is ignored. On a re-run an upatch already pinned this boot
/// with the archived payload is counted and left alone; loading it
/// again would only attach a second link to fail at the pin. Once this
/// boot's init event is on record the restore has happened and the
/// register covers what it loaded, so an archived artifact that is not
/// loaded cannot be applied any more: nothing would measure it. It was
/// renamed into the archive since, or left behind by an unload cut
/// short, and either is for the operator to resolve.
fn restore_locked(recorded: bool) -> Result<Vec<MeasuredUpatch>, c_int> {
    let names = match archived() {
        Ok(Some(names)) if !names.is_empty() => names,
        Ok(_) => return Ok(Vec::new()),
        Err(err) => {
            error(&cat!(
                "boot-restore: scandir ",
                UPATCHES_DIR,
                ": ",
                strerr(-err)
            ));
            return Err(err);
        }
    };
    // The loads the eventlog records without a later unload.
    let measured = match MeasuredSet::log() {
        Ok(set) => set,
        Err(ret) => {
            error(&cat!(
                "boot-restore: cannot read the eventlog's loads: ",
                strerr(-ret)
            ));
            return Err(ret);
        }
    };
    let n = names.len();
    info(&cat!(
        "boot-restore: re-applying ",
        n,
        " upatch",
        plural(n),
        " from ",
        UPATCHES_DIR
    ));
    let mut restored = Vec::with_capacity(n);
    for name in &names {
        if let Some(e) = restore_one(name, &measured, recorded)? {
            restored.push(e);
        }
    }
    drop(measured);
    let cnt = restored.len();
    info(&cat!(
        "boot-restore: ",
        cnt,
        " upatch",
        plural(cnt),
        " re-applied"
    ));
    Ok(restored)
}

/// The restore. A run after the register was bound this boot runs
/// beside the upatch commands the completed activation admits, so it
/// takes their lock: an unload between the archive scan and the pin
/// check is otherwise taken for an archived upatch that is not loaded.
pub(super) fn boot_restore(recorded: bool) -> Result<Vec<MeasuredUpatch>, c_int> {
    let lock = match recorded.then(eventlog::lock).transpose() {
        Ok(lock) => lock,
        Err(err) => {
            error(&cat!(
                "boot-restore: cannot take the register lock: ",
                strerr(-err)
            ));
            return Err(err);
        }
    };
    let ret = restore_locked(recorded);
    if ret.is_ok()
        && let Err(err) = java_agent::sync()
    {
        warn(&cat!(
            "boot-restore: cannot bring the Java agents and /run/environment.d/shirudo.conf in line: ",
            strerr(-err)
        ));
    }
    drop(lock);
    ret
}

/// The binding a verifier needs to recompute the register's public area,
/// appended to the eventlog.
fn append_init_event(
    init: &Init,
    set: &[MeasuredUpatch],
    digests: &Digests,
    bound: &ChainInitInfo,
) -> c_int {
    // Every set entry is a name, its digest and their keys.
    let mut buf = vec![0u8; 64 * 1024 + set.len() * (NAME_MAX + 128)];
    let mut e = JsonEmit::fixed(&mut buf);
    let name_len = TPM_NAME_LEN.min(bound.name.len());

    eventlog::record_open(&mut e, b"init", &digests.init);
    e.kv_int(b"tpm_reset_count", bound.reset_count.into());
    e.kv_string(b"cert_sha256", &hex(&digests.cert));
    e.arr_open(b"certs");
    for c in keys::members(&init.enrolled) {
        e.str(&hex(c.sha256()));
    }
    e.arr_close();
    e.kv_string(b"set_digest", &hex(&digests.set));
    e.kv_string(b"tree_root", &hex(&digests.tree_root));
    e.arr_open(b"set");
    for m in set {
        e.obj_open();
        e.kv_string(b"name", cstr(&m.name));
        e.kv_string(b"payload_sha256", cstr(&m.payload_hex));
        if m.ty == TYPE_JAVA {
            e.kv_string(b"type", b"java");
        }
        e.obj_close();
    }
    e.arr_close();
    e.kv_int(b"pcr", CHAIN_PCR.into());
    e.kv_string(b"pcr_before", &hex(&bound.pcr_before));
    e.kv_int(b"phase_pcr", CHAIN_PHASE_PCR.into());
    e.kv_string(b"phase_before", &hex(&bound.phase_before));
    e.kv_string(b"bound_in", if bound.initrd { b"initrd" } else { b"root" });
    e.kv_string(b"nv_name", &hex(&bound.name[..name_len]));
    e.kv_string(b"nv_writer_public", &hex(&bound.writer_public));
    e.kv_string(b"anchor", cstr(&bound.anchor));
    e.kv_string(b"anchor_digest", &hex(&bound.anchor_digest));
    e.kv_string(b"chain", &hex(&bound.value));
    e.obj_close();
    if e.err() != 0 {
        error(&cat!(
            "eventlog: init entry encode failed: ",
            strerr(-e.err())
        ));
        return e.err();
    }
    // From the initrd the record waits under /run for the root file
    // system's init: the eventlog is on a root that is read-only here.
    let log = if init.initrd {
        eventlog::pending_path()
    } else {
        eventlog::path()
    };
    eventlog::append_to(log, e.output())
}

/// The upatch tree's projection root at boot, zero without a tree.
fn tree_root_at_boot() -> Result<[u8; 32], c_int> {
    let mut root = [0; 32];
    let s = match state_read() {
        Err(err) if err == -ENOENT => return Ok(root),
        s => s?,
    };

    crate::util::hex::decode(cstr(&s.projection_root), &mut root)?;
    Ok(root)
}

/// The digests the init event is made of, and the event.
struct Digests {
    cert: [u8; 32],
    set: [u8; 32],
    tree_root: [u8; 32],
    init: [u8; 32],
}

/// eventlog.max_bytes of the configuration.
fn eventlog_max_bytes() -> Result<u64, c_int> {
    let mut cfg = Box::new(Config::zeroed());
    let ret = config::load(&mut cfg);
    let max = cfg.eventlog_max_bytes;

    // SAFETY: the configuration, all of it.
    unsafe { explicit_bzero((&raw mut *cfg).cast(), size_of::<Config>()) };
    if ret != 0 { Err(ret) } else { Ok(max) }
}

/// Binds this boot's register and extends it by one "init" event
/// covering the restored set, then appends the matching eventlog entry.
/// One extension per boot regardless of upatch count; a re-run finds
/// the register written and on record and leaves it alone. The register
/// is mandatory: a TPM that cannot be opened or an index that cannot be
/// bound is a hard error (tpm_error), never an unmeasured init, because
/// an unmeasured target is indistinguishable from a tampered one.
pub(super) fn bind_register(init: &Init, set: &mut [MeasuredUpatch]) -> c_int {
    let mut d = Digests {
        cert: [0; 32],
        set: [0; 32],
        tree_root: [0; 32],
        init: [0; 32],
    };
    let n = set.len();

    match eventlog_max_bytes() {
        Err(ret) => {
            error(&cat!("chain: configuration unreadable: ", strerr(-ret)));
            return ret;
        }
        Ok(max) if eventlog::would_exceed(max) => {
            let log = eventlog::path();
            error(&cat!(
                "eventlog ",
                log,
                " would exceed eventlog.max_bytes=",
                max,
                "; refusing chain extend (eventlog_full)"
            ));
            return -ENOSPC;
        }
        Ok(_) => {}
    }
    if init.enrolled.len() == 0 {
        error(b"chain: no certificate enrolled");
        return -ENOENT;
    }
    d.cert = match init.enrolled.digest() {
        Ok(digest) => digest,
        Err(ret) => {
            error(&cat!("chain: cannot hash the enrolled set: ", strerr(-ret)));
            return ret;
        }
    };
    // init_event = SHA256("shirudo-init\0" || cert_sha256 || set_digest
    //                     || tree_root), the formula the operator's
    // predictor shares (`shirudo attest predict`).
    match tree_root_at_boot() {
        Ok(root) => d.tree_root = root,
        Err(ret) => {
            error(&cat!(
                "chain: cannot read the upatch tree state ",
                BPM_TREE_STATE_PATH,
                ": ",
                strerr(-ret)
            ));
            return ret;
        }
    }
    match chain::init_event(&d.cert, &mut set[..n], &d.tree_root) {
        Ok(digests) => {
            d.set = digests.set;
            d.init = digests.event;
        }
        Err(ret) => {
            error(&cat!("chain: cannot hash the init event: ", strerr(-ret)));
            return ret;
        }
    }
    let mut bound = Box::new(ChainInitInfo::zeroed());
    let ret = chain::init(&d.init, &mut bound);
    match ret {
        0 => {}
        r if r == -ENODEV => {
            error(b"tpm: not usable; shirudo requires a TPM 2.0 (tpm_error)");
            return r;
        }
        r if r == -EEXIST => {
            error(b"tpm: the register this boot recorded is gone or replaced; refusing to bind another before the next TPM reset (tampered)");
            return r;
        }
        r if r == -EACCES => {
            error(&cat!(
                "tpm: register ",
                NV_INDEX_TEXT,
                " cannot be bound (tpm_error); on a TPM with owner auth set, supply it via tpm.owner_auth in /etc/shirudo/shirudo.conf or SHIRUDO_TPM_OWNER_AUTH"
            ));
            return r;
        }
        r => {
            error(b"tpm: register extend failed, the chain did not advance while the LSM is active (tpm_error); the operator must reconcile");
            return r;
        }
    }
    if bound.reused {
        info(&cat!(
            "tpm: register already bound this boot; chain unchanged (index ",
            NV_INDEX_TEXT,
            ")"
        ));
        return 0;
    }
    let ret = append_init_event(init, set, &d, &bound);
    if ret != 0 {
        error(b"eventlog: append failed after the extend: register and log disagree; the operator must reconcile");
        return ret;
    }
    let phase: &str = if bound.initrd {
        "initrd"
    } else {
        "root file system"
    };
    info(&cat!(
        "tpm: register bound in the ",
        phase,
        " and extended (index ",
        NV_INDEX_TEXT,
        ", PCR ",
        CHAIN_PCR,
        " anchored, ",
        n,
        " upatch",
        plural(n),
        " in set)"
    ));
    if !bound.initrd {
        warn(&cat!(
            "tpm: init ran after the initrd; the register's binding can be told from an initrd one by PCR ",
            CHAIN_PHASE_PCR
        ));
    } else if bound.phase_before.iter().all(|&b| b == 0) {
        warn(&cat!(
            "tpm: PCR ",
            CHAIN_PHASE_PCR,
            " holds no phase measurement; systemd measures enter-initrd only for a measured UKI boot, so a verifier cannot pin this binding to the initrd by it"
        ));
    }
    0
}
