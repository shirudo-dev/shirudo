// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Brings the enforcement up: loads `bpf2`, freezes the anchor it
//! enforces into the identity map, and attaches its guards and the
//! seal's in order, the bpf() gates last. Each link is pinned, so it
//! outlives init; a run that fails unpins every link it pinned and
//! removes the maps it pinned, leaving nothing half attached.
//!
//! bpf2 and the seal are light skeletons built into the binary: their
//! loaders, generated when shirudo was built, make their maps and
//! programs, which rust/src/skel.rs gives types; the seal's takes the
//! maps it shares with bpf2 from bpf2.

use core::ffi::{CStr, c_int};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use super::{NV_INDEX, SIG_KEYRING_BPF, cat, error, info, last_err, strerr};
use crate::errno::{E2BIG, EACCES, EINVAL, EKEYREJECTED, ENOENT, ENOKEY, EOPNOTSUPP};
use crate::skel::bpf2::{self, TaskAuthority};
use crate::skel::seal;
use crate::sys::identity::Identity;
use crate::sys::libc::{
    AT_FDCWD, O_CLOEXEC, O_DIRECTORY, O_RDONLY, STATX_MNT_ID_UNIQUE, SYS_PIDFD_OPEN, Statx, Zeroed,
    access, close, open, statx, syscall, unlink,
};
use crate::util::bpf_sys::bpf_map_freeze;
use crate::util::identity;
use crate::util::image_guards::{
    GATE_GUARDS, GATE_HOOK_COUNT, GUARD_BPF, GUARD_BPF_MAP, GUARD_BPF_PROG, GUARD_KEY_PERMISSION,
    GUARD_MAPS, GUARD_PROG_LOAD, GUARD_REMOVEXATTR, GUARD_ROOTS, GUARD_SETXATTR, GUARD_TASKS,
    GUARD_TPM_COMMAND, GUARD_UNLINK, IMAGE_OBSERVER_GUARDS, IMAGE_SEAL_GUARDS, ImageGuard,
    MOUNT_GUARDS, OBSERVER_GUARDS, SEAL_GUARDS,
};
use crate::util::image_runtime;
use crate::util::io::kernel_dev;
use crate::util::keyring;
use crate::util::lskel::{Failed, Prog, Skeleton, pin};
use crate::util::nv_writer;
use crate::util::tpm::Tpm;

const BPFFS_DIR: &CStr = c"/run/shirudo/bpffs";
const RUN_DIR: &CStr = c"/run/shirudo";
const IDENTITY_PIN: &CStr = c"/run/shirudo/bpffs/identity";
const TAMPER_PIN: &CStr = c"/run/shirudo/bpffs/tamper";
const INTEGRITY_PIN: &CStr = c"/run/shirudo/bpffs/integrity";
const TPM_COMMAND_LINK_PIN: &CStr = c"/run/shirudo/bpffs/bpf2_tpm_command_link";
/// What a failed run removes besides its links: every map it pinned.
const MAP_PINS: [&CStr; 9] = [
    IDENTITY_PIN,
    TAMPER_PIN,
    INTEGRITY_PIN,
    c"/run/shirudo/bpffs/unlink_grant",
    c"/run/shirudo/bpffs/task_authority",
    c"/run/shirudo/bpffs/task_policy",
    c"/run/shirudo/bpffs/socket_policy",
    c"/run/shirudo/bpffs/devices",
    c"/run/shirudo/bpffs/config_roots",
];
/// `IDENTITY_KEYS_MAX`: the keys the identity map records.
const IDENTITY_KEYS_MAX: usize = 16;
/// `TASK_BOOTSTRAP`: the authority of the task bringing enforcement up.
const TASK_BOOTSTRAP: u8 = 2;

fn exists(path: &CStr) -> bool {
    // SAFETY: a C string.
    unsafe { access(path.as_ptr(), 0) == 0 }
}

fn gate(guard: usize) -> &'static ImageGuard {
    &GATE_GUARDS[guard]
}

/// Reports a skeleton whose loader failed: its -errno.
fn load_failed(name: &[u8], (step, err): Failed) -> c_int {
    error(&cat!(name, ": ", step, ": ", strerr(-err)));
    err
}

/// A pinned link: dropped, its descriptor lets go of the link, which
/// its pin keeps.
struct Link {
    _fd: OwnedFd,
    pin: &'static CStr,
}

impl Link {
    /// Removes the pin, so that the link goes with its descriptor.
    fn unpin(&self) {
        // SAFETY: a C string.
        unsafe { unlink(self.pin.as_ptr()) };
    }
}

/// Attaches the LSM program `prog` and pins its link at `path`.
fn attach_pin(prog: &Prog<'_>, path: &'static CStr) -> Result<Link, c_int> {
    let link = prog.attach_lsm()?;
    pin(link.as_raw_fd(), path)?;
    Ok(Link {
        _fd: link,
        pin: path,
    })
}

/// Attaches the `guards` of `obj` in order, their links into `links`.
fn attach_group(obj: &Skeleton, guards: &[ImageGuard], links: &mut Vec<Link>) -> c_int {
    for g in guards {
        let Some(p) = obj.prog(g.prog.to_bytes()) else {
            error(&cat!("program ", g.prog.to_bytes(), " missing"));
            return -ENOENT;
        };
        match attach_pin(&p, g.pin) {
            Ok(l) => links.push(l),
            Err(ret) => {
                error(&cat!("attach ", g.prog.to_bytes(), ": ", strerr(-ret)));
                return ret;
            }
        }
    }
    0
}

/// The asymmetric keys of `ring`, at most IDENTITY_KEYS_MAX, and
/// whether it held more.
fn asymmetric_keys(ring: i32) -> Result<(Vec<i32>, bool), c_int> {
    let (mut keys, mut overflow) = (Vec::new(), false);
    let ret = keyring::list(ring, |serial, ty, _| {
        if ty.to_bytes() != b"asymmetric" {
            return;
        }
        if keys.len() >= IDENTITY_KEYS_MAX {
            overflow = true;
        } else {
            keys.push(serial);
        }
    });

    if ret != 0 {
        Err(ret)
    } else {
        Ok((keys, overflow))
    }
}

/// Boot validation checked the complete config verification key set;
/// init freezes the keys the sealed keyring holds.
fn dm_verity_anchor(id: &mut Identity) -> c_int {
    let ring = keyring::dm_verity_serial();

    if ring <= 0 {
        let err = if ring != 0 { ring } else { -ENOKEY };
        error(&cat!(
            "resolve the dm-verity keyring serial: ",
            strerr(-err)
        ));
        return err;
    }
    let (keys, overflow) = match asymmetric_keys(ring) {
        Ok(found) => found,
        Err(err) => {
            error(&cat!(
                "list the dm-verity keyring ",
                ring,
                ": ",
                strerr(-err)
            ));
            return err;
        }
    };
    if keys.is_empty() || overflow {
        error(&cat!(
            "dm-verity keyring ",
            ring,
            " has an invalid key count ",
            keys.len()
        ));
        return -EKEYREJECTED;
    }
    id.dm_verity_ring = ring;
    id.n_dm_verity_keys = keys.len() as u32;
    id.dm_verity_keys[..keys.len()].copy_from_slice(&keys);
    0
}

/// Initial TPM contact is trusted in the authenticated initrd. Later
/// connections salt their sessions with the key whose name is frozen
/// here.
fn record_ek_name(id: &mut Identity) -> c_int {
    match Tpm::open() {
        Ok(tpm) => {
            id.ek_name = *tpm.ek_name();
            0
        }
        Err(ret) => ret,
    }
}

/// Seeds the bootstrap task's authority, freezes the shared state but
/// the expected config roots, which change with each mapping, and pins
/// it.
fn freeze_task_maps(obj: &Skeleton) -> c_int {
    let authority = TaskAuthority {
        trusted: TASK_BOOTSTRAP,
        ..TaskAuthority::zeroed()
    };
    // SAFETY: pidfd_open() of this process.
    let pidfd =
        unsafe { syscall(SYS_PIDFD_OPEN, std::process::id() as c_int, 0 as c_int) } as c_int;
    if pidfd < 0 {
        return last_err();
    }
    let tasks = bpf2::maps(obj).shirudo_tasks;
    let ret = tasks.update(&pidfd, &authority).and_then(|()| {
        let mut maps = GUARD_MAPS.iter().enumerate().skip(GUARD_TASKS);
        maps.try_for_each(|(i, m)| {
            let fd = obj.map_fd(m.def.index);
            // Expected roots change for each mapping.
            let err = if i == GUARD_ROOTS {
                0
            } else {
                bpf_map_freeze(fd)
            };
            if err != 0 {
                return Err(err);
            }
            // SAFETY: a static C string of the table.
            pin(fd, m.pin)
        })
    });
    // SAFETY: the pidfd opened above.
    unsafe { close(pidfd) };
    ret.err().unwrap_or(0)
}

fn mount_id_unique(path: &CStr) -> Result<u64, c_int> {
    let mut stx = Statx::zeroed();
    // SAFETY: path is a C string and stx has room for the result.
    if unsafe { statx(AT_FDCWD, path.as_ptr(), 0, STATX_MNT_ID_UNIQUE, &mut stx) } != 0 {
        return Err(last_err());
    }
    if stx.stx_mask & STATX_MNT_ID_UNIQUE == 0 || stx.stx_mnt_id == 0 {
        return Err(-EOPNOTSUPP);
    }
    Ok(stx.stx_mnt_id)
}

/// The recorder in the mount guards sees the bootstrap task open the
/// bpffs root; the record is read back, since a guard with none to keep
/// would let an unmount above the bpffs through.
fn record_bpffs_mount(obj: &Skeleton) -> Result<(), c_int> {
    // SAFETY: a C string.
    let fd = unsafe { open(BPFFS_DIR.as_ptr(), O_RDONLY | O_DIRECTORY | O_CLOEXEC) };
    if fd < 0 {
        return Err(last_err());
    }
    // SAFETY: open returned this owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    drop(fd);

    let map = bpf2::maps(obj).shirudo_mnt_rec;
    let mut rec = map.lookup(&0)?;
    if rec.mount == 0 || rec.mount_ns == 0 {
        return Err(-ENOENT);
    }
    if super::initrd::in_initrd() {
        rec.initrd_root_id = mount_id_unique(c"/")?;
        rec.sysroot_id = mount_id_unique(super::initrd::sysroot())?;
        if rec.initrd_root_id == rec.sysroot_id {
            return Err(-EINVAL);
        }
        map.update(&0, &rec)?;
    }
    map.freeze()
}

/// The objects and links of one run, in the order a failed run undoes
/// them.
struct Attached {
    seal_obj: Option<Skeleton>,
    image_seal: Vec<Link>,
    image_observer: Vec<Link>,
    observer: Vec<Link>,
    seal: Vec<Link>,
    mount: Vec<Link>,
    gates: [Option<Link>; GATE_HOOK_COUNT],
}

/// The gates in the order a run that ends lets go of them.
const GATE_RELEASE: [usize; GATE_HOOK_COUNT] = [
    GUARD_BPF,
    GUARD_BPF_MAP,
    GUARD_BPF_PROG,
    GUARD_PROG_LOAD,
    GUARD_KEY_PERMISSION,
    GUARD_TPM_COMMAND,
    GUARD_REMOVEXATTR,
    GUARD_SETXATTR,
    GUARD_UNLINK,
];

impl Attached {
    fn gate(&mut self, guard: usize, p: Option<&Prog<'_>>, hook: &str) -> c_int {
        match p
            .ok_or(-ENOENT)
            .and_then(|p| attach_pin(p, gate(guard).pin))
        {
            Ok(l) => {
                self.gates[guard] = Some(l);
                0
            }
            Err(ret) => {
                error(&cat!("attach lsm/", hook, ": ", strerr(-ret)));
                ret
            }
        }
    }

    /// Writable state and runtime processes always get the full seal,
    /// which shares bpf2's policy maps.
    fn attach_seal(&mut self, bpf2: &Skeleton) -> c_int {
        let m = bpf2::maps(bpf2);
        let shared = seal::Shared {
            shirudo_bpffs_sb: &m.shirudo_bpffs_sb,
            shirudo_tasks: &m.shirudo_tasks,
            shirudo_devices: &m.shirudo_devices,
            shirudo_roots: &m.shirudo_roots,
            shirudo_tamper: &m.shirudo_tamper,
            shirudo_task_policy: &m.shirudo_task_policy,
            shirudo_sock_policy: &m.shirudo_sock_policy,
            shirudo_unlink_grant: &m.shirudo_unlink_grant,
        };
        let obj = match seal::load(&shared) {
            Ok(obj) => obj,
            Err(f) => return load_failed(b"seal", f),
        };
        if let Err(err) = seal::maps(&obj).seal_scratch_map.freeze() {
            error(&cat!("seal: freeze seal_scratch_map: ", strerr(-err)));
            return err;
        }
        let (seal, image_seal) = (&SEAL_GUARDS, &IMAGE_SEAL_GUARDS);
        let mut err = attach_group(&obj, seal, &mut self.seal);
        if err == 0 {
            err = attach_group(&obj, image_seal, &mut self.image_seal);
        }
        if err == 0 {
            self.seal_obj = Some(obj);
        }
        err
    }

    fn run(&mut self, obj: &Skeleton) -> c_int {
        let mut id = Identity::zeroed();

        match std::fs::metadata(super::path(BPFFS_DIR.to_bytes())) {
            Ok(m) => id.sb_dev = kernel_dev(std::os::unix::fs::MetadataExt::dev(&m)),
            Err(e) => {
                let err = -e.raw_os_error().unwrap_or(crate::errno::EIO);
                error(&cat!("stat ", BPFFS_DIR, ": ", strerr(-err)));
                return err;
            }
        }
        match std::fs::metadata(super::path(RUN_DIR.to_bytes())) {
            Ok(m) => id.run_dev = kernel_dev(std::os::unix::fs::MetadataExt::dev(&m)),
            Err(e) => return -e.raw_os_error().unwrap_or(crate::errno::EIO),
        }
        match std::fs::metadata(super::path(super::VAR_LIB.to_bytes())) {
            Ok(m) => {
                id.state_dev = std::os::unix::fs::MetadataExt::dev(&m);
                id.state_ino = std::os::unix::fs::MetadataExt::ino(&m);
            }
            Err(e) => return -e.raw_os_error().unwrap_or(crate::errno::EIO),
        }
        let Some(root) = image_runtime::runtime_root() else {
            return -crate::errno::EINVAL;
        };
        id.runtime_root = root;
        let Some(config_pcr) = image_runtime::config_pcr() else {
            return -crate::errno::EINVAL;
        };
        id.config_pcr = config_pcr;

        // The trust anchor lsm/bpf_prog_load enforces: only a load the
        // kernel verified against exactly this sealed keyring, of exactly
        // this kind, is admitted from userspace. The keyring is enrolled
        // and sealed by now, so this resolves the serial the kernel
        // records for a load that names it as keyring_id.
        let keyring = keyring::bpf_serial();
        id.keyring_type = SIG_KEYRING_BPF;
        if keyring <= 0 {
            let err = if keyring != 0 { keyring } else { -ENOKEY };
            error(&cat!("resolve the bpf keyring serial: ", strerr(-err)));
            return err;
        }
        id.keyring_serial = keyring;

        // The keys that keyring holds, for lsm/key_permission: with the
        // keyring itself, what no task but shirudo may write, unlink,
        // revoke or invalidate for the rest of the boot.
        let (keys, overflow) = match asymmetric_keys(keyring) {
            Ok(k) => k,
            Err(err) => {
                error(&cat!(
                    "list the anchor keyring ",
                    keyring,
                    ": ",
                    strerr(-err)
                ));
                return err;
            }
        };
        if overflow || keys.is_empty() {
            let what = if overflow { "too many" } else { "no" };
            error(&cat!(
                "anchor keyring ",
                keyring,
                " holds ",
                what,
                " asymmetric keys"
            ));
            return if overflow { -E2BIG } else { -ENOKEY };
        }
        id.n_keys = keys.len() as u32;
        id.nv_index = NV_INDEX;
        id.key_serials[..keys.len()].copy_from_slice(&keys);
        let err = dm_verity_anchor(&mut id);
        if err != 0 {
            return err;
        }
        let err = nv_writer::create(&mut id.nv_writer_seed, &mut id.nv_writer_public);
        if err != 0 {
            error(&cat!("init: create TPM RSA-3072 NV writer: ", strerr(-err)));
            return err;
        }
        let err = record_ek_name(&mut id);
        if err != 0 {
            error(&cat!(
                "init: record the endorsement key name: ",
                strerr(-err),
                " (tpm_error)"
            ));
            return err;
        }

        let sb = bpf2::maps(obj).shirudo_bpffs_sb;
        if let Err(err) = sb.update(&0, &id) {
            error(&cat!("populate sb-identity map: ", strerr(-err)));
            return err;
        }
        if let Err(err) = sb.freeze() {
            error(&cat!("freeze sb-identity map: ", strerr(-err)));
            return err;
        }
        let err = freeze_task_maps(obj);
        if err != 0 {
            return err;
        }
        // Pinned so that every later command reads the anchor init froze
        // from the kernel rather than from a file: the serial a load
        // names and status reports is the one lsm/bpf_prog_load enforces.
        if let Err(err) = sb.pin(IDENTITY_PIN) {
            error(&cat!(
                "pin identity map at ",
                IDENTITY_PIN,
                ": ",
                strerr(-err)
            ));
            return err;
        }

        // The executable-identity guard precedes every BPF admission gate.
        let (observer, image_observer, mount) =
            (&OBSERVER_GUARDS, &IMAGE_OBSERVER_GUARDS, &MOUNT_GUARDS);
        let mut err = attach_group(obj, observer, &mut self.observer);
        if err == 0 {
            err = attach_group(obj, image_observer, &mut self.image_observer);
        }
        if err != 0 {
            return err;
        }
        let mut progs = Vec::new();
        for g in 0..GATE_HOOK_COUNT {
            let Some(p) = obj.prog(gate(g).prog.to_bytes()) else {
                error(b"expected programs missing in bpf2 object");
                return -ENOENT;
            };
            progs.push((g, p));
        }
        let prog = |guard: usize| progs.iter().find(|(g, _)| *g == guard).map(|(_, p)| p);

        // The prctl identity guard is already active. The remaining hooks
        // go on as the bpffs guards, the seal's filesystem and
        // exec-identity hooks, then the bpf() gates (map fd access,
        // bpf_prog_load admission, then lsm/bpf) LAST. Pinning a link
        // creates a bpffs inode, gated by neither guard set; the seal's
        // unsigned load and the identity-map freeze precede the gates.
        for (guard, hook) in [
            (GUARD_UNLINK, "inode_unlink"),
            (GUARD_SETXATTR, "inode_setxattr"),
            (GUARD_REMOVEXATTR, "inode_removexattr"),
            (GUARD_KEY_PERMISSION, "key_permission"),
            (GUARD_TPM_COMMAND, "tpm_command"),
        ] {
            let err = self.gate(guard, prog(guard), hook);
            if err != 0 {
                return err;
            }
        }
        // With the other bpffs guards, so the mount is immutable before
        // enforcement goes live.
        let err = attach_group(obj, mount, &mut self.mount);
        if err != 0 {
            return err;
        }
        if let Err(err) = record_bpffs_mount(obj) {
            error(&cat!("record the bpffs mount: ", strerr(-err)));
            return err;
        }
        let err = self.attach_seal(obj);
        if err != 0 {
            return err;
        }
        for (guard, hook) in [
            (GUARD_BPF_MAP, "bpf_map"),
            (GUARD_BPF_PROG, "bpf_prog"),
            (GUARD_PROG_LOAD, "bpf_prog_load"),
            (GUARD_BPF, "bpf"),
        ] {
            let err = self.gate(guard, prog(guard), hook);
            if err != 0 {
                return err;
            }
        }
        info(&cat!(
            obj.name(),
            " and seal attached: lsm/bpf gate live, writable state sealed"
        ));
        0
    }

    /// Lets go of the seal and the links; after a failed run (`err`)
    /// unpins each link and removes the maps it pinned first.
    fn release(self, err: c_int) {
        let Attached {
            seal_obj,
            image_seal,
            image_observer,
            observer,
            seal,
            mount,
            mut gates,
        } = self;
        for group in [image_seal, image_observer, observer, seal, mount] {
            for l in group {
                if err != 0 {
                    l.unpin();
                }
            }
        }
        if err != 0 {
            for l in GATE_RELEASE.iter().filter_map(|&g| gates[g].as_ref()) {
                l.unpin();
            }
            for pin in MAP_PINS {
                // SAFETY: a C string.
                unsafe { unlink(pin.as_ptr()) };
            }
        }
        drop(seal_obj);
        for g in GATE_RELEASE {
            drop(gates[g].take());
        }
    }
}

/// Brings the enforcement up, or finds it up.
pub(super) fn attach() -> c_int {
    let bpf_gate = gate(GUARD_BPF).pin;

    if exists(bpf_gate) {
        let mut id = Identity::zeroed();
        let err = identity::read(&mut id);
        if err != 0
            || id.nv_writer_public[0] & 0x80 == 0
            || id.nv_index != NV_INDEX
            || !exists(TPM_COMMAND_LINK_PIN)
        {
            error(b"init: TPM NV index guard missing or changed; reboot with the updated initrd");
            return if err != 0 { err } else { -EACCES };
        }
        info(&cat!(
            "bpf2 already attached (",
            bpf_gate.to_bytes(),
            " exists)"
        ));
        return 0;
    }
    // A failed attempt removes its own pins, a crash does not. Once the
    // identity map is pinned, the image bootstrap refuses a re-run
    // before it gets here, so map pins are all a crash can have left.
    for m in &GUARD_MAPS {
        // SAFETY: a static C string of the table.
        let pin = m.pin;
        // SAFETY: a C string.
        if unsafe { unlink(pin.as_ptr()) } != 0 {
            let err = last_err();
            if err != -ENOENT {
                error(&cat!("unlink stale ", pin, ": ", strerr(-err)));
                return err;
            }
        }
    }
    let obj = match bpf2::load() {
        Ok(obj) => obj,
        Err(f) => return load_failed(b"bpf2", f),
    };
    let mut a = Attached {
        seal_obj: None,
        image_seal: Vec::new(),
        image_observer: Vec::new(),
        observer: Vec::new(),
        seal: Vec::new(),
        mount: Vec::new(),
        gates: [const { None }; GATE_HOOK_COUNT],
    };
    let err = a.run(&obj);
    a.release(err);
    drop(obj);
    err
}
