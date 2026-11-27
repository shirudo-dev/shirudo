// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The config image runtime. The authenticated initrd mounts the runtime
//! image its bootstrap names and the config image the activation journal
//! selects, each a dm-verity device the BPF guards observed being made;
//! every later command but a few finds them as they were left, or
//! refuses to run.
//!
//! A command runs on one thread, so the state is the thread's. The
//! journal and what its callbacks reach are kept apart: a callback
//! borrows the state while the journal that calls it is borrowed, and a
//! borrow taken twice panics rather than aliases.

use core::cell::RefCell;
use core::ffi::{CStr, c_int};
use core::ptr;
use std::ffi::{CString, OsStr};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::ErrorKind;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use crate::errno::{
    EACCES, EBADMSG, EBUSY, EEXIST, EINPROGRESS, EINVAL, EIO, EKEYREJECTED, ENAMETOOLONG, ENODEV,
    ENOENT, ENOKEY, ENXIO, EPERM, EPROTO, ESTALE, EUCLEAN, last_errno, text,
};
use crate::sys::identity::{DEVICE_CONFIG, DEVICE_RUNTIME, DeviceAuthority, Identity};
use crate::sys::libc::Zeroed;
use crate::sys::libc::{
    O_DIRECTORY, O_NOFOLLOW, O_PATH, Statvfs, explicit_bzero, fsetxattr, fstatvfs, fwrite, ioctl,
    stdout, umount2,
};
use crate::text::cstr;
use crate::util::bpf_sys::{bpf_map_get_next_key, bpf_map_lookup_elem, bpf_obj_get};
use crate::util::config::{self, CONF_PATH, Config};
use crate::util::config_image::ConfigImageOpen;
use crate::util::config_measure;
use crate::util::config_update::{
    BootIdentity, ConfigUpdate, ConfigUpdateOps, ConfigUpdateRecord, ConfigUpdateTarget,
};
use crate::util::crypto_openssl::{
    key_algorithm, pubkey_digest, verify_detached_x509, x509_from_der,
};
use crate::util::dm_verity::{self, DmVerity, minor};
use crate::util::hex;
use crate::util::identity;
use crate::util::image_bootstrap::{self, ImageBootstrap, path_valid};
use crate::util::image_cache::{SEAL_LABEL, XATTR_SEAL, fetch_verified};
use crate::util::image_config;
use crate::util::image_guards::{GUARD_DEVICES, GUARD_MAPS, guard_map_check, image_guards_ready};
use crate::util::image_keys::{self, RUNTIME_CERT_PATH};
use crate::util::io::{self, kernel_dev, read_whole};
use crate::util::json::JsonEmit;
use crate::util::keyring;
use crate::util::keys::{TrustedCert, TrustedSet, members, read_der_fd};
use crate::util::seal;
use crate::util::tpm::Tpm;

const RUNTIME_DIR: &CStr = c"/run/shirudo/runtime";
const RUNTIME_CONF_PATH: &CStr = c"/run/shirudo/runtime/etc/shirudo/shirudo.conf";
const CONFIG_IMAGE_DIR: &CStr = c"/run/shirudo/config";
const CONFIG_CANDIDATE_DIR: &CStr = c"/run/shirudo/config-candidate";
const CONFIG_UPDATE_DIR: &CStr = c"/var/lib/shirudo/config-update";
const IMAGE_CACHE_DIR: &CStr = c"/var/lib/shirudo/images";
const DEVICES_MAP: &CStr = c"/run/shirudo/bpffs/devices";
const RUNTIME_MAPPING: &CStr = c"shirudo-runtime";
const CONFIG_NVPCR_AUTH_PATH: &CStr = c"/run/systemd/nvpcr/shirudo-config.auth";

const MNT_DETACH: c_int = 2;
const ST_RDONLY: u64 = 1;
const ST_NOSUID: u64 = 2;
const ST_NODEV: u64 = 4;
const ST_NOEXEC: u64 = 8;
/// _IOR(0x12, 128, __u64).
const BLKGETDISKSEQ: core::ffi::c_ulong = 0x8008_1280;

/// Why a config is prepared: in the initrd, for the boot activation
/// event, as a live update, or to stage it for the next boot.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Prepare {
    Boot,
    BootEvent,
    Update,
    Stage,
}

/// A config verification certificate of the runtime image, read once
/// from the image the guards watched and kept for the command.
struct ConfigCertificate {
    x509: openssl::x509::X509,
    der: Vec<u8>,
    fingerprint: [u8; 32],
}

/// The largest config root signature the image holds,
/// `CONFIG_IMAGE_SIG_MAX`.
const CONFIG_IMAGE_SIG_MAX: usize = 16384;

/// An ext4 file system's root directory's inode.
const EXT4_ROOT_INO: u64 = 2;

/// What the journal's callbacks reach: everything but the journal.
struct State {
    boot_target: ConfigUpdateTarget,
    boot_runtime: DmVerity,
    candidate: Option<ConfigImageOpen>,
    candidate_device: DmVerity,
    bootstrap_config: Config,
    bootstrap: ImageBootstrap,
    tpm: Option<Tpm>,
    candidate_fd: Option<OwnedFd>,
    certificates: Vec<ConfigCertificate>,
    /// What current_config() refused status with.
    config_state: c_int,
    loaded: bool,
    boot_keys_open: bool,
    boot_target_valid: bool,
}

impl State {
    fn new() -> Self {
        State {
            boot_target: ConfigUpdateTarget::zeroed(),
            boot_runtime: DmVerity::empty(),
            candidate: None,
            candidate_device: DmVerity::empty(),
            bootstrap_config: Config::zeroed(),
            bootstrap: ImageBootstrap::empty(),
            tpm: None,
            candidate_fd: None,
            certificates: Vec::new(),
            config_state: 0,
            loaded: false,
            boot_keys_open: false,
            boot_target_valid: false,
        }
    }

    fn candidate_raw(&self) -> c_int {
        self.candidate_fd.as_ref().map_or(-1, AsRawFd::as_raw_fd)
    }
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::new());
    static JOURNAL: RefCell<Option<ConfigUpdate<'static>>> = const { RefCell::new(None) };
}

fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with_borrow_mut(f)
}

/// `f` on the open journal, or -EINVAL without one.
fn with_journal<R>(
    f: impl FnOnce(&mut ConfigUpdate<'static>) -> Result<R, c_int>,
) -> Result<R, c_int> {
    JOURNAL.with_borrow_mut(|journal| journal.as_mut().map_or(Err(-EINVAL), f))
}

fn journal_open() -> bool {
    JOURNAL.with_borrow(Option::is_some)
}

fn say(level: fn(&[u8]), text: String) {
    let text = CString::new(text).unwrap_or_default();

    level(text.to_bytes());
}

fn error(text: String) {
    say(crate::log::err, text);
}

fn warn(text: String) {
    say(crate::log::warn, text);
}

fn io_err(e: &std::io::Error) -> c_int {
    -e.raw_os_error().unwrap_or(EIO)
}

fn path(p: &CStr) -> &Path {
    Path::new(OsStr::from_bytes(p.to_bytes()))
}

fn print(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stdout, which the other
    // commands write too.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stdout) };
}

/// strscpy(): `src` into `dst`, truncated, NUL-terminated.
fn copy_str(dst: &mut [u8], src: &[u8]) {
    let n = src.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&src[..n]);
    dst[n..].fill(0);
}

/// A root-owned directory no one else can write, made 0700 and sealed
/// if it was not there.
fn mkdir_owned(p: &CStr) -> c_int {
    let created = match DirBuilder::new().mode(0o700).create(path(p)) {
        Ok(()) => true,
        Err(e) if e.kind() == ErrorKind::AlreadyExists => false,
        Err(e) => return io_err(&e),
    };
    let st = match fs::symlink_metadata(path(p)) {
        Ok(st) => st,
        Err(e) => return io_err(&e),
    };
    if !st.is_dir() || st.uid() != 0 || st.mode() & 0o022 != 0 {
        return -EPERM;
    }
    if !created {
        return 0;
    }
    seal::label(p).err().unwrap_or(0)
}

/// The dm name of the config image with this root.
fn mapping_name(root: &[u8; 32]) -> CString {
    let hex: String = root.iter().map(|b| format!("{b:02x}")).collect();
    CString::new(format!("shirudo-config-{hex}")).unwrap_or_default()
}

/// The root of the config image on `device` at `dir` as a descriptor,
/// opened once and checked where it was opened, `bad` when it is not: a
/// path checked first and opened after is root's to swap between the
/// two in a mount namespace of its own, and a directory of the image
/// bound elsewhere has the image's device too, but every relative path
/// read from it lands elsewhere in the image.
fn config_root_open(dir: &CStr, device: u64, bad: c_int) -> Result<OwnedFd, c_int> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(O_PATH | O_DIRECTORY | O_NOFOLLOW)
        .open(path(dir))
        .map_err(|e| io_err(&e))?;
    let st = f.metadata().map_err(|e| io_err(&e))?;
    if st.dev() == device && st.ino() == EXT4_ROOT_INO {
        Ok(f.into())
    } else {
        Err(bad)
    }
}

/// The config verification certificate the bootstrap names at `index`,
/// from the runtime image on `device`: an ML-DSA-87 key, none named
/// twice.
fn read_config_certificate(s: &mut State, index: usize, device: u64) -> c_int {
    let name = CString::new(cstr(&s.bootstrap.certificates[index])).unwrap_or_default();
    let fd = match open_runtime_file(&name, device) {
        Ok(fd) => fd,
        Err(err) => return err,
    };
    let der = read_der_fd(fd.as_fd());
    drop(fd);
    let cert = der.and_then(|der| {
        let x509 = x509_from_der(&der)?;
        if key_algorithm(&x509, 32)?.as_bytes() != b"ML-DSA-87" {
            return Err(-EKEYREJECTED);
        }
        let fingerprint = pubkey_digest(&x509)?;
        Ok(ConfigCertificate {
            x509,
            der,
            fingerprint,
        })
    });
    match cert {
        Err(err) => err,
        Ok(c)
            if s.certificates
                .iter()
                .any(|o| o.fingerprint == c.fingerprint) =>
        {
            -EEXIST
        }
        Ok(c) => {
            s.certificates.push(c);
            0
        }
    }
}

/// Whether a config verification certificate signed the root hash of the
/// image `opened`: 0, -ENOKEY without a certificate or a signature,
/// -EKEYREJECTED when none did.
fn verify_config_root(
    bootstrap: &ImageBootstrap,
    certificates: &[ConfigCertificate],
    opened: &ConfigImageOpen,
) -> c_int {
    let Some(signature) = &opened.signature else {
        return -ENOKEY;
    };
    if bootstrap.n_certificates == 0 {
        return -ENOKEY;
    }
    let sig = match read_whole(signature.as_fd(), CONFIG_IMAGE_SIG_MAX) {
        Ok(sig) => sig,
        Err(err) => return err,
    };
    let root: String = opened
        .image
        .root_hash
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let signed = certificates[..bootstrap.n_certificates.min(certificates.len())]
        .iter()
        .any(|c| verify_detached_x509(root.as_bytes(), &sig, &c.x509) == 0);
    if signed { 0 } else { -EKEYREJECTED }
}

/// Whether the BPF guards observed `device`, the dm-verity mapping with
/// `root` when given, being made as `kind`, and this very instance of
/// it: 0 or -EACCES.
fn device_observed(device: u64, root: Option<&[u8; 32]>, kind: u32) -> c_int {
    let node = format!("/dev/dm-{}", minor(device));
    let block = match OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(&node)
    {
        Ok(f) => f,
        Err(e) => return io_err(&e),
    };
    match block.metadata() {
        Ok(st) if st.file_type().is_block_device() && st.rdev() == device => {}
        Ok(_) => return -EPERM,
        Err(e) => return io_err(&e),
    }
    let mut diskseq = 0u64;
    // SAFETY: the open block device and room for its sequence number.
    if unsafe { ioctl(block.as_raw_fd(), BLKGETDISKSEQ, &mut diskseq) } != 0 {
        return last_errno();
    }
    // SAFETY: a C string.
    let fd = unsafe { bpf_obj_get(DEVICES_MAP.as_ptr()) };
    if fd < 0 {
        return last_errno();
    }
    // SAFETY: the map bpf_obj_get() opened, the fd's from here.
    let map = unsafe { OwnedFd::from_raw_fd(fd) };
    if let Err(e) = guard_map_check(map.as_fd(), &GUARD_MAPS[GUARD_DEVICES]) {
        return e;
    }
    let dev = kernel_dev(device);
    let (mut key, mut next) = (0u64, 0u64);
    // SAFETY: the map and room for its first key.
    if unsafe { bpf_map_get_next_key(map.as_raw_fd(), ptr::null(), (&raw mut key).cast()) } != 0 {
        return -EACCES;
    }
    loop {
        let mut entry = DeviceAuthority::zeroed();
        // SAFETY: the map, a key of it and room for its value.
        let found = unsafe {
            bpf_map_lookup_elem(
                map.as_raw_fd(),
                (&raw const key).cast(),
                (&raw mut entry).cast(),
            )
        } == 0;
        if found
            && entry.dev == dev
            && entry.kind == kind
            && entry.diskseq == diskseq
            && root.is_none_or(|r| entry.root == *r)
        {
            return 0;
        }
        // SAFETY: the map, a key of it and room for the next.
        if unsafe {
            bpf_map_get_next_key(
                map.as_raw_fd(),
                (&raw const key).cast(),
                (&raw mut next).cast(),
            )
        } != 0
        {
            return -EACCES;
        }
        key = next;
    }
}

/// Whether the filesystem under `fd` is mounted read-only, nosuid and
/// nodev, and noexec unless `executable`: 0 or -EPERM.
fn mount_flags(fd: c_int, executable: bool) -> c_int {
    let required = ST_RDONLY | ST_NOSUID | ST_NODEV | if executable { 0 } else { ST_NOEXEC };
    let mut st = Statvfs::zeroed();
    // SAFETY: the caller's fd and room for its filesystem's state.
    if unsafe { fstatvfs(fd, &mut st) } != 0 {
        return last_errno();
    }
    if st.f_flag & required == required {
        0
    } else {
        -EPERM
    }
}

/// A regular file of the runtime image, on `device`.
fn open_runtime_file(p: &CStr, device: u64) -> Result<OwnedFd, c_int> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path(p))
        .map_err(|e| io_err(&e))?;
    let st = f.metadata().map_err(|e| io_err(&e))?;
    if !st.is_file() || st.dev() != device {
        return Err(-EPERM);
    }
    Ok(f.into())
}

fn runtime_device() -> Result<u64, c_int> {
    fs::metadata(path(RUNTIME_DIR))
        .map(|m| m.dev())
        .map_err(|e| io_err(&e))
}

/// The settings of the mounted runtime image, and its config
/// certificates, read for this command. Outside the initrd the guards
/// must have watched the runtime being mapped.
fn load_runtime_config(s: &mut State, trusted_boot: bool) -> c_int {
    if !trusted_boot {
        let ret = image_guards_ready();
        if ret != 0 {
            return ret;
        }
    }
    let dev = match runtime_device() {
        Ok(dev) => dev,
        Err(err) => return err,
    };
    if !trusted_boot {
        let ret = device_observed(dev, Some(&s.bootstrap.runtime_root), DEVICE_RUNTIME);
        if ret != 0 {
            return ret;
        }
    }
    let conf = match open_runtime_file(RUNTIME_CONF_PATH, dev) {
        Ok(fd) => fd,
        Err(err) => return err,
    };
    s.bootstrap.n_certificates = 0;
    let mut ret = image_bootstrap::read_fd(conf.as_raw_fd(), &mut s.bootstrap, false);
    if ret == 0 {
        ret = config::load_fd(&mut s.bootstrap_config, conf.as_fd(), RUNTIME_CONF_PATH);
    }
    drop(conf);
    if ret != 0 {
        return ret;
    }
    if s.bootstrap.config[0] == 0 || s.bootstrap.n_certificates == 0 || !s.bootstrap.have_pcr {
        return -EINVAL;
    }
    let ret = image_config::set(&s.bootstrap_config, -1);
    if ret != 0 {
        return ret;
    }
    s.certificates.clear();
    for i in 0..s.bootstrap.n_certificates {
        let ret = read_config_certificate(s, i, dev);
        if ret != 0 {
            s.certificates.clear();
            return ret;
        }
    }
    match open_runtime_file(RUNTIME_CERT_PATH, dev) {
        Ok(fd) => mount_flags(fd.as_raw_fd(), true),
        Err(err) => err,
    }
}

/// Maps, checks and mounts the runtime image the bootstrap names, or
/// takes the one the guards watched being mounted. The initrd checks it
/// against the root its authenticated UKI carries.
fn mount_runtime(s: &mut State, trusted_boot: bool) -> c_int {
    if !s.loaded {
        return -EINVAL;
    }
    if !trusted_boot
        && let Ok(dev) = runtime_device()
        && device_observed(dev, Some(&s.bootstrap.runtime_root), DEVICE_RUNTIME) == 0
    {
        return load_runtime_config(s, trusted_boot);
    }
    let mut device = DmVerity::empty();
    let mut created = false;
    let mut step = "open runtime image";
    let opened = ConfigImageOpen::open(
        CStr::from_bytes_until_nul(&s.bootstrap.runtime).unwrap_or_default(),
        Some(&s.bootstrap.runtime_root),
    );
    let mut ret = opened.as_ref().err().copied().unwrap_or(0);
    if let Ok(image) = &opened {
        step = "prepare runtime mountpoint";
        ret = mkdir_owned(RUNTIME_DIR);
        if ret == 0 {
            step = "create runtime dm-verity mapping";
            ret = dm_verity::place(dm_verity::create(image, RUNTIME_MAPPING), &mut device);
            created = ret == 0;
        }
        if ret == -EEXIST {
            step = "inspect runtime dm-verity mapping";
            ret = dm_verity::place(
                dm_verity::inspect(RUNTIME_MAPPING, &image.image),
                &mut device,
            );
        }
        if ret == 0 {
            step = "verify runtime image";
            ret = dm_verity::verify(&device, image);
        }
        if ret == 0 {
            step = "mount runtime image";
            ret = dm_verity::mount_at(&device, RUNTIME_DIR, true);
        }
    }
    if ret != 0 && created {
        let cleanup = dm_verity::remove(&mut device, false);
        if cleanup != 0 {
            warn(format!(
                "image: cannot remove runtime mapping: {}",
                text(cleanup)
            ));
        }
    }
    dm_verity::close_loops(&mut device);
    if ret == 0 && trusted_boot {
        s.boot_runtime = device;
    }
    drop(opened);
    if ret == 0 {
        step = "load runtime config";
        ret = load_runtime_config(s, trusted_boot);
        // SAFETY: a C string.
        if ret != 0 && unsafe { umount2(RUNTIME_DIR.as_ptr(), MNT_DETACH) } != 0 {
            warn(format!(
                "image: cannot unmount the runtime: {}",
                text(last_errno())
            ));
        }
    }
    if ret != 0 {
        error(format!("image: {step}: {}", text(ret)));
    }
    ret
}

/// Removes a config mapping the guards watched shirudo make that is not
/// the active config's: a candidate an update or a stage is done with,
/// or one an interrupted update left. One the guards did not watch being
/// made is not shirudo's, and stays.
fn collect_mapping(name: &CStr, device: u64, active: u64) -> c_int {
    if device == active || device_observed(device, None, DEVICE_CONFIG) != 0 {
        return 0;
    }
    let name = name.to_bytes();
    let mut retired = DmVerity::empty();
    if name.len() >= retired.name.len() {
        return -ENAMETOOLONG;
    }
    copy_str(&mut retired.name, name);
    retired.device = device;
    let ret = dm_verity::remove(&mut retired, false);
    if ret != 0 && ret != -EBUSY && ret != -ENXIO && ret != -ENODEV {
        warn(format!(
            "image: cannot remove retired mapping {}: {}",
            String::from_utf8_lossy(name),
            text(ret)
        ));
    }
    0
}

fn collect_mappings(journal_open: bool) {
    if !journal_open {
        return;
    }
    let active = fs::metadata(path(CONFIG_IMAGE_DIR)).map_or(0, |m| m.dev());
    let ret = dm_verity::list(|name, device| collect_mapping(name, device, active));
    if ret != 0 {
        warn(format!(
            "image: cannot collect retired mappings: {}",
            text(ret)
        ));
    }
}

fn close_candidate(s: &mut State, journal_open: bool) {
    s.candidate_fd = None;
    // SAFETY: a C string.
    if journal_open && unsafe { umount2(CONFIG_CANDIDATE_DIR.as_ptr(), MNT_DETACH) } != 0 {
        let err = last_errno();
        if err != -EINVAL && err != -ENOENT {
            warn(format!(
                "image: cannot release candidate mount: {}",
                text(err)
            ));
        }
    }
    dm_verity::close_loops(&mut s.candidate_device);
    s.candidate = None;
}

/// `remove` until it is not -EBUSY, 100 times at most and 10 ms apart:
/// a just-rejected mapping stays busy while udev probes it.
fn retry_busy(remove: impl FnMut() -> c_int) -> c_int {
    retry_busy_with(remove, std::thread::sleep)
}

/// As [`retry_busy`], with `pause` for each wait between two attempts.
pub(crate) fn retry_busy_with(
    mut remove: impl FnMut() -> c_int,
    mut pause: impl FnMut(std::time::Duration),
) -> c_int {
    let mut ret = 0;
    for attempt in 0..100 {
        ret = remove();
        if ret != -EBUSY {
            return ret;
        }
        if attempt < 99 {
            pause(std::time::Duration::from_millis(10));
        }
    }
    ret
}

fn remove_candidate(device: &mut DmVerity) -> c_int {
    retry_busy(|| dm_verity::remove(device, false))
}

/// The candidate's BPF trust set, valid; for a live update, also all
/// held by the kernel, which enrols a set only at boot.
fn candidate_keys(fd: c_int, purpose: Prepare) -> c_int {
    let mut set = TrustedSet::default();
    let mut ret = image_keys::validate_set(RUNTIME_CERT_PATH, fd, &mut set);
    if ret == 0 && purpose != Prepare::Stage {
        ret = image_keys::check_set(&set);
    }
    // Before the activation PCR is extended, which nothing takes back.
    if ret == 0 && purpose == Prepare::Update {
        ret = image_keys::check_purge(fd);
    }
    if ret == -ENOKEY {
        error("image: BPF signer was not enrolled at boot; reboot with the new trusted key set required".into());
    }
    ret
}

fn mount_candidate(s: &mut State) -> c_int {
    let current =
        fs::metadata(path(CONFIG_IMAGE_DIR)).is_ok_and(|m| m.dev() == s.candidate_device.device);
    let dir = if current {
        CONFIG_IMAGE_DIR
    } else {
        // SAFETY: a C string.
        if unsafe { umount2(CONFIG_CANDIDATE_DIR.as_ptr(), MNT_DETACH) } != 0 {
            let err = last_errno();
            if err != -EINVAL && err != -ENOENT {
                return err;
            }
        }
        let mut ret = mkdir_owned(CONFIG_CANDIDATE_DIR);
        if ret == 0 {
            ret = dm_verity::mount_at(&s.candidate_device, CONFIG_CANDIDATE_DIR, false);
        }
        if ret != 0 {
            return ret;
        }
        CONFIG_CANDIDATE_DIR
    };
    match config_root_open(dir, s.candidate_device.device, -ESTALE) {
        Ok(fd) => {
            s.candidate_fd = Some(fd);
            0
        }
        Err(err) => err,
    }
}

/// Maps, checks and mounts the config image `target` names as the
/// candidate, a config verification certificate having signed its root,
/// and validates it; outside the initrd, also that the guards watched
/// its mapping being made, and for a live update that the kernel holds
/// its keys. A mapping made for a candidate refused is removed again.
/// The journal is open whenever this runs.
fn prepare_config(s: &mut State, target: &ConfigUpdateTarget, purpose: Prepare) -> c_int {
    let trusted_boot = purpose == Prepare::Boot;

    close_candidate(s, true);
    if !trusted_boot {
        collect_mappings(true);
    }
    let prefix = cstr(&target.prefix);
    let cache = [IMAGE_CACHE_DIR.to_bytes(), b"/"].concat();
    if !prefix.starts_with(&cache) || !path_valid(prefix) {
        return -EPERM;
    }
    let opened = match ConfigImageOpen::open(
        CStr::from_bytes_until_nul(&target.prefix).unwrap_or_default(),
        None,
    ) {
        Ok(opened) => opened,
        Err(err) => return err,
    };
    let candidate = &*s.candidate.insert(opened);
    if target.root_hash != candidate.image.root_hash {
        return -EKEYREJECTED;
    }
    let ret = verify_config_root(&s.bootstrap, &s.certificates, candidate);
    if ret != 0 {
        return ret;
    }
    let name = mapping_name(&target.root_hash);
    let mut created = false;
    // SAFETY: a C string, the candidate image and its mapping to fill.
    let mut ret = dm_verity::place(
        dm_verity::inspect(&name, &candidate.image),
        &mut s.candidate_device,
    );
    if ret == -ENXIO || ret == -ENODEV || ret == -ENOENT {
        ret = dm_verity::place(dm_verity::create(candidate, &name), &mut s.candidate_device);
        created = ret == 0;
    }
    if ret == 0 {
        ret = dm_verity::verify(&s.candidate_device, candidate);
    }
    if ret == 0 && !trusted_boot {
        ret = device_observed(
            s.candidate_device.device,
            Some(&candidate.image.root_hash),
            DEVICE_CONFIG,
        );
    }
    if ret == 0 {
        ret = mount_candidate(s);
        if ret == 0 {
            let fd = s.candidate_raw();
            ret = mount_flags(fd, false);
            if ret == 0 {
                ret = crate::util::image_config::validate(fd);
            }
            if ret == 0 && !trusted_boot {
                ret = candidate_keys(fd, purpose);
            }
        }
    }
    if ret != 0 && created {
        close_candidate(s, true);
        let cleanup = remove_candidate(&mut s.candidate_device);
        if cleanup != 0 && cleanup != -ENXIO && cleanup != -ENODEV {
            warn(format!(
                "image: cannot remove rejected mapping {}: {}",
                String::from_utf8_lossy(cstr(&s.candidate_device.name)),
                text(cleanup)
            ));
        }
    }
    ret
}

/// Revokes what the candidate revokes and mounts it as the config, the
/// one the image config reads from here.
fn activate_config(s: &mut State, boot: bool) -> c_int {
    let ret = image_keys::apply(s.candidate_raw(), boot);
    if ret != 0 {
        return ret;
    }
    let ret = mkdir_owned(CONFIG_IMAGE_DIR);
    if ret != 0 {
        return ret;
    }
    let dev = match fs::metadata(path(CONFIG_IMAGE_DIR)) {
        Ok(m) => m.dev(),
        Err(e) => return io_err(&e),
    };
    if dev != s.candidate_device.device {
        // SAFETY: a C string.
        if unsafe { umount2(CONFIG_IMAGE_DIR.as_ptr(), MNT_DETACH) } != 0 {
            let err = last_errno();
            if err != -EINVAL {
                return err;
            }
        }
        let ret = dm_verity::mount_at(&s.candidate_device, CONFIG_IMAGE_DIR, false);
        if ret != 0 {
            return ret;
        }
    }
    let dir = match config_root_open(CONFIG_IMAGE_DIR, s.candidate_device.device, -ESTALE) {
        Ok(fd) => fd,
        Err(err) => return err,
    };
    let ret = mount_flags(dir.as_raw_fd(), false);
    if ret != 0 {
        return ret;
    }
    image_config::set(&s.bootstrap_config, dir.as_raw_fd())
}

/// The journal's operations: the TPM the state holds, the candidate
/// config it prepares and activates, and the seal's label.
struct RuntimeOps {
    /// Whether an activation records key revocations as a boot does,
    /// rather than as a live update.
    boot: bool,
}

/// How long a command waits for another's config operation lock.
const UPDATE_LOCK_WAIT_MS: u32 = 30 * 1000;
static UPDATE_OPS: RuntimeOps = RuntimeOps { boot: false };
static BOOT_OPS: RuntimeOps = RuntimeOps { boot: true };

impl ConfigUpdateOps for RuntimeOps {
    fn boot_identity(&self) -> Result<BootIdentity, c_int> {
        let (reset, restart) = with_tpm(Tpm::boot_identity)?;

        Ok(BootIdentity { reset, restart })
    }

    fn pcr_read(&self, pcr: u32) -> Result<[u8; 32], c_int> {
        if config_measure::nvpcr(pcr) {
            with_tpm(|tpm| tpm.nv_read(pcr))
        } else {
            with_tpm(|tpm| tpm.pcr_read(pcr))
        }
    }

    fn pcr_extend(&self, pcr: u32, event: &[u8; 32]) -> Result<(), c_int> {
        if !config_measure::nvpcr(pcr) {
            return with_tpm(|tpm| tpm.pcr_extend(pcr, event));
        }
        let authorize = nvpcr_authorize().inspect_err(|&e| {
            crate::log::err(
                format!(
                    "image: config NvPCR policy branch {}: {}",
                    CONFIG_NVPCR_AUTH_PATH.to_string_lossy(),
                    text(e)
                )
                .as_bytes(),
            );
        })?;
        with_tpm(|tpm| tpm.nvpcr_extend(pcr, &authorize, event))
    }

    fn prepare(&self, target: &ConfigUpdateTarget) -> Result<(), c_int> {
        let purpose = if self.boot {
            Prepare::BootEvent
        } else {
            Prepare::Update
        };
        match with_state(|s| prepare_config(s, target, purpose)) {
            0 => Ok(()),
            err => Err(err),
        }
    }

    fn activate(&self, _: &ConfigUpdate<'_>, _: &ConfigUpdateTarget) -> Result<(), c_int> {
        match with_state(|s| activate_config(s, self.boot)) {
            0 => Ok(()),
            err => Err(err),
        }
    }

    fn seal(&self, fd: BorrowedFd<'_>) -> Result<(), c_int> {
        let label = SEAL_LABEL.to_bytes();
        // SAFETY: the journal's fd, a C string and the label's bytes.
        if unsafe {
            fsetxattr(
                fd.as_raw_fd(),
                XATTR_SEAL.as_ptr(),
                label.as_ptr().cast(),
                label.len(),
                0,
            )
        } != 0
        {
            return Err(last_errno());
        }
        Ok(())
    }
}

/// The systemd record names the first branch of the NvPCR write policy.
/// The TPM checks that it belongs to the index before extending.
fn nvpcr_authorize() -> Result<[u8; 32], c_int> {
    let data = io::read(CONFIG_NVPCR_AUTH_PATH, 65)?;
    parse_nvpcr_authorize(&data)
}

fn parse_nvpcr_authorize(data: &[u8]) -> Result<[u8; 32], c_int> {
    let digits = data.strip_suffix(b"\n").unwrap_or(data);
    let mut authorize = [0u8; 32];
    if digits.contains(&0) || hex::decode(digits, &mut authorize).is_err() {
        return Err(-EBADMSG);
    }
    Ok(authorize)
}

/// `f` on the TPM open_update() opened: -EINVAL before it has.
fn with_tpm<R>(f: impl FnOnce(&Tpm) -> Result<R, c_int>) -> Result<R, c_int> {
    with_state(|s| s.tpm.as_ref().map_or(Err(-EINVAL), f))
}

fn open_update() -> c_int {
    if journal_open() {
        return 0;
    }
    let mut ret = mkdir_owned(CONFIG_UPDATE_DIR);
    if ret == 0 {
        ret = match Tpm::open() {
            Ok(tpm) => {
                with_state(|s| s.tpm = Some(tpm));
                0
            }
            Err(err) => err,
        };
    }
    if ret == 0 {
        ret = match ConfigUpdate::open(CONFIG_UPDATE_DIR, &UPDATE_OPS, UPDATE_LOCK_WAIT_MS) {
            Ok(journal) => {
                JOURNAL.set(Some(journal));
                0
            }
            Err(err) => err,
        };
    }
    ret
}

/// The config the boot activates: the one staged for it, the journal's
/// selection, or the bootstrap's config without one, as the image there
/// is now.
fn boot_target() -> Result<ConfigUpdateTarget, c_int> {
    let previous = match with_journal(|j| j.read_state()) {
        Ok(previous) => Some(previous),
        Err(err) if err == -ENOENT => None,
        Err(err) => return Err(err),
    };
    if let Some(previous) = &previous {
        let boot = UPDATE_OPS.boot_identity()?;
        if let Some(staged) = with_journal(|j| j.staged(previous, boot.reset))? {
            return Ok(staged);
        }
    }
    let prefix = match &previous {
        Some(previous) => cstr(&previous.target.prefix).to_vec(),
        None => with_state(|s| cstr(&s.bootstrap.config).to_vec()),
    };
    let prefix_c = CString::new(prefix.clone()).unwrap_or_default();
    let opened = ConfigImageOpen::open(&prefix_c, None)?;
    if previous.is_some_and(|p| p.target.root_hash != opened.image.root_hash) {
        return Err(-EKEYREJECTED);
    }
    let mut target = ConfigUpdateTarget::zeroed();
    if prefix.len() >= target.prefix.len() {
        return Err(-ENAMETOOLONG);
    }
    copy_str(&mut target.prefix, &prefix);
    target.root_hash = opened.image.root_hash;
    Ok(target)
}

fn boot_keys_error(step: &str, ret: c_int) -> c_int {
    error(format!("initrd boot keys: {step}: {}", text(ret)));
    ret
}

/// The config verification certificates into the dm-verity keyring,
/// sealed after them: the kernel trusts every key in it for config
/// roots, so whether init sealed it now or earlier this boot, it must
/// hold exactly the runtime image's set.
fn enroll_config_keys(s: &State) -> c_int {
    let ring = keyring::dm_verity_serial();
    if ring < 0 {
        return boot_keys_error("lookup dm-verity keyring", ring);
    }
    let mut certs = Vec::with_capacity(s.certificates.len());
    let mut added = false;
    for c in &s.certificates {
        certs.push(&c.der[..]);
        let key = keyring::dm_verity_add_cert(&c.der);
        if key < 0 && key != -EPERM && key != -EACCES {
            return boot_keys_error("add config verification certificate", key);
        }
        added |= key >= 0;
    }
    if added {
        let ret = keyring::dm_verity_seal();
        if ret == -EEXIST {
            return boot_keys_error(
                "seal dm-verity keyring restricted by another task (tampered)",
                -EKEYREJECTED,
            );
        }
        if ret != 0 {
            return boot_keys_error("seal dm-verity keyring", ret);
        }
    }
    if !added && keyring::holds_exactly(ring, &[]) == 1 {
        return boot_keys_error(
            "dm-verity keyring sealed empty at boot; boot with dm_verity.keyring_unsealed=1",
            -ENOKEY,
        );
    }
    let ret = keyring::holds_exactly(ring, &certs);
    if ret != 1 {
        return boot_keys_error(
            "check dm-verity verification keys",
            if ret < 0 { ret } else { -EKEYREJECTED },
        );
    }
    0
}

/// Whether the shirudo commands hold the image state: the runtime
/// image's root, once the bootstrap is loaded.
pub(crate) fn runtime_root() -> Option<[u8; 32]> {
    with_state(|s| s.loaded.then_some(s.bootstrap.runtime_root))
}

/// The authenticated bootstrap's config PCR, or its NvPCR index.
pub(crate) fn config_pcr() -> Option<u32> {
    with_state(|s| s.loaded.then_some(s.bootstrap.pcr))
}

/// The config activation journal of this command, which attestation
/// reports on; null without one.
pub(crate) fn update_context() -> *mut ConfigUpdate<'static> {
    JOURNAL.with_borrow_mut(|journal| journal.as_mut().map_or(ptr::null_mut(), ptr::from_mut))
}

fn reject_overrides() -> c_int {
    const NAMES: [&str; 9] = [
        "SHIRUDO_KEYS_DIR",
        "SHIRUDO_TPM_TCTI",
        "SHIRUDO_TPM_OWNER_AUTH",
        "SHIRUDO_EVENTLOG_PATH",
        "SHIRUDO_EVENTLOG_PENDING_PATH",
        "SHIRUDO_INITRD_RELEASE",
        "SHIRUDO_SYSROOT",
        "TSS2_LOGFILE",
        "SSLKEYLOGFILE",
    ];
    match NAMES.iter().find(|n| std::env::var_os(n).is_some()) {
        Some(name) => {
            error(format!("bootstrap override {name} is forbidden"));
            -EPERM
        }
        None => 0,
    }
}

/// Loads the authenticated bootstrap: on an enforcing boot from the
/// runtime image the identity names, before it from the initrd's own
/// config. 1 once loaded, or -errno.
pub(crate) fn bootstrap_load() -> c_int {
    if with_state(|s| s.loaded) {
        return 1;
    }
    let mode = identity::enforcement_active();
    if mode < 0 {
        return mode;
    }
    let (identity, id) = match identity::read() {
        Ok(identity) => (identity, 0),
        Err(err) => (Identity::zeroed(), err),
    };
    if mode != 0 && id != 0 {
        return id;
    }
    if id == 0 && mode == 0 {
        return -EPROTO;
    }
    with_state(|s| {
        let ret = if id == 0 {
            s.bootstrap.runtime_root = identity.runtime_root;
            s.bootstrap.have_root = true;
            load_runtime_config(s, false)
        } else {
            let mut ret = image_bootstrap::read(CONF_PATH, &mut s.bootstrap, true);
            if ret == 0 && (s.bootstrap.runtime[0] == 0 || !s.bootstrap.have_root) {
                ret = -EINVAL;
            }
            if ret == 0 {
                ret = config::load_path(&mut s.bootstrap_config, CONF_PATH);
            }
            ret
        };
        if ret != 0 {
            return ret;
        }
        let ret = reject_overrides();
        if ret != 0 {
            return ret;
        }
        let ret = image_config::set(&s.bootstrap_config, -1);
        if ret != 0 {
            return ret;
        }
        s.loaded = true;
        1
    })
}

/// Mounts the authenticated runtime image, or takes the one mounted.
pub(crate) fn runtime_mount() -> c_int {
    with_state(|s| mount_runtime(s, false))
}

/// Keep the runtime signer in the boot set while the guard loaders start.
fn add_runtime_signer(set: &mut TrustedSet, primary: TrustedCert) -> Result<(), c_int> {
    if members(set)
        .iter()
        .any(|c| c.fingerprint() == primary.fingerprint())
    {
        return Ok(());
    }
    set.push(primary)
}

/// The initrd's boot trust set: the runtime mounted, its config
/// certificate sealed into the dm-verity keyring, the boot config
/// prepared and its key set validated, with the runtime's signer added
/// for the guard loaders until activation. The mounts stay until
/// [`boot_keys_close`].
pub(crate) fn boot_keys(set: &mut TrustedSet) -> c_int {
    with_state(|s| s.boot_keys_open = true);
    let ret = with_state(|s| mount_runtime(s, true));
    if ret != 0 {
        return boot_keys_error("mount runtime", ret);
    }
    let ret = with_state(|s| enroll_config_keys(s));
    if ret != 0 {
        return boot_keys_error("enrol config certificate", ret);
    }
    let ret = open_update();
    if ret != 0 {
        return boot_keys_error("open config update state", ret);
    }
    let target = match boot_target() {
        Ok(target) => target,
        Err(err) => return boot_keys_error("select boot config", err),
    };
    let ret = with_state(|s| {
        s.boot_target = target;
        prepare_config(s, &target, Prepare::Boot)
    });
    if ret != 0 {
        return boot_keys_error("prepare boot config", ret);
    }
    let ret = image_keys::validate_set(RUNTIME_CERT_PATH, with_state(|s| s.candidate_raw()), set);
    if ret != 0 {
        return boot_keys_error("validate BPF trust set", ret);
    }
    let primary = match TrustedCert::primary_at(RUNTIME_CERT_PATH) {
        Ok(c) => c,
        Err(err) => return boot_keys_error("digest primary certificate", err),
    };
    if let Err(err) = add_runtime_signer(set, primary) {
        return boot_keys_error("add runtime certificate to trusted set", err);
    }
    with_state(|s| s.boot_target_valid = true);
    0
}

/// Releases what [`boot_keys`] mounted and mapped: 0 or the first error.
pub(crate) fn boot_keys_close() -> c_int {
    with_state(|s| {
        if !s.boot_keys_open {
            return 0;
        }
        image_config::clear();
        s.candidate_fd = None;
        s.certificates.clear();
        let mut ret = 0;
        // SAFETY: a C string.
        if unsafe { umount2(CONFIG_CANDIDATE_DIR.as_ptr(), 0) } != 0 {
            let err = last_errno();
            if err != -EINVAL && err != -ENOENT {
                ret = err;
            }
        }
        for (device, image) in [
            (&mut s.candidate_device, Some(&mut s.candidate)),
            (&mut s.boot_runtime, None),
        ] {
            if image.is_none() {
                // SAFETY: a C string.
                if unsafe { umount2(RUNTIME_DIR.as_ptr(), 0) } != 0 {
                    let err = last_errno();
                    if err != -EINVAL && err != -ENOENT && ret == 0 {
                        ret = err;
                    }
                }
            }
            if device.name[0] != 0 {
                let err = dm_verity::remove(device, false);
                if ret == 0 && err != 0 && err != -ENXIO && err != -ENODEV {
                    ret = err;
                }
            }
            if let Some(image) = image {
                *image = None;
            }
        }
        s.boot_keys_open = false;
        ret
    })
}

/// Activates the boot config through the journal: -EINPROGRESS while
/// an activation is pending, which blocks further changes.
pub(crate) fn boot() -> c_int {
    let ret = open_update();
    if ret != 0 {
        return ret;
    }
    let (valid, saved, pcr) = with_state(|s| (s.boot_target_valid, s.boot_target, s.bootstrap.pcr));
    let target = if valid {
        saved
    } else {
        match boot_target() {
            Ok(target) => target,
            Err(err) => return err,
        }
    };
    let ret = with_journal(|j| {
        j.set_ops(&BOOT_OPS);
        let booted = j.boot(&target, pcr);
        j.set_ops(&UPDATE_OPS);
        booted
    })
    .err()
    .unwrap_or(0);
    if ret == -EINPROGRESS {
        error("image: activation is pending; further changes are blocked".into());
    }
    ret
}

/// Whether the config the journal selected is the one mounted, through
/// a mapping the guards watched being made, and so the config the image
/// config reads: 0, -EUCLEAN or -errno.
fn config_mount_check(s: &State, record: &ConfigUpdateRecord) -> c_int {
    let opened = match ConfigImageOpen::open(
        CStr::from_bytes_until_nul(&record.target.prefix).unwrap_or_default(),
        None,
    ) {
        Ok(opened) => opened,
        Err(err) => return err,
    };
    let mut ret = 0;
    if record.target.root_hash != opened.image.root_hash {
        ret = -EKEYREJECTED;
    }
    let mut device = DmVerity::empty();
    if ret == 0 {
        let name = mapping_name(&record.target.root_hash);
        ret = dm_verity::place(dm_verity::inspect(&name, &opened.image), &mut device);
    }
    drop(opened);
    if ret != 0 {
        return ret;
    }
    let ret = (|| {
        match fs::metadata(path(CONFIG_IMAGE_DIR)) {
            Ok(m) if m.dev() == device.device => {}
            _ => return -EUCLEAN,
        }
        let ret = device_observed(device.device, Some(&record.target.root_hash), DEVICE_CONFIG);
        if ret != 0 {
            return ret;
        }
        let dir = match config_root_open(CONFIG_IMAGE_DIR, device.device, -EUCLEAN) {
            Ok(fd) => fd,
            Err(err) => return err,
        };
        let ret = mount_flags(dir.as_raw_fd(), false);
        if ret != 0 {
            return ret;
        }
        image_config::set(&s.bootstrap_config, dir.as_raw_fd())
    })();
    dm_verity::close_loops(&mut device);
    ret
}

/// Completes the boot's activation once the config it selected is the
/// one mounted.
pub(crate) fn boot_complete() -> c_int {
    let ret = match with_journal(|j| j.read_state()) {
        Ok(record) => with_state(|s| config_mount_check(s, &record)),
        Err(err) => err,
    };
    if ret != 0 {
        return ret;
    }
    with_journal(|j| j.complete_boot()).err().unwrap_or(0)
}

/// Whether the journal's selection is complete and the config mounted.
fn current_config() -> c_int {
    let ret = open_update();
    if ret != 0 {
        return ret;
    }
    match with_journal(|j| j.check()) {
        Ok(record) => with_state(|s| config_mount_check(s, &record)),
        Err(err) => err,
    }
}

/// status is how a fleet sees these states, so it runs in them while
/// every other command refuses: with the pending config's settings when
/// that is the config mounted, and with the runtime image's alone
/// otherwise, since a config the record cannot vouch for names no export
/// destination.
fn status_config(state: c_int) -> c_int {
    with_state(|s| s.config_state = state);
    if state == -EINPROGRESS
        && let Ok(record) = with_journal(|j| j.read_state())
    {
        with_state(|s| config_mount_check(s, &record));
    }
    0
}

/// Enters the image state `command` needs before it runs with `args`,
/// the command word first: nothing outside an enforcing boot or for the
/// commands that need none; else the runtime's settings, the journal,
/// and for all but `image` the config the journal selected. Options
/// that would point a command away from the runtime's keys, TPM or
/// certificates are refused there.
pub(crate) fn enter(command: &[u8], args: &[&[u8]]) -> c_int {
    let image_exempt = matches!(
        args.get(1),
        Some(&(b"build" | b"verify" | b"--help" | b"-h" | b"--list-cmds"))
    );
    if command == b"image" && image_exempt {
        return 0;
    }
    if matches!(
        command,
        b"init" | b"genkey" | b"build" | b"help" | b"version"
    ) {
        return 0;
    }
    let mode = identity::enforcement_active();
    if mode < 0 {
        return mode;
    }
    let ret = match identity::read() {
        Ok(_) => 0,
        Err(err) => err,
    };
    if mode != 0 && ret != 0 {
        return ret;
    }
    if ret != 0 {
        return if ret == -ENOENT || ret == -EPERM || ret == -EACCES {
            0
        } else {
            ret
        };
    }
    if mode == 0 {
        return -EPROTO;
    }
    let ret = bootstrap_load();
    if ret < 0 {
        return ret;
    }
    let ret = with_state(|s| load_runtime_config(s, false));
    if ret != 0 {
        return ret;
    }
    let redirects = |a: &&[u8]| {
        a.starts_with(b"--keys-dir") || a.starts_with(b"--cert") || a.starts_with(b"--tcti")
    };
    if args.iter().skip(1).any(redirects) {
        return -EPERM;
    }
    if command == b"image" {
        return open_update();
    }
    let ret = current_config();
    if command == b"status" && [-EINPROGRESS, -EUCLEAN, -ESTALE, -EKEYREJECTED].contains(&ret) {
        return status_config(ret);
    }
    ret
}

/// The config state status reports: 0 with the selected config active,
/// -EINPROGRESS while an activation is pending, or the integrity error
/// the other commands refuse on; -ENODEV without activation state.
/// `root` is the selected or pending config's, zero when unknown.
pub(crate) fn config_state(root: &mut [u8; 32]) -> c_int {
    if !journal_open() {
        return -ENODEV;
    }
    *root = with_journal(|j| j.read_state()).map_or([0; 32], |record| record.target.root_hash);
    with_state(|s| s.config_state)
}

/// Prints the activation state, as JSON with `json`: 0, -EINPROGRESS
/// while an activation is pending, -ENODEV without activation state, or
/// the error the config fails its check with.
pub(crate) fn status(json: bool) -> c_int {
    if !journal_open() {
        return -ENODEV;
    }
    let record = match with_journal(|j| j.read_state()) {
        Ok(record) => record,
        Err(err) => return err,
    };
    let staged = match with_journal(|j| j.read_staged()) {
        Ok(staged) => Some(staged),
        Err(err) if err == -ENOENT => None,
        Err(err) => return err,
    };
    let hex = |root: &[u8; 32]| -> String { root.iter().map(|b| format!("{b:02x}")).collect() };
    let next_root = staged.map(|staged| hex(&staged.target.root_hash));
    let root = hex(&record.target.root_hash);
    let ret = if record.pending {
        -EINPROGRESS
    } else {
        current_config()
    };
    if !json {
        let pending = if record.pending {
            "yes, until the next reboot"
        } else {
            "no"
        };
        let consistent = if ret != 0 { "no" } else { "yes" };
        let lines = [
            ("Config root hash:", root),
            (
                "Next boot root hash:",
                next_root.unwrap_or_else(|| "none".to_owned()),
            ),
            ("PCR:", record.pcr.to_string()),
            ("Sequence:", (record.sequence as i64).to_string()),
            ("TPM reset count:", record.reset_count.to_string()),
            ("Restart count:", record.restart_count.to_string()),
            ("Pending:", pending.to_owned()),
            ("Consistent:", consistent.to_owned()),
        ];
        for (label, value) in lines {
            print(format!("{label:<22} {value}\n").as_bytes());
        }
        return ret;
    }
    let mut buf = [0u8; 768];
    let mut e = JsonEmit::fixed(&mut buf);
    e.obj_open();
    e.kv_string(b"root_hash", root.as_bytes());
    match &next_root {
        Some(next) => e.kv_string(b"next_boot_root_hash", next.as_bytes()),
        None => e.kv_null(b"next_boot_root_hash"),
    }
    e.kv_int(b"pcr", i64::from(record.pcr));
    e.kv_int(b"sequence", record.sequence as i64);
    e.kv_int(b"reset_count", i64::from(record.reset_count));
    e.kv_int(b"restart_count", i64::from(record.restart_count));
    e.kv_bool(b"pending", record.pending);
    e.kv_bool(b"consistent", ret == 0);
    e.obj_close();
    if e.err() != 0 {
        return e.err();
    }
    print(&[e.output(), b"\n"].concat());
    ret
}

/// Leaves what [`enter`] or the initrd entered: mounts, mappings the
/// guards never watched being made, the journal and the TPM, the
/// bootstrap's secrets wiped.
pub(crate) fn leave() {
    boot_keys_close();
    image_config::clear();
    let open = journal_open();
    with_state(|s| close_candidate(s, open));
    collect_mappings(open);
    if open {
        JOURNAL.set(None);
    }
    with_state(|s| {
        s.tpm = None;
        s.certificates.clear();
        // SAFETY: the bootstrap config's bytes, wiped.
        unsafe { explicit_bzero((&raw mut s.bootstrap_config).cast(), size_of::<Config>()) };
    });
}

/// Fetches the config image at `prefix` into the cache and begins its
/// activation through the journal: 0, -EINPROGRESS while one is pending,
/// -ENODEV without activation state, or -errno.
pub(crate) fn update(prefix: &CStr) -> c_int {
    if !journal_open() {
        return -ENODEV;
    }
    let mut target = ConfigUpdateTarget::zeroed();
    let mut ret = current_config();
    if ret == 0 {
        ret = mkdir_owned(IMAGE_CACHE_DIR);
    }
    if ret == 0 {
        ret = fetch_verified(prefix, &mut target, |image| {
            with_state(|s| verify_config_root(&s.bootstrap, &s.certificates, image))
        });
    }
    if ret == 0 {
        let pcr = with_state(|s| s.bootstrap.pcr);
        ret = with_journal(|j| j.begin(&target, pcr)).err().unwrap_or(0);
    }
    ret
}

/// Fetches the config image at `prefix` into the cache, prepares it as
/// a live update would, and stages it for the next boot: 0, -ENODEV
/// without activation state, or -errno.
pub(crate) fn stage(prefix: &CStr) -> c_int {
    if !journal_open() {
        return -ENODEV;
    }
    let mut target = ConfigUpdateTarget::zeroed();
    let mut ret = current_config();
    if ret == 0 {
        ret = mkdir_owned(IMAGE_CACHE_DIR);
    }
    if ret == 0 {
        ret = fetch_verified(prefix, &mut target, |image| {
            with_state(|s| verify_config_root(&s.bootstrap, &s.certificates, image))
        });
    }
    if ret == 0 {
        ret = with_state(|s| prepare_config(s, &target, Prepare::Stage));
    }
    if ret == 0 {
        ret = with_journal(|j| j.stage(&target)).err().unwrap_or(0);
    }
    ret
}

/// Drops the config staged for the next boot: 0, -ENODEV without
/// activation state, or -errno.
pub(crate) fn stage_cancel() -> c_int {
    if !journal_open() {
        return -ENODEV;
    }
    let ret = current_config();
    if ret != 0 {
        return ret;
    }
    with_journal(|j| j.clear_staged()).err().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{add_runtime_signer, parse_nvpcr_authorize};
    use crate::errno::EBADMSG;
    use crate::testutil::TempDir;
    use crate::util::keys::{TrustedCert, TrustedSet};
    use openssl::pkey::{PKey, Private};

    fn cert_for_key(key: &PKey<Private>, name: &str) -> Vec<u8> {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::x509::{X509, X509NameBuilder};

        let mut subject = X509NameBuilder::new().unwrap();
        subject.append_entry_by_text("CN", name).unwrap();
        let subject = subject.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_subject_name(&subject).unwrap();
        cert.set_issuer_name(&subject).unwrap();
        cert.set_pubkey(key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.sign(key, MessageDigest::sha256()).unwrap();
        cert.build().to_der().unwrap()
    }

    #[test]
    fn boot_set_takes_one_certificate_per_runtime_key() {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;

        let dir = TempDir::new();
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        std::fs::write(dir.join("first.der"), cert_for_key(&key, "first")).unwrap();
        std::fs::write(dir.join("second.der"), cert_for_key(&key, "second")).unwrap();
        let first = TrustedCert::primary_at(&dir.cpath("first.der")).unwrap();
        let second = TrustedCert::primary_at(&dir.cpath("second.der")).unwrap();
        assert_ne!(first.sha256(), second.sha256());
        assert_eq!(first.fingerprint(), second.fingerprint());

        let mut set = TrustedSet::default();
        set.push(first).unwrap();
        add_runtime_signer(&mut set, second).unwrap();
        assert_eq!(set.len(), 1);

        let other = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        std::fs::write(dir.join("third.der"), cert_for_key(&other, "third")).unwrap();
        let third = TrustedCert::primary_at(&dir.cpath("third.der")).unwrap();
        add_runtime_signer(&mut set, third).unwrap();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn nvpcr_policy_branch_is_exact_hex_with_optional_newline() {
        let hex = b"0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF";
        let decoded = parse_nvpcr_authorize(hex).unwrap();
        assert_eq!(decoded[0..4], [0x01, 0x23, 0x45, 0x67]);
        let mut with_newline = hex.to_vec();
        with_newline.push(b'\n');
        assert_eq!(parse_nvpcr_authorize(&with_newline), Ok(decoded));
        for invalid in [
            &hex[..63],
            &with_newline[..63],
            &b""[..],
            &b"0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEx"[..],
        ] {
            assert_eq!(parse_nvpcr_authorize(invalid), Err(-EBADMSG));
        }
        with_newline[10] = 0;
        assert_eq!(parse_nvpcr_authorize(&with_newline), Err(-EBADMSG));
        with_newline[10] = b'a';
        with_newline[64] = 0;
        assert_eq!(parse_nvpcr_authorize(&with_newline), Err(-EBADMSG));
        with_newline[64] = b'\r';
        assert_eq!(parse_nvpcr_authorize(&with_newline), Err(-EBADMSG));
    }
}
