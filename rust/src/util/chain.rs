// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The measurement register: an NV extend index
//! bound to this boot and anchored in a PCR, after systemd's NvPCR, and
//! the digests every measuring path shares.

use core::ffi::{CStr, c_int};
use openssl::hash::{Hasher, MessageDigest};

use crate::errno::{
    E2BIG, EACCES, EEXIST, EINVAL, EIO, EKEYREJECTED, ENODEV, ENOENT, EPROTO, text,
};
use crate::sys::libc::scrub;
use crate::sys::tss2::NV_WRITTEN;
use crate::text::{cstr, strsprintf};
use crate::util::config::{self, Scrubbed};
use crate::util::crypto_openssl::sha256_into;
use crate::util::eventlog::{EventlogInit, NV_INDEX, boot_init};
use crate::util::initrd::in_initrd;
use crate::util::nv_writer;
use crate::util::tpm::{Branches, NvInfo, REGISTER_ATTRS, Tpm};
use crate::util::tpm_wire::{
    DIGEST_LEN, NAME_LEN, NV_RSA_BYTES, RegisterPolicy, nv_name, register_policy,
};
use crate::util::upatch::{NAME_MAX, PAYLOAD_HASH_LEN, TYPE_BPF, TYPE_JAVA};

/// `CHAIN_NAME`, the register's name in its anchor.
const CHAIN_NAME: &[u8] = b"shirudo";
/// `CHAIN_PCR`: PCR 9, which holds the initrd and nothing measured after
/// it, and takes the anchor.
pub(crate) const PCR: u32 = 9;
/// `CHAIN_PHASE_PCR`: PCR 11, which systemd extends with the boot phase.
pub(crate) const PHASE_PCR: u32 = 11;
/// `CHAIN_PCR_MASK`: the PCRs the init branch binds to.
pub(crate) const PCR_MASK: u32 = (1 << PCR) | (1 << PHASE_PCR);
/// `CHAIN_ANCHOR_MAX`.
pub(crate) const ANCHOR_MAX: usize = 128;

/// `struct measured_upatch`: a member of the set an init event lists.
#[repr(C)]
pub struct MeasuredUpatch {
    pub(crate) name: [u8; NAME_MAX + 1],
    pub(crate) payload_hex: [u8; 2 * PAYLOAD_HASH_LEN + 1],
    pub(crate) ty: u32,
}

/// `struct chain_init_info`: the binding chain_init() made or found.
#[repr(C)]
pub struct ChainInitInfo {
    pub(crate) writer_public: [u8; NV_RSA_BYTES],
    pub(crate) reused: bool,
    pub(crate) initrd: bool,
    pub(crate) reset_count: u32,
    pub(crate) value: [u8; DIGEST_LEN],
    pub(crate) pcr_before: [u8; DIGEST_LEN],
    pub(crate) phase_before: [u8; DIGEST_LEN],
    pub(crate) name: [u8; NAME_LEN],
    pub(crate) name_len: usize,
    pub(crate) anchor: [u8; ANCHOR_MAX],
    pub(crate) anchor_digest: [u8; DIGEST_LEN],
}

/// `struct chain_status`: the register as a status report sees it.
#[repr(C)]
pub struct ChainStatus {
    pub(crate) tpm: bool,
    pub(crate) defined: bool,
    pub(crate) written: bool,
    pub(crate) logged: bool,
    pub(crate) anchored: bool,
    pub(crate) rebound: bool,
    pub(crate) value: [u8; DIGEST_LEN],
    pub(crate) name: [u8; NAME_LEN],
    pub(crate) name_len: usize,
    pub(crate) init: EventlogInit,
}

impl ChainInitInfo {
    /// No binding, for init() to fill.
    const fn zeroed() -> Self {
        ChainInitInfo {
            writer_public: [0; NV_RSA_BYTES],
            reused: false,
            initrd: false,
            reset_count: 0,
            value: [0; DIGEST_LEN],
            pcr_before: [0; DIGEST_LEN],
            phase_before: [0; DIGEST_LEN],
            name: [0; NAME_LEN],
            name_len: 0,
            anchor: [0; ANCHOR_MAX],
            anchor_digest: [0; DIGEST_LEN],
        }
    }
}

impl ChainStatus {
    /// No status, for status() to fill.
    const fn zeroed() -> Self {
        ChainStatus {
            tpm: false,
            defined: false,
            written: false,
            logged: false,
            anchored: false,
            rebound: false,
            value: [0; DIGEST_LEN],
            name: [0; NAME_LEN],
            name_len: 0,
            init: EventlogInit::zeroed(),
        }
    }
}

const _: () = assert!(size_of::<MeasuredUpatch>() == 328);
const _: () = assert!(size_of::<ChainInitInfo>() == 696);
const _: () = assert!(core::mem::offset_of!(ChainInitInfo, reset_count) == 388);
const _: () = assert!(core::mem::offset_of!(ChainInitInfo, name_len) == 528);
const _: () = assert!(core::mem::offset_of!(ChainInitInfo, anchor_digest) == 664);
const _: () = assert!(size_of::<ChainStatus>() == 624);
const _: () = assert!(core::mem::offset_of!(ChainStatus, name_len) == 72);
const _: () = assert!(core::mem::offset_of!(ChainStatus, init) == 80);

/// memneq_explicit(): whether the two
/// differ, in a time that depends on their length alone.
/// The history root of a tree after one more operation, whatever its
/// outcome on this node: SHA-256 of "shirudo-tree-history" with its NUL,
/// the root before it and the operation's digest. The publisher computes
/// a segment's base with it, without the TPM.
pub(crate) fn history_step(
    prev: &[u8; 32],
    operation_digest: &[u8; 32],
) -> Result<[u8; 32], c_int> {
    const TAG: &[u8] = b"shirudo-tree-history\0";
    let mut buf = [0u8; TAG.len() + 64];

    buf[..TAG.len()].copy_from_slice(TAG);
    buf[TAG.len()..TAG.len() + 32].copy_from_slice(prev);
    buf[TAG.len() + 32..].copy_from_slice(operation_digest);
    crate::util::crypto_openssl::sha256(&buf)
}

pub(crate) fn memneq_explicit(a: &[u8], b: &[u8]) -> bool {
    let mut neq = 0u8;

    for (x, y) in a.iter().zip(b) {
        neq |= x ^ y;
        neq = core::hint::black_box(neq);
    }
    neq != 0
}

/// SHA-256 of `a` followed by `b`, without copying either input.
pub(crate) fn sha256_parts(a: &[u8], b: &[u8]) -> Result<[u8; DIGEST_LEN], c_int> {
    let mut hash = Hasher::new(MessageDigest::sha256()).map_err(|_| -EIO)?;
    hash.update(a).map_err(|_| -EIO)?;
    if !b.is_empty() {
        hash.update(b).map_err(|_| -EIO)?;
    }
    let digest = hash.finish().map_err(|_| -EIO)?;
    (*digest).try_into().map_err(|_| -EIO)
}

/// The digest of `parts` one after the other.
fn digest(parts: &[&[u8]]) -> Result<[u8; DIGEST_LEN], c_int> {
    crate::util::crypto_openssl::sha256(&parts.concat())
}

/// The digest of `parts` one after the other into `out`, or zeros and
/// the error.
fn digest_into(parts: &[&[u8]], out: &mut [u8; DIGEST_LEN]) -> c_int {
    match digest(parts) {
        Ok(digest) => {
            *out = digest;
            0
        }
        Err(err) => {
            *out = [0; DIGEST_LEN];
            err
        }
    }
}

/// The init event: the set sorted by name, its listing of one
/// "[java ]<payload hex> <name>\n" line a member, whose digest goes
/// into `set_digest`, and the digest of the tag, `cert_sha`, the listing's
/// and `tree_root` into `event`. Both are zeros when it fails.
pub(crate) fn init_event(
    cert_sha: &[u8; DIGEST_LEN],
    set: &mut [MeasuredUpatch],
    tree_root: &[u8; DIGEST_LEN],
    set_digest: &mut [u8; DIGEST_LEN],
    event: &mut [u8; DIGEST_LEN],
) -> c_int {
    // In the order strcmp() gives their names, which no two share.
    set.sort_unstable_by(|a, b| cstr(&a.name).cmp(cstr(&b.name)));
    *event = [0; DIGEST_LEN];
    let listing: Vec<u8> = set
        .iter()
        .flat_map(|m| {
            [
                if m.ty == TYPE_JAVA {
                    &b"java "[..]
                } else {
                    &b""[..]
                },
                cstr(&m.payload_hex),
                b" ",
                cstr(&m.name),
                b"\n",
            ]
            .concat()
        })
        .collect();
    let ret = digest_into(&[&listing], set_digest);
    if ret != 0 {
        return ret;
    }
    digest_into(
        &[b"shirudo-init\0", cert_sha, &set_digest[..], tree_root],
        event,
    )
}

/// The event of the key `cert_sha` under `tag`: the digest of the tag,
/// its NUL and the key's digest.
pub(crate) fn key_event(
    tag: &CStr,
    cert_sha: &[u8; DIGEST_LEN],
) -> Result<[u8; DIGEST_LEN], c_int> {
    digest(&[tag.to_bytes_with_nul(), cert_sha])
}

/// The domain tag of a BPF or Java load or unload.
pub(crate) fn upatch_tag(ty: u32, load: bool) -> Option<&'static CStr> {
    match (ty, load) {
        (TYPE_BPF, true) => Some(c"shirudo-upatch"),
        (TYPE_BPF, false) => Some(c"shirudo-unload"),
        (TYPE_JAVA, true) => Some(c"shirudo-java"),
        (TYPE_JAVA, false) => Some(c"shirudo-java-unload"),
        _ => None,
    }
}

/// The event of a upatch loaded or unloaded: the digest of `tag` and its
/// NUL, the payload digest and the name, up to its NUL and cut at
/// NAME_MAX bytes.
pub(crate) fn upatch_event(
    tag: &CStr,
    name: &[u8],
    payload: &[u8; DIGEST_LEN],
) -> Result<[u8; DIGEST_LEN], c_int> {
    let name = cstr(name);
    let name = &name[..name.len().min(NAME_MAX)];
    digest(&[tag.to_bytes_with_nul(), payload, name])
}

/// The event of a tree operation: the digest of the tag and its NUL,
/// `seq` as a u64 most significant byte first, and the operation's
/// digest.
pub(crate) fn tree_event(
    seq: i64,
    operation: &[u8; DIGEST_LEN],
) -> Result<[u8; DIGEST_LEN], c_int> {
    digest(&[b"shirudo-tree\0", &(seq as u64).to_be_bytes(), operation])
}

/// The register `chain` extended by `event`, as the TPM extends it, or
/// zeros and the error.
pub(crate) fn fold(chain: &mut [u8; DIGEST_LEN], event: &[u8; DIGEST_LEN]) -> c_int {
    let both = [&chain[..], event].concat();
    digest_into(&[&both], chain)
}

/// Append the PCR 9 anchor to systemd's userspace measurement log. A
/// partially written record leaves its sticky bit set, so replay refuses
/// the whole log after an interrupted append.
fn log_anchor(anchor: &[u8], digest: &[u8; DIGEST_LEN]) -> Result<(), c_int> {
    if anchor.iter().any(|&b| b == b'"' || b == b'\\' || b < 0x20) {
        return Err(-EINVAL);
    }
    let mut boot = [0u8; 64];
    crate::util::eventlog::read_boot_id(&mut boot);
    let mut boot_id = [0u8; 32];
    let mut count = 0;
    for &b in cstr(&boot)
        .iter()
        .filter(|&&b| b != b'-' && b != b'\n')
        .take(32)
    {
        boot_id[count] = b;
        count += 1;
    }
    if count != boot_id.len() {
        return Err(-EIO);
    }
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: CLOCK_BOOTTIME and room for its timespec.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut now) } != 0 {
        return Err(-EIO);
    }
    let seconds = u64::try_from(now.tv_sec).map_err(|_| -EIO)?;
    let micros = seconds
        .checked_mul(1_000_000)
        .and_then(|n| n.checked_add(u64::try_from(now.tv_nsec).ok()? / 1_000))
        .ok_or(-EIO)?;
    let record = anchor_record(anchor, digest, &boot_id, micros)?;

    // SAFETY: a process credential query with no pointer.
    let euid = unsafe { libc::geteuid() };
    // SAFETY: a process credential query with no pointer.
    let uid = unsafe { libc::getuid() };
    let path = measure_log_path(
        std::env::var_os("SYSTEMD_MEASURE_LOG_USERSPACE").as_deref(),
        euid == uid,
    );
    let _ = std::fs::create_dir("/run/log");
    let _ = std::fs::create_dir("/run/log/systemd");
    append_anchor_record(&path, &record)
}

fn measure_log_path(override_path: Option<&std::ffi::OsStr>, same_uid: bool) -> std::path::PathBuf {
    if same_uid && let Some(path) = override_path {
        return std::path::PathBuf::from(path);
    }
    std::path::PathBuf::from("/run/log/systemd/tpm2-measure.log")
}

fn anchor_record(
    anchor: &[u8],
    digest: &[u8; DIGEST_LEN],
    boot_id: &[u8; 32],
    timestamp: u64,
) -> Result<Vec<u8>, c_int> {
    let mut json = [0u8; 766];
    let mut e = crate::util::json::JsonEmit::fixed(&mut json);
    e.obj_open();
    e.kv_int(b"pcr", i64::from(PCR));
    e.arr_open(b"digests");
    e.obj_open();
    e.kv_string(b"hashAlg", b"sha256");
    e.kv_string(b"digest", &crate::util::hex::encode(digest));
    e.obj_close();
    e.arr_close();
    e.kv_string(b"content_type", b"systemd");
    e.obj_open_key(b"content");
    e.kv_string(b"string", anchor);
    e.kv_string(b"bootId", boot_id);
    e.kv_u64(b"timestamp", timestamp);
    e.kv_string(b"eventType", b"nvpcr-init");
    e.obj_close();
    e.obj_close();
    let json = e.finish().map_err(|_| -E2BIG)?;
    let mut record = Vec::with_capacity(json.len() + 2);
    record.push(0x1e);
    record.extend_from_slice(&json);
    record.push(b'\n');
    Ok(record)
}

fn append_anchor_record(path: &std::path::Path, record: &[u8]) -> Result<(), c_int> {
    use std::io::{Seek, SeekFrom, Write};
    use std::os::fd::AsFd;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOCTTY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| -e.raw_os_error().unwrap_or(EIO))?;
    crate::util::io::lock_exclusive(file.as_fd())?;
    let state = file
        .metadata()
        .map_err(|e| -e.raw_os_error().unwrap_or(EIO))?;
    if !state.is_file() || state.permissions().mode() & 0o1000 != 0 {
        return Err(-crate::errno::ESTALE);
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o1600))
        .map_err(|e| -e.raw_os_error().unwrap_or(EIO))?;
    file.seek(SeekFrom::End(0))
        .map_err(|e| -e.raw_os_error().unwrap_or(EIO))?;
    file.write_all(record)
        .map_err(|e| -e.raw_os_error().unwrap_or(EIO))?;
    file.sync_all()
        .map_err(|e| -e.raw_os_error().unwrap_or(EIO))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| -e.raw_os_error().unwrap_or(EIO))?;
    file.sync_all()
        .map_err(|e| -e.raw_os_error().unwrap_or(EIO))?;
    Ok(())
}

/// `v` as "%x" prints it.
fn lower_hex(v: u32, buf: &mut [u8; 8]) -> &[u8] {
    let skip = (v.leading_zeros() / 4).min(7) as usize;

    for (i, d) in buf.iter_mut().enumerate() {
        *d = b"0123456789abcdef"[((v >> (28 - 4 * i)) & 0xf) as usize];
    }
    &buf[skip..]
}

/// The NUL-terminated PCR record anchoring the register named `name`:
/// "nvpcr-init:shirudo:0x<index>:<name in hex>".
pub(crate) fn anchor(name: &[u8]) -> Result<[u8; ANCHOR_MAX], c_int> {
    let mut index = [0u8; 8];
    let name = name.get(..NAME_LEN).ok_or(-EINVAL)?;
    let hex = crate::util::hex::encode(name);
    let parts: [&[u8]; 6] = [
        b"nvpcr-init:",
        CHAIN_NAME,
        b":0x",
        lower_hex(NV_INDEX, &mut index),
        b":",
        &hex,
    ];
    let mut out = [0u8; ANCHOR_MAX];
    strsprintf(&mut out, &parts).map_err(|_| -E2BIG)?;
    Ok(out)
}

/// The binding PCR values in PCR order, as PolicyPCR hashes them.
fn bind_values(
    pcr_before: &[u8; DIGEST_LEN],
    phase_before: &[u8; DIGEST_LEN],
    out: &mut [u8; 2 * DIGEST_LEN],
) {
    out[..DIGEST_LEN].copy_from_slice(pcr_before);
    out[DIGEST_LEN..].copy_from_slice(phase_before);
}

/// The register's policy for the PCR values it binds to and the writer,
/// its two branches, and the names its index has before and after the
/// first write, TPMA_NV_WRITTEN being part of the public area.
struct Expectation {
    branch_written: [u8; DIGEST_LEN],
    branch_init: [u8; DIGEST_LEN],
    policy: [u8; DIGEST_LEN],
    unwritten: [u8; NAME_LEN],
    written: [u8; NAME_LEN],
}

impl Expectation {
    const fn new() -> Self {
        Expectation {
            branch_written: [0; DIGEST_LEN],
            branch_init: [0; DIGEST_LEN],
            policy: [0; DIGEST_LEN],
            unwritten: [0; NAME_LEN],
            written: [0; NAME_LEN],
        }
    }
}

/// The register's policy and its branches for the PCR values it binds
/// to and the writer into `e`.
fn expectation_policy(
    pcr_before: &[u8; DIGEST_LEN],
    phase_before: &[u8; DIGEST_LEN],
    writer_public: &[u8; NV_RSA_BYTES],
    e: &mut Expectation,
) -> c_int {
    let mut values = [0u8; 2 * DIGEST_LEN];

    bind_values(pcr_before, phase_before, &mut values);
    let digests = RegisterPolicy {
        branch_written: &mut e.branch_written,
        branch_init: &mut e.branch_init,
        policy: &mut e.policy,
    };
    let ret = register_policy(PCR_MASK, &values, writer_public, digests);

    if ret != 0 {
        crate::log::err(format!("tpm: compute signed register policy: {}", text(ret)).as_bytes());
    }
    ret
}

/// The expectation for the PCR values and the writer into `e`.
fn register_expectation(
    pcr_before: &[u8; DIGEST_LEN],
    phase_before: &[u8; DIGEST_LEN],
    writer_public: &[u8; NV_RSA_BYTES],
    e: &mut Expectation,
) -> c_int {
    let ret = expectation_policy(pcr_before, phase_before, writer_public, e);

    if ret != 0 {
        return ret;
    }
    let size = DIGEST_LEN as u16;
    let ret = nv_name(NV_INDEX, REGISTER_ATTRS, &e.policy, size, &mut e.unwritten);

    if ret != 0 {
        return ret;
    }
    nv_name(
        NV_INDEX,
        REGISTER_ATTRS | NV_WRITTEN,
        &e.policy,
        size,
        &mut e.written,
    )
}

fn name_equals(info: &NvInfo, name: &[u8; NAME_LEN]) -> bool {
    info.name().len() == NAME_LEN && !memneq_explicit(info.name(), name)
}

/// 0 as success, any other code as its error.
fn zero_or(ret: c_int) -> Result<(), c_int> {
    if ret != 0 { Err(ret) } else { Ok(()) }
}

/// The index defined afresh with `policy`, undefined first when
/// `defined`, under the owner auth of the configuration.
fn register_define(tpm: &Tpm, defined: bool, policy: &[u8; DIGEST_LEN]) -> Result<(), c_int> {
    let mut cfg = Scrubbed::new();

    let loaded = config::load(&mut cfg);
    if loaded != 0 {
        crate::log::err(format!("tpm: configuration unreadable: {}", text(loaded)).as_bytes());
        return Err(loaded);
    }
    let c = &*cfg;
    let auth = c
        .tpm_owner_auth
        .get(..c.tpm_owner_auth_len)
        .ok_or(-EINVAL)?;

    if defined {
        tpm.nv_undefine(NV_INDEX, auth)?;
    }
    tpm.nv_define(NV_INDEX, policy, auth)
}

/// The NV writer init froze, set on the connection: its modulus.
fn register_writer(tpm: &mut Tpm) -> Result<[u8; NV_RSA_BYTES], c_int> {
    let mut seed = [0u8; DIGEST_LEN];
    let mut public = [0u8; NV_RSA_BYTES];
    let ret = nv_writer::read(&mut seed, &mut public);
    let set = zero_or(ret).and_then(|()| tpm.set_writer(&seed, &public));

    scrub(&mut seed);
    set.map(|()| public)
}

/// Bind the register to this boot and write `event` as its first event,
/// or find the binding a run before made: chain_init().
pub(crate) fn init(event: &[u8; DIGEST_LEN], info: &mut ChainInitInfo) -> c_int {
    *info = ChainInitInfo::zeroed();
    let Ok(mut tpm) = Tpm::open() else {
        return -ENODEV;
    };

    bind(&mut tpm, event, info).err().unwrap_or(0)
}

/// chain_init() on the connection `tpm`.
fn bind(tpm: &mut Tpm, event: &[u8; DIGEST_LEN], info: &mut ChainInitInfo) -> Result<(), c_int> {
    let mut e = Expectation::new();
    let mut rec = EventlogInit::zeroed();

    info.reset_count = tpm.reset_count()?;
    let mut nv = tpm.nv_info(NV_INDEX)?;

    // A record of this boot for the TPM's reset count means init bound
    // the register already: written and of the recorded name, a re-run
    // keeps it; anything else is refused, as binding again would restart
    // the history the record vouches for. A log that cannot be read may
    // hold such a record.
    let ret = boot_init(&mut rec);
    if ret != 0 && ret != -ENOENT {
        crate::log::err(
            &[
                &b"tpm: eventlog "[..],
                crate::util::eventlog::path().to_bytes(),
                b" unreadable: ",
                text(ret).as_bytes(),
                b"; not binding register 0x",
                format!("{NV_INDEX:08x}").as_bytes(),
            ]
            .concat(),
        );
        return Err(ret);
    }
    let recorded = ret == 0 && (!rec.have_reset_count || rec.reset_count == info.reset_count);
    if recorded {
        return rebind(tpm, &rec, &nv, &mut e, info);
    }
    if nv.defined && nv.written {
        crate::log::warn(
            format!(
                "tpm: register 0x{NV_INDEX:08x} written this boot without a record; rebinding it"
            )
            .as_bytes(),
        );
    }

    info.pcr_before = tpm.pcr_read(PCR)?;
    info.phase_before = tpm.pcr_read(PHASE_PCR)?;
    info.initrd = in_initrd();
    info.writer_public = register_writer(tpm)?;
    zero_or(register_expectation(
        &info.pcr_before,
        &info.phase_before,
        &info.writer_public,
        &mut e,
    ))?;
    info.anchor = anchor(&e.written)?;

    if !nv.defined || nv.written || !name_equals(&nv, &e.unwritten) {
        register_define(tpm, nv.defined, &e.policy)?;
        nv = tpm.nv_info(NV_INDEX)?;
        if !nv.defined || !name_equals(&nv, &e.unwritten) {
            crate::log::err(
                format!(
                    "tpm: register 0x{NV_INDEX:08x} name does not match the computed public area"
                )
                .as_bytes(),
            );
            return Err(-EPROTO);
        }
    }

    let branches = Branches {
        written: &e.branch_written,
        init: &e.branch_init,
    };
    tpm.nv_extend_first(NV_INDEX, PCR_MASK, &branches, event)?;
    info.name = e.written;
    info.name_len = NAME_LEN;
    zero_or(sha256_into(cstr(&info.anchor), &mut info.anchor_digest))?;
    if let Err(ret) = tpm.pcr_extend(PCR, &info.anchor_digest) {
        crate::log::err(format!("tpm: register written but PCR {PCR} not anchored; the init branch stays open until reboot").as_bytes());
        return Err(ret);
    }
    if let Err(ret) = log_anchor(cstr(&info.anchor), &info.anchor_digest) {
        crate::log::warn(
            format!(
                "tpm: PCR {PCR} anchor not in systemd's measurement log: {}",
                text(ret)
            )
            .as_bytes(),
        );
    }
    info.value = tpm.nv_read(NV_INDEX)?;
    Ok(())
}

/// The binding the record `rec` of this boot names: the register as it
/// is when written under the recorded name, else -EEXIST.
fn rebind(
    tpm: &mut Tpm,
    rec: &EventlogInit,
    nv: &NvInfo,
    e: &mut Expectation,
    info: &mut ChainInitInfo,
) -> Result<(), c_int> {
    info.writer_public = register_writer(tpm)?;
    zero_or(register_expectation(
        &rec.pcr_before,
        &rec.phase_before,
        &info.writer_public,
        e,
    ))?;
    if !name_equals(nv, &e.written) {
        crate::log::err(b"tpm: recorded register has an obsolete policy; trusted reboot required");
        return Err(-EEXIST);
    }
    if memneq_explicit(&info.writer_public, &rec.writer_public) {
        crate::log::err(b"tpm: recorded NV writer differs from the guarded key");
        return Err(-EKEYREJECTED);
    }
    if nv.defined && nv.written && name_equals(nv, &rec.name) {
        let name = nv.name();

        info.value = tpm.nv_read(NV_INDEX)?;
        info.name[..name.len()].copy_from_slice(name);
        info.name_len = name.len();
        info.pcr_before = rec.pcr_before;
        info.phase_before = rec.phase_before;
        info.anchor_digest = rec.anchor_digest;
        info.anchor = anchor(&info.name)?;
        info.initrd = rec.initrd;
        info.reused = true;
        return Ok(());
    }
    let state = if !nv.defined {
        c"gone"
    } else if !nv.written {
        c"unwritten"
    } else {
        c"not the recorded index"
    };
    crate::log::err(
        &[
            &b"tpm: register 0x"[..],
            format!("{NV_INDEX:08x}").as_bytes(),
            b" bound this boot is ",
            state.to_bytes(),
            b"; not binding another before the next TPM reset",
        ]
        .concat(),
    );
    Err(-EEXIST)
}

/// Extend this boot's register by `event` through the written branch,
/// its value then into `out_chain` when given.
pub(crate) fn extend(event: &[u8; DIGEST_LEN], out_chain: Option<&mut [u8; DIGEST_LEN]>) -> c_int {
    let mut e = Expectation::new();
    let mut rec = EventlogInit::zeroed();

    if boot_init(&mut rec) != 0 {
        return -ENODEV;
    }
    let ret = expectation_policy(
        &rec.pcr_before,
        &rec.phase_before,
        &rec.writer_public,
        &mut e,
    );
    if ret != 0 {
        return ret;
    }

    let Ok(mut tpm) = Tpm::open() else {
        return -ENODEV;
    };

    extend_on(&mut tpm, &rec, &e, event, out_chain)
        .err()
        .unwrap_or(0)
}

/// Extend on the connection `tpm`, with the record `rec` and the
/// branches and policy `e` of its binding.
fn extend_on(
    tpm: &mut Tpm,
    rec: &EventlogInit,
    e: &Expectation,
    event: &[u8; DIGEST_LEN],
    out_chain: Option<&mut [u8; DIGEST_LEN]>,
) -> Result<(), c_int> {
    let nv = tpm.nv_info(NV_INDEX)?;

    if !nv.defined || !nv.written {
        return Err(-ENODEV);
    }
    if !name_equals(&nv, &rec.name) {
        crate::log::err(
            format!("tpm: register 0x{NV_INDEX:08x} is not the index init recorded (recreated?)")
                .as_bytes(),
        );
        return Err(-EACCES);
    }
    if memneq_explicit(&nv.policy, &e.policy) {
        crate::log::err(b"tpm: register write policy is obsolete or substituted");
        return Err(-EACCES);
    }
    let reset = tpm.reset_count()?;
    if !rec.have_reset_count || reset != rec.reset_count {
        crate::log::err(b"tpm: register reset differs from the init record");
        return Err(-EACCES);
    }
    let writer_public = register_writer(tpm)?;
    if memneq_explicit(&writer_public, &rec.writer_public) {
        crate::log::err(b"tpm: recorded NV writer differs from the guarded key");
        return Err(-EKEYREJECTED);
    }
    let branches = Branches {
        written: &e.branch_written,
        init: &e.branch_init,
    };
    tpm.nv_extend(NV_INDEX, &branches, event)
        .map_err(|_| -EIO)?;
    if let Some(out_chain) = out_chain {
        *out_chain = tpm.nv_read(NV_INDEX).map_err(|_| -EIO)?;
    }
    Ok(())
}

/// The register's value this boot. A missing TPM or failed read is ENODEV.
pub(crate) fn read() -> Result<[u8; DIGEST_LEN], c_int> {
    let tpm = Tpm::open().map_err(|_| -ENODEV)?;
    tpm.nv_read(NV_INDEX).map_err(|_| -ENODEV)
}

/// The register as the TPM reports it, over the session init pinned.
pub(crate) struct ChainLive {
    pub(crate) name: [u8; NAME_LEN],
    pub(crate) reset_count: u32,
    pub(crate) value: [u8; DIGEST_LEN],
}

/// The live register's name, value and TPM reset count: -ENODEV when no
/// TPM answers or the index is not written this reset, -EIO when a read
/// fails.
pub(crate) fn live() -> Result<ChainLive, c_int> {
    let tpm = Tpm::open().map_err(|_| -ENODEV)?;
    let reset_count = tpm.reset_count().map_err(|_| -EIO)?;
    let nv = tpm.nv_info(NV_INDEX).map_err(|_| -EIO)?;
    let name = match <[u8; NAME_LEN]>::try_from(nv.name()) {
        Ok(name) if nv.defined && nv.written => name,
        _ => return Err(-ENODEV),
    };
    let value = tpm.nv_read(NV_INDEX).map_err(|_| -EIO)?;

    Ok(ChainLive {
        name,
        reset_count,
        value,
    })
}

/// Whether a TPM answers with the register written.
pub(crate) fn bound() -> bool {
    let Ok(tpm) = Tpm::open_quiet() else {
        return false;
    };

    tpm.nv_info(NV_INDEX)
        .is_ok_and(|nv| nv.defined && nv.written)
}

/// The register as the TPM and this boot's records show it: chain_status().
pub(crate) fn status(st: &mut ChainStatus) -> c_int {
    *st = ChainStatus::zeroed();
    st.logged = boot_init(&mut st.init) == 0;
    st.rebound = st.logged && st.init.records_epoch > 1;
    let Ok(tpm) = Tpm::open_quiet() else {
        return -ENODEV;
    };
    st.tpm = true;
    status_on(&tpm, st)
}

/// chain_status() on the connection `tpm`.
fn status_on(tpm: &Tpm, st: &mut ChainStatus) -> c_int {
    let mut e = Expectation::new();
    let mut ret = 0;
    let reset_count = match tpm.reset_count() {
        Ok(count) => count,
        Err(ret) => return ret,
    };
    let nv = match tpm.nv_info(NV_INDEX) {
        Ok(nv) => nv,
        Err(ret) => return ret,
    };
    let name = nv.name();

    st.defined = nv.defined;
    st.written = nv.written;
    st.name[..name.len()].copy_from_slice(name);
    st.name_len = name.len();
    if nv.defined && nv.written {
        match tpm.nv_read(NV_INDEX) {
            Ok(value) => st.value = value,
            Err(err) => ret = err,
        }
    }
    st.anchored = nv.defined
        && nv.written
        && st.logged
        && name_equals(&nv, &st.init.name)
        && (!st.init.have_reset_count || st.init.reset_count == reset_count);
    if st.anchored {
        let init = &st.init;

        ret = expectation_policy(
            &init.pcr_before,
            &init.phase_before,
            &init.writer_public,
            &mut e,
        );
        if ret != 0 {
            st.anchored = false;
            return ret;
        }
        let attrs = REGISTER_ATTRS | NV_WRITTEN;
        st.anchored = nv_name(
            NV_INDEX,
            attrs,
            &e.policy,
            DIGEST_LEN as u16,
            &mut e.written,
        ) == 0
            && name_equals(&nv, &e.written);
    }
    ret
}

#[cfg(test)]
mod tests;
