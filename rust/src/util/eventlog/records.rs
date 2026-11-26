// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! What the records of a boot say: the register they replay to, the
//! binding of its init record, a tree operation measured, and the
//! upatches loaded and unloaded.

use core::ffi::{CStr, c_int};

use super::{sha256_into, walk_boot, walk_log};
use crate::errno::{EINVAL, ENOENT};
use crate::text::cstr;
use crate::util::hex::{self, hex_decode};
use crate::util::json::{JsonField, parse_schema};
use crate::util::upatch::{NAME_MAX, PAYLOAD_HASH_LEN, TYPE_BPF, TYPE_JAVA, name_valid};

const NAME_LEN: usize = 34;
const NV_RSA_BYTES: usize = 384;

/// `enum eventlog_upatch_event`.
pub(crate) const UPATCH_INIT: c_int = 0;
pub(crate) const UPATCH_LOAD: c_int = 1;
pub(crate) const UPATCH_UNLOAD: c_int = 2;

struct UpatchRecord {
    record: &'static [u8],
    kind: &'static [u8],
    ty: u32,
    load: bool,
}

const UPATCH_RECORDS: [UpatchRecord; 4] = [
    UpatchRecord {
        record: b"upatch_load",
        kind: b"load",
        ty: TYPE_BPF,
        load: true,
    },
    UpatchRecord {
        record: b"upatch_unload",
        kind: b"unload",
        ty: TYPE_BPF,
        load: false,
    },
    UpatchRecord {
        record: b"java_load",
        kind: b"java-load",
        ty: TYPE_JAVA,
        load: true,
    },
    UpatchRecord {
        record: b"java_unload",
        kind: b"java-unload",
        ty: TYPE_JAVA,
        load: false,
    },
];

pub(crate) fn upatch_record(ty: u32, load: bool) -> Option<&'static [u8]> {
    UPATCH_RECORDS
        .iter()
        .find(|r| r.ty == ty && r.load == load)
        .map(|r| r.record)
}

pub(crate) fn upatch_record_parse(record: &[u8]) -> Option<(u32, bool)> {
    UPATCH_RECORDS
        .iter()
        .find(|r| r.record == record)
        .map(|r| (r.ty, r.load))
}

pub(crate) fn upatch_kind_parse(kind: &[u8]) -> Option<(u32, bool)> {
    UPATCH_RECORDS
        .iter()
        .find(|r| r.kind == kind)
        .map(|r| (r.ty, r.load))
}

/// What the walk of this boot's lines calls with each.
pub(crate) type LineFn<'a> = &'a mut dyn FnMut(&CStr) -> c_int;
/// What the upatch walks call with each event: the event, and for a
/// load or an unload the upatch's name and its payload's digest in hex.
pub(crate) type UpatchFn<'a> = &'a mut dyn FnMut(c_int, &[u8], &[u8]) -> c_int;

/// `struct eventlog_init`: this boot's last init record.
#[repr(C)]
pub struct EventlogInit {
    pub(crate) writer_public: [u8; NV_RSA_BYTES],
    pub(crate) pcr: u32,
    pub(crate) initrd: bool,
    pub(crate) pcr_before: [u8; 32],
    pub(crate) phase_before: [u8; 32],
    pub(crate) name: [u8; NAME_LEN],
    pub(crate) name_len: usize,
    pub(crate) anchor_digest: [u8; 32],
    pub(crate) have_reset_count: bool,
    pub(crate) reset_count: u32,
    pub(crate) records: u32,
    pub(crate) records_epoch: u32,
}

const _: () = assert!(size_of::<EventlogInit>() == 544);

impl EventlogInit {
    /// No record, for boot_init() to fill.
    pub(crate) const fn zeroed() -> Self {
        EventlogInit {
            writer_public: [0; NV_RSA_BYTES],
            pcr: 0,
            initrd: false,
            pcr_before: [0; 32],
            phase_before: [0; 32],
            name: [0; NAME_LEN],
            name_len: 0,
            anchor_digest: [0; 32],
            have_reset_count: false,
            reset_count: 0,
            records: 0,
            records_epoch: 0,
        }
    }
}

/// `hex` decoded into `out`, as hex_decode() takes it: 0 or -EINVAL.
fn decode(hex: &[u8], out: &mut [u8]) -> c_int {
    // SAFETY: hex ends in a NUL the parser wrote, and out has room for
    // out.len() bytes.
    unsafe { hex_decode(hex.as_ptr().cast(), out.as_mut_ptr(), out.len()) }
}

/// The register this boot's records replay to: each digest folded in
/// order, from zero at an init record.
pub(crate) fn replay(out: &mut [u8; 32]) -> c_int {
    let mut chain = [0u8; 32];
    let ret = walk_boot(&mut |line, is_init| replay_line(line, is_init, &mut chain));

    if ret == 0 {
        *out = chain;
    }
    ret
}

fn replay_line(line: &CStr, is_init: bool, chain: &mut [u8; 32]) -> c_int {
    let mut digest_hex = [0u8; 2 * 32 + 1];
    let mut digest = [0u8; 32];
    let mut cat = [0u8; 64];
    let f = [JsonField::string(
        c"digest",
        |hex: &mut [u8; 2 * 32 + 1]| hex,
    )];

    if parse_schema(line.to_bytes(), &f, &mut digest_hex).is_err()
        || !f[0].seen()
        || decode(&digest_hex, &mut digest) != 0
    {
        return -EINVAL;
    }
    if is_init {
        *chain = [0; 32];
    }
    cat[..32].copy_from_slice(chain);
    cat[32..].copy_from_slice(&digest);
    sha256_into(&cat, chain)
}

/// This boot's last init record into `out`, which the caller zeroed.
pub(crate) fn boot_init(out: &mut EventlogInit) -> c_int {
    walk_boot(&mut |line, is_init| init_line(line, is_init, out))
}

/// What the line of an init record gives, its digests and names in hex.
struct InitLine {
    writer_public: [u8; 2 * NV_RSA_BYTES + 1],
    pcr_before: [u8; 2 * 32 + 1],
    name: [u8; 2 * NAME_LEN + 1],
    phase_before: [u8; 2 * 32 + 1],
    anchor: [u8; 2 * 32 + 1],
    bound_in: [u8; 8],
    pcr: i64,
    reset_count: i64,
}

fn init_line(line: &CStr, is_init: bool, out: &mut EventlogInit) -> c_int {
    let mut init = InitLine {
        writer_public: [0; 2 * NV_RSA_BYTES + 1],
        pcr_before: [0; 2 * 32 + 1],
        name: [0; 2 * NAME_LEN + 1],
        phase_before: [0; 2 * 32 + 1],
        anchor: [0; 2 * 32 + 1],
        bound_in: [0; 8],
        pcr: -1,
        reset_count: -1,
    };

    if !is_init {
        return 0;
    }
    let f = [
        JsonField::string(c"pcr_before", |i: &mut InitLine| &mut i.pcr_before),
        JsonField::string(c"nv_name", |i| &mut i.name),
        JsonField::string(c"anchor_digest", |i| &mut i.anchor),
        JsonField::int(c"pcr", |i| &mut i.pcr),
        JsonField::int(c"tpm_reset_count", |i| &mut i.reset_count),
        JsonField::string(c"phase_before", |i| &mut i.phase_before),
        JsonField::string(c"bound_in", |i| &mut i.bound_in),
        JsonField::string(c"nv_writer_public", |i| &mut i.writer_public),
    ];
    let ret = parse_schema(line.to_bytes(), &f, &mut init);

    if ret.is_err()
        || !f[0].seen()
        || !f[1].seen()
        || !f[2].seen()
        || !f[3].seen()
        || !f[5].seen()
        || !(0..24).contains(&init.pcr)
        || (f[4].seen() && !(0..=i64::from(u32::MAX)).contains(&init.reset_count))
        || cstr(&init.name).len() != 2 * NAME_LEN
        || decode(&init.pcr_before, &mut out.pcr_before) != 0
        || decode(&init.phase_before, &mut out.phase_before) != 0
        || decode(&init.name, &mut out.name) != 0
        || decode(&init.anchor, &mut out.anchor_digest) != 0
        || !f[7].seen()
        || decode(&init.writer_public, &mut out.writer_public) != 0
    {
        return -EINVAL;
    }
    out.initrd = f[6].seen() && cstr(&init.bound_in) == b"initrd";
    // Records are of one TPM reset unless both carry a count and the
    // counts differ; a record without one cannot vouch for a reset in
    // between.
    let have_reset_count = f[4].seen();
    out.records = out.records.wrapping_add(1);
    if out.records == 1
        || (have_reset_count && out.have_reset_count && init.reset_count as u32 != out.reset_count)
    {
        out.records_epoch = 1;
    } else {
        out.records_epoch = out.records_epoch.wrapping_add(1);
    }
    out.have_reset_count = have_reset_count;
    out.reset_count = init.reset_count as u32;
    out.name_len = NAME_LEN;
    out.pcr = init.pcr as u32;
    0
}

/// Each of this boot's lines to `each`, which ends the walk with an
/// error it returns.
pub(crate) fn boot_lines(each: LineFn<'_>) -> c_int {
    walk_boot(&mut |line, _| each(line))
}

/// What the line of a tree operation gives.
struct TreeOpLine {
    ty: [u8; 32],
    digest: [u8; 128],
    seq: i64,
}

/// Whether this boot measured the tree operation of sequence `seq` and
/// digest `digest`: 1, 0, or a negative errno.
pub(crate) fn tree_op_measured(seq: i64, digest: &[u8]) -> c_int {
    let mut found = false;
    let ret = walk_boot(&mut |line, _| {
        let mut op = TreeOpLine {
            ty: [0; 32],
            digest: [0; 128],
            seq: 0,
        };
        let tree = [
            JsonField::int(c"seq", |o: &mut TreeOpLine| &mut o.seq),
            JsonField::string(c"operation_digest", |o| &mut o.digest),
        ];
        let f = [
            JsonField::string(c"type", |o: &mut TreeOpLine| &mut o.ty),
            JsonField::object(c"tree", &tree),
        ];

        if parse_schema(line.to_bytes(), &f, &mut op).is_err() {
            return -EINVAL;
        }
        if f[0].seen()
            && cstr(&op.ty) == b"tree_op"
            && tree[0].seen()
            && tree[1].seen()
            && op.seq == seq
            && cstr(&op.digest) == digest
        {
            found = true;
        }
        0
    });

    if ret == -ENOENT {
        return 0;
    }
    if ret != 0 {
        return ret;
    }
    c_int::from(found)
}

/// The upatch walk's state: the caller's callback, what the schema fills
/// of each record, and the callback's last result.
struct UpatchSink<'a> {
    cb: UpatchFn<'a>,
    ty: [u8; 32],
    name: [u8; NAME_MAX + 1],
    payload_hex: [u8; 2 * PAYLOAD_HASH_LEN + 1],
    set_name: [u8; NAME_MAX + 1],
    set_payload_hex: [u8; 2 * PAYLOAD_HASH_LEN + 1],
    ret: c_int,
}

/// Validate a member and give every reader the same hex spelling as
/// register replay and the payload stored on disk.
fn canonical_payload<'a>(name: &[u8], payload_hex: &'a mut [u8]) -> Result<&'a [u8], c_int> {
    if !name_valid(Some(name)) {
        return Err(-EINVAL);
    }
    let mut payload = [0u8; PAYLOAD_HASH_LEN];
    hex::decode(cstr(payload_hex), &mut payload)?;
    payload_hex[..2 * PAYLOAD_HASH_LEN].make_ascii_lowercase();
    Ok(cstr(payload_hex))
}

/// The sink's callback on `event` for the upatch its fields name.
fn notify(u: &mut UpatchSink<'_>, event: c_int) -> c_int {
    let name = cstr(&u.name);
    let payload = match canonical_payload(name, &mut u.payload_hex) {
        Ok(payload) => payload,
        Err(err) => return err,
    };
    (u.cb)(event, name, payload)
}

/// An entry of an init record's set: a load boot restore made.
fn take_set_entry(u: &mut UpatchSink<'_>) -> Result<(), c_int> {
    let name = cstr(&u.set_name);
    let payload = canonical_payload(name, &mut u.set_payload_hex)?;
    u.ret = (u.cb)(UPATCH_LOAD, name, payload);
    u.set_name[0] = 0;
    u.set_payload_hex[0] = 0;
    match u.ret {
        0 => Ok(()),
        err => Err(err),
    }
}

/// One record of the log to `cb`, as [`upatches`] would give it.
pub(crate) fn upatches_record(line: &CStr, is_init: bool, cb: UpatchFn<'_>) -> c_int {
    let mut sink = UpatchSink {
        cb,
        ty: [0; 32],
        name: [0; NAME_MAX + 1],
        payload_hex: [0; 2 * PAYLOAD_HASH_LEN + 1],
        set_name: [0; NAME_MAX + 1],
        set_payload_hex: [0; 2 * PAYLOAD_HASH_LEN + 1],
        ret: 0,
    };
    upatches_line(&mut sink, line, is_init)
}

/// The upatch events of this boot's records, or with `all` of every
/// record: an init and the set its record lists, then each load and
/// unload.
pub(crate) fn upatches(all: bool, cb: UpatchFn<'_>) -> c_int {
    let mut sink = UpatchSink {
        cb,
        ty: [0; 32],
        name: [0; NAME_MAX + 1],
        payload_hex: [0; 2 * PAYLOAD_HASH_LEN + 1],
        set_name: [0; NAME_MAX + 1],
        set_payload_hex: [0; 2 * PAYLOAD_HASH_LEN + 1],
        ret: 0,
    };

    walk_log(all, &mut |line, is_init| {
        upatches_line(&mut sink, line, is_init)
    })
}

fn upatches_line(u: &mut UpatchSink<'_>, line: &CStr, is_init: bool) -> c_int {
    u.ty = [0; 32];
    u.name[0] = 0;
    u.payload_hex[0] = 0;
    u.set_name[0] = 0;
    u.set_payload_hex[0] = 0;
    if is_init {
        let ret = (u.cb)(UPATCH_INIT, &[], &[]);
        if ret != 0 {
            return ret;
        }
    }
    let set_entry = [
        JsonField::string(c"name", |u: &mut UpatchSink<'_>| &mut u.set_name),
        JsonField::string(c"payload_sha256", |u| &mut u.set_payload_hex),
    ];
    let upatch = [
        JsonField::string(c"name", |u: &mut UpatchSink<'_>| &mut u.name),
        JsonField::string(c"payload_sha256", |u| &mut u.payload_hex),
    ];
    // Set entries cannot borrow fields from an upatch object or an
    // earlier set entry.
    let set_field = JsonField::array(c"set", &set_entry, &take_set_entry);
    let f = [
        JsonField::string(c"type", |u: &mut UpatchSink<'_>| &mut u.ty),
        if is_init {
            set_field
        } else {
            set_field.keyless()
        },
        JsonField::object(c"upatch", &upatch),
    ];

    if parse_schema(line.to_bytes(), &f, u).is_err() {
        return if u.ret != 0 { u.ret } else { -EINVAL };
    }
    if is_init {
        return 0;
    }
    let Some((_, load)) = upatch_record_parse(cstr(&u.ty)) else {
        return 0;
    };
    if !f[2].seen() {
        return -EINVAL;
    }
    let event = if load { UPATCH_LOAD } else { UPATCH_UNLOAD };
    notify(u, event)
}
