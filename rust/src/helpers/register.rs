// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-register: the measurement register driven against a TPM
//! (SHIRUDO_TPM_TCTI), with the eventlog and certificate where the
//! environment says, and what a shell test asserts on printed. Besides
//! init, loads, tree operations, reads and status, it sets up the NV
//! writer's identity as init would, and makes the attacks the register
//! must withstand: the index recreated, the init branch tried again, and
//! a register of the target's own forged in the real one's place.
//!
//!   test-register writer-create|writer-remove|writer-public|read|status
//!   test-register init <event hex>
//!   test-register load <upatch> <payload hex>
//!   test-register java-load <upatch> <payload hex>
//!   test-register tree <seq> <op> <id> sha256:<hex>
//!   test-register extend-raw <event hex>
//!   test-register pcr <pcr> | pcr-extend <pcr> <digest hex>
//!   test-register ek-public rsa|ecc | recreate | first-write <event hex>
//!   test-register forge <index hex> <pcr> <phase pcr> <event hex> <nonce hex>
//!   test-register evidence <nonce hex> [<challenge>]

use core::ffi::{CStr, c_int};

use super::{err, helper_main, out, out_bytes, perror, strerror};
use crate::sys::identity::Identity;
use crate::sys::version::shirudo_version_id;
use crate::util::attest::{PCR_DEFAULT, challenge_read, evidence_config};
use crate::util::bpf_sys::{
    Attr, BPF_ANY, BPF_MAP_CREATE, bpf_map_freeze, bpf_map_update_elem, bpf_obj_pin,
};
use crate::util::chain::{self, ANCHOR_MAX, ChainInitInfo, ChainStatus, PCR, PCR_MASK, PHASE_PCR};
use crate::util::crypto_openssl::sha256;
use crate::util::eventlog::{self, EventlogInit, NV_INDEX, boot_init, read_boot_id, timestamp};
use crate::util::hex::{decode, encode};
use crate::util::identity::IDENTITY_PIN;
use crate::util::image_guards::{GUARD_IDENTITY, GUARD_MAPS};
use crate::util::json::JsonEmit;
use crate::util::nv_writer;
use crate::util::tpm::{Attestation, Branches, KeyPublic, NvInfo, Tpm};
use crate::util::tpm_wire::{NV_RSA_BYTES, RegisterPolicy, register_policy};
use crate::util::upatch::{TYPE_BPF, TYPE_JAVA};

helper_main!(shirudo_helper_test_register, run);

fn hex(b: &[u8]) -> String {
    String::from_utf8_lossy(&encode(b)).into_owned()
}

fn puthex(b: &[u8]) {
    if b.len() <= 1024 {
        out(&format!("{}\n", hex(b)));
    }
}

/// `text` decoded into 32 bytes.
fn digest(text: &CStr) -> Option<[u8; 32]> {
    let mut d = [0u8; 32];
    decode(text.to_bytes(), &mut d).ok().map(|()| d)
}

/// As atoi(): the leading decimal number, 0 for none.
fn atoi(text: &CStr) -> i64 {
    let t = text.to_bytes();
    let (neg, rest) = match t {
        [b'-', rest @ ..] => (true, rest),
        [b'+', rest @ ..] => (false, rest),
        _ => (false, t),
    };
    let n = rest.iter().take_while(|c| c.is_ascii_digit()).count();
    let v: i64 = std::str::from_utf8(&rest[..n])
        .ok()
        .and_then(|d| d.parse().ok())
        .unwrap_or(0);
    if neg { -v } else { v }
}

/// The TPM writer's public identity recorded, as init pins it, before the
/// VM attaches its LSM.
fn writer_create() -> c_int {
    let mut id = Identity::zeroed();
    let ret = (|| {
        let ret = nv_writer::create(&mut id.nv_writer_seed, &mut id.nv_writer_public);
        if ret != 0 {
            return ret;
        }
        let def = &GUARD_MAPS[GUARD_IDENTITY].def;
        let mut name = [0u8; 16];
        let truncated = &def.name.to_bytes()[..def.name.to_bytes().len().min(15)];
        name[..truncated.len()].copy_from_slice(truncated);
        let fd = match Attr::new()
            .u32(0, def.map_type)
            .u32(4, def.key_size)
            .u32(8, def.value_size)
            .u32(12, def.max_entries)
            .u32(16, def.flags)
            .put(28, &name)
            .run(BPF_MAP_CREATE)
        {
            Ok(fd) => fd,
            Err(e) => return -e,
        };
        let zero = 0u32;
        // SAFETY: the map, a key and a value of its sizes, and a C string;
        // the map's fd closed once.
        unsafe {
            let mut ret = bpf_map_update_elem(
                fd,
                (&raw const zero).cast(),
                (&raw const id).cast(),
                BPF_ANY,
            );
            if ret == 0 {
                ret = bpf_map_freeze(fd);
            }
            if ret == 0 {
                ret = bpf_obj_pin(fd, IDENTITY_PIN.as_ptr());
            }
            libc::close(fd);
            ret
        }
    })();
    if ret == 0 {
        return 0;
    }
    err(&format!("TPM writer setup: {}\n", strerror(-ret)));
    1
}

/// The common head of a record of the log: its time, index, digest,
/// type and boot.
fn record_head(e: &mut JsonEmit, index: u32, event: &[u8; 32], ty: &[u8]) {
    let (mut ts, mut boot_id) = ([0u8; 32], [0u8; 64]);
    timestamp(&mut ts);
    read_boot_id(&mut boot_id);
    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_string(b"ts", crate::text::cstr(&ts));
    e.kv_string(b"nv_index", format!("0x{index:08X}").as_bytes());
    e.kv_string(b"alg", b"sha256");
    e.kv_string(b"digest", &encode(event));
    e.kv_string(b"type", ty);
    e.kv_string(b"boot_id", crate::text::cstr(&boot_id));
}

/// The record `fill` emits appended to the log.
fn append(fill: impl FnOnce(&mut JsonEmit)) -> c_int {
    let mut buf = [0u8; 4096];
    let mut e = JsonEmit::fixed(&mut buf);
    fill(&mut e);
    if e.err() != 0 {
        return e.err();
    }
    eventlog::append(e.output())
}

/// An init recorded the way shirudo init does, minus the set details.
fn append_init(event: &[u8; 32], info: &ChainInitInfo) -> c_int {
    append(|e| {
        record_head(e, NV_INDEX, event, b"init");
        e.kv_int(b"tpm_reset_count", info.reset_count.into());
        e.kv_int(b"pcr", PCR.into());
        e.kv_string(b"pcr_before", &encode(&info.pcr_before));
        e.kv_int(b"phase_pcr", PHASE_PCR.into());
        e.kv_string(b"phase_before", &encode(&info.phase_before));
        e.kv_string(b"bound_in", if info.initrd { b"initrd" } else { b"root" });
        e.kv_string(b"nv_name", &encode(&info.name[..info.name_len]));
        e.kv_string(b"nv_writer_public", &encode(&info.writer_public));
        e.kv_string(b"anchor", crate::text::cstr(&info.anchor));
        e.kv_string(b"anchor_digest", &encode(&info.anchor_digest));
        e.kv_string(b"chain", &encode(&info.value));
        e.obj_close();
    })
}

fn print_init(event: &[u8; 32]) -> c_int {
    let mut info = ChainInitInfo::zeroed();
    let ret = chain::init(event, &mut info);
    out(&format!("rc={ret}\n"));
    if ret != 0 {
        return 1;
    }
    out(&format!(
        "reused={}\nreset_count={}\nvalue={}\nname={}\npcr_before={}\nphase_before={}\nbound_in={}\nanchor={}\n",
        c_int::from(info.reused),
        info.reset_count,
        hex(&info.value),
        hex(&info.name[..info.name_len]),
        hex(&info.pcr_before),
        hex(&info.phase_before),
        if info.initrd { "initrd" } else { "root" },
        String::from_utf8_lossy(crate::text::cstr(&info.anchor))
    ));
    c_int::from(!info.reused && append_init(event, &info) != 0)
}

/// `event` extended into the register, its value printed, and `record`
/// appended to the log.
/// What makes the log's record of an extension, given its value.
type Record<'a> = &'a dyn Fn(&mut JsonEmit, &[u8; 32]);

fn extend(event: &[u8; 32], record: Option<Record<'_>>) -> c_int {
    let mut chain = [0u8; 32];
    let ret = chain::extend(event, Some(&mut chain));
    out(&format!("rc={ret}\n"));
    if ret != 0 {
        return 1;
    }
    out("value=");
    puthex(&chain);
    match record {
        Some(fill) => c_int::from(append(|e| fill(e, &chain)) != 0),
        None => 0,
    }
}

fn load(name: &CStr, payload_hex: &CStr, ty: u32) -> c_int {
    let Some(payload) = digest(payload_hex) else {
        return 2;
    };
    let (Some(tag), Some(record)) = (
        chain::upatch_tag(ty, true),
        eventlog::upatch_record(ty, true),
    ) else {
        return 1;
    };
    let Ok(event) = chain::upatch_event(tag, name.to_bytes(), &payload) else {
        return 1;
    };
    extend(
        &event,
        Some(&|e: &mut JsonEmit, chain: &[u8; 32]| {
            record_head(e, NV_INDEX, &event, record);
            e.obj_open_key(b"upatch");
            e.kv_string(b"name", name.to_bytes());
            e.kv_string(b"payload_sha256", &encode(&payload));
            e.obj_close();
            e.kv_string(b"chain", &encode(chain));
            e.obj_close();
        }),
    )
}

/// A tree operation, with the digest in the form the target records.
fn tree(args: &[&CStr]) -> c_int {
    let seq = atoi(args[2]);
    let (op, id, digest_text) = (args[3], args[4], args[5]);
    let Some(hex_part) = digest_text.to_bytes().strip_prefix(b"sha256:") else {
        return 2;
    };
    let mut operation = [0u8; 32];
    if decode(hex_part, &mut operation).is_err() {
        return 2;
    }
    let Ok(event) = chain::tree_event(seq, &operation) else {
        return 2;
    };
    extend(
        &event,
        Some(&|e: &mut JsonEmit, chain: &[u8; 32]| {
            record_head(e, NV_INDEX, &event, b"tree_op");
            e.obj_open_key(b"tree");
            e.kv_int(b"seq", seq);
            e.kv_string(b"op", op.to_bytes());
            e.kv_string(b"id", id.to_bytes());
            e.kv_string(b"operation_digest", digest_text.to_bytes());
            e.obj_close();
            e.kv_string(b"chain", &encode(chain));
            e.obj_close();
        }),
    )
}

fn status() -> c_int {
    let mut st = Box::new(ChainStatus::zeroed());
    let ret = chain::status(&mut st);
    let b = |v: bool| c_int::from(v);
    out(&format!(
        "rc={ret}\ntpm={} defined={} written={} logged={} anchored={}\nrebound={}\n",
        b(st.tpm),
        b(st.defined),
        b(st.written),
        b(st.logged),
        b(st.anchored),
        b(st.rebound)
    ));
    if st.defined && st.written {
        out("value=");
        puthex(&st.value);
    }
    c_int::from(ret != 0)
}

/// `f` on a TPM connection, closed after; None when it does not open.
fn with_tpm<R>(f: impl FnOnce(&mut Tpm) -> R) -> Option<R> {
    let mut t = Tpm::open().ok()?;

    Some(f(&mut t))
}

/// What a step returned, as the helper prints it.
fn rc<T>(result: &Result<T, c_int>) -> c_int {
    result.as_ref().err().copied().unwrap_or(0)
}

/// 0 as success, any other code as its error.
fn zero_or(ret: c_int) -> Result<(), c_int> {
    if ret != 0 { Err(ret) } else { Ok(()) }
}

fn ek_public(kind: &CStr) -> c_int {
    let Some(ret) = with_tpm(|t| match t.ek_create(kind.to_bytes() == b"rsa") {
        Ok(ek) => {
            out("public=");
            puthex(&ek.public().area);
            out("name=");
            puthex(&ek.public().name);
            0
        }
        Err(ret) => ret,
    }) else {
        return 1;
    };
    out(&format!("rc={ret}\n"));
    c_int::from(ret != 0)
}

/// The attack: recreate the index with the same public area.
fn recreate() -> c_int {
    let Some(result) = with_tpm(|t| {
        let nv = t.nv_info(NV_INDEX)?;
        if nv.defined {
            t.nv_undefine(NV_INDEX, &[])?;
        }
        t.nv_define(NV_INDEX, &nv.policy, &[])?;
        t.nv_info(NV_INDEX)
    }) else {
        return 1;
    };
    out(&format!("rc={}\n", rc(&result)));
    let Ok(nv) = result else {
        return 1;
    };
    out(&format!("written={}\nname=", c_int::from(nv.written)));
    puthex(nv.name());
    0
}

/// The attack: try the init branch again after the anchor.
fn first_write(event_hex: &CStr) -> c_int {
    let Some(event) = digest(event_hex) else {
        return 2;
    };
    let mut rec: Box<EventlogInit> = Box::new(EventlogInit::zeroed());
    let (mut seed, mut public) = ([0u8; 32], [0u8; NV_RSA_BYTES]);
    if boot_init(&mut rec) != 0 {
        return 2;
    }
    if nv_writer::read(&mut seed, &mut public) != 0 || public != rec.writer_public {
        return 2;
    }
    let values = [rec.pcr_before, rec.phase_before].concat();
    let (mut written, mut init, mut policy) = ([0u8; 32], [0u8; 32], [0u8; 32]);
    let digests = RegisterPolicy {
        branch_written: &mut written,
        branch_init: &mut init,
        policy: &mut policy,
    };
    let ret = register_policy(PCR_MASK, &values, &rec.writer_public, digests);
    if ret != 0 {
        err(&format!("register policy: {}\n", strerror(-ret)));
        return 1;
    }
    let branches = Branches {
        written: &written,
        init: &init,
    };
    let Some(result) = with_tpm(|t| {
        t.set_writer(&seed, &public)?;
        t.nv_extend_first(NV_INDEX, PCR_MASK, &branches, &event)
    }) else {
        return 1;
    };
    let ret = rc(&result);
    out(&format!("rc={ret}\n"));
    c_int::from(ret != 0)
}

/// What forge() made on the TPM, for the evidence it prints.
struct Forged {
    reset: u32,
    before: [u8; 64],
    anchor: [u8; ANCHOR_MAX],
    anchor_digest: [u8; 32],
    value: [u8; 32],
    values: [[u8; 32]; 24],
    ak: KeyPublic,
    ek: KeyPublic,
    quote: Attestation,
    certify: Attestation,
    after: Attestation,
    nv: NvInfo,
}

/// The register of the target's own at `index`, bound to `pcr` and
/// `phase`, written with `event`, anchored into `pcr`, quoted and
/// certified with `nonce`.
fn forge_on_tpm(
    t: &mut Tpm,
    seed: &[u8; 32],
    public: &[u8; NV_RSA_BYTES],
    index: u32,
    (pcr, phase): (u32, u32),
    event: &[u8; 32],
    nonce: &[u8],
) -> Result<Forged, c_int> {
    let mask = (1u32 << pcr) | (1u32 << phase);
    let quoted = PCR_DEFAULT | mask;
    let (mut written, mut init, mut policy) = ([0u8; 32], [0u8; 32], [0u8; 32]);
    let mut before = [0u8; 64];
    let mut values = [[0u8; 32]; 24];

    t.set_writer(seed, public)?;
    let reset = t.reset_count()?;
    before[..32].copy_from_slice(&t.pcr_read(pcr)?);
    before[32..].copy_from_slice(&t.pcr_read(phase)?);
    let digests = RegisterPolicy {
        branch_written: &mut written,
        branch_init: &mut init,
        policy: &mut policy,
    };
    zero_or(register_policy(mask, &before, public, digests))?;
    t.nv_define(index, &policy, &[])?;
    let branches = Branches {
        written: &written,
        init: &init,
    };
    t.nv_extend_first(index, mask, &branches, event)?;
    let nv = t.nv_info(index)?;
    let anchor = chain::anchor(nv.name())?;
    let anchor_digest = sha256(crate::text::cstr(&anchor))?;
    t.pcr_extend(pcr, &anchor_digest)?;
    let value = t.nv_read(index)?;
    let ak = t.ak_create()?;
    let ek = t.ek_create(false)?;
    for (i, value) in (0u32..).zip(values.iter_mut()) {
        if quoted & (1 << i) != 0 {
            *value = t.pcr_read(i)?;
        }
    }
    let certify = t.nv_certify(&ak, index, nonce)?;
    let mut signatures = [0u8; 64];
    signatures[..32].copy_from_slice(&sha256(&certify.signature)?);
    let quote_nonce = sha256(&signatures)?;
    let quote = t.quote(&ak, &quote_nonce, quoted)?;
    let after_nonce = sha256(&quote.signature)?;
    let after = t.nv_certify(&ak, index, &after_nonce)?;
    // Flushing lets the keys go; keep their public parts.
    let (ak_public, ek_public) = (ak.public().clone(), ek.public().clone());
    drop(ek);
    drop(ak);
    Ok(Forged {
        reset,
        before,
        anchor,
        anchor_digest,
        value,
        values,
        ak: ak_public,
        ek: ek_public,
        quote,
        certify,
        after,
        nv,
    })
}

/// The attack: a register of the target's own at another handle, bound
/// to PCRs the target can extend and reset at will, written with the init
/// event the operator expects, anchored into one of those PCRs and
/// certified by the genuine attestation key in the real register's place;
/// the attestation document it makes printed.
fn forge(args: &[&CStr]) -> c_int {
    let index_text = args[2].to_bytes();
    let n = index_text
        .iter()
        .take_while(|c| c.is_ascii_hexdigit())
        .count();
    let index = std::str::from_utf8(&index_text[..n])
        .ok()
        .and_then(|d| u32::from_str_radix(d, 16).ok())
        .unwrap_or(0);
    let (pcr, phase) = (atoi(args[3]) as u32, atoi(args[4]) as u32);
    let nonce_hex = args[6].to_bytes();
    let nonce_len = nonce_hex.len() / 2;
    let mut nonce = [0u8; 64];
    let Some(event) = digest(args[5]) else {
        return 2;
    };
    if pcr > 23
        || phase > 23
        || pcr == phase
        || nonce_len == 0
        || nonce_len > nonce.len()
        || decode(nonce_hex, &mut nonce[..nonce_len]).is_err()
    {
        return 2;
    }
    let nonce = &nonce[..nonce_len];
    let (mut seed, mut public) = ([0u8; 32], [0u8; NV_RSA_BYTES]);
    if nv_writer::read(&mut seed, &mut public) != 0 {
        return 1;
    }
    let Some(result) =
        with_tpm(|t| forge_on_tpm(t, &seed, &public, index, (pcr, phase), &event, nonce))
    else {
        return 1;
    };
    let f = match result {
        Ok(f) => f,
        Err(ret) => {
            out(&format!("rc={ret}\n"));
            return 1;
        }
    };
    let quoted = PCR_DEFAULT | (1u32 << pcr) | (1u32 << phase);
    let (mut ts, mut boot_id) = ([0u8; 32], [0u8; 64]);
    timestamp(&mut ts);
    read_boot_id(&mut boot_id);
    let (ts, boot_id) = (
        crate::text::cstr(&ts).to_vec(),
        crate::text::cstr(&boot_id).to_vec(),
    );
    let nv_index = format!("0x{index:08X}");
    let mut buf = vec![0u8; 32 * 1024];
    let mut e = JsonEmit::fixed(&mut buf);
    // SAFETY: the version ID, a static C string.
    let version_id = unsafe { CStr::from_ptr(&raw const shirudo_version_id) };
    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_string(b"kind", b"shirudo-attestation");
    e.kv_string(b"version_id", version_id.to_bytes());
    e.kv_string(b"ts", &ts);
    e.kv_string(b"boot_id", &boot_id);
    e.kv_string(b"nonce", &encode(nonce));
    e.kv_string(b"pcr_bank", b"sha256");
    e.kv_int(b"pcr_mask", quoted.into());
    e.arr_open(b"pcrs");
    for i in (0..24).filter(|i| quoted & (1 << i) != 0) {
        e.obj_open();
        e.kv_int(b"index", i);
        e.kv_string(b"value", &encode(&f.values[i as usize]));
        e.obj_close();
    }
    e.arr_close();
    e.obj_open_key(b"ak");
    e.kv_string(b"public", &encode(&f.ak.area));
    e.kv_string(b"name", &encode(&f.ak.name));
    e.obj_close();
    e.obj_open_key(b"ek");
    e.kv_string(b"type", b"ecc");
    e.kv_string(b"public", &encode(&f.ek.area));
    e.kv_string(b"name", &encode(&f.ek.name));
    e.obj_close();
    e.obj_open_key(b"quote");
    e.kv_string(b"attest", &encode(&f.quote.attest));
    e.kv_string(b"signature", &encode(&f.quote.signature));
    e.obj_close();
    e.obj_open_key(b"register");
    e.kv_string(b"nv_index", nv_index.as_bytes());
    e.kv_int(b"pcr", pcr.into());
    e.kv_string(b"name", &encode(f.nv.name()));
    e.kv_string(b"value", &encode(&f.value));
    e.kv_string(b"attest", &encode(&f.certify.attest));
    e.kv_string(b"signature", &encode(&f.certify.signature));
    e.kv_string(b"after_attest", &encode(&f.after.attest));
    e.kv_string(b"after_signature", &encode(&f.after.signature));
    e.obj_close();
    e.arr_open(b"eventlog");
    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_string(b"ts", &ts);
    e.kv_string(b"nv_index", nv_index.as_bytes());
    e.kv_string(b"alg", b"sha256");
    e.kv_string(b"digest", &encode(&event));
    e.kv_string(b"type", b"init");
    e.kv_string(b"boot_id", &boot_id);
    e.kv_int(b"tpm_reset_count", f.reset.into());
    e.kv_int(b"pcr", pcr.into());
    e.kv_string(b"pcr_before", &encode(&f.before[..32]));
    e.kv_int(b"phase_pcr", phase.into());
    e.kv_string(b"phase_before", &encode(&f.before[32..]));
    e.kv_string(b"bound_in", b"initrd");
    e.kv_string(b"nv_name", &encode(f.nv.name()));
    e.kv_string(b"nv_writer_public", &encode(&public));
    e.kv_string(b"anchor", crate::text::cstr(&f.anchor));
    e.kv_string(b"anchor_digest", &encode(&f.anchor_digest));
    e.kv_string(b"chain", &encode(&f.value));
    e.obj_close();
    e.arr_close();
    e.kv_null(b"credential");
    e.kv_null(b"ek_certificate");
    e.obj_open_key(b"logs");
    e.kv_null(b"firmware");
    e.kv_null(b"systemd");
    e.obj_close();
    e.obj_close();
    if e.err() != 0 {
        return 1;
    }
    out_bytes(e.output());
    out("\n");
    0
}

fn evidence(args: &[&CStr]) -> c_int {
    let nonce_hex = args[2].to_bytes();
    let nonce_len = nonce_hex.len() / 2;
    let mut nonce = [0u8; 64];
    if nonce_len > nonce.len() || decode(nonce_hex, &mut nonce[..nonce_len]).is_err() {
        return 2;
    }
    let mut challenge = None;
    if let Some(path) = args.get(3) {
        match challenge_read(path) {
            Ok(read) => challenge = Some(read),
            Err(_) => {
                err("evidence: bad challenge\n");
                return 2;
            }
        }
    }
    match evidence_config(&nonce[..nonce_len], PCR_DEFAULT, challenge.as_ref(), None) {
        Ok(doc) => {
            out_bytes(&doc);
            out("\n");
            0
        }
        Err(ret) => {
            err(&format!("evidence: {}\n", strerror(-ret)));
            1
        }
    }
}

fn run(args: &[&CStr]) -> c_int {
    if args.len() < 2 {
        return 2;
    }
    match (args[1].to_bytes(), args.len()) {
        (b"writer-create", 2) => writer_create(),
        (b"writer-remove", 2) => {
            // SAFETY: a C string.
            if unsafe { libc::unlink(IDENTITY_PIN.as_ptr()) } != 0 {
                perror("unlink protocol-test identity");
                return 1;
            }
            0
        }
        (b"writer-public", 2) => {
            let (mut seed, mut public) = ([0u8; 32], [0u8; NV_RSA_BYTES]);
            if nv_writer::read(&mut seed, &mut public) != 0 {
                return 1;
            }
            puthex(&public);
            0
        }
        (b"init", 3) => match digest(args[2]) {
            Some(event) => print_init(&event),
            None => 2,
        },
        (b"load", 4) => load(args[2], args[3], TYPE_BPF),
        (b"java-load", 4) => load(args[2], args[3], TYPE_JAVA),
        (b"tree", 6) => tree(args),
        (b"extend-raw", 3) => match digest(args[2]) {
            Some(event) => extend(&event, None),
            None => 2,
        },
        (b"read", _) => match chain::read() {
            Ok(chain) => {
                out("rc=0\n");
                out("value=");
                puthex(&chain);
                0
            }
            Err(ret) => {
                out(&format!("rc={ret}\n"));
                1
            }
        },
        (b"status", _) => status(),
        // A measurement into a PCR, as systemd's boot phases make them.
        (b"pcr-extend", 4) => {
            let Some(d) = digest(args[3]) else {
                return 2;
            };
            match with_tpm(|t| t.pcr_extend(atoi(args[2]) as u32, &d)) {
                Some(result) => {
                    let ret = rc(&result);
                    out(&format!("rc={ret}\n"));
                    c_int::from(ret != 0)
                }
                None => 2,
            }
        }
        (b"pcr", 3) => match with_tpm(|t| t.pcr_read(atoi(args[2]) as u32)) {
            Some(Ok(v)) => {
                puthex(&v);
                0
            }
            _ => 1,
        },
        // The endorsement key of a type, as a target without a certificate
        // presents it.
        (b"ek-public", 3) => ek_public(args[2]),
        (b"recreate", _) => recreate(),
        (b"first-write", 3) => first_write(args[2]),
        (b"forge", 7) => forge(args),
        (b"evidence", 3 | 4) => evidence(args),
        _ => 2,
    }
}
