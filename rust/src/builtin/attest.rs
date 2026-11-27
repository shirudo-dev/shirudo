// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo attest`: on a target, a TPM-signed evidence document; on the
//! operator, verifying one, predicting the register a set of upatches
//! yields, and making a credential challenge for a target's key.

use core::ffi::{CStr, c_int};
use std::ffi::CString;

use crate::errno::{EEXIST, EINVAL, EIO, EKEYREJECTED, ENODATA, ENODEV, ENXIO};
use crate::ffi;
use crate::sys::libc::{fwrite, stdout, strerror};
use crate::sys::tss2::NV_WRITTEN;
use crate::text::{cstr, parse_u64};
use crate::util::attest::{
    self, AttestChallengePolicy, AttestExpect, MadeChallenge, NONCE_MAX, PCR_DEFAULT, Report,
    challenge_read, evidence_config, parse_name_digest, parse_pcr_value, parse_pcrs,
};
use crate::util::chain::{self, MeasuredUpatch, PCR, PCR_MASK as CHAIN_PCR_MASK, PHASE_PCR};
use crate::util::config_measure::{CONFIG_NVPCR_INDEX, pcr_valid};
use crate::util::crypto_openssl::sha256_into;
use crate::util::eventlog::{self, NV_INDEX};
use crate::util::help::{
    Help, HelpItem, HelpSection, is_help, is_list_cmds, print_help, print_subcmd_list,
    resolve_subcommand,
};
use crate::util::hex;
use crate::util::image_runtime;
use crate::util::io;
use crate::util::json::{JsonEmit, MAX_BYTES};
use crate::util::keys::{self, KEYS_MAX};
use crate::util::measured::{set_add, upatch_of};
use crate::util::options::{
    EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OPT_REPEAT, OptParser, OptSpec,
};
use crate::util::seal;
use crate::util::tpm::REGISTER_ATTRS;
use crate::util::tpm_wire::{NAME_LEN, NV_RSA_BYTES, RegisterPolicy, nv_name, register_policy};
use crate::util::upatch::{TYPE_BPF, TYPE_JAVA, Upatch};

const MEMBERS_MAX: usize = 256;
const REPORT_MAX: usize = 8192;
const EVENTS_MAX: usize = 256;
const KEYS_DER_MAX: usize = 1024 * 1024;
/// The register's PCRs, as the options and messages take them.
const CHAIN_PCR: u64 = PCR as u64;
const CHAIN_PHASE_PCR: u64 = PHASE_PCR as u64;

static SUBCMDS: [HelpItem; 3] = [
    HelpItem::new(
        c"verify",
        c"check an evidence document against the expected state",
    ),
    HelpItem::new(
        c"predict",
        c"compute the register value a set of upatches yields",
    ),
    HelpItem::new(
        c"challenge",
        c"make a credential challenge for a target's attestation key",
    ),
];

const EVIDENCE_NONCE: c_int = 0;
const EVIDENCE_PCRS: c_int = 1;
const EVIDENCE_CHALLENGE: c_int = 2;
const EVIDENCE_OUTPUT: c_int = 3;

static EVIDENCE_OPTS: [OptSpec; 4] = [
    OptSpec::new(
        c"--nonce",
        0,
        0,
        Some(c"<hex>"),
        c"freshness value from the verifier (up to 64 bytes)",
    ),
    OptSpec::new(
        c"--pcrs",
        0,
        0,
        Some(c"<list>"),
        c"PCRs to quote, comma separated (default 0-7,9,11-15)",
    ),
    OptSpec::new(
        c"--challenge",
        0,
        0,
        Some(c"<path>"),
        c"a challenge from the verifier to activate while attesting",
    ),
    OptSpec::new(
        c"--output",
        b'o',
        0,
        Some(c"<path>"),
        c"write the evidence there (0600) instead of stdout",
    ),
];

const VERIFY_EVIDENCE: c_int = 0;
const VERIFY_NONCE: c_int = 1;
const VERIFY_AK_NAME: c_int = 2;
const VERIFY_CERT: c_int = 3;
const VERIFY_UPATCH: c_int = 4;
const VERIFY_EXPECT: c_int = 5;
const VERIFY_TREE_ROOT: c_int = 6;
const VERIFY_EXPECT_CHAIN: c_int = 7;
const VERIFY_EXPECT_CONFIG_ROOT: c_int = 8;
const VERIFY_EXPECT_CONFIG_PCR: c_int = 9;
const VERIFY_EXPECT_CONFIG_NVPCR: c_int = 10;
const VERIFY_EXPECT_PCR: c_int = 11;
const VERIFY_ALLOW_RUNTIME_EVENTS: c_int = 12;
const VERIFY_JSON: c_int = 13;
const VERIFY_STRICT_ANCHOR: c_int = 14;
const VERIFY_EXPECT_CREDENTIAL: c_int = 15;
const VERIFY_EK_NAME: c_int = 16;
const VERIFY_EXPECT_BIND_PCR: c_int = 17;
const VERIFY_REQUIRE_INITRD: c_int = 18;

static VERIFY_OPTS: [OptSpec; 19] = [
    OptSpec::new(
        c"--evidence",
        0,
        0,
        Some(c"<path>"),
        c"the document a target produced",
    ),
    OptSpec::new(
        c"--nonce",
        0,
        0,
        Some(c"<hex>"),
        c"the nonce that document was requested with",
    ),
    OptSpec::new(
        c"--ak-name",
        0,
        0,
        Some(c"<hex>"),
        c"the attestation key name pinned at enrollment",
    ),
    OptSpec::new(
        c"--cert",
        0,
        OPT_REPEAT,
        Some(c"<cert.der>"),
        c"a certificate the target enrols (repeatable)",
    ),
    OptSpec::new(
        c"--upatch",
        0,
        OPT_REPEAT,
        Some(c"<file>"),
        c"an installed artifact (repeatable)",
    ),
    OptSpec::new(
        c"--expect",
        0,
        OPT_REPEAT,
        Some(c"[java:]<name>=<hex>"),
        c"an installed upatch by name and payload digest",
    ),
    OptSpec::new(
        c"--tree-root",
        0,
        0,
        Some(c"<hex>"),
        c"the upatch tree projection root at boot",
    ),
    OptSpec::new(
        c"--expect-chain",
        0,
        0,
        Some(c"<hex>"),
        c"the register value after the expected events",
    ),
    OptSpec::new(
        c"--expect-config-root",
        0,
        0,
        Some(c"<hex>"),
        c"approved config image hash",
    ),
    OptSpec::new(
        c"--expect-config-pcr",
        0,
        0,
        Some(c"<n>"),
        c"reserved config PCR number",
    ),
    OptSpec::new(
        c"--expect-config-nvpcr",
        0,
        0,
        Some(c"<name>"),
        c"the config NvPCR TPM name",
    ),
    OptSpec::new(
        c"--expect-pcr",
        0,
        OPT_REPEAT,
        Some(c"<n>=<hex>"),
        c"a PCR value the quote must carry (repeatable)",
    ),
    OptSpec::new(
        c"--allow-runtime-events",
        0,
        0,
        None,
        c"accept loads, unloads and revocations after boot",
    ),
    OptSpec::new(
        c"--json",
        0,
        0,
        None,
        c"print the checks and the verdict as JSON",
    ),
    OptSpec::new(
        c"--strict-anchor",
        0,
        0,
        None,
        c"require the anchoring PCR to hold only the anchor",
    ),
    OptSpec::new(
        c"--expect-credential",
        0,
        0,
        Some(c"<hex>"),
        c"the credential the challenge given to the target carried",
    ),
    OptSpec::new(
        c"--ek-name",
        0,
        0,
        Some(c"<hex>"),
        c"the endorsement key name pinned at enrollment",
    ),
    OptSpec::new(
        c"--expect-bind-pcr",
        0,
        OPT_REPEAT,
        Some(c"<n>=<hex>"),
        c"a PCR value the register was bound under (repeatable)",
    ),
    OptSpec::new(
        c"--require-initrd",
        0,
        0,
        None,
        c"fail unless init bound the register from the initrd",
    ),
];

const CHALLENGE_EVIDENCE: c_int = 0;
const CHALLENGE_AK_NAME: c_int = 1;
const CHALLENGE_EK_CA: c_int = 2;
const CHALLENGE_EK_NAME: c_int = 3;
const CHALLENGE_TRUST_PRESENTED_EK: c_int = 4;
const CHALLENGE_OUTPUT: c_int = 5;

static CHALLENGE_OPTS: [OptSpec; 6] = [
    OptSpec::new(
        c"--evidence",
        0,
        0,
        Some(c"<path>"),
        c"a document the target produced, carrying its keys",
    ),
    OptSpec::new(
        c"--ak-name",
        0,
        0,
        Some(c"<hex>"),
        c"the attestation key name the challenge is for",
    ),
    OptSpec::new(
        c"--ek-ca",
        0,
        0,
        Some(c"<bundle>"),
        c"PEM issuers the endorsement certificate must chain to",
    ),
    OptSpec::new(
        c"--ek-name",
        0,
        0,
        Some(c"<hex>"),
        c"an endorsement key name known out of band",
    ),
    OptSpec::new(
        c"--trust-presented-ek",
        0,
        0,
        None,
        c"accept an endorsement key nothing vouches for",
    ),
    OptSpec::new(
        c"--output",
        b'o',
        0,
        Some(c"<path>"),
        c"write the challenge there (0600)",
    ),
];

const PREDICT_CERT: c_int = 0;
const PREDICT_UPATCH: c_int = 1;
const PREDICT_EXPECT: c_int = 2;
const PREDICT_TREE_ROOT: c_int = 3;
const PREDICT_EVENT: c_int = 4;
const PREDICT_BIND_PCR: c_int = 5;
const PREDICT_JSON: c_int = 6;
const PREDICT_WRITER_PUBLIC: c_int = 7;

static PREDICT_OPTS: [OptSpec; 8] = [
    OptSpec::new(
        c"--cert",
        0,
        OPT_REPEAT,
        Some(c"<cert.der>"),
        c"a certificate the target enrols (repeatable)",
    ),
    OptSpec::new(
        c"--upatch",
        0,
        OPT_REPEAT,
        Some(c"<file>"),
        c"an installed artifact (repeatable)",
    ),
    OptSpec::new(
        c"--expect",
        0,
        OPT_REPEAT,
        Some(c"[java:]<name>=<hex>"),
        c"an installed upatch by name and payload digest",
    ),
    OptSpec::new(
        c"--tree-root",
        0,
        0,
        Some(c"<hex>"),
        c"the upatch tree projection root at boot",
    ),
    OptSpec::new(
        c"--event",
        0,
        OPT_REPEAT,
        Some(c"<kind>:<name>=<hex>"),
        c"a load, unload, java-load, java-unload, tree:<seq> or revoke:<fingerprint> event after boot",
    ),
    OptSpec::new(
        c"--bind-pcr",
        0,
        OPT_REPEAT,
        Some(c"<n>=<hex>"),
        c"PCR 9 and 11 values at binding, for the register name",
    ),
    OptSpec::new(c"--json", 0, 0, None, c"print the values as JSON"),
    OptSpec::new(
        c"--writer-public",
        0,
        0,
        Some(c"<hex>"),
        c"init record's 384-byte RSA modulus (with --bind-pcr)",
    ),
];

static SECTIONS: [HelpSection; 5] = [
    HelpSection::items(c"subcommands:", &SUBCMDS),
    HelpSection::options(c"evidence options (target):", &EVIDENCE_OPTS),
    HelpSection::options(c"verify options (operator):", &VERIFY_OPTS),
    HelpSection::options(c"predict options (operator):", &PREDICT_OPTS),
    HelpSection::options(c"challenge options (operator):", &CHALLENGE_OPTS),
];

static HELP: Help = Help::new(
    c"shirudo attest [--nonce=<hex>] [--pcrs=<list>] [--challenge=<path>] [--output=<path>]\n       \
      shirudo attest verify --evidence=<path> --nonce=<hex> --ak-name=<hex> [options]\n       \
      shirudo attest predict --cert=<cert.der> [options]\n       \
      shirudo attest challenge --evidence=<path> --output=<path> \
      --ek-ca=<bundle>|--ek-name=<hex>|--trust-presented-ek [options]",
    Some(
        c"Without a subcommand: emit a TPM-signed evidence document for this\n\
          target (quote over the PCRs, certification of the measurement register,\n\
          this boot's eventlog, the firmware and systemd measurement logs), activating\n\
          the verifier's challenge when given one.\n\
          verify, predict and challenge run on the operator and touch no TPM.",
    ),
    &SECTIONS,
    None,
);

fn print(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stdout.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stdout) };
}

fn message(parts: &[&[u8]]) -> CString {
    let mut text = parts.concat();

    if let Some(nul) = text.iter().position(|&c| c == 0) {
        text.truncate(nul);
    }
    CString::new(text).unwrap_or_default()
}

fn error(parts: &[&[u8]]) {
    let msg = message(parts);
    crate::log::err(msg.to_bytes());
}

fn warn(parts: &[&[u8]]) {
    let msg = message(parts);
    crate::log::warn(msg.to_bytes());
}

fn strerr(err: c_int) -> &'static [u8] {
    // SAFETY: strerror() gives a C string that outlives the message.
    unsafe { ffi::c_str(strerror(err)) }
}

/// The value of the option or argument `p` last returned, empty for a
/// flag.
fn value<'a>(p: &OptParser<'a>) -> &'a [u8] {
    p.value().map_or(&[], CStr::to_bytes)
}

/// Reports a usage error of `p`'s command, its message formatted.
fn usage(p: &OptParser<'_>, message: impl AsRef<[u8]>) -> c_int {
    p.usage(message.as_ref());
    EXIT_USAGE
}

/// The nonce of `v`: hex of 1 to NONCE_MAX bytes.
fn nonce_of(p: &OptParser<'_>, v: &[u8], nonce: &mut [u8; NONCE_MAX]) -> Result<usize, c_int> {
    match hex::decode_max(v, nonce) {
        Ok(n) if n > 0 => Ok(n),
        _ => Err(usage(
            p,
            format!("--nonce must be hex of up to {NONCE_MAX} bytes"),
        )),
    }
}

/// A key name of `v`, of the option `what`: 2 * NAME_LEN hex digits.
fn name_of(p: &OptParser<'_>, what: &str, v: &[u8]) -> Result<[u8; NAME_LEN], c_int> {
    let mut name = [0u8; NAME_LEN];

    if hex::decode(v, &mut name).is_ok() {
        return Ok(name);
    }
    Err(usage(
        p,
        format!("{what} must be {} hex characters", 2 * NAME_LEN),
    ))
}

fn parse_hex32(what: &[u8], text: &[u8]) -> Result<[u8; 32], c_int> {
    let mut value = [0u8; 32];

    if hex::decode(text, &mut value).is_ok() {
        return Ok(value);
    }
    error(&[b"attest: ", what, b" must be 64 hex characters"]);
    Err(EXIT_USAGE)
}

/// The upatches the init event counts, at most MEMBERS_MAX.
struct Members(Vec<MeasuredUpatch>);

impl Members {
    fn new() -> Self {
        Members(Vec::with_capacity(MEMBERS_MAX))
    }

    /// The members added so far.
    fn members(&mut self) -> &mut [MeasuredUpatch] {
        &mut self.0
    }

    fn add(&mut self, name: &[u8], payload_hex: &[u8], ty: u32) -> Result<(), c_int> {
        set_add(&mut self.0, MEMBERS_MAX, name, payload_hex, ty)
    }

    fn add_file(&mut self, path: &[u8]) -> Result<(), c_int> {
        let e = match Upatch::open(&message(&[path])) {
            Ok(u) => upatch_of(&u),
            Err(ret) => {
                error(&[b"attest: open ", path, b": ", strerr(-ret)]);
                return Err(EXIT_USAGE);
            }
        };
        if let Err(ret) = self.add(cstr(&e.name), cstr(&e.payload_hex), e.ty) {
            let why: &[u8] = if ret == -EEXIST {
                b"a second upatch of that name"
            } else {
                strerr(-ret)
            };
            error(&[b"attest: --upatch ", path, b": ", why]);
            return Err(EXIT_USAGE);
        }
        Ok(())
    }

    fn add_spec(&mut self, spec: &[u8]) -> Result<(), c_int> {
        let (ty, rest) = match spec.strip_prefix(b"java:") {
            Some(rest) => (TYPE_JAVA, rest),
            None => (TYPE_BPF, spec),
        };
        let added = parse_name_digest(rest)
            .and_then(|(name, payload)| self.add(name, &hex::encode(&payload), ty));
        if let Err(ret) = added {
            let why: &[u8] = if ret == -EEXIST {
                b"a second upatch of that name"
            } else if ret == -EINVAL {
                b"not an upatch name and a digest"
            } else {
                strerr(-ret)
            };
            error(&[b"attest: --expect '", spec, b"': ", why]);
            return Err(EXIT_USAGE);
        }
        Ok(())
    }
}

/// The file at `path`, of at most `max` bytes.
fn read(path: &[u8], max: usize) -> Result<Vec<u8>, c_int> {
    io::read(&message(&[path]), max)
}

/// What the init event counts of a certificate: the SHA-256 of its DER.
fn cert_digest(path: &[u8]) -> Result<[u8; 32], c_int> {
    let mut out = [0; 32];
    let ret = match read(path, KEYS_DER_MAX) {
        Ok(der) if der.is_empty() => -ENODATA,
        Ok(der) => sha256_into(&der, &mut out),
        Err(err) => err,
    };

    if ret != 0 {
        error(&[b"attest: --cert ", path, b": ", strerr(-ret)]);
        return Err(EXIT_USAGE);
    }
    Ok(out)
}

/// The certificates of `--cert`: the digest of each, at most KEYS_MAX.
fn cert_add(p: &OptParser<'_>, v: &[u8], certs: &mut Vec<[u8; 32]>) -> Result<(), c_int> {
    if certs.len() >= KEYS_MAX {
        return Err(usage(p, format!("at most {KEYS_MAX} --cert")));
    }
    certs.push(cert_digest(v)?);
    Ok(())
}

/// Folds a `<kind>:<name>=<hex>` event into `register`.
fn apply_event(spec: &[u8], register: &mut [u8; 32]) -> Result<(), c_int> {
    let mut parts = spec.splitn(2, |&c| c == b':');
    let (Some(kind), Some(rest)) = (parts.next(), parts.next()) else {
        return Err(-EINVAL);
    };
    let (name, digest) = parse_name_digest(rest)?;
    let event = if let Some((ty, load)) = eventlog::upatch_kind_parse(kind) {
        let tag = chain::upatch_tag(ty, load).ok_or(-EINVAL)?;
        chain::upatch_event(tag, name, &digest)
    } else {
        match kind {
            b"tree" => {
                let seq = parse_u64(name, i64::MAX as u64)
                    .ok()
                    .and_then(|s| i64::try_from(s).ok())
                    .filter(|&s| s >= 1)
                    .ok_or(-EINVAL)?;
                chain::tree_event(seq, &digest)
            }
            b"revoke" => chain::key_event(c"shirudo-key-revoke", &digest),
            _ => return Err(-EINVAL),
        }
    }
    .map_err(|_| -EIO)?;
    if chain::fold(register, &event) != 0 {
        return Err(-EIO);
    }
    Ok(())
}

/// The values predict prints: `key: value` lines, or members of JSON.
struct Predicted<'a> {
    json: Option<JsonEmit<'a>>,
}

impl Predicted<'_> {
    fn kv(&mut self, key: &[u8], value: &[u8]) {
        match &mut self.json {
            Some(e) => e.kv_string(key, value),
            None => print(&[key, b": ", value, b"\n"].concat()),
        }
    }
}

/// The SHA-256 of the certificates a target enrols, as the init event
/// counts them.
fn anchor_digest(certs: &[[u8; 32]]) -> Option<[u8; 32]> {
    keys::anchor_digest(certs).ok()
}

/// A `<n>=<hex>` PCR value of the option `what` into `values`, once for
/// each PCR, which `mask` marks.
fn pcr_expect(
    p: &OptParser<'_>,
    what: &str,
    v: &[u8],
    values: &mut [[u8; 32]; 24],
    mask: &mut u32,
) -> Result<(), c_int> {
    let (n, value) = parse_pcr_value(v).map_err(|_| EXIT_USAGE)?;

    values[n] = parse_hex32(format!("{what} value").as_bytes(), value)?;
    if *mask & (1 << n) != 0 {
        return Err(usage(p, format!("{what} {n} given twice")));
    }
    *mask |= 1 << n;
    Ok(())
}

fn predict(args: &[&CStr]) -> c_int {
    let mut p = OptParser::new(c"attest predict", &PREDICT_OPTS, Some(&HELP), args, 2);
    let mut writer_public = [0u8; NV_RSA_BYTES];
    let mut tree_root = [0u8; 32];
    let mut certs = Vec::new();
    let mut bind = [[0u8; 32]; 2];
    let mut have_bind = [false; 2];
    let mut have_writer = false;
    let mut events = Vec::new();
    let mut m = Members::new();
    let mut json = false;

    let parsed = (|| loop {
        let opt = p.next();
        let v = value(&p);
        match opt {
            OPT_END => return Ok(()),
            PREDICT_CERT => cert_add(&p, v, &mut certs)?,
            PREDICT_UPATCH => m.add_file(v)?,
            PREDICT_EXPECT => m.add_spec(v)?,
            PREDICT_TREE_ROOT => tree_root = parse_hex32(b"--tree-root", v)?,
            PREDICT_EVENT => {
                if events.len() >= EVENTS_MAX {
                    return Err(usage(&p, format!("at most {EVENTS_MAX} --event")));
                }
                events.push(v);
            }
            PREDICT_WRITER_PUBLIC => {
                if hex::decode(v, &mut writer_public).is_err() {
                    return Err(usage(&p, "invalid RSA-3072 --writer-public"));
                }
                have_writer = true;
            }
            PREDICT_JSON => json = true,
            PREDICT_BIND_PCR => {
                let slot = parse_pcr_value(v).ok().and_then(|(n, value)| {
                    let s = [CHAIN_PCR, CHAIN_PHASE_PCR]
                        .iter()
                        .position(|&pcr| pcr == n as u64)?;
                    bind[s] = parse_hex32(b"--bind-pcr value", value).ok()?;
                    Some((n, s))
                });
                let Some((n, s)) = slot else {
                    return Err(usage(
                        &p,
                        format!("--bind-pcr takes {CHAIN_PCR}=<hex> or {CHAIN_PHASE_PCR}=<hex>"),
                    ));
                };
                if have_bind[s] {
                    return Err(usage(&p, format!("--bind-pcr {n} given twice")));
                }
                have_bind[s] = true;
            }
            OPT_ARG => {
                p.usage_arg(b"unexpected argument ");
                return Err(EXIT_USAGE);
            }
            OPT_DONE => return Err(0),
            _ => return Err(EXIT_USAGE),
        }
    })();
    if let Err(code) = parsed {
        return code;
    }
    if certs.is_empty() {
        return usage(&p, "--cert is required");
    }
    let mut json_buf = vec![0u8; 4096];
    let mut out = Predicted {
        json: json.then(|| JsonEmit::fixed(&mut json_buf)),
    };
    if let Some(e) = &mut out.json {
        e.obj_open();
        e.kv_int(b"schema", 1);
    }
    let (mut set_digest, mut init, mut register) = ([0u8; 32], [0u8; 32], [0u8; 32]);
    let ok = anchor_digest(&certs).is_some_and(|cert_sha| {
        chain::init_event(
            &cert_sha,
            m.members(),
            &tree_root,
            &mut set_digest,
            &mut init,
        ) == 0
    });
    if !ok {
        error(&[b"attest predict: cannot hash the init event"]);
        return EXIT_USAGE;
    }
    out.kv(b"set_digest", &hex::encode(&set_digest));
    out.kv(b"init_event", &hex::encode(&init));
    if chain::fold(&mut register, &init) != 0 {
        error(&[b"attest predict: cannot hash the register at boot"]);
        return EXIT_USAGE;
    }
    out.kv(b"register_at_boot", &hex::encode(&register));
    for ev in &events {
        if apply_event(ev, &mut register).is_err() {
            error(&[b"attest predict: bad --event '", ev, b"'"]);
            return EXIT_USAGE;
        }
    }
    if !events.is_empty() {
        out.kv(b"register_after_events", &hex::encode(&register));
    }
    if have_bind[0] && have_bind[1] {
        let (mut written, mut initial, mut policy) = ([0u8; 32], [0u8; 32], [0u8; 32]);
        let mut name = [0u8; NAME_LEN];
        let mut anchor_digest = [0u8; 32];

        if !have_writer {
            error(&[b"attest predict: --bind-pcr requires --writer-public"]);
            return EXIT_USAGE;
        }
        let ret = register_policy(
            CHAIN_PCR_MASK,
            bind.as_flattened(),
            &writer_public,
            RegisterPolicy {
                branch_written: &mut written,
                branch_init: &mut initial,
                policy: &mut policy,
            },
        );
        if ret != 0 {
            error(&[b"attest predict: cannot compute the signed write policy"]);
            return 1;
        }
        if nv_name(
            NV_INDEX,
            REGISTER_ATTRS | NV_WRITTEN,
            &policy,
            32,
            &mut name,
        ) != 0
        {
            error(&[b"attest predict: cannot compute the register name"]);
            return 1;
        }
        out.kv(b"register_name", &hex::encode(&name));
        let anchor = match chain::anchor(&name) {
            Ok(anchor) => anchor,
            Err(_) => {
                error(&[b"attest predict: the anchor does not fit"]);
                return EXIT_USAGE;
            }
        };
        out.kv(b"anchor", cstr(&anchor));
        if sha256_into(cstr(&anchor), &mut anchor_digest) != 0 {
            error(&[b"attest predict: cannot hash the anchor"]);
            return EXIT_USAGE;
        }
        if chain::fold(&mut bind[0], &anchor_digest) != 0 {
            error(&[
                format!("attest predict: cannot hash PCR {CHAIN_PCR} after the anchor").as_bytes(),
            ]);
            return EXIT_USAGE;
        }
        out.kv(
            format!("pcr{CHAIN_PCR}_after_anchor").as_bytes(),
            &hex::encode(&bind[0]),
        );
    } else if have_bind[0] || have_bind[1] || have_writer {
        error(&[format!(
            "attest predict: --bind-pcr needs both {CHAIN_PCR} and {CHAIN_PHASE_PCR}"
        )
        .as_bytes()]);
        return EXIT_USAGE;
    }
    if let Some(e) = &mut out.json {
        e.obj_close();
        if e.err() != 0 {
            error(&[b"attest predict: json encode failed"]);
            return 1;
        }
        print(&[e.output(), b"\n"].concat());
    }
    0
}

/// The report as JSON: one check or note per line, OK, FAIL or NOTE then
/// the text.
fn report_json(report: &[u8], verdict: &[u8]) -> c_int {
    let mut buf = vec![0u8; 2 * REPORT_MAX];
    let mut e = JsonEmit::fixed(&mut buf);

    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_string(b"verdict", verdict);
    e.arr_open(b"checks");
    for line in report.split(|&c| c == b'\n') {
        let kind: &[u8] = match line.get(..8) {
            Some(b"  OK    ") if line.len() > 8 => b"ok",
            Some(b"  FAIL  ") if line.len() > 8 => b"fail",
            Some(b"  NOTE  ") if line.len() > 8 => b"note",
            _ => continue,
        };
        let text = &line[8..];
        e.obj_open();
        e.kv_string(b"result", kind);
        e.kv_string(b"text", &text[..text.len().min(REPORT_MAX - 1)]);
        e.obj_close();
    }
    e.arr_close();
    e.obj_close();
    if e.err() != 0 {
        error(&[b"attest: json encode failed"]);
        return 1;
    }
    let n = e.written();
    print(&[&buf[..n], b"\n"].concat());
    0
}

fn read_evidence(path: &[u8]) -> Result<Vec<u8>, c_int> {
    let ret = match read(path, MAX_BYTES) {
        Ok(f) if f.is_empty() => Err(-ENODATA),
        r => r,
    };

    ret.map_err(|err| {
        error(&[b"attest: evidence ", path, b": ", strerr(-err)]);
        EXIT_USAGE
    })
}

fn verify(args: &[&CStr]) -> c_int {
    // On the heap, so that the credential it may hold is scrubbed when it
    // goes.
    let mut x: Box<AttestExpect> = Box::default();

    verify_against(args, &mut x).unwrap_or_else(|code| code)
}

/// attest verify with the expectation `x` its options fill.
fn verify_against(args: &[&CStr], x: &mut AttestExpect) -> Result<c_int, c_int> {
    let mut p = OptParser::new(c"attest verify", &VERIFY_OPTS, Some(&HELP), args, 2);
    let mut nonce = [0u8; NONCE_MAX];
    let mut nonce_len = 0;
    let mut certs = Vec::new();
    let mut tree_root = [0u8; 32];
    let mut evidence_path = None;
    let mut m = Members::new();
    let (mut json, mut have_tree_root) = (false, false);

    loop {
        let opt = p.next();
        let v = value(&p);
        match opt {
            OPT_END => break,
            VERIFY_EVIDENCE => evidence_path = Some(v),
            VERIFY_NONCE => nonce_len = nonce_of(&p, v, &mut nonce)?,
            VERIFY_AK_NAME => x.ak_name = Some(name_of(&p, "--ak-name", v)?),
            VERIFY_CERT => cert_add(&p, v, &mut certs)?,
            VERIFY_UPATCH => m.add_file(v)?,
            VERIFY_EXPECT => m.add_spec(v)?,
            VERIFY_TREE_ROOT => {
                tree_root = parse_hex32(b"--tree-root", v)?;
                have_tree_root = true;
            }
            VERIFY_EXPECT_CONFIG_ROOT => {
                x.config_root = Some(parse_hex32(b"--expect-config-root", v)?);
            }
            VERIFY_EXPECT_CONFIG_PCR => {
                let pcr = p.number(0, 15).map_err(|_| EXIT_USAGE)? as u32;
                if pcr_valid(pcr) != 0 {
                    return Err(usage(&p, "--expect-config-pcr cannot be 9 or 11"));
                }
                x.config_pcr = Some(pcr);
            }
            VERIFY_EXPECT_CONFIG_NVPCR => {
                x.config_nvpcr_name = Some(name_of(&p, "--expect-config-nvpcr", v)?);
                x.config_pcr = Some(CONFIG_NVPCR_INDEX);
            }
            VERIFY_EXPECT_CHAIN => x.chain = Some(parse_hex32(b"--expect-chain", v)?),
            VERIFY_EXPECT_PCR => {
                pcr_expect(&p, "--expect-pcr", v, &mut x.pcrs, &mut x.pcr_expect_mask)?;
            }
            VERIFY_JSON => json = true,
            VERIFY_ALLOW_RUNTIME_EVENTS => x.allow_runtime_events = true,
            VERIFY_STRICT_ANCHOR => x.strict_anchor = true,
            VERIFY_EXPECT_CREDENTIAL => {
                x.credential = Some(parse_hex32(b"--expect-credential", v)?);
            }
            VERIFY_EK_NAME => x.ek_name = Some(name_of(&p, "--ek-name", v)?),
            VERIFY_EXPECT_BIND_PCR => {
                pcr_expect(
                    &p,
                    "--expect-bind-pcr",
                    v,
                    &mut x.bind_values,
                    &mut x.bind_expect_mask,
                )?;
            }
            VERIFY_REQUIRE_INITRD => x.require_initrd = true,
            OPT_ARG => {
                p.usage_arg(b"unexpected argument ");
                return Err(EXIT_USAGE);
            }
            OPT_DONE => return Ok(0),
            _ => return Err(EXIT_USAGE),
        }
    }
    if p.given(VERIFY_EXPECT_CONFIG_PCR) && p.given(VERIFY_EXPECT_CONFIG_NVPCR) {
        return Err(usage(
            &p,
            "--expect-config-pcr and --expect-config-nvpcr exclude each other",
        ));
    }
    if x.config_root.is_some() && x.config_pcr.is_none() {
        return Err(usage(
            &p,
            "--expect-config-root requires --expect-config-pcr or --expect-config-nvpcr",
        ));
    }
    let Some(evidence_path) = evidence_path.filter(|_| nonce_len > 0) else {
        return Err(usage(&p, "--evidence and --nonce are required"));
    };
    if certs.is_empty() && (!m.0.is_empty() || have_tree_root) {
        return Err(usage(
            &p,
            "--upatch, --expect and --tree-root describe the init event and need --cert",
        ));
    }
    // The credential proves that the pinned attestation key sits beside
    // the endorsement key; recovered on the target, its value says
    // nothing about which key signed the evidence.
    if x.credential.is_some() && x.ak_name.is_none() {
        error(&[
            b"attest verify: --expect-credential needs the key the challenge was made for; give --ak-name",
        ]);
        return Err(EXIT_USAGE);
    }
    if x.ak_name.is_none() {
        warn(&[b"attest verify: no --ak-name; the signer is not pinned"]);
    }
    x.nonce = nonce[..nonce_len].to_vec();
    if !certs.is_empty() {
        let (mut set_digest, mut init) = ([0u8; 32], [0u8; 32]);
        let ok = anchor_digest(&certs).is_some_and(|cert_sha| {
            chain::init_event(
                &cert_sha,
                m.members(),
                &tree_root,
                &mut set_digest,
                &mut init,
            ) == 0
        });
        if !ok {
            error(&[b"attest verify: cannot hash the init event"]);
            return Err(EXIT_USAGE);
        }
        x.init_event = Some(init);
    }
    let evidence = read_evidence(evidence_path)?;
    let mut report = Report::new(REPORT_MAX);
    let err = match attest::verify(&evidence, x, &mut report) {
        Ok(()) => 0,
        Err(err) => err,
    };
    let report = report.text();
    if err == -EINVAL {
        if !json {
            print(report);
        }
        error(&[
            b"attest verify: ",
            evidence_path,
            b" is not a shirudo evidence document",
        ]);
        return Err(EXIT_USAGE);
    }
    let verdict: &[u8] = if err != 0 { b"fail" } else { b"ok" };
    if json {
        let ret = report_json(report, verdict);
        return Ok(if ret == 0 && err != 0 { 1 } else { ret });
    }
    print(report);
    print(&[b"verdict: ", verdict, b"\n"].concat());
    Ok(c_int::from(err != 0))
}

fn challenge(args: &[&CStr]) -> c_int {
    let mut p = OptParser::new(c"attest challenge", &CHALLENGE_OPTS, Some(&HELP), args, 2);
    let mut pol = AttestChallengePolicy::default();
    let (mut evidence_path, mut out_path) = (None, None);

    loop {
        let opt = p.next();
        let v = value(&p);
        match opt {
            OPT_END => break,
            CHALLENGE_EVIDENCE => evidence_path = Some(v),
            CHALLENGE_EK_CA => pol.ek_ca = p.value(),
            CHALLENGE_AK_NAME => match name_of(&p, "--ak-name", v) {
                Ok(name) => pol.ak_name = Some(name),
                Err(code) => return code,
            },
            CHALLENGE_EK_NAME => match name_of(&p, "--ek-name", v) {
                Ok(name) => pol.ek_name = Some(name),
                Err(code) => return code,
            },
            CHALLENGE_TRUST_PRESENTED_EK => pol.trust_presented = true,
            CHALLENGE_OUTPUT => out_path = Some(v),
            OPT_ARG => {
                p.usage_arg(b"unexpected argument ");
                return EXIT_USAGE;
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    let (Some(evidence_path), Some(out_path)) = (evidence_path, out_path) else {
        return usage(&p, "--evidence and --output are required");
    };
    let evidence = match read_evidence(evidence_path) {
        Ok(evidence) => evidence,
        Err(code) => return code,
    };
    let mut report = Report::new(REPORT_MAX);
    let made = attest::challenge_make(&evidence, &pol, &mut report);
    print(report.text());
    match made {
        Ok(made) => challenge_write(out_path, &made),
        Err(err) if err == -EINVAL => {
            error(&[
                b"attest challenge: ",
                evidence_path,
                b" carries no endorsement key",
            ]);
            EXIT_USAGE
        }
        Err(_) => {
            print(b"verdict: fail\n");
            1
        }
    }
}

/// The challenge made into the file at `out_path`, and the credential it
/// carries printed.
fn challenge_write(out_path: &[u8], made: &MadeChallenge) -> c_int {
    let out = match seal::Output::create(out_path, 0o600) {
        Ok(out) => out,
        Err(e) => {
            error(&[b"attest challenge: open ", out_path, b": ", strerr(-e)]);
            return 1;
        }
    };
    if let Err(e) = out.commit(&made.document) {
        error(&[b"attest challenge: write ", out_path, b": ", strerr(-e)]);
        return 1;
    }
    print(
        &[
            b"challenge: ",
            out_path,
            b"\ncredential: ",
            &hex::encode(&made.credential[..]),
            b"\n",
        ]
        .concat(),
    );
    0
}

fn evidence(args: &[&CStr]) -> c_int {
    let mut p = OptParser::new(c"attest", &EVIDENCE_OPTS, Some(&HELP), args, 1);
    let mut nonce = [0u8; NONCE_MAX];
    let mut nonce_len = 0;
    let mut mask = PCR_DEFAULT;
    let (mut out_path, mut challenge_path) = (None, None);

    loop {
        let opt = p.next();
        let v = value(&p);
        match opt {
            OPT_END => break,
            EVIDENCE_CHALLENGE => challenge_path = Some(v),
            EVIDENCE_NONCE => match nonce_of(&p, v, &mut nonce) {
                Ok(n) => nonce_len = n,
                Err(code) => return code,
            },
            EVIDENCE_PCRS => match parse_pcrs(v) {
                Ok(pcrs) => mask = pcrs,
                Err(_) => return usage(&p, "--pcrs takes a comma separated list of 0..23"),
            },
            EVIDENCE_OUTPUT => out_path = Some(v),
            OPT_ARG => {
                p.usage_arg(b"unexpected argument ");
                return EXIT_USAGE;
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    if nonce_len == 0 {
        warn(&[b"attest: no --nonce; the evidence proves no freshness"]);
    }
    let mut challenge = None;
    if let Some(path) = challenge_path {
        match challenge_read(&message(&[path])) {
            Ok(read) => challenge = Some(read),
            Err(_) => {
                error(&[b"attest: ", path, b" is not a shirudo credential challenge"]);
                return 2;
            }
        }
    }
    // SAFETY: the journal of the runtime's state, this thread's, which
    // nothing else touches while attest reads it, or none.
    let update = unsafe { image_runtime::update_context().as_ref() };
    let body = match evidence_config(&nonce[..nonce_len], mask, challenge.as_ref(), update) {
        Ok(body) => body,
        Err(r) if r == -ENXIO => {
            error(&[b"attest: no TPM answered (tpm_error)"]);
            return 1;
        }
        Err(r) if r == -ENODEV => {
            error(&[format!(
                "attest: register 0x{NV_INDEX:08X} is not bound this boot (tpm_error); \
                 run shirudo init first"
            )
            .as_bytes()]);
            return 1;
        }
        Err(r) if r == -EKEYREJECTED => {
            error(&[b"attest: the TPM refused the challenge; the attestation key or the endorsement key is not this TPM's"]);
            return 1;
        }
        Err(r) => {
            error(&[b"attest: evidence failed: ", strerr(-r)]);
            return 1;
        }
    };
    let ret = match out_path {
        Some(path) => match seal::Output::create(path, 0o600) {
            Ok(out) => out.commit(&body).err().map_or(0, |e| {
                error(&[b"attest: write ", path, b": ", strerr(-e)]);
                e
            }),
            Err(e) => {
                error(&[b"attest: open ", path, b": ", strerr(-e)]);
                e
            }
        },
        None => {
            // SAFETY: the bytes, to the C library's stdout.
            let n = unsafe { fwrite(body.as_ptr().cast(), 1, body.len(), stdout) };
            // SAFETY: a newline, to the C library's stdout.
            let nl = n == body.len()
                && unsafe { crate::sys::libc::fputc(c_int::from(b'\n'), stdout) } >= 0;
            if nl { 0 } else { -EIO }
        }
    };
    c_int::from(ret != 0)
}

/// `shirudo attest` on `args`, its name first.
pub(crate) fn cmd_attest(args: &[&CStr]) -> c_int {
    if let Some(word) = args.get(1) {
        let arg = word.to_bytes();

        if is_help(Some(arg)) {
            print_help(&HELP);
            return 0;
        }
        if is_list_cmds(Some(arg)) {
            print_subcmd_list(&SUBCMDS);
            return 0;
        }
        if arg.first() != Some(&b'-') {
            let Some(sub) = resolve_subcommand(c"attest", word, &SUBCMDS) else {
                return EXIT_USAGE;
            };
            return match sub.to_bytes() {
                b"verify" => verify(args),
                b"challenge" => challenge(args),
                _ => predict(args),
            };
        }
    }
    evidence(args)
}

#[cfg(test)]
mod tests;
