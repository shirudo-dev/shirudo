// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Attestation: the evidence a target emits, the
//! challenge an operator makes for its keys, and the verification the
//! operator runs against the evidence.

use core::ffi::{CStr, c_char, c_int};
use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;

use crate::errno::{
    E2BIG, EAGAIN, EBADMSG, EINVAL, EIO, EKEYREJECTED, ENODEV, ENOENT, ENOMEM, ENOSPC, ENXIO,
    EUCLEAN, text,
};
use crate::ffi;
use crate::sys::libc::getrandom;
use crate::sys::tss2::NV_WRITTEN;
use crate::sys::version::shirudo_version_id;
use crate::text::{cstr, digits, parse_u64, parse_x64};
use crate::util::bpm_tree::digest_bytes;
use crate::util::chain::{
    self, ANCHOR_MAX, PCR as CHAIN_PCR, PCR_MASK as CHAIN_PCR_MASK, PHASE_PCR as CHAIN_PHASE_PCR,
    memneq_explicit,
};
use crate::util::config_attest::{self, Evidence, Quote};
use crate::util::config_measure::nvpcr;
use crate::util::config_update::ConfigUpdate;
use crate::util::crypto_openssl::{
    Cert, CertPubkey, base64, base64_decode, cert_pubkey, cert_read_der, cert_verify_chain,
    ecdh_p256_ephemeral, rsa_oaep_encrypt, sha256, sha256_into,
};
use crate::util::eventlog::{self, NV_INDEX};
use crate::util::hex::{decode, decode_max, encode};
use crate::util::io;
use crate::util::json::{JsonEmit, JsonField, MAX_BYTES as JSON_MAX_BYTES, parse_schema};
use crate::util::tpm::{
    ATTEST_MAX, Attestation, EK_ATTRS, Key, KeyPublic, NvInfo, PUBLIC_MAX, REGISTER_ATTRS,
    SIGNATURE_MAX, Tpm,
};
use crate::util::tpm_wire::{
    ALG_ECC, ALG_RSA, CREDENTIAL_LEN, EK_POLICY, ID_OBJECT_LEN, NAME_LEN, NV_RSA_BYTES,
    RegisterPolicy, ST_ATTEST_NV, ST_ATTEST_QUOTE, TpmAttest, TpmEccPublic, TpmPublic,
    attest_parse, attest_signer, attest_verify as signature_verify, credential_protect,
    ecc_public_parse, kdfe, nv_name, object_name, public_parse, register_policy,
};
use crate::util::upatch::{self, NAME_MAX as UPATCH_NAME_MAX};

const FIRMWARE_LOG_PATH: &CStr = c"/sys/kernel/security/tpm0/binary_bios_measurements";
const SYSTEMD_LOG_PATH: &CStr = c"/run/log/systemd/tpm2-measure.log";
const LOG_MAX_BYTES: usize = 2 * 1024 * 1024;
const EK_CERT_MAX: usize = 4096;
const QUOTE_ATTEMPTS: u32 = 3;
const RECORDS_MAX: usize = 4096;
const EK_CERT_B64_MAX: usize = 4 * EK_CERT_MAX.div_ceil(3) + 1;
/// restricted | sign | fixedTPM | fixedParent | sensitiveDataOrigin
const AK_ATTRS_REQUIRED: u32 = 0x0005_0032;
/// The longest nonce.
pub(crate) const NONCE_MAX: usize = 64;
/// The PCRs a quote covers when
/// the operator names none.
pub(crate) const PCR_DEFAULT: u32 = 0x0000_FAFF;
/// The longest challenge.
const CHALLENGE_MAX: usize = 16 * 1024;
/// The longest challenge made.
const CHALLENGE_DOC_MAX: usize = 4096;
/// The longest secret of a challenge, an RSA-2048 key's OAEP.
const SECRET_MAX: usize = 256;
/// The label of a credential's seed, which the TPM takes with its NUL.
const IDENTITY: &CStr = c"IDENTITY";

/// A credential challenge: the blob and the encrypted seed
/// TPM2_ActivateCredential takes, for the attestation key of a name under
/// the endorsement key of a type.
pub(crate) struct AttestChallenge {
    ek_rsa: bool,
    ak_name: [u8; NAME_LEN],
    blob: [u8; ID_OBJECT_LEN],
    secret: Vec<u8>,
}

/// What the operator vouches for when making a challenge.
#[derive(Default)]
pub(crate) struct AttestChallengePolicy<'a> {
    /// The issuer bundle the EK certificate must chain to.
    pub(crate) ek_ca: Option<&'a CStr>,
    pub(crate) ak_name: Option<[u8; NAME_LEN]>,
    pub(crate) ek_name: Option<[u8; NAME_LEN]>,
    /// Accept an unvouched endorsement key.
    pub(crate) trust_presented: bool,
}

/// What the operator expects the evidence to show.
#[derive(Default)]
pub(crate) struct AttestExpect {
    /// The nonce the evidence was requested with.
    pub(crate) nonce: Vec<u8>,
    pub(crate) ak_name: Option<[u8; NAME_LEN]>,
    /// The register's value after the expected events.
    pub(crate) chain: Option<[u8; 32]>,
    /// The init event of the certificates, set and tree root known.
    pub(crate) init_event: Option<[u8; 32]>,
    pub(crate) allow_runtime_events: bool,
    pub(crate) strict_anchor: bool,
    /// The PCRs whose values the quote must carry, and the values.
    pub(crate) pcr_expect_mask: u32,
    pub(crate) pcrs: [[u8; 32]; 24],
    pub(crate) credential: Option<[u8; CREDENTIAL_LEN]>,
    pub(crate) ek_name: Option<[u8; NAME_LEN]>,
    /// The binding must be the initrd's.
    pub(crate) require_initrd: bool,
    /// The PCRs whose values at binding time are pinned, and the values.
    pub(crate) bind_expect_mask: u32,
    pub(crate) bind_values: [[u8; 32]; 24],
    pub(crate) config_root: Option<[u8; 32]>,
    pub(crate) config_pcr: Option<u32>,
    pub(crate) config_nvpcr_name: Option<[u8; NAME_LEN]>,
}

/// An eventlog record as the report names it.
struct Record {
    ty: Vec<u8>,
    label: Vec<u8>,
    digest: [u8; 32],
    /// The digest follows from the record's fields.
    derived: bool,
}

/// The boot's last init record.
struct InitRecord {
    writer_public: [u8; NV_RSA_BYTES],
    present: bool,
    initrd: bool,
    reset_count: Option<u32>,
    pcr: u32,
    phase_pcr: u32,
    digest: [u8; 32],
    pcr_before: [u8; 32],
    phase_before: [u8; 32],
    name: [u8; NAME_LEN],
    anchor_digest: [u8; 32],
}

impl InitRecord {
    const fn new() -> Self {
        InitRecord {
            writer_public: [0; NV_RSA_BYTES],
            present: false,
            initrd: false,
            reset_count: None,
            pcr: 0,
            phase_pcr: 0,
            digest: [0; 32],
            pcr_before: [0; 32],
            phase_before: [0; 32],
            name: [0; NAME_LEN],
            anchor_digest: [0; 32],
        }
    }
}

/// What the evidence's schema reads into: the text of each value, in
/// room that bounds it, and what its arrays of PCRs and records give.
struct Parse {
    writer_public_hex: [u8; 2 * NV_RSA_BYTES + 1],
    nonce_hex: [u8; 2 * NONCE_MAX + 1],
    pcr_mask: i64,
    ak_public_hex: [u8; 2 * PUBLIC_MAX + 1],
    ak_name_hex: [u8; 2 * NAME_LEN + 1],
    quote_attest_hex: [u8; 2 * ATTEST_MAX + 1],
    quote_sig_hex: [u8; 2 * SIGNATURE_MAX + 1],
    ek_type: [u8; 8],
    ek_public_hex: [u8; 2 * PUBLIC_MAX + 1],
    ek_name_hex: [u8; 2 * NAME_LEN + 1],
    cred_hex: [u8; 2 * CREDENTIAL_LEN + 1],
    reg_index: [u8; 16],
    reg_pcr: i64,
    reg_name_hex: [u8; 2 * NAME_LEN + 1],
    reg_value_hex: [u8; 65],
    reg_attest_hex: [u8; 2 * ATTEST_MAX + 1],
    reg_sig_hex: [u8; 2 * SIGNATURE_MAX + 1],
    reg_after_attest_hex: [u8; 2 * ATTEST_MAX + 1],
    reg_after_sig_hex: [u8; 2 * SIGNATURE_MAX + 1],
    nvpcr_name_hex: [u8; 2 * NAME_LEN + 1],
    nvpcr_attest_hex: [u8; 2 * ATTEST_MAX + 1],
    nvpcr_sig_hex: [u8; 2 * SIGNATURE_MAX + 1],
    nvpcr_after_attest_hex: [u8; 2 * ATTEST_MAX + 1],
    nvpcr_after_sig_hex: [u8; 2 * SIGNATURE_MAX + 1],
    pcr_index: i64,
    pcr_value_hex: [u8; 65],
    pcr_have: u32,
    pcrs: [[u8; 32]; 24],
    ty: [u8; 16],
    digest_hex: [u8; 65],
    pcr_before_hex: [u8; 65],
    phase_before_hex: [u8; 65],
    bound_in: [u8; 8],
    nv_name_hex: [u8; 2 * NAME_LEN + 1],
    anchor: [u8; ANCHOR_MAX],
    anchor_digest_hex: [u8; 65],
    chain_hex: [u8; 65],
    rec_pcr: i64,
    rec_phase_pcr: i64,
    rec_reset: i64,
    upatch_name: [u8; UPATCH_NAME_MAX + 1],
    upatch_payload_hex: [u8; 65],
    tree_id: [u8; UPATCH_NAME_MAX + 1],
    tree_op: [u8; 16],
    /// `sizeof("sha256:") + 64`.
    tree_digest_hex: [u8; 8 + 64],
    tree_seq: i64,
    key_fingerprint: [u8; 65],
    key_sha_hex: [u8; 65],
    recs: Vec<Record>,
    /// Init records this boot.
    inits: u32,
    /// Those for the last reset count.
    inits_epoch: u32,
    init: InitRecord,
}

impl Parse {
    /// Nothing parsed yet, a record's numbers not given.
    const fn new() -> Self {
        Parse {
            writer_public_hex: [0; 2 * NV_RSA_BYTES + 1],
            nonce_hex: [0; 2 * NONCE_MAX + 1],
            pcr_mask: 0,
            ak_public_hex: [0; 2 * PUBLIC_MAX + 1],
            ak_name_hex: [0; 2 * NAME_LEN + 1],
            quote_attest_hex: [0; 2 * ATTEST_MAX + 1],
            quote_sig_hex: [0; 2 * SIGNATURE_MAX + 1],
            ek_type: [0; 8],
            ek_public_hex: [0; 2 * PUBLIC_MAX + 1],
            ek_name_hex: [0; 2 * NAME_LEN + 1],
            cred_hex: [0; 2 * CREDENTIAL_LEN + 1],
            reg_index: [0; 16],
            reg_pcr: 0,
            reg_name_hex: [0; 2 * NAME_LEN + 1],
            reg_value_hex: [0; 65],
            reg_attest_hex: [0; 2 * ATTEST_MAX + 1],
            reg_sig_hex: [0; 2 * SIGNATURE_MAX + 1],
            reg_after_attest_hex: [0; 2 * ATTEST_MAX + 1],
            reg_after_sig_hex: [0; 2 * SIGNATURE_MAX + 1],
            nvpcr_name_hex: [0; 2 * NAME_LEN + 1],
            nvpcr_attest_hex: [0; 2 * ATTEST_MAX + 1],
            nvpcr_sig_hex: [0; 2 * SIGNATURE_MAX + 1],
            nvpcr_after_attest_hex: [0; 2 * ATTEST_MAX + 1],
            nvpcr_after_sig_hex: [0; 2 * SIGNATURE_MAX + 1],
            pcr_index: 0,
            pcr_value_hex: [0; 65],
            pcr_have: 0,
            pcrs: [[0; 32]; 24],
            ty: [0; 16],
            digest_hex: [0; 65],
            pcr_before_hex: [0; 65],
            phase_before_hex: [0; 65],
            bound_in: [0; 8],
            nv_name_hex: [0; 2 * NAME_LEN + 1],
            anchor: [0; ANCHOR_MAX],
            anchor_digest_hex: [0; 65],
            chain_hex: [0; 65],
            rec_pcr: -1,
            rec_phase_pcr: -1,
            rec_reset: -1,
            upatch_name: [0; UPATCH_NAME_MAX + 1],
            upatch_payload_hex: [0; 65],
            tree_id: [0; UPATCH_NAME_MAX + 1],
            tree_op: [0; 16],
            tree_digest_hex: [0; 8 + 64],
            tree_seq: 0,
            key_fingerprint: [0; 65],
            key_sha_hex: [0; 65],
            recs: Vec::new(),
            inits: 0,
            inits_epoch: 0,
            init: InitRecord::new(),
        }
    }
}

/// The log at `path`, read to its end and of 1 to LOG_MAX_BYTES bytes,
/// in base64; none where it cannot be. securityfs reports a size of 0
/// for the firmware event log, so the log is read to its end rather than
/// for the size a stat gives.
fn read_log_base64(path: &CStr) -> Option<Vec<u8>> {
    let file = File::open(OsStr::from_bytes(path.to_bytes())).ok()?;
    let mut log = Vec::new();

    file.take(LOG_MAX_BYTES as u64 + 1)
        .read_to_end(&mut log)
        .ok()?;
    if log.is_empty() || log.len() > LOG_MAX_BYTES {
        return None;
    }
    base64(&log).ok()
}

/// `data` as hex under `key`; more than an attestation's worth stops the
/// emitter with -E2BIG.
fn emit_hex(e: &mut JsonEmit, key: &[u8], data: &[u8]) {
    if data.len() > ATTEST_MAX {
        e.set_err(-E2BIG);
        return;
    }
    e.kv_string(key, &encode(data));
}

/// The digest a quote over `mask` carries: SHA-256 of the PCR values
/// it selects, in index order. None where the hash fails, which the
/// target and the operator alike take as a digest that does not match.
fn pcr_values_digest(mask: u32, values: &[[u8; 32]; 24]) -> Option<[u8; 32]> {
    let selected: Vec<u8> = (0..values.len())
        .filter(|&i| mask & (1 << i) != 0)
        .flat_map(|i| values[i])
        .collect();

    sha256(&selected).ok()
}

/// What the quote `quote` holds, as far as it parses: none where it
/// does not.
fn quoted(quote: &Attestation) -> Option<TpmAttest> {
    let mut a = TpmAttest::zeroed();

    (attest_parse(&quote.attest, &mut a) == 0).then_some(a)
}

/// Whether the quote covers the PCR values read beside it, which alone
/// makes it acceptable.
fn quote_covers(quote: &Attestation, mask: u32, values: &[[u8; 32]; 24]) -> bool {
    let Some(a) = quoted(quote).filter(|a| a.ty == ST_ATTEST_QUOTE && a.pcr_mask == mask) else {
        return false;
    };
    pcr_values_digest(mask, values).is_some_and(|d| !memneq_explicit(&d, &a.pcr_digest))
}

/// The quote commits to the opening NV certifications, including their
/// TPM signatures, even when the TPM clock has not advanced.
fn snapshot_quote_nonce(register: &[u8], config: Option<&[u8]>) -> Result<[u8; 32], c_int> {
    let mut hashes = [0u8; 64];
    let mut digest = [0u8; 32];
    let ret = sha256_into(register, &mut digest);
    if ret != 0 {
        return Err(ret);
    }
    hashes[..32].copy_from_slice(&digest);
    if let Some(config) = config.filter(|signature| !signature.is_empty()) {
        let ret = sha256_into(config, &mut digest);
        if ret != 0 {
            return Err(ret);
        }
        hashes[32..].copy_from_slice(&digest);
    }
    sha256(&hashes)
}

fn same_nv(a: &TpmAttest, a_bytes: &[u8], b: &TpmAttest, b_bytes: &[u8]) -> bool {
    a.ty == ST_ATTEST_NV
        && b.ty == ST_ATTEST_NV
        && a.reset_count == b.reset_count
        && a.restart_count == b.restart_count
        && a.firmware_version == b.firmware_version
        && a.offset == 0
        && b.offset == 0
        && a.index_name_len == NAME_LEN
        && b.index_name_len == NAME_LEN
        && a.index_name == b.index_name
        && a.nv_len == 32
        && b.nv_len == 32
        && a.nv_data_in(a_bytes)
            .is_some_and(|value| b.nv_data_in(b_bytes) == Some(value))
}

fn certify_after_quote(
    tpm: &Tpm,
    ak: &Key<'_>,
    index: u32,
    nonce: &[u8; 32],
    before: &Attestation,
) -> Result<Attestation, c_int> {
    let after = tpm.nv_certify(ak, index, nonce)?;
    let a = quoted(before).ok_or(-EBADMSG)?;
    let b = quoted(&after).ok_or(-EBADMSG)?;
    if !same_nv(&a, &before.attest, &b, &after.attest) {
        return Err(-EAGAIN);
    }
    Ok(after)
}

/// What the TPM gave the evidence: the PCRs quoted and their values, the
/// register's value and name, the quote, the register's opening and
/// closing certifications, the keys' public parts, and the credential
/// a challenge carried.
struct Measured {
    pcr_mask: u32,
    values: [[u8; 32]; 24],
    register: [u8; 32],
    nv: NvInfo,
    quote: Attestation,
    certify: Attestation,
    register_after: Attestation,
    config_nvpcr: Option<(NvInfo, Attestation, Attestation)>,
    ak: KeyPublic,
    ek: KeyPublic,
    ek_rsa: bool,
    ek_certificate: Option<Vec<u8>>,
    /// On the heap, so that it is scrubbed when it goes.
    credential: Vec<u8>,
}

/// The PCRs of `mask` read and quoted with the nonce, again while they
/// change under the quote: -EAGAIN when they kept changing.
fn quote_pcrs(
    tpm: &Tpm,
    ak: &Key<'_>,
    nonce: &[u8],
    mask: u32,
    values: &mut [[u8; 32]; 24],
) -> Result<Attestation, c_int> {
    for _ in 0..QUOTE_ATTEMPTS {
        for (i, value) in (0u32..).zip(values.iter_mut()) {
            if mask & (1 << i) == 0 {
                continue;
            }
            *value = tpm.pcr_read(i)?;
        }
        let quote = tpm.quote(ak, nonce, mask)?;
        if quote_covers(&quote, mask, values) {
            return Ok(quote);
        }
    }
    crate::log::err(b"attest: PCRs kept changing while quoting");
    Err(-EAGAIN)
}

/// The TPM's EK certificate in base64, and whether its key is RSA; none
/// where it has no certificate or it does not encode.
fn ek_certificate_base64(tpm: &Tpm) -> (Option<Vec<u8>>, bool) {
    match tpm.ek_certificate(EK_CERT_MAX) {
        Ok((der, rsa)) => (base64(&der).ok(), rsa),
        Err(_) => (None, false),
    }
}

/// The credential the challenge carries, activated with the keys:
/// -EKEYREJECTED for a challenge of another attestation key, or the
/// TPM's refusal.
fn activate(tpm: &Tpm, ak: &Key<'_>, ek: &Key<'_>, c: &AttestChallenge) -> Result<Vec<u8>, c_int> {
    if c.ak_name != ak.public().name {
        crate::log::err(b"attest: the challenge was made for another attestation key");
        return Err(-EKEYREJECTED);
    }
    tpm.activate_credential(ak, ek, &c.blob, &c.secret)
        .and_then(|credential| {
            if credential.len() > CREDENTIAL_LEN {
                return Err(-E2BIG);
            }
            Ok(credential)
        })
        .inspect_err(|_| {
            crate::log::err(b"attest: the TPM refused the challenge: not made for this attestation key under this endorsement key");
        })
}

/// The quoted PCR agrees with the active config. A TPM restart alone
/// does not end a PCR history; only a reset does.
fn quote_matches_config(
    config: &Evidence,
    quote: &TpmAttest,
    values: &[[u8; 32]; 24],
    in_nvpcr: bool,
) -> bool {
    quote.reset_count == config.reset_count
        && (in_nvpcr
            || usize::try_from(config.pcr)
                .ok()
                .and_then(|pcr| values.get(pcr))
                == Some(&config.value))
}

/// Collection requires the certification to match the active journal
/// record's reset and restart counts. Replay groups by reset alone.
fn nvpcr_matches_config(config: &Evidence, certified: &TpmAttest, bytes: &[u8]) -> bool {
    certified.reset_count == config.reset_count
        && certified.restart_count == config.restart_count
        && certified.offset == 0
        && certified.nv_len == 32
        && certified
            .nv_data_in(bytes)
            .is_some_and(|data| !memneq_explicit(data, &config.value))
}

/// What the TPM gives the evidence, the TPM let go of before the file
/// work: -ENXIO without a TPM, -ENODEV without a register bound,
/// -EBADMSG for a malformed certification, -EAGAIN for PCRs that keep
/// changing, and -EUCLEAN for data not of the active config value.
fn measure(
    config: &Evidence,
    nonce: &[u8],
    mut pcr_mask: u32,
    challenge: Option<&AttestChallenge>,
) -> Result<Measured, c_int> {
    let mut values = [[0u8; 32]; 24];
    let in_nvpcr = config.present && nvpcr(config.pcr);

    if config.present && !in_nvpcr {
        pcr_mask |= 1u32.checked_shl(config.pcr).ok_or(-EUCLEAN)?;
    }
    // The keys go before the connection, the endorsement key first, on
    // every path out: they are dropped in the reverse of their making.
    let tpm = Tpm::open().map_err(|_| -ENXIO)?;
    let nv = tpm.nv_info(NV_INDEX)?;
    if !nv.defined || !nv.written {
        return Err(-ENODEV);
    }
    let ak = tpm.ak_create()?;
    let certify = tpm.nv_certify(&ak, NV_INDEX, nonce)?;
    let certified = quoted(&certify).ok_or(-EBADMSG)?;
    let register: [u8; 32] = if certified.ty == ST_ATTEST_NV && certified.nv_len == 32 {
        certified
            .nv_data_in(&certify.attest)
            .and_then(|data| data.try_into().ok())
            .ok_or(-EBADMSG)?
    } else {
        return Err(-EBADMSG);
    };
    let config_nvpcr = if in_nvpcr {
        let info = tpm.nv_info(config.pcr)?;
        let certification = tpm.nv_certify(&ak, config.pcr, nonce)?;
        let mut certified = TpmAttest::zeroed();
        if attest_parse(&certification.attest, &mut certified) != 0
            || !nvpcr_matches_config(config, &certified, &certification.attest)
        {
            return Err(-EUCLEAN);
        }
        Some((info, certification))
    } else {
        None
    };
    let quote_nonce = snapshot_quote_nonce(
        &certify.signature,
        config_nvpcr.as_ref().map(|(_, c)| c.signature.as_slice()),
    )?;
    let quote = quote_pcrs(&tpm, &ak, &quote_nonce, pcr_mask, &mut values)?;
    if config.present
        && quoted(&quote).is_none_or(|q| !quote_matches_config(config, &q, &values, in_nvpcr))
    {
        return Err(-EUCLEAN);
    }
    let after_nonce = sha256(&quote.signature)?;
    let config_nvpcr = config_nvpcr
        .map(|(info, before)| {
            let after = certify_after_quote(&tpm, &ak, config.pcr, &after_nonce, &before)?;
            Ok::<_, c_int>((info, before, after))
        })
        .transpose()?;
    let register_after = certify_after_quote(&tpm, &ak, NV_INDEX, &after_nonce, &certify)?;
    let (ek_certificate, ek_cert_rsa) = ek_certificate_base64(&tpm);
    // The endorsement key the certificate describes, or the one the
    // challenge was made for; a TPM without a certificate yields its ECC
    // key, which the operator pins by name.
    let ek_rsa = challenge.map_or(ek_cert_rsa, |c| c.ek_rsa);
    let ek = tpm.ek_create(ek_rsa)?;
    let credential = match challenge {
        Some(c) => activate(&tpm, &ak, &ek, c)?,
        None => Vec::new(),
    };
    let (ak_public, ek_public) = (ak.public().clone(), ek.public().clone());

    // The keys are flushed and the TPM closed before the file work.
    drop(ek);
    drop(ak);
    drop(tpm);
    Ok(Measured {
        pcr_mask,
        values,
        register,
        nv,
        quote,
        certify,
        register_after,
        config_nvpcr,
        ak: ak_public,
        ek: ek_public,
        ek_rsa,
        ek_certificate,
        credential,
    })
}

/// The room the document may take: enough for the logs, the EK
/// certificate, the config's events and the eventlog twice over, and at
/// most what a JSON document may be.
fn document_room(m: &Measured, logs: &[&Option<Vec<u8>>; 2], config: &Evidence) -> usize {
    let with_nul = |b64: &Option<Vec<u8>>| b64.as_ref().map_or(0, |b| b.len() + 1);
    let mut need = (64 * 1024usize)
        .wrapping_add(with_nul(logs[0]))
        .wrapping_add(with_nul(logs[1]))
        .wrapping_add(with_nul(&m.ek_certificate))
        .wrapping_add(config.n_events().wrapping_mul(160));
    let eventlog = std::fs::metadata(OsStr::from_bytes(eventlog::path().to_bytes()));

    if let Ok(size) = eventlog.map(|meta| meta.len())
        && i64::try_from(size).is_ok_and(|size| size > 0)
    {
        let size = usize::try_from(size).unwrap_or(usize::MAX);
        need = need.saturating_add(2usize.saturating_mul(size));
    }
    need.min(JSON_MAX_BYTES)
}

fn emit_certification(e: &mut JsonEmit, before: &Attestation, after: &Attestation) {
    emit_hex(e, b"attest", &before.attest);
    emit_hex(e, b"signature", &before.signature);
    emit_hex(e, b"after_attest", &after.attest);
    emit_hex(e, b"after_signature", &after.signature);
}

/// attest: the target's register, its quoted PCRs, its keys and logs,
/// and the config the journal `update` runs, with the nonce and the
/// credential a challenge carried, as a document: -EINVAL for a nonce
/// too long or a mask of no PCR or past 23.
pub(crate) fn evidence_config(
    nonce: &[u8],
    pcr_mask: u32,
    challenge: Option<&AttestChallenge>,
    update: Option<&ConfigUpdate<'_>>,
) -> Result<Vec<u8>, c_int> {
    if nonce.len() > NONCE_MAX || pcr_mask == 0 || pcr_mask & !0x00FF_FFFF != 0 {
        return Err(-EINVAL);
    }
    let config = config_attest::collect(update)?;
    let m = measure(&config, nonce, pcr_mask, challenge)?;
    let firmware = read_log_base64(FIRMWARE_LOG_PATH);
    let systemd = read_log_base64(SYSTEMD_LOG_PATH);
    let room = document_room(&m, &[&firmware, &systemd], &config);
    let mut doc = Vec::new();

    doc.try_reserve_exact(room).map_err(|_| -ENOMEM)?;
    doc.resize(room, 0);
    let mut e = JsonEmit::fixed(&mut doc);
    emit_evidence(&mut e, &m, nonce, &config, [&firmware, &systemd])?;
    let len = match e.err() {
        0 => e.written(),
        err => return Err(err),
    };
    doc.truncate(len);
    Ok(doc)
}

/// The document of the evidence into `e`: the config's error, or the
/// emitter's in it.
fn emit_evidence(
    e: &mut JsonEmit,
    m: &Measured,
    nonce: &[u8],
    config: &Evidence,
    logs: [&Option<Vec<u8>>; 2],
) -> Result<(), c_int> {
    let mut ts = [0u8; 32];
    let mut boot_id = [0u8; 64];
    let (ak, ek) = (&m.ak, &m.ek);

    eventlog::timestamp(&mut ts);
    eventlog::read_boot_id(&mut boot_id);
    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_string(b"kind", b"shirudo-attestation");
    // SAFETY: the build's version ID, a C string the link provides.
    let version_id = unsafe { CStr::from_ptr(&raw const shirudo_version_id) };
    e.kv_string(b"version_id", version_id.to_bytes());
    e.kv_string(b"ts", cstr(&ts));
    e.kv_string(b"boot_id", cstr(&boot_id));
    e.kv_string(b"nonce", &encode(nonce));
    e.kv_string(b"pcr_bank", b"sha256");
    e.kv_int(b"pcr_mask", i64::from(m.pcr_mask));
    e.arr_open(b"pcrs");
    for (i, value) in (0i64..).zip(&m.values) {
        if m.pcr_mask & (1 << i) == 0 {
            continue;
        }
        e.obj_open();
        e.kv_int(b"index", i);
        emit_hex(e, b"value", value);
        e.obj_close();
    }
    e.arr_close();
    e.obj_open_key(b"ak");
    emit_hex(e, b"public", &ak.area);
    emit_hex(e, b"name", &ak.name);
    e.obj_close();
    e.obj_open_key(b"ek");
    e.kv_string(b"type", if m.ek_rsa { b"rsa" } else { b"ecc" });
    emit_hex(e, b"public", &ek.area);
    emit_hex(e, b"name", &ek.name);
    e.obj_close();
    e.obj_open_key(b"quote");
    emit_hex(e, b"attest", &m.quote.attest);
    emit_hex(e, b"signature", &m.quote.signature);
    e.obj_close();
    e.obj_open_key(b"register");
    e.kv_string(b"nv_index", format!("0x{NV_INDEX:08X}").as_bytes());
    e.kv_int(b"pcr", i64::from(CHAIN_PCR));
    emit_hex(e, b"name", m.nv.name());
    emit_hex(e, b"value", &m.register);
    emit_certification(e, &m.certify, &m.register_after);
    e.obj_close();
    if let Some((info, before, after)) = &m.config_nvpcr {
        e.obj_open_key(b"config_nvpcr");
        emit_hex(e, b"name", info.name());
        emit_certification(e, before, after);
        e.obj_close();
    }
    e.arr_open(b"eventlog");
    let ret = eventlog::boot_lines(&mut |line| {
        e.raw(line.to_bytes());
        0
    });
    if ret != 0 && ret != -ENOENT {
        crate::log::err(
            &[
                &b"attest: eventlog "[..],
                eventlog::path().to_bytes(),
                b" unreadable: ",
                text(ret).as_bytes(),
            ]
            .concat(),
        );
        return Err(ret);
    }
    e.arr_close();
    config_attest::emit(e, config)?;
    if m.credential.is_empty() {
        e.kv_null(b"credential");
    } else {
        e.obj_open_key(b"credential");
        emit_hex(e, b"value", &m.credential);
        e.obj_close();
    }
    emit_text_or_null(e, b"ek_certificate", &m.ek_certificate);
    e.obj_open_key(b"logs");
    emit_text_or_null(e, b"firmware", logs[0]);
    emit_text_or_null(e, b"systemd", logs[1]);
    e.obj_close();
    e.obj_close();
    Ok(())
}

/// `text` under `key`, or null without it.
fn emit_text_or_null(e: &mut JsonEmit, key: &[u8], text: &Option<Vec<u8>>) {
    match text {
        Some(text) => e.kv_string(key, text),
        None => e.kv_null(key),
    }
}

/* ---- verification ---------------------------------------------------- */

/// What the array of PCRs calls with each: its value, under its index.
fn on_pcr(p: &mut Parse) -> Result<(), c_int> {
    let index = usize::try_from(p.pcr_index)
        .ok()
        .filter(|&i| i < p.pcrs.len())
        .ok_or(-EINVAL)?;

    if !hex_into(&p.pcr_value_hex, &mut p.pcrs[index]) {
        return Err(-EINVAL);
    }
    p.pcr_have |= 1u32 << index;
    Ok(())
}

/// Whether the report may print `s` as it stands. The report prints a
/// record's type and label as they stand, and the target writes them:
/// only the words its writers use may pass, or an escape sequence would
/// rewrite what the operator reads.
fn record_word(s: &[u8]) -> bool {
    s.iter().all(|&c| c.is_ascii_lowercase() || c == b'_')
}

/// The hex of the C string in `hex` decoded into all of `out`.
fn hex_into(hex: &[u8], out: &mut [u8]) -> bool {
    decode(cstr(hex), out).is_ok()
}

/// The bytes the hex of the C string in `hex` spells, as the start of
/// `room`: -EINVAL for more than it holds or for what is not hex.
fn hex_text<'a>(hex: &[u8], room: &'a mut [u8]) -> Result<&'a [u8], c_int> {
    let n = decode_max(cstr(hex), room)?;

    room.get(..n).ok_or(-EINVAL)
}

/// At most the first `n` bytes of `s`, as `%.<n>s` prints them.
fn first(s: &[u8], n: usize) -> &[u8] {
    s.get(..n).unwrap_or(s)
}

/// The init record the parse holds, of the digest `digest`, as the
/// boot's last: -EINVAL for a field out of range or not hex.
fn take_init(p: &mut Parse, digest: &[u8; 32]) -> Result<(), c_int> {
    let prev_reset = p.init.reset_count;
    let mut init = InitRecord::new();
    // Checked, as the record must carry it, but not used.
    let mut chain = [0u8; 32];

    let (Ok(pcr), Ok(phase_pcr)) = (u32::try_from(p.rec_pcr), u32::try_from(p.rec_phase_pcr))
    else {
        return Err(-EINVAL);
    };
    if pcr >= 24
        || phase_pcr <= pcr
        || phase_pcr >= 24
        || p.rec_reset > i64::from(u32::MAX)
        || !hex_into(&p.pcr_before_hex, &mut init.pcr_before)
        || !hex_into(&p.phase_before_hex, &mut init.phase_before)
        || !hex_into(&p.nv_name_hex, &mut init.name)
        || !hex_into(&p.anchor_digest_hex, &mut init.anchor_digest)
        || !hex_into(&p.chain_hex, &mut chain)
        || !hex_into(&p.writer_public_hex, &mut init.writer_public)
    {
        return Err(-EINVAL);
    }
    init.digest = *digest;
    init.pcr = pcr;
    init.phase_pcr = phase_pcr;
    init.initrd = cstr(&p.bound_in) == b"initrd";
    init.reset_count = u32::try_from(p.rec_reset).ok();
    init.present = true;
    // Records are of one TPM reset unless both carry a count and the
    // counts differ; a second record for one reset is a register bound
    // again after boot.
    p.inits = p.inits.wrapping_add(1);
    let reset_changed =
        matches!((init.reset_count, prev_reset), (Some(now), Some(before)) if now != before);
    if p.inits == 1 || reset_changed {
        p.inits_epoch = 1;
    } else {
        p.inits_epoch = p.inits_epoch.wrapping_add(1);
    }
    p.init = init;
    Ok(())
}

/// Whether the digest of the load or unload `r` follows from its name
/// and payload, which the tag `tag` measures: -EINVAL for a name that is
/// not an upatch's.
fn derive_upatch(p: &Parse, tag: &CStr, r: &mut Record) -> Result<(), c_int> {
    let name = cstr(&p.upatch_name);
    let mut payload = [0u8; 32];
    let mut event = [0u8; 32];

    if !upatch::name_valid(Some(name)) {
        return Err(-EINVAL);
    }
    r.label = name.to_vec();
    if hex_into(&p.upatch_payload_hex, &mut payload)
        && chain::upatch_event(tag, name, &payload, &mut event) == 0
    {
        r.derived = !memneq_explicit(&event, &r.digest);
    }
    Ok(())
}

/// Whether the digest of the tree operation `r` follows from its
/// sequence and operation digest.
fn derive_tree_op(p: &Parse, r: &mut Record) {
    let mut event = [0u8; 32];

    // verify cannot tie op and id to the digest: leave them out.
    r.label = format!("seq {}", p.tree_seq).into_bytes();
    if p.tree_seq > 0
        && let Some(operation) = digest_bytes(&p.tree_digest_hex)
        && chain::tree_event(p.tree_seq, &operation, &mut event) == 0
    {
        r.derived = !memneq_explicit(&event, &r.digest);
        // The digest's hex after its "sha256:".
        let hex = cstr(&p.tree_digest_hex).get(7..).unwrap_or_default();
        r.label = [
            format!("seq {} operation ", p.tree_seq).as_bytes(),
            first(hex, 12),
        ]
        .concat();
    }
}

/// Whether the digest of the revocation `r` follows from the
/// certificate's digest.
fn derive_key_revoke(p: &Parse, r: &mut Record) {
    let mut sha = [0u8; 32];
    let mut event = [0u8; 32];

    // Nor the fingerprint: name the measured certificate.
    if hex_into(&p.key_sha_hex, &mut sha)
        && chain::key_event(c"shirudo-key-revoke", &sha, &mut event) == 0
    {
        r.derived = !memneq_explicit(&event, &r.digest);
        r.label = [b"certificate ", first(cstr(&p.key_sha_hex), 12)].concat();
    }
}

/// What the eventlog's array calls with each record.
fn on_record(p: &mut Parse) -> Result<(), c_int> {
    if p.recs.len() >= RECORDS_MAX {
        return Err(-E2BIG);
    }
    let ty = cstr(&p.ty).to_vec();
    if !record_word(&ty) {
        return Err(-EINVAL);
    }
    let mut r = Record {
        ty: ty.clone(),
        label: Vec::new(),
        digest: [0; 32],
        derived: false,
    };
    if !hex_into(&p.digest_hex, &mut r.digest) {
        return Err(-EINVAL);
    }
    match ty.as_slice() {
        b"init" => {
            take_init(p, &r.digest)?;
            // This boot's register starts here.
            p.recs.clear();
        }
        b"tree_op" => derive_tree_op(p, &mut r),
        b"key_revoke" => derive_key_revoke(p, &mut r),
        _ => {
            if let Some((payload_type, load)) = eventlog::upatch_record_parse(&ty) {
                let tag = chain::upatch_tag(payload_type, load).ok_or(-EINVAL)?;
                derive_upatch(p, tag, &mut r)?;
            }
        }
    }
    p.recs.push(r);
    // Reset the per-element scratch the next element may not set.
    p.ty[0] = 0;
    p.digest_hex[0] = 0;
    p.pcr_before_hex[0] = 0;
    p.phase_before_hex[0] = 0;
    p.nv_name_hex[0] = 0;
    p.anchor_digest_hex[0] = 0;
    p.chain_hex[0] = 0;
    p.upatch_name[0] = 0;
    p.upatch_payload_hex[0] = 0;
    p.tree_id[0] = 0;
    p.tree_op[0] = 0;
    p.tree_digest_hex[0] = 0;
    p.key_fingerprint[0] = 0;
    p.key_sha_hex[0] = 0;
    p.anchor[0] = 0;
    p.writer_public_hex[0] = 0;
    p.bound_in[0] = 0;
    p.tree_seq = 0;
    p.rec_pcr = -1;
    p.rec_phase_pcr = -1;
    p.rec_reset = -1;
    Ok(())
}

/// The tag of a line of the report, as long as each tag.
const TAG_LEN: usize = 8;
const TAG_OK: &[u8; TAG_LEN] = b"  OK    ";
const TAG_FAIL: &[u8; TAG_LEN] = b"  FAIL  ";
const TAG_NOTE: &[u8; TAG_LEN] = b"  NOTE  ";

/// A report of checks and notes, a line each, in at most `cap` bytes
/// and the NUL after them, as the C's buffer of that size held it, and
/// how many of the checks failed.
pub(crate) struct Report {
    text: Vec<u8>,
    cap: usize,
    failed: u32,
}

impl Report {
    /// A report of at most `cap` bytes, its NUL included.
    pub(crate) fn new(cap: usize) -> Self {
        Report {
            text: Vec::new(),
            cap,
            failed: 0,
        }
    }

    /// The lines of the report.
    pub(crate) fn text(&self) -> &[u8] {
        &self.text
    }

    /// A line: its tag, any text that fits whole, then its line feed.
    /// Keep room for the line feed and the C buffer's trailing NUL.
    fn line(&mut self, tag: &[u8; TAG_LEN], text: &[u8]) {
        let Some(room) = self.cap.checked_sub(self.text.len()) else {
            return;
        };
        if room < TAG_LEN + 2 {
            return;
        }
        self.text.extend_from_slice(tag);
        if text.len() <= room - TAG_LEN - 2 {
            self.text.extend_from_slice(text);
        }
        self.text.push(b'\n');
    }

    /// A check, which counts when it failed.
    fn check(&mut self, ok: bool, text: &[u8]) {
        if !ok {
            self.failed = self.failed.saturating_add(1);
        }
        self.line(if ok { TAG_OK } else { TAG_FAIL }, text);
    }

    /// A remark, which is no check.
    fn note(&mut self, text: &[u8]) {
        self.line(TAG_NOTE, text);
    }
}

/// The attestation key that signs the evidence's attestations, its name,
/// and the default challenge for an opening certification.
struct Signer<'a> {
    key: &'a TpmEccPublic,
    name: &'a [u8; NAME_LEN],
    nonce: &'a [u8],
}

/// An attestation of the evidence: its bytes, and what they hold as far
/// as they parse.
struct Signed {
    bytes: Vec<u8>,
    attest: TpmAttest,
    /// The attestation and its signature parse, and were checked.
    checked: bool,
}

/// The attestation in `attest_hex`, which `sig_hex` signs, checked
/// against the signer, every check into the report as `what`'s: -EINVAL
/// for hex that does not decode.
fn check_signed(
    rep: &mut Report,
    signer: &Signer,
    what: &[u8],
    attest_hex: &[u8],
    sig_hex: &[u8],
    expected_nonce: Option<&[u8]>,
) -> Result<Signed, c_int> {
    let mut bytes = vec![0u8; ATTEST_MAX];
    let mut sig = [0u8; SIGNATURE_MAX];
    let mut attest = TpmAttest::zeroed();

    let attest_len = decode_max(cstr(attest_hex), &mut bytes)?;
    let sig = hex_text(sig_hex, &mut sig)?;
    bytes.truncate(attest_len);
    let checked = check_attest(
        rep,
        signer,
        what,
        &bytes,
        sig,
        expected_nonce.unwrap_or(signer.nonce),
        &mut attest,
    );
    Ok(Signed {
        bytes,
        attest,
        checked,
    })
}

/// The checks of check_signed() on the attestation `bytes`, parsed into
/// `attest`, and its signature `sig`: whether they parse.
fn check_attest(
    rep: &mut Report,
    signer: &Signer,
    what: &[u8],
    bytes: &[u8],
    sig: &[u8],
    expected_nonce: &[u8],
    attest: &mut TpmAttest,
) -> bool {
    if attest_parse(bytes, attest) != 0 {
        rep.check(
            false,
            &[what, b": attestation structure unparseable"].concat(),
        );
        return false;
    }
    let ret = signature_verify(bytes, sig, &signer.key.x, &signer.key.y);
    if ret == -EBADMSG {
        rep.check(
            false,
            &[what, b": signature structure unparseable"].concat(),
        );
        return false;
    }
    rep.check(
        ret == 0,
        &[what, b": ECDSA signature by the attestation key"].concat(),
    );
    rep.check(
        attest_signer(attest, signer.name) == Ok(true),
        &[what, b": signed by the key as an endorsement primary"].concat(),
    );
    let carried = attest.extra_in(bytes).is_some_and(|extra| {
        extra.len() == expected_nonce.len()
            && (expected_nonce.is_empty() || !memneq_explicit(extra, expected_nonce))
    });
    rep.check(
        carried,
        &[what, b": carries the expected challenge"].concat(),
    );
    true
}

/// Whether `public` is an endorsement key of the TCG default template.
fn endorsement_template(public: &TpmPublic) -> bool {
    public.attrs == EK_ATTRS
        && public.policy_len == 32
        && !memneq_explicit(&public.policy, &EK_POLICY)
}

/// parse_schema() of the evidence into the parse: whether it carries an
/// endorsement key, credential and config NvPCR certification, or -EINVAL.
fn parse_evidence(p: &mut Parse, evidence: &[u8]) -> Result<(bool, bool, bool), c_int> {
    let pcr_sub = [
        JsonField::int(c"index", |p: &mut Parse| &mut p.pcr_index),
        JsonField::string(c"value", |p| &mut p.pcr_value_hex),
    ];
    let ak_sub = [
        JsonField::string(c"public", |p: &mut Parse| &mut p.ak_public_hex),
        JsonField::string(c"name", |p| &mut p.ak_name_hex),
    ];
    let quote_sub = [
        JsonField::string(c"attest", |p: &mut Parse| &mut p.quote_attest_hex),
        JsonField::string(c"signature", |p| &mut p.quote_sig_hex),
    ];
    let ek_sub = [
        JsonField::string(c"type", |p: &mut Parse| &mut p.ek_type),
        JsonField::string(c"public", |p| &mut p.ek_public_hex),
        JsonField::string(c"name", |p| &mut p.ek_name_hex),
    ];
    let cred_sub = [JsonField::string(c"value", |p: &mut Parse| &mut p.cred_hex)];
    let nvpcr_sub = [
        JsonField::string(c"name", |p: &mut Parse| &mut p.nvpcr_name_hex),
        JsonField::string(c"attest", |p| &mut p.nvpcr_attest_hex),
        JsonField::string(c"signature", |p| &mut p.nvpcr_sig_hex),
        JsonField::string(c"after_attest", |p| &mut p.nvpcr_after_attest_hex),
        JsonField::string(c"after_signature", |p| &mut p.nvpcr_after_sig_hex),
    ];
    let reg_sub = [
        JsonField::string(c"nv_index", |p: &mut Parse| &mut p.reg_index),
        JsonField::int(c"pcr", |p| &mut p.reg_pcr),
        JsonField::string(c"name", |p| &mut p.reg_name_hex),
        JsonField::string(c"value", |p| &mut p.reg_value_hex),
        JsonField::string(c"attest", |p| &mut p.reg_attest_hex),
        JsonField::string(c"signature", |p| &mut p.reg_sig_hex),
        JsonField::string(c"after_attest", |p| &mut p.reg_after_attest_hex),
        JsonField::string(c"after_signature", |p| &mut p.reg_after_sig_hex),
    ];
    let upatch_sub = [
        JsonField::string(c"name", |p: &mut Parse| &mut p.upatch_name),
        JsonField::string(c"payload_sha256", |p| &mut p.upatch_payload_hex),
    ];
    let key_sub = [
        JsonField::string(c"fingerprint", |p: &mut Parse| &mut p.key_fingerprint),
        JsonField::string(c"cert_sha256", |p| &mut p.key_sha_hex),
    ];
    let tree_sub = [
        JsonField::int(c"seq", |p: &mut Parse| &mut p.tree_seq),
        JsonField::string(c"op", |p| &mut p.tree_op),
        JsonField::string(c"id", |p| &mut p.tree_id),
        JsonField::string(c"operation_digest", |p| &mut p.tree_digest_hex),
    ];
    let rec_sub = [
        JsonField::string(c"type", |p: &mut Parse| &mut p.ty),
        JsonField::string(c"digest", |p| &mut p.digest_hex),
        JsonField::int(c"pcr", |p| &mut p.rec_pcr),
        JsonField::int(c"tpm_reset_count", |p| &mut p.rec_reset),
        JsonField::string(c"pcr_before", |p| &mut p.pcr_before_hex),
        JsonField::int(c"phase_pcr", |p| &mut p.rec_phase_pcr),
        JsonField::string(c"phase_before", |p| &mut p.phase_before_hex),
        JsonField::string(c"bound_in", |p| &mut p.bound_in),
        JsonField::string(c"nv_name", |p| &mut p.nv_name_hex),
        JsonField::string(c"nv_writer_public", |p| &mut p.writer_public_hex),
        JsonField::string(c"anchor", |p| &mut p.anchor),
        JsonField::string(c"anchor_digest", |p| &mut p.anchor_digest_hex),
        JsonField::string(c"chain", |p| &mut p.chain_hex),
        JsonField::object(c"upatch", &upatch_sub),
        JsonField::object(c"tree", &tree_sub),
        JsonField::object(c"key", &key_sub),
    ];
    let top = [
        JsonField::string(c"nonce", |p: &mut Parse| &mut p.nonce_hex),
        JsonField::int(c"pcr_mask", |p| &mut p.pcr_mask),
        JsonField::array(c"pcrs", &pcr_sub, &on_pcr),
        JsonField::object(c"ak", &ak_sub),
        JsonField::object(c"quote", &quote_sub),
        JsonField::object(c"register", &reg_sub),
        JsonField::array(c"eventlog", &rec_sub, &on_record),
        JsonField::object(c"ek", &ek_sub),
        JsonField::object(c"credential", &cred_sub),
        JsonField::object(c"config_nvpcr", &nvpcr_sub),
    ];

    if parse_schema(evidence, &top, p).is_err() || !top[..7].iter().all(JsonField::seen) {
        return Err(-EINVAL);
    }
    let have_nvpcr = top[9].seen();
    if have_nvpcr && !nvpcr_sub.iter().all(JsonField::seen) {
        return Err(-EINVAL);
    }
    if !signed_fields_valid(&p.quote_attest_hex, &p.quote_sig_hex)
        || !signed_fields_valid(&p.reg_attest_hex, &p.reg_sig_hex)
        || !signed_fields_valid(&p.reg_after_attest_hex, &p.reg_after_sig_hex)
        || (have_nvpcr
            && (!signed_fields_valid(&p.nvpcr_attest_hex, &p.nvpcr_sig_hex)
                || !signed_fields_valid(&p.nvpcr_after_attest_hex, &p.nvpcr_after_sig_hex)))
    {
        return Err(-EINVAL);
    }
    Ok((
        ek_sub.iter().all(JsonField::seen),
        cred_sub[0].seen(),
        have_nvpcr,
    ))
}

fn signed_fields_valid(attest_hex: &[u8], sig_hex: &[u8]) -> bool {
    let mut attest = [0u8; ATTEST_MAX];
    let mut sig = [0u8; SIGNATURE_MAX];
    decode_max(cstr(attest_hex), &mut attest).is_ok_and(|len| len != 0)
        && decode_max(cstr(sig_hex), &mut sig).is_ok_and(|len| len != 0)
}

fn signature_bytes(hex: &[u8]) -> Result<Vec<u8>, c_int> {
    let mut signature = vec![0u8; SIGNATURE_MAX];
    let len = decode_max(cstr(hex), &mut signature)?;
    if len == 0 {
        return Err(-EINVAL);
    }
    signature.truncate(len);
    Ok(signature)
}

fn check_after_quote(
    rep: &mut Report,
    signer: &Signer<'_>,
    what: &[u8],
    before: &Signed,
    attest_hex: &[u8],
    sig_hex: &[u8],
    nonce: &[u8; 32],
) -> Result<(), c_int> {
    if !before.checked {
        return Ok(());
    }
    let after = check_signed(rep, signer, what, attest_hex, sig_hex, Some(nonce))?;
    if !after.checked {
        return Err(-EKEYREJECTED);
    }
    rep.check(
        same_nv(&before.attest, &before.bytes, &after.attest, &after.bytes),
        &[
            what,
            b": same index and value on both sides of the PCR quote",
        ]
        .concat(),
    );
    Ok(())
}

/// attest verify: the evidence checked against what the operator
/// expects, every check into the report: -EKEYREJECTED when one failed,
/// -EINVAL for a malformed document.
pub(crate) fn verify(
    evidence: &[u8],
    expect: &AttestExpect,
    rep: &mut Report,
) -> Result<(), c_int> {
    let mut p = Box::new(Parse::new());

    p.recs.try_reserve_exact(RECORDS_MAX).map_err(|_| -ENOMEM)?;
    let (have_ek, have_cred, have_nvpcr) = parse_evidence(&mut p, evidence)?;
    let config = parse_config(rep, evidence)?;

    // Freshness: the document must answer this request.
    let mut nonce = [0u8; NONCE_MAX];
    let nonce = hex_text(&p.nonce_hex, &mut nonce)?;
    let fresh = expect.nonce.len() == nonce.len()
        && (nonce.is_empty() || !memneq_explicit(nonce, &expect.nonce));
    rep.check(fresh, b"nonce matches the request");

    let (ak_pub, ak_name) = check_ak(rep, &p, expect)?;
    check_ek(rep, &p, expect, have_ek)?;
    check_credential(rep, &p, expect, have_cred)?;

    let signer = Signer {
        key: &ak_pub,
        name: &ak_name,
        nonce,
    };
    let register_sig = signature_bytes(&p.reg_sig_hex)?;
    let config_sig = if have_nvpcr {
        Some(signature_bytes(&p.nvpcr_sig_hex)?)
    } else {
        None
    };
    let quote_nonce = snapshot_quote_nonce(&register_sig, config_sig.as_deref())?;
    let quote_sig = signature_bytes(&p.quote_sig_hex)?;
    let after_nonce = sha256(&quote_sig)?;

    let quote = check_signed(
        rep,
        &signer,
        b"quote",
        &p.quote_attest_hex,
        &p.quote_sig_hex,
        Some(&quote_nonce),
    )?;
    check_quote(rep, &mut p, &quote);
    let certify = check_signed(
        rep,
        &signer,
        b"register",
        &p.reg_attest_hex,
        &p.reg_sig_hex,
        None,
    )?;
    let register = read_register(&p)?;
    check_certify(rep, &register, &certify);
    if quote.checked && certify.checked {
        let (q, c) = (&quote.attest, &certify.attest);
        rep.check(
            q.reset_count == c.reset_count
                && q.restart_count == c.restart_count
                && q.firmware_version == c.firmware_version,
            b"quote and certification are of one TPM boot",
        );
    }
    check_after_quote(
        rep,
        &signer,
        b"register after quote",
        &certify,
        &p.reg_after_attest_hex,
        &p.reg_after_sig_hex,
        &after_nonce,
    )?;
    let nvpcr_value =
        check_config_nvpcr(rep, &p, expect, &signer, &quote, have_nvpcr, &after_nonce)?;
    check_config(
        rep,
        &p,
        expect,
        &config,
        &quote.attest,
        nvpcr_value.as_ref(),
    );

    check_binding(rep, &p, expect, &register)?;
    check_epoch(rep, &p, &certify);
    check_replay(rep, &p, &register.value);
    check_anchor(rep, &p, expect);
    check_state(rep, &p, expect, &register.value);
    for bit in 0..24u32 {
        if expect.pcr_expect_mask & (1 << bit) == 0 {
            continue;
        }
        let i = bit as usize;
        rep.check(
            p.pcr_have & (1 << bit) != 0 && !memneq_explicit(&p.pcrs[i], &expect.pcrs[i]),
            format!("PCR {bit} matches the expected value").as_bytes(),
        );
    }
    if rep.failed != 0 {
        return Err(-EKEYREJECTED);
    }
    Ok(())
}

/// The config's history the evidence carries, the failure of a history
/// out of order into the report.
fn parse_config(rep: &mut Report, evidence: &[u8]) -> Result<Evidence, c_int> {
    config_attest::parse(evidence).map_err(|ret| {
        if ret == -EKEYREJECTED {
            rep.check(
                false,
                b"config: the events are one boot event followed by updates in sequence",
            );
        }
        // What json_parse() refuses past a bound is a malformed document.
        if ret == -E2BIG || ret == -ENOSPC {
            return -EINVAL;
        }
        ret
    })
}

/// The attestation key the evidence names, checked: its public area and
/// its name, or -EKEYREJECTED for a key that is not a P-256 ECDSA key.
fn check_ak(
    rep: &mut Report,
    p: &Parse,
    expect: &AttestExpect,
) -> Result<(TpmEccPublic, [u8; NAME_LEN]), c_int> {
    let mut ak_public = [0u8; PUBLIC_MAX];
    let mut ak_name = [0u8; NAME_LEN];
    let mut ak_pub = TpmEccPublic::zeroed();
    let mut computed = [0u8; NAME_LEN];

    let ak_public = hex_text(&p.ak_public_hex, &mut ak_public)?;
    if !hex_into(&p.ak_name_hex, &mut ak_name) {
        return Err(-EINVAL);
    }
    if ecc_public_parse(ak_public, &mut ak_pub) != 0 {
        rep.check(
            false,
            b"attestation key: public area is not a P-256 ECDSA key",
        );
        return Err(-EKEYREJECTED);
    }
    rep.check(
        ak_pub.attrs & AK_ATTRS_REQUIRED == AK_ATTRS_REQUIRED,
        b"attestation key: restricted, fixed to this TPM",
    );
    let named = object_name(ak_public, &mut computed) == 0;
    rep.check(
        named && !memneq_explicit(&computed, &ak_name),
        b"attestation key: name matches its public area",
    );
    match &expect.ak_name {
        Some(pinned) => rep.check(
            !memneq_explicit(&ak_name, pinned),
            b"attestation key: the pinned key",
        ),
        None => rep.note(&[b"attestation key not pinned: name ", cstr(&p.ak_name_hex)].concat()),
    }
    Ok((ak_pub, ak_name))
}

/// The endorsement key the evidence carries, if any, checked, and
/// against the one pinned.
fn check_ek(
    rep: &mut Report,
    p: &Parse,
    expect: &AttestExpect,
    have_ek: bool,
) -> Result<(), c_int> {
    if have_ek {
        let mut ek_public = [0u8; PUBLIC_MAX];
        let mut ek_name = [0u8; NAME_LEN];
        let mut computed = [0u8; NAME_LEN];
        let mut ek_pub = TpmPublic::zeroed();

        let ek_public = hex_text(&p.ek_public_hex, &mut ek_public)?;
        if !hex_into(&p.ek_name_hex, &mut ek_name) {
            return Err(-EINVAL);
        }
        let parsed = public_parse(ek_public, &mut ek_pub) == 0;
        let named = parsed
            && object_name(ek_public, &mut computed) == 0
            && !memneq_explicit(&computed, &ek_name);
        rep.check(named, b"endorsement key: name matches its public area");
        rep.check(
            parsed && endorsement_template(&ek_pub),
            b"endorsement key: TCG default template under the endorsement policy",
        );
    } else {
        rep.note(b"no endorsement key in the evidence");
    }
    if let Some(pinned) = &expect.ek_name {
        let mut ek_name = [0u8; NAME_LEN];
        let ok =
            have_ek && hex_into(&p.ek_name_hex, &mut ek_name) && !memneq_explicit(&ek_name, pinned);

        rep.check(ok, b"endorsement key: the pinned key");
    }
    Ok(())
}

/// The credential the target activated, if any, against the one the
/// challenge carried.
fn check_credential(
    rep: &mut Report,
    p: &Parse,
    expect: &AttestExpect,
    have_cred: bool,
) -> Result<(), c_int> {
    // On the heap, so that it is scrubbed when it goes.
    let mut room = vec![0u8; CREDENTIAL_LEN];
    let cred = if have_cred {
        hex_text(&p.cred_hex, &mut room)?
    } else {
        &[]
    };

    match &expect.credential {
        Some(want) => rep.check(
            have_cred && cred.len() == CREDENTIAL_LEN && !memneq_explicit(cred, want),
            b"attestation key: activated the credential made for it under the endorsement key",
        ),
        None if have_cred => {
            rep.note(b"a credential was activated but none is expected (--expect-credential)")
        }
        None => {}
    }
    Ok(())
}

/// The quote's checks against the PCRs the document lists, which stand
/// as quoted only when they pass.
fn check_quote(rep: &mut Report, p: &mut Parse, quote: &Signed) {
    if !quote.checked {
        p.pcr_have = 0;
        return;
    }
    let q = &quote.attest;
    let complete =
        q.ty == ST_ATTEST_QUOTE && p.pcr_mask == i64::from(q.pcr_mask) && p.pcr_have == q.pcr_mask;
    rep.check(complete, b"quote: covers the PCRs the document lists");
    let vouched = complete
        && pcr_values_digest(q.pcr_mask, &p.pcrs)
            .is_some_and(|d| !memneq_explicit(&d, &q.pcr_digest));
    rep.check(vouched, b"quote: PCR digest matches the listed values");
    if !vouched {
        p.pcr_have = 0;
    }
}

/// The register as the document lists it.
struct Register {
    index: u64,
    name: [u8; NAME_LEN],
    value: [u8; 32],
}

/// The register the document lists: -EINVAL for a field malformed.
fn read_register(p: &Parse) -> Result<Register, c_int> {
    let mut register = Register {
        index: 0,
        name: [0; NAME_LEN],
        value: [0; 32],
    };

    if !hex_into(&p.reg_name_hex, &mut register.name)
        || !hex_into(&p.reg_value_hex, &mut register.value)
        || !(0..24).contains(&p.reg_pcr)
    {
        return Err(-EINVAL);
    }
    let digits = cstr(&p.reg_index).strip_prefix(b"0x").ok_or(-EINVAL)?;
    register.index = parse_x64(digits, 0xffff_ffff).map_err(|_| -EINVAL)?;
    Ok(register)
}

/// The certification's checks against the register the document lists.
fn check_certify(rep: &mut Report, register: &Register, certify: &Signed) {
    if !certify.checked {
        return;
    }
    let c = &certify.attest;
    rep.check(
        c.ty == ST_ATTEST_NV
            && c.index_name_len == NAME_LEN
            && !memneq_explicit(&c.index_name, &register.name),
        b"register: certification names the listed index",
    );
    let contents = c.ty == ST_ATTEST_NV
        && c.offset == 0
        && c.nv_len == 32
        && c.nv_data_in(&certify.bytes)
            .is_some_and(|data| !memneq_explicit(data, &register.value));
    rep.check(
        contents,
        b"register: certified contents match the listed value",
    );
}

/// Only a certification of the listed index name and exactly 32 bytes
/// supplies replay input. Signature validity is reported separately.
fn certified_nvpcr_value(signed: &Signed, name: &[u8; NAME_LEN]) -> Option<[u8; 32]> {
    let nv = &signed.attest;
    if !signed.checked
        || nv.ty != ST_ATTEST_NV
        || nv.index_name_len != NAME_LEN
        || memneq_explicit(&nv.index_name, name)
        || nv.offset != 0
        || nv.nv_len != 32
    {
        return None;
    }
    nv.nv_data_in(&signed.bytes)?.try_into().ok()
}

/// Verify an optional AK-signed config NvPCR certification against the
/// quote's TPM boot and, when supplied, the operator's pinned index.
fn check_config_nvpcr(
    rep: &mut Report,
    p: &Parse,
    expect: &AttestExpect,
    signer: &Signer<'_>,
    quote: &Signed,
    present: bool,
    after_nonce: &[u8; 32],
) -> Result<Option<[u8; 32]>, c_int> {
    if !present {
        if expect.config_nvpcr_name.is_some() {
            rep.check(false, b"config NvPCR: certification missing");
        }
        return Ok(None);
    }
    let mut name = [0u8; NAME_LEN];
    if !hex_into(&p.nvpcr_name_hex, &mut name) {
        return Err(-EINVAL);
    }
    let signed = check_signed(
        rep,
        signer,
        b"config NvPCR",
        &p.nvpcr_attest_hex,
        &p.nvpcr_sig_hex,
        None,
    )?;
    let value = certified_nvpcr_value(&signed, &name);
    rep.check(
        value.is_some(),
        b"config NvPCR: certified name and contents",
    );
    let (nv, q) = (&signed.attest, &quote.attest);
    rep.check(
        signed.checked
            && quote.checked
            && nv.reset_count == q.reset_count
            && nv.restart_count == q.restart_count
            && nv.firmware_version == q.firmware_version,
        b"config NvPCR: same TPM boot as quote",
    );
    if let Some(pinned) = expect.config_nvpcr_name {
        rep.check(
            !memneq_explicit(&name, &pinned),
            b"config NvPCR: the operator-pinned index",
        );
    } else {
        rep.note(b"config NvPCR has no operator pin; use --expect-config-nvpcr");
    }
    check_after_quote(
        rep,
        signer,
        b"config NvPCR after quote",
        &signed,
        &p.nvpcr_after_attest_hex,
        &p.nvpcr_after_sig_hex,
        after_nonce,
    )?;
    Ok(value)
}

/// The config's history against the quote, where the evidence carries
/// one or the operator expects one.
fn check_config(
    rep: &mut Report,
    p: &Parse,
    expect: &AttestExpect,
    config: &Evidence,
    quote: &TpmAttest,
    nvpcr_value: Option<&[u8; 32]>,
) {
    if !config.present && expect.config_root.is_none() && expect.config_pcr.is_none() {
        return;
    }
    let quoted = Quote {
        mask: quote.pcr_mask,
        reset: quote.reset_count,
        pcrs: &p.pcrs,
        nvpcr: nvpcr_value,
    };
    let (ret, reason) = config_attest::verify(
        config,
        &quoted,
        expect.config_root.as_ref(),
        expect.config_pcr,
    );

    rep.check(ret == 0, &[b"config: ", reason.to_bytes()].concat());
    if config.present && expect.config_root.is_none() {
        rep.note(
            b"config root has no operator approval; use --expect-config-root with --expect-config-pcr",
        );
    }
    if config.present {
        rep.note(
            b"config records a selection; operation completion depends on trusted runtime guards",
        );
    }
}

/// The binding of the register: -EKEYREJECTED without an init record or
/// for recorded values its policy cannot be computed of.
fn check_binding(
    rep: &mut Report,
    p: &Parse,
    expect: &AttestExpect,
    register: &Register,
) -> Result<(), c_int> {
    let init = &p.init;
    let mut branch_written = [0u8; 32];
    let mut branch_init = [0u8; 32];
    let mut policy = [0u8; 32];
    let mut bind = [0u8; 64];
    let mut expected_name = [0u8; NAME_LEN];

    // The binding: the certified index must have the public area a
    // register bound to the recorded PCR values has, which is what makes
    // a recreation impossible to pass off, and those values are what the
    // operator pins to tell an initrd binding from a later one. The
    // handle and the PCRs are the register's, never the document's: taken
    // from the record, a target could certify an index of its own under a
    // policy over PCRs it can extend and reset at will.
    rep.check(init.present, b"eventlog: this boot has an init record");
    if !init.present {
        return Err(-EKEYREJECTED);
    }
    rep.check(
        register.index == u64::from(NV_INDEX)
            && p.reg_pcr == i64::from(CHAIN_PCR)
            && init.pcr == CHAIN_PCR
            && init.phase_pcr == CHAIN_PHASE_PCR,
        format!(
            "register: the document names index 0x{NV_INDEX:08X} and PCRs {CHAIN_PCR} and {CHAIN_PHASE_PCR}"
        )
        .as_bytes(),
    );
    bind[..32].copy_from_slice(&init.pcr_before);
    bind[32..].copy_from_slice(&init.phase_before);
    let ret = register_policy(
        CHAIN_PCR_MASK,
        &bind,
        &init.writer_public,
        RegisterPolicy {
            branch_written: &mut branch_written,
            branch_init: &mut branch_init,
            policy: &mut policy,
        },
    );
    if ret != 0 {
        rep.check(false, b"register: cannot compute the signed write policy");
        // Malformed recorded values are the document's failure, not a
        // parse error.
        return Err(if ret == -EINVAL { -EKEYREJECTED } else { ret });
    }
    let ret = nv_name(
        NV_INDEX,
        REGISTER_ATTRS | NV_WRITTEN,
        &policy,
        32,
        &mut expected_name,
    );
    if ret != 0 {
        rep.check(false, b"register: cannot compute the index name");
        return Err(ret);
    }
    rep.check(
        !memneq_explicit(&expected_name, &register.name)
            && !memneq_explicit(&expected_name, &init.name),
        format!(
            "register: public area is bound to PCRs {CHAIN_PCR} and {CHAIN_PHASE_PCR} as recorded"
        )
        .as_bytes(),
    );
    for bit in 0..24u32 {
        if expect.bind_expect_mask & (1 << bit) == 0 {
            continue;
        }
        let held = match bit {
            CHAIN_PCR => Some(&init.pcr_before),
            CHAIN_PHASE_PCR => Some(&init.phase_before),
            _ => None,
        };
        rep.check(
            held.is_some_and(|h| !memneq_explicit(h, &expect.bind_values[bit as usize])),
            format!("binding: PCR {bit} held the expected value").as_bytes(),
        );
    }
    if expect.require_initrd {
        rep.check(init.initrd, b"binding: made while the initrd ran");
    } else {
        let place: &[u8] = if init.initrd {
            b"initrd"
        } else {
            b"root file system"
        };

        rep.note(&[b"binding: made in the ", place].concat());
    }
    Ok(())
}

/// The epoch: one binding per TPM reset, and the one on record is of
/// the reset the TPM certifies in, so no register bound again after
/// boot can pass as the boot's.
fn check_epoch(rep: &mut Report, p: &Parse, certify: &Signed) {
    rep.check(
        p.inits_epoch == 1,
        format!(
            "eventlog: one init record for this TPM reset ({} this boot)",
            p.inits
        )
        .as_bytes(),
    );
    if certify.checked {
        rep.check(
            p.init.reset_count == Some(certify.attest.reset_count),
            b"register: init record is of the TPM's current reset count",
        );
    }
}

/// The records replayed to the certified value, and each one after the
/// init record whose digest its fields do not give.
fn check_replay(rep: &mut Report, p: &Parse, value: &[u8; 32]) {
    let mut register = [0u8; 32];
    let mut replayed = true;

    for r in &p.recs {
        if chain::fold(&mut register, &r.digest) != 0 {
            replayed = false;
        }
    }
    let n = p.recs.len();
    let plural = if n == 1 { "" } else { "s" };
    rep.check(
        replayed && !memneq_explicit(&register, value),
        format!("eventlog: {n} record{plural} replay to the certified value").as_bytes(),
    );
    // A digest the record's own fields do not produce is a record
    // relabelled after the fact: the replay still closes, but what the
    // events say happened is not what was measured.
    for (i, r) in p.recs.iter().enumerate().skip(1) {
        if !r.derived {
            rep.check(
                false,
                &[
                    format!("eventlog: event {i} (").as_bytes(),
                    &r.ty,
                    b" ",
                    &r.label,
                    b") digest does not derive from its fields",
                ]
                .concat(),
            );
        }
    }
}

/// The anchor: the init record's digest of it and the anchoring PCR.
fn check_anchor(rep: &mut Report, p: &Parse, expect: &AttestExpect) {
    let mut anchor = [0u8; ANCHOR_MAX];
    let mut anchor_digest = [0u8; 32];

    let mut named = chain::anchor(&p.init.name, &mut anchor) == 0
        && sha256_into(cstr(&anchor), &mut anchor_digest) == 0;
    rep.check(
        named && !memneq_explicit(&anchor_digest, &p.init.anchor_digest),
        b"anchor: record digest matches the index name",
    );
    let mut pcr_expected = p.init.pcr_before;
    named = chain::fold(&mut pcr_expected, &anchor_digest) == 0 && named;
    if p.pcr_have & (1 << CHAIN_PCR) == 0 {
        rep.check(
            false,
            format!("anchor: PCR {CHAIN_PCR} is not in the quote").as_bytes(),
        );
        return;
    }
    let exact = named && !memneq_explicit(&pcr_expected, &p.pcrs[CHAIN_PCR as usize]);
    if exact || expect.strict_anchor {
        rep.check(
            exact,
            format!("anchor: PCR {CHAIN_PCR} equals the recorded value extended by the anchor")
                .as_bytes(),
        );
    } else {
        rep.note(
            format!(
                "anchor: PCR {CHAIN_PCR} carries further measurements after the anchor; replay the logs to confirm it"
            )
            .as_bytes(),
        );
    }
}

/// The register's state against the one expected, and the events after
/// boot named.
fn check_state(rep: &mut Report, p: &Parse, expect: &AttestExpect, value: &[u8; 32]) {
    let runtime = p.recs.len().saturating_sub(1);

    if let Some(init_event) = &expect.init_event {
        rep.check(
            !memneq_explicit(&p.init.digest, init_event),
            b"state: init event covers the expected certificate, set and tree root",
        );
    }
    if let Some(chain_value) = &expect.chain {
        rep.check(
            !memneq_explicit(value, chain_value),
            b"state: register equals the expected value",
        );
    } else if let Some(init_event) = &expect.init_event {
        let mut predicted = [0u8; 32];
        let folded = chain::fold(&mut predicted, init_event) == 0;

        if runtime == 0 {
            rep.check(
                folded && !memneq_explicit(value, &predicted),
                b"state: register equals the value predicted for the set at boot",
            );
        } else {
            let plural = if runtime == 1 { "" } else { "s" };

            rep.check(
                expect.allow_runtime_events,
                format!("state: {runtime} event{plural} after boot change the register").as_bytes(),
            );
        }
    } else {
        rep.note(
            &[
                b"no expected state given; the register value is ",
                cstr(&p.reg_value_hex),
            ]
            .concat(),
        );
    }
    for r in p.recs.iter().skip(1) {
        rep.note(&[b"event after boot: ", &r.ty[..], b" ", &r.label].concat());
    }
}

/// What a challenge's document gives, in hex.
struct ChallengeJson {
    blob_hex: [u8; 2 * ID_OBJECT_LEN + 1],
    secret_hex: [u8; 2 * SECRET_MAX + 1],
    ak_hex: [u8; 2 * NAME_LEN + 1],
    kind: [u8; 32],
    ty: [u8; 8],
}

/// The challenge an operator made, from the file at `path`: -EINVAL for
/// a document that is not one, or the error of reading it.
pub(crate) fn challenge_read(path: &CStr) -> Result<AttestChallenge, c_int> {
    let mut json = ChallengeJson {
        blob_hex: [0; 2 * ID_OBJECT_LEN + 1],
        secret_hex: [0; 2 * SECRET_MAX + 1],
        ak_hex: [0; 2 * NAME_LEN + 1],
        kind: [0; 32],
        ty: [0; 8],
    };
    let ek_sub = [JsonField::string(c"type", |c: &mut ChallengeJson| {
        &mut c.ty
    })];
    let top = [
        JsonField::string(c"kind", |c: &mut ChallengeJson| &mut c.kind),
        JsonField::object(c"ek", &ek_sub),
        JsonField::string(c"ak_name", |c| &mut c.ak_hex),
        JsonField::string(c"credential_blob", |c| &mut c.blob_hex),
        JsonField::string(c"secret", |c| &mut c.secret_hex),
    ];
    let mut secret = [0u8; SECRET_MAX];

    let doc = io::read(path, CHALLENGE_MAX)?;
    let parsed = parse_schema(&doc, &top, &mut json);
    if parsed.is_err()
        || !top[0].seen()
        || cstr(&json.kind) != b"shirudo-credential"
        || !ek_sub[0].seen()
        || !top[2].seen()
        || !top[3].seen()
        || !top[4].seen()
    {
        return Err(-EINVAL);
    }
    let ek_rsa = match cstr(&json.ty) {
        b"rsa" => true,
        b"ecc" => false,
        _ => return Err(-EINVAL),
    };
    let mut challenge = AttestChallenge {
        ek_rsa,
        ak_name: [0; NAME_LEN],
        blob: [0; ID_OBJECT_LEN],
        secret: Vec::new(),
    };
    if !hex_into(&json.ak_hex, &mut challenge.ak_name)
        || !hex_into(&json.blob_hex, &mut challenge.blob)
    {
        return Err(-EINVAL);
    }
    let secret = hex_text(&json.secret_hex, &mut secret)?;
    if secret.is_empty() {
        return Err(-EINVAL);
    }
    challenge.secret = secret.to_vec();
    Ok(challenge)
}

/// Whether the certificate's key is the endorsement key of the evidence.
fn cert_describes(key: &CertPubkey, public: &TpmPublic) -> bool {
    let rsa = public.ty == ALG_RSA;

    if key.rsa != rsa {
        return false;
    }
    if key.rsa {
        let e = if public.rsa_exponent != 0 {
            public.rsa_exponent
        } else {
            65537
        };

        let (Some(key_n), Some(public_n)) = (key.n.get(..key.n_len), public.n.get(..public.n_len))
        else {
            return false;
        };
        return key.n_len == public.n_len && !memneq_explicit(key_n, public_n) && key.e == e;
    }
    !memneq_explicit(&key.x, &public.x) && !memneq_explicit(&key.y, &public.y)
}

/// A challenge made: the document that carries it, and the credential
/// the target recovers with it, on the heap so that it is scrubbed when
/// it goes.
pub(crate) struct MadeChallenge {
    pub(crate) document: Vec<u8>,
    pub(crate) credential: Box<[u8; CREDENTIAL_LEN]>,
}

/// The seed a credential is protected under, and the ECDH secret it is
/// derived from, on the heap so that they are scrubbed when they go.
struct Seed {
    seed: [u8; 32],
    z: [u8; 32],
}

/// What the evidence gives of its keys, in hex, and of its EK certificate
/// in base64.
struct KeysJson {
    ek_public_hex: [u8; 2 * PUBLIC_MAX + 1],
    ak_hex: [u8; 2 * NAME_LEN + 1],
    ek_type: [u8; 8],
    ek_name_hex: [u8; 2 * NAME_LEN + 1],
    cert_b64: Vec<u8>,
}

/// The keys of the evidence a challenge is made for.
struct ChallengeKeys {
    json: Box<KeysJson>,
    rsa: bool,
    ak_name: [u8; NAME_LEN],
    ek_name: [u8; NAME_LEN],
    ek_public: Vec<u8>,
    public: TpmPublic,
    /// The evidence carries an EK certificate.
    have_cert: bool,
}

/// The keys the evidence names: -EINVAL for a document without them
/// whole, or with an endorsement key not of the type it names.
fn challenge_keys(evidence: &[u8]) -> Result<ChallengeKeys, c_int> {
    let mut json = Box::new(KeysJson {
        ek_public_hex: [0; 2 * PUBLIC_MAX + 1],
        ak_hex: [0; 2 * NAME_LEN + 1],
        ek_type: [0; 8],
        ek_name_hex: [0; 2 * NAME_LEN + 1],
        cert_b64: vec![0; EK_CERT_B64_MAX],
    });
    let ak_sub = [JsonField::string(c"name", |k: &mut KeysJson| &mut k.ak_hex)];
    let ek_sub = [
        JsonField::string(c"type", |k: &mut KeysJson| &mut k.ek_type),
        JsonField::string(c"public", |k| &mut k.ek_public_hex),
        JsonField::string(c"name", |k| &mut k.ek_name_hex),
    ];
    let top = [
        JsonField::object(c"ak", &ak_sub),
        JsonField::object(c"ek", &ek_sub),
        JsonField::string(c"ek_certificate", |k: &mut KeysJson| {
            k.cert_b64.as_mut_slice()
        }),
    ];
    let mut ak_name = [0u8; NAME_LEN];
    let mut ek_name = [0u8; NAME_LEN];
    let mut ek_public = [0u8; PUBLIC_MAX];
    let mut public = TpmPublic::zeroed();

    let parsed = parse_schema(evidence, &top, &mut *json);
    if parsed.is_err()
        || !ak_sub[0].seen()
        || !ek_sub[0].seen()
        || !ek_sub[1].seen()
        || !ek_sub[2].seen()
        || !hex_into(&json.ak_hex, &mut ak_name)
    {
        return Err(-EINVAL);
    }
    let ek_public = hex_text(&json.ek_public_hex, &mut ek_public)?;
    if !hex_into(&json.ek_name_hex, &mut ek_name) {
        return Err(-EINVAL);
    }
    let rsa = match cstr(&json.ek_type) {
        b"rsa" => true,
        b"ecc" => false,
        _ => return Err(-EINVAL),
    };
    if public_parse(ek_public, &mut public) != 0 || public.ty != if rsa { ALG_RSA } else { ALG_ECC }
    {
        return Err(-EINVAL);
    }
    Ok(ChallengeKeys {
        rsa,
        ak_name,
        ek_name,
        ek_public: ek_public.to_vec(),
        public,
        have_cert: top[2].seen(),
        json,
    })
}

/// A certificate cert_read_der() reads into, owned until this value drops.
struct HeldCert(Cert);

/// The certificate in the base64 `b64` and its key: none when it does
/// not decode, parse or hold a key of the kinds a TPM's endorsement key
/// has.
fn ek_certificate(b64: &[u8]) -> Option<(HeldCert, CertPubkey)> {
    let mut der = vec![0u8; EK_CERT_MAX];
    let mut cert = HeldCert(Cert::new());
    let mut key = CertPubkey {
        rsa: false,
        n: [0; 512],
        n_len: 0,
        e: 0,
        x: [0; 32],
        y: [0; 32],
    };

    let der_len = base64_decode(b64, &mut der).ok()?;
    let der = der.get(..der_len)?;
    // SAFETY: the DER's bytes, and the certificate to read them into.
    if unsafe { cert_read_der(der.as_ptr(), der.len(), &mut cert.0) } != 0 {
        return None;
    }
    // SAFETY: the certificate read above, and room for its key.
    if unsafe { cert_pubkey(&cert.0, &mut key) } != 0 {
        return None;
    }
    Some((cert, key))
}

/// Whether the certificate chains to the issuer bundle at `bundle`: 0,
/// -EKEYREJECTED with libcrypto's reason, or -EINVAL for a bundle that
/// cannot be loaded.
fn cert_chains(cert: &HeldCert, bundle: &CStr) -> (c_int, &'static [u8]) {
    let mut reason: *const c_char = c"".as_ptr();

    // SAFETY: the certificate, the bundle's path, a C string, and where
    // the reason goes.
    let ret = unsafe { cert_verify_chain(&cert.0, bundle.as_ptr(), &mut reason) };
    // SAFETY: a static C string of libcrypto's, or the empty one above.
    (ret, unsafe { ffi::c_str(reason) })
}

/// The checks of the EK certificate the evidence carries, if any, into
/// the report.
fn check_ek_certificate(rep: &mut Report, pol: &AttestChallengePolicy, keys: &ChallengeKeys) {
    let vouched = pol.ek_name.is_some() || pol.trust_presented;

    if !keys.have_cert {
        if vouched {
            rep.note(b"no endorsement certificate: the endorsement key is trusted as presented");
        } else {
            rep.check(
                false,
                b"no endorsement certificate: pin the key with --ek-name or waive with --trust-presented-ek",
            );
        }
        return;
    }
    let Some((cert, key)) = ek_certificate(cstr(&keys.json.cert_b64)) else {
        rep.check(
            false,
            b"endorsement certificate: parseable with a P-256 or RSA-2048 key",
        );
        return;
    };
    rep.check(
        cert_describes(&key, &keys.public),
        b"endorsement certificate: describes the endorsement key",
    );
    let Some(bundle) = pol.ek_ca else {
        if vouched {
            rep.note(b"endorsement certificate: not checked against an issuer bundle (--ek-ca)");
        } else {
            rep.check(
                false,
                b"endorsement certificate: not checked against an issuer bundle; pass --ek-ca, pin the key with --ek-name or waive with --trust-presented-ek",
            );
        }
        return;
    };
    let (ret, reason) = cert_chains(&cert, bundle);
    if ret == -EINVAL {
        rep.check(
            false,
            &[
                b"endorsement certificate: issuer bundle ",
                bundle.to_bytes(),
                b" unreadable",
            ]
            .concat(),
        );
        return;
    }
    let (sep, why): (&[u8], &[u8]) = if ret != 0 {
        (b": ", reason)
    } else {
        (b"", b"")
    };
    rep.check(
        ret == 0,
        &[
            b"endorsement certificate: chains to ",
            bundle.to_bytes(),
            sep,
            why,
        ]
        .concat(),
    );
}

/// `buf` filled from the kernel's random source: -EIO where it gives
/// less.
fn random(buf: &mut [u8]) -> Result<(), c_int> {
    // SAFETY: the room of buf, of its length.
    let got = unsafe { getrandom(buf.as_mut_ptr().cast(), buf.len(), 0) };
    if usize::try_from(got) != Ok(buf.len()) {
        return Err(-EIO);
    }
    Ok(())
}

/// The secret that carries the seed to the endorsement key `public`,
/// the seed into `seed`: RSA-OAEP of a random seed, or the ephemeral
/// point of an ECDH whose secret the seed derives from.
fn seal_seed(rsa: bool, public: &TpmPublic, seed: &mut Seed) -> Result<Vec<u8>, c_int> {
    if rsa {
        random(&mut seed.seed)?;
        let n = public.n.get(..public.n_len).ok_or(-EIO)?;
        let mut secret = [0u8; 256];
        let secret_len = rsa_oaep_encrypt(
            n,
            public.rsa_exponent,
            IDENTITY.to_bytes_with_nul(),
            &seed.seed,
            &mut secret,
        )
        .map_err(|_| -EIO)?;
        return secret.get(..secret_len).map(<[u8]>::to_vec).ok_or(-EIO);
    }
    let (mut eph_x, mut eph_y) = ([0u8; 32], [0u8; 32]);
    if ecdh_p256_ephemeral(&public.x, &public.y, &mut eph_x, &mut eph_y, &mut seed.z) != 0
        || kdfe(
            &seed.z,
            IDENTITY.to_bytes(),
            &eph_x,
            &public.x,
            &mut seed.seed,
        ) != 0
    {
        return Err(-EIO);
    }
    Ok([&[0, 32][..], &eph_x, &[0, 32], &eph_y].concat())
}

/// attest challenge: after the checks the policy asks for, into the
/// report, a credential the target recovers only with the attestation
/// key the evidence names under its endorsement key, and the challenge
/// that carries it: -EKEYREJECTED when a check failed, -EINVAL for
/// evidence without the keys.
pub(crate) fn challenge_make(
    evidence: &[u8],
    pol: &AttestChallengePolicy,
    rep: &mut Report,
) -> Result<MadeChallenge, c_int> {
    let mut computed = [0u8; NAME_LEN];
    let mut blob = [0u8; ID_OBJECT_LEN];
    let mut credential = Box::new([0u8; CREDENTIAL_LEN]);
    let mut seed = Box::new(Seed {
        seed: [0; 32],
        z: [0; 32],
    });

    let keys = challenge_keys(evidence)?;
    // The operator's pins come first: the challenge is for the key the
    // operator enrolled, not for whatever the document names.
    if let Some(pinned) = &pol.ak_name {
        rep.check(
            !memneq_explicit(&keys.ak_name, pinned),
            b"attestation key: the pinned key",
        );
    }
    if let Some(pinned) = &pol.ek_name {
        rep.check(
            !memneq_explicit(&keys.ek_name, pinned),
            b"endorsement key: the pinned key",
        );
    }

    // The key must be an endorsement key, not any decryption key.
    let named = object_name(&keys.ek_public, &mut computed) == 0;
    rep.check(
        named && !memneq_explicit(&computed, &keys.ek_name),
        b"endorsement key: name matches its public area",
    );
    rep.check(
        endorsement_template(&keys.public),
        b"endorsement key: TCG default template under the endorsement policy",
    );
    check_ek_certificate(rep, pol, &keys);
    if rep.failed != 0 {
        return Err(-EKEYREJECTED);
    }

    random(&mut credential[..])?;
    let secret = seal_seed(keys.rsa, &keys.public, &mut seed)?;
    if credential_protect(&seed.seed, &keys.ak_name, &credential, &mut blob) != 0 {
        return Err(-EIO);
    }
    let document = challenge_document(&keys, &blob, &secret)?;
    Ok(MadeChallenge {
        document,
        credential,
    })
}

/// The challenge's document: the keys as the evidence named them, the
/// credential's blob and the secret.
fn challenge_document(
    keys: &ChallengeKeys,
    blob: &[u8; ID_OBJECT_LEN],
    secret: &[u8],
) -> Result<Vec<u8>, c_int> {
    let mut room = [0u8; CHALLENGE_DOC_MAX];
    let mut e = JsonEmit::fixed(&mut room);

    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_string(b"kind", b"shirudo-credential");
    e.obj_open_key(b"ek");
    e.kv_string(b"type", if keys.rsa { b"rsa" } else { b"ecc" });
    e.kv_string(b"name", cstr(&keys.json.ek_name_hex));
    e.obj_close();
    e.kv_string(b"ak_name", cstr(&keys.json.ak_hex));
    e.kv_string(b"credential_blob", &encode(blob));
    e.kv_string(b"secret", &encode(secret));
    e.obj_close();
    e.finish()
}

/// `--pcrs`: PCRs 0 to 23 apart by commas, as a mask; -EINVAL for
/// anything else, an empty list among it.
pub(crate) fn parse_pcrs(list: &[u8]) -> Result<u32, c_int> {
    let mut mask = 0u32;
    let mut rest = list;

    while !rest.is_empty() {
        let (number, after) = rest.split_at(digits(rest));
        let pcr = parse_u64(number, 23).map_err(|_| -EINVAL)?;

        mask |= 1 << pcr;
        rest = match after {
            [b',', next @ ..] if !next.is_empty() => next,
            [] => after,
            _ => return Err(-EINVAL),
        };
    }
    if mask == 0 {
        return Err(-EINVAL);
    }
    Ok(mask)
}

/// `<pcr>=<value>`: the PCR, below 24, and the text of its value after
/// the equals sign; -EINVAL for anything else.
pub(crate) fn parse_pcr_value(arg: &[u8]) -> Result<(usize, &[u8]), c_int> {
    let (number, rest) = arg.split_at(digits(arg));
    let (Some(value), Ok(pcr)) = (rest.strip_prefix(b"="), parse_u64(number, 23)) else {
        return Err(-EINVAL);
    };
    let pcr = usize::try_from(pcr).map_err(|_| -EINVAL)?;

    Ok((pcr, value))
}

/// `<name>=<digest>`: a name of 1 to UPATCH_NAME_MAX bytes up to the
/// first equals sign, then the 64 hex digits of the digest; -EINVAL for
/// anything else.
pub(crate) fn parse_name_digest(spec: &[u8]) -> Result<(&[u8], [u8; 32]), c_int> {
    let mut parts = spec.splitn(2, |&c| c == b'=');
    let mut digest = [0u8; 32];

    let (Some(name), Some(hex)) = (parts.next(), parts.next()) else {
        return Err(-EINVAL);
    };
    if name.is_empty() || name.len() > UPATCH_NAME_MAX || decode(hex, &mut digest).is_err() {
        return Err(-EINVAL);
    }
    Ok((name, digest))
}

#[cfg(shirudo_fuzz)]
mod fuzz;
#[cfg(test)]
mod tests;
