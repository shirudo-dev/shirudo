// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The libtss2 client: the
//! measurement register and its NV writer key, PCRs, the endorsement and
//! attestation keys, quotes, certifications and credentials. Every
//! command goes through a salted HMAC session bound to the endorsement
//! key init froze.

use core::ffi::{CStr, c_int};
use core::mem::ManuallyDrop;
use core::ptr;
use std::ffi::CString;

use crate::errno::{
    E2BIG, EACCES, EINVAL, EIO, EKEYREJECTED, ENODATA, ENODEV, ENOENT, EPROTO, EPROTONOSUPPORT,
    text,
};
use crate::sys::identity::Identity;
use crate::sys::libc::{env, errno, scrub, setenv, unsetenv};
use crate::sys::tss2::*;
use crate::text::cstr;
use crate::util::config::{self, Scrubbed};
use crate::util::identity;
use crate::util::image_config;
use crate::util::tpm_wire::{
    EK_POLICY, TpmPublic, nv_extend_cphash, object_name, policy_nv_written, policy_or,
    public_marshal, register_policy_final, writer_auth_hash, writer_public,
};

const EK_CERT_NV_RSA: u32 = 0x01C0_0002;
const EK_CERT_NV_ECC: u32 = 0x01C0_000A;
const NV_READ_CHUNK: usize = 512;
const NVPCR_WRITE_AUTH: u32 = 0x7;
const NVPCR_POLICY_WRITE: u32 = 0x8;
const NVPCR_TYPE_MASK: u32 = 0xf0;
const NVPCR_TYPE_EXTEND: u32 = 0x40;

/// The sizes of digests, names and the TPM's other records.
const DIGEST_LEN: usize = 32;
const NAME_LEN: usize = 34;
const NV_RSA_BYTES: usize = 384;
const NV_RSA_PUBLIC_AREA_LEN: usize = 408;
pub(crate) const PUBLIC_MAX: usize = 512;
pub(crate) const ATTEST_MAX: usize = 1024;
pub(crate) const SIGNATURE_MAX: usize = 160;
const PCR_SELECT_LEN: u8 = 3;
/// The longest TCTI a config names, with its NUL.
const TCTI_MAX: usize = 256;

/// The measurement register's NV attributes, the NV writer's object
/// attributes and the TCG endorsement key's.
pub(crate) const REGISTER_ATTRS: u32 = 0x0e06_0048;
const WRITER_ATTRS: u32 = 0x0004_0072;
pub(crate) const EK_ATTRS: u32 = 0x0003_00b2;
/// TPM_NV_POLICY_REF, without the NUL sizeof() counts.
const NV_POLICY_REF: &[u8] = b"shirudo-nv-writer-v1";
/// CONF_PATH of util/paths.h, which a message names.
const CONF_PATH: &CStr = c"/etc/shirudo/shirudo.conf";

/// The TCTI library's context, finalized when it goes.
struct Tcti(*mut TctiContext);

impl Tcti {
    /// The TCTI `conf` names, loaded: the loader's code on failure.
    fn load(conf: &CStr) -> Result<Self, Rc> {
        let mut context = ptr::null_mut();
        // SAFETY: a C string and room for the context the loader allocates.
        let ret = unsafe { Tss2_TctiLdr_Initialize(conf.as_ptr(), &mut context) };

        if ret != RC_SUCCESS {
            return Err(ret);
        }
        Ok(Tcti(context))
    }
}

impl Drop for Tcti {
    fn drop(&mut self) {
        // SAFETY: the context the loader gave, finalized once.
        unsafe { Tss2_TctiLdr_Finalize(&mut self.0) };
    }
}

/// An ESYS context and the TCTI it talks through, which outlives it:
/// the context is finalized first when it goes.
struct Esys {
    context: *mut EsysContext,
    /// Held for the context, which uses it until it is finalized.
    _tcti: Tcti,
}

impl Drop for Esys {
    fn drop(&mut self) {
        // SAFETY: the context Esys_Initialize() gave, finalized once and
        // before its TCTI.
        unsafe { Esys_Finalize(&mut self.context) };
    }
}

/// An output ESYS allocates for a command, freed with Esys_Free() when
/// it goes.
struct EsysOut<T>(*mut T);

impl<T> EsysOut<T> {
    fn new() -> Self {
        EsysOut(ptr::null_mut())
    }

    /// Where the command puts the output.
    fn room(&mut self) -> *mut *mut T {
        &mut self.0
    }

    /// The output, or None while ESYS has given none.
    fn get(&self) -> Option<&T> {
        // SAFETY: NULL, or the T a command allocated and filled through
        // room(), which stays until drop() frees it.
        unsafe { self.0.as_ref() }
    }

    /// The output to change, as get() gives it to read.
    fn get_mut(&mut self) -> Option<&mut T> {
        // SAFETY: as get(), and borrowed through this one's &mut alone.
        unsafe { self.0.as_mut() }
    }
}

impl<T> Drop for EsysOut<T> {
    fn drop(&mut self) {
        // SAFETY: NULL, which Esys_Free() takes, or what ESYS allocated,
        // freed once.
        unsafe { Esys_Free(self.0.cast()) };
    }
}

/// The NV writer a connection authorizes register writes with: the salt
/// of its key and the modulus init froze.
struct Writer {
    seed: [u8; DIGEST_LEN],
    public: [u8; NV_RSA_BYTES],
}

/// A connection to the TPM: its ESYS context, the salted HMAC session
/// every command goes through, the endorsement key that salts it, and
/// once set the NV writer. Dropping it flushes the session and then the
/// key and closes the context. The methods take `&self`, as what they
/// change is the TPM's and ESYS's, behind a raw pointer that keeps a
/// `Tpm` on its thread.
pub(crate) struct Tpm {
    esys: Esys,
    session: EsysTr,
    session_key: EsysTr,
    ek_name: [u8; NAME_LEN],
    /// On the heap, so that the seed is scrubbed when it goes.
    writer: Option<Box<Writer>>,
}

impl Drop for Tpm {
    fn drop(&mut self) {
        self.flush(self.session);
        self.flush(self.session_key);
    }
}

/// A key or session the TPM holds for a connection, flushed when it
/// goes.
pub(crate) struct Handle<'t> {
    tpm: &'t Tpm,
    handle: EsysTr,
}

impl Drop for Handle<'_> {
    fn drop(&mut self) {
        self.tpm.flush(self.handle);
    }
}

#[cfg(feature = "test-helpers")]
impl Handle<'_> {
    /// The ESYS handle, for a test helper's own commands.
    pub(crate) fn raw(&self) -> EsysTr {
        self.handle
    }

    /// Flushes the handle now: the TPM's code.
    pub(crate) fn flush(self) -> Rc {
        let this = ManuallyDrop::new(self);

        // SAFETY: the context and its handle, flushed here in place of the
        // drop that ManuallyDrop holds back.
        unsafe { Esys_FlushContext(this.tpm.context(), this.handle) }
    }
}

fn nvpcr_policy_valid(info: &NvInfo, policy: &[u8; DIGEST_LEN]) -> bool {
    info.defined
        && info.written
        && usize::from(info.data_size) == DIGEST_LEN
        && info.attrs & NVPCR_WRITE_AUTH == 0
        && info.attrs & NVPCR_POLICY_WRITE != 0
        && info.attrs & NVPCR_TYPE_MASK == NVPCR_TYPE_EXTEND
        && info.policy == *policy
}

/// What a key shows of itself: its marshalled TPMT_PUBLIC and its name.
#[derive(Clone)]
pub(crate) struct KeyPublic {
    pub(crate) area: Vec<u8>,
    pub(crate) name: [u8; NAME_LEN],
}

/// A primary key under the endorsement hierarchy, flushed when it goes,
/// with its public area and name.
pub(crate) struct Key<'t> {
    handle: Handle<'t>,
    public: KeyPublic,
}

impl Key<'_> {
    pub(crate) fn public(&self) -> &KeyPublic {
        &self.public
    }

    /// The handle, which the caller now owns, and the public parts.
    fn into_raw(self) -> (EsysTr, KeyPublic) {
        let Key { handle, public } = self;
        let handle = ManuallyDrop::new(handle);

        (handle.handle, public)
    }

    /// The ESYS handle, for a test helper's own commands.
    #[cfg(feature = "test-helpers")]
    pub(crate) fn raw(&self) -> EsysTr {
        self.handle.handle
    }
}

/// The ESYS handle of an NV index, closed when it goes.
struct NvIndex<'t> {
    tpm: &'t Tpm,
    handle: EsysTr,
}

impl Drop for NvIndex<'_> {
    fn drop(&mut self) {
        // SAFETY: the context and its handle of the index, closed once.
        unsafe { Esys_TR_Close(self.tpm.context(), &mut self.handle) };
    }
}

/// The owner hierarchy's password, set for the commands made while it
/// lives and cleared when it goes.
struct OwnerAuth<'t>(&'t Tpm);

impl Drop for OwnerAuth<'_> {
    fn drop(&mut self) {
        let empty = Tpm2bDigest::zeroed();

        // SAFETY: the context, a handle and an empty password.
        unsafe { Esys_TR_SetAuth(self.0.context(), ESYS_TR_RH_OWNER, &empty) };
    }
}

/// An NV index as the TPM describes it.
pub(crate) struct NvInfo {
    pub(crate) defined: bool,
    pub(crate) written: bool,
    pub(crate) attrs: u32,
    pub(crate) data_size: u16,
    pub(crate) policy: [u8; DIGEST_LEN],
    name: [u8; NAME_LEN],
    name_len: usize,
}

impl NvInfo {
    const UNDEFINED: NvInfo = NvInfo {
        defined: false,
        written: false,
        attrs: 0,
        data_size: 0,
        policy: [0; DIGEST_LEN],
        name: [0; NAME_LEN],
        name_len: 0,
    };

    /// The index's name, empty when the TPM gave one longer than a
    /// SHA-256 name.
    pub(crate) fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// A quote or a certification as the TPM marshalled it, and the
/// attestation key's TPMT_SIGNATURE over it.
pub(crate) struct Attestation {
    pub(crate) attest: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

/// What the NV writer signs to authorize one NV_Extend.
pub(crate) struct WriterAuthorization {
    nonce: Tpm2bDigest,
    cphash: Tpm2bDigest,
    pub(crate) digest: [u8; DIGEST_LEN],
}

/// The branches of a register write.
pub(crate) struct Branches<'a> {
    pub(crate) written: &'a [u8; DIGEST_LEN],
    pub(crate) init: &'a [u8; DIGEST_LEN],
}

/// The TCTI: SHIRUDO_TPM_TCTI or the configuration's before an
/// authenticated image is active, so tests can pick a software TPM, and
/// a device TCTI once one is. -EACCES for another, -E2BIG for one of
/// TCTI_MAX bytes or more.
pub(crate) fn tcti() -> Result<CString, c_int> {
    let active = image_config::active();
    let mut cfg = Scrubbed::new();
    let named = if active {
        None
    } else {
        env(c"SHIRUDO_TPM_TCTI").filter(|t| !t.is_empty())
    };
    let value = match named {
        Some(t) => t.to_bytes(),
        None if config::load(&mut cfg) == 0 && cfg.tpm_tcti[0] != 0 => cstr(&cfg.tpm_tcti),
        None => b"device:/dev/tpmrm0",
    };

    if active && !value.starts_with(b"device:") {
        return Err(-EACCES);
    }
    if value.len() >= TCTI_MAX {
        return Err(-E2BIG);
    }
    CString::new(value).map_err(|_| -EINVAL)
}

/// The library's logging off, since that can expose session keys even
/// during bootstrap.
fn library_logging_off() -> Result<(), c_int> {
    // SAFETY: two C strings; the environment is this command's alone.
    let mut set = unsafe { setenv(c"TSS2_LOG".as_ptr(), c"all+none".as_ptr(), 1) } == 0;

    if set {
        // SAFETY: a C string; the environment is this command's alone.
        set = unsafe { unsetenv(c"TSS2_LOGFILE".as_ptr()) } == 0;
    }
    if !set {
        let e = -errno();

        crate::log::err(format!("tpm: cannot disable library logging: {}", text(e)).as_bytes());
        return Err(e);
    }
    Ok(())
}

/// Whether `ret` is the TPM's `code`, of either format.
fn rc_is(ret: Rc, code: Rc) -> bool {
    if ret & 0xFFFF_0000 != 0 {
        return false; // not a TPM-layer code
    }
    if ret & RC_FMT1 != 0 {
        return (ret & 0x0BF) == (code & 0x0BF);
    }
    (ret & 0xFFF) == code
}

fn rc_is_auth_failure(ret: Rc) -> bool {
    rc_is(ret, RC_BAD_AUTH)
        || rc_is(ret, RC_AUTH_FAIL)
        || rc_is(ret, RC_NV_AUTHORIZATION)
        || rc_is(ret, RC_POLICY_FAIL)
}

/// The SHA-256 bank's PCRs of `mask`.
fn pcr_selection(mask: u32) -> PcrSelectionList {
    let mut sel = PcrSelectionList::zeroed();
    let [low, middle, high, _] = mask.to_le_bytes();

    sel.count = 1;
    sel.pcrSelections[0].hash = ALG_SHA256;
    sel.pcrSelections[0].sizeofSelect = PCR_SELECT_LEN;
    sel.pcrSelections[0].pcrSelect[..3].copy_from_slice(&[low, middle, high]);
    sel
}

/// `data` as a TPM2B_DIGEST.
fn digest2b(data: &[u8]) -> Result<Tpm2bDigest, c_int> {
    let mut digest = Tpm2bDigest::zeroed();
    let (Some(room), Ok(size)) = (
        digest.buffer.get_mut(..data.len()),
        u16::try_from(data.len()),
    ) else {
        return Err(-EINVAL);
    };

    room.copy_from_slice(data);
    digest.size = size;
    Ok(digest)
}

fn owner_auth_error(op: &CStr, index: u32, ret: Rc) -> c_int {
    if rc_is_auth_failure(ret) {
        crate::log::err(
            &[
                &b"tpm: "[..],
                op.to_bytes(),
                b"(0x",
                format!("{index:08x}").as_bytes(),
                b"): owner-hierarchy authorization failed (rc=0x",
                format!("{ret:08x}").as_bytes(),
                b"). This TPM has owner auth set; supply it via tpm.owner_auth in ",
                CONF_PATH.to_bytes(),
                b" (or SHIRUDO_TPM_OWNER_AUTH), or clear the TPM owner auth.",
            ]
            .concat(),
        );
        return -EACCES;
    }
    crate::log::err(
        &[
            &b"tpm: "[..],
            op.to_bytes(),
            b"(0x",
            format!("{index:08x}").as_bytes(),
            b"): rc=0x",
            format!("{ret:08x}").as_bytes(),
        ]
        .concat(),
    );
    -EIO
}

/// The marshalled TPMT_PUBLIC of a key shirudo makes, from the area ESYS
/// gave.
fn public_from_tss(p: &Public) -> Result<Vec<u8>, c_int> {
    let mut public = TpmPublic::zeroed();
    let mut out = [0u8; PUBLIC_MAX];
    let mut len = 0;

    if p.nameAlg != ALG_SHA256 || p.authPolicy.size > 32 {
        return Err(-EINVAL);
    }
    public.ty = p.type_;
    public.attrs = p.objectAttributes;
    public.policy_len = usize::from(p.authPolicy.size);
    public.policy[..public.policy_len].copy_from_slice(&p.authPolicy.buffer[..public.policy_len]);
    if p.type_ == ALG_ECC {
        ecc_public_from_tss(p, &mut public)?;
    } else if p.type_ == ALG_RSA {
        rsa_public_from_tss(p, &mut public)?;
    } else {
        return Err(-EPROTONOSUPPORT);
    }
    let e = public_marshal(&public, &mut out, &mut len);

    if e != 0 {
        return Err(e);
    }
    out.get(..len).map(<[u8]>::to_vec).ok_or(-EINVAL)
}

/// An ECC key's parameters and point into `public`.
fn ecc_public_from_tss(p: &Public, public: &mut TpmPublic) -> Result<(), c_int> {
    // SAFETY: the ECC parameters, which the key's type says it has.
    let ecc = unsafe { &p.parameters.eccDetail };
    // SAFETY: the ECC point, likewise.
    let point = unsafe { &p.unique.ecc };

    public.sym_alg = ecc.symmetric.algorithm;
    if public.sym_alg != ALG_NULL {
        // SAFETY: a symmetric definition's bits, integers of which any
        // bits are a value, as the C read them whatever the algorithm.
        public.sym_bits = unsafe { ecc.symmetric.keyBits.sym };
        // SAFETY: its mode, likewise.
        public.sym_mode = unsafe { ecc.symmetric.mode.sym };
    }
    public.scheme = ecc.scheme.scheme;
    if public.scheme != ALG_NULL {
        // SAFETY: every scheme of a key holds its hash first.
        public.scheme_hash = unsafe { ecc.scheme.details.anySig.hashAlg };
    }
    public.curve = ecc.curveID;
    if ecc.kdf.scheme != ALG_NULL || point.x.size != 32 || point.y.size != 32 {
        return Err(-EINVAL);
    }
    public.x.copy_from_slice(&point.x.buffer[..32]);
    public.y.copy_from_slice(&point.y.buffer[..32]);
    Ok(())
}

/// An RSA key's parameters and modulus into `public`.
fn rsa_public_from_tss(p: &Public, public: &mut TpmPublic) -> Result<(), c_int> {
    // SAFETY: the RSA parameters, which the key's type says it has.
    let rsa = unsafe { &p.parameters.rsaDetail };
    // SAFETY: the modulus, likewise.
    let n = unsafe { &p.unique.rsa };

    public.sym_alg = rsa.symmetric.algorithm;
    if public.sym_alg != ALG_NULL {
        // SAFETY: a symmetric definition's bits, integers of which any
        // bits are a value, as the C read them whatever the algorithm.
        public.sym_bits = unsafe { rsa.symmetric.keyBits.sym };
        // SAFETY: its mode, likewise.
        public.sym_mode = unsafe { rsa.symmetric.mode.sym };
    }
    public.scheme = rsa.scheme.scheme;
    if public.scheme != ALG_NULL {
        // SAFETY: every scheme of a key holds its hash first.
        public.scheme_hash = unsafe { rsa.scheme.details.anySig.hashAlg };
    }
    public.rsa_bits = rsa.keyBits;
    public.rsa_exponent = rsa.exponent;
    let Some(modulus) = n
        .buffer
        .get(..usize::from(n.size))
        .filter(|m| m.len() <= public.n.len())
    else {
        return Err(-EINVAL);
    };
    public.n_len = modulus.len();
    public.n[..modulus.len()].copy_from_slice(modulus);
    Ok(())
}

/// `data` as a TPM2B: its size, most significant byte first, and itself.
fn put2b(out: &mut Vec<u8>, data: &[u8]) -> Result<(), c_int> {
    let size = u16::try_from(data.len()).map_err(|_| -EINVAL)?;

    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

/// A P-256 ECDSA signature's r or s, of at most 64 bytes.
fn signature_half(p: &Tpm2bEccParameter) -> Option<&[u8]> {
    p.buffer
        .get(..usize::from(p.size))
        .filter(|half| half.len() <= 64)
}

/// An ECDSA signature as TPMT_SIGNATURE.
fn marshal_signature(sig: &Signature) -> Result<Vec<u8>, c_int> {
    // SAFETY: the ECDSA variant, integers and arrays of them of which any
    // bits are a value; used only once the algorithm says ECDSA.
    let e = unsafe { &sig.signature.ecdsa };
    let (true, Some(r), Some(s)) = (
        sig.sigAlg == ALG_ECDSA,
        signature_half(&e.signatureR),
        signature_half(&e.signatureS),
    ) else {
        return Err(-EINVAL);
    };
    let mut out = Vec::with_capacity(SIGNATURE_MAX);

    out.extend_from_slice(&sig.sigAlg.to_be_bytes());
    out.extend_from_slice(&e.hash.to_be_bytes());
    put2b(&mut out, r)?;
    put2b(&mut out, s)?;
    Ok(out)
}

/// An attestation and its signature as ESYS gave them: -E2BIG for one
/// longer than ATTEST_MAX.
fn attestation(
    attest: &EsysOut<Tpm2bAttest>,
    sig: &EsysOut<Signature>,
) -> Result<Attestation, c_int> {
    let (Some(attest), Some(sig)) = (attest.get(), sig.get()) else {
        return Err(-EPROTO);
    };
    let Some(data) = attest
        .attestationData
        .get(..usize::from(attest.size))
        .filter(|a| a.len() <= ATTEST_MAX)
    else {
        return Err(-E2BIG);
    };

    Ok(Attestation {
        attest: data.to_vec(),
        signature: marshal_signature(sig)?,
    })
}

/// The caller's nonce as qualifying data: -EINVAL for one too long.
fn qualifying(nonce: &[u8]) -> Result<Tpm2bData, c_int> {
    let mut qual = Tpm2bData::zeroed();
    let (Some(room), Ok(size)) = (
        qual.buffer.get_mut(..nonce.len()),
        u16::try_from(nonce.len()),
    ) else {
        return Err(-EINVAL);
    };

    room.copy_from_slice(nonce);
    qual.size = size;
    Ok(qual)
}

impl Tpm {
    /// Opens the TPM.
    pub(crate) fn open() -> Result<Tpm, c_int> {
        Self::open_logged(false)
    }

    /// Opens the TPM without the messages of one that is not there.
    pub(crate) fn open_quiet() -> Result<Tpm, c_int> {
        Self::open_logged(true)
    }

    fn open_logged(quiet: bool) -> Result<Tpm, c_int> {
        let active = identity::enforcement_active();

        if active < 0 {
            crate::log::err(
                format!("tpm: cannot determine enforcement state: {}", text(active)).as_bytes(),
            );
            return Err(active);
        }
        library_logging_off()?;
        let conf = tcti().inspect_err(|&e| {
            if !quiet && e == -EACCES {
                crate::log::err(b"tpm: authenticated runtime requires a device TCTI");
            } else if !quiet {
                crate::log::err(
                    format!("tpm: the TCTI is longer than {} bytes", TCTI_MAX - 1).as_bytes(),
                );
            }
        })?;
        let tcti = Tcti::load(&conf).map_err(|ret| {
            if !quiet {
                crate::log::err(
                    &[
                        &b"tpm: TctiLdr_Initialize("[..],
                        conf.to_bytes(),
                        b"): rc=0x",
                        format!("{ret:08x}").as_bytes(),
                    ]
                    .concat(),
                );
            }
            -EIO
        })?;
        let mut context = ptr::null_mut();
        // SAFETY: room for the context, over the TCTI, which the Esys made
        // of both keeps until it has finalized the context.
        let ret = unsafe { Esys_Initialize(&mut context, tcti.0, ptr::null_mut()) };

        if ret != RC_SUCCESS {
            if !quiet {
                crate::log::err(format!("tpm: Esys_Initialize: rc=0x{ret:08x}").as_bytes());
            }
            return Err(-EIO);
        }
        let mut tpm = Tpm {
            esys: Esys {
                context,
                _tcti: tcti,
            },
            session: ESYS_TR_NONE,
            session_key: ESYS_TR_NONE,
            ek_name: [0; NAME_LEN],
            writer: None,
        };

        tpm.session_setup(active != 0)?;
        Ok(tpm)
    }

    fn context(&self) -> *mut EsysContext {
        self.esys.context
    }

    /// Flushes `handle`, a key or session of the connection, unless it is
    /// ESYS_TR_NONE.
    fn flush(&self, handle: EsysTr) {
        if handle != ESYS_TR_NONE {
            // SAFETY: the context and its handle.
            unsafe { Esys_FlushContext(self.context(), handle) };
        }
    }

    /// The session key: the ECC endorsement key, which once enforcement
    /// is active must be the one init froze in the identity.
    fn session_setup(&mut self, active: bool) -> Result<(), c_int> {
        let id = if active {
            let id = match identity::read() {
                Ok(id) => id,
                Err(ret) => {
                    crate::log::err(
                        format!("tpm: frozen identity unreadable: {}", text(ret)).as_bytes(),
                    );
                    return Err(ret);
                }
            };
            if id.ek_name[0] != 0 || u16::from(id.ek_name[1]) != ALG_SHA256 {
                crate::log::err(b"tpm: no frozen session key; trusted reboot required");
                return Err(-EACCES);
            }
            id
        } else {
            Identity::zeroed()
        };
        let (key, public) = self.ek_create(false)?.into_raw();

        self.session_key = key;
        self.ek_name = public.name;
        if active && self.ek_name != id.ek_name {
            crate::log::err(b"tpm: not the TPM init bound (session key name differs)");
            return Err(-EACCES);
        }
        self.session = self.start_session(SE_HMAC)?;
        Ok(())
    }

    /// Starts a salted session bound to the session key: an audit HMAC
    /// session for commands without an authorization handle, or a policy
    /// session.
    fn start_session(&self, ty: u8) -> Result<EsysTr, c_int> {
        let sym = sym_def_null();
        let mut attrs = SESSION_CONTINUESESSION;
        let mut session = ESYS_TR_NONE;

        if ty == SE_HMAC {
            attrs |= SESSION_AUDIT;
        }
        // SAFETY: the context, handles, a template and room for the
        // session.
        let mut ret = unsafe {
            Esys_StartAuthSession(
                self.context(),
                self.session_key,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ptr::null(),
                ty,
                &sym,
                ALG_SHA256,
                &mut session,
            )
        };
        if ret == RC_SUCCESS {
            // SAFETY: the context and the session it started.
            ret = unsafe { Esys_TRSess_SetAttributes(self.context(), session, attrs, 0xff) };
        }
        if ret != RC_SUCCESS {
            crate::log::err(format!("tpm: start salted session: rc=0x{ret:08x}").as_bytes());
            self.flush(session);
            return Err(-EIO);
        }
        Ok(session)
    }

    /// A salted policy session, flushed when it goes.
    pub(crate) fn start_policy_session(&self) -> Result<Handle<'_>, c_int> {
        let handle = self.start_session(SE_POLICY)?;

        Ok(Handle { tpm: self, handle })
    }

    /// The name of the endorsement key that salts the sessions.
    pub(crate) fn ek_name(&self) -> &[u8; NAME_LEN] {
        &self.ek_name
    }

    /// The NV writer a register write is authorized by: -EACCES for a
    /// modulus whose top bit is clear, which is none.
    pub(crate) fn set_writer(
        &mut self,
        seed: &[u8; DIGEST_LEN],
        public: &[u8; NV_RSA_BYTES],
    ) -> Result<(), c_int> {
        if public[0] & 0x80 == 0 {
            crate::log::err(b"tpm: NV writer identity is required");
            return Err(-EACCES);
        }
        let writer = self.writer.insert(Box::new(Writer {
            seed: [0; DIGEST_LEN],
            public: [0; NV_RSA_BYTES],
        }));

        writer.seed.copy_from_slice(seed);
        writer.public.copy_from_slice(public);
        Ok(())
    }

    pub(crate) fn pcr_read(&self, pcr: u32) -> Result<[u8; DIGEST_LEN], c_int> {
        let mut values = EsysOut::<DigestList>::new();
        let mut counter = 0u32;

        if pcr >= 24 {
            return Err(-EINVAL);
        }
        let sel = pcr_selection(1 << pcr);
        // SAFETY: the context, handles, the selection and room for the
        // results.
        let ret = unsafe {
            Esys_PCR_Read(
                self.context(),
                self.session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &sel,
                &mut counter,
                ptr::null_mut(),
                values.room(),
            )
        };
        if ret != RC_SUCCESS {
            crate::log::err(format!("tpm: PCR_Read({pcr}): rc=0x{ret:08x}").as_bytes());
            return Err(-EIO);
        }
        match values.get() {
            Some(v) if v.count == 1 && usize::from(v.digests[0].size) == DIGEST_LEN => {
                let mut value = [0u8; DIGEST_LEN];

                value.copy_from_slice(&v.digests[0].buffer[..DIGEST_LEN]);
                Ok(value)
            }
            _ => {
                crate::log::err(format!("tpm: PCR {pcr} has no SHA-256 bank").as_bytes());
                Err(-ENOENT)
            }
        }
    }

    pub(crate) fn pcr_extend(&self, pcr: u32, digest: &[u8; DIGEST_LEN]) -> Result<(), c_int> {
        let mut dv = DigestValues::zeroed();

        dv.count = 1;
        if pcr >= 24 {
            return Err(-EINVAL);
        }
        dv.digests[0].hashAlg = ALG_SHA256;
        dv.digests[0].digest.sha256 = *digest;
        // SAFETY: the context, handles and the digests.
        let ret = unsafe {
            Esys_PCR_Extend(
                self.context(),
                ESYS_TR_PCR0 + pcr,
                self.session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &dv,
            )
        };

        if ret != RC_SUCCESS {
            crate::log::err(format!("tpm: PCR_Extend({pcr}): rc=0x{ret:08x}").as_bytes());
            return Err(-EIO);
        }
        Ok(())
    }

    /// The TPM's clock: its reset and restart counts.
    fn clock(&self) -> Result<(u32, u32), c_int> {
        let mut info = EsysOut::<TimeInfo>::new();
        // SAFETY: the context, handles and room for the time.
        let ret = unsafe {
            Esys_ReadClock(
                self.context(),
                self.session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                info.room(),
            )
        };

        if ret != RC_SUCCESS {
            crate::log::err(format!("tpm: ReadClock: rc=0x{ret:08x}").as_bytes());
            return Err(-EIO);
        }
        let c = &info.get().ok_or(-EPROTO)?.clockInfo;

        Ok((c.resetCount, c.restartCount))
    }

    /// The TPM's reset count.
    pub(crate) fn reset_count(&self) -> Result<u32, c_int> {
        self.clock().map(|(reset, _)| reset)
    }

    /// The TPM's reset and restart counts, which name this boot.
    pub(crate) fn boot_identity(&self) -> Result<(u32, u32), c_int> {
        self.clock()
    }

    /// The ESYS handle of the NV index: -ENOENT, quiet, for one not
    /// defined, or -EIO.
    fn nv_index(&self, index: u32) -> Result<NvIndex<'_>, c_int> {
        let mut handle = ESYS_TR_NONE;
        // SAFETY: the context, an index, handles and room for the handle.
        let ret = unsafe {
            Esys_TR_FromTPMPublic(
                self.context(),
                index,
                self.session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &mut handle,
            )
        };

        if rc_is(ret, RC_HANDLE) {
            return Err(-ENOENT); // quiet: undefined is normal
        }
        if ret != RC_SUCCESS {
            crate::log::err(
                format!("tpm: TR_FromTPMPublic(0x{index:08x}): rc=0x{ret:08x}").as_bytes(),
            );
            return Err(-EIO);
        }
        Ok(NvIndex { tpm: self, handle })
    }

    /// The NV index's state, `defined` false for one there is not.
    pub(crate) fn nv_info(&self, index: u32) -> Result<NvInfo, c_int> {
        let mut public = EsysOut::<Tpm2bNvPublic>::new();
        let mut name = EsysOut::<Tpm2bName>::new();
        let nv = match self.nv_index(index) {
            Err(e) if e == -ENOENT => return Ok(NvInfo::UNDEFINED),
            nv => nv?,
        };
        // SAFETY: the context, the index's handle, handles and room for
        // its public area and name.
        let ret = unsafe {
            Esys_NV_ReadPublic(
                self.context(),
                nv.handle,
                self.session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                public.room(),
                name.room(),
            )
        };

        drop(nv);
        if ret != RC_SUCCESS {
            crate::log::err(
                format!("tpm: NV_ReadPublic(0x{index:08x}): rc=0x{ret:08x}").as_bytes(),
            );
            return Err(-EIO);
        }
        let (Some(public), Some(name)) = (public.get(), name.get()) else {
            return Err(-EPROTO);
        };
        let p = &public.nvPublic;
        let mut info = NvInfo {
            defined: true,
            written: p.attributes & NV_WRITTEN != 0,
            attrs: p.attributes,
            data_size: p.dataSize,
            ..NvInfo::UNDEFINED
        };

        if usize::from(p.authPolicy.size) == DIGEST_LEN {
            info.policy
                .copy_from_slice(&p.authPolicy.buffer[..DIGEST_LEN]);
        }
        if let Some(given) = name
            .name
            .get(..usize::from(name.size))
            .filter(|n| n.len() <= NAME_LEN)
        {
            info.name[..given.len()].copy_from_slice(given);
            info.name_len = given.len();
        }
        Ok(info)
    }

    /// The owner hierarchy's password `auth` for the commands made while
    /// what this returns lives.
    fn owner_auth(&self, auth: &[u8]) -> Result<OwnerAuth<'_>, c_int> {
        let mut owner = digest2b(auth)?;
        // SAFETY: the context, a handle and the password, which ESYS
        // copies.
        let ret = unsafe { Esys_TR_SetAuth(self.context(), ESYS_TR_RH_OWNER, &owner) };

        scrub(&mut owner.buffer);
        if ret != RC_SUCCESS {
            crate::log::err(format!("tpm: TR_SetAuth(owner): rc=0x{ret:08x}").as_bytes());
            return Err(-EIO);
        }
        Ok(OwnerAuth(self))
    }

    pub(crate) fn nv_define(
        &self,
        index: u32,
        policy: &[u8; DIGEST_LEN],
        owner_auth: &[u8],
    ) -> Result<(), c_int> {
        let mut public = Tpm2bNvPublic::zeroed();
        let nv_auth = Tpm2bDigest::zeroed();
        let mut nv = ESYS_TR_NONE;
        let auth = self.owner_auth(owner_auth)?;

        public.nvPublic.nvIndex = index;
        public.nvPublic.nameAlg = ALG_SHA256;
        public.nvPublic.attributes = REGISTER_ATTRS;
        public.nvPublic.authPolicy = digest2b(policy)?;
        public.nvPublic.dataSize = DIGEST_LEN as u16;
        // SAFETY: the context, handles, the index's password and public
        // area, and room for its handle.
        let ret = unsafe {
            Esys_NV_DefineSpace(
                self.context(),
                ESYS_TR_RH_OWNER,
                self.session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &nv_auth,
                &public,
                &mut nv,
            )
        };
        drop(auth);
        if ret != RC_SUCCESS {
            return Err(owner_auth_error(c"NV_DefineSpace", index, ret));
        }
        drop(NvIndex {
            tpm: self,
            handle: nv,
        });
        Ok(())
    }

    pub(crate) fn nv_undefine(&self, index: u32, owner_auth: &[u8]) -> Result<(), c_int> {
        let nv = self.nv_index(index)?;
        let auth = self.owner_auth(owner_auth)?;
        // SAFETY: the context and handles.
        let ret = unsafe {
            Esys_NV_UndefineSpace(
                self.context(),
                ESYS_TR_RH_OWNER,
                nv.handle,
                self.session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
            )
        };

        drop(auth);
        if ret != RC_SUCCESS {
            drop(nv);
            return Err(owner_auth_error(c"NV_UndefineSpace", index, ret));
        }
        // ESYS released the index's handle with the index.
        core::mem::forget(nv);
        Ok(())
    }

    pub(crate) fn nv_read(&self, index: u32) -> Result<[u8; DIGEST_LEN], c_int> {
        let mut data = EsysOut::<Tpm2bMaxNvBuffer>::new();
        let nv = self.nv_index(index)?;
        // SAFETY: the context, handles and room for the data.
        let ret = unsafe {
            Esys_NV_Read(
                self.context(),
                nv.handle,
                nv.handle,
                self.session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                DIGEST_LEN as u16,
                0,
                data.room(),
            )
        };
        drop(nv);
        if rc_is(ret, RC_NV_UNINITIALIZED) {
            return Err(-ENODATA); // quiet: nothing written this boot
        }
        if ret != RC_SUCCESS {
            crate::log::err(format!("tpm: NV_Read(0x{index:08x}): rc=0x{ret:08x}").as_bytes());
            return Err(-EIO);
        }
        match data.get() {
            Some(d) if usize::from(d.size) == DIGEST_LEN => {
                let mut value = [0u8; DIGEST_LEN];

                value.copy_from_slice(&d.buffer[..DIGEST_LEN]);
                Ok(value)
            }
            d => {
                let size = d.map_or(0, |d| d.size);

                crate::log::err(
                    format!("tpm: NV_Read returned {size} bytes, expected {DIGEST_LEN}").as_bytes(),
                );
                Err(-EIO)
            }
        }
    }

    /// The command hash of the NV_Extend of `event` to the index named
    /// `name`, the TPM's nonce of `session`, and their digest, which the
    /// NV writer signs.
    pub(crate) fn writer_prepare(
        &self,
        session: &Handle<'_>,
        name: &[u8; NAME_LEN],
        event: &[u8; DIGEST_LEN],
    ) -> Result<WriterAuthorization, c_int> {
        let mut tpm_nonce = EsysOut::<Tpm2bDigest>::new();
        let mut cphash = [0u8; DIGEST_LEN];
        let e = nv_extend_cphash(name, event, &mut cphash);

        if e != 0 {
            crate::log::err(format!("tpm: compute NV_Extend command hash: {}", text(e)).as_bytes());
            return Err(e);
        }
        // SAFETY: the context, the session and room for its nonce.
        let ret =
            unsafe { Esys_TRSess_GetNonceTPM(self.context(), session.handle, tpm_nonce.room()) };
        let Some(&nonce) = tpm_nonce.get().filter(|_| ret == RC_SUCCESS) else {
            crate::log::err(format!("tpm: NV writer PolicySigned: rc=0x{ret:08x}").as_bytes());
            return Err(-EACCES);
        };
        let mut authorization = WriterAuthorization {
            nonce,
            cphash: digest2b(&cphash)?,
            digest: [0; DIGEST_LEN],
        };
        let e = match nonce.buffer.get(..usize::from(nonce.size)) {
            Some(nonce) => writer_auth_hash(nonce, &cphash, &mut authorization.digest),
            None => -EINVAL,
        };

        if e != 0 {
            crate::log::err(
                format!("tpm: compute NV writer authorization: {}", text(e)).as_bytes(),
            );
            return Err(e);
        }
        Ok(authorization)
    }

    /// The NV writer: an RSA primary under the owner hierarchy whose
    /// unique field the salt `seed` fills. The salt varies the key each
    /// boot, the owner seed reproduces it after a reset, and the frozen
    /// modulus `expected` refuses one made under another owner seed. The
    /// key, loaded until it goes, and its modulus.
    pub(crate) fn writer_primary(
        &self,
        seed: &[u8; DIGEST_LEN],
        expected: Option<&[u8; NV_RSA_BYTES]>,
    ) -> Result<(Handle<'_>, [u8; NV_RSA_BYTES]), c_int> {
        let creation_pcr = PcrSelectionList::zeroed();
        let sensitive = Tpm2bSensitiveCreate::zeroed();
        let mut out_pub = EsysOut::<Tpm2bPublic>::new();
        let mut in_pub = Tpm2bPublic::zeroed();
        let outside = Tpm2bData::zeroed();
        let mut handle = ESYS_TR_NONE;
        let auth = self.config_owner_auth()?;
        let p = &mut in_pub.publicArea;
        let mut rsa = Tpm2bPublicKeyRsa::zeroed();

        p.type_ = ALG_RSA;
        p.nameAlg = ALG_SHA256;
        p.objectAttributes = WRITER_ATTRS;
        p.parameters.rsaDetail = RsaParms {
            symmetric: sym_def(ALG_NULL, 0, 0),
            scheme: rsa_scheme(ALG_RSASSA, ALG_SHA256),
            keyBits: 3072,
            exponent: 65537,
        };
        rsa.size = DIGEST_LEN as u16;
        rsa.buffer[..DIGEST_LEN].copy_from_slice(seed);
        p.unique.rsa = rsa;
        // SAFETY: the context, handles, the templates, and room for the
        // handle and public area.
        let ret = unsafe {
            Esys_CreatePrimary(
                self.context(),
                ESYS_TR_RH_OWNER,
                self.session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &sensitive,
                &in_pub,
                &outside,
                &creation_pcr,
                &mut handle,
                out_pub.room(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        drop(auth);
        scrub(&mut rsa.buffer);
        // SAFETY: the RSA variant, which the template was filled with.
        scrub(unsafe { &mut in_pub.publicArea.unique.rsa.buffer });
        if ret != RC_SUCCESS {
            crate::log::err(format!("tpm: CreatePrimary(NV writer): rc=0x{ret:08x}").as_bytes());
            return Err(if rc_is_auth_failure(ret) {
                -EACCES
            } else {
                -EIO
            });
        }
        let key = Handle { tpm: self, handle };

        match self.writer_public(&out_pub, &key, expected) {
            Ok(public) => Ok((key, public)),
            Err(e) => {
                crate::log::err(b"tpm: NV writer public key differs from the expected key");
                Err(e)
            }
        }
    }

    /// The owner hierarchy's password of the configuration, set until
    /// what this returns goes.
    fn config_owner_auth(&self) -> Result<OwnerAuth<'_>, c_int> {
        let mut cfg = Scrubbed::new();
        let e = config::load(&mut cfg);
        let auth = if e == 0 {
            let c = &*cfg;

            match c.tpm_owner_auth.get(..c.tpm_owner_auth_len) {
                Some(auth) => self.owner_auth(auth),
                None => Err(-EINVAL),
            }
        } else {
            Err(e)
        };

        cfg.scrub();
        auth
    }

    /// The modulus of the writer `key` the TPM made, if it is the key
    /// shirudo asks for and, when given, the `expected` one.
    fn writer_public(
        &self,
        out_pub: &EsysOut<Tpm2bPublic>,
        key: &Handle<'_>,
        expected: Option<&[u8; NV_RSA_BYTES]>,
    ) -> Result<[u8; NV_RSA_BYTES], c_int> {
        let mut area = [0u8; NV_RSA_PUBLIC_AREA_LEN];
        let mut computed = [0u8; NAME_LEN];
        let mut public = [0u8; NV_RSA_BYTES];
        let p = &out_pub.get().ok_or(-EPROTO)?.publicArea;
        // SAFETY: the RSA parameters, integers of which any bits are
        // values, as the C read them whatever the type.
        let r = unsafe { &p.parameters.rsaDetail };
        // SAFETY: the modulus, likewise.
        let n = unsafe { &p.unique.rsa };
        let bad = p.type_ != ALG_RSA
            || p.nameAlg != ALG_SHA256
            || p.objectAttributes != WRITER_ATTRS
            || p.authPolicy.size != 0
            || r.symmetric.algorithm != ALG_NULL
            || r.scheme.scheme != ALG_RSASSA
            // SAFETY: every scheme of a key holds its hash first.
            || unsafe { r.scheme.details.anySig.hashAlg } != ALG_SHA256
            || r.keyBits != 3072
            || r.exponent != 65537
            || usize::from(n.size) != NV_RSA_BYTES;

        if bad {
            return Err(-EPROTO);
        }
        public.copy_from_slice(&n.buffer[..NV_RSA_BYTES]);
        if expected.is_some_and(|x| *x != public) {
            return Err(-EKEYREJECTED);
        }
        writer_public(&public, &mut area);
        let e = object_name(&area, &mut computed);

        if e != 0 {
            return Err(e);
        }
        if self.object_name(key.handle) != Some(computed) {
            return Err(-EPROTO);
        }
        Ok(public)
    }

    /// The name ESYS holds for the object `handle`, if it is a SHA-256
    /// name.
    fn object_name(&self, handle: EsysTr) -> Option<[u8; NAME_LEN]> {
        let mut name = EsysOut::<Tpm2bName>::new();
        // SAFETY: the context, the object and room for its name.
        let ret = unsafe { Esys_TR_GetName(self.context(), handle, name.room()) };
        let given = name.get().filter(|_| ret == RC_SUCCESS)?;

        given.name.get(..usize::from(given.size))?.try_into().ok()
    }

    /// Creates the NV writer of salt `seed` and flushes it: its modulus.
    pub(crate) fn writer_create(
        &self,
        seed: &[u8; DIGEST_LEN],
    ) -> Result<[u8; NV_RSA_BYTES], c_int> {
        self.writer_primary(seed, None).map(|(_, public)| public)
    }

    /// The NV writer's RSASSA signature over `hash`.
    fn writer_sign(
        &self,
        key: &Handle<'_>,
        hash: &[u8; DIGEST_LEN],
    ) -> Result<[u8; NV_RSA_BYTES], c_int> {
        let scheme = sig_scheme(ALG_RSASSA, ALG_SHA256);
        let mut signature = EsysOut::<Signature>::new();
        let mut validation = TkHashcheck::zeroed();
        let digest = digest2b(hash)?;

        validation.tag = ST_HASHCHECK;
        validation.hierarchy = RH_NULL;
        // SAFETY: the context, handles, the digest, scheme and ticket, and
        // room for the signature.
        let ret = unsafe {
            Esys_Sign(
                self.context(),
                key.handle,
                self.session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &digest,
                &scheme,
                &validation,
                signature.room(),
            )
        };
        if ret != RC_SUCCESS {
            crate::log::err(format!("tpm: Sign(NV writer): rc=0x{ret:08x}").as_bytes());
            return Err(-EACCES);
        }
        let s = signature
            .get()
            .filter(|s| s.sigAlg == ALG_RSASSA)
            .ok_or(-EPROTO)?;
        // SAFETY: the RSASSA variant, which the algorithm says the
        // signature holds.
        let rsassa = unsafe { &s.signature.rsassa };

        if rsassa.hash != ALG_SHA256 || usize::from(rsassa.sig.size) != NV_RSA_BYTES {
            return Err(-EPROTO);
        }
        let mut out = [0u8; NV_RSA_BYTES];

        out.copy_from_slice(&rsassa.sig.buffer[..NV_RSA_BYTES]);
        Ok(out)
    }

    /// TPM2_PolicySigned in `session` with the NV writer `key`'s signature
    /// over the authorization: the TPM's code.
    pub(crate) fn writer_authorize(
        &self,
        key: &Handle<'_>,
        session: &Handle<'_>,
        authorization: &WriterAuthorization,
        signature: &[u8; NV_RSA_BYTES],
    ) -> Rc {
        let mut timeout = EsysOut::<Tpm2bDigest>::new();
        let mut ticket = EsysOut::<TkAuth>::new();
        let mut policy_ref = Tpm2bDigest::zeroed();
        let mut sig = Signature::zeroed();
        let mut rsa = Tpm2bPublicKeyRsa::zeroed();

        policy_ref.size = NV_POLICY_REF.len() as u16;
        policy_ref.buffer[..NV_POLICY_REF.len()].copy_from_slice(NV_POLICY_REF);
        rsa.size = NV_RSA_BYTES as u16;
        rsa.buffer[..NV_RSA_BYTES].copy_from_slice(signature);
        sig.sigAlg = ALG_RSASSA;
        sig.signature.rsassa = SignatureRsa {
            hash: ALG_SHA256,
            sig: rsa,
        };
        // SAFETY: the context, handles, the authorization's nonce and
        // command hash, the reference and signature, and room for the
        // outputs.
        unsafe {
            Esys_PolicySigned(
                self.context(),
                key.handle,
                session.handle,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &authorization.nonce,
                &authorization.cphash,
                &policy_ref,
                0,
                &sig,
                timeout.room(),
                ticket.room(),
            )
        }
    }

    /// The policy session's PolicySigned by the NV writer over the exact
    /// NV_Extend of `event` to `index`.
    fn policy_writer_signed(
        &self,
        session: &Handle<'_>,
        index: u32,
        event: &[u8; DIGEST_LEN],
    ) -> Result<(), c_int> {
        let Some(writer) = self.writer.as_deref() else {
            return Err(-EKEYREJECTED);
        };
        let nv = self.nv_info(index)?;
        let name = match <[u8; NAME_LEN]>::try_from(nv.name()) {
            Ok(name) if nv.defined => name,
            _ => {
                crate::log::err(b"tpm: NV writer requires a defined register");
                return Err(-ENODEV);
            }
        };
        let authorization = self.writer_prepare(session, &name, event)?;
        let (key, _) = self.writer_primary(&writer.seed, Some(&writer.public))?;
        let mut signature = self.writer_sign(&key, &authorization.digest);
        let authorized = signature.as_ref().map_err(|&e| e).and_then(|signature| {
            let ret = self.writer_authorize(&key, session, &authorization, signature);

            if ret != RC_SUCCESS {
                crate::log::err(format!("tpm: NV writer PolicySigned: rc=0x{ret:08x}").as_bytes());
                return Err(-EACCES);
            }
            Ok(())
        });

        drop(key);
        if let Ok(signature) = &mut signature {
            scrub(signature);
        }
        authorized
    }

    /// PolicyCommandCode(NV_Extend) closes the session, whose digest must
    /// be the one computed in software: a drift is caught here.
    pub(crate) fn policy_session_finish(
        &self,
        session: &Handle<'_>,
        expected: &[u8; DIGEST_LEN],
    ) -> Result<(), c_int> {
        let mut digest = EsysOut::<Tpm2bDigest>::new();
        // SAFETY: the context, handles and a command code.
        let ret = unsafe {
            Esys_PolicyCommandCode(
                self.context(),
                session.handle,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                CC_NV_EXTEND,
            )
        };

        if ret != RC_SUCCESS {
            crate::log::err(format!("tpm: register policy assertion: rc=0x{ret:08x}").as_bytes());
            return Err(-EACCES);
        }
        // SAFETY: the context, handles and room for the digest.
        let ret = unsafe {
            Esys_PolicyGetDigest(
                self.context(),
                session.handle,
                self.session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                digest.room(),
            )
        };
        let differs = ret != RC_SUCCESS
            || digest.get().is_none_or(|d| {
                usize::from(d.size) != DIGEST_LEN || d.buffer[..DIGEST_LEN] != *expected
            });

        if differs {
            crate::log::err(
                format!(
                    "tpm: register policy digest does not match the computed policy (rc=0x{ret:08x})"
                )
                .as_bytes(),
            );
            return Err(-EPROTO);
        }
        Ok(())
    }

    /// The assertions of the branch `init` names: PolicyNvWritten, then
    /// PolicyPCR of the live PCRs of `pcr_mask` for the init branch, then
    /// PolicyOR of both branches. The TPM's code.
    fn policy_branch(
        &self,
        session: &Handle<'_>,
        init: bool,
        pcr_mask: u32,
        branches: &Branches<'_>,
    ) -> Rc {
        let mut list = DigestList::zeroed();
        // SAFETY: the context, the session and handles.
        let mut ret = unsafe {
            Esys_PolicyNvWritten(
                self.context(),
                session.handle,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                if init { NO } else { YES },
            )
        };
        if ret == RC_SUCCESS && init {
            let live = Tpm2bDigest::zeroed();
            let sel = pcr_selection(pcr_mask);

            // SAFETY: the context, the session, handles, an empty digest
            // and the selection.
            ret = unsafe {
                Esys_PolicyPCR(
                    self.context(),
                    session.handle,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    &live,
                    &sel,
                )
            };
        }
        if ret != RC_SUCCESS {
            return ret;
        }
        list.count = 2;
        list.digests[0].size = DIGEST_LEN as u16;
        list.digests[0].buffer[..DIGEST_LEN].copy_from_slice(branches.written);
        list.digests[1].size = DIGEST_LEN as u16;
        list.digests[1].buffer[..DIGEST_LEN].copy_from_slice(branches.init);
        // SAFETY: the context, the session, handles and the branches.
        unsafe {
            Esys_PolicyOR(
                self.context(),
                session.handle,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &list,
            )
        }
    }

    /// Walks one branch of the register's write policy in a real session,
    /// the first write of a boot the init branch, and authorizes the exact
    /// NV_Extend with the TPM-held writer after PolicyOR. The session's
    /// digest is checked against the software policy to catch a drift.
    fn register_session(
        &self,
        init: bool,
        index: u32,
        event: &[u8; DIGEST_LEN],
        pcr_mask: u32,
        branches: &Branches<'_>,
    ) -> Result<Handle<'_>, c_int> {
        let mut expected = [0u8; DIGEST_LEN];
        let Some(writer) = self.writer.as_deref() else {
            crate::log::err(b"tpm: register policy requires the NV writer public key");
            return Err(-EACCES);
        };
        let session = self.start_policy_session()?;
        let ret = self.policy_branch(&session, init, pcr_mask, branches);

        if ret == RC_SUCCESS {
            self.policy_writer_signed(&session, index, event)?;
        }
        if ret != RC_SUCCESS {
            if rc_is(ret, RC_VALUE) && init {
                crate::log::err(b"tpm: the anchoring PCR moved; the register can only be initialised in the boot window");
            } else {
                crate::log::err(
                    format!("tpm: register policy assertion: rc=0x{ret:08x}").as_bytes(),
                );
            }
            return Err(-EACCES);
        }
        let e = register_policy_final(
            branches.written,
            branches.init,
            &writer.public,
            &mut expected,
        );

        if e != 0 {
            crate::log::err(format!("tpm: compute signed register policy: {}", text(e)).as_bytes());
            return Err(e);
        }
        self.policy_session_finish(&session, &expected)?;
        Ok(session)
    }

    fn nv_extend_session(
        &self,
        index: u32,
        session: &Handle<'_>,
        event: &[u8; DIGEST_LEN],
    ) -> Result<(), c_int> {
        let mut data = Tpm2bMaxNvBuffer::zeroed();

        data.size = DIGEST_LEN as u16;
        let nv = self.nv_index(index)?;

        data.buffer[..DIGEST_LEN].copy_from_slice(event);
        // SAFETY: the context, handles and the data.
        let ret = unsafe {
            Esys_NV_Extend(
                self.context(),
                nv.handle,
                nv.handle,
                session.handle,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &data,
            )
        };

        drop(nv);
        if ret != RC_SUCCESS {
            crate::log::err(format!("tpm: NV_Extend(0x{index:08x}): rc=0x{ret:08x}").as_bytes());
            return Err(if rc_is_auth_failure(ret) {
                -EACCES
            } else {
                -EIO
            });
        }
        Ok(())
    }

    /// Extend a systemd NvPCR after its first write. The file supplies
    /// the authorized branch; the TPM checks the index's actual policy.
    pub(crate) fn nvpcr_extend(
        &self,
        index: u32,
        authorize: &[u8; DIGEST_LEN],
        event: &[u8; DIGEST_LEN],
    ) -> Result<(), c_int> {
        let info = self.nv_info(index)?;
        let mut written = [0u8; DIGEST_LEN];
        let mut policy = [0u8; DIGEST_LEN];
        let zero = [0u8; DIGEST_LEN];
        let ret = policy_nv_written(&zero, true, &mut written);
        if ret != 0 {
            return Err(ret);
        }
        let ret = policy_or(authorize, &written, &mut policy);
        if ret != 0 {
            return Err(ret);
        }
        if !nvpcr_policy_valid(&info, &policy) {
            crate::log::err(
                format!("tpm: 0x{index:08x} is not the initialized NvPCR its write policy names")
                    .as_bytes(),
            );
            return Err(-EACCES);
        }

        let session = self.start_policy_session()?;
        let mut branches = DigestList::zeroed();
        // SAFETY: the context, policy session and authorization handles.
        let mut ret = unsafe {
            Esys_PolicyNvWritten(
                self.context(),
                session.handle,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                YES,
            )
        };
        if ret == RC_SUCCESS {
            branches.count = 2;
            branches.digests[0].size = DIGEST_LEN as u16;
            branches.digests[0].buffer[..DIGEST_LEN].copy_from_slice(authorize);
            branches.digests[1].size = DIGEST_LEN as u16;
            branches.digests[1].buffer[..DIGEST_LEN].copy_from_slice(&written);
            // SAFETY: the context, policy session, and two digest branches.
            ret = unsafe {
                Esys_PolicyOR(
                    self.context(),
                    session.handle,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    &branches,
                )
            };
        }
        let mut digest = EsysOut::<Tpm2bDigest>::new();
        if ret == RC_SUCCESS {
            // SAFETY: the context, sessions and room for the digest.
            ret = unsafe {
                Esys_PolicyGetDigest(
                    self.context(),
                    session.handle,
                    self.session,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    digest.room(),
                )
            };
        }
        let valid = ret == RC_SUCCESS
            && digest.get().is_some_and(|d| {
                usize::from(d.size) == DIGEST_LEN && d.buffer[..DIGEST_LEN] == policy
            });
        if !valid {
            crate::log::err(
                format!("tpm: NvPCR 0x{index:08x} policy assertion: rc=0x{ret:08x}").as_bytes(),
            );
            return Err(-EACCES);
        }
        self.nv_extend_session(index, &session, event)
    }

    /// One extend of the register, through the policy branch `init`
    /// names.
    fn nv_extend_through(
        &self,
        init: bool,
        index: u32,
        pcr_mask: u32,
        branches: &Branches<'_>,
        event: &[u8; DIGEST_LEN],
    ) -> Result<(), c_int> {
        let session = self.register_session(init, index, event, pcr_mask, branches)?;
        let extended = self.nv_extend_session(index, &session, event);

        drop(session);
        extended
    }

    /// The register's first extend of this boot, through the init branch
    /// bound to the PCRs of `pcr_mask`.
    pub(crate) fn nv_extend_first(
        &self,
        index: u32,
        pcr_mask: u32,
        branches: &Branches<'_>,
        event: &[u8; DIGEST_LEN],
    ) -> Result<(), c_int> {
        self.nv_extend_through(true, index, pcr_mask, branches, event)
    }

    /// An extend of the register through the written branch.
    pub(crate) fn nv_extend(
        &self,
        index: u32,
        branches: &Branches<'_>,
        event: &[u8; DIGEST_LEN],
    ) -> Result<(), c_int> {
        self.nv_extend_through(false, index, 0, branches, event)
    }

    /// A primary under the endorsement hierarchy, with its marshalled
    /// public area and its name, the latter checked against the area so
    /// that what the evidence carries is what the TPM named.
    fn endorsement_primary(&self, in_pub: &Tpm2bPublic, what: &CStr) -> Result<Key<'_>, c_int> {
        let sensitive = Tpm2bSensitiveCreate::zeroed();
        let creation_pcr = PcrSelectionList::zeroed();
        let mut out_pub = EsysOut::<Tpm2bPublic>::new();
        let outside = Tpm2bData::zeroed();
        let mut computed = [0u8; NAME_LEN];
        let mut handle = ESYS_TR_NONE;
        let auth = if self.session == ESYS_TR_NONE {
            ESYS_TR_PASSWORD
        } else {
            self.session
        };
        // SAFETY: the context, handles, the templates and room for the
        // handle and public area.
        let ret = unsafe {
            Esys_CreatePrimary(
                self.context(),
                ESYS_TR_RH_ENDORSEMENT,
                auth,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &sensitive,
                in_pub,
                &outside,
                &creation_pcr,
                &mut handle,
                out_pub.room(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if ret != RC_SUCCESS {
            let what = what.to_bytes();
            let rc = format!("{ret:08x}");
            let message: &[&[u8]] = if rc_is_auth_failure(ret) {
                &[
                    b"tpm: CreatePrimary(",
                    what,
                    b"): the endorsement hierarchy has an auth value (rc=0x",
                    rc.as_bytes(),
                    b")",
                ]
            } else {
                &[b"tpm: CreatePrimary(", what, b"): rc=0x", rc.as_bytes()]
            };

            crate::log::err(&message.concat());
            return Err(-EIO);
        }
        let handle = Handle { tpm: self, handle };
        let area = public_from_tss(&out_pub.get().ok_or(-EPROTO)?.publicArea)?;

        drop(out_pub);
        let e = object_name(&area, &mut computed);

        if e != 0 {
            return Err(e);
        }
        if self.object_name(handle.handle) != Some(computed) {
            crate::log::err(
                &[
                    &b"tpm: "[..],
                    what.to_bytes(),
                    b" name does not match its marshalled public area",
                ]
                .concat(),
            );
            return Err(-EPROTO);
        }
        Ok(Key {
            handle,
            public: KeyPublic {
                area,
                name: computed,
            },
        })
    }

    /// The attestation key: a restricted ECDSA P-256 primary under the
    /// endorsement hierarchy.
    pub(crate) fn ak_create(&self) -> Result<Key<'_>, c_int> {
        let mut in_pub = Tpm2bPublic::zeroed();
        let p = &mut in_pub.publicArea;

        p.type_ = ALG_ECC;
        p.nameAlg = ALG_SHA256;
        p.objectAttributes = OBJECT_FIXEDTPM
            | OBJECT_FIXEDPARENT
            | OBJECT_SENSITIVEDATAORIGIN
            | OBJECT_USERWITHAUTH
            | OBJECT_RESTRICTED
            | OBJECT_SIGN_ENCRYPT;
        p.parameters.eccDetail = EccParms {
            symmetric: sym_def(ALG_NULL, 0, 0),
            scheme: ecc_scheme(ALG_ECDSA, ALG_SHA256),
            curveID: ECC_NIST_P256,
            kdf: kdf_null(),
        };
        self.endorsement_primary(&in_pub, c"attestation key")
    }

    /// The TCG endorsement key, RSA 2048 or ECC P-256.
    pub(crate) fn ek_create(&self, rsa: bool) -> Result<Key<'_>, c_int> {
        let mut in_pub = Tpm2bPublic::zeroed();
        let p = &mut in_pub.publicArea;
        let symmetric = sym_def(ALG_AES, 128, ALG_CFB);

        p.type_ = if rsa { ALG_RSA } else { ALG_ECC };
        p.nameAlg = ALG_SHA256;
        p.objectAttributes = EK_ATTRS;
        p.authPolicy = digest2b(&EK_POLICY)?;
        if rsa {
            let mut unique = Tpm2bPublicKeyRsa::zeroed();

            unique.size = 256;
            p.parameters.rsaDetail = RsaParms {
                symmetric,
                scheme: rsa_scheme(ALG_NULL, 0),
                keyBits: 2048,
                exponent: 0,
            };
            p.unique.rsa = unique;
        } else {
            let mut empty = Tpm2bEccParameter::zeroed();

            empty.size = 32;
            p.parameters.eccDetail = EccParms {
                symmetric,
                scheme: ecc_scheme(ALG_NULL, 0),
                curveID: ECC_NIST_P256,
                kdf: kdf_null(),
            };
            p.unique.ecc = EccPoint { x: empty, y: empty };
        }
        self.endorsement_primary(&in_pub, c"endorsement key")
    }

    pub(crate) fn quote(
        &self,
        ak: &Key<'_>,
        nonce: &[u8],
        pcr_mask: u32,
    ) -> Result<Attestation, c_int> {
        let scheme = sig_scheme(ALG_NULL, 0);
        let mut quoted = EsysOut::<Tpm2bAttest>::new();
        let mut sig = EsysOut::<Signature>::new();
        let qual = qualifying(nonce)?;
        let sel = pcr_selection(pcr_mask);
        // SAFETY: the context, handles, the nonce, scheme and selection,
        // and room for the quote and signature.
        let ret = unsafe {
            Esys_Quote(
                self.context(),
                ak.handle.handle,
                self.session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &qual,
                &scheme,
                &sel,
                quoted.room(),
                sig.room(),
            )
        };
        if ret != RC_SUCCESS {
            crate::log::err(format!("tpm: Quote: rc=0x{ret:08x}").as_bytes());
            return Err(-EIO);
        }
        attestation(&quoted, &sig)
    }

    pub(crate) fn nv_certify(
        &self,
        ak: &Key<'_>,
        index: u32,
        nonce: &[u8],
    ) -> Result<Attestation, c_int> {
        let scheme = sig_scheme(ALG_NULL, 0);
        let mut info = EsysOut::<Tpm2bAttest>::new();
        let mut sig = EsysOut::<Signature>::new();
        let qual = qualifying(nonce)?;
        let nv = self.nv_index(index)?;
        // SAFETY: the context, handles, the nonce and scheme, and room for
        // the certification and signature.
        let ret = unsafe {
            Esys_NV_Certify(
                self.context(),
                ak.handle.handle,
                nv.handle,
                nv.handle,
                self.session,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                &qual,
                &scheme,
                DIGEST_LEN as u16,
                0,
                info.room(),
                sig.room(),
            )
        };
        drop(nv);
        if ret != RC_SUCCESS {
            crate::log::err(format!("tpm: NV_Certify(0x{index:08x}): rc=0x{ret:08x}").as_bytes());
            return Err(if rc_is(ret, RC_NV_UNINITIALIZED) {
                -ENODATA
            } else {
                -EIO
            });
        }
        attestation(&info, &sig)
    }

    /// TPM2_ActivateCredential through the endorsement key's policy: the
    /// credential an operator made for `ak` under `ek` with `blob` and
    /// `secret`, or -EKEYREJECTED for one the TPM refuses.
    pub(crate) fn activate_credential(
        &self,
        ak: &Key<'_>,
        ek: &Key<'_>,
        blob: &[u8],
        secret: &[u8],
    ) -> Result<Vec<u8>, c_int> {
        let mut sec = Tpm2bEncryptedSecret::zeroed();
        let mut cert_info = EsysOut::<Tpm2bDigest>::new();
        let mut id = Tpm2bIdObject::zeroed();
        let (Some(id_room), Some(sec_room), Ok(id_size), Ok(sec_size)) = (
            id.credential.get_mut(..blob.len()),
            sec.secret.get_mut(..secret.len()),
            u16::try_from(blob.len()),
            u16::try_from(secret.len()),
        ) else {
            return Err(-EINVAL);
        };

        id_room.copy_from_slice(blob);
        id.size = id_size;
        sec_room.copy_from_slice(secret);
        sec.size = sec_size;
        let session = self.start_policy_session()?;
        // The endorsement key's policy: the hierarchy's own authorisation.
        // SAFETY: the context and handles, the rest NULL.
        let ret = unsafe {
            Esys_PolicySecret(
                self.context(),
                ESYS_TR_RH_ENDORSEMENT,
                session.handle,
                self.session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if ret != RC_SUCCESS {
            crate::log::err(format!("tpm: PolicySecret(endorsement): rc=0x{ret:08x}").as_bytes());
            return Err(-EACCES);
        }
        // SAFETY: the context, handles, the credential and secret, and room
        // for what it protects.
        let ret = unsafe {
            Esys_ActivateCredential(
                self.context(),
                ak.handle.handle,
                ek.handle.handle,
                self.session,
                session.handle,
                ESYS_TR_NONE,
                &id,
                &sec,
                cert_info.room(),
            )
        };
        drop(session);
        if ret != RC_SUCCESS {
            crate::log::err(format!("tpm: ActivateCredential: rc=0x{ret:08x}").as_bytes());
            return Err(if ret & 0xFFFF_0000 == 0 {
                -EKEYREJECTED
            } else {
                -EIO
            });
        }
        let credential = cert_info.get().ok_or(-EPROTO).and_then(|c| {
            c.buffer
                .get(..usize::from(c.size))
                .map(<[u8]>::to_vec)
                .ok_or(-E2BIG)
        });

        if let Some(c) = cert_info.get_mut() {
            scrub(&mut c.buffer);
        }
        credential
    }

    /// The whole of an NV index, in chunks the TPM takes: -E2BIG for one
    /// of more than `max` bytes.
    fn nv_read_all(&self, index: u32, max: usize) -> Result<Vec<u8>, c_int> {
        let mut public = EsysOut::<Tpm2bNvPublic>::new();
        let nv = self.nv_index(index)?;
        // SAFETY: the context, handles and room for the public area.
        let ret = unsafe {
            Esys_NV_ReadPublic(
                self.context(),
                nv.handle,
                self.session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                public.room(),
                ptr::null_mut(),
            )
        };

        if ret != RC_SUCCESS {
            return Err(-EIO);
        }
        let total = usize::from(public.get().ok_or(-EIO)?.nvPublic.dataSize);

        drop(public);
        if total > max {
            return Err(-E2BIG);
        }
        let mut out = Vec::with_capacity(total);

        while out.len() < total {
            let want = (total - out.len()).min(NV_READ_CHUNK);

            self.nv_read_chunk(&nv, want, &mut out)?;
        }
        Ok(out)
    }

    /// Up to `want` bytes of the index `nv` from where `out` ends,
    /// appended to it: -EIO for none.
    fn nv_read_chunk(&self, nv: &NvIndex<'_>, want: usize, out: &mut Vec<u8>) -> Result<(), c_int> {
        let mut data = EsysOut::<Tpm2bMaxNvBuffer>::new();
        let (Ok(size), Ok(offset)) = (u16::try_from(want), u16::try_from(out.len())) else {
            return Err(-EIO);
        };
        // SAFETY: the context, handles and room for the data.
        let ret = unsafe {
            Esys_NV_Read(
                self.context(),
                nv.handle,
                nv.handle,
                self.session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                size,
                offset,
                data.room(),
            )
        };

        if ret != RC_SUCCESS {
            return Err(-EIO);
        }
        let chunk = data
            .get()
            .and_then(|d| d.buffer.get(..usize::from(d.size)))
            .filter(|c| !c.is_empty() && c.len() <= want)
            .ok_or(-EIO)?;

        out.extend_from_slice(chunk);
        Ok(())
    }

    /// The endorsement key's certificate from its TCG NV index, the ECC
    /// one first, and whether it is the RSA one: -ENOENT for none, -E2BIG
    /// for one of more than `max` bytes.
    pub(crate) fn ek_certificate(&self, max: usize) -> Result<(Vec<u8>, bool), c_int> {
        match self.nv_read_all(EK_CERT_NV_ECC, max) {
            Err(e) if e == -ENOENT => self.nv_read_all(EK_CERT_NV_RSA, max).map(|c| (c, true)),
            ecc => ecc.map(|c| (c, false)),
        }
    }
}

#[cfg(feature = "test-helpers")]
impl Tpm {
    /// The ESYS context, for a test helper's own commands.
    pub(crate) fn esys_context(&self) -> *mut EsysContext {
        self.context()
    }

    /// The TCTI, for a test helper that stands a proxy before it.
    pub(crate) fn tcti_context(&self) -> *mut TctiContext {
        self.esys._tcti.0
    }

    /// The HMAC session the connection's commands go through.
    pub(crate) fn hmac_session(&self) -> EsysTr {
        self.session
    }

    /// The key that salts the connection's sessions replaced by `key`,
    /// ESYS_TR_NONE for none: the key it held, which the connection
    /// flushes when it goes only if it holds it again by then.
    pub(crate) fn replace_salt_key(&mut self, key: EsysTr) -> EsysTr {
        core::mem::replace(&mut self.session_key, key)
    }
}

#[cfg(test)]
mod tests {
    use super::{NvInfo, nvpcr_policy_valid};

    #[test]
    fn nvpcr_requires_initialized_extend_index_and_exact_policy() {
        let policy = [0x5a; 32];
        let mut info = NvInfo {
            defined: true,
            written: true,
            attrs: 0x48,
            data_size: 32,
            policy,
            ..NvInfo::UNDEFINED
        };
        assert!(nvpcr_policy_valid(&info, &policy));
        info.defined = false;
        assert!(!nvpcr_policy_valid(&info, &policy));
        info.defined = true;
        info.written = false;
        assert!(!nvpcr_policy_valid(&info, &policy));
        info.written = true;
        info.data_size = 64;
        assert!(!nvpcr_policy_valid(&info, &policy));
        info.data_size = 32;
        for attrs in [0x40, 0x49, 0x4a, 0x4c, 0x08] {
            info.attrs = attrs;
            assert!(!nvpcr_policy_valid(&info, &policy));
        }
        info.attrs = 0x48;
        assert!(!nvpcr_policy_valid(&info, &[0; 32]));
    }
}
