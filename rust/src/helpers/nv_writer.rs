// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-nv-writer: what the NV writer's protection leaves a process:
//! its public key as the init record holds it, a TPM2_Sign of an
//! unrelated key allowed, and raw NV_Extend commands to the TPM device
//! refused, alone and in a child that inherits the open device.
//!
//!   test-nv-writer public <writer modulus hex>
//!   test-nv-writer sign-allowed|sign-allowed-inherited <TCTI>
//!   test-nv-writer raw-extend|raw-extend-nonblock|raw-extend-inherited|raw-extend-other|raw-extend-short <device>

use core::ffi::{CStr, c_int};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;

use super::{err, helper_main, perror};
use crate::sys::tss2::{
    ALG_ECC, ALG_ECDSA, ALG_NULL, ALG_SHA256, CC_NV_EXTEND, ECC_NIST_P256, ESYS_TR_NONE,
    ESYS_TR_PASSWORD, EccParms, Esys_CreatePrimary, Esys_Finalize, Esys_FlushContext, Esys_Free,
    Esys_Initialize, Esys_Sign, EsysContext, EsysTr, OBJECT_FIXEDPARENT, OBJECT_FIXEDTPM,
    OBJECT_SENSITIVEDATAORIGIN, OBJECT_SIGN_ENCRYPT, OBJECT_USERWITHAUTH, PcrSelectionList,
    RC_SUCCESS, RH_NULL, Rc, ST_HASHCHECK, Signature, TctiContext, TkHashcheck, Tpm2bData,
    Tpm2bDigest, Tpm2bPublic, Tpm2bSensitiveCreate, Tss2_TctiLdr_Finalize, Tss2_TctiLdr_Initialize,
    Zeroed, ecc_scheme, kdf_null, sig_scheme, sym_def,
};
use crate::util::eventlog::{EventlogInit, NV_INDEX, boot_init};

helper_main!(shirudo_helper_test_nv_writer, run);

/// ESYS_TR_RH_NULL: the null hierarchy.
const ESYS_TR_RH_NULL: EsysTr = 0x107;
/// The size of the NV writer's RSA modulus.
const NV_RSA_BYTES: usize = 384;

/// The writer modulus as the identity map holds it, compared with the
/// init record's from a trusted reader.
fn public_matches_init(hex: &CStr) -> c_int {
    let mut expected = [0u8; NV_RSA_BYTES];
    if hex.count_bytes() != 2 * NV_RSA_BYTES
        || crate::util::hex::decode(hex.to_bytes(), &mut expected).is_err()
    {
        err(&format!(
            "writer modulus must be {} hex digits\n",
            2 * NV_RSA_BYTES
        ));
        return 1;
    }
    let mut rec: Box<EventlogInit> = Box::new(EventlogInit::zeroed());
    if boot_init(&mut rec) != 0 || rec.writer_public != expected {
        err("writer modulus differs between identity and init record\n");
        return 1;
    }
    0
}

/// A process that may: forked when `inherited`, run here when not;
/// whether it ran and succeeded.
fn in_child_if(inherited: bool, f: impl FnOnce() -> c_int) -> c_int {
    if !inherited {
        return f();
    }
    // SAFETY: a fork of this process, one thread; the child exits from
    // what f() gives.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        perror("fork");
        return 1;
    }
    if pid == 0 {
        let ret = f();
        // SAFETY: the C library's streams flushed and the child gone.
        unsafe {
            libc::fflush(core::ptr::null_mut());
            libc::_exit(ret);
        }
    }
    let mut status = 0;
    // SAFETY: the child and room for its status.
    if unsafe { libc::waitpid(pid, &mut status, 0) } != pid {
        perror("waitpid");
        return 1;
    }
    c_int::from(!libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0)
}

fn sign_once(esys: *mut EsysContext, key: EsysTr) -> c_int {
    let mut validation = TkHashcheck::zeroed();
    validation.tag = ST_HASHCHECK;
    validation.hierarchy = RH_NULL;
    let scheme = sig_scheme(ALG_ECDSA, ALG_SHA256);
    let mut digest = Tpm2bDigest::zeroed();
    digest.size = 32;
    digest.buffer[..32].fill(0x5a);
    let mut signature: *mut Signature = core::ptr::null_mut();
    // SAFETY: the context, the key, the digest, scheme and ticket, and
    // room for the signature, freed once.
    let ret = unsafe {
        let ret = Esys_Sign(
            esys,
            key,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &digest,
            &scheme,
            &validation,
            &mut signature,
        );
        let signed = ret == RC_SUCCESS && !signature.is_null();
        Esys_Free(signature.cast());
        if signed {
            return 0;
        }
        ret
    };
    err(&format!("unrelated TPM2_Sign failed: rc=0x{ret:08x}\n"));
    1
}

/// An ECDSA key in the null hierarchy, and a signature with it, here or
/// in a child.
fn sign_check(device: &CStr, inherited: bool) -> c_int {
    let mut tcti: *mut TctiContext = core::ptr::null_mut();
    let mut esys: *mut EsysContext = core::ptr::null_mut();
    let mut out_public: *mut Tpm2bPublic = core::ptr::null_mut();
    let mut key: EsysTr = ESYS_TR_NONE;
    let mut in_public = Tpm2bPublic::zeroed();
    let p = &mut in_public.publicArea;
    p.type_ = ALG_ECC;
    p.nameAlg = ALG_SHA256;
    p.objectAttributes = OBJECT_FIXEDTPM
        | OBJECT_FIXEDPARENT
        | OBJECT_SENSITIVEDATAORIGIN
        | OBJECT_USERWITHAUTH
        | OBJECT_SIGN_ENCRYPT;
    p.parameters.eccDetail = EccParms {
        symmetric: sym_def(ALG_NULL, 0, 0),
        scheme: ecc_scheme(ALG_ECDSA, ALG_SHA256),
        curveID: ECC_NIST_P256,
        kdf: kdf_null(),
    };
    // SAFETY: the TCTI and ESYS contexts, the templates and the rooms the
    // calls fill; what they give freed, flushed and finalized once.
    unsafe {
        let mut trc: Rc = Tss2_TctiLdr_Initialize(device.as_ptr(), &mut tcti);
        if trc == RC_SUCCESS {
            trc = Esys_Initialize(&mut esys, tcti, core::ptr::null_mut());
        }
        if trc == RC_SUCCESS {
            trc = Esys_CreatePrimary(
                esys,
                ESYS_TR_RH_NULL,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &Tpm2bSensitiveCreate::zeroed(),
                &in_public,
                &Tpm2bData::zeroed(),
                &PcrSelectionList::zeroed(),
                &mut key,
                &mut out_public,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
        }
        let ret = if trc != RC_SUCCESS {
            err(&format!(
                "prepare TPM signing request on {}: rc=0x{trc:08x}\n",
                device.to_string_lossy()
            ));
            1
        } else {
            in_child_if(inherited, || sign_once(esys, key))
        };
        Esys_Free(out_public.cast());
        if key != ESYS_TR_NONE {
            Esys_FlushContext(esys, key);
        }
        Esys_Finalize(&mut esys);
        Tss2_TctiLdr_Finalize(&mut tcti);
        ret
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Probe {
    /// NV_Extend of the writer's index.
    Target,
    /// NV_Extend of the index after it, which the protection lets by.
    Other,
    /// A command cut short.
    Short,
}

fn write_extend(fd: c_int, device: &str, probe: Probe) -> c_int {
    let index = if probe == Probe::Other {
        NV_INDEX + 1
    } else {
        NV_INDEX
    };
    let size: usize = if probe == Probe::Short { 10 } else { 18 };
    let mut command = [0u8; 18];
    command[..2].copy_from_slice(&[0x80, 0x01]);
    command[2..6].copy_from_slice(&(size as u32).to_be_bytes());
    command[6..10].copy_from_slice(&CC_NV_EXTEND.to_be_bytes());
    command[10..14].copy_from_slice(&index.to_be_bytes());
    command[14..18].copy_from_slice(&index.to_be_bytes());
    // SAFETY: the command's first size bytes to the device.
    let written = unsafe { libc::write(fd, command.as_ptr().cast(), size) };
    let errno = if written < 0 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    } else {
        0
    };
    let allowed = match probe {
        Probe::Other => written == size as isize,
        _ => written == -1 && errno == libc::EACCES,
    };
    if allowed {
        return 0;
    }
    err(&format!(
        "{device} NV_Extend 0x{index:08x}: wrote {written}/{size}, errno={errno}\n"
    ));
    1
}

fn raw_extend_check(device: &CStr, probe: Probe, nonblock: bool, inherited: bool) -> c_int {
    let name = device.to_string_lossy();
    if name != "/dev/tpmrm0" && name != "/dev/tpm0" {
        return 2;
    }
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(if nonblock { libc::O_NONBLOCK } else { 0 })
        .open(std::ffi::OsStr::from_bytes(device.to_bytes()))
    {
        Ok(file) => file,
        Err(_) => {
            perror(&name);
            return 1;
        }
    };
    in_child_if(inherited, || write_extend(file.as_raw_fd(), &name, probe))
}

fn run(args: &[&CStr]) -> c_int {
    let [_, how, arg] = args else {
        return 2;
    };
    match how.to_bytes() {
        b"public" => public_matches_init(arg),
        b"sign-allowed" => sign_check(arg, false),
        b"sign-allowed-inherited" => sign_check(arg, true),
        b"raw-extend" => raw_extend_check(arg, Probe::Target, false, false),
        b"raw-extend-nonblock" => raw_extend_check(arg, Probe::Target, true, false),
        b"raw-extend-inherited" => raw_extend_check(arg, Probe::Target, false, true),
        b"raw-extend-other" => raw_extend_check(arg, Probe::Other, true, false),
        b"raw-extend-short" => raw_extend_check(arg, Probe::Short, false, false),
        _ => 2,
    }
}
