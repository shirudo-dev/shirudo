// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The NV writer key: the TPM key that alone
//! may extend the measurement register, created from a fresh seed at
//! init, and read back from the identity map after.

use core::ffi::c_int;

use crate::errno::{EINTR, EIO, EKEYREJECTED, text};
use crate::sys::libc::{errno, getrandom, scrub};
use crate::util::identity;
use crate::util::tpm::Tpm;
use crate::util::tpm_wire::{DIGEST_LEN, NV_RSA_BYTES};

/// A fresh seed into `seed`, and the writer key the TPM creates from it,
/// its modulus into `public`; on failure both are zeroed.
pub(crate) fn create(seed: &mut [u8; DIGEST_LEN], public: &mut [u8; NV_RSA_BYTES]) -> c_int {
    let mut off = 0;

    while off < seed.len() {
        // SAFETY: the room left in seed.
        let got = unsafe { getrandom(seed[off..].as_mut_ptr().cast(), seed.len() - off, 0) };

        if got < 0 && errno() == EINTR {
            continue;
        }
        if got <= 0 {
            return failed(if got < 0 { -errno() } else { -EIO }, seed, public);
        }
        off += got as usize;
    }

    match Tpm::open().and_then(|tpm| tpm.writer_create(seed)) {
        Ok(modulus) => {
            *public = modulus;
            0
        }
        Err(err) => failed(err, seed, public),
    }
}

fn failed(err: c_int, seed: &mut [u8; DIGEST_LEN], public: &mut [u8; NV_RSA_BYTES]) -> c_int {
    crate::log::err(format!("nv writer: TPM key creation failed: {}", text(err)).as_bytes());
    scrub(seed);
    public.fill(0);
    err
}

/// The writer's seed and modulus as init froze them in the identity map;
/// -EKEYREJECTED when the modulus there is not one, its top bit clear.
pub(crate) fn read(seed: &mut [u8; DIGEST_LEN], public: &mut [u8; NV_RSA_BYTES]) -> c_int {
    let id = match identity::read() {
        Ok(id) => id,
        Err(err) => {
            crate::log::err(
                format!("nv writer: public key lookup failed: {}", text(err)).as_bytes(),
            );
            return err;
        }
    };
    let err = if id.nv_writer_public[0] & 0x80 == 0 {
        -EKEYREJECTED
    } else {
        0
    };
    if err != 0 {
        crate::log::err(format!("nv writer: public key lookup failed: {}", text(err)).as_bytes());
        return err;
    }
    seed.copy_from_slice(&id.nv_writer_seed);
    public.copy_from_slice(&id.nv_writer_public);
    0
}
