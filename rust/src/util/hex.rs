// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Hex: each byte as two lowercase digits, the high nibble first, and
//! decoded from digits of either case. The Lean model `Shirudo.Hex`
//! states what an encoding and a decode are.

use core::ffi::c_int;

use crate::errno::EINVAL;

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// The lowercase hex of `bytes`.
pub(crate) fn encode(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .flat_map(|b| [DIGITS[usize::from(b >> 4)], DIGITS[usize::from(b & 0xf)]])
        .collect()
}

/// The value of hex digit `c` of either case.
fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// The bytes the digits `hex` spell into `out`, two digits a byte, in
/// order until a byte that is not a digit: -EINVAL unless `hex` holds
/// exactly twice as many digits as `out` has bytes.
pub(crate) fn decode(hex: &[u8], out: &mut [u8]) -> Result<(), c_int> {
    if Some(hex.len()) != out.len().checked_mul(2) {
        return Err(-EINVAL);
    }
    for (o, pair) in out.iter_mut().zip(hex.as_chunks::<2>().0.iter()) {
        match (nibble(pair[0]), nibble(pair[1])) {
            (Some(hi), Some(lo)) => *o = (hi << 4) | lo,
            _ => return Err(-EINVAL),
        }
    }
    Ok(())
}

/// The bytes an even run of at most twice as many digits as `out` has
/// bytes spells, into the start of `out`: how many, or -EINVAL.
pub(crate) fn decode_max(hex: &[u8], out: &mut [u8]) -> Result<usize, c_int> {
    let n = hex.len() / 2;
    let Some(room) = out.get_mut(..n).filter(|_| hex.len().is_multiple_of(2)) else {
        return Err(-EINVAL);
    };

    decode(hex, room)?;
    Ok(n)
}

/// The 32 bytes named by an OCI sha256 digest.
pub(crate) fn decode_sha256_digest(digest: &[u8]) -> Result<[u8; 32], c_int> {
    let hex = digest.strip_prefix(b"sha256:").ok_or(-EINVAL)?;
    let mut out = [0u8; 32];
    decode(hex, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests;

mod capi {
    use core::ffi::{CStr, c_char, c_int};

    use crate::errno::EINVAL;

    use crate::sys::libc::{strlen, strnlen};

    /// # Safety
    ///
    /// `inp` holds `n` bytes, and `out` room for `2 * n + 1`.
    pub unsafe extern "C" fn hex_encode(inp: *const u8, n: usize, out: *mut c_char) {
        // SAFETY: the caller's bytes and room.
        let (inp, out) = unsafe {
            (
                crate::ffi::slice(inp, n),
                core::slice::from_raw_parts_mut(out.cast::<u8>(), 2 * n + 1),
            )
        };
        let hex = super::encode(inp);
        out[..hex.len()].copy_from_slice(&hex);
        out[hex.len()] = 0;
    }

    /// # Safety
    ///
    /// `hex` is a C string, and `out` room for `n` bytes.
    pub unsafe extern "C" fn hex_decode(hex: *const c_char, out: *mut u8, n: usize) -> c_int {
        // SAFETY: the caller's C string.
        let len = unsafe { strlen(hex) };
        if Some(len) != n.checked_mul(2) {
            return -EINVAL;
        }
        // SAFETY: the string's digits, and the caller's room.
        let (hex, out) = unsafe {
            (
                crate::ffi::slice(hex.cast::<u8>(), len),
                core::slice::from_raw_parts_mut(out, n),
            )
        };
        super::decode(hex, out).map_or_else(|e| e, |()| 0)
    }

    /// # Safety
    ///
    /// `hex` is a C string or holds `2 * cap + 1` bytes, `out` is room for
    /// `cap` bytes and `len` for their count.
    pub unsafe extern "C" fn hex_decode_max(
        hex: *const c_char,
        out: *mut u8,
        cap: usize,
        len: *mut usize,
    ) -> c_int {
        // SAFETY: the caller's string, read no further than one digit
        // past the most it may hold, and the caller's room.
        let (digits, room) = unsafe {
            let n = strnlen(hex, cap.saturating_mul(2).saturating_add(1));

            (
                crate::ffi::slice(hex.cast::<u8>(), n),
                crate::ffi::bytes_mut(out, cap),
            )
        };
        match super::decode_max(digits, room) {
            Ok(n) => {
                // SAFETY: the caller's room for the count.
                unsafe { *len = n };
                0
            }
            Err(e) => e,
        }
    }

    /// The 32 bytes of a `sha256:<64 hex digits>` digest.
    ///
    /// # Safety
    ///
    /// `digest` is NULL or a C string, and `out` room for 32 bytes.
    #[allow(dead_code)] // Removed after the remaining callers and tests use slices.
    pub unsafe extern "C" fn sha256_digest_decode(digest: *const c_char, out: *mut u8) -> c_int {
        if digest.is_null() {
            return -EINVAL;
        }
        // SAFETY: the caller's C string and room.
        let (digest, out) = unsafe {
            (
                CStr::from_ptr(digest).to_bytes(),
                core::slice::from_raw_parts_mut(out, 32),
            )
        };
        match digest.strip_prefix(b"sha256:") {
            Some(hex) => super::decode(hex, out).map_or_else(|e| e, |()| 0),
            None => -EINVAL,
        }
    }
}

/// `SHA256_DIGEST_STR_SIZE`: an OCI digest and its terminator.
pub(crate) const SHA256_DIGEST_STR_SIZE: usize = 72;

/// The 32 bytes of `d` as an OCI digest, "sha256:" and 64 lowercase hex
/// digits, terminated.
pub(crate) fn sha256_digest_encode(d: &[u8; 32]) -> [u8; SHA256_DIGEST_STR_SIZE] {
    let mut out = [0u8; SHA256_DIGEST_STR_SIZE];

    out[..7].copy_from_slice(b"sha256:");
    out[7..71].copy_from_slice(&encode(d));
    out
}

#[allow(unused_imports)] // The digest shim remains for the next test commit.
pub(crate) use capi::{hex_decode, hex_decode_max, hex_encode, sha256_digest_decode};
