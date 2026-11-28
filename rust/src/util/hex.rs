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
    let len = bytes.len().saturating_mul(2);
    let mut out = vec![0u8; len];

    encode_into(bytes, &mut out);
    out
}

/// Write the two lowercase digits of each input byte into a slice with
/// exactly twice as many bytes as the input.
fn encode_into(bytes: &[u8], out: &mut [u8]) {
    for (pair, &byte) in out.as_chunks_mut::<2>().0.iter_mut().zip(bytes) {
        pair[0] = DIGITS[usize::from(byte >> 4)];
        pair[1] = DIGITS[usize::from(byte & 0xf)];
    }
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

#[cfg(kani)]
#[path = "hex/kani.rs"]
mod proofs;
#[cfg(test)]
mod tests;

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
