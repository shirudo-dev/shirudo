// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::{parse_name_digest, parse_pcr_value, parse_pcrs, record_word};
use crate::errno::EINVAL;

#[kani::proof]
fn attest_pcr_value() {
    let bytes: [u8; 6] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());

    let mut end = 0usize;
    while end < len && bytes[end].is_ascii_digit() {
        end += 1;
    }
    let mut pcr = 0usize;
    for &digit in &bytes[..end] {
        pcr = pcr * 10 + usize::from(digit - b'0');
    }
    let expected = if end > 0 && end < len && bytes[end] == b'=' && pcr <= 23 {
        Ok((pcr, &bytes[end + 1..len]))
    } else {
        Err(-EINVAL)
    };
    assert_eq!(parse_pcr_value(&bytes[..len]), expected);
}

#[kani::proof]
#[kani::unwind(18)]
fn attest_fields() {
    let bytes: [u8; 16] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let mut expected = true;
    for &c in &bytes[..len] {
        expected &= (b'a'..=b'z').contains(&c) || c == b'_';
    }
    assert_eq!(record_word(&bytes[..len]), expected);
}

// Parse the short decimal tokens directly, rather than using the
// production split_at() and parse_u64() combination.
#[kani::proof]
fn attest_pcrs() {
    let bytes: [u8; 6] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());

    let mut value = 0u32;
    let mut have_digit = false;
    let mut mask = 0u32;
    let mut valid = len > 0;
    for i in 0..len {
        let c = bytes[i];
        if c.is_ascii_digit() {
            value = value * 10 + u32::from(c - b'0');
            have_digit = true;
        } else if c == b',' && have_digit && value <= 23 && i + 1 < len {
            mask |= 1u32 << value;
            value = 0;
            have_digit = false;
        } else {
            valid = false;
        }
    }
    valid &= have_digit && value <= 23;
    if valid {
        mask |= 1u32 << value;
    }
    let expected = if valid { Ok(mask) } else { Err(-EINVAL) };
    assert_eq!(parse_pcrs(&bytes[..len]), expected);
}

// Shirudo.Hex.hexVal in Hex.lean gives each ASCII hex digit its value.
fn digest_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[kani::proof]
#[kani::unwind(35)]
fn attest_name_digest_one_digit() {
    let position: usize = kani::any();
    let digit: u8 = kani::any();
    kani::assume(position < 64);
    let mut spec = [b'0'; 66];
    spec[0] = b'n';
    spec[1] = b'=';
    spec[2 + position] = digit;
    let actual = parse_name_digest(&spec);
    if let Some(value) = digest_digit(digit) {
        let mut expected = [0u8; 32];
        expected[position / 2] = if position % 2 == 0 { value << 4 } else { value };
        assert_eq!(actual, Ok((&b"n"[..], expected)));
    } else {
        assert_eq!(actual, Err(-EINVAL));
    }
}

#[kani::proof]
#[kani::unwind(35)]
fn attest_name_digest_short_shape() {
    let name_len: usize = kani::any();
    let digest_len: usize = kani::any();
    kani::assume(name_len <= 4 && (63..=65).contains(&digest_len));
    let mut spec = [b'0'; 70];
    spec[..name_len].fill(b'n');
    spec[name_len] = b'=';
    let actual = parse_name_digest(&spec[..name_len + 1 + digest_len]);
    if name_len > 0 && digest_len == 64 {
        assert_eq!(actual, Ok((&spec[..name_len], [0u8; 32])));
    } else {
        assert_eq!(actual, Err(-EINVAL));
    }
}
