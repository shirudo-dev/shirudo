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

// Reference grammar: one or more decimal PCR numbers, separated by commas.
// Parse each token separately, independent of the production character scan.
#[kani::proof]
fn attest_pcrs() {
    let bytes: [u8; 6] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());

    let mut mask = 0u32;
    let mut valid = len > 0;
    let mut start = 0usize;
    for end in 0..=len {
        if end != len && bytes[end] != b',' {
            continue;
        }
        if end == start {
            valid = false;
            break;
        }
        let mut value = 0u32;
        for &digit in &bytes[start..end] {
            if !digit.is_ascii_digit() {
                valid = false;
                break;
            }
            value = value * 10 + u32::from(digit - b'0');
        }
        if !valid || value > 23 {
            valid = false;
            break;
        }
        mask |= 1u32 << value;
        start = end + 1;
    }
    let expected = if valid { Ok(mask) } else { Err(-EINVAL) };
    assert_eq!(parse_pcrs(&bytes[..len]), expected);
}

// Shirudo.Hex.nibble in Hex.lean gives each ASCII hex digit its value.
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

// Without an equals sign, no name/digest pair exists.
#[kani::proof]
fn attest_name_missing_equals() {
    let bytes: [u8; 6] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    if !bytes[..len].contains(&b'=') {
        assert_eq!(parse_name_digest(&bytes[..len]), Err(-EINVAL));
    }
}
