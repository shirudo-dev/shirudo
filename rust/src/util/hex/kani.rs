// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::{decode, decode_max, decode_sha256_digest, encode_into};

// Shirudo.Hex.encodeByte in Hex.lean uses the high and low nibbles;
// this arithmetic spelling is independent of the production table.
fn model_digit(nibble: u8) -> u8 {
    if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + nibble - 10
    }
}

#[kani::proof]
fn hex_roundtrip() {
    let bytes: [u8; 4] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let mut digits = [0u8; 8];
    encode_into(&bytes[..len], &mut digits[..2 * len]);

    for i in 0..len {
        assert_eq!(digits[2 * i], model_digit(bytes[i] >> 4));
        assert_eq!(digits[2 * i + 1], model_digit(bytes[i] & 0x0f));
    }
    let mut decoded = [0u8; 4];
    assert_eq!(decode(&digits[..2 * len], &mut decoded[..len]), Ok(()));
    assert_eq!(&decoded[..len], &bytes[..len]);
}

// Shirudo.Hex.hexVal in Hex.lean gives each ASCII hex digit its value.
fn model_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[kani::proof]
fn hex_decode() {
    let text: [u8; 16] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 8);
    let mut out = [0u8; 8];
    let actual = decode(&text[..2 * len], &mut out[..len]);
    let mut valid = true;
    for i in 0..len {
        match (model_value(text[2 * i]), model_value(text[2 * i + 1])) {
            (Some(hi), Some(lo)) => {
                if actual.is_ok() {
                    assert_eq!(out[i], (hi << 4) | lo);
                }
            }
            _ => valid = false,
        }
    }
    assert_eq!(actual.is_ok(), valid);
}

#[kani::proof]
fn hex_decode_max() {
    let text: [u8; 17] = kani::any();
    let len: usize = kani::any();
    let capacity: usize = kani::any();
    kani::assume(len <= text.len() && capacity <= 8);
    let mut out = [0xa5u8; 8];
    let actual = decode_max(&text[..len], &mut out[..capacity]);
    let count = len / 2;
    let mut valid = len % 2 == 0 && count <= capacity;
    for i in 0..count {
        if model_value(text[2 * i]).is_none() || model_value(text[2 * i + 1]).is_none() {
            valid = false;
        }
    }
    assert_eq!(actual.is_ok(), valid);
    if valid {
        assert_eq!(actual, Ok(count));
        for i in 0..count {
            let hi = model_value(text[2 * i]).unwrap_or(0);
            let lo = model_value(text[2 * i + 1]).unwrap_or(0);
            assert_eq!(out[i], (hi << 4) | lo);
        }
        for &byte in &out[count..] {
            assert_eq!(byte, 0xa5);
        }
    }
}

#[kani::proof]
fn hex_encode_model() {
    let bytes: [u8; 8] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let mut digits = [0u8; 16];
    encode_into(&bytes[..len], &mut digits[..2 * len]);
    for i in 0..len {
        assert_eq!(digits[2 * i], model_digit(bytes[i] >> 4));
        assert_eq!(digits[2 * i + 1], model_digit(bytes[i] & 0x0f));
    }
}

#[kani::proof]
#[kani::unwind(35)]
fn hex_digest_one_digit() {
    let position: usize = kani::any();
    let digit: u8 = kani::any();
    kani::assume(position < 64);
    let mut text = [b'0'; 71];
    text[..7].copy_from_slice(b"sha256:");
    text[7 + position] = digit;
    let actual = decode_sha256_digest(&text);
    if let Some(value) = model_value(digit) {
        let mut expected = [0u8; 32];
        expected[position / 2] = if position % 2 == 0 { value << 4 } else { value };
        assert_eq!(actual, Ok(expected));
    } else {
        assert_eq!(actual, Err(-crate::errno::EINVAL));
    }
}

#[kani::proof]
#[kani::unwind(35)]
fn hex_digest_shape() {
    let boundary: usize = kani::any();
    let prefix_at: usize = kani::any();
    let prefix_byte: u8 = kani::any();
    kani::assume(boundary < 7 && prefix_at < 7);
    let lengths = [0, 6, 7, 8, 70, 71, 72];
    let len = lengths[boundary];
    let mut text = [b'0'; 72];
    text[..7].copy_from_slice(b"sha256:");
    text[prefix_at] = prefix_byte;
    let actual = decode_sha256_digest(&text[..len]);
    if len == 71 && prefix_byte == b"sha256:"[prefix_at] {
        assert_eq!(actual, Ok([0u8; 32]));
    } else {
        assert_eq!(actual, Err(-crate::errno::EINVAL));
    }
}
