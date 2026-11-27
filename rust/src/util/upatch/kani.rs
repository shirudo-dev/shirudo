// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::{name_from_pin_into, pin_name, pin_name_into};

// Shirudo.PinName.encodeByte in PinName.lean maps dot to tilde-d.
#[kani::proof]
fn pin_name_one() {
    let byte: u8 = kani::any();
    let actual = pin_name(&[byte]);
    if byte == b'.' {
        assert_eq!(actual.as_slice(), b"~d");
    } else {
        assert_eq!(actual.as_slice(), &[byte]);
    }
}

// Shirudo.PinName.encodeByte and encode in PinName.lean.
#[kani::proof]
fn pin_name_encode() {
    let bytes: [u8; 8] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let mut out = [0u8; 16];
    let used = pin_name_into(&bytes[..len], &mut out);
    let mut pos = 0;
    for &byte in &bytes[..len] {
        if byte == b'.' {
            assert_eq!(out[pos], b'~');
            assert_eq!(out[pos + 1], b'd');
            pos += 2;
        } else {
            assert_eq!(out[pos], byte);
            pos += 1;
        }
    }
    assert_eq!(used, pos);
}

// Shirudo.PinName.decode in PinName.lean: a tilde must have a d after it.
#[kani::proof]
fn pin_name_decode() {
    let pin: [u8; 8] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= pin.len());
    let mut out = [0u8; 8];
    let actual = name_from_pin_into(&pin[..len], &mut out);
    let mut model = [0u8; 8];
    let mut used = 0;
    let mut skip = false;
    let mut valid = true;
    for i in 0..len {
        if skip {
            skip = false;
        } else if pin[i] == b'~' {
            if i + 1 == len || pin[i + 1] != b'd' {
                valid = false;
                break;
            }
            model[used] = b'.';
            used += 1;
            skip = true;
        } else {
            model[used] = pin[i];
            used += 1;
        }
    }
    assert_eq!(actual.is_some(), valid);
    if valid {
        assert_eq!(actual, Some(used));
        assert_eq!(&out[..used], &model[..used]);
    }
}

// Shirudo.PinName.decode_encode in PinName.lean.
#[kani::proof]
fn pin_name_roundtrip() {
    let name: [u8; 4] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= name.len());
    kani::assume(!name[..len].contains(&b'~'));
    let mut pin = [0u8; 8];
    let pin_len = pin_name_into(&name[..len], &mut pin);
    let mut decoded = [0u8; 8];
    let decoded_len = name_from_pin_into(&pin[..pin_len], &mut decoded);
    assert_eq!(decoded_len, Some(len));
    assert_eq!(&decoded[..len], &name[..len]);
}
