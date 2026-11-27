// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::{append_text, last_newline_end};
use crate::errno::EINVAL;

#[kani::proof]
fn io_lines() {
    let bytes: [u8; 8] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let actual = last_newline_end(&bytes[..len]);
    let mut expected = 0;
    for i in 0..len {
        if bytes[i] == b'\n' {
            expected = i + 1;
        }
    }
    assert_eq!(actual, expected);
    assert!(actual <= len);
    if actual != 0 {
        assert_eq!(bytes[actual - 1], b'\n');
        for &c in &bytes[actual..len] {
            assert_ne!(c, b'\n');
        }
    }
}

#[kani::proof]
fn io_append_text() {
    let bytes: [u8; 3] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let trimmed = if len > 0 && bytes[len - 1] == b'\n' {
        len - 1
    } else {
        len
    };
    let expected = if bytes[..trimmed].contains(&b'\n') || bytes[..trimmed].contains(&0) {
        Err(-EINVAL)
    } else {
        Ok(&bytes[..trimmed])
    };
    assert_eq!(append_text(&bytes[..len]), expected);
}
