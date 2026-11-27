// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::{contains, find, name_has_suffix, parse_u64, parse_x64, strscpy, utf8_width};
use crate::errno::{E2BIG, EINVAL, ERANGE};

// Main's string-suffix harness covered names of at most six bytes and
// suffixes of at most three. A suffix needs a nonempty stem.
#[kani::proof]
fn string_suffix() {
    let name: [u8; 6] = kani::any();
    let suffix: [u8; 3] = kani::any();
    let name_len: usize = kani::any();
    let suffix_len: usize = kani::any();
    kani::assume(name_len <= name.len());
    kani::assume(suffix_len <= suffix.len());

    let mut expected = name_len > suffix_len;
    if expected {
        for i in 0..suffix.len() {
            if i < suffix_len && name[name_len - suffix_len + i] != suffix[i] {
                expected = false;
            }
        }
    }
    assert_eq!(
        name_has_suffix(&name[..name_len], &suffix[..suffix_len]),
        expected
    );
}

// Main's string-copy harness checked complete and truncated copies with
// source and destination lengths up to eight bytes.
#[kani::proof]
fn string_copy() {
    let src: [u8; 8] = kani::any();
    let mut dst: [u8; 8] = kani::any();
    let before = dst;
    let src_len: usize = kani::any();
    let dst_len: usize = kani::any();
    kani::assume(src_len <= src.len());
    kani::assume(dst_len <= dst.len());

    let result = strscpy(&mut dst[..dst_len], &src[..src_len]);
    let expected = if dst_len == 0 || src_len >= dst_len {
        Err(-E2BIG)
    } else {
        Ok(src_len)
    };
    assert_eq!(result, expected);

    let copied = if dst_len == 0 {
        0
    } else {
        src_len.min(dst_len - 1)
    };
    for i in 0..dst.len() {
        if i < copied {
            assert_eq!(dst[i], src[i]);
        } else if i == copied && dst_len > 0 {
            assert_eq!(dst[i], 0);
        } else {
            assert_eq!(dst[i], before[i]);
        }
    }
}

// Table 3-7 of the Unicode Standard, stated by its allowed byte ranges.
// This is separate from utf8_width's code point calculation.
fn utf8_table(s: &[u8]) -> usize {
    let Some(&first) = s.first() else { return 0 };
    let tail = |n: usize| s.get(n).is_some_and(|&b| (0x80..=0xbf).contains(&b));
    match first {
        0x00..=0x7f => 1,
        0xc2..=0xdf if tail(1) => 2,
        0xe0 if s.get(1).is_some_and(|&b| (0xa0..=0xbf).contains(&b)) && tail(2) => 3,
        0xe1..=0xec | 0xee..=0xef if tail(1) && tail(2) => 3,
        0xed if s.get(1).is_some_and(|&b| (0x80..=0x9f).contains(&b)) && tail(2) => 3,
        0xf0 if s.get(1).is_some_and(|&b| (0x90..=0xbf).contains(&b)) && tail(2) && tail(3) => 4,
        0xf1..=0xf3 if tail(1) && tail(2) && tail(3) => 4,
        0xf4 if s.get(1).is_some_and(|&b| (0x80..=0x8f).contains(&b)) && tail(2) && tail(3) => 4,
        _ => 0,
    }
}

// Four bytes contain every UTF-8 sequence. The fifth byte checks that
// a longer suffix cannot change the width of a complete first sequence.
#[kani::proof]
fn string_utf8() {
    let bytes: [u8; 5] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 4);
    assert_eq!(utf8_width(&bytes[..len]), utf8_table(&bytes[..len]));
    assert_eq!(utf8_width(&bytes[..4]), utf8_width(&bytes));
}

// The reference enumerates every possible starting position without
// calling windows() or the production search function.
#[kani::proof]
fn string_search() {
    let haystack: [u8; 5] = kani::any();
    let needle: [u8; 2] = kani::any();
    let haystack_len: usize = kani::any();
    let needle_len: usize = kani::any();
    kani::assume(haystack_len <= haystack.len());
    kani::assume(needle_len <= needle.len());

    let expected = if needle_len == 0 {
        Some(0)
    } else {
        let mut first = None;
        for start in 0..=haystack.len() {
            if first.is_none() && start + needle_len <= haystack_len {
                let mut equal = true;
                for offset in 0..needle.len() {
                    if offset < needle_len && haystack[start + offset] != needle[offset] {
                        equal = false;
                    }
                }
                if equal {
                    first = Some(start);
                }
            }
        }
        first
    };
    let haystack = &haystack[..haystack_len];
    let needle = &needle[..needle_len];
    assert_eq!(find(haystack, needle), expected);
    assert_eq!(contains(haystack, needle), expected.is_some());
}

// Shirudo.Number.valueFrom in Number.lean folds digits as value * base
// + digit. Inputs of at most four bytes cannot overflow u64.
#[kani::proof]
fn string_number_model() {
    let bytes: [u8; 4] = kani::any();
    let len: usize = kani::any();
    let max: u64 = kani::any();
    let hex: bool = kani::any();
    kani::assume(len <= bytes.len());

    let mut value = 0u64;
    let mut valid = len != 0;
    let base = if hex { 16u64 } else { 10u64 };
    for &c in &bytes[..len] {
        let digit = match c {
            b'0'..=b'9' => Some(u64::from(c - b'0')),
            b'a'..=b'f' if hex => Some(u64::from(c - b'a') + 10),
            b'A'..=b'F' if hex => Some(u64::from(c - b'A') + 10),
            _ => None,
        };
        if let Some(digit) = digit {
            value = value * base + digit;
        } else {
            valid = false;
        }
    }
    let expected = if !valid {
        Err(-EINVAL)
    } else if value > max {
        Err(-ERANGE)
    } else {
        Ok(value)
    };
    let actual = if hex {
        parse_x64(&bytes[..len], max)
    } else {
        parse_u64(&bytes[..len], max)
    };
    assert_eq!(actual, expected);
}
