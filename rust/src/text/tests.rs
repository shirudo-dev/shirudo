// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::errno::{E2BIG, EINVAL, ERANGE};

/// The bytes of `text` in a vector of exactly their length, so that the
/// function under test sees no byte past them.
fn span(text: &[u8]) -> Vec<u8> {
    text.to_vec()
}

#[test]
fn digits_counts_leading_digits() {
    assert_eq!(digits(b"123abc"), 3);
    assert_eq!(digits(b"abc"), 0);
    assert_eq!(digits(b""), 0);
}

#[test]
fn decimal_fills_its_span() {
    assert_eq!(parse_u64(b"0", u64::MAX), Ok(0));
    assert_eq!(parse_u64(b"007", u64::MAX), Ok(7));
    assert_eq!(parse_u64(b"18446744073709551615", u64::MAX), Ok(u64::MAX));
}

#[test]
fn nothing_past_the_span_is_read() {
    assert_eq!(parse_u64(&span(b"123456")[..3], u64::MAX), Ok(123));
    assert_eq!(parse_u64(&span(b"123")[..0], u64::MAX), Err(-EINVAL));
}

#[test]
fn sign_blank_or_prefix_is_no_number() {
    for bad in ["", "-1", "+1", " 1", "1 ", "0x10", "1.5", "1e3", "12a"] {
        assert_eq!(parse_u64(bad.as_bytes(), u64::MAX), Err(-EINVAL), "{bad:?}");
    }
}

#[test]
fn number_past_its_bound_is_out_of_range() {
    assert_eq!(parse_u64(b"18446744073709551616", u64::MAX), Err(-ERANGE));
    assert_eq!(parse_u64(b"10", 10), Ok(10));
    assert_eq!(parse_u64(b"11", 10), Err(-ERANGE));
    assert_eq!(parse_u64(b"9", 5), Err(-ERANGE));
    assert_eq!(parse_u64(b"0", 0), Ok(0));
}

#[test]
fn malformed_number_however_long() {
    assert_eq!(parse_u64(b"99999999999999999999x", u64::MAX), Err(-EINVAL));
}

#[test]
fn hex_takes_either_case_and_no_prefix() {
    assert_eq!(parse_x64(b"ff", u64::MAX), Ok(255));
    assert_eq!(parse_x64(b"FF", u64::MAX), Ok(255));
    assert_eq!(parse_x64(b"ffffffffffffffff", u64::MAX), Ok(u64::MAX));
    assert_eq!(parse_x64(b"10000000000000000", u64::MAX), Err(-ERANGE));
    assert_eq!(parse_x64(b"0x10", u64::MAX), Err(-EINVAL));
    assert_eq!(parse_x64(b"g", u64::MAX), Err(-EINVAL));
}

#[test]
fn signed_number_spans_the_whole_range() {
    let s64 = |s: &str| parse_s64(s.as_bytes(), i64::MIN, i64::MAX);

    assert_eq!(s64("-9223372036854775808"), Ok(i64::MIN));
    assert_eq!(s64("9223372036854775807"), Ok(i64::MAX));
    assert_eq!(s64("-0"), Ok(0));
    assert_eq!(s64("9223372036854775808"), Err(-ERANGE));
    assert_eq!(s64("-9223372036854775809"), Err(-ERANGE));
}

#[test]
fn signed_number_keeps_bounds_and_form() {
    assert_eq!(parse_s64(b"0", 1, 10), Err(-ERANGE));
    assert_eq!(parse_s64(b"-6", -5, 5), Err(-ERANGE));
    assert_eq!(parse_s64(b"-5", -5, 5), Ok(-5));
    for bad in ["-", "--", "--1", "+1", " -1", "-x"] {
        assert_eq!(
            parse_s64(bad.as_bytes(), i64::MIN, i64::MAX),
            Err(-EINVAL),
            "{bad:?}"
        );
    }
}

#[test]
fn strscpy_copies_what_fits_whole() {
    let (mut six, mut big, mut one) = ([0xffu8; 6], [0xffu8; 64], [0xffu8; 1]);

    assert_eq!(strscpy(&mut six, b"hello"), Ok(5));
    assert_eq!(cstr(&six), b"hello");
    assert_eq!(strscpy(&mut big, b"hello"), Ok(5));
    assert_eq!(cstr(&big), b"hello");
    assert_eq!(strscpy(&mut one, b""), Ok(0));
    assert_eq!(cstr(&one), b"");
}

#[test]
fn strscpy_cuts_and_says_so() {
    let (mut five, mut one) = ([0xffu8; 5], [0xffu8; 1]);

    assert_eq!(strscpy(&mut five, b"hello"), Err(-E2BIG));
    assert_eq!(cstr(&five), b"hell");
    assert_eq!(strscpy(&mut one, b"hello"), Err(-E2BIG));
    assert_eq!(cstr(&one), b"");
    assert_eq!(strscpy(&mut [], b"hello"), Err(-E2BIG));
}

#[test]
fn name_glob_match_takes_stars_and_question_marks() {
    let glob = |pattern: &str, name: &str| name_glob_match(pattern.as_bytes(), name.as_bytes());

    for (pattern, name) in [
        ("php-fpm", "php-fpm"),
        ("php-fpm*", "php-fpm"),
        ("php-fpm*", "php-fpm8.3"),
        ("*.php", "index.php"),
        ("*.php", ".php"),
        ("a*c", "ac"),
        ("a*c", "abcbc"),
        ("*a*b*", "xaybz"),
        ("a**b", "ab"),
        ("php?.?", "php8.3"),
        ("*", "a"),
        ("*", ""),
        ("", ""),
    ] {
        assert!(glob(pattern, name), "{pattern:?}, {name:?}");
    }
    for (pattern, name) in [
        ("php-fpm", "php-fpm8"),
        ("php-fpm8", "php-fpm"),
        ("php-fpm*", "php-cgi8.3"),
        ("*.php", "index.php.bak"),
        ("a*c", "abcb"),
        ("*a*b*", "xbya"),
        ("php?.?", "php8.31"),
        ("php?", "php"),
        ("?", ""),
        ("", "a"),
    ] {
        assert!(!glob(pattern, name), "{pattern:?}, {name:?}");
    }
}

#[test]
fn name_glob_match_leaves_out_dot_and_dotdot() {
    for (pattern, name) in [
        ("*", "."),
        ("*", ".."),
        (".", "."),
        ("?", "."),
        ("??", ".."),
    ] {
        assert!(!name_glob_match(pattern.as_bytes(), name.as_bytes()));
    }
    for (pattern, name) in [("*", "..."), (".*", ".profile"), ("??", "a.")] {
        assert!(name_glob_match(pattern.as_bytes(), name.as_bytes()));
    }
}

#[test]
fn name_glob_match_reads_counted_bytes() {
    assert!(name_glob_match(b"php*", &b"php-fpm/junk"[..7]));
    assert!(!name_glob_match(b"*junk", &b"php-fpm/junk"[..7]));
    assert!(!name_glob_match(b"a", b"a\0b"));
    assert!(name_glob_match(b"a?b", b"a\0b"));
}

#[test]
fn dns_name_is_ldh_labels_and_no_address() {
    for good in [
        "registry.example.com",
        "Reg-1.Example",
        "localhost",
        "1.2.3.example",
        "0x.1",
    ] {
        assert!(dns_name_valid(good.as_bytes()), "{good}");
    }
    for bad in [
        "",
        ".",
        "example..com",
        "example.com.",
        "-example.com",
        "example-.com",
        "exa_mple.com",
        "example.com:443",
        "10.0.2.2",
        "127.1",
        "0x7f.1",
        "2130706433",
    ] {
        assert!(!dns_name_valid(bad.as_bytes()), "{bad}");
    }
    let label = "a".repeat(63);
    assert!(dns_name_valid(format!("{label}.example").as_bytes()));
    assert!(!dns_name_valid(format!("{label}a.example").as_bytes()));
    let longest = format!("{label}.{label}.{label}.{}", &label[..61]);
    assert_eq!(longest.len(), 253);
    assert!(dns_name_valid(longest.as_bytes()));
    assert!(!dns_name_valid(format!("{longest}a").as_bytes()));
}

#[test]
fn utf8_width_takes_well_formed_characters_only() {
    for (text, width) in [
        (&b""[..], 0),
        (b"a", 1),
        (b"\x7f", 1),
        (b"\xc2\x80", 2),
        (b"\xdf\xbf", 2),
        (b"\xe0\xa0\x80", 3),
        (b"\xed\x9f\xbf", 3),
        (b"\xee\x80\x80", 3),
        (b"\xef\xbf\xbf", 3),
        (b"\xf0\x90\x80\x80", 4),
        (b"\xf4\x8f\xbf\xbf", 4),
        (b"\xc3\xa9z", 2),
    ] {
        assert_eq!(utf8_width(&span(text)), width, "{text:?}");
    }
    for bad in [
        &b"\x80"[..],
        b"\xbf",
        b"\xc3",
        b"\xe2\x82",
        b"\xe2\x82z",
        b"\xc0\x80",
        b"\xc0\xaf",
        b"\xc1\xbf",
        b"\xe0\x80\xaf",
        b"\xe0\x9f\xbf",
        b"\xed\xa0\x80",
        b"\xed\xbf\xbf",
        b"\xf0\x8f\xbf\xbf",
        b"\xf4\x90\x80\x80",
        b"\xf5\x80\x80\x80",
        b"\xf8\x88\x80\x80\x80",
        b"\xff",
    ] {
        assert_eq!(utf8_width(&span(bad)), 0, "{bad:?}");
    }
}

/// Every scalar value, encoded.
fn scalar_values() -> impl Iterator<Item = (u32, Vec<u8>)> {
    (0..=0x10ffffu32).filter_map(|cp| {
        let c = char::from_u32(cp)?;
        let mut buf = [0u8; 4];
        Some((cp, c.encode_utf8(&mut buf).as_bytes().to_vec()))
    })
}

/// Every scalar value's encoding is taken, and there are no more 2-, 3-
/// and 4-byte sequences taken than scalar values of that length, so
/// those encodings are all there is.
#[test]
fn utf8_width_takes_the_scalar_values_alone() {
    assert_eq!(
        scalar_values()
            .filter(|(_, e)| utf8_width(e) != e.len())
            .count(),
        0
    );
    let two = (0..1u32 << 16)
        .filter(|i| utf8_width(&i.to_be_bytes()[2..]) == 2)
        .count();
    assert_eq!(two, 0x780);
    let three = (0..1u32 << 24)
        .filter(|i| utf8_width(&i.to_be_bytes()[1..]) == 3)
        .count();
    assert_eq!(three, 0xf000);
    let four = (0..1u32 << 22)
        .filter(|i| {
            let b = [
                0xf0 | (i >> 18) as u8,
                0x80 | (i >> 12 & 0x3f) as u8,
                0x80 | (i >> 6 & 0x3f) as u8,
                0x80 | (i & 0x3f) as u8,
            ];
            utf8_width(&b) == 4
        })
        .count();
    assert_eq!(four, 0x10_0000);
}

fn sanitized(text: &[u8], lines: bool) -> Vec<u8> {
    let mut buf = span(text);
    sanitize(&mut buf, lines);
    buf
}

#[test]
fn text_sanitize_replaces_controls_and_stray_bytes() {
    for (text, lines, want) in [
        (&b""[..], false, &b""[..]),
        (b"plain ~text", false, b"plain ~text"),
        (b"\x1b[31mred", false, b"?[31mred"),
        (b"a\0b\x7f", false, b"a?b?"),
        (b"t\tl\n", false, b"t?l?"),
        (b"t\tl\n", true, b"t\tl\n"),
        (b"a\r\nb\rc\r", true, b"a\r\nb?c?"),
        (b"\xc2\x9b\x33\x31m", true, b"??31m"),
        (b"\xc2\x80\xc2\x9f\xc2\xa0", false, b"????\xc2\xa0"),
        (
            b"caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x90\x9d",
            false,
            b"caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x90\x9d",
        ),
        (b"\xff\xc3z\xe2\x82", false, b"??z??"),
        (b"\xed\xa0\x80", false, b"???"),
    ] {
        assert_eq!(sanitized(text, lines), want, "{text:?}");
    }
}

/// Every scalar value but the controls passes; a control leaves only '?'.
#[test]
fn text_sanitize_passes_all_but_the_controls() {
    let wrong = scalar_values()
        .filter(|(cp, e)| {
            let control = *cp < 0x20 || (0x7f..=0x9f).contains(cp);
            let out = sanitized(e, false);
            if control {
                out.iter().any(|&c| c != b'?')
            } else {
                out != *e
            }
        })
        .count();
    assert_eq!(wrong, 0);
}

#[test]
fn memneq_explicit_tells_every_bit_apart() {
    use crate::util::chain::memneq_explicit;
    let a: Vec<u8> = (0..33u8)
        .map(|i| i.wrapping_mul(37).wrapping_add(1))
        .collect();
    let mut b = a.clone();

    assert!(!memneq_explicit(&a, &b));
    assert!(!memneq_explicit(&a[..0], &b[..0]));
    for i in 0..a.len() {
        for bit in 0..8 {
            b[i] ^= 1 << bit;
            assert!(memneq_explicit(&a, &b));
            assert!(!memneq_explicit(&a[..i], &b[..i]));
            b[i] ^= 1 << bit;
        }
    }
}

#[test]
fn name_has_suffix_wants_a_stem() {
    assert!(name_has_suffix(b"a.upatch", b".upatch"));
    assert!(name_has_suffix(&b"a.upatch.x"[..8], b".upatch"));
    assert!(!name_has_suffix(b".upatch", b".upatch"));
    assert!(!name_has_suffix(b"a.upatch.bak", b".upatch"));
    assert!(!name_has_suffix(b"a.UPATCH", b".upatch"));
    assert!(!name_has_suffix(b"", b""));
    assert!(name_has_suffix(b"a", b""));
}

#[test]
fn find_reads_only_the_counted_bytes() {
    let text = b"a\0b..c";

    assert_eq!(find(text, b".."), Some(3));
    assert_eq!(find(&text[..4], b".."), None);
    assert_eq!(find(text, b"..C"), None);
    assert_eq!(find(text, b""), Some(0));
    assert_eq!(find(b"", b""), Some(0));
    assert!(!contains(&text[..3], b".."));
}

#[test]
fn sprintf_result_keeps_a_fitting_output_and_clears_a_truncated_one() {
    let mut first = b'x';
    assert_eq!(sprintf_result(Some(&mut first), 4, 3), 3);
    assert_eq!(first, b'x');

    assert_eq!(sprintf_result(Some(&mut first), 4, 4), -E2BIG);
    assert_eq!(first, 0);
    assert_eq!(sprintf_result(None, 0, 0), -E2BIG);
    assert_eq!(sprintf_result(None, 0, -1), -E2BIG);
}
