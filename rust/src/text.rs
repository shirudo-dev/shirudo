// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The string rules of the C library, for Rust callers: a C string is the bytes of a buffer before its first
//! NUL, and a function here does to them what its C namesake does.

use core::ffi::c_int;

use crate::errno::{E2BIG, EINVAL, ERANGE};

/// The C string a buffer holds: its bytes up to the first NUL.
pub fn cstr(buf: &[u8]) -> &[u8] {
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());

    &buf[..n]
}

/// The byte at `i` of a C string, and the NUL past its end.
pub fn at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

/// strstr(): where `needle` first starts in `s`.
pub fn find(s: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    s.windows(needle.len()).position(|w| w == needle)
}

pub fn contains(s: &[u8], needle: &[u8]) -> bool {
    find(s, needle).is_some()
}

/// strscpy(): `src` into `dst`, terminated; -E2BIG, with as much of it
/// as fits, when it does not.
pub fn strscpy(dst: &mut [u8], src: &[u8]) -> Result<usize, c_int> {
    let Some(room) = dst.len().checked_sub(1) else {
        return Err(-E2BIG);
    };
    let n = src.len().min(room);

    dst[..n].copy_from_slice(&src[..n]);
    dst[n] = 0;
    if src.len() > room {
        return Err(-E2BIG);
    }
    Ok(n)
}

/// strsprintf() of a format of `%s` conversions alone: the parts one
/// after another, or -E2BIG and an empty buffer when they do not fit.
pub fn strsprintf(dst: &mut [u8], parts: &[&[u8]]) -> Result<usize, c_int> {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let Some(room) = dst.len().checked_sub(1) else {
        return Err(-E2BIG);
    };
    let mut pos = 0;

    for part in parts {
        let n = part.len().min(room - pos);

        dst[pos..pos + n].copy_from_slice(&part[..n]);
        pos += n;
    }
    dst[pos] = 0;
    if total > room {
        dst[0] = 0;
        return Err(-E2BIG);
    }
    Ok(total)
}

/// The text from `start` to `end` of the line in `buf`, without blanks
/// before it or blanks and line ends after it, which become NULs, as the
/// trim() of the C line readers made them: where it starts and ends.
pub fn trim_blanks(buf: &mut [u8], start: usize, end: usize) -> (usize, usize) {
    let mut s = start;
    let mut e = end;

    while s < e && matches!(buf[s], b' ' | b'\t') {
        s += 1;
    }
    while e > s && matches!(buf[e - 1], b' ' | b'\t' | b'\n' | b'\r') {
        e -= 1;
        buf[e] = 0;
    }
    (s, e)
}

/// The decimal digits of `v` in `buf`, as `%llu` prints them.
pub fn decimal(mut v: u64, buf: &mut [u8; 20]) -> &[u8] {
    let mut i = buf.len();

    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            return &buf[i..];
        }
    }
}

/// digits(): how many of the bytes of `s`, from the first, are decimal
/// digits.
pub fn digits(s: &[u8]) -> usize {
    s.iter().take_while(|c| c.is_ascii_digit()).count()
}

/// parse_u64(): the decimal number `s` spells, digits alone; -EINVAL for
/// anything else, -ERANGE when it is above `max`.
pub fn parse_u64(s: &[u8], max: u64) -> Result<u64, c_int> {
    if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
        return Err(-EINVAL);
    }
    s.iter().try_fold(0u64, |v, &c| {
        v.checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(c - b'0')))
            .filter(|&v| v <= max)
            .ok_or(-ERANGE)
    })
}

/// parse_s64(): an optional minus and the digits of a decimal number,
/// from `min` to `max`; -EINVAL for anything else, -ERANGE out of range.
pub fn parse_s64(s: &[u8], min: i64, max: i64) -> Result<i64, c_int> {
    let (neg, digits) = match s.strip_prefix(b"-") {
        Some(d) => (true, d),
        None => (false, s),
    };
    let limit = if neg {
        i64::MAX as u64 + 1
    } else {
        i64::MAX as u64
    };
    let v = parse_u64(digits, limit)?;
    let r = if !neg {
        v as i64
    } else if v == limit {
        i64::MIN
    } else {
        -(v as i64)
    };
    if r < min || r > max {
        Err(-ERANGE)
    } else {
        Ok(r)
    }
}

/// name_has_suffix(): whether `name` is a stem of at least one byte and
/// then `suffix`, as a file name and its extension are.
pub fn name_has_suffix(name: &[u8], suffix: &[u8]) -> bool {
    name.len() > suffix.len() && name.ends_with(suffix)
}

/// Whether the counted file `name` matches `pattern`: `*` takes any
/// run of bytes, `?` takes one byte and every other byte itself. The
/// directory entries "." and ".." never match.
pub fn name_glob_match(pattern: &[u8], name: &[u8]) -> bool {
    if matches!(name, b"." | b"..") {
        return false;
    }
    let (mut p, mut n) = (0usize, 0usize);
    let mut after_star = None;
    let mut retry_at = 0usize;

    while n < name.len() {
        if pattern.get(p) == Some(&b'*') {
            p += 1;
            after_star = Some(p);
            retry_at = n;
        } else if pattern.get(p).is_some_and(|&c| c == b'?' || c == name[n]) {
            p += 1;
            n += 1;
        } else if let Some(after) = after_star {
            p = after;
            retry_at += 1;
            n = retry_at;
        } else {
            return false;
        }
    }
    while pattern.get(p) == Some(&b'*') {
        p += 1;
    }
    p == pattern.len()
}

/// parse_x64(): parse_u64() of hexadecimal digits of either case.
pub fn parse_x64(s: &[u8], max: u64) -> Result<u64, c_int> {
    if s.is_empty() || !s.iter().all(u8::is_ascii_hexdigit) {
        return Err(-EINVAL);
    }
    s.iter().try_fold(0u64, |v, &c| {
        let d = u64::from((c as char).to_digit(16).unwrap_or(0));
        v.checked_mul(16)
            .and_then(|v| v.checked_add(d))
            .filter(|&v| v <= max)
            .ok_or(-ERANGE)
    })
}

/// The result of snprintf() into `size` bytes: the length, or -E2BIG.
/// On truncation, clear the first byte of the output when it exists.
pub(crate) fn sprintf_result(first: Option<&mut u8>, size: usize, n: c_int) -> c_int {
    if usize::try_from(n).is_ok_and(|n| n < size) {
        return n;
    }
    if let Some(first) = first {
        *first = 0;
    }
    -E2BIG
}

/// strsprintf() of a C format: the C library's snprintf() into the
/// `size` bytes at `buf`, and the length written, or -E2BIG with `buf`
/// left empty when the output does not fit. The caller's unsafe block
/// holds the room, the format and the arguments it converts.
macro_rules! csprintf {
    ($buf:expr, $size:expr, $fmt:expr $(, $arg:expr)* $(,)?) => {{
        let (buf, size): (*mut ::core::ffi::c_char, usize) = ($buf, $size);
        let n = $crate::sys::libc::snprintf(buf, size, $fmt $(, $arg)*);
        #[allow(unused_unsafe)]
        let first = if size == 0 {
            None
        } else {
            // SAFETY: the caller gave snprintf room for size bytes.
            Some(unsafe { &mut *buf.cast::<u8>() })
        };
        $crate::text::sprintf_result(first, size, n)
    }};
}
pub(crate) use csprintf;

/// A label an IPv4 parser reads as a number: decimal digits, or 0x and
/// hex digits.
fn numeric_dns_label(label: &[u8]) -> bool {
    match label {
        [] => false,
        [b'0', b'x' | b'X', rest @ ..] if !label[2..].is_empty() => {
            rest.iter().all(u8::is_ascii_hexdigit)
        }
        _ => label.iter().all(u8::is_ascii_digit),
    }
}

/// dns_name_valid(): a DNS host name, labels of letters, digits and inner
/// hyphens, 1 to 63 bytes each and 253 in all, not all of them numbers,
/// which an IPv4 parser would read as an address.
pub fn dns_name_valid(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let mut numeric = true;
    for label in name.split(|&c| c == b'.') {
        if label.is_empty()
            || label.len() > 63
            || label[0] == b'-'
            || label[label.len() - 1] == b'-'
            || !label
                .iter()
                .all(|&c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return false;
        }
        numeric &= numeric_dns_label(label);
    }
    !numeric
}

/// utf8_width(): the length of the well-formed UTF-8 sequence `s` starts
/// with, by Table 3-7 of the Unicode Standard, or 0 for none.
pub fn utf8_width(s: &[u8]) -> usize {
    let Some(&c) = s.first() else {
        return 0;
    };
    if c < 0x80 {
        return 1;
    }
    let (width, mut cp) = match c {
        _ if c & 0xe0 == 0xc0 => (2, u32::from(c & 0x1f)),
        _ if c & 0xf0 == 0xe0 => (3, u32::from(c & 0x0f)),
        _ if c & 0xf8 == 0xf0 => (4, u32::from(c & 0x07)),
        _ => return 0,
    };
    if width > s.len() {
        return 0;
    }
    for &b in &s[1..width] {
        if b & 0xc0 != 0x80 {
            return 0;
        }
        cp = (cp << 6) | u32::from(b & 0x3f);
    }
    let shortest = [0, 0, 0x80, 0x800, 0x10000][width];
    if cp < shortest || cp > 0x10_ffff || (0xd800..=0xdfff).contains(&cp) {
        return 0;
    }
    width
}

/// text_sanitize(): `s` made safe to show on a terminal, its length
/// unchanged: every byte of a C0 or C1 control, DEL or an ill-formed
/// sequence becomes `?`, and with `lines` tabs, line feeds and a carriage
/// return before one stay.
pub fn sanitize(s: &mut [u8], lines: bool) {
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        let n = utf8_width(&s[i..]);
        let shown = match c {
            b'\t' | b'\n' => lines,
            b'\r' => lines && s.get(i + 1) == Some(&b'\n'),
            _ => match n {
                1 => c >= 0x20 && c != 0x7f,
                2 => c != 0xc2 || s[i + 1] >= 0xa0,
                _ => n != 0,
            },
        };
        let n = n.max(1);
        if !shown {
            s[i..i + n].fill(b'?');
        }
        i += n;
    }
}

#[cfg(test)]
mod tests;
