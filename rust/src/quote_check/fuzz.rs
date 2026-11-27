// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-quote-check: one row of shirudo-quote-check as a backend hands
//! it over: its verdict the same each time, the fields a row needs for
//! any verdict but malformed, and the line the verdict is written as,
//! which must read back as one JSON object.

use core::ffi::{CStr, c_int};

use super::{
    BODY_HEX_LEN, LINE_MAX, QUOTE_BAD_SIGNATURE, QUOTE_BODY_MISMATCH, QUOTE_MALFORMED, QUOTE_OK,
    QuoteResult, row_check, row_emit,
};
use crate::errno::{E2BIG, EINVAL};
use crate::fuzzing::fuzz_target;
use crate::util::json::JsonEmit;
use crate::util::json::{Visit, walk};

fn abort() -> ! {
    std::process::abort()
}

fn result() -> QuoteResult {
    QuoteResult::empty()
}

/// The row's four tab-separated fields, or None for another count.
fn row_fields(row: &[u8]) -> Option<[&[u8]; 4]> {
    let mut it = row.split(|&b| b == b'\t');
    let fields = [it.next()?, it.next()?, it.next()?, it.next()?];
    it.next().is_none().then_some(fields)
}

fn base64_digit(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// RFC 4648 section 4 without the decoder the checker uses: whole groups
/// of four digits, padding at the end alone, and zero in the bits of the
/// last digit that no byte takes.
fn is_canonical_base64(s: &[u8]) -> bool {
    if !s.len().is_multiple_of(4) {
        return false;
    }
    let pad = s.iter().rev().take(2).take_while(|&&c| c == b'=').count();
    if !s[..s.len() - pad]
        .iter()
        .all(|&c| base64_digit(c).is_some())
    {
        return false;
    }
    match pad {
        1 => base64_digit(s[s.len() - 2]).is_some_and(|d| d & 0x03 == 0),
        2 => base64_digit(s[s.len() - 3]).is_some_and(|d| d & 0x0f == 0),
        _ => true,
    }
}

fn is_sha256_hex(s: &[u8]) -> bool {
    s.len() == BODY_HEX_LEN && s.iter().all(u8::is_ascii_hexdigit)
}

/// What the line of one verdict holds, as walk() reports it.
#[derive(Default)]
struct Line {
    key: Vec<u8>,
    ak_public: Vec<u8>,
    objects: u32,
    ok: Option<bool>,
    has_reason: bool,
    has_ak_public: bool,
}

impl Visit for Line {
    fn open(&mut self, array: bool) -> Result<(), c_int> {
        self.objects += 1;
        if array { Err(-EINVAL) } else { Ok(()) }
    }
    fn close(&mut self, _: bool) -> Result<(), c_int> {
        Ok(())
    }
    fn key(&mut self, key: &CStr) -> Result<(), c_int> {
        if key.count_bytes() >= 16 {
            return Err(-E2BIG);
        }
        self.key = key.to_bytes().to_vec();
        Ok(())
    }
    fn string(&mut self, s: &CStr) -> Result<(), c_int> {
        match &self.key[..] {
            b"reason" => self.has_reason = true,
            b"ak_public" => {
                self.has_ak_public = true;
                self.ak_public = s.to_bytes().to_vec();
            }
            _ => {}
        }
        Ok(())
    }
    fn number(&mut self, text: &[u8], _: bool) -> Result<(), c_int> {
        if self.key != b"ok" {
            return Ok(());
        }
        match text {
            [d @ (b'0' | b'1')] if self.ok.is_none() => {
                self.ok = Some(*d == b'1');
                Ok(())
            }
            _ => Err(-EINVAL),
        }
    }
    fn literal(&mut self, _: c_int) -> Result<(), c_int> {
        Ok(())
    }
}

fn same_result(a: &QuoteResult, b: &QuoteResult) -> bool {
    a.verdict == b.verdict
        && a.ak_name == b.ak_name
        && a.ak_public_len == b.ak_public_len
        && a.ak_public == b.ak_public
        && a.reset_count == b.reset_count
        && a.clock == b.clock
}

/// The line is one JSON object on one line within LINE_MAX, its "ok" is
/// the verdict, a reject alone names a reason, and an accepted row's key
/// comes back in the spelling the row gave it.
fn check_line(res: &QuoteResult, ak: &[u8]) {
    let accepted = res.verdict == QUOTE_OK;
    let mut text = [b'x'; LINE_MAX + 1];
    let mut e = JsonEmit::fixed(&mut text[..LINE_MAX]);
    if row_emit(res, &mut e) != 0 {
        abort();
    }
    let len = text.iter().position(|&c| c == 0).unwrap_or(text.len());
    let mut line = Line::default();
    if len >= LINE_MAX
        || text[..len].contains(&b'\n')
        || walk(&text[..len], &mut line).is_err()
        || line.objects != 1
        || line.ok != Some(accepted)
        || line.has_reason == accepted
        || line.has_ak_public != accepted
    {
        abort();
    }
    if accepted && line.ak_public != ak {
        abort();
    }
}

fuzz_target!(
    shirudo_fuzz_quote_check,
    shirudo_fuzz_quote_check_init,
    |data| {
        let (mut res, mut again) = (result(), result());
        let ret = row_check(data, &mut res);
        if row_check(data, &mut again) != ret {
            abort();
        }
        if ret.is_err() {
            return;
        }
        if !same_result(&res, &again) {
            abort();
        }
        let mut ak: &[u8] = &[];
        match res.verdict {
            QUOTE_MALFORMED => {}
            QUOTE_OK | QUOTE_BAD_SIGNATURE | QUOTE_BODY_MISMATCH => {
                // Nothing is checked of a row that is not all four fields.
                let Some(fields) = row_fields(data) else {
                    abort();
                };
                if !is_canonical_base64(fields[0])
                    || !is_canonical_base64(fields[1])
                    || !is_canonical_base64(fields[2])
                    || !is_sha256_hex(fields[3])
                    || res.ak_public_len > res.ak_public.len()
                {
                    abort();
                }
                ak = fields[2];
            }
            _ => abort(),
        }
        check_line(&res, ak);
    }
);
