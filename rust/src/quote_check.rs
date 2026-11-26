// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! shirudo-quote-check: rows of keepalive quotes on standard input, one
//! JSON verdict per row on standard output, for as long as rows come.
//! The checks are those a backend runs on a keepalive quote, without a
//! TPM, a key list or state: the attestation key signed it as an
//! endorsement primary, and it covers the SHA-256 of the body the record
//! carries. main() is tools/quote-check/quote-check.rs; the unit suite
//! and the fuzzer drive the rows.

use core::ffi::{CStr, c_int};
use std::io::{BufRead, Write};

use crate::errno::{EBADMSG, EINVAL, EIO, EKEYREJECTED};
use crate::ffi;
use crate::sys::libc::strerror;
use crate::util::help::Help;
use crate::util::io;
use crate::util::json::JsonEmit;
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptParser};
use crate::util::tpm::{ATTEST_MAX, PUBLIC_MAX, SIGNATURE_MAX};
use crate::util::tpm_wire::{
    ALG_ECC, ALG_ECDSA, ALG_SHA256, DIGEST_LEN, ECC_NIST_P256, NAME_LEN, ST_ATTEST_QUOTE,
    TpmAttest, TpmPublic, attest_parse, attest_signer, attest_verify, object_name, public_parse,
};

/// The length of the standard base64 of `n` bytes.
const fn base64_len(n: usize) -> usize {
    4 * n.div_ceil(3)
}

const BODY_HEX_LEN: usize = 2 * DIGEST_LEN;
/// `QUOTE_ROW_MAX`: attest, sig, ak and body_sha256 with the three tabs
/// between them.
const ROW_MAX: usize =
    base64_len(ATTEST_MAX) + base64_len(SIGNATURE_MAX) + base64_len(PUBLIC_MAX) + BODY_HEX_LEN + 3;
/// `QUOTE_LINE_MAX`: room for any verdict's line.
const LINE_MAX: usize = 1024;

/// `enum quote_verdict`.
const QUOTE_OK: c_int = 0;
const QUOTE_BAD_SIGNATURE: c_int = 1;
const QUOTE_BODY_MISMATCH: c_int = 2;
const QUOTE_MALFORMED: c_int = 3;

/// `struct quote_result`: what follows the verdict describes a QUOTE_OK
/// row alone.
#[repr(C)]
pub struct QuoteResult {
    verdict: c_int,
    ak_name: [u8; NAME_LEN],
    ak_public: [u8; PUBLIC_MAX],
    ak_public_len: usize,
    reset_count: u32,
    clock: u64,
}

const _: () = assert!(size_of::<QuoteResult>() == 576);

impl QuoteResult {
    const fn malformed() -> Self {
        QuoteResult {
            verdict: QUOTE_MALFORMED,
            ak_name: [0; NAME_LEN],
            ak_public: [0; PUBLIC_MAX],
            ak_public_len: 0,
            reset_count: 0,
            clock: 0,
        }
    }
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(base64_len(data.len()));

    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);

        for i in 0..4 {
            out.push(if i <= chunk.len() {
                BASE64[(n >> (18 - 6 * i) & 63) as usize]
            } else {
                b'='
            });
        }
    }
    out
}

/// The bytes of `text` where it is standard base64 with its padding and
/// nothing else, the encoding of what it decodes to and of at most
/// `cap` bytes; a backend's row admits no other spelling of a field.
fn base64_field(text: &[u8], cap: usize) -> Option<Vec<u8>> {
    if text.len() > base64_len(cap) || !text.len().is_multiple_of(4) {
        return None;
    }
    let value = |c: u8| BASE64.iter().position(|&b| b == c).map(|v| v as u32);
    let mut out = Vec::with_capacity(text.len() / 4 * 3);

    for (i, quad) in text.as_chunks::<4>().0.iter().enumerate() {
        let last = i + 1 == text.len() / 4;
        let pad = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad != 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &quad[..4 - pad] {
            n = n << 6 | value(c)?;
        }
        n <<= 6 * pad as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        // The bits padding leaves over are zero in the one encoding.
        if bytes[3 - pad..].iter().any(|&b| b != 0) {
            return None;
        }
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    (out.len() <= cap).then_some(out)
}

/// The SHA-256 a row's last field spells in 64 hex digits of either
/// case.
fn body_sha256_field(text: &[u8]) -> Option<[u8; DIGEST_LEN]> {
    let digit = |c: u8| char::from(c).to_digit(16);
    let mut out = [0u8; DIGEST_LEN];

    if text.len() != BODY_HEX_LEN {
        return None;
    }
    for (b, pair) in out.iter_mut().zip(text.as_chunks::<2>().0.iter()) {
        *b = (digit(pair[0])? << 4 | digit(pair[1])?) as u8;
    }
    Some(out)
}

fn ak_is_p256_ecdsa(ak: &TpmPublic) -> bool {
    ak.ty == ALG_ECC
        && ak.curve == ECC_NIST_P256
        && ak.scheme == ALG_ECDSA
        && ak.scheme_hash == ALG_SHA256
}

/// shirudo attest signs its quotes with the same key over a nonce the
/// caller chooses and refuses an empty PCR selection, so the empty one
/// is what makes a quote a keepalive's.
fn is_keepalive_quote(attest: &TpmAttest) -> bool {
    attest.ty == ST_ATTEST_QUOTE && attest.pcr_mask == 0
}

/// One TabSeparated row without its newline into `res`: Ok with the
/// verdict there, whatever the row holds, or the error where the check
/// itself could not run and there is no verdict.
fn row_check(row: &[u8], res: &mut QuoteResult) -> Result<(), c_int> {
    *res = QuoteResult::malformed();
    let fields: Vec<&[u8]> = row.split(|&c| c == b'\t').collect();
    let &[attest, sig, ak, body] = &fields[..] else {
        return Ok(());
    };
    let (Some(attest), Some(sig), Some(ak), Some(body)) = (
        base64_field(attest, ATTEST_MAX),
        base64_field(sig, SIGNATURE_MAX),
        base64_field(ak, PUBLIC_MAX),
        body_sha256_field(body),
    ) else {
        return Ok(());
    };
    res.ak_public[..ak.len()].copy_from_slice(&ak);
    res.ak_public_len = ak.len();

    let mut public = TpmPublic::zeroed();
    if public_parse(&ak, &mut public) != 0 || !ak_is_p256_ecdsa(&public) {
        return Ok(());
    }
    let mut quote = TpmAttest::zeroed();
    if attest_parse(&attest, &mut quote) != 0 || !is_keepalive_quote(&quote) {
        return Ok(());
    }

    match object_name(&ak, &mut res.ak_name) {
        0 => {}
        err => return Err(err),
    }
    if !attest_signer(&quote, &res.ak_name)? {
        res.verdict = QUOTE_BAD_SIGNATURE;
        return Ok(());
    }
    match attest_verify(&attest, &sig, &public.x, &public.y) {
        0 => {}
        err if err == -EBADMSG => return Ok(()),
        err if err == -EKEYREJECTED => {
            res.verdict = QUOTE_BAD_SIGNATURE;
            return Ok(());
        }
        err => return Err(err),
    }

    if quote.extra_in(&attest) != Some(&body[..]) {
        res.verdict = QUOTE_BODY_MISMATCH;
        return Ok(());
    }
    res.verdict = QUOTE_OK;
    res.reset_count = quote.reset_count;
    res.clock = quote.clock;
    Ok(())
}

/// The verdict as its JSON object, without a newline, into `e`.
fn row_emit(res: &QuoteResult, e: &mut JsonEmit) -> c_int {
    let mut ret = 0;

    e.obj_open();
    match res.verdict {
        QUOTE_OK => match res.ak_public.get(..res.ak_public_len) {
            Some(public) => {
                let name = crate::util::hex::encode(&res.ak_name);

                e.kv_int(b"ok", 1);
                e.kv_string(b"ak_name", &name);
                e.kv_string(b"ak_public", &base64_encode(public));
                e.kv_int(b"reset_count", i64::from(res.reset_count));
                e.kv_u64(b"clock", res.clock);
            }
            None => ret = -EINVAL,
        },
        QUOTE_BAD_SIGNATURE | QUOTE_BODY_MISMATCH | QUOTE_MALFORMED => {
            let reason: &[u8] = match res.verdict {
                QUOTE_BAD_SIGNATURE => b"bad_signature",
                QUOTE_BODY_MISMATCH => b"body_mismatch",
                _ => b"malformed",
            };
            e.kv_int(b"ok", 0);
            e.kv_string(b"reason", reason);
        }
        _ => ret = -EINVAL,
    }
    e.obj_close();
    if ret != 0 { ret } else { e.err() }
}

static HELP: Help = Help::new(
    c"shirudo-quote-check",
    Some(
        c"Reads TabSeparated rows from standard input until it ends:\n  \
          <attest>\\t<sig>\\t<ak>\\t<body_sha256>\n\
          attest, sig and ak are a keepalive quote's TPMS_ATTEST and\n\
          TPMT_SIGNATURE and the signing key's TPMT_PUBLIC, in standard\n\
          base64. body_sha256 is the SHA-256 of the record's body, 64\n\
          hex digits. Writes one JSON line per row, in order:\n  \
          {\"ok\":1,\"ak_name\":\"<hex>\",\"ak_public\":\"<base64>\",\n   \
          \"reset_count\":<n>,\"clock\":<n>}\n  \
          {\"ok\":0,\"reason\":\"bad_signature\"|\"body_mismatch\"|\n   \
          \"malformed\"}",
    ),
    &[],
    None,
);

/// The verdict of one input line: a NUL or a row longer than the
/// permitted maximum makes it malformed.
fn line_check(line: &[u8]) -> Result<QuoteResult, c_int> {
    let row = line.strip_suffix(b"\n").unwrap_or(line);
    let mut res = QuoteResult::malformed();

    if !line.contains(&0) && row.len() <= ROW_MAX {
        row_check(row, &mut res)?;
    }
    Ok(res)
}

/// The rows of standard input until it ends, each verdict written and
/// flushed before the next row is read: the caller waits for each row's
/// answer before it sends the next.
fn check_rows() -> Result<(), c_int> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let mut line = Vec::new();
    let mut json = [0u8; LINE_MAX];

    loop {
        line.clear();
        if input
            .read_until(b'\n', &mut line)
            .map_err(|e| io::errno_of(&e))?
            == 0
        {
            return Ok(());
        }
        let res = line_check(&line)?;
        let mut e = JsonEmit::fixed(&mut json);
        match row_emit(&res, &mut e) {
            0 => {}
            err => return Err(err),
        }
        output
            .write_all(e.output())
            .and_then(|()| output.write_all(b"\n"))
            .and_then(|()| output.flush())
            .map_err(|_| -EIO)?;
    }
}

fn quote_check(args: &[&CStr]) -> c_int {
    let mut p = OptParser::new(c"shirudo-quote-check", &[], Some(&HELP), args, 1);

    match p.next() {
        OPT_END => {}
        OPT_DONE => return 0,
        OPT_ARG => {
            p.usage_arg(b"takes no argument, got ");
            return EXIT_USAGE;
        }
        _ => return EXIT_USAGE,
    }
    match check_rows() {
        Ok(()) => 0,
        Err(err) => {
            // SAFETY: strerror() gives a C string.
            let why = unsafe { ffi::c_str(strerror(-err)) };
            let _ = std::io::stderr().write_all(&[b"shirudo-quote-check: ", why, b"\n"].concat());
            1
        }
    }
}

#[cfg(shirudo_fuzz)]
mod fuzz;
#[cfg(test)]
mod tests;

mod capi {
    use core::ffi::{c_char, c_int};

    /// # Safety
    ///
    /// `argv` holds `argc` C strings, as main() receives them.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn quote_check_main(argc: c_int, argv: *const *const c_char) -> c_int {
        // SAFETY: main()'s arguments, which live as long as the process.
        super::quote_check(&unsafe { crate::ffi::args(argc, argv) })
    }
}
