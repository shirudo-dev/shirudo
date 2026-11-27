// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The OpenTelemetry export of shirudo: a BPF map as an OTLP log or as
//! the metrics its signed decoder makes of it, a map too large for OTLP
//! as a snapshot in S3 that a log points at, and the status keepalive,
//! sent over OTLP/HTTP JSON with the OTEL_EXPORTER_OTLP_* settings.

mod http;
mod otlp;
mod s3;

use core::ffi::{CStr, c_char, c_int};

use crate::bpf::btf::{
    Btf, INT_SIGNED, KIND_CONST, KIND_INT, KIND_RESTRICT, KIND_TYPE_TAG, KIND_TYPEDEF,
    KIND_VOLATILE,
};
use crate::errno::{E2BIG, EINVAL, ENODATA, EOPNOTSUPP};
use crate::sys::libc::{fwrite, stderr};
use crate::util::map_format;
use crate::util::map_read::MapView;

/// `enum otel_signal`, the values of SHIRUDO_UPATCH_DECODER_EXPORT_*.
pub(crate) const LOG: c_int = 1;
pub(crate) const METRIC: c_int = 2;

/// `enum otel_mode`.
pub(crate) const AUTO: c_int = 0;
pub(crate) const FORCE_LOG: c_int = 1;
pub(crate) const FORCE_METRIC: c_int = 2;
pub(crate) const S3: c_int = 3;

/// The deepest a BTF type's typedefs and modifiers are followed.
const MAX_TYPE_UNWRAP: usize = 32;

/// `struct otel_opts`: where and how to export, NULL strings for none.
#[derive(Clone, Copy)]
pub struct OtelOpts {
    pub endpoint: *const c_char,
    pub tenant_id: *const c_char,
    pub s3_uri: *const c_char,
    pub allow_insecure: bool,
    pub retries: u32,
    pub log_record_max_bytes: u32,
    pub otlp_max_bytes: u32,
}

impl OtelOpts {
    /// What a caller without options gets: 3 retries.
    const fn defaults() -> Self {
        OtelOpts {
            endpoint: core::ptr::null(),
            tenant_id: core::ptr::null(),
            s3_uri: core::ptr::null(),
            allow_insecure: false,
            retries: 3,
            log_record_max_bytes: 0,
            otlp_max_bytes: 0,
        }
    }

    fn endpoint(&self) -> Option<&CStr> {
        // SAFETY: the options' strings, NULL or C strings that outlive
        // the export.
        unsafe { opt_cstr(self.endpoint) }
    }

    fn tenant_id(&self) -> Option<&CStr> {
        // SAFETY: as endpoint().
        unsafe { opt_cstr(self.tenant_id) }
    }

    fn s3_uri(&self) -> Option<&CStr> {
        // SAFETY: as endpoint().
        unsafe { opt_cstr(self.s3_uri) }
    }
}

/// # Safety
///
/// `p` is NULL or a C string that outlives `'a`.
unsafe fn opt_cstr<'a>(p: *const c_char) -> Option<&'a CStr> {
    // SAFETY: the caller's C string.
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) })
}

/// A name of a map view, empty for none.
fn name_or_empty(s: Option<&'static CStr>) -> &'static [u8] {
    s.map_or(b"", CStr::to_bytes)
}

/// isspace() of the C locale, `\v` and `\f` with the rest.
fn is_c_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn hex_lower(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| [HEX[usize::from(b >> 4)], HEX[usize::from(b & 0xf)]])
        .collect()
}

/// A diagnostic to the C library's stderr, as the rest of the command
/// writes them.
fn eprint(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stderr.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stderr) };
}

/// The value's BTF type with its typedefs and modifiers followed.
fn unwrap_btf_type(btf: &Btf, mut id: u32) -> Option<u32> {
    for _ in 0..MAX_TYPE_UNWRAP {
        if !btf.has(id) {
            return None;
        }
        if !matches!(
            btf.kind(id),
            KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG
        ) {
            return Some(id);
        }
        id = btf.size_or_type(id);
    }
    None
}

/// Whether the map's value is an integer scalar of 1, 2, 4 or 8 bytes,
/// and signed: -ENODATA without BTF, -EOPNOTSUPP for another value.
fn metric_type(v: &MapView) -> Result<(bool, u32), c_int> {
    let btf = v
        .btf
        .as_ref()
        .filter(|_| v.value_type_id != 0)
        .ok_or(-ENODATA)?;
    let t = unwrap_btf_type(btf, v.value_type_id).ok_or(-EOPNOTSUPP)?;
    let size = btf.size_or_type(t);
    if btf.kind(t) != KIND_INT || size != v.value_size || !matches!(size, 1 | 2 | 4 | 8) {
        return Err(-EOPNOTSUPP);
    }
    let (offset, bits, enc) = (btf.int_offset(t), btf.int_bits(t), btf.int_encoding(t));
    if offset != 0 || u32::from(bits) != size * 8 {
        return Err(-EOPNOTSUPP);
    }
    Ok((enc & INT_SIGNED != 0, size))
}

/// The signal a map exports as without a decoder: a metric only for an
/// unsigned per-CPU integer, which sums across CPUs, else a log; and
/// why.
pub(crate) fn classify(v: &MapView) -> (c_int, String) {
    if v.serialized {
        return (LOG, "map uses a serializer".into());
    }
    if v.skipped {
        return (LOG, "map type is not generically readable".into());
    }
    if !map_format::is_percpu(v.ty) {
        return (LOG, "map is not per-CPU".into());
    }
    match metric_type(v) {
        Err(_) => (LOG, "value is not a BTF integer scalar".into()),
        Ok((true, _)) => (LOG, "value is signed".into()),
        Ok((false, width)) => (METRIC, format!("unsigned per-CPU {}-bit scalar", width * 8)),
    }
}

/// Exports the map as `mode` says, through the decoder at `decoder_path`
/// or the upatch's.
pub(crate) fn send_file(
    decoder_path: Option<&CStr>,
    v: &MapView,
    mode: c_int,
    opts: Option<&OtelOpts>,
) -> c_int {
    if mode == S3 {
        let Some(uri) = opts.and_then(OtelOpts::s3_uri) else {
            return -EINVAL;
        };
        return s3::send(uri, v, opts, decoder_path);
    }
    let signal = match mode {
        FORCE_METRIC => METRIC,
        FORCE_LOG | AUTO => LOG,
        _ => return -EINVAL,
    };
    let endpoint = opts.and_then(OtelOpts::endpoint);
    match http::open_for_map(endpoint, v, opts, mode == AUTO, signal, decoder_path) {
        Ok(mut t) => t.emit(v),
        Err(err) => err,
    }
}

/// Exports the map as a log or metric, as its shape suggests.
pub(crate) fn send_auto(v: &MapView, opts: Option<&OtelOpts>) -> c_int {
    send_file(None, v, AUTO, opts)
}

/// Exports the map as its decoder's signed signal selection says, and a
/// log too large for OTLP as a snapshot in S3 when there is a bucket.
pub(crate) fn send_decoded(v: &MapView, signal: c_int, opts: Option<&OtelOpts>) -> c_int {
    let mode = match signal {
        LOG => FORCE_LOG,
        METRIC => FORCE_METRIC,
        _ => return -EINVAL,
    };
    let ret = send_file(None, v, mode, opts);
    if ret == -E2BIG && opts.and_then(OtelOpts::s3_uri).is_some() {
        return send_file(None, v, S3, opts);
    }
    ret
}

/// The OTLP severity of a status verdict, and its text.
pub(crate) fn status_severity(status: &[u8]) -> (c_int, &'static CStr) {
    match status {
        b"ok" => (9, c"INFO"),
        b"degraded" | b"init-pending" | b"reboot-pending" => (13, c"WARN"),
        _ => (17, c"ERROR"),
    }
}

/// The log or metric payload the decoder of the artifact at `path`
/// makes of `v`, for the otel map test helper.
#[cfg(feature = "test-helpers")]
pub(crate) fn payload_file(path: &CStr, v: &MapView, metric: bool) -> Result<Vec<u8>, c_int> {
    if metric {
        otlp::metric_payload(Some(path), v)
    } else {
        otlp::log_payload(Some(path), v, 0)
    }
}

/// Sends `body` as the string body of one OTLP log with the one string
/// attribute `attr_key`, as the keepalive sends its body: the receiver
/// decodes the very bytes passed in. A body with a NUL or malformed
/// UTF-8 is -EILSEQ, and nothing is sent. 0 or -errno.
#[allow(clippy::too_many_arguments)]
pub(crate) fn send_log_string(
    opts: Option<&OtelOpts>,
    scope_name: &[u8],
    event_name: &[u8],
    severity_number: c_int,
    severity_text: &[u8],
    body: &[u8],
    attr_key: &[u8],
    attr_value: &[u8],
) -> c_int {
    let record = otlp::StringRecord {
        scope_name,
        event_name,
        severity_number,
        severity_text,
        body,
        attr_key,
        attr_value,
    };
    http::send_log_string(opts, &record)
}

/// The seconds a Retry-After value asks for at `now`, for the otel map
/// test helper.
#[cfg(feature = "test-helpers")]
pub(crate) fn retry_after(value: &[u8], now: i64) -> Result<u64, c_int> {
    http::retry_after(value, now)
}

#[cfg(shirudo_fuzz)]
mod fuzz;
