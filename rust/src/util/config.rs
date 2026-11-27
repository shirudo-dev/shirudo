// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The site configuration: the `key = value`
//! lines of /etc/shirudo/shirudo.conf, or the settings a config image
//! carries, and the TPM settings the environment overrides.

use core::ffi::{CStr, c_int};
use core::mem::MaybeUninit;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsFd, BorrowedFd, IntoRawFd};

use crate::errno::{EINVAL, EIO, ENOENT, EPERM};
use crate::sys::libc::{O_RDONLY, close, env, errno, explicit_bzero, scrub};
use crate::text::{dns_name_valid, parse_u64, strscpy, trim_blanks};
use crate::util::hex::decode_max;
use crate::util::io::{check_secret, check_trusted, open_trusted};
use crate::util::json::MAX_BYTES;

const OWNER_AUTH_MAX: usize = 256;
const TPM_TCTI_MAX: usize = 256;
const TLS_HOSTS_MAX: usize = 1024;
const MAP_EXPORT_PATH_MAX: usize = 4096;
const MAP_EXPORT_ENDPOINT_MAX: usize = 2048;
const MAP_EXPORT_URI_MAX: usize = 2048;
const TENANT_ID_MAX: usize = 128;
pub(crate) const LOG_RECORD_MAX_DEFAULT: u32 = 1024 * 1024;
pub(crate) const OTLP_MAX_DEFAULT: u32 = 4 * 1024 * 1024;
pub(crate) const CONF_PATH: &CStr = c"/etc/shirudo/shirudo.conf";

/// `struct config`.
pub struct Config {
    pub(crate) eventlog_max_bytes: u64,
    pub(crate) tpm_owner_auth: [u8; OWNER_AUTH_MAX],
    pub(crate) tpm_owner_auth_len: usize,
    pub(crate) tpm_tcti: [u8; TPM_TCTI_MAX],
    pub(crate) tls_classical_hosts_valid: bool,
    pub(crate) tls_classical_hosts: [u8; TLS_HOSTS_MAX],
    pub(crate) map_export_valid: bool,
    pub(crate) map_export_json_path: [u8; MAP_EXPORT_PATH_MAX],
    pub(crate) map_export_otel_endpoint: [u8; MAP_EXPORT_ENDPOINT_MAX],
    pub(crate) map_export_tenant_id: [u8; TENANT_ID_MAX + 1],
    pub(crate) map_export_otel_insecure: bool,
    pub(crate) map_export_otel_retries: u32,
    pub(crate) map_export_s3_uri: [u8; MAP_EXPORT_URI_MAX],
    pub(crate) map_export_log_record_max_bytes: u32,
    pub(crate) map_export_otlp_max_bytes: u32,
}

/// A configuration scrubbed when it goes, as `__cleanup(config_clear)`
/// left the C's.
pub(crate) struct Scrubbed(Box<Config>);

impl Scrubbed {
    /// An empty configuration, for load() to fill.
    pub(crate) fn new() -> Self {
        Scrubbed(Box::new(Config::zeroed()))
    }

    /// Every byte of the configuration scrubbed, now.
    pub(crate) fn scrub(&mut self) {
        let cfg: *mut Config = &mut *self.0;
        // SAFETY: the bytes of the configuration, all of whose bits zeroed
        // are a value of it.
        unsafe { explicit_bzero(cfg.cast(), size_of::<Config>()) };
    }
}

impl core::ops::Deref for Scrubbed {
    type Target = Config;

    fn deref(&self) -> &Config {
        &self.0
    }
}

impl core::ops::DerefMut for Scrubbed {
    fn deref_mut(&mut self) -> &mut Config {
        &mut self.0
    }
}

impl Drop for Scrubbed {
    fn drop(&mut self) {
        self.scrub();
    }
}

impl Config {
    /// A configuration of zeros, which every field takes as a value.
    pub(crate) fn zeroed() -> Self {
        // SAFETY: integers, booleans and arrays of bytes, for which all
        // bits zeroed are a value.
        unsafe { MaybeUninit::zeroed().assume_init() }
    }

    /// The configuration of no file: zeros, and the defaults.
    fn defaults() -> Self {
        let mut cfg = Self::zeroed();
        cfg.map_export_valid = true;
        cfg.tls_classical_hosts_valid = true;
        cfg.map_export_otel_retries = 3;
        cfg.map_export_log_record_max_bytes = LOG_RECORD_MAX_DEFAULT;
        cfg.map_export_otlp_max_bytes = OTLP_MAX_DEFAULT;
        cfg
    }
}

/// A tenant ID: 1 to 128 of `[A-Za-z0-9._-]`.
fn tenant_id_valid(id: &[u8]) -> bool {
    !id.is_empty()
        && id.len() <= TENANT_ID_MAX
        && id
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// A list of exact DNS names apart by single commas, or none.
fn tls_classical_hosts_valid(value: &[u8]) -> bool {
    if value.is_empty() {
        return true;
    }
    let mut rest = value;
    loop {
        let len = rest.iter().position(|&c| c == b',').unwrap_or(rest.len());
        let mut name = [0u8; 254];

        if len == 0 || len >= name.len() {
            return false;
        }
        name[..len].copy_from_slice(&rest[..len]);
        if !dns_name_valid(&name[..len]) {
            return false;
        }
        if len == rest.len() {
            return true;
        }
        rest = &rest[len + 1..];
        if rest.is_empty() {
            return false;
        }
    }
}

/// A setting of the map export refused: the export goes idle.
fn map_export_bad(cfg: &mut Config, key: &CStr, val: &CStr, reason: &CStr) {
    cfg.map_export_valid = false;
    crate::log::warn(
        &[
            &b"config: "[..],
            key.to_bytes(),
            b": bad value '",
            val.to_bytes(),
            b"' (",
            reason.to_bytes(),
            b")",
        ]
        .concat(),
    );
}

/// Owner auth is a literal passphrase, or `hex:<even hex>` for a binary
/// auth value, what provisioning tools that randomise owner auth emit.
fn set_owner_auth(cfg: &mut Config, val: &CStr) {
    let bytes = val.to_bytes();

    if let Some(hex) = bytes.strip_prefix(b"hex:") {
        let mut auth = [0u8; OWNER_AUTH_MAX];
        let decoded = decode_max(hex, &mut auth);

        // An ignored value leaves the one set before intact.
        if let Ok(n) = decoded {
            cfg.tpm_owner_auth[..n].copy_from_slice(&auth[..n]);
            cfg.tpm_owner_auth_len = n;
        } else {
            crate::log::warn(
                format!(
                    "config: tpm.owner_auth: not an even count of up to {} hex digits (ignored)",
                    2 * auth.len()
                )
                .as_bytes(),
            );
        }
        scrub(&mut auth);
        return;
    }
    if bytes.len() > cfg.tpm_owner_auth.len() {
        crate::log::warn(b"config: tpm.owner_auth too long (ignored)");
        return;
    }
    cfg.tpm_owner_auth[..bytes.len()].copy_from_slice(bytes);
    cfg.tpm_owner_auth_len = bytes.len();
}

/// `strscpy()` into a field: whether the whole value fit.
fn set_string(dst: &mut [u8], val: &CStr) -> bool {
    strscpy(dst, val.to_bytes()).is_ok()
}

/// The terminated text at `start` of `buf`.
fn text_at(buf: &[u8], start: usize) -> &CStr {
    CStr::from_bytes_until_nul(&buf[start..]).unwrap_or(c"")
}

/// One `key = value` line into `cfg`.
fn apply(cfg: &mut Config, key: &CStr, val: &CStr) {
    let k = key.to_bytes();
    let v = val.to_bytes();

    match k {
        b"eventlog.max_bytes" => match parse_u64(v, u64::MAX) {
            Ok(n) => cfg.eventlog_max_bytes = n,
            Err(_) => crate::log::warn(
                &[
                    &b"config: eventlog.max_bytes: bad value '"[..],
                    val.to_bytes(),
                    b"' (ignored)",
                ]
                .concat(),
            ),
        },
        b"tpm.owner_auth" => set_owner_auth(cfg, val),
        b"tpm.tcti" => {
            if v.len() >= cfg.tpm_tcti.len() {
                crate::log::warn(b"config: tpm.tcti too long (ignored)");
            } else {
                set_string(&mut cfg.tpm_tcti, val);
            }
        }
        b"tls.classical_hosts" => {
            if !set_string(&mut cfg.tls_classical_hosts, val) || !tls_classical_hosts_valid(v) {
                cfg.tls_classical_hosts_valid = false;
                crate::log::warn(b"config: tls.classical_hosts: invalid exact DNS host list");
            }
        }
        b"map_export.json_path" => {
            if !set_string(&mut cfg.map_export_json_path, val) {
                map_export_bad(cfg, key, val, c"value too long");
            } else if !v.is_empty() && v[0] != b'/' {
                map_export_bad(cfg, key, val, c"path must be absolute");
            }
        }
        b"map_export.otel_endpoint" => {
            if !set_string(&mut cfg.map_export_otel_endpoint, val) {
                map_export_bad(cfg, key, val, c"value too long");
            }
        }
        b"map_export.tenant_id" => {
            if !v.is_empty() && !tenant_id_valid(v) {
                map_export_bad(
                    cfg,
                    key,
                    val,
                    c"expected 1..128 characters from A-Z, a-z, 0-9, '.', '_', '-'",
                );
            } else {
                set_string(&mut cfg.map_export_tenant_id, val);
            }
        }
        b"map_export.otel_insecure" => match v {
            b"true" => cfg.map_export_otel_insecure = true,
            b"false" => cfg.map_export_otel_insecure = false,
            _ => map_export_bad(cfg, key, val, c"expected true or false"),
        },
        b"map_export.otel_retries" => {
            match parse_u64(v, 10).and_then(|n| u32::try_from(n).map_err(|_| -EINVAL)) {
                Ok(n) => cfg.map_export_otel_retries = n,
                Err(_) => map_export_bad(cfg, key, val, c"expected 0..10"),
            }
        }
        b"map_export.s3_uri" => {
            if !set_string(&mut cfg.map_export_s3_uri, val) {
                map_export_bad(cfg, key, val, c"value too long");
            }
        }
        b"map_export.log_record_max_bytes" | b"map_export.otlp_max_bytes" => {
            match parse_u64(v, MAX_BYTES as u64).and_then(|n| u32::try_from(n).map_err(|_| -EINVAL))
            {
                Ok(n) if n != 0 => {
                    if k == b"map_export.log_record_max_bytes" {
                        cfg.map_export_log_record_max_bytes = n;
                    } else {
                        cfg.map_export_otlp_max_bytes = n;
                    }
                }
                _ => map_export_bad(cfg, key, val, c"expected 1..8388608 bytes"),
            }
        }
        _ if k.starts_with(b"config.") || k.starts_with(b"runtime.") => {}
        _ if k.starts_with(b"map_export.") => map_export_bad(cfg, key, val, c"unknown key"),
        _ if k.starts_with(b"tls.") => {
            cfg.tls_classical_hosts_valid = false;
            crate::log::warn(
                &[&b"config: "[..], key.to_bytes(), b": unknown TLS setting"].concat(),
            );
        }
        _ => crate::log::warn(
            &[
                &b"config: unknown key '"[..],
                key.to_bytes(),
                b"' (ignored)",
            ]
            .concat(),
        ),
    }
}

/// One line of the file, as getline() gave it with its newline, into
/// `cfg`.
fn parse_line(cfg: &mut Config, line: &[u8]) {
    // The line as the C string the C trimmed in place.
    let mut buf = [line, b"\0"].concat();
    let (ps, pe) = trim_blanks(&mut buf, 0, line.len());
    if ps == pe || buf[ps] == b'#' {
        return;
    }
    let Some(eq) = buf[ps..pe].iter().position(|&c| c == b'=').map(|i| ps + i) else {
        return;
    };
    buf[eq] = 0;
    let (ks, _) = trim_blanks(&mut buf, ps, eq);
    let (vs, _) = trim_blanks(&mut buf, eq + 1, pe);
    apply(cfg, text_at(&buf, ks), text_at(&buf, vs));
}

/// The lines of the file `f` into `cfg`, `path` naming it for the log:
/// a line longer than MAX is skipped, one with a NUL ends the read.
/// What the file holds, and the copies made of it, go back to the
/// allocator, which scrubs them.
fn parse(cfg: &mut Config, mut f: File, path: &CStr) -> c_int {
    const MAX: usize = MAP_EXPORT_PATH_MAX + 127;
    let mut ret = 0;

    let mut text = Vec::new();
    let read = f.read_to_end(&mut text);
    // What a failed read gave, up to its last whole line, as getline()
    // gave it before the call that failed.
    let whole = match &read {
        Ok(_) => text.len(),
        Err(_) => text.iter().rposition(|&c| c == b'\n').map_or(0, |i| i + 1),
    };
    for line in text[..whole].split_inclusive(|&c| c == b'\n') {
        let err = if line.contains(&0) {
            -EINVAL
        } else if line.strip_suffix(b"\n").unwrap_or(line).len() > MAX {
            crate::log::warn(format!("config: line longer than {MAX} bytes (ignored)").as_bytes());
            continue;
        } else {
            0
        };
        if err != 0 {
            unreadable(path, err);
            ret = err;
            break;
        }
        parse_line(cfg, line);
    }
    if let (Err(e), 0) = (&read, ret) {
        ret = -e.raw_os_error().unwrap_or(EIO);
        unreadable(path, ret);
    }
    // The TPM owner's authorization is for no other user's eyes.
    if cfg.tpm_owner_auth_len != 0 && check_secret(f.as_fd(), path) != 0 {
        scrub(&mut cfg.tpm_owner_auth);
        cfg.tpm_owner_auth_len = 0;
        ret = -EPERM;
    }
    // SAFETY: the file's fd, closed once; the File gave it up.
    if unsafe { close(f.into_raw_fd()) } != 0 && ret == 0 {
        ret = -errno();
    }
    ret
}

/// A line the file could not give.
fn unreadable(path: &CStr, err: c_int) {
    crate::log::err(
        &[
            &b"config: "[..],
            path.to_bytes(),
            b": unreadable line: ",
            crate::errno::text(err).as_bytes(),
        ]
        .concat(),
    );
}

fn finish(cfg: &mut Config, ret: c_int) -> c_int {
    if cfg.map_export_s3_uri[0] != 0 && cfg.map_export_otel_endpoint[0] == 0 {
        map_export_bad(
            cfg,
            c"map_export.s3_uri",
            c"",
            c"requires map_export.otel_endpoint for its reference event",
        );
    }
    if cfg.map_export_log_record_max_bytes > cfg.map_export_otlp_max_bytes {
        map_export_bad(
            cfg,
            c"map_export.log_record_max_bytes",
            c"",
            c"must not exceed otlp_max_bytes",
        );
    }
    ret
}

/// The file at `path` into `cfg`, over the defaults: none at all is
/// no error.
pub(crate) fn load_path(cfg: &mut Config, path: &CStr) -> c_int {
    *cfg = Config::defaults();
    let ret = match open_trusted(path, O_RDONLY) {
        Ok(fd) => parse(cfg, File::from(fd), path),
        // The environment's overrides still apply.
        Err(ret) if ret == -ENOENT => 0,
        Err(ret) => ret,
    };
    finish(cfg, ret)
}

/// The configuration from the image, or else the file and then the
/// environment, which wins so that one dev run can point at swtpm while
/// the file is shared.
pub(crate) fn load(cfg: &mut Config) -> c_int {
    if crate::util::image_config::get(cfg) != 0 {
        return 0;
    }
    let ret = load_path(cfg, CONF_PATH);
    if ret != 0 && ret != -ENOENT {
        return ret;
    }
    if let Some(auth) = env(c"SHIRUDO_TPM_OWNER_AUTH") {
        set_owner_auth(cfg, auth);
    }
    if let Some(tcti) = env(c"SHIRUDO_TPM_TCTI").filter(|t| !t.is_empty()) {
        if tcti.to_bytes().len() < cfg.tpm_tcti.len() {
            set_string(&mut cfg.tpm_tcti, tcti);
        } else {
            crate::log::warn(b"SHIRUDO_TPM_TCTI too long (ignored)");
        }
    }
    if ret == -ENOENT { 0 } else { ret }
}

/// The configuration in the file open on `fd`, read from its start
/// through a copy of the fd; the caller keeps its own.
pub(crate) fn load_fd(cfg: &mut Config, fd: BorrowedFd<'_>, label: &CStr) -> c_int {
    *cfg = Config::defaults();
    let mut f = match fd.try_clone_to_owned() {
        Ok(copy) => File::from(copy),
        Err(e) => return -e.raw_os_error().unwrap_or(EIO),
    };
    if let Err(e) = f.seek(SeekFrom::Start(0)) {
        return -e.raw_os_error().unwrap_or(EIO);
    }
    let ret = if check_trusted(f.as_fd(), label) != 0 {
        -EPERM
    } else {
        parse(cfg, f, label)
    };
    finish(cfg, ret)
}

#[cfg(shirudo_fuzz)]
mod fuzz;
