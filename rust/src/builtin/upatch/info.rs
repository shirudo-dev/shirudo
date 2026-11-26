// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo upatch info`: an upatch file described offline, its header,
//! signature, payload digest, signed sections and decoders. No signature
//! is checked, so the names it shows are as the file has them: made
//! printable, and in JSON lossy UTF-8.

use core::ffi::{CStr, c_int};
use std::ffi::CString;

use super::{JSON_MAX, hex, log_err, out, print_json, strerr};
use crate::text::{cstr, sanitize};
use crate::util::help::{Help, HelpSection};
use crate::util::json::JsonEmit;
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptParser, OptSpec};
use crate::util::upatch::Upatch;
/// UPATCH_DECODER_LANG_LUA, _INPUT_MAP_V1, _EXPORT_LOG and _METRIC.
const LANG_LUA: u32 = 1;
const INPUT_MAP_V1: u32 = 1;
const EXPORT_LOG: u32 = 1;
const EXPORT_METRIC: u32 = 2;

fn language(l: u32) -> &'static [u8] {
    if l == LANG_LUA { b"lua" } else { b"unknown" }
}

fn input(f: u32) -> &'static [u8] {
    if f == INPUT_MAP_V1 {
        b"shirudo.map.v1"
    } else {
        b"unknown"
    }
}

fn signal(s: u32) -> &'static [u8] {
    match s {
        EXPORT_LOG => b"log",
        EXPORT_METRIC => b"metric",
        _ => b"unknown",
    }
}

/// The bytes up to a NUL made printable, as the C library's
/// text_sanitize() makes them.
fn printable(s: &[u8]) -> Vec<u8> {
    let mut buf = cstr(s).to_vec();
    sanitize(&mut buf, false);
    buf
}

/// What printable() shows, as JSON escapes it and U+FFFD for a stray
/// byte.
fn unverified(e: &mut JsonEmit, key: &[u8], val: &[u8]) {
    e.kv_string_lossy(key, cstr(val));
}

/// A length within a container, as JSON takes a number.
fn json_len(len: usize) -> i64 {
    i64::try_from(len).unwrap_or(i64::MAX)
}

fn json(u: &Upatch, path: &[u8]) -> c_int {
    let mut e = JsonEmit::growing(JSON_MAX);
    let h = &u.hdr;

    e.obj_open();
    e.kv_int(b"schema", 1);
    unverified(&mut e, b"path", path);
    unverified(&mut e, b"name", u.name());
    e.kv_string(b"type", if u.is_unload() { b"unload" } else { b"load" });
    e.kv_string(b"payload_type", u.payload_type());
    e.kv_int(b"version", i64::from(h.version));
    e.kv_string(b"payload_sha256", &hex(&h.payload_sha256));
    e.kv_int(b"loader_insns_len", i64::from(h.loader_insns_len));
    e.kv_int(b"signature_len", i64::from(h.signature_len));
    e.kv_int(b"data_len", i64::from(h.data_len));
    e.kv_int(b"log_buf_sz", i64::from(h.log_buf_sz));
    e.kv_int(b"file_size", json_len(u.bytes().len()));
    match u.signed_name() {
        Some(name) => unverified(&mut e, b"signed_name", name),
        None => e.kv_null(b"signed_name"),
    }
    e.kv_int(
        b"attach_metadata_len",
        json_len(u.signed_attach().map_or(0, <[u8]>::len)),
    );
    e.kv_int(b"jar_len", json_len(u.signed_jar().map_or(0, <[u8]>::len)));
    match u.signed_unload_payload() {
        Some(p) => e.kv_string(b"unload_payload_sha256", &hex(p)),
        None => e.kv_null(b"unload_payload_sha256"),
    }
    e.arr_open(b"decoders");
    for d in u.decoders() {
        e.obj_open();
        e.kv_string(b"language", language(d.language));
        e.kv_int(b"api_version", i64::from(d.api_version));
        e.kv_string(b"input_format", input(d.input_format));
        e.kv_string(b"export_signal", signal(d.export_signal));
        unverified(&mut e, b"upatch", d.upatch);
        unverified(&mut e, b"map", d.map);
        unverified(&mut e, b"source_file", d.source_name);
        unverified(&mut e, b"entrypoint", d.entrypoint);
        e.kv_int(b"source_len", json_len(d.source.len()));
        e.obj_close();
    }
    e.arr_close();
    e.obj_close();
    print_json(e, b"upatch info")
}

fn line(label: &str, value: &[u8]) -> Vec<u8> {
    [format!("{label:<23}").as_bytes(), value, b"\n"].concat()
}

fn section(label: &str, value: &[u8]) -> Vec<u8> {
    [format!("  {label:<22} ").as_bytes(), value, b"\n"].concat()
}

fn text(u: &Upatch, path: &[u8]) {
    let h = &u.hdr;
    let mut t = Vec::new();

    t.extend(line("File:", &printable(path)));
    t.extend(line("Name:", &printable(u.name())));
    t.extend(line(
        "Type:",
        if u.is_unload() {
            b"UNLOAD-directive"
        } else {
            b"LOAD"
        },
    ));
    t.extend(line("Payload type:", u.payload_type()));
    t.extend(line("Version:", h.version.to_string().as_bytes()));
    t.extend(line("Payload sha256:", &hex(&h.payload_sha256)));
    t.extend(line(
        "File size:",
        format!("{} bytes", u.bytes().len()).as_bytes(),
    ));

    t.extend_from_slice(b"\nLoader:\n");
    t.extend(section(
        "Instructions:",
        format!("off={} len={}", h.loader_insns_off, h.loader_insns_len).as_bytes(),
    ));
    t.extend(section(
        "Log buffer size:",
        h.log_buf_sz.to_string().as_bytes(),
    ));
    let data = if h.data_len != 0 {
        format!("off={} len={}", h.data_off, h.data_len)
    } else {
        "(none)".into()
    };
    t.extend(section("Data:", data.as_bytes()));

    t.extend_from_slice(b"\nSignature:\n");
    t.extend(section("Offset:", h.signature_off.to_string().as_bytes()));
    t.extend(section(
        "Length:",
        format!("{} bytes", h.signature_len).as_bytes(),
    ));

    t.extend_from_slice(b"\nSigned sections:\n");
    match u.signed_name() {
        Some(name) => t.extend(section("Name:", &printable(name))),
        None => t.extend(section("Name:", b"(none)")),
    }
    let attach = match u.signed_attach() {
        Some(a) => format!("{} bytes", a.len()),
        None => "(none)".into(),
    };
    t.extend(section("Attach metadata:", attach.as_bytes()));
    if let Some(jar) = u.signed_jar() {
        t.extend(section(
            "Java agent jar:",
            format!("{} bytes", jar.len()).as_bytes(),
        ));
    }
    match u.signed_unload_payload() {
        Some(p) => t.extend(section("Unload payload:", &hex(p))),
        None => t.extend(section("Unload payload:", b"(none)")),
    }

    t.extend_from_slice(b"\nDecoders:\n");
    if !u.has_decoders() {
        t.extend_from_slice(b"  (none)\n");
    } else {
        for d in u.decoders() {
            t.extend(section(
                "Target:",
                &[&printable(d.upatch)[..], b"/", &printable(d.map)].concat(),
            ));
            let sub =
                |label: &str, v: &[u8]| [format!("    {label:<20} ").as_bytes(), v, b"\n"].concat();
            t.extend(sub(
                "Language:",
                &[
                    language(d.language),
                    format!(" (api={})", d.api_version).as_bytes(),
                ]
                .concat(),
            ));
            t.extend(sub("Input:", input(d.input_format)));
            t.extend(sub("Export signal:", signal(d.export_signal)));
            t.extend(sub(
                "Source:",
                &[
                    &printable(d.source_name)[..],
                    b":",
                    &printable(d.entrypoint),
                    format!(" ({} bytes)", d.source.len()).as_bytes(),
                ]
                .concat(),
            ));
        }
    }
    out(&t);
}

const INFO_JSON: c_int = 0;

static INFO_OPTS: [OptSpec; 1] = [OptSpec::new(
    c"--json",
    0,
    0,
    None,
    c"print one JSON object",
)];

static INFO_SECTIONS: [HelpSection; 1] = [HelpSection::options(c"options:", &INFO_OPTS)];

static INFO_HELP: Help = Help::new(
    c"shirudo upatch info [--json] <file.upatch>",
    Some(
        c"Describe a .upatch file: header, signature, payload digest,\n\
          attach metadata and signed decoders. Offline: no kernel state\n\
          read, runs on any host. For the program as actually loaded\n\
          (authoritative, via kernel BTF line_info) use `shirudo upatch get`.",
    ),
    &INFO_SECTIONS,
    Some(
        c"Examples:\n  shirudo upatch info cve-2026-31431.upatch\n  \
          shirudo upatch info --json /var/lib/shirudo/upatches/foo.upatch",
    ),
);

/// `upatch info`, from `info` on.
pub(super) fn run(args: &[&CStr]) -> c_int {
    let mut p = OptParser::new(c"upatch info", &INFO_OPTS, Some(&INFO_HELP), args, 1);
    let (mut json_out, mut path) = (false, None);

    loop {
        match p.next() {
            OPT_END => break,
            INFO_JSON => json_out = true,
            OPT_ARG => {
                if path.is_some() {
                    p.usage_arg(b"unexpected argument ");
                    return EXIT_USAGE;
                }
                path = p.value();
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    let Some(path) = path.map(CStr::to_bytes) else {
        p.usage(b"takes <file.upatch>");
        return EXIT_USAGE;
    };
    let u = match Upatch::open(&CString::new(path).unwrap_or_default()) {
        Ok(u) => u,
        Err(e) => {
            log_err(&[b"upatch info: ", path, b": ", strerr(-e)].concat());
            return 1;
        }
    };
    if json_out {
        json(&u, path)
    } else {
        text(&u, path);
        0
    }
}

#[cfg(shirudo_fuzz)]
mod fuzz;
