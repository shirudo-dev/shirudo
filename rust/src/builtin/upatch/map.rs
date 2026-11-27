// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo upatch map`: the maps the loaded upatches pin, listed, or
//! one map's or every map's contents read from the kernel. Contents are
//! printed, appended as JSON records through the upatch's signed
//! decoders, or exported over OTLP, from the command line or the
//! map_export configuration.

use core::ffi::{CStr, c_int};
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, IntoRawFd};
use std::os::unix::fs::FileExt;

use super::{JSON_MAX, Summaries, log_err, log_warn, strerr, type_name};
use crate::errno::{EINVAL, EIO, ENODATA};
use crate::sys::libc::{LOCK_UN, O_APPEND, O_CREAT, O_RDWR, close, errno, ferror, flock, stdout};
use crate::text::cstr;
use crate::util::config::{self, Scrubbed};
use crate::util::decode;
use crate::util::help::{Help, HelpSection};
use crate::util::io::{lock_exclusive, write_complete};
use crate::util::json::JsonEmit;
use crate::util::map_read::{self, MAP_ENTRIES_DEFAULT, MAP_READ_PEEK, MapView};
use crate::util::map_render;
use crate::util::options::{
    EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OPT_OPTIONAL, OptParser, OptSpec,
};
use crate::util::otel::{self, OtelOpts};
use crate::util::seal;
use crate::util::upatch::name_valid;

const MAP_ALL: c_int = 0;
const MAP_JSON: c_int = 1;
const MAP_SHOW_FULL: c_int = 2;
const MAP_PEEK: c_int = 3;
const MAP_OTEL: c_int = 4;
const MAP_OTEL_ENDPOINT: c_int = 5;
const MAP_TENANT_ID: c_int = 6;
const MAP_OTEL_INSECURE: c_int = 7;
const MAP_OTEL_RETRIES: c_int = 8;
const MAP_S3_URI: c_int = 9;

static MAP_OPTS: [OptSpec; 10] = [
    OptSpec::new(
        c"--all",
        0,
        0,
        None,
        c"export every map from every loaded upatch",
    ),
    OptSpec::new(
        c"--json",
        0,
        OPT_OPTIONAL,
        Some(c"<path>"),
        c"print JSON or append it to path",
    ),
    OptSpec::new(
        c"--show-full",
        0,
        0,
        None,
        c"lift the per-map 256-entry truncation cap",
    ),
    OptSpec::new(
        c"--peek",
        0,
        0,
        None,
        c"read serializer-backed maps without draining them",
    ),
    OptSpec::new(
        c"--otel",
        0,
        0,
        None,
        c"export maps through signed decoders or automatic classification",
    ),
    OptSpec::new(
        c"--otel-endpoint",
        0,
        0,
        Some(c"<url>"),
        c"OTLP base URL (signal path is appended)",
    ),
    OptSpec::new(
        c"--tenant-id",
        0,
        0,
        Some(c"<id>"),
        c"add X-Tenant-ID to OTLP requests",
    ),
    OptSpec::new(
        c"--otel-insecure",
        0,
        0,
        None,
        c"allow cleartext remote OTLP or disable HTTPS verification",
    ),
    OptSpec::new(
        c"--otel-retries",
        0,
        0,
        Some(c"<0-10>"),
        c"OTLP retries after the first attempt (default: 3)",
    ),
    OptSpec::new(
        c"--s3-uri",
        0,
        0,
        Some(c"<uri>"),
        c"S3 overflow destination for OTLP payloads",
    ),
];

static MAP_SECTIONS: [HelpSection; 1] = [HelpSection::options(c"options:", &MAP_OPTS)];

static MAP_HELP: Help = Help::new(
    c"shirudo upatch map [--all] [<upatch>] [<map>] [--json[=<path>]] [--show-full] [--peek]\n                          \
      [--otel] [--otel-endpoint=<url>]\n                          \
      [--otel-insecure] [--otel-retries=<0-10>] [--s3-uri=<uri>]",
    Some(
        c"Read the contents of a pinned upatch map from the\n\
          target kernel. With no positional args, list every pinned\n\
          map across every loaded upatch. With <upatch>, list maps\n\
          for that upatch only. With <upatch> <map>, dump the map's\n\
          contents, BTF type-aware where the build embedded `-g`. If the upatch\n\
          pins a serializer for the map, run it and print the serialized\n\
          pages. With --all, export detailed contents for every loaded map\n\
          using command-line or map_export.* configuration.",
    ),
    &MAP_SECTIONS,
    Some(
        c"Examples:\n  shirudo upatch map\n  shirudo upatch map --all\n  \
          shirudo upatch map kernel-obs exec --json\n  \
          shirudo upatch map cve-2026-31431-counter\n  \
          shirudo upatch map cve-2026-31431-counter blocked_af_alg\n  \
          shirudo upatch map cve-2026-31431-counter blocked_af_alg \\\n    \
          --json=/var/log/shirudo/maps.ndjson\n  \
          shirudo upatch map cve-2026-31431-counter blocked_af_alg --otel\n  \
          shirudo upatch map foo values --otel \\\n    \
          --otel-endpoint=https://collector:4318\n  \
          shirudo upatch map cve-2026-31431-counter big_hash --show-full",
    ),
);

/// What the command line asks for, and the configuration fills in.
#[derive(Default)]
struct Args<'a> {
    all: bool,
    json: bool,
    json_path: Option<&'a CStr>,
    show_full: bool,
    peek: bool,
    otel: bool,
    endpoint: Option<&'a CStr>,
    tenant_id: Option<&'a CStr>,
    insecure: Option<bool>,
    retries: Option<u32>,
    s3_uri: Option<&'a CStr>,
    upatch: Option<&'a CStr>,
    map: Option<&'a CStr>,
}

/// A tenant ID: 1 to 128 of `[A-Za-z0-9._-]`.
fn tenant_id_valid(id: &[u8]) -> bool {
    (1..=128).contains(&id.len())
        && id
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

/// The command line, or how the command exits without running.
fn parse<'a>(p: &mut OptParser<'a>) -> Result<Args<'a>, c_int> {
    let mut o = Args::default();

    loop {
        let opt = p.next();
        let value = p.value();
        match opt {
            OPT_END => break,
            MAP_ALL => o.all = true,
            MAP_JSON => {
                o.json = true;
                o.json_path = value;
            }
            MAP_SHOW_FULL => o.show_full = true,
            MAP_PEEK => o.peek = true,
            MAP_OTEL => o.otel = true,
            MAP_OTEL_ENDPOINT => o.endpoint = value,
            MAP_TENANT_ID => {
                if !value.is_some_and(|v| tenant_id_valid(v.to_bytes())) {
                    p.usage(b"--tenant-id takes 1..128 characters using A-Z, a-z, 0-9, '.', '_', or '-'");
                    return Err(EXIT_USAGE);
                }
                o.tenant_id = value;
            }
            MAP_OTEL_INSECURE => o.insecure = Some(true),
            MAP_OTEL_RETRIES => match p.number(0, 10) {
                Ok(n) => o.retries = Some(n as u32),
                Err(_) => return Err(EXIT_USAGE),
            },
            MAP_S3_URI => o.s3_uri = value,
            OPT_ARG => {
                if o.map.is_some() {
                    p.usage_arg(b"unexpected argument ");
                    return Err(EXIT_USAGE);
                }
                if o.upatch.is_some() {
                    o.map = value;
                } else {
                    o.upatch = value;
                }
            }
            OPT_DONE => return Err(0),
            _ => return Err(EXIT_USAGE),
        }
    }
    Ok(o)
}

/// A configured string, none when empty.
fn configured(field: &[u8]) -> Option<&CStr> {
    CStr::from_bytes_until_nul(field)
        .ok()
        .filter(|s| !s.is_empty())
}

fn os_err(e: &std::io::Error) -> c_int {
    -e.raw_os_error().unwrap_or(EIO)
}

/// Appends `json` and a newline to the locked `file` of `size` bytes,
/// after a newline when it lacks a last one; rolls a partial append back.
fn append_locked(mut file: &File, path: &CStr, json: &[u8]) -> c_int {
    let size = match file.metadata() {
        Ok(m) if m.file_type().is_file() => m.len(),
        Ok(_) => return -EINVAL,
        Err(e) => return os_err(&e),
    };
    let wrote = (|| {
        if size > 0 {
            let mut last = [0u8];
            match file.read_at(&mut last, size - 1) {
                Ok(1) => {}
                Ok(_) => return Err(-EIO),
                Err(e) => return Err(os_err(&e)),
            }
            if last[0] != b'\n' {
                file.write_all(b"\n").map_err(|e| os_err(&e))?;
            }
        }
        file.write_all(json).map_err(|e| os_err(&e))?;
        file.write_all(b"\n").map_err(|e| os_err(&e))?;
        file.sync_all().map_err(|e| os_err(&e))
    })();
    match wrote {
        Ok(()) => 0,
        Err(ret) => {
            if let Err(e) = file.set_len(size) {
                log_warn(
                    &[
                        b"upatch map: could not roll back partial JSON append to ",
                        path.to_bytes(),
                        b": ",
                        strerr(-os_err(&e)),
                    ]
                    .concat(),
                );
            }
            ret
        }
    }
}

/// Appends the record `json` to the file at `path`, under its lock: 0 or
/// -errno.
fn append_record(path: &CStr, json: &[u8]) -> c_int {
    let file = match seal::output_open(path.to_bytes(), O_RDWR | O_CREAT | O_APPEND, 0o644) {
        Ok(fd) => File::from(fd),
        Err(err) => return err,
    };
    let mut ret = lock_exclusive(file.as_fd()).err().unwrap_or(0);
    if ret == 0 {
        ret = append_locked(&file, path, json);
        // SAFETY: the descriptor locked above.
        unsafe { flock(file.as_raw_fd(), LOCK_UN) };
    }
    // SAFETY: the descriptor, closed once, its error kept.
    if unsafe { close(file.into_raw_fd()) } != 0 && ret == 0 {
        ret = -errno();
    }
    ret
}

/// The record `json` and its newline, appended to the file at `path` or
/// written to stdout: 0 or -errno.
fn emit_record(path: Option<&CStr>, json: &[u8]) -> c_int {
    match path {
        Some(p) => append_record(p, json),
        None => {
            let out = std::io::stdout();
            write_complete(out.as_fd(), json)
                .and_then(|()| write_complete(out.as_fd(), b"\n"))
                .err()
                .unwrap_or(0)
        }
    }
}

/// Reports an emit_record() failure for `path`.
fn emit_failed(path: Option<&CStr>, e: c_int) {
    match path {
        Some(p) => log_err(
            &[
                b"upatch map: append JSON to ",
                p.to_bytes(),
                b": ",
                strerr(-e),
            ]
            .concat(),
        ),
        None => log_err(&[b"upatch map: print JSON: ", strerr(-e)].concat()),
    }
}

/// The map's JSON record as its decoder makes it, without trailing line
/// ends: 0 or -errno.
fn append_json(path: Option<&CStr>, v: &MapView) -> c_int {
    match decode::map_json(v) {
        Ok(json) => {
            let end = json
                .iter()
                .rposition(|&c| c != b'\n' && c != b'\r')
                .map_or(0, |i| i + 1);
            emit_record(path, &json[..end])
        }
        Err(e) => e,
    }
}

/// Map `map` of upatch `upatch` read and exported as `a` asks, printed
/// in detail when `detail`: 0 or 1.
fn export(upatch: &CStr, map: &CStr, a: &Args, opts: &OtelOpts, detail: bool) -> c_int {
    let cap = if a.show_full || a.json || a.otel {
        0
    } else {
        MAP_ENTRIES_DEFAULT
    };
    let (u, m) = (upatch.to_bytes(), map.to_bytes());
    let v = match map_read::read(u, m, cap, if a.peek { MAP_READ_PEEK } else { 0 }) {
        Ok(v) => v,
        Err(r) => {
            log_err(&[b"upatch map: read ", u, b"/", m, b": ", strerr(-r)].concat());
            return 1;
        }
    };
    let mut ret = 0;

    if a.json {
        let e = append_json(a.json_path, &v);
        if e != 0 {
            if e == -ENODATA {
                log_err(
                    &[
                        b"upatch map: ",
                        u,
                        b"/",
                        m,
                        b" has no decoder, and --json writes what a decoder returns",
                    ]
                    .concat(),
                );
            } else {
                emit_failed(a.json_path, e);
            }
            ret = 1;
        }
    }
    if a.otel {
        let e = match decode::signal(&v) {
            Err(e) if e == -ENODATA => otel::send_auto(&v, Some(opts)),
            Ok(s) => otel::send_decoded(&v, s as c_int, Some(opts)),
            Err(e) => e,
        };
        if e != 0 {
            log_err(&[b"upatch map: OTLP export ", u, b"/", m, b": ", strerr(-e)].concat());
            ret = 1;
        }
    }
    if detail {
        map_render::print_detail(&v);
        // SAFETY: the C library's stdout, whose error flag the print
        // leaves.
        if unsafe { ferror(stdout) } != 0 {
            ret = 1;
        }
    }
    ret
}

/// The maps listed, as a table or a JSON record: 0 or 1.
fn summary(a: &Args, maps: &Summaries) -> c_int {
    if !a.json {
        map_render::print_summary(maps.as_slice());
        return 0;
    }
    let mut e = JsonEmit::growing(JSON_MAX);
    e.obj_open();
    e.kv_int(b"schema", 1);
    e.arr_open(b"maps");
    for m in maps.as_slice() {
        e.obj_open();
        e.kv_string(b"upatch", cstr(&m.upatch));
        e.kv_string(b"name", cstr(&m.name));
        e.kv_string(b"type", type_name(m));
        e.kv_int(b"max_entries", i64::from(m.max_entries));
        if m.n_cpus > 1 {
            e.kv_int(b"n_cpus", i64::from(m.n_cpus));
        }
        e.obj_close();
    }
    e.arr_close();
    e.obj_close();
    if e.err() != 0 {
        return 1;
    }
    let r = emit_record(a.json_path, e.output());
    if r != 0 {
        emit_failed(a.json_path, r);
    }
    c_int::from(r != 0)
}

/// `upatch map`, from `map` on.
pub(super) fn run(args: &[&CStr]) -> c_int {
    let mut cfg = Scrubbed::new();
    let mut p = OptParser::new(c"upatch map", &MAP_OPTS, Some(&MAP_HELP), args, 1);
    let mut a = match parse(&mut p) {
        Ok(a) => a,
        Err(code) => return code,
    };
    let mut opts = OtelOpts {
        endpoint: core::ptr::null(),
        tenant_id: core::ptr::null(),
        s3_uri: core::ptr::null(),
        allow_insecure: a.insecure.unwrap_or(false),
        retries: a.retries.unwrap_or(3),
        log_record_max_bytes: 0,
        otlp_max_bytes: 0,
    };

    if a.all {
        let e = config::load(&mut cfg);
        if e != 0 {
            log_err(&[b"upatch map: load export configuration: ", strerr(-e)].concat());
            return 1;
        }
        let c = &*cfg;
        if !c.map_export_valid {
            log_err(b"upatch map: invalid map_export configuration");
            return 2;
        }
        if !a.json
            && let Some(p) = configured(&c.map_export_json_path)
        {
            a.json_path = Some(p);
            a.json = true;
        }
        a.otel |= configured(&c.map_export_otel_endpoint).is_some();
        if a.otel {
            a.endpoint = a.endpoint.or(configured(&c.map_export_otel_endpoint));
            a.tenant_id = a.tenant_id.or(configured(&c.map_export_tenant_id));
            a.s3_uri = a.s3_uri.or(configured(&c.map_export_s3_uri));
            opts.allow_insecure = a.insecure.unwrap_or(c.map_export_otel_insecure);
            opts.retries = a.retries.unwrap_or(c.map_export_otel_retries);
            opts.log_record_max_bytes = c.map_export_log_record_max_bytes;
            opts.otlp_max_bytes = c.map_export_otlp_max_bytes;
        }
    }
    let ptr = |s: Option<&CStr>| s.map_or(core::ptr::null(), CStr::as_ptr);
    opts.endpoint = ptr(a.endpoint);
    opts.tenant_id = ptr(a.tenant_id);
    opts.s3_uri = ptr(a.s3_uri);

    let otlp_options = a.endpoint.is_some()
        || a.tenant_id.is_some()
        || a.insecure.is_some()
        || a.retries.is_some()
        || a.s3_uri.is_some();
    if otlp_options && !a.otel {
        p.usage(b"OTLP options require --otel");
        return EXIT_USAGE;
    }
    if a.all && (a.upatch.is_some() || a.map.is_some()) {
        p.usage(b"--all does not accept positional arguments");
        return EXIT_USAGE;
    }
    if a.otel && !a.all && (a.upatch.is_none() || a.map.is_none()) {
        p.usage(b"--otel requires <upatch> and <map>");
        return EXIT_USAGE;
    }
    let detail = !a.json && !a.otel;
    if let Some(u) = a.upatch
        && !name_valid(Some(u.to_bytes()))
    {
        p.usage(&[b"invalid upatch name '", u.to_bytes(), b"'"].concat());
        return EXIT_USAGE;
    }
    if let (Some(u), Some(m)) = (a.upatch, a.map) {
        return export(u, m, &a, &opts, detail);
    }
    let maps = Summaries::of(a.upatch);
    if a.all {
        let mut ret = 0;
        for m in maps.as_slice() {
            let (Ok(u), Ok(name)) = (
                CStr::from_bytes_until_nul(&m.upatch),
                CStr::from_bytes_until_nul(&m.name),
            ) else {
                ret = 1;
                continue;
            };
            if export(u, name, &a, &opts, detail) != 0 {
                ret = 1;
            }
        }
        return ret;
    }
    summary(&a, &maps)
}
