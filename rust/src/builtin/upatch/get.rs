// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo upatch get`: a loaded upatch described from the kernel,
//! where it attaches, its source as the signed loader's BTF line_info
//! gives it, and every map it pins with their contents. It reads only
//! what the LSM allows: bpf() info and lookups, xattrs and stat.

use core::ffi::{CStr, c_int, c_long};
use std::ffi::CString;

use super::{JSON_MAX, Summaries, log_err, out, print_json, strerr, type_name};
use crate::bpf::btf::Btf;
use crate::sys::libc::close;
use crate::text::cstr;
use crate::util::bpf_info::{Info, PROG_INFO_SIZE};
use crate::util::bpf_sys::bpf_prog_get_fd_by_id;
use crate::util::help::{Help, HelpSection};
use crate::util::json::JsonEmit;
use crate::util::kernel_btf;
use crate::util::map_read::{self, MAP_ENTRIES_DEFAULT, MAP_READ_PEEK, MapSummary, MapView};
use crate::util::map_render;
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptParser, OptSpec};
use crate::util::timefmt::format_duration;
use crate::util::upatch::name_valid;
use crate::util::upatch_resolve::{
    LinkMisses, each_link_misses, first_prog_id, loaded_at, payload_sha256, resolve_location,
};
use crate::util::upatch_table::age_sec;

/// Where `struct bpf_prog_info` keeps what is read of it.
const PROG_BTF_ID: usize = 128;
const PROG_NR_LINE_INFO: usize = 148;
const PROG_LINE_INFO: usize = 152;
const PROG_LINE_INFO_REC_SIZE: usize = 172;
/// `struct bpf_line_info`: insn_off, file_name_off, line_off, line_col.
const LINE_INFO_SIZE: usize = 16;

/// A source line of the program.
struct Line {
    file: Vec<u8>,
    line: u32,
    src: Vec<u8>,
}

/// The upatch as the kernel has it loaded.
struct Loaded {
    prog_id: u32,
    location: Vec<u8>,
    loaded_at: Vec<u8>,
    payload: Vec<u8>,
    /// None when the kernel could not read the counters.
    programs: Option<Vec<LinkMisses>>,
    /// Unique, by file and then line: line_info follows the instructions,
    /// so a line recurs and lines come out of order.
    lines: Vec<Line>,
}

/// The source lines the `rec_size`-byte line_info records `recs` name in
/// `btf`, skipping any blank.
fn lines(btf: &Btf, recs: &[u8], rec_size: usize) -> Vec<Line> {
    if rec_size < LINE_INFO_SIZE {
        return Vec::new();
    }
    let string = |off: u32| btf.str_at(off);
    let mut v: Vec<Line> = recs
        .chunks_exact(rec_size)
        .filter_map(|r| {
            let word =
                |i: usize| u32::from_ne_bytes(r[i * 4..i * 4 + 4].try_into().unwrap_or_default());
            let src = string(word(2))?;
            let start = src.iter().position(|&c| c != b' ' && c != b'\t')?;
            let file = string(word(1)).filter(|f| !f.is_empty()).unwrap_or(b"?");
            Some(Line {
                file: file.to_vec(),
                line: word(3) >> 10,
                src: src[start..].to_vec(),
            })
        })
        .collect();
    v.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
    v.dedup_by(|b, a| a.file == b.file && a.line == b.line);
    v
}

/// The source lines of program `prog`, none when it was built without
/// them, or -errno.
fn source(prog: c_int) -> Result<Vec<Line>, c_int> {
    let mut info = Info::<PROG_INFO_SIZE>::new();
    info.read(prog)?;
    let nr = info.u32_at(PROG_NR_LINE_INFO);
    let rec_size = info.u32_at(PROG_LINE_INFO_REC_SIZE);
    let btf_id = info.u32_at(PROG_BTF_ID);
    if nr == 0 || btf_id == 0 || rec_size == 0 {
        return Ok(Vec::new());
    }
    let mut recs = vec![0u8; nr as usize * rec_size as usize];
    let mut info = Info::<PROG_INFO_SIZE>::new();
    info.set(PROG_NR_LINE_INFO, &nr.to_ne_bytes());
    info.set(PROG_LINE_INFO_REC_SIZE, &rec_size.to_ne_bytes());
    info.set(PROG_LINE_INFO, &(recs.as_mut_ptr() as u64).to_ne_bytes());
    info.read(prog)?;
    let btf = kernel_btf::by_id(btf_id)?;
    Ok(lines(&btf, &recs, rec_size as usize))
}

/// Upatch `name` as loaded, from its first link or, an XDP upatch with no
/// device yet, its program pin; or -errno. Missing line_info is no
/// failure: the rest still describes it.
fn collect(name: &CStr) -> Result<Loaded, c_int> {
    let prog_id = first_prog_id(name.to_bytes())?;
    let n = name.to_bytes();
    let loaded_at = loaded_at(n);
    let payload = payload_sha256(n);
    let vbtf = kernel_btf::vmlinux();
    let location = resolve_location(vbtf, n).unwrap_or_else(|_| b"?".to_vec());

    let programs = each_link_misses(vbtf, n).ok();

    let prog = bpf_prog_get_fd_by_id(prog_id);
    if prog < 0 {
        return Err(prog);
    }
    let lines = source(prog);
    // SAFETY: the descriptor opened above.
    unsafe { close(prog) };
    Ok(Loaded {
        prog_id,
        location,
        loaded_at,
        payload,
        programs,
        lines: lines?,
    })
}

/// How long ago the time `ts` was, as format_duration() puts it, or
/// nothing when it is none.
fn age(ts: &[u8]) -> Vec<u8> {
    let Ok(ts) = CString::new(ts) else {
        return Vec::new();
    };
    // SAFETY: a C string.
    let secs = unsafe { age_sec(ts.as_ptr()) };
    if secs < 0 {
        return Vec::new();
    }
    let mut buf = [0u8; 16];
    format_duration(secs as c_long, &mut buf);
    cstr(&buf).to_vec()
}

/// What map `m` of upatch `upatch` holds, its first `cap` entries or
/// all for 0, without draining a serializer.
fn read_map(upatch: &CStr, m: &MapSummary, cap: u32) -> Result<MapView, c_int> {
    map_read::read(upatch.to_bytes(), cstr(&m.name), cap, MAP_READ_PEEK)
}

fn text(name: &CStr, l: &Loaded, maps: &[MapSummary], cap: u32) {
    let kv = |label: &str, v: &[u8]| [format!("{label:<22} ").as_bytes(), v, b"\n"].concat();
    let mut t = Vec::new();

    t.extend(kv("Name:", name.to_bytes()));
    t.extend(kv("Location:", &l.location));
    t.extend(kv("Program ID:", l.prog_id.to_string().as_bytes()));
    if !l.loaded_at.is_empty() {
        let age = age(&l.loaded_at);
        let ago = if age.is_empty() {
            Vec::new()
        } else {
            [&b"  ("[..], &age, b" ago)"].concat()
        };
        t.extend(kv("Loaded at:", &[&l.loaded_at[..], &ago].concat()));
    }
    if l.payload.is_empty() {
        t.extend(kv("Payload sha256:", b"unavailable"));
    } else {
        t.extend(kv(
            "Payload sha256:",
            &[&l.payload[..], b"  (signature-bound)"].concat(),
        ));
    }
    match &l.programs {
        None => t.extend(kv("Missed runs:", b"unavailable")),
        Some(programs) if programs.is_empty() => {
            t.extend(kv("Missed runs:", b"not counted for this attach kind"));
        }
        Some(programs) => {
            let missed = programs.iter().fold(0u64, |n, p| n.wrapping_add(p.missed));
            t.extend(kv("Missed runs:", missed.to_string().as_bytes()));
            if programs.len() > 1 {
                for p in programs {
                    let location: &[u8] = if p.location.is_empty() {
                        b"?"
                    } else {
                        &p.location
                    };
                    t.extend(kv(
                        "",
                        &[location, b": ", p.missed.to_string().as_bytes()].concat(),
                    ));
                }
            }
        }
    }
    let names = maps
        .iter()
        .map(|m| cstr(&m.name))
        .collect::<Vec<_>>()
        .join(&b", "[..]);
    t.extend(kv("Maps:", if maps.is_empty() { b"none" } else { &names }));

    t.extend_from_slice(b"\nSource (kernel BTF line_info):\n\n");
    if l.lines.is_empty() {
        t.extend_from_slice(b"  no line info: built without clang -g\n");
    }
    for file in l.lines.chunk_by(|a, b| a.file == b.file) {
        t.extend([&b"  "[..], &file[0].file, b":\n"].concat());
        for x in file {
            t.extend([format!("    {:>5}: ", x.line).as_bytes(), &x.src, b"\n"].concat());
        }
    }
    out(&t);

    for m in maps {
        let v = read_map(name, m, cap);
        out(&[b"\n== Map: ", cstr(&m.name), b" ==\n"].concat());
        match v {
            Ok(v) => map_render::print_detail(&v),
            Err(e) => out(&[b"  (read failed: ", strerr(-e), b")\n"].concat()),
        }
    }
}

fn json(name: &CStr, l: &Loaded, maps: &[MapSummary], cap: u32) -> c_int {
    let mut e = JsonEmit::growing(JSON_MAX);

    e.obj_open();
    e.kv_int(b"schema", 1);
    e.obj_open_key(b"upatch");
    e.kv_string(b"name", name.to_bytes());
    e.kv_string(b"location", &l.location);
    e.kv_int(b"prog_id", i64::from(l.prog_id));
    e.kv_string(b"loaded_at", &l.loaded_at);
    e.kv_string(b"age", &age(&l.loaded_at));
    if l.payload.is_empty() {
        e.kv_null(b"payload_sha256");
    } else {
        e.kv_string(b"payload_sha256", &l.payload);
    }
    if let Some(programs) = &l.programs {
        if programs.is_empty() {
            e.kv_null(b"missed_runs");
        } else {
            e.kv_u64(
                b"missed_runs",
                programs.iter().fold(0u64, |n, p| n.wrapping_add(p.missed)),
            );
        }
    } else {
        e.kv_null(b"missed_runs");
    }
    e.arr_open(b"programs");
    if let Some(programs) = &l.programs {
        for p in programs {
            e.obj_open();
            e.kv_string(b"location", &p.location);
            e.kv_u64(b"missed_runs", p.missed);
            e.obj_close();
        }
    }
    e.arr_close();
    e.obj_open_key(b"source");
    e.arr_open(b"files");
    for file in l.lines.chunk_by(|a, b| a.file == b.file) {
        e.obj_open();
        e.kv_string(b"path", &file[0].file);
        e.arr_open(b"lines");
        for x in file {
            e.obj_open();
            e.kv_int(b"line", i64::from(x.line));
            e.kv_string(b"src", &x.src);
            e.obj_close();
        }
        e.arr_close();
        e.obj_close();
    }
    e.arr_close();
    e.obj_close();
    e.arr_open(b"maps");
    for m in maps {
        match read_map(name, m, cap) {
            Ok(v) => map_render::emit_json_object(&mut e, &v),
            Err(err) => {
                e.obj_open();
                e.kv_string(b"name", cstr(&m.name));
                e.kv_string(b"type", type_name(m));
                e.kv_int(b"max_entries", i64::from(m.max_entries));
                e.kv_string(b"error", strerr(-err));
                e.obj_close();
            }
        }
    }
    e.arr_close();
    e.obj_close();
    e.obj_close();
    print_json(e, b"upatch get")
}

const GET_JSON: c_int = 0;
const GET_SHOW_FULL: c_int = 1;

static GET_OPTS: [OptSpec; 2] = [
    OptSpec::new(c"--json", 0, 0, None, c"machine-readable JSON output"),
    OptSpec::new(
        c"--show-full",
        0,
        0,
        None,
        c"lift the per-map 256-entry truncation cap",
    ),
];

static GET_SECTIONS: [HelpSection; 1] = [HelpSection::options(c"options:", &GET_OPTS)];

static GET_HELP: Help = Help::new(
    c"shirudo upatch get <name> [--json] [--show-full]",
    Some(
        c"Describe a loaded upatch from the target kernel:\n  \
          - the SEC()-style attach hook (e.g. fexit/tcp_v4_connect),\n  \
          - the prog source via BTF line_info installed by the\n    \
          signed loader (authoritative, but sparse),\n  \
          - every pinned map: BTF key/value type definitions plus\n    \
          the live key/value contents.\n\
          Read-only; uses only LSM-allowed bpf() ops, xattr and stat.",
    ),
    &GET_SECTIONS,
    Some(
        c"Examples:\n  shirudo upatch get cve-2026-31431\n  \
          shirudo upatch get cve-2026-31431 --json | jq",
    ),
);

/// `upatch get`, from `get` on.
pub(super) fn run(args: &[&CStr]) -> c_int {
    let mut p = OptParser::new(c"upatch get", &GET_OPTS, Some(&GET_HELP), args, 1);
    let (mut json_out, mut show_full) = (false, false);
    let mut want: Option<&[u8]> = None;

    loop {
        match p.next() {
            OPT_END => break,
            GET_JSON => json_out = true,
            GET_SHOW_FULL => show_full = true,
            OPT_ARG => {
                if want.is_some() {
                    p.usage_arg(b"unexpected argument ");
                    return EXIT_USAGE;
                }
                want = p.value().map(CStr::to_bytes);
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    let Some(want) = want else {
        p.usage(b"takes the name of a loaded upatch");
        return EXIT_USAGE;
    };
    if !name_valid(Some(want)) {
        p.usage(&[b"invalid name '", want, b"'"].concat());
        return EXIT_USAGE;
    }
    let Ok(name) = CString::new(want) else {
        return 2;
    };
    let loaded = match collect(&name) {
        Ok(l) => l,
        Err(e) => {
            log_err(&[b"upatch get: '", want, b"': ", strerr(-e)].concat());
            return 1;
        }
    };
    let maps = Summaries::of(Some(&name));
    let cap = if show_full { 0 } else { MAP_ENTRIES_DEFAULT };
    if json_out {
        json(&name, &loaded, maps.as_slice(), cap)
    } else {
        text(&name, &loaded, maps.as_slice(), cap);
        0
    }
}
