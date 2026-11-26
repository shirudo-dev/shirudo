// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo upatch`: describe an upatch file, list the archived and the
//! loaded upatches, describe a loaded one and read its maps from the
//! kernel, and load and unload upatches through the signed loader.

mod get;
mod info;
mod list;
pub(crate) mod loader;
mod map;
mod ops;
mod reconcile;

use core::ffi::{CStr, c_int};
use std::ffi::CString;

use crate::sys::libc::{fwrite, stderr, stdout};
use crate::util::help::{
    Help, HelpItem, HelpSection, is_help, is_list_cmds, print_help, print_subcmd_list,
    resolve_subcommand,
};
use crate::util::json::JsonEmit;
use crate::util::map_read::{self, MapSummary};

/// The most a JSON document grows to.
const JSON_MAX: usize = 8 * 1024 * 1024;

pub(crate) use ops::{
    UPATCH_PURGE_NO_ARCHIVE, UPATCH_PURGE_NO_SIGNER, UPATCH_PURGE_OTHER_SIGNER, install,
    install_fd, purge, purge_check, remove, remove_fd,
};

static SUBCMDS: [HelpItem; 7] = [
    HelpItem::new(
        c"load",
        c"load a signed .upatch into the target kernel (target-only)",
    ),
    HelpItem::new(
        c"unload",
        c"apply a signed UNLOAD directive (forward chain extension)",
    ),
    HelpItem::new(
        c"list",
        c"list the archived and the loaded upatches on this host",
    ),
    HelpItem::new(
        c"info",
        c"describe a .upatch file (any host; offline, no kernel state)",
    ),
    HelpItem::new(
        c"get",
        c"dump source of a loaded upatch from the target kernel (BTF line_info)",
    ),
    HelpItem::new(
        c"map",
        c"read pinned map contents (target-only; BTF type-aware)",
    ),
    HelpItem::new(
        c"reconcile",
        c"attach loaded XDP upatches to devices that appeared later (target-only)",
    ),
];

static UPATCH_SECTIONS: [HelpSection; 1] = [HelpSection::items(c"subcommands:", &SUBCMDS)];

static UPATCH_HELP: Help = Help::new(
    c"shirudo upatch <subcommand> [<args>...]",
    Some(
        c"Manage signed BPF programs (.upatch). load/unload are target-only;\n\
          list/info/get are read-only and run on either side.",
    ),
    &UPATCH_SECTIONS,
    None,
);

/// Text to the C library's stdout, where the C subcommands write.
fn out(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stdout.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stdout) };
}

/// Text to the C library's stderr.
fn err(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stderr.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stderr) };
}

/// A message through the log function `f`, err() or its kin.
fn log(f: fn(&[u8]), text: &[u8]) {
    let text = CString::new(
        text.iter()
            .copied()
            .filter(|&c| c != 0)
            .collect::<Vec<u8>>(),
    )
    .unwrap_or_default();
    f(text.to_bytes());
}

fn log_err(text: &[u8]) {
    log(crate::log::err, text);
}

fn log_warn(text: &[u8]) {
    log(crate::log::warn, text);
}

fn log_info(text: &[u8]) {
    log(crate::log::info, text);
}

fn log_audit(text: &[u8]) {
    log(crate::log::audit, text);
}

/// The maps the loaded upatches pin: upatch `upatch`'s, or every
/// upatch's for none.
struct Summaries(Vec<MapSummary>);

impl Summaries {
    fn of(upatch: Option<&CStr>) -> Self {
        Summaries(map_read::list(upatch.map(CStr::to_bytes)))
    }

    fn as_slice(&self) -> &[MapSummary] {
        &self.0
    }
}

/// A map's type name, "" for none.
fn type_name(m: &MapSummary) -> &'static [u8] {
    m.type_name.map_or(b"", CStr::to_bytes)
}

/// The category of a pin that could not be opened: the guards refused
/// it, or it is missing or not what it should be.
fn pin_category(err: c_int) -> &'static CStr {
    use crate::errno::{EACCES, ENOENT, EPERM, ESTALE};

    match err {
        EACCES | EPERM => c"lsm_denied",
        ENOENT | ESTALE => c"tampered",
        _ => c"unknown",
    }
}

fn strerr(err: c_int) -> &'static [u8] {
    // SAFETY: strerror() gives a C string that outlives the message.
    unsafe { crate::ffi::c_str(crate::sys::libc::strerror(err)) }
}

/// `s` padded with spaces to `width` bytes, as printf's %-Ns does.
fn pad(s: &[u8], width: usize) -> Vec<u8> {
    let mut v = s.to_vec();
    v.resize(width.max(s.len()), b' ');
    v
}

fn hex(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| [HEX[usize::from(b >> 4)], HEX[usize::from(b & 0xf)]])
        .collect()
}

/// The document `e` built, printed with its newline, or the failure to
/// encode it reported for `cmd`: 0 or 1.
fn print_json(e: JsonEmit, cmd: &[u8]) -> c_int {
    match e.finish() {
        Ok(doc) => {
            out(&[&doc[..], b"\n"].concat());
            0
        }
        Err(e) => {
            err(&[cmd, b": json encode failed: ", strerr(-e), b"\n"].concat());
            1
        }
    }
}

/// `shirudo upatch`, from `upatch` on.
pub(crate) fn cmd_upatch(args: &[&CStr]) -> c_int {
    let word = |i: usize| args.get(i).map(|a| a.to_bytes());
    if args.len() < 2 || is_help(word(1)) {
        print_help(&UPATCH_HELP);
        return if args.len() < 2 { 2 } else { 0 };
    }
    if is_list_cmds(word(1)) {
        print_subcmd_list(&SUBCMDS);
        return 0;
    }
    let Some(canonical) = resolve_subcommand(c"shirudo upatch", args[1], &SUBCMDS) else {
        return 2;
    };
    let rest = &args[1..];
    match canonical.to_bytes() {
        b"info" => info::run(rest),
        b"list" => list::run(rest),
        b"get" => get::run(rest),
        b"load" => ops::run_load(rest),
        b"unload" => ops::run_unload(rest),
        b"map" => map::run(rest),
        b"reconcile" => reconcile::run(rest),
        _ => 2,
    }
}
