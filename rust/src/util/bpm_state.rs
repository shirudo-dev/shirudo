// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The packages bpm installed, as /var/lib/shirudo/bpm/state.json records
//! them.

use core::ffi::{CStr, c_int};
use std::os::fd::AsFd;

use crate::errno::{E2BIG, EINVAL, ENODEV, ENOENT};
use crate::sys::libc::{O_DIRECTORY, O_NONBLOCK, O_RDONLY, PATH_MAX};
use crate::text::{cstr, strsprintf};
use crate::util::bpm_oci::{MAX_NAME, name_ok, version_ok};
use crate::util::json::{JsonEmit, JsonField, parse_schema};
use crate::util::seal;
use crate::util::{identity, io};

/// `BPM_MAX_STATE`: the most packages the state records.
const MAX_STATE: usize = 256;
const STATE_FILE_MAX: usize = 8 * 1024 * 1024;
const STATE_EMIT_MAX: usize = 1024 * 1024;

/// BPM_STATE_PATH, BPM_VAR_DIR and BPM_PACKAGES_DIR of util/paths.h.
const STATE_PATH: &CStr = c"/var/lib/shirudo/bpm/state.json";
const VAR_DIR: &CStr = c"/var/lib/shirudo/bpm";
const PACKAGES_DIR: &[u8] = b"/var/lib/shirudo/bpm/packages";

/// `struct bpm_state_entry`.
#[derive(Clone, Copy)]
pub struct BpmStateEntry {
    pub(crate) name: [u8; MAX_NAME],
    pub(crate) version: [u8; MAX_NAME],
    pub(crate) source: [u8; MAX_NAME],
    pub(crate) path: [u8; PATH_MAX],
}

impl BpmStateEntry {
    pub(crate) const fn new() -> Self {
        BpmStateEntry {
            name: [0; MAX_NAME],
            version: [0; MAX_NAME],
            source: [0; MAX_NAME],
            path: [0; PATH_MAX],
        }
    }
}

/// Where the entries go, and the scratch entry the schema fills for each
/// before `take_entry()` takes it.
struct StateSink<'s> {
    items: &'s mut [BpmStateEntry],
    n: usize,
    scratch: BpmStateEntry,
}

impl StateSink<'_> {
    fn take_entry(&mut self) -> Result<(), c_int> {
        let mut expected = [0u8; PATH_MAX];
        let Some(item) = self.items.get_mut(self.n) else {
            return Err(-E2BIG);
        };
        let e = &self.scratch;
        let (name, version, source) = (cstr(&e.name), cstr(&e.version), cstr(&e.source));

        if name.is_empty()
            || version.is_empty()
            || !name_ok(name)
            || !version_ok(version)
            || !name_ok(source)
        {
            return Err(-EINVAL);
        }
        if strsprintf(&mut expected, &[PACKAGES_DIR, b"/", name, b"/", version]).is_err()
            || cstr(&expected) != cstr(&e.path)
        {
            return Err(-EINVAL);
        }
        *item = self.scratch;
        self.n += 1;
        // A field the next entry leaves out is not this entry's.
        self.scratch = BpmStateEntry::new();
        Ok(())
    }
}

/// The entries of a state document into `st`, as many as it holds, or
/// -EINVAL or -E2BIG.
fn parse(body: &[u8], st: &mut [BpmStateEntry]) -> Result<usize, c_int> {
    let mut sink = StateSink {
        items: st,
        n: 0,
        scratch: BpmStateEntry::new(),
    };
    let sub = [
        JsonField::string(c"name", |s: &mut StateSink| &mut s.scratch.name),
        JsonField::string(c"version", |s| &mut s.scratch.version),
        JsonField::string(c"source", |s| &mut s.scratch.source),
        JsonField::string(c"path", |s| &mut s.scratch.path),
    ];
    let root = [JsonField::array(c"packages", &sub, &StateSink::take_entry)];

    parse_schema(body, &root, &mut sink)?;
    if !root[0].seen() {
        return Err(-EINVAL);
    }
    Ok(sink.n)
}

/// The entries as the document parse() reads, into `buf`: the written
/// length or -E2BIG.
fn emit(st: &[BpmStateEntry], buf: &mut [u8]) -> Result<usize, c_int> {
    let mut e = JsonEmit::fixed(buf);

    e.obj_open();
    e.kv_int(b"schema", 1);
    e.arr_open(b"packages");
    for entry in st {
        e.obj_open();
        e.kv_string(b"name", cstr(&entry.name));
        e.kv_string(b"version", cstr(&entry.version));
        e.kv_string(b"source", cstr(&entry.source));
        e.kv_string(b"path", cstr(&entry.path));
        e.obj_close();
    }
    e.arr_close();
    e.obj_close();
    if e.err() != 0 {
        return Err(-E2BIG);
    }
    Ok(e.written())
}

fn read_state_file() -> Result<Vec<u8>, c_int> {
    let active = identity::enforcement_active();
    if active < 0 {
        return Err(active);
    }
    if active == 0 {
        return io::read(STATE_PATH, STATE_FILE_MAX);
    }
    let root = identity::state_root_open().map_err(|e| if e == -ENOENT { -ENODEV } else { e })?;
    let bpm = seal::open_child(root.as_fd(), c"bpm", O_RDONLY | O_DIRECTORY)?;
    let state = seal::open_child(bpm.as_fd(), c"state.json", O_RDONLY | O_NONBLOCK)?;
    io::read_fd(state.as_fd(), STATE_PATH, STATE_FILE_MAX)
}

/// The recorded entries, as many as `st` holds; none when there is no
/// state yet.
fn read(st: &mut [BpmStateEntry]) -> Result<usize, c_int> {
    let body = match read_state_file() {
        Ok(body) => body,
        Err(err) if err == -ENOENT => return Ok(0),
        Err(err) => return Err(err),
    };
    parse(&body, st)
}

/// The packages the state records.
pub(crate) fn read_all() -> Result<Vec<BpmStateEntry>, c_int> {
    let mut st = vec![BpmStateEntry::new(); MAX_STATE];
    let n = read(&mut st)?;
    st.truncate(n);
    Ok(st)
}

fn write_state_file(body: &[u8]) -> Result<(), c_int> {
    let active = identity::enforcement_active();
    if active < 0 {
        return Err(active);
    }
    if active == 0 {
        seal::mkdir_p(VAR_DIR.to_bytes(), 0o700)?;
        return seal::write_file(STATE_PATH.to_bytes(), body, 0o600);
    }
    let root = identity::state_root_open()?;
    let bpm = seal::open_or_create_child_dir(root.as_fd(), c"bpm", 0o700)?;
    seal::replace_locked_at(bpm.as_fd(), c"state.json", body, 0o600)
}

pub(crate) fn write(st: &[BpmStateEntry]) -> Result<(), c_int> {
    let mut buf = vec![0u8; STATE_EMIT_MAX];
    let len = emit(st, &mut buf)?;
    write_state_file(&buf[..len])
}

#[cfg(test)]
mod tests;
