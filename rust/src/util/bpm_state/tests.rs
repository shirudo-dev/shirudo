// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;

/// An entry of `name` at `version` from the main source, where its
/// package is installed.
fn entry(name: &[u8], version: &[u8]) -> BpmStateEntry {
    let mut e = BpmStateEntry::new();

    e.name[..name.len()].copy_from_slice(name);
    e.version[..version.len()].copy_from_slice(version);
    e.source[..4].copy_from_slice(b"main");
    let path = [PACKAGES_DIR, b"/", name, b"/", version].concat();
    e.path[..path.len()].copy_from_slice(&path);
    e
}

/// emit() of `st` into a buffer of `cap` bytes: its result and the
/// document.
fn emitted(st: &[BpmStateEntry], cap: usize) -> (c_int, Vec<u8>) {
    let mut buf = vec![0u8; cap];
    let ret = match emit(st, &mut buf) {
        Ok(len) => {
            buf.truncate(len);
            0
        }
        Err(err) => {
            buf.clear();
            err
        }
    };
    (ret, buf)
}

/// parse() of `doc`: its result and the entries.
fn parsed(doc: &[u8]) -> (c_int, Vec<BpmStateEntry>) {
    let mut out = vec![BpmStateEntry::new(); MAX_STATE];
    let ret = match parse(doc, &mut out) {
        Ok(n) => {
            out.truncate(n);
            0
        }
        Err(err) => {
            out.clear();
            err
        }
    };
    (ret, out)
}

fn same(a: &BpmStateEntry, b: &BpmStateEntry) -> bool {
    a.name == b.name && a.version == b.version && a.source == b.source && a.path == b.path
}

#[test]
fn state_reads_back_what_it_writes() {
    let st = [entry(b"kernel-obs", b"1.0.0"), entry(b"fix", b"2.1.0-rc.1")];
    let (ret, doc) = emitted(&st, 4096);

    assert_eq!(ret, 0);
    let (ret, back) = parsed(&doc);
    assert_eq!(ret, 0);
    assert_eq!(back.len(), 2);
    assert!(back.iter().zip(&st).all(|(a, b)| same(a, b)));
    assert_eq!(emitted(&st, 16).0, -E2BIG);
}

#[test]
fn state_refuses_an_entry_out_of_place() {
    let mut e = entry(b"fix", b"1.0.0");
    let end = cstr(&e.path).len() - 1;

    e.path[end] = b'1';
    assert_eq!(parsed(&emitted(&[e], 4096).1).0, -EINVAL);
    let mut e = entry(b"../fix", b"1.0.0");
    assert_eq!(parsed(&emitted(&[e], 4096).1).0, -EINVAL);
    assert_eq!(parsed(br#"{"schema":1}"#).0, -EINVAL);
    e.name[0] = 0;
    assert_eq!(parsed(&emitted(&[e], 4096).1).0, -EINVAL);
}
