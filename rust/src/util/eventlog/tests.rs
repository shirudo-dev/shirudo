// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::testutil::TempDir;
use crate::util::upatch::{TYPE_BPF, TYPE_JAVA};

/// This thread's log, in `dir`.
fn use_log(dir: &TempDir) {
    let leak = |name| -> &'static CStr { Box::leak(dir.cpath(name).into_boxed_c_str()) };

    TEST_PATHS.set(Some((leak("eventlog"), leak("pending"))));
}

/// A record of `ty` and a digest of `fill` bytes, whose fields `body`
/// adds.
fn record(ty: &[u8], fill: u8, body: impl FnOnce(&mut JsonEmit)) -> Vec<u8> {
    let mut buf = [0u8; 1024];
    let mut e = JsonEmit::fixed(&mut buf);

    record_open(&mut e, ty, &[fill; 32]);
    body(&mut e);
    e.obj_close();
    assert_eq!(e.err(), 0);
    let n = e.written();
    buf[..n].to_vec()
}

fn plain(ty: &[u8], fill: u8) -> Vec<u8> {
    record(ty, fill, |_| {})
}

fn write_log(text: &[u8]) {
    std::fs::write(path().to_str().unwrap(), text).unwrap();
}

/// The register the log replays to.
fn replayed() -> Result<[u8; 32], c_int> {
    let mut out = [0u8; 32];
    match records::replay(&mut out) {
        0 => Ok(out),
        err => Err(err),
    }
}

/// The lines, each with its newline.
fn lines(lines: &[&[u8]]) -> Vec<u8> {
    lines.iter().flat_map(|l| [*l, b"\n"].concat()).collect()
}

/// A record killed before its newline is no record yet: readers skip it,
/// and the next append drops it rather than run on from it.
#[test]
#[cfg_attr(miri, ignore = "gmtime_r is a foreign call")]
fn unfinished_append_is_no_record() {
    let dir = TempDir::new();
    use_log(&dir);
    let (init, load, unload) = (
        plain(b"init", 1),
        plain(b"upatch_load", 2),
        plain(b"upatch_unload", 3),
    );

    write_log(&lines(&[&init]));
    let alone = replayed().unwrap();
    write_log(&lines(&[&init, &unload]));
    let both = replayed().unwrap();
    write_log(&[lines(&[&init]), load[..load.len() - 1].to_vec()].concat());
    assert_eq!(replayed(), Ok(alone));
    write_log(&[lines(&[&init]), load].concat());
    assert_eq!(replayed(), Ok(alone));
    assert_eq!(append_to(path(), &unload), 0);
    assert_eq!(replayed(), Ok(both));
}

/// A NUL would end the walk early and hide the records after it.
#[test]
#[cfg_attr(miri, ignore = "gmtime_r is a foreign call")]
fn nul_in_the_log_is_refused() {
    let dir = TempDir::new();
    use_log(&dir);
    let (init, unload) = (plain(b"init", 1), plain(b"upatch_unload", 3));

    write_log(&lines(&[&init, &[b"\0", &unload[..]].concat()]));
    assert_eq!(replayed(), Err(-EINVAL));
}

const DIGEST_HEX: &[u8] = b"abababababababababababababababababababababababababababababababab";

fn operation() -> Vec<u8> {
    [&b"sha256:"[..], DIGEST_HEX].concat()
}

fn tree_record(seq: i64, op: &[u8]) -> Vec<u8> {
    record(b"tree_op", 7, |e| {
        e.obj_open_key(b"tree");
        e.kv_int(b"seq", seq);
        e.kv_string(b"operation_digest", op);
        e.obj_close();
    })
}

/// Tree recovery asks whether an operation was measured this boot before
/// it applies the operation again, which would measure it twice.
#[test]
#[cfg_attr(miri, ignore = "gmtime_r is a foreign call")]
fn tree_op_measured_this_boot() {
    let dir = TempDir::new();
    use_log(&dir);
    let (init, tree) = (plain(b"init", 1), tree_record(3, &operation()));

    assert_eq!(records::tree_op_measured(3, &operation()), 0);
    write_log(&lines(&[&init, &tree]));
    assert_eq!(records::tree_op_measured(3, &operation()), 1);
    assert_eq!(records::tree_op_measured(4, &operation()), 0);
    assert_eq!(
        records::tree_op_measured(3, &[&operation()[..], b"0"].concat()),
        0
    );
    write_log(&lines(&[&tree]));
    assert_eq!(records::tree_op_measured(3, &operation()), 0);
}

#[derive(Default)]
struct Seen {
    inits: i32,
    loads: i32,
    unloads: i32,
    last: Vec<u8>,
}

/// The upatch events of this boot's records, counted into `s`.
fn count_upatches(s: &mut Seen) -> c_int {
    records::upatches(false, &mut |event, name, _| {
        if event == UPATCH_INIT {
            s.inits += 1;
            return 0;
        }
        s.loads += c_int::from(event == records::UPATCH_LOAD);
        s.unloads += c_int::from(event == UPATCH_UNLOAD);
        s.last = name.to_vec();
        0
    })
}

fn set_record(ty: &[u8], name: &[u8]) -> Vec<u8> {
    record(ty, 2, |e| {
        e.arr_open(b"set");
        e.obj_open();
        e.kv_string(b"name", name);
        e.kv_string(b"payload_sha256", DIGEST_HEX);
        e.obj_close();
        e.arr_close();
    })
}

/// A mixed-case log digest denotes the same payload that a pin reports
/// in lowercase hex.
#[test]
#[cfg_attr(
    miri,
    ignore = "eventlog file reads use open flags Miri does not support"
)]
fn measured_set_uses_decoded_payload() {
    let dir = TempDir::new();
    use_log(&dir);
    let mixed = std::str::from_utf8(DIGEST_HEX)
        .unwrap()
        .to_ascii_uppercase();
    let init = format!(r#"{{"type":"init","set":[{{"name":"boot","payload_sha256":"{mixed}"}}]}}"#);
    let load =
        format!(r#"{{"type":"upatch_load","upatch":{{"name":"fix","payload_sha256":"{mixed}"}}}}"#);
    write_log(&lines(&[init.as_bytes(), load.as_bytes()]));

    let set = crate::util::measured::MeasuredSet::log().unwrap();
    assert!(set.holds(b"boot", DIGEST_HEX));
    assert!(set.holds(b"fix", DIGEST_HEX));
}

/// The record reader gives both init set members and later loads the
/// lowercase spelling, without needing to open the eventlog.
#[test]
fn upatch_records_canonicalize_payload_hex() {
    let mixed = std::str::from_utf8(DIGEST_HEX)
        .unwrap()
        .to_ascii_uppercase();
    let init = format!(r#"{{"type":"init","set":[{{"name":"boot","payload_sha256":"{mixed}"}}]}}"#);
    let load =
        format!(r#"{{"type":"upatch_load","upatch":{{"name":"fix","payload_sha256":"{mixed}"}}}}"#);
    for (record, is_init, name) in [
        (init.as_str(), true, &b"boot"[..]),
        (load.as_str(), false, &b"fix"[..]),
    ] {
        let line = std::ffi::CString::new(record).unwrap();
        let mut got = Vec::new();
        assert_eq!(
            records::upatches_record(&line, is_init, &mut |event, member, payload| {
                if event == records::UPATCH_LOAD {
                    got.push((member.to_vec(), payload.to_vec()));
                }
                0
            }),
            0
        );
        assert_eq!(got, [(name.to_vec(), DIGEST_HEX.to_vec())]);
    }
}

/// Only an init record's set says what boot restore loaded.
#[test]
#[cfg_attr(miri, ignore = "gmtime_r is a foreign call")]
fn set_counts_in_an_init_record_alone() {
    let dir = TempDir::new();
    use_log(&dir);
    let mut s = Seen::default();

    write_log(&lines(&[
        &set_record(b"init", b"fix"),
        &set_record(b"key_revoke", b"ghost"),
    ]));
    assert_eq!(count_upatches(&mut s), 0);
    assert_eq!(
        (s.inits, s.loads, s.unloads, s.last.as_slice()),
        (1, 1, 0, &b"fix"[..])
    );
    write_log(&lines(&[&set_record(b"init", b"../fix")]));
    assert_eq!(count_upatches(&mut s), -EINVAL);
}

/// A set member must supply its own name and digest, even if an upatch
/// object elsewhere in the same record supplies the missing field.
#[test]
fn set_member_cannot_borrow_upatch_fields() {
    let digest = std::str::from_utf8(DIGEST_HEX).unwrap();
    for member in [
        format!(r#"{{"payload_sha256":"{digest}"}}"#),
        r#"{"name":"restored"}"#.to_owned(),
    ] {
        let text = format!(
            r#"{{"type":"init","upatch":{{"name":"outer","payload_sha256":"{digest}"}},"set":[{member}]}}"#
        );
        let line = std::ffi::CString::new(text).unwrap();
        let mut loads = 0;
        assert_eq!(
            records::upatches_record(&line, true, &mut |event, _, _| {
                loads += c_int::from(event == records::UPATCH_LOAD);
                0
            }),
            -EINVAL
        );
        assert_eq!(loads, 0);
    }
}

/// The next set member cannot reuse the preceding member's fields.
#[test]
fn set_member_cannot_borrow_previous_fields() {
    let digest = std::str::from_utf8(DIGEST_HEX).unwrap();
    let text = format!(
        r#"{{"type":"init","set":[{{"name":"first","payload_sha256":"{digest}"}},{{"payload_sha256":"{digest}"}}]}}"#
    );
    let line = std::ffi::CString::new(text).unwrap();
    let mut loaded = Vec::new();
    assert_eq!(
        records::upatches_record(&line, true, &mut |event, name, _| {
            if event == records::UPATCH_LOAD {
                loaded.push(name.to_vec());
            }
            0
        }),
        -EINVAL
    );
    assert_eq!(loaded, [b"first".to_vec()]);
}

fn upatch_event_record(ty: &[u8], name: &[u8]) -> Vec<u8> {
    record(ty, 3, |e| {
        e.obj_open_key(b"upatch");
        e.kv_string(b"name", name);
        e.kv_string(b"payload_sha256", DIGEST_HEX);
        e.obj_close();
    })
}

#[test]
fn upatch_records_name_type_and_direction() {
    assert_eq!(
        records::upatch_record(TYPE_BPF, true),
        Some(&b"upatch_load"[..])
    );
    assert_eq!(
        records::upatch_record(TYPE_JAVA, false),
        Some(&b"java_unload"[..])
    );
    assert_eq!(records::upatch_record(3, true), None);
    assert_eq!(
        records::upatch_record_parse(b"java_load"),
        Some((TYPE_JAVA, true))
    );
    assert_eq!(
        records::upatch_record_parse(b"upatch_unload"),
        Some((TYPE_BPF, false))
    );
    assert_eq!(records::upatch_record_parse(b"java_loa"), None);
    assert_eq!(records::upatch_record_parse(b"upatch_load "), None);
    assert_eq!(
        records::upatch_kind_parse(b"java-unload"),
        Some((TYPE_JAVA, false))
    );
}

#[test]
#[cfg_attr(miri, ignore = "gmtime_r is a foreign call")]
fn java_records_count_as_upatch_events() {
    let dir = TempDir::new();
    use_log(&dir);
    let mut s = Seen::default();
    let init = set_record(b"init", b"fix");
    let load = upatch_event_record(b"java_load", b"agent");
    let unload = upatch_event_record(b"java_unload", b"agent");

    write_log(&lines(&[&init, &load, &unload]));
    assert_eq!(count_upatches(&mut s), 0);
    assert_eq!(
        (s.inits, s.loads, s.unloads, s.last.as_slice()),
        (1, 2, 1, &b"agent"[..])
    );
}
