// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;

/// SHA-256 of `data` for the expected event values.
fn sha256(data: &[u8]) -> [u8; 32] {
    crate::util::crypto_openssl::sha256(data).unwrap()
}

#[test]
#[cfg_attr(miri, ignore = "OpenSSL SHA-256 is foreign code")]
fn sha256_parts_hashes_the_concatenation() {
    assert_eq!(sha256_parts(b"ab", b"c"), Ok(sha256(b"abc")));
    assert_eq!(sha256_parts(b"abc", b""), Ok(sha256(b"abc")));
    assert_eq!(sha256_parts(b"", b"abc"), Ok(sha256(b"abc")));
    assert_eq!(sha256_parts(b"", b""), Ok(sha256(b"")));
}

#[test]
#[cfg_attr(miri, ignore = "OpenSSL SHA-256 is foreign code")]
fn chain_events_hash_their_documented_input() {
    let cert = [0xa5u8; 32];
    let input = [&b"shirudo-key-revoke\0"[..], &cert].concat();

    assert_eq!(key_event(c"shirudo-key-revoke", &cert), Ok(sha256(&input)));
}

#[test]
fn upatch_tags_are_distinct() {
    let tags = [
        upatch_tag(TYPE_BPF, true),
        upatch_tag(TYPE_BPF, false),
        upatch_tag(TYPE_JAVA, true),
        upatch_tag(TYPE_JAVA, false),
    ]
    .map(|tag| tag.map(CStr::to_bytes));

    assert_eq!(
        tags,
        [
            Some(&b"shirudo-upatch"[..]),
            Some(&b"shirudo-unload"[..]),
            Some(&b"shirudo-java"[..]),
            Some(&b"shirudo-java-unload"[..]),
        ]
    );
    assert!(upatch_tag(3, true).is_none());
}

#[test]
#[cfg_attr(miri, ignore = "OpenSSL SHA-256 is foreign code")]
fn java_unload_event_hashes_its_documented_input() {
    let payload = [0x3cu8; 32];
    let mut name = [b'n'; NAME_MAX + 1];
    name[NAME_MAX] = 0;
    let tag = upatch_tag(TYPE_JAVA, false).unwrap();
    let event = upatch_event(tag, &name, &payload).unwrap();
    assert_eq!(
        event,
        sha256(&[tag.to_bytes_with_nul(), &payload, &name[..NAME_MAX]].concat())
    );
}

#[test]
#[cfg_attr(miri, ignore = "OpenSSL SHA-256 is foreign code")]
fn chain_fold_extends_like_the_register() {
    let mut chain = [0u8; 32];
    let event = [0x5au8; 32];
    let input = [[0u8; 32], event].concat();

    // SAFETY: two digests, the first written.
    assert_eq!(fold(&mut chain, &event), Ok(()));
    assert_eq!(chain, sha256(&input));
}

/// The operation digests of a three-operation tree, and the history root
/// after none, one, two and all of them as Python's hashlib gives it:
///
///   root = bytes(32)
///   for d in digests:
///       root = sha256(b"shirudo-tree-history\0" + root + d).digest()
const TREE_OPERATIONS: [&[u8]; 3] = [
    b"13b248d4a85d91150717e3e96dc9c2d7a8a43633e3b58f8f6168d408aed26c43",
    b"5ce215313f29f87bfb87aa0cc65c237bf21bdc7702606e9cc29be187f950074b",
    b"bd98b27dd5cfc9deeb0e4f49a7d4bd0f991762ec784be9ea838a59966d9dd0dc",
];
const HISTORY_ROOTS: [&[u8]; 4] = [
    b"0000000000000000000000000000000000000000000000000000000000000000",
    b"470779d64e1302c4826a4be3222020050e70784ae6016040eabde9d0d8770d80",
    b"889efeb27650c0111168d523c935f051addbcc049d079e440e518dd3939722f0",
    b"bdc9ee89e753beca03d6e9ae89344269cb3a2e8ba3662122f55b1e3f7ff34011",
];

fn operation(i: usize) -> [u8; 32] {
    let mut digest = [0u8; 32];
    crate::util::hex::decode(TREE_OPERATIONS[i], &mut digest).unwrap();
    digest
}

/// The history root after the first `n` operations, in hex.
fn history_root_after(n: usize) -> Vec<u8> {
    let root = (0..n).fold([0u8; 32], |root, i| {
        history_step(&root, &operation(i)).unwrap()
    });
    crate::util::hex::encode(&root)
}

#[test]
#[cfg_attr(miri, ignore = "OpenSSL SHA-256 is foreign code")]
fn history_root_matches_the_reference() {
    for n in [0, 1, 3] {
        assert_eq!(history_root_after(n), HISTORY_ROOTS[n]);
    }
}

#[test]
#[cfg_attr(miri, ignore = "OpenSSL SHA-256 is foreign code")]
fn history_root_differs_from_the_projection_root() {
    const PROJECTION_ROOTS: [&[u8]; 3] = [
        b"04f83540c1727aefcf3c53449a99594c8fd1cc15e1466dbdbf3168cc8f9dc136",
        b"a042a582b3a3d8c1b633b8ed0356e0b52f1f5aa25af85b06cc3f481562dcda93",
        b"154522480ff8884daa95589e80f26f20248bbf9c192dfbb3cee04e03b4f136a1",
    ];
    let (mut history, mut projection) = ([0u8; 32], [0u8; 32]);

    for i in 0..TREE_OPERATIONS.len() {
        let digest = operation(i);
        let prev = projection;

        history = history_step(&history, &digest).unwrap();
        projection = sha256_parts(&prev, &digest).unwrap();
        assert_eq!(crate::util::hex::encode(&projection), PROJECTION_ROOTS[i]);
        assert_eq!(crate::util::hex::encode(&history), HISTORY_ROOTS[i + 1]);
        assert_ne!(history, projection);
    }
}

#[test]
fn anchor_returns_the_complete_terminated_record() {
    let mut name = [0xa5u8; NAME_LEN];
    name[..2].copy_from_slice(&[0, 0x0b]);
    let value = anchor(&name).unwrap();
    let expected = [
        &b"nvpcr-init:shirudo:0x1818e00:000b"[..],
        &b"a5".repeat(DIGEST_LEN),
    ]
    .concat();

    assert_eq!(cstr(&value), expected);
    assert!(value[expected.len()..].iter().all(|&byte| byte == 0));
    assert_eq!(anchor(&name[..NAME_LEN - 1]), Err(-EINVAL));
}

#[test]
fn anchor_record_matches_systemd_shape() {
    let anchor = b"nvpcr-init:shirudo:0x1818e00:000b01";
    let digest = [0x5a; 32];
    let boot_id = *b"0123456789abcdef0123456789abcdef";
    let record = anchor_record(anchor, &digest, &boot_id, 123_456).unwrap();
    assert_eq!(log_anchor(b"nvpcr-init:\"x", &digest), Err(-EINVAL));
    let expected = [
        &b"\x1e{\"pcr\":9,\"digests\":[{\"hashAlg\":\"sha256\",\"digest\":\""[..],
        &crate::util::hex::encode(&digest),
        &b"\"}],\"content_type\":\"systemd\",\"content\":{\"string\":\""[..],
        anchor,
        &b"\",\"bootId\":\""[..],
        &boot_id,
        &b"\",\"timestamp\":123456,\"eventType\":\"nvpcr-init\"}}\n"[..],
    ]
    .concat();
    assert_eq!(record, expected);
    assert_eq!(
        measure_log_path(Some(std::ffi::OsStr::new("/home/test/log")), true),
        std::path::Path::new("/home/test/log")
    );
    assert_eq!(
        measure_log_path(Some(std::ffi::OsStr::new("/home/test/log")), false),
        std::path::Path::new("/run/log/systemd/tpm2-measure.log")
    );
}

#[cfg(not(miri))]
#[test]
fn anchor_log_marks_an_interrupted_record() {
    use std::os::unix::fs::PermissionsExt;

    let root = std::path::PathBuf::from(std::env::var_os("HOME").unwrap()).join(".cache/pt");
    std::fs::create_dir_all(&root).unwrap();
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = root.join(format!(
        "shirudo-r13-anchor-{}-{unique}",
        std::process::id()
    ));
    let record = anchor_record(
        b"nvpcr-init:shirudo:0x1818e00:000b01",
        &[0x5a; 32],
        b"0123456789abcdef0123456789abcdef",
        123_456,
    )
    .unwrap();
    append_anchor_record(&path, &record).unwrap();
    append_anchor_record(&path, &record).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes, [record.as_slice(), record.as_slice()].concat());
    let metadata = std::fs::metadata(&path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o1600)).unwrap();
    assert_eq!(
        append_anchor_record(&path, &record),
        Err(-crate::errno::ESTALE)
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    std::fs::remove_file(&path).unwrap();
}
