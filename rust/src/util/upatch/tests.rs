// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::text::cstr;

#[test]
fn bpffs_name_round_trips() {
    assert_eq!(pin_name(b"a.b..c"), b"a~db~d~dc");
    assert_eq!(name_from_pin(b"a~db~d~dc").as_deref(), Some(&b"a.b..c"[..]));
    assert_eq!(name_from_pin(b"a~x"), None);
    assert_eq!(name_from_pin(b"a~"), None);
}

/// An attach entry of `kind`, an XDP program's classes in its union.
fn entry(kind: u32, classes: u32) -> Vec<u8> {
    let mut e = vec![0u8; PROG_ENTRY];

    e[..4].copy_from_slice(&ROLE_ATTACH.to_le_bytes());
    e[4..8].copy_from_slice(&kind.to_le_bytes());
    e[8..12].copy_from_slice(&classes.to_le_bytes());
    e
}

/// Program metadata of `nr_maps` maps and the entries.
fn metadata(nr_maps: u32, entries: &[Vec<u8>]) -> Vec<u8> {
    let head = [PROG_MAGIC, PROG_VERSION, entries.len() as u32, nr_maps];
    head.iter()
        .flat_map(|v| v.to_le_bytes())
        .chain(entries.concat())
        .collect()
}

#[test]
fn prog_specs_take_the_signed_counts() {
    let md = metadata(3, &[entry(ATTACH_RAW_TRACEPOINT, 0)]);
    let specs = Specs::parse(&md, 3, 1).unwrap();
    let s = &specs.as_slice()[0];

    assert_eq!(
        (s.role, s.kind, s.target_fd),
        (ROLE_ATTACH, ATTACH_RAW_TRACEPOINT, -1)
    );
}

#[test]
fn prog_specs_refuse_another_header_count() {
    let md = metadata(3, &[entry(ATTACH_RAW_TRACEPOINT, 0)]);

    for (maps, progs) in [(4, 1), (2, 1), (3, 2), (3, 0)] {
        assert_eq!(
            Specs::parse(&md, maps, progs).err(),
            Some(-EINVAL),
            "{maps} {progs}"
        );
    }
}

/// Metadata of one kprobe multi program and its UPKS name block.
fn one_kprobe_multi(kind: u32, names: &[u8], nr_syms: u32) -> Vec<u8> {
    let words = |values: &[u32]| {
        values
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<u8>>()
    };
    let mut md = metadata(0, &[entry(kind, 0)]);

    md.extend(words(&[KPROBE_TARGET_MAGIC, KPROBE_TARGET_VERSION, 1, 0]));
    md.extend(words(&[0, nr_syms, names.len() as u32]));
    md.extend_from_slice(names);
    md
}

fn parse_one_kprobe(md: &[u8]) -> Result<Specs, c_int> {
    Specs::parse(md, 0, 1)
}

#[test]
fn kprobe_multi_names_are_parsed_in_order() {
    let specs = parse_one_kprobe(&one_kprobe_multi(
        ATTACH_KRETPROBE_MULTI,
        b"vfs_a\0vfs_b\0",
        2,
    ))
    .unwrap();
    let spec = &specs.as_slice()[0];
    // SAFETY: the parser's array of its two owned C strings.
    let syms = unsafe { crate::ffi::slice(spec.kprobe_syms, spec.nr_kprobe_syms as usize) };
    let names: Vec<Vec<u8>> = syms
        .iter()
        // SAFETY: every parser-produced pointer names a string in its
        // owned symbol buffer.
        .map(|&sym| unsafe { crate::ffi::c_str(sym) }.to_vec())
        .collect();

    assert_eq!(spec.kind, ATTACH_KRETPROBE_MULTI);
    assert_eq!(names, [b"vfs_a".to_vec(), b"vfs_b".to_vec()]);
}

#[test]
fn kprobe_multi_refuses_a_malformed_list() {
    for (names, count) in [
        (&b"b\0a\0"[..], 2),
        (b"a\0a\0", 2),
        (b"a\0b\0", 1),
        (b"a\0", 0),
        (b"a*\0", 1),
        (b"\0a\0", 1),
        (b"abc", 1),
    ] {
        assert_eq!(
            parse_one_kprobe(&one_kprobe_multi(ATTACH_KPROBE_MULTI, names, count)).err(),
            Some(-EINVAL),
            "{names:?}, {count}"
        );
    }
}

#[test]
fn kprobe_multi_block_is_exact() {
    let valid = one_kprobe_multi(ATTACH_KPROBE_MULTI, b"a\0", 1);
    assert!(parse_one_kprobe(&valid).is_ok());

    let mut missing = valid.clone();
    missing.truncate(PROG_METADATA + PROG_ENTRY);
    let mut cut = valid.clone();
    cut.pop();
    let mut trailing = valid.clone();
    trailing.push(0);
    let mut bad_magic = valid.clone();
    bad_magic[PROG_METADATA + PROG_ENTRY] ^= 1;
    let mut target = valid.clone();
    target[PROG_METADATA + 16] = b'a';
    let mut offset = valid.clone();
    offset[PROG_METADATA + 8] = 1;

    for malformed in [missing, cut, trailing, bad_magic, target, offset] {
        assert_eq!(parse_one_kprobe(&malformed).err(), Some(-EINVAL));
    }
}

#[test]
fn kprobe_symbol_is_one_plain_name() {
    for good in [&b"vfs_read"[..], b"foo.cold.1", &[b'a'; KPROBE_SYM_MAX - 1]] {
        assert!(kprobe_sym_valid(good), "{good:?}");
    }
    for bad in [
        &b""[..],
        b"a,b",
        b"a*",
        b"a?",
        b"a|b",
        b"a b",
        b"a\n",
        b"a\x7f",
        b"a\xc3",
        &[b'a'; KPROBE_SYM_MAX],
    ] {
        assert!(!kprobe_sym_valid(bad), "{bad:?}");
    }
}

#[test]
fn policy_path_takes_a_wildcard_in_its_last_component() {
    for path in [
        &b"/usr/sbin/httpd"[..],
        b"/httpd",
        b"/usr/sbin/php-fpm*",
        b"/usr/sbin/*fpm?.?",
        b"/*",
    ] {
        assert!(policy_path_valid(path), "{path:?}");
    }
    for path in [
        &b""[..],
        b"usr/sbin/httpd",
        b"/",
        b"/usr/sbin/",
        b"/usr/sbin/php-fpm*/",
        b"/opt/*/bin/app",
        b"/opt/app?/bin/app",
        b"/*/*",
    ] {
        assert!(!policy_path_valid(path), "{path:?}");
    }
}

#[test]
fn policy_path_ends_within_its_limit() {
    let mut path = vec![b'a'; POLICY_PATH_LEN_MAX];
    path[0] = b'/';

    assert!(policy_path_valid(&path));
    path.push(b'a');
    assert!(!policy_path_valid(&path));
    path.truncate(POLICY_PATH_LEN_MAX);
    path.push(0);
    assert!(!policy_path_valid(&path));
}

#[test]
fn policy_path_pattern_is_the_last_component_with_a_wildcard() {
    let literal = b"/usr/sbin/httpd";
    let pattern = b"/usr/sbin/php-fpm*";
    let root = b"/v?";

    assert_eq!(policy_path_pattern(literal), None);
    assert_eq!(policy_path_pattern(pattern), Some(&b"php-fpm*"[..]));
    assert_eq!(policy_path_pattern(root), Some(&b"v?"[..]));
}

fn signed_data(sections: &[(u32, &[u8])]) -> Vec<u8> {
    let words = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
    let (mut data, mut dir) = (Vec::new(), Vec::new());
    for &(tag, bytes) in sections {
        dir.extend(words(&[tag, 0, data.len() as u32, bytes.len() as u32]));
        data.extend_from_slice(bytes);
    }
    let dir_off = data.len() as u32;
    data.extend(dir);
    data.extend(words(&[
        SIGNED_TRAILER_MAGIC,
        SIGNED_VERSION,
        dir_off,
        sections.len() as u32,
    ]));
    data
}

/// A BPF container named `name` of an 8-byte loader and signature,
/// whose data holds the signed sections.
fn container(name: &[u8], sections: &[(u32, &[u8])]) -> Vec<u8> {
    let words = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
    let data = signed_data(sections);
    let at = HEADER_SIZE as u32;
    let mut c = [&MAGIC.to_le_bytes()[..], &words(&[VERSION, 0]), name].concat();
    c.resize(304, 0);
    c.extend(words(&[
        at,
        8,
        at + 8,
        8,
        0,
        0,
        at + 16,
        data.len() as u32,
        0,
        0,
        0,
        0,
        TYPE_BPF,
        0,
    ]));
    c.resize(HEADER_SIZE + 16, 0);
    c.extend(data);
    c
}

/// A Java LOAD container whose signed type is present with `ty`, or
/// absent. Its data is NAME, JAR and optionally TYPE.
fn java_container(ty: Option<u32>) -> Vec<u8> {
    let words = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
    let mut name = [0u8; NAME_MAX];
    let jar = b"PK\x03\x04jar!";
    let ty_bytes = ty.unwrap_or_default().to_le_bytes();

    name[..5].copy_from_slice(b"agent");
    let mut sections: Vec<(u32, &[u8])> = vec![(SECTION_NAME, &name), (SECTION_JAR, jar)];
    if ty.is_some() {
        sections.push((SECTION_TYPE, &ty_bytes));
    }
    let data = signed_data(&sections);
    let signature_off = HEADER_SIZE as u32;
    let data_off = signature_off + 8;
    let mut c = [
        &MAGIC.to_le_bytes()[..],
        &words(&[VERSION, 0]),
        &b"agent"[..],
    ]
    .concat();
    c.resize(304, 0);
    c.extend(words(&[
        0,
        0,
        signature_off,
        8,
        0,
        0,
        data_off,
        data.len() as u32,
        0,
        0,
        0,
        0,
        TYPE_JAVA,
        0,
    ]));
    c.resize(data_off as usize, 0);
    c.extend(data);
    c
}

fn set_header_field(c: &mut [u8], field: usize, value: u32) {
    c[304 + field * 4..304 + (field + 1) * 4].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn name_stops_at_its_nul() {
    let c = container(b"kernel-obs", &[]);

    assert_eq!(Upatch::from_bytes(&c).unwrap().name(), b"kernel-obs");
}

#[test]
fn a_name_without_its_nul_is_refused() {
    let c = container(&[b'a'; NAME_MAX], &[]);

    assert_eq!(Upatch::from_bytes(&c).err(), Some(-EINVAL));
}

#[test]
fn prog_name_is_what_the_kernel_takes() {
    let mut out = [0xffu8; 16];

    let c = container(b"fix-cve.2026", &[]);
    Upatch::from_bytes(&c).unwrap().prog_name(&mut out);
    assert_eq!(cstr(&out), b"fix_cve.2026");
    let c = container(&[b'a'; NAME_MAX - 1], &[]);
    Upatch::from_bytes(&c).unwrap().prog_name(&mut out);
    assert_eq!(cstr(&out).len(), 15);
}

#[test]
fn name_signed_is_the_header_name() {
    let mut signed = [0u8; NAME_MAX];
    let name_signed = |name: &[u8], sections: &[(u32, &[u8])]| {
        Upatch::from_bytes(&container(name, sections))
            .unwrap()
            .name_signed()
    };

    signed[..3].copy_from_slice(b"fix");
    assert!(!name_signed(b"fix", &[]));
    assert!(name_signed(b"fix", &[(SECTION_NAME, &signed)]));
    assert!(!name_signed(b"fiy", &[(SECTION_NAME, &signed)]));
}

/// Each signed section is found where the directory places it, and a
/// directory that names one twice is taken for none.
#[test]
fn signed_sections_are_once_each() {
    let payload = [7u8; PAYLOAD_HASH_LEN];
    let one = container(
        b"fix",
        &[(SECTION_ATTACH, b"meta"), (SECTION_UNLOAD, &payload)],
    );
    let twice = container(
        b"fix",
        &[
            (SECTION_UNLOAD, &payload),
            (SECTION_ATTACH, b"meta"),
            (SECTION_UNLOAD, &payload),
        ],
    );

    let u = Upatch::from_bytes(&one).unwrap();
    assert_eq!(u.signed_attach(), Some(&b"meta"[..]));
    assert_eq!(u.signed_unload_payload(), Some(&payload));
    assert!(u.signed_name().is_none() && !u.has_decoders());
    let u = Upatch::from_bytes(&twice).unwrap();
    assert_eq!((u.signed_attach(), u.signed_unload_payload()), (None, None));
}

/// One signed byte string holds a second directory where a header that
/// ends the loader 16 bytes earlier would otherwise find it.
fn split_container(shift: usize) -> Vec<u8> {
    let words = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
    let at = HEADER_SIZE as u32;
    let insns = [b'x'; 32];
    let mut name = [0u8; NAME_MAX];
    name[..3].copy_from_slice(b"fix");
    let directory = words(&[SECTION_NAME, 0, 0, NAME_MAX as u32]);
    let trailer = words(&[
        SIGNED_TRAILER_MAGIC,
        SIGNED_VERSION,
        (NAME_MAX + SIGNED_SECTION) as u32,
        1,
    ]);
    let data = [&name[..], &directory, &directory, &trailer].concat();
    let mut c = [&MAGIC.to_le_bytes()[..], &words(&[VERSION, 0]), b"fix"].concat();

    c.resize(304, 0);
    c.extend(words(&[
        at,
        8,
        at + 8,
        (insns.len() - shift) as u32,
        0,
        0,
        at + 8 + insns.len() as u32 - shift as u32,
        data.len() as u32 + shift as u32,
        0,
        0,
        0,
        0,
        TYPE_BPF,
        0,
    ]));
    c.resize(HEADER_SIZE + 8, 0);
    c.extend(insns);
    c.extend(data);
    c
}

#[test]
fn one_signature_keeps_its_sections_in_one_split() {
    assert!(
        Upatch::from_bytes(&split_container(0))
            .unwrap()
            .name_signed()
    );
    assert!(
        Upatch::from_bytes(&split_container(16))
            .unwrap()
            .signed_name()
            .is_none()
    );
}

/// What does not fit the container, or is not one, is refused.
#[test]
fn a_cut_container_is_refused() {
    let c = container(b"fix", &[(SECTION_ATTACH, b"meta")]);

    assert!(Upatch::from_bytes(&c).is_ok());
    for len in [0, 8, HEADER_SIZE, c.len() - 1] {
        assert_eq!(Upatch::from_bytes(&c[..len]).err(), Some(-EINVAL), "{len}");
    }
}

#[test]
fn java_load_opens_with_its_jar() {
    let c = java_container(Some(TYPE_JAVA));
    let u = Upatch::from_bytes(&c).unwrap();

    assert_eq!(u.payload_type(), b"java");
    assert_eq!(u.signed_type(), TYPE_JAVA);
    assert!(u.name_signed());
    assert_eq!(u.signed_jar(), Some(&b"PK\x03\x04jar!"[..]));
    assert!(u.loader().is_empty());
}

#[test]
fn java_header_needs_the_signed_type() {
    assert_eq!(
        Upatch::from_bytes(&java_container(Some(TYPE_BPF))).err(),
        Some(-EINVAL)
    );
    assert_eq!(
        Upatch::from_bytes(&java_container(None)).err(),
        Some(-EINVAL)
    );

    let mut unknown = java_container(Some(TYPE_JAVA));
    set_header_field(&mut unknown, 12, 3);
    assert_eq!(Upatch::from_bytes(&unknown).err(), Some(-EINVAL));
}

#[test]
fn java_header_carries_no_loader() {
    let mut loader = java_container(Some(TYPE_JAVA));
    set_header_field(&mut loader, 0, HEADER_SIZE as u32);
    set_header_field(&mut loader, 1, 8);
    assert_eq!(Upatch::from_bytes(&loader).err(), Some(-EINVAL));

    let mut programs = java_container(Some(TYPE_JAVA));
    set_header_field(&mut programs, 10, 1);
    assert_eq!(Upatch::from_bytes(&programs).err(), Some(-EINVAL));

    let mut unsigned = java_container(Some(TYPE_JAVA));
    set_header_field(&mut unsigned, 3, 0);
    assert_eq!(Upatch::from_bytes(&unsigned).err(), Some(-EINVAL));
}

#[test]
fn member_is_a_name_and_a_payload() {
    let payload = b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let long = b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0";

    assert!(member_valid(b"fix", payload));
    for name in [&b"a\nb"[..], b"../fix", b""] {
        assert!(!member_valid(name, payload), "{name:?}");
    }
    assert!(!member_valid(b"fix", long));
    assert!(!member_valid(b"fix", b"00"));
    assert!(!member_valid(b"fix", b""));
}

/// A name's pin directory spells each dot in two bytes, within the
/// kernel's NAME_MAX.
#[test]
fn name_fits_its_pin_directory() {
    const LINUX_NAME_MAX: usize = 255;
    let mut name = vec![b'a'; LINUX_NAME_MAX];

    assert!(name_valid(Some(&name)));
    name[LINUX_NAME_MAX - 1] = b'.';
    assert!(!name_valid(Some(&name)));
    name.pop();
    name[LINUX_NAME_MAX - 2] = b'.';
    assert!(name_valid(Some(&name)));
    assert!(!name_valid(Some(&[b'a'; LINUX_NAME_MAX + 1])));
}

#[test]
fn xdp_classes_come_from_xdp_programs_alone() {
    let spec = |kind, device_classes| {
        // SAFETY: a spec of no binary, for which zeros are a value.
        let mut s: ProgSpec = unsafe { core::mem::zeroed() };
        s.kind = kind;
        s.device_classes = device_classes;
        s
    };
    let specs = [
        spec(ATTACH_XDP, 1),
        spec(ATTACH_RAW_TRACEPOINT, 16),
        spec(ATTACH_XDP, 8),
    ];

    assert_eq!(specs_xdp_classes(&specs), 9);
    assert_eq!(specs_xdp_classes(&specs[1..2]), 0);
    assert_eq!(specs_xdp_classes(&[]), 0);
}

#[test]
fn xdp_masks_are_signed_and_bounded() {
    for mask in 1..=31u32 {
        let md = metadata(0, &[entry(ATTACH_XDP, mask)]);
        match Specs::parse(&md, 0, 1) {
            Ok(specs) => {
                let s = &specs.as_slice()[0];
                assert_eq!(mask & !XDP_ALL, 0);
                assert_eq!((s.kind, s.device_classes, s.offset), (ATTACH_XDP, mask, 0));
            }
            Err(_) => assert_ne!(mask & !XDP_ALL, 0),
        }
    }
    for spoil in [
        |e: &mut Vec<u8>| e[8..12].copy_from_slice(&0u32.to_le_bytes()),
        |e: &mut Vec<u8>| e[8..12].copy_from_slice(&32u32.to_le_bytes()),
        |e: &mut Vec<u8>| e[12] = 1,
        |e: &mut Vec<u8>| e[16] = b'x',
        |e: &mut Vec<u8>| e[16 + ATTACH_TARGET_MAX] = b'x',
        |e: &mut Vec<u8>| e[16 + ATTACH_TARGET_MAX - 1] = b'x',
        |e: &mut Vec<u8>| *e.last_mut().unwrap() = b'x',
    ] {
        let mut e = entry(ATTACH_XDP, XDP_ALL);
        spoil(&mut e);
        assert_eq!(Specs::parse(&metadata(0, &[e]), 0, 1).err(), Some(-EINVAL));
    }
}

#[test]
fn xdp_programs_select_disjoint_classes() {
    let two = |first, second| metadata(0, &[entry(ATTACH_XDP, first), entry(ATTACH_XDP, second)]);

    assert!(Specs::parse(&two(XDP_NETWORK, XDP_VIRTUAL), 0, 2).is_ok());
    assert_eq!(
        Specs::parse(&two(XDP_NETWORK | XDP_VIRTUAL, XDP_VIRTUAL), 0, 2).err(),
        Some(-EINVAL)
    );
}

#[test]
fn reserved_header_words_must_be_zero() {
    let mut bytes = [0u8; HEADER_SIZE];
    bytes[..8].copy_from_slice(&MAGIC.to_le_bytes());
    bytes[8..12].copy_from_slice(&VERSION.to_le_bytes());
    bytes[16] = b'a';
    assert!(parse_header(&bytes).is_ok());

    for offset in [320, 324] {
        bytes[offset] = 1;
        assert_eq!(parse_header(&bytes).err(), Some(-EINVAL));
        bytes[offset] = 0;
    }
}
