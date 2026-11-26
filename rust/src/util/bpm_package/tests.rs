// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::errno::{EINVAL, ENAMETOOLONG};
use crate::text::cstr;
use crate::util::bpm_oci::Descriptor;

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// An index entry of package `name`, `size` its package size field.
fn entry(name: &str, size: &str) -> String {
    format!(
        r#"{{"name":"{name}","version":"1.0.0","repository":"shirudo/pkg","manifest_digest":"{DIGEST}","package_digest":"{DIGEST}"{size}}}"#
    )
}

/// facade::index_parse() of an index of `entries`: their count or the
/// error.
fn index_of(entries: &[String]) -> Result<usize, core::ffi::c_int> {
    let text = format!(r#"{{"schema":1,"packages":[{}]}}"#, entries.join(","));
    facade::index_parse(text.as_bytes()).map(|e| e.len())
}

/// Every entry carries the size of its package, which the target holds
/// the download to: the first one may not leave it out any more than the
/// others.
#[test]
fn index_entry_needs_its_package_size() {
    let sized = |name, size| entry(name, &format!(r#","package_size":{size}"#));

    assert_eq!(index_of(&[sized("a", "10"), sized("b", "20")]), Ok(2));
    assert_eq!(index_of(&[entry("a", "")]), Err(-EINVAL));
    assert_eq!(index_of(&[sized("a", "10"), entry("b", "")]), Err(-EINVAL));
    assert_eq!(index_of(&[sized("a", "null")]), Err(-EINVAL));
    assert_eq!(index_of(&[sized("a", "0")]), Err(-EINVAL));
}

/// One rule for every member: an archive rooted at ./ unpacked, while
/// the member readers, which want <name>-<version>/<member>, found none.
#[test]
fn archive_path_has_no_dot_component() {
    for good in ["t-1.0.0/", "t-1.0.0/Beefile", "t-1.0.0/a/.b"] {
        assert!(archive_rel_ok(good.as_bytes()), "{good}");
    }
    for bad in [
        "",
        "/t-1.0.0/Beefile",
        "./",
        "./Beefile",
        "t-1.0.0/./Beefile",
        "t-1.0.0/../Beefile",
        "t-1.0.0//Beefile",
    ] {
        assert!(!archive_rel_ok(bad.as_bytes()), "{bad}");
    }
}

/// The precedence example of SemVer 2.0.0, 11.4, and build metadata.
#[test]
fn semver_follows_its_precedence() {
    let order = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0-rc.2+x",
        "1.0.0-rc.10",
        "1.0.0",
        "1.2.3",
        "1.10.0",
    ];

    for (i, a) in order.iter().enumerate() {
        for (j, b) in order.iter().enumerate() {
            assert_eq!(
                semver_compare(a.as_bytes(), b.as_bytes()),
                (i.cmp(&j) as i8).into(),
                "{a} {b}"
            );
        }
    }
    assert_eq!(semver_compare(b"1.0.0-rc.1+b2", b"1.0.0-rc.1+b1"), 0);
    assert_eq!(semver_compare(b"1.0.0+b2", b"1.0.0"), 0);
}

/// Versions SemVer does not describe sort below those it does and by
/// their bytes among themselves: the order is total over all of them.
#[test]
fn version_order_is_total() {
    let v: [&[u8]; 16] = [
        b"1.",
        b"1.2.3-rc.1",
        b"01.10.0",
        b"1.2",
        b"01.2.0",
        b"1.2.0-rc",
        b"1.2.3.4",
        b"1.2.3.5",
        b"1.0.0foo",
        b"1.0.0",
        b"1.0.0-rc.01",
        b"1.0.0-rc.1",
        b"0.9.0+build.5",
        b"2.0.0-0.3.7",
        b"1_0",
        b"9",
    ];

    assert_eq!(semver_compare(b"1.2.3.5", b"1.2.3.4"), 1);
    assert_eq!(semver_compare(b"01.0.0", b"0.0.1"), -1);
    assert_eq!(semver_compare(b"1.0.0-rc.01", b"1.0.0-rc.1"), -1);
    for a in v {
        for b in v {
            let ab = semver_compare(a, b);
            assert_eq!(ab, -semver_compare(b, a));
            for c in v {
                if ab <= 0 && semver_compare(b, c) <= 0 {
                    assert!(semver_compare(a, c) <= 0);
                }
            }
        }
    }
}

#[test]
fn semver_valid_is_semver_alone() {
    for good in [
        "0.0.0",
        "1.2.3",
        "1.0.0-rc.1",
        "1.0.0-0.3.7",
        "1.0.0-x-y.z",
        "1.0.0+build.5",
        "1.0.0-alpha+001",
        "18446744073709551615.0.0",
    ] {
        assert!(semver::valid(good.as_bytes()), "{good}");
    }
    for bad in [
        "",
        "1",
        "1.2",
        "1.2.3.4",
        "01.0.0",
        "1.02.0",
        "1.0.0foo",
        "1.0.0-",
        "1.0.0-rc..1",
        "1.0.0-rc.01",
        "1.0.0+",
        "1.0.0+a..b",
        "1.0.0_rc",
        "v1.0.0",
        "1.0.0-rc.1+b_1",
        "18446744073709551616.0.0",
    ] {
        assert!(!semver::valid(bad.as_bytes()), "{bad}");
    }
}

/// Install took any name holding .upatch for a load while uninstall went
/// by the suffix, so x.upatch.bak was loaded and never unloaded.
#[test]
fn upatch_member_goes_by_suffix() {
    let mut out = [0u8; 32];

    assert!(upatch_member(b"x.upatch") == UpatchMember::Load);
    assert!(upatch_member(b"unload.upatch") == UpatchMember::Load);
    assert!(upatch_member(b"x.unload.upatch") == UpatchMember::Unload);
    for other in [
        &b"x.upatch.bak"[..],
        b"x.upatchy",
        b"x.unload.upatch.x",
        b".x.upatch",
        b".upatch",
        b"upatch",
        b"",
        b"x.upatch\0x.upatch",
    ] {
        assert!(upatch_member(other) == UpatchMember::Other, "{other:?}");
    }
    assert_eq!(upatch_pair(b"x.upatch", &mut out), 0);
    assert_eq!(cstr(&out), b"x.unload.upatch");
    assert_eq!(upatch_pair(b"x.unload.upatch", &mut out), 0);
    assert_eq!(cstr(&out), b"x.upatch");
    assert_eq!(upatch_pair(b"x.upatch.bak", &mut out), -EINVAL);
    assert_eq!(upatch_pair(b"x.upatch", &mut out[..15]), -ENAMETOOLONG);
    assert_eq!(upatch_pair(b"x.upatch", &mut out[..16]), 0);
}

#[test]
fn tree_manifest_is_the_publisher_form() {
    let payload = Descriptor::of(
        crate::util::bpm_oci::TREE_MEDIA,
        b"sha256:1111111111111111111111111111111111111111111111111111111111111111",
        123,
    );
    let sig = Descriptor::of(
        crate::util::bpm_oci::TREE_SIG_MEDIA,
        b"sha256:2222222222222222222222222222222222222222222222222222222222222222",
        45,
    );

    assert_eq!(
        tree_manifest(&payload, &sig).unwrap(),
        concat!(
            r#"{"schemaVersion":2,"#,
            r#""mediaType":"application/vnd.oci.image.manifest.v1+json","#,
            r#""artifactType":"application/vnd.shirudo.upatch.tree.v1","#,
            r#""config":{"mediaType":"application/vnd.oci.empty.v1+json","#,
            r#""digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","#,
            r#""size":2},"#,
            r#""layers":[{"mediaType":"application/vnd.shirudo.upatch.tree.v1+json","#,
            r#""digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","#,
            r#""size":123},"#,
            r#"{"mediaType":"application/vnd.shirudo.upatch.tree.signature.v1","#,
            r#""digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","#,
            r#""size":45}]}"#
        )
        .as_bytes()
    );
}

use crate::testutil::TempDir;
use std::fs::{self, File};
use std::os::fd::AsFd;
use std::os::unix::fs::symlink;

fn extract_members(members: &[test_archive::Member<'_>], dir: &TempDir) -> i32 {
    fs::write(dir.join("archive.bee"), test_archive::archive(members)).unwrap();
    fs::create_dir(dir.join("out")).unwrap();
    let archive = File::open(dir.join("archive.bee")).unwrap();
    let out = File::open(dir.join("out")).unwrap();
    extract_fd(archive.as_fd(), out.as_fd())
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn extract_from_open_archive_stays_below_open_directory() {
    let dir = TempDir::new();
    let members: &[test_archive::Member<'_>] = &[
        ("pkg/", b'5', b""),
        ("pkg/Beefile", b'0', b"name"),
        ("pkg/upatches/", b'5', b""),
        ("pkg/upatches/a.upatch", b'0', b"a"),
        ("pkg/doc/deep/notes", b'0', b"n"),
    ];
    assert_eq!(extract_members(members, &dir), 0);
    assert_eq!(fs::read(dir.join("out/Beefile")).unwrap(), b"name");
    assert_eq!(fs::read(dir.join("out/doc/deep/notes")).unwrap(), b"n");
    assert!(!dir.join("out/pkg").exists());
    let archive = File::open(dir.join("archive.bee")).unwrap();
    let out = File::open(dir.join("out")).unwrap();
    assert_eq!(
        extract_fd(archive.as_fd(), out.as_fd()),
        -crate::errno::EEXIST
    );
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn extract_rejects_links_and_second_tree() {
    for (members, expected) in [
        (
            &[("pkg/", b'5', &b""[..]), ("pkg/link", b'2', b"")][..],
            -crate::errno::EPERM,
        ),
        (
            &[("pkg/a", b'0', &b"a"[..]), ("other/b", b'0', b"b")][..],
            -crate::errno::EINVAL,
        ),
        (&[("pkg/../b", b'0', &b"b"[..])][..], -crate::errno::EINVAL),
    ] {
        let dir = TempDir::new();
        assert_eq!(extract_members(members, &dir), expected);
        assert!(!dir.join("out/b").exists());
    }
}

#[test]
#[cfg_attr(miri, ignore = "openat2 is unavailable in Miri")]
fn extract_rejects_a_symlink_in_destination() {
    let dir = TempDir::new();
    fs::write(
        dir.join("archive.bee"),
        test_archive::archive(&[("pkg/upatches/a.upatch", b'0', b"a")]),
    )
    .unwrap();
    fs::create_dir(dir.join("out")).unwrap();
    fs::create_dir(dir.join("elsewhere")).unwrap();
    symlink(dir.join("elsewhere"), dir.join("out/upatches")).unwrap();
    let archive = File::open(dir.join("archive.bee")).unwrap();
    let out = File::open(dir.join("out")).unwrap();
    assert_eq!(
        extract_fd(archive.as_fd(), out.as_fd()),
        -crate::errno::ELOOP
    );
    assert!(
        fs::read_dir(dir.join("elsewhere"))
            .unwrap()
            .next()
            .is_none()
    );
}
