// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::errno::EINVAL;

const HEX64: &str = "00112233445566778899aabbccddeeffFFEEDDCCBBAA99887766554433221100";
const HEX64_LOWER: &str = "00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100";

#[test]
fn encode_is_lower_case() {
    assert_eq!(
        encode(&[0x00, 0x0a, 0xde, 0xad, 0xbe, 0xff]),
        b"000adeadbeff"
    );
}

#[test]
fn decode_takes_either_case() {
    let mut out = [0u8; 3];

    decode(b"0aFf", &mut out[..2]).unwrap();
    assert_eq!(out[..2], [0x0a, 0xff]);
    decode(b"DEadBE", &mut out).unwrap();
    assert_eq!(out, [0xde, 0xad, 0xbe]);
}

#[test]
fn decode_wants_the_exact_length() {
    let mut out = [0u8; 1];

    assert_eq!(decode(b"abc", &mut out), Err(-EINVAL));
    assert_eq!(decode(b"abcd", &mut out), Err(-EINVAL));
}

#[test]
fn decode_refuses_non_hex() {
    assert_eq!(decode(b"zz", &mut [0u8; 1]), Err(-EINVAL));
}

#[test]
fn decode_max_of_a_slice_fills_the_start() {
    let mut out = [0u8; 3];

    assert_eq!(decode_max(b"", &mut out), Ok(0));
    assert_eq!(decode_max(b"aB", &mut out), Ok(1));
    assert_eq!(out[0], 0xab);
    assert_eq!(decode_max(b"00ff10", &mut out), Ok(3));
    assert_eq!(out, [0x00, 0xff, 0x10]);
    for bad in [&b"abc"[..], b"00ff1022", b"0g"] {
        assert_eq!(decode_max(bad, &mut out), Err(-EINVAL), "{bad:?}");
    }
}

#[test]
fn sha256_digest_is_prefix_and_64_digits() {
    let text = format!("sha256:{HEX64}");
    let digest = decode_sha256_digest(text.as_bytes());
    let expected = digest.expect("valid digest");
    assert_eq!(
        (expected[0], expected[1], expected[16], expected[31]),
        (0x00, 0x11, 0xff, 0x00)
    );
    for bad in [
        HEX64.to_string(),
        format!("sha512:{HEX64}"),
        format!("SHA256:{HEX64}"),
        format!("sha256:{HEX64}0"),
        "sha256:".to_string(),
        format!("sha256:g{}", &HEX64[1..]),
    ] {
        assert_eq!(decode_sha256_digest(bad.as_bytes()), Err(-EINVAL), "{bad}");
    }
}

/// The digest written reads back, in lowercase whatever case it came in.
#[test]
fn sha256_digest_encodes_in_lowercase() {
    let original = format!("sha256:{HEX64}");
    let digest = decode_sha256_digest(original.as_bytes()).expect("valid digest");
    let text = sha256_digest_encode(&digest);
    assert_eq!(&text[..71], format!("sha256:{HEX64_LOWER}").as_bytes());
    assert_eq!(text[71], 0);
    let lower = format!("sha256:{HEX64_LOWER}");
    let back = decode_sha256_digest(lower.as_bytes()).expect("lowercase digest");
    assert_eq!(back, digest);
}
