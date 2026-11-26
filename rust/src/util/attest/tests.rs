// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;

#[test]
fn pcrs_are_a_list_up_to_23() {
    assert_eq!(parse_pcrs(b"0"), Ok(1));
    assert_eq!(parse_pcrs(b"0,9,23"), Ok(1 | 1 << 9 | 1 << 23));
    assert_eq!(parse_pcrs(b"9,9"), Ok(1 << 9));
    for bad in [
        &b""[..],
        b"24",
        b"1,,2",
        b",1",
        b"1,",
        b"1,2,",
        b"1 ",
        b"+1",
        b"0x1",
    ] {
        assert_eq!(parse_pcrs(bad), Err(-EINVAL), "{bad:?}");
    }
}

#[test]
fn pcr_value_is_a_pcr_and_an_equals() {
    assert_eq!(parse_pcr_value(b"15=ab"), Ok((15, &b"ab"[..])));
    assert_eq!(parse_pcr_value(b"0="), Ok((0, &b""[..])));
    for bad in [&b"24=ab"[..], b"=ab", b"15", b"1 5=ab"] {
        assert_eq!(parse_pcr_value(bad), Err(-EINVAL), "{bad:?}");
    }
}

const D64: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// parse_name_digest() of `spec`: the name and the digest, or the error.
fn name_digest(spec: &str) -> Result<(Vec<u8>, [u8; 32]), c_int> {
    parse_name_digest(spec.as_bytes()).map(|(name, digest)| (name.to_vec(), digest))
}

#[test]
fn name_digest_is_a_name_and_64_digits() {
    let (name, digest) = name_digest(&format!("fix={D64}")).unwrap();
    assert_eq!((name.as_slice(), digest[1]), (&b"fix"[..], 0x11));
    assert_eq!(name_digest(&format!("a:b={D64}")).unwrap().0, b"a:b");
    for bad in [
        format!("={D64}"),
        format!("fix{D64}"),
        format!("fix={D64}0"),
        format!("fix=={D64}"),
    ] {
        assert_eq!(name_digest(&bad), Err(-EINVAL), "{bad}");
    }
    let longest = "n".repeat(UPATCH_NAME_MAX);
    assert_eq!(
        name_digest(&format!("{longest}={D64}")).unwrap().0.len(),
        UPATCH_NAME_MAX
    );
    assert_eq!(name_digest(&format!("{longest}n={D64}")), Err(-EINVAL));
}

#[test]
fn report_lines_are_a_tag_the_text_and_a_line_feed() {
    let mut rep = Report::new(64);

    rep.check(true, b"abc");
    rep.check(false, b"def");
    rep.note(b"ghi");
    assert_eq!(rep.text(), b"  OK    abc\n  FAIL  def\n  NOTE  ghi\n");
    assert_eq!(rep.failed, 1);
}

#[test]
fn report_is_bounded_as_the_c_buffer_was() {
    // A text that does not fit with a line feed and NUL is left out.
    let mut rep = Report::new(24);
    rep.check(false, b"x");
    rep.note(b"too long a text");
    assert_eq!(rep.text(), b"  FAIL  x\n  NOTE  \n");
    // No line once a tag, line feed and NUL would not fit, though the
    // failure still counts.
    rep.check(false, b"y");
    assert_eq!(rep.text(), b"  FAIL  x\n  NOTE  \n");
    assert_eq!(rep.failed, 2);

    // The final line ends with a line feed even at the cap.
    let mut rep = Report::new(12);
    rep.check(true, b"abc");
    rep.note(b"d");
    assert_eq!(rep.text(), b"  OK    \n");

    let mut rep = Report::new(0);
    rep.check(true, b"abc");
    assert_eq!(rep.text(), b"");
}

#[test]
fn every_bounded_report_line_ends_with_a_line_feed() {
    for cap in 0..=128 {
        let mut rep = Report::new(cap);
        rep.check(true, b"a moderately long check");
        rep.note(b"a second line");
        rep.check(false, b"one more check");
        assert!(rep.text().len() < cap || cap == 0, "cap={cap}");
        assert!(
            rep.text().is_empty() || rep.text().ends_with(b"\n"),
            "cap={cap}"
        );
        assert_eq!(rep.failed, 1);
    }
}

#[test]
fn record_without_own_digest_is_rejected() {
    let valid = format!(
        r#"{{"nonce":"","pcr_mask":1,"pcrs":[],"ak":{{}},"quote":{{"attest":"00","signature":"00"}},"register":{{"attest":"00","signature":"00","after_attest":"00","after_signature":"00"}},"eventlog":[{{"type":"other","digest":"{D64}"}}]}}"#
    );
    let missing = format!(
        r#"{{"nonce":"","pcr_mask":1,"pcrs":[],"ak":{{}},"quote":{{"attest":"00","signature":"00"}},"register":{{"attest":"00","signature":"00","after_attest":"00","after_signature":"00"}},"eventlog":[{{"type":"other","digest":"{D64}"}},{{"type":"other"}}]}}"#
    );
    assert!(parse_evidence(&mut Parse::new(), valid.as_bytes()).is_ok());
    assert_eq!(
        parse_evidence(&mut Parse::new(), missing.as_bytes()),
        Err(-EINVAL)
    );
}

#[test]
fn config_collection_keeps_pcr_history_across_restart_but_refuses_old_nvpcr_record() {
    use crate::util::config_measure::CONFIG_NVPCR_INDEX;

    let mut config = Evidence::default();
    config.present = true;
    config.reset_count = 7;
    config.restart_count = 3;
    config.pcr = 15;
    config.value = [0x42; 32];
    let mut quote = TpmAttest::zeroed();
    quote.reset_count = 7;
    quote.restart_count = 4;
    let mut values = [[0u8; 32]; 24];
    values[15] = config.value;

    assert!(quote_matches_config(&config, &quote, &values, false));
    quote.reset_count = 8;
    assert!(!quote_matches_config(&config, &quote, &values, false));
    quote.reset_count = 7;

    config.pcr = CONFIG_NVPCR_INDEX;
    assert!(quote_matches_config(&config, &quote, &values, true));
    let bytes = config.value;
    let mut certified = TpmAttest::zeroed();
    certified.reset_count = 7;
    certified.restart_count = 4;
    certified.nv_data = bytes.as_ptr();
    certified.nv_len = 32;
    assert!(!nvpcr_matches_config(&config, &certified, &bytes));
    certified.restart_count = 3;
    assert!(nvpcr_matches_config(&config, &certified, &bytes));
    certified.reset_count = 8;
    assert!(!nvpcr_matches_config(&config, &certified, &bytes));
}

#[test]
fn config_nvpcr_replay_input_needs_the_listed_name_and_full_value() {
    let name = [0x53; NAME_LEN];
    let mut signed = Signed {
        bytes: vec![0x42; 32],
        attest: TpmAttest::zeroed(),
        checked: true,
    };
    signed.attest.ty = ST_ATTEST_NV;
    signed.attest.index_name = name;
    signed.attest.index_name_len = NAME_LEN;
    signed.attest.nv_data = signed.bytes.as_ptr();
    signed.attest.nv_len = 32;
    assert_eq!(certified_nvpcr_value(&signed, &name), Some([0x42; 32]));
    assert_eq!(certified_nvpcr_value(&signed, &[0x54; NAME_LEN]), None);

    signed.attest.offset = 1;
    assert_eq!(certified_nvpcr_value(&signed, &name), None);
    signed.attest.offset = 0;
    signed.attest.nv_len = 33;
    assert_eq!(certified_nvpcr_value(&signed, &name), None);
    signed.attest.nv_len = 32;
    signed.attest.ty = ST_ATTEST_QUOTE;
    assert_eq!(certified_nvpcr_value(&signed, &name), None);
    signed.attest.ty = ST_ATTEST_NV;
    signed.checked = false;
    assert_eq!(certified_nvpcr_value(&signed, &name), None);
}

#[test]
fn config_nvpcr_evidence_requires_all_certification_fields() {
    let base =
        br#"{"nonce":"","pcr_mask":1,"pcrs":[],"ak":{},"quote":{"attest":"00","signature":"00"},"register":{"attest":"00","signature":"00","after_attest":"00","after_signature":"00"},"eventlog":[]}"#;
    let incomplete = br#"{"nonce":"","pcr_mask":1,"pcrs":[],"ak":{},"quote":{"attest":"00","signature":"00"},"register":{"attest":"00","signature":"00","after_attest":"00","after_signature":"00"},"eventlog":[],"config_nvpcr":{"name":"00","attest":"00"}}"#;
    let complete = br#"{"nonce":"","pcr_mask":1,"pcrs":[],"ak":{},"quote":{"attest":"00","signature":"00"},"register":{"attest":"00","signature":"00","after_attest":"00","after_signature":"00"},"eventlog":[],"config_nvpcr":{"name":"00","attest":"00","signature":"00","after_attest":"00","after_signature":"00"}}"#;

    assert_eq!(
        parse_evidence(&mut Parse::new(), base),
        Ok((false, false, false))
    );
    assert_eq!(parse_evidence(&mut Parse::new(), incomplete), Err(-EINVAL));
    assert_eq!(
        parse_evidence(&mut Parse::new(), complete),
        Ok((false, false, true))
    );
}
