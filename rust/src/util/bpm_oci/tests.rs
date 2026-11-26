// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::errno::EINVAL;

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const MEDIA: &str = r#""mediaType":"application/vnd.shirudo.upatch.v1""#;

/// parse_manifest() of a manifest with `layers`: its result and the
/// count of layers.
fn manifest_of(layers: &str) -> (core::ffi::c_int, core::ffi::c_int) {
    let mut descs = [const { Descriptor::new() }; 4];
    let text = format!(r#"{{"schemaVersion":2,"layers":[{layers}]}}"#);
    let mut n = -1;
    let ret = manifest::parse_manifest(text.as_bytes(), &mut descs[..4], &mut n, None);

    (ret, n)
}

/// The registry writes the manifest before anything is verified: a layer
/// without its digest or with a negative size would be fetched from an
/// empty URL or skip the size check.
#[test]
fn manifest_layer_is_a_whole_descriptor() {
    let layer = format!(r#"{{{MEDIA},"digest":"{DIGEST}","size":5}}"#);

    assert_eq!(manifest_of(&layer), (0, 1));
    for bad in [
        format!(r#"{{{MEDIA},"size":5}}"#),
        format!(r#"{{{MEDIA},"digest":"sha512:aa","size":5}}"#),
        format!(r#"{{{MEDIA},"digest":"{DIGEST}"}}"#),
        format!(r#"{{{MEDIA},"digest":"{DIGEST}","size":-5}}"#),
        format!(r#"{{"digest":"{DIGEST}","size":5}}"#),
        format!(r#"{layer},{{{MEDIA},"size":5}}"#),
    ] {
        assert_eq!(manifest_of(&bad).0, -EINVAL, "{bad}");
    }
}

#[test]
fn registry_auth_refuses_raw_nul() {
    let valid = br#"{"auths":{"registry.example":{"auth":"dXNlcjpwYXNz"}}}"#;
    let registry = br#""registry.example""#;
    let mut client = Client::new();

    assert_eq!(auth::auth_entry(valid, registry, client.as_mut()), 0);
    assert_eq!(cstr(&client.as_mut().username), b"user");
    assert_eq!(cstr(&client.as_mut().password), b"pass");
    for invalid in [&[b"\0", &valid[..]].concat(), &[&valid[..], b"\0"].concat()] {
        let mut client = Client::new();
        assert_eq!(
            auth::auth_entry(invalid, registry, client.as_mut()),
            -EINVAL
        );
        assert!(cstr(&client.as_mut().username).is_empty());
        assert!(cstr(&client.as_mut().password).is_empty());
    }
}

#[test]
fn bearer_token_is_a_member_of_the_answer() {
    let answers: &[(&[u8], &[u8])] = &[
        (br#"{"token":"granted"}"#, b"granted"),
        (
            br#" { "access_token" : "abc.def", "expires_in": 300 } "#,
            b"abc.def",
        ),
        (br#"{"access_token":"a","token":"t"}"#, b"t"),
        (br#"{"token":null,"access_token":"a"}"#, b"a"),
        (br#"{"note":"\"token\":\"note\"","token":"t"}"#, b"t"),
        (br#"{"note":"token","text":"note","token":"t"}"#, b"t"),
        (br#"{"data":{"token":"inner"},"token":"t"}"#, b"t"),
        (br#"{"data":[{"token":"inner"}],"access_token":"a"}"#, b"a"),
        (br#"{"token":"\u0041\/b"}"#, b"A/b"),
        (br#"{"token":"1234567"}"#, b"1234567"),
    ];

    for (body, want) in answers {
        let mut token = [0; 8];

        assert_eq!(auth::token_from_body(body, &mut token), Ok(()));
        assert_eq!(cstr(&token), *want);
    }
}

#[test]
fn bearer_token_refusal_preserves_output() {
    let invalid: &[&[u8]] = &[
        b"",
        br#"{"token":"a b"}"#,
        br#"{"token":"a\tb"}"#,
        b"{\"token\":\"a\x7f\"}",
        br#"{"token":"a\"b"}"#,
        br#"{"token":"a\\b"}"#,
        br#"{"token":"12345678"}"#,
        br#"{"token":42}"#,
        br#"{"token":"a","token":"b"}"#,
        br#"{"token":"a"} {"#,
        br#""token":"a""#,
        br#"{"data":{"token":"inner"}}"#,
        b"{\"token\":\"\xff\"}",
        b"{\"token\":\"\0\"}",
    ];

    for body in invalid {
        let mut token = *b"keep\0###";

        assert_eq!(auth::token_from_body(body, &mut token), Err(-EINVAL));
        assert_eq!(&token, b"keep\0###");
    }
}

#[test]
fn authentication_scheme_is_a_whole_token() {
    assert_eq!(auth::challenge_params(b"bAsIc", b"Basic"), Some(&b""[..]));
    assert_eq!(
        auth::challenge_params(b"Basic realm", b"Basic"),
        Some(&b" realm"[..])
    );
    assert_eq!(auth::challenge_params(b"Other", b"Basic"), None);
    assert_eq!(auth::challenge_params(b"BasicOther realm", b"Basic"), None);
    assert_eq!(
        auth::parse_challenge(b"BearerOther realm").err(),
        Some(-EINVAL)
    );

    let challenge = auth::parse_challenge(
        br#"bEaReR realm="https://registry.example/token",service="registry",scope="pull""#,
    )
    .unwrap();
    assert_eq!(challenge.realm, b"https://registry.example/token");
    assert_eq!(challenge.service, b"registry");
    assert_eq!(challenge.scope, b"pull");
}

#[test]
#[cfg_attr(miri, ignore = "libcurl URL parsing is a foreign call")]
fn registry_owns_the_auth_challenge() {
    let base = b"https://Registry.example";

    assert!(http::registry_origin(
        base,
        Some(b"https://registry.example:443/blob")
    ));
    for other in [
        &b"https://cdn.example/blob"[..],
        b"https://registry.example:444/blob",
        b"http://registry.example/blob",
        b"https://user@registry.example/blob",
    ] {
        assert!(!http::registry_origin(base, Some(other)));
    }
    assert!(!http::registry_origin(base, None));
    assert!(!http::registry_origin(
        b"https://[fe80::1%25eth0]",
        Some(b"https://[fe80::1%25eth1]/blob")
    ));
}

#[test]
fn new_response_clears_saved_headers() {
    let mut response = HttpResponse::new();
    http::header_line(&mut response, b"WWW-Authenticate: Basic realm=registry\r\n");
    http::header_line(&mut response, b"Location: /uploads/one\r\n");
    assert!(!cstr(&response.www_auth).is_empty());
    assert!(!cstr(&response.location).is_empty());
    http::header_line(&mut response, b"HTTP/2 401\r\n");
    assert!(cstr(&response.www_auth).is_empty());
    assert!(cstr(&response.location).is_empty());
}

#[test]
fn registry_headers_are_bounded_and_counted() {
    let mut response = HttpResponse::new();
    http::header_line(&mut response, b"Location: /uploads/one\r\n");
    http::header_line(&mut response, b"WWW-Authenticate: Basic realm\r\n");
    assert_eq!(cstr(&response.location), b"/uploads/one");
    assert_eq!(cstr(&response.www_auth), b"Basic realm\r\n");

    http::header_line(&mut response, b"Location: /uploads/\0two\r\n");
    http::header_line(&mut response, b"WWW-Authenticate: Bearer\0\r\n");
    assert_eq!(cstr(&response.location), b"/uploads/one");
    assert_eq!(cstr(&response.www_auth), b"Basic realm\r\n");

    let mut line = b"Location: ".to_vec();
    line.resize(4096, b'a');
    http::header_line(&mut response, &line);
    assert_eq!(cstr(&response.location), b"/uploads/one");
    http::header_line(&mut response, &line[..4095]);
    assert_eq!(cstr(&response.location), &line[10..4095]);

    let mut challenge = b"WWW-Authenticate: ".to_vec();
    challenge.resize(challenge.len() + response.www_auth.len(), b'a');
    http::header_line(&mut response, &challenge[..challenge.len() - 1]);
    assert_eq!(cstr(&response.www_auth).len(), response.www_auth.len() - 1);
    http::header_line(&mut response, &challenge);
    assert!(cstr(&response.www_auth).is_empty());
}
