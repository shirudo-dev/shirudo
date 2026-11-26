// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Small gzip ustar archives for the package reader and installer tests.

/// One archive member: its name, ustar type and file bytes.
pub(crate) type Member<'a> = (&'a str, u8, &'a [u8]);

pub(crate) fn archive(members: &[Member<'_>]) -> Vec<u8> {
    let mut tar = Vec::new();
    for &(name, kind, body) in members {
        assert!(name.len() < 100);
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(format!("{:07o}\0", 0o644).as_bytes());
        h[124..136].copy_from_slice(format!("{:011o}\0", body.len()).as_bytes());
        h[148..156].fill(b' ');
        h[156] = kind;
        h[257..263].copy_from_slice(b"ustar\0");
        let sum: u32 = h.iter().map(|&byte| u32::from(byte)).sum();
        h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        tar.extend_from_slice(&h);
        tar.extend_from_slice(body);
        tar.resize(tar.len().next_multiple_of(512), 0);
    }
    tar.extend_from_slice(&[0; 1024]);
    crate::util::gzip::gzip(&tar).unwrap()
}
