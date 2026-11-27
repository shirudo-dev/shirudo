// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-eventlog: an event log replayed, its init record of this boot
//! found, and this boot's lines walked. The seed's boot ID is this
//! boot's, so that the records of the corpus count as this boot's.

use std::sync::OnceLock;

use super::records::{boot_init, boot_lines};
use super::{EventlogInit, read_boot_id};
use crate::fuzzing::{fuzz_target, input_file};
use crate::text::cstr;

const SEED_BOOT: &[u8] = b"00000000-0000-4000-8000-000000000000";

static BOOT: OnceLock<Vec<u8>> = OnceLock::new();

fn env(name: &str, value: &str) {
    // SAFETY: the environment, which the fuzzer's one thread alone
    // touches.
    unsafe { std::env::set_var(name, value) };
}

fn init() {
    let mut boot = [0u8; 64];
    read_boot_id(&mut boot);
    let boot = cstr(&boot).to_vec();
    if boot.len() != SEED_BOOT.len() {
        std::process::abort();
    }
    let _ = BOOT.set(boot);
    env("SHIRUDO_EVENTLOG_PENDING_PATH", "/nonexistent/eventlog");
}

fuzz_target!(
    shirudo_fuzz_eventlog,
    shirudo_fuzz_eventlog_init,
    |data| {
        let Some(boot) = BOOT.get() else {
            return;
        };
        let mut log = data.to_vec();
        let mut at = 0;
        while let Some(i) = log[at..]
            .windows(SEED_BOOT.len())
            .position(|w| w == SEED_BOOT)
        {
            log[at + i..at + i + SEED_BOOT.len()].copy_from_slice(boot);
            at += i + SEED_BOOT.len();
        }
        let Some(input) = input_file(&log) else {
            return;
        };
        env("SHIRUDO_EVENTLOG_PATH", &input.path.to_string_lossy());
        let mut root = [0u8; 32];
        let _ = super::replay(&mut root);
        let mut rec: EventlogInit = EventlogInit::zeroed();
        let _ = boot_init(&mut rec);
        let mut seen = 0usize;
        let _ = boot_lines(&mut |line| {
            seen += line.to_bytes().len();
            0
        });
    },
    init
);
