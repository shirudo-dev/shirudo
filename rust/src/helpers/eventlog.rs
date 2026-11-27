// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-eventlog: the eventlog's pending record driven, with the log and
//! the pending file where SHIRUDO_EVENTLOG_PATH and
//! SHIRUDO_EVENTLOG_PENDING_PATH say, and what a shell test asserts on
//! printed.
//!
//!   test-eventlog init log|pending <bound_in> [<reset count>]
//!   test-eventlog boot-init|lines|adopt

use core::ffi::{CStr, c_int};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use super::{err, helper_main, out};
use crate::text::cstr;
use crate::util::chain::{PCR, PHASE_PCR};
use crate::util::eventlog::{
    EventlogInit, NV_INDEX, adopt_pending_locked, append_to, boot_init, boot_lines, path,
    pending_path, read_boot_id, timestamp,
};
use crate::util::hex::encode;
use crate::util::json::JsonEmit;

helper_main!(shirudo_helper_test_eventlog, run);

/// The sizes of an NV index's writer's RSA modulus and of a TPM name.
const NV_RSA_BYTES: usize = 384;
const NAME_LEN: usize = 34;

/// An init record of this boot with fixed values, bound where told,
/// appended to `log`.
fn append_init(log: &CStr, bound_in: &[u8], reset_count: u32) -> c_int {
    let mut modulus = [0u8; NV_RSA_BYTES];
    modulus[0] = 0x80;
    modulus[NV_RSA_BYTES - 1] = 1;
    let (mut ts, mut boot_id) = ([0u8; 32], [0u8; 64]);
    timestamp(&mut ts);
    read_boot_id(&mut boot_id);
    let zero = encode(&[0; 32]);
    let name = encode(&[0; NAME_LEN]);
    let nv_index = format!("0x{NV_INDEX:08X}");

    let mut buf = [0u8; 4096];
    let mut e = JsonEmit::fixed(&mut buf);
    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_string(b"ts", cstr(&ts));
    e.kv_string(b"nv_index", nv_index.as_bytes());
    e.kv_string(b"alg", b"sha256");
    e.kv_string(b"digest", &zero);
    e.kv_string(b"type", b"init");
    e.kv_string(b"boot_id", cstr(&boot_id));
    e.kv_int(b"tpm_reset_count", i64::from(reset_count));
    e.kv_int(b"pcr", i64::from(PCR));
    e.kv_string(b"pcr_before", &zero);
    e.kv_int(b"phase_pcr", i64::from(PHASE_PCR));
    e.kv_string(b"phase_before", &zero);
    e.kv_string(b"bound_in", bound_in);
    e.kv_string(b"nv_name", &name);
    e.kv_string(b"nv_writer_public", &encode(&modulus));
    e.kv_string(b"anchor", b"shirudo-anchor:test");
    e.kv_string(b"anchor_digest", &zero);
    e.kv_string(b"chain", &zero);
    e.obj_close();
    if e.err() != 0 {
        return e.err();
    }
    match CStr::from_bytes_until_nul(&buf) {
        Ok(line) => append_to(log, line.to_bytes()),
        Err(_) => -crate::errno::E2BIG,
    }
}

fn run(args: &[&CStr]) -> c_int {
    let word = |i: usize| args.get(i).map(|a| a.to_bytes());
    match (word(1), args.len()) {
        (Some(b"init"), 4 | 5) => {
            let log = if word(2) == Some(b"pending") {
                pending_path()
            } else {
                path()
            };
            // As strtoul(), which the C helper called: 0 for none.
            let reset = word(4).map_or(1, |r| {
                let digits = r.iter().take_while(|c| c.is_ascii_digit()).count();
                std::str::from_utf8(&r[..digits])
                    .ok()
                    .and_then(|d| d.parse::<u64>().ok())
                    .unwrap_or(0) as u32
            });
            let ret = append_init(log, args[3].to_bytes(), reset);
            out(&format!("rc={ret}\n"));
            c_int::from(ret != 0)
        }
        (Some(b"boot-init"), _) => {
            let mut rec: EventlogInit = EventlogInit::zeroed();
            let ret = boot_init(&mut rec);
            out(&format!("rc={ret}\n"));
            if ret != 0 {
                return 1;
            }
            out(&format!(
                "bound_in={}\nrecords={}\nreset_count={}\n",
                if rec.initrd { "initrd" } else { "root" },
                rec.records,
                rec.reset_count
            ));
            0
        }
        (Some(b"lines"), _) => {
            let mut n = 0u32;
            let ret = boot_lines(&mut |_| {
                n += 1;
                0
            });
            out(&format!("rc={ret}\nlines={n}\n"));
            c_int::from(ret != 0)
        }
        (Some(b"adopt"), _) => {
            let ret = adopt_pending_locked();
            let pending =
                std::path::Path::new(OsStr::from_bytes(pending_path().to_bytes())).exists();
            out(&format!(
                "rc={ret}\npending={}\n",
                if pending { "present" } else { "absent" }
            ));
            c_int::from(ret != 0)
        }
        (None, _) => {
            let me = args
                .first()
                .map_or("test-eventlog".into(), |a| a.to_string_lossy());
            err(&format!(
                "usage: {me} init log|pending <bound_in> [reset] | boot-init | lines | adopt\n"
            ));
            2
        }
        _ => {
            err("unknown subcommand\n");
            2
        }
    }
}
