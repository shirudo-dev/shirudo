// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-image-keys: an image's trust set validated, and with
//! certificates for the BPF keyring, a live config update made through
//! the journal with the TPM and the keyring stood in for.
//!
//!   test-image-keys <primary cert> <image root>
//!   test-image-keys <primary cert> <image root> <journal dir> <held cert>...
//!
//! SHIRUDO_TEST_IMAGE_INTERRUPT fails the live update's first activation.

use core::cell::RefCell;
use core::ffi::{CStr, c_int};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;

use super::{helper_main, out};
use crate::errno::EIO;
use crate::util::chain::fold;
use crate::util::config_update::{BootIdentity, ConfigUpdate, ConfigUpdateOps, ConfigUpdateTarget};
use crate::util::image_keys::{check_set_with, validate_set};
use crate::util::keys::{TrustedSet, read_der};

helper_main!(shirudo_helper_test_image_keys, run);

struct Context<'a> {
    set: &'a TrustedSet,
    /// The certificates the BPF keyring holds, as the command line names.
    held: &'a [&'a CStr],
    pcr: [u8; 32],
    extends: u32,
    activations: u32,
    live: bool,
    interrupt: bool,
}

/// Whether the keyring holds `der`: 1, 0, or -errno for a held
/// certificate that does not read.
fn holds(held: &[&CStr], der: &[u8]) -> c_int {
    for path in held {
        match read_der(path) {
            Ok(candidate) if candidate == der => return 1,
            Ok(_) => {}
            Err(e) => return e,
        }
    }
    0
}

/// A stand-in TPM of one boot, whose PCR `Context` keeps, and the BPF
/// keyring that holds the certificates the command line names.
impl ConfigUpdateOps for RefCell<Context<'_>> {
    fn boot_identity(&self) -> Result<BootIdentity, c_int> {
        Ok(BootIdentity {
            reset: 1,
            restart: 1,
        })
    }

    fn pcr_read(&self, _: u32) -> Result<[u8; 32], c_int> {
        Ok(self.borrow().pcr)
    }

    fn pcr_extend(&self, _: u32, event: &[u8; 32]) -> Result<(), c_int> {
        let mut c = self.borrow_mut();
        c.extends += 1;
        fold(&mut c.pcr, event)
    }

    fn prepare(&self, _: &ConfigUpdateTarget) -> Result<(), c_int> {
        let c = self.borrow();
        if !c.live {
            return Ok(());
        }
        match check_set_with(c.set, |der| holds(c.held, der)) {
            0 => Ok(()),
            err => Err(err),
        }
    }

    fn activate(&self, _: &ConfigUpdate<'_>, _: &ConfigUpdateTarget) -> Result<(), c_int> {
        let mut c = self.borrow_mut();
        c.activations += 1;
        if c.live && c.interrupt {
            c.interrupt = false;
            return Err(-EIO);
        }
        Ok(())
    }

    fn seal(&self, _: BorrowedFd<'_>) -> Result<(), c_int> {
        Ok(())
    }
}

fn target(prefix: &[u8], fill: u8) -> Box<ConfigUpdateTarget> {
    let mut t = Box::new(ConfigUpdateTarget::zeroed());
    t.prefix[..prefix.len()].copy_from_slice(prefix);
    t.root_hash = [fill; 32];
    t
}

/// A boot to /verified/boot, then a live update to /verified/live,
/// in the journal at `directory`.
fn live_update(directory: &CStr, set: &TrustedSet, held: &[&CStr]) -> c_int {
    let c = RefCell::new(Context {
        set,
        held,
        pcr: [0; 32],
        extends: 0,
        activations: 0,
        live: false,
        interrupt: false,
    });
    let mut journal = match ConfigUpdate::open(directory, &c, 0) {
        Ok(journal) => journal,
        Err(err) => return err,
    };
    let mut ret = journal.boot(&target(b"/verified/boot", 1), 15);
    if ret.is_ok() {
        ret = journal.complete_boot();
    }
    {
        let mut c = c.borrow_mut();
        c.live = true;
        c.interrupt = std::env::var_os("SHIRUDO_TEST_IMAGE_INTERRUPT").is_some();
        c.extends = 0;
        c.activations = 0;
    }
    if ret.is_ok() {
        ret = journal.begin(&target(b"/verified/live", 2), 15);
    }
    let c = c.borrow();
    out(&format!(
        "extends={} activations={}\n",
        c.extends, c.activations
    ));
    ret.err().unwrap_or(0)
}

fn run(args: &[&CStr]) -> c_int {
    if args.len() != 3 && args.len() < 5 {
        return 2;
    }
    let Ok(root) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(std::ffi::OsStr::from_bytes(args[2].to_bytes()))
    else {
        return 2;
    };
    let mut set = TrustedSet::default();
    let mut ret = validate_set(args[1], root.as_raw_fd(), &mut set);
    if ret == 0 && args.len() >= 5 {
        ret = live_update(args[3], &set, &args[4..]);
    }
    drop(root);
    out(&format!("rc={ret} signers={}\n", set.len()));
    c_int::from(ret != 0)
}
