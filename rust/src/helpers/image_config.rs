// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-image-config: a config image's bootstrap file, or the config an
//! image root gives, read as shirudo reads them.
//!
//!   test-image-config bootstrap <initial> [<runtime>]
//!   test-image-config validate|effective <image root>
//!   test-image-config relative <image root> <path>

use core::ffi::{CStr, c_int};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;

use super::{helper_main, out};
use crate::errno::{EINVAL, EIO};
use crate::text::cstr;
use crate::util::config::{Config, load_path};
use crate::util::image_bootstrap::{self, ImageBootstrap};
use crate::util::image_config::{self, REGISTRIES, get, open, open_relative, validate};

helper_main!(shirudo_helper_test_image_config, run);

fn text(field: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(cstr(field))
}

fn read_bootstrap(args: &[&CStr]) -> c_int {
    let mut boot: Box<ImageBootstrap> = Box::new(ImageBootstrap::empty());
    let mut ret = image_bootstrap::read(args[2], &mut boot, true)
        .err()
        .unwrap_or(0);
    if ret == 0
        && let Some(runtime) = args.get(3)
    {
        ret = image_bootstrap::read(runtime, &mut boot, false)
            .err()
            .unwrap_or(0);
    }
    if ret == 0 {
        let root = crate::util::hex::encode(&boot.runtime_root);
        out(&format!(
            "runtime={}\nroot={}\nconfig={}\npcr={}\ncertificates={}\n",
            text(&boot.runtime),
            String::from_utf8_lossy(&root),
            text(&boot.config),
            boot.pcr,
            boot.n_certificates
        ));
        for cert in &boot.certificates[..boot.n_certificates] {
            out(&format!("certificate={}\n", text(cert)));
        }
    }
    out(&format!("rc={ret}\n"));
    c_int::from(ret != 0)
}

/// Opened `fd`, printed as `what=open`, or -errno.
fn opened(fd: c_int, what: &str) -> c_int {
    if fd < 0 {
        return fd;
    }
    // SAFETY: the descriptor just opened, owned and closed here.
    drop(unsafe { OwnedFd::from_raw_fd(fd) });
    out(&format!("{what}\n"));
    0
}

fn effective() -> c_int {
    let mut cfg = Box::new(Config::zeroed());
    if get(&mut cfg) == 0 {
        return -EIO;
    }
    out(&format!(
        "owner={}\ntcti={}\nlimit={}\n",
        String::from_utf8_lossy(&cfg.tpm_owner_auth[..cfg.tpm_owner_auth_len]),
        text(&cfg.tpm_tcti),
        cfg.eventlog_max_bytes
    ));
    let fd = open(REGISTRIES, libc::O_RDONLY | libc::O_DIRECTORY);
    if opened(fd, "registries=open") != 0 {
        out("registries=missing\n");
    }
    0
}

fn with_image(args: &[&CStr], root: c_int) -> c_int {
    let mut bootstrap = Box::new(Config::zeroed());
    let ret = load_path(&mut bootstrap, c"/dev/null");
    if ret != 0 {
        return ret;
    }
    bootstrap.tpm_owner_auth[..15].copy_from_slice(b"bootstrap-owner");
    bootstrap.tpm_owner_auth_len = 15;
    let _ = crate::text::strscpy(&mut bootstrap.tpm_tcti, b"bootstrap-tcti");
    let set = || image_config::set(&bootstrap, root);
    match (args[1].to_bytes(), args.get(3)) {
        (b"validate", _) => validate(root),
        (b"effective", _) => match set() {
            0 => effective(),
            err => err,
        },
        (b"relative", Some(path)) => match set() {
            0 => opened(open_relative(path, libc::O_RDONLY), "resolved=open"),
            err => err,
        },
        _ => -EINVAL,
    }
}

fn run(args: &[&CStr]) -> c_int {
    if !(3..=4).contains(&args.len()) {
        return 2;
    }
    if args[1].to_bytes() == b"bootstrap" {
        return read_bootstrap(args);
    }
    let Ok(root) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(std::ffi::OsStr::from_bytes(args[2].to_bytes()))
    else {
        return 1;
    };
    let ret = with_image(args, root.as_raw_fd());
    image_config::clear();
    drop(root);
    out(&format!("rc={ret}\n"));
    c_int::from(ret != 0)
}
