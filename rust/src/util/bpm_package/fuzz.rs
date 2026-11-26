// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-bpm-tar: the Beefile read from a package's gzip tar;
//! fuzz-bpm-index: a package index parsed, its versions in an order
//! install can pick the newest by; fuzz-bpm-package: a package's
//! identity read and its files extracted.

use std::os::fd::AsFd;
use std::path::PathBuf;
use std::sync::OnceLock;

use super::info::load_info;
use super::{PackageInfo, extract_fd, index_parse, read_member_in, semver_compare};
use crate::fuzzing::{fuzz_target, input_gzip_file};
use crate::heap::xfree;
use crate::text::cstr;

fuzz_target!(shirudo_fuzz_bpm_tar, shirudo_fuzz_bpm_tar_init, |data| {
    let Some(input) = input_gzip_file(data) else {
        return;
    };
    let mut dir = [0; 256];
    let _ = read_member_in(&input.path, b"Beefile", None, Some(&mut dir), 1 << 20);
});

fuzz_target!(
    shirudo_fuzz_bpm_index,
    shirudo_fuzz_bpm_index_init,
    |data| {
        let Ok(entries) = index_parse(data) else {
            return;
        };
        // install picks the newest version by this order: it must be one.
        for w in entries.windows(2) {
            let ab = semver_compare(cstr(&w[0].version), cstr(&w[1].version));
            let ba = semver_compare(cstr(&w[1].version), cstr(&w[0].version));
            if ab.signum() != -ba.signum() {
                std::process::abort();
            }
        }
    }
);

/// The directory the packages extract into, removed at exit.
static BASE: OnceLock<PathBuf> = OnceLock::new();

extern "C" fn remove_base() {
    if let Some(base) = BASE.get() {
        let _ = std::fs::remove_dir_all(base);
    }
}

fn package_init() {
    let mut template = *b"/tmp/shirudo-fuzz-bpm-package-XXXXXX\0";
    // SAFETY: a template mkdtemp() fills in place, and a handler of no
    // arguments.
    unsafe {
        if libc::mkdtemp(template.as_mut_ptr().cast()).is_null() || libc::atexit(remove_base) != 0 {
            std::process::abort();
        }
    }
    let base = String::from_utf8_lossy(cstr(&template)).into_owned();
    let _ = BASE.set(PathBuf::from(base));
}

fuzz_target!(
    shirudo_fuzz_bpm_package,
    shirudo_fuzz_bpm_package_init,
    |data| {
        let (Some(base), Some(input)) = (BASE.get(), input_gzip_file(data)) else {
            return;
        };
        let dest = base.join("pkg");
        // SAFETY: an identity of nothing, for which zeros are the value.
        let mut info: PackageInfo = unsafe { core::mem::zeroed() };
        if load_info(&input.path, &mut info) == 0 {
            // SAFETY: the certificate the read gave, freed once.
            unsafe { xfree(info.cert.cast(), info.cert_len + 1) };
        }
        if std::fs::create_dir(&dest).is_ok()
            && let Ok(dir) = std::fs::File::open(&dest)
        {
            extract_fd(input.fd.as_fd(), dir.as_fd());
        }
        if let Ok(entries) = std::fs::read_dir(base) {
            for e in entries.flatten() {
                let _ =
                    std::fs::remove_dir_all(e.path()).or_else(|_| std::fs::remove_file(e.path()));
            }
        }
    },
    package_init
);
