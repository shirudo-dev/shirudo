// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-image: a config image's bootstrap file read, initial and
//! runtime, and its hash file's superblock.

use std::fs::File;
use std::os::fd::AsRawFd;

use crate::fuzzing::{fuzz_target, input_file};

fuzz_target!(shirudo_fuzz_image, shirudo_fuzz_image_init, |data| {
    let Some(input) = input_file(data) else {
        return;
    };
    let fd = input.fd.as_raw_fd();
    let mut boot: Box<super::ImageBootstrap> = Box::new(super::ImageBootstrap::empty());
    let _ = super::read_fd(fd, &mut boot, true);
    let _ = super::read_fd(fd, &mut boot, false);
    let _ = crate::util::config_image::read_header(&File::from(input.fd));
});
