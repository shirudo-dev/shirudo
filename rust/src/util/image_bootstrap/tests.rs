// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::errno::{E2BIG, EINVAL};

fn parsed(text: &[u8], initial: bool) -> (c_int, Box<ImageBootstrap>) {
    let mut boot: Box<ImageBootstrap> = Box::new(ImageBootstrap::empty());
    let ret = parse(text, &mut boot, initial).err().unwrap_or(0);
    (ret, boot)
}

#[test]
fn takes_keys_past_comments_blanks_and_line_ends() {
    let root = "ab".repeat(32);
    let text = format!(
        "# a comment\n\n \t\nruntime.image = /run/shirudo/runtime.img\r\n\
         runtime.root_hash={root}\nconfig.image =\t/var/lib/shirudo/images/a\nother = ignored"
    );
    let (ret, boot) = parsed(text.as_bytes(), true);
    assert_eq!(ret, 0);
    assert_eq!(cstr(&boot.runtime), b"/run/shirudo/runtime.img");
    assert_eq!(cstr(&boot.config), b"/var/lib/shirudo/images/a");
    assert!(boot.have_root);
    assert_eq!(boot.runtime_root, [0xab; 32]);
}

#[test]
fn takes_the_last_line_without_its_newline() {
    let (ret, boot) = parsed(b"config.image = /a/b", false);
    assert_eq!(ret, 0);
    assert_eq!(cstr(&boot.config), b"/a/b");
}

#[test]
fn refuses_what_the_c_refused() {
    assert_eq!(parsed(b"config.image /a/b\n", false).0, -EINVAL);
    assert_eq!(parsed(b"config.image = /a\0b\n", false).0, -EINVAL);
    assert_eq!(parsed(b"config.unknown = 1\n", false).0, -EINVAL);
    assert_eq!(parsed(b"config.image = relative\n", false).0, -EINVAL);
    // The runtime image and its root are the initial read's alone.
    let root = format!("runtime.root_hash = {}\n", "00".repeat(32));
    assert_eq!(parsed(root.as_bytes(), false).0, -EINVAL);
    assert_eq!(parsed(b"runtime.image = /run/x\n", false).0, -EINVAL);
}

#[test]
fn a_line_past_its_limit_is_too_long() {
    let fits = format!("#{}\n", "x".repeat(PATH_MAX + 126));
    assert_eq!(parsed(fits.as_bytes(), false).0, 0);
    let long = format!("#{}\n", "x".repeat(PATH_MAX + 127));
    assert_eq!(parsed(long.as_bytes(), false).0, -E2BIG);
    // Without its newline as with it.
    assert_eq!(parsed(&long.as_bytes()[..long.len() - 1], false).0, -E2BIG);
}
