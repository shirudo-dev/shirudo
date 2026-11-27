// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::{key_file_into, key_file_size};
use crate::errno::EINVAL;

#[kani::proof]
fn paths_key_file() {
    let dir: [u8; 2] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= dir.len());
    let file = b"f";
    let actual_size = key_file_size(&dir[..len], file);
    if len == 0 || dir[..len].contains(&0) {
        assert_eq!(actual_size, Err(-EINVAL));
    } else {
        let separator = usize::from(dir[len - 1] != b'/');
        let size = len + separator + file.len();
        assert_eq!(actual_size, Ok(size));
        let mut out = [0u8; 4];
        assert_eq!(key_file_into(&dir[..len], file, &mut out[..size]), Ok(()));
        assert_eq!(&out[..len], &dir[..len]);
        if separator != 0 {
            assert_eq!(out[len], b'/');
        }
        assert_eq!(out[size - 1], b'f');
    }
}

#[kani::proof]
fn paths_key_file_parts() {
    let dir: [u8; 2] = kani::any();
    let file: [u8; 2] = kani::any();
    let dir_len: usize = kani::any();
    let file_len: usize = kani::any();
    let capacity: usize = kani::any();
    kani::assume(dir_len <= 2 && file_len <= 2 && capacity <= 6);
    kani::assume(!file[..file_len].contains(&0));
    let dir = &dir[..dir_len];
    let file = &file[..file_len];
    let mut out: [u8; 6] = kani::any();
    let before = out;
    let result = key_file_into(dir, file, &mut out[..capacity]);
    if dir.is_empty() || dir.contains(&0) {
        assert_eq!(result, Err(-EINVAL));
        assert_eq!(out, before);
    } else {
        let separator = usize::from(!dir.ends_with(b"/"));
        let size = dir_len + separator + file_len;
        assert_eq!(key_file_size(dir, file), Ok(size));
        if capacity == size {
            assert_eq!(result, Ok(()));
            assert_eq!(&out[..dir_len], dir);
            if separator != 0 {
                assert_eq!(out[dir_len], b'/');
            }
            assert_eq!(&out[dir_len + separator..size], file);
            assert_eq!(&out[size..], &before[size..]);
        } else {
            assert_eq!(result, Err(-EINVAL));
            assert_eq!(out, before);
        }
    }
}
