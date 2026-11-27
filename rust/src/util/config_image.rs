// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The config image: a data file, its
//! dm-verity hash tree behind the veritysetup superblock, its root hash,
//! and the signature of the root, opened and checked against each other.

use core::ffi::{CStr, c_int};
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, OpenOptionsExt};

use crate::errno::{EFBIG, EINVAL, EIO, EKEYREJECTED, ENAMETOOLONG};
use crate::sys::libc::Zeroed;
use crate::sys::libc::{
    AT_EMPTY_PATH, O_NOFOLLOW, O_NONBLOCK, PATH_MAX, S_IFMT, S_IFREG, STATX_SIZE, STATX_TYPE,
    Statx, errno, statx,
};
use crate::util::hex;

pub(crate) const BLOCK_SIZE: u64 = 4096;
const SALT_SIZE: usize = 32;
pub(crate) const SIG_MAX: u64 = 16384;
pub(crate) const MAX_BYTES: u64 = 1 << 40;
const DIGESTS_PER_BLOCK: u64 = BLOCK_SIZE / 32;
const SUPERBLOCK_SIZE: usize = 512;

/// `struct config_image`.
#[derive(Clone, Copy)]
pub struct ConfigImage {
    pub(crate) data_blocks: u64,
    pub(crate) hash_blocks: u64,
    pub(crate) signed_root: bool,
    pub(crate) salt: [u8; SALT_SIZE],
    pub(crate) root_hash: [u8; 32],
}

/// An image and its open parts, the signature only for a signed root.
pub struct ConfigImageOpen {
    pub(crate) image: ConfigImage,
    pub(crate) data: File,
    pub(crate) hash: File,
    pub(crate) signature: Option<File>,
}

impl ConfigImage {
    const fn zeroed() -> Self {
        ConfigImage {
            data_blocks: 0,
            hash_blocks: 0,
            signed_root: false,
            salt: [0; SALT_SIZE],
            root_hash: [0; 32],
        }
    }
}

impl ConfigImageOpen {
    /// The image at `prefix`, its `.img`, `.hash` and `.sig` opened and
    /// checked; with `expected_root`, signed for that root hash.
    pub(crate) fn open(prefix: &CStr, expected_root: Option<&[u8; 32]>) -> Result<Self, c_int> {
        if prefix.is_empty() {
            return Err(-EINVAL);
        }
        let (image, data, hash, signature) = open_parts(prefix.to_bytes(), expected_root)?;
        Ok(ConfigImageOpen {
            image,
            data,
            hash,
            signature,
        })
    }
}

/// The blocks of the hash tree over `data_blocks`: a level of digests per
/// block of the level below, up to one root block.
fn hash_blocks(mut data_blocks: u64) -> Result<u64, c_int> {
    let mut total = 1;

    if data_blocks == 0 || data_blocks > MAX_BYTES / BLOCK_SIZE {
        return Err(-EFBIG);
    }
    while data_blocks > 1 {
        data_blocks = data_blocks.div_ceil(DIGESTS_PER_BLOCK);
        total += data_blocks;
    }
    Ok(total)
}

/// The size of the regular file `file`.
fn regular_file_size(file: &File) -> Result<u64, c_int> {
    let mut st = Statx::zeroed();

    // SAFETY: an empty path with AT_EMPTY_PATH names the file's fd, and a
    // statx to fill.
    if unsafe {
        statx(
            file.as_raw_fd(),
            c"".as_ptr(),
            AT_EMPTY_PATH,
            STATX_TYPE | STATX_SIZE,
            &mut st,
        )
    } != 0
    {
        return Err(-errno());
    }
    if st.stx_mode & S_IFMT != S_IFREG {
        return Err(-EINVAL);
    }
    Ok(st.stx_size)
}

/// `buf.len()` bytes from the start of `file`; -EIO when it ends first.
fn read_exact_at_start(file: &File, buf: &mut [u8]) -> c_int {
    let mut done = 0;

    while done < buf.len() {
        match file.read_at(&mut buf[done..], done as u64) {
            Ok(0) => return -EIO,
            Ok(n) => done += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return -e.raw_os_error().unwrap_or(EIO),
        }
    }
    0
}

fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// A veritysetup superblock of version 1 and SHA-256 over 4096-byte
/// blocks with a 32-byte salt.
fn superblock_ok(h: &[u8; SUPERBLOCK_SIZE]) -> bool {
    let mut algorithm = [0u8; 32];

    algorithm[..6].copy_from_slice(b"sha256");
    &h[0..8] == b"verity\0\0"
        && le32(&h[8..]) == 1
        && le32(&h[12..]) == 1
        && h[32..64] == algorithm
        && le32(&h[64..]) == BLOCK_SIZE as u32
        && le32(&h[68..]) == BLOCK_SIZE as u32
        && le16(&h[80..]) == SALT_SIZE as u16
}

/// The image the superblock at the start of `hash` describes.
pub(crate) fn read_header(hash: &File) -> Result<ConfigImage, c_int> {
    let mut header = [0u8; SUPERBLOCK_SIZE];
    let mut image = ConfigImage::zeroed();

    let ret = read_exact_at_start(hash, &mut header);
    if ret != 0 {
        return Err(ret);
    }
    if !superblock_ok(&header) {
        return Err(-EINVAL);
    }
    image.data_blocks = le64(&header[72..]);
    image.hash_blocks = hash_blocks(image.data_blocks)?;
    image.salt.copy_from_slice(&header[88..88 + SALT_SIZE]);
    Ok(image)
}

/// Whether the data and hash files are the sizes `image` gives them.
pub(crate) fn check_files(data: &File, hash: &File, image: &ConfigImage) -> c_int {
    let blocks = match hash_blocks(image.data_blocks) {
        Ok(blocks) => blocks,
        Err(e) => return e,
    };
    if blocks != image.hash_blocks {
        return -EINVAL;
    }
    let sizes = regular_file_size(data).and_then(|d| Ok((d, regular_file_size(hash)?)));
    let (data_size, hash_size) = match sizes {
        Ok(sizes) => sizes,
        Err(e) => return e,
    };
    if data_size != image.data_blocks * BLOCK_SIZE || hash_size != image.hash_blocks * BLOCK_SIZE {
        return -EINVAL;
    }
    0
}

/// `<prefix><suffix>` opened for reading, not through a symbolic link.
fn open_part(prefix: &[u8], suffix: &[u8]) -> Result<File, c_int> {
    let path = [prefix, suffix].concat();

    if path.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(OsStr::from_bytes(&path))
        .map_err(|e| -e.raw_os_error().unwrap_or(EIO))
}

/// The root hash `<prefix>.roothash` holds, 64 lowercase hex digits.
fn read_root(prefix: &[u8], root: &mut [u8; 32]) -> c_int {
    let mut text = [0u8; 64];

    let file = match open_part(prefix, b".roothash") {
        Ok(file) => file,
        Err(e) => return e,
    };
    let mut ret = match regular_file_size(&file) {
        Ok(64) => 0,
        Ok(_) => -EINVAL,
        Err(e) => e,
    };
    if ret == 0 {
        ret = read_exact_at_start(&file, &mut text);
    }
    if ret != 0 {
        return ret;
    }
    if !text
        .iter()
        .all(|&c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return -EINVAL;
    }
    hex::decode(&text, root).map_or_else(|e| e, |()| 0)
}

/// The image at `prefix`, its parts open and checked against each other
/// and its root against `expected_root`, or else signed: the image, its
/// data and hash files, and its signature unless `expected_root` names
/// the root.
fn open_parts(
    prefix: &[u8],
    expected_root: Option<&[u8; 32]>,
) -> Result<(ConfigImage, File, File, Option<File>), c_int> {
    let data = open_part(prefix, b".img")?;
    let hash = open_part(prefix, b".verity")?;
    let mut header = read_header(&hash)?;
    let mut ret = read_root(prefix, &mut header.root_hash);
    if ret == 0 {
        ret = check_files(&data, &hash, &header);
    }
    if ret != 0 {
        return Err(ret);
    }
    if let Some(root) = expected_root {
        if *root != header.root_hash {
            return Err(-EKEYREJECTED);
        }
        return Ok((header, data, hash, None));
    }
    header.signed_root = true;
    let signature = open_part(prefix, b".p7s")?;
    match regular_file_size(&signature) {
        Ok(0) => Err(-EINVAL),
        Ok(size) if size > SIG_MAX => Err(-EINVAL),
        Ok(_) => Ok((header, data, hash, Some(signature))),
        Err(e) => Err(e),
    }
}
