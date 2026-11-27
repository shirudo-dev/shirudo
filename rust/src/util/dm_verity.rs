// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The dm-verity mappings: a config image's data
//! and hash tree attached to read-only loop devices and mapped through
//! device-mapper's verity target, and the mappings listed, inspected, read
//! back whole, mounted and removed.

use core::ffi::{CStr, c_char, c_int, c_long, c_ulong};
use core::mem::MaybeUninit;
use core::ptr;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};

use crate::errno::{
    EBADF, EEXIST, EINTR, EINVAL, EIO, EKEYREJECTED, ENAMETOOLONG, ENODEV, ENOENT, EOVERFLOW,
    ESTALE,
};
use crate::sys::libc::Zeroed;
use crate::sys::libc::{
    AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW, O_CLOEXEC, O_DIRECT, O_NOFOLLOW, O_NONBLOCK,
    O_RDONLY, O_RDWR, PATH_MAX, S_IFBLK, S_IFCHR, S_IFMT, S_IFREG, STATX_BASIC_STATS, SYS_ADD_KEY,
    SYS_KEYCTL, Statx, close, errno, getrandom, ioctl, mknod, mount, open, pread, statx, syscall,
    umount2,
};
use crate::text::{cstr, strscpy};
use crate::util::config_image::{BLOCK_SIZE, ConfigImage, ConfigImageOpen, SIG_MAX, check_files};
use crate::util::hex::hex_encode;
use crate::util::image_guards::{ConfigRootGuard, config_root_begin, config_root_end};
use crate::util::keyring;

const DM_BUFFER_SIZE: usize = 4096;
const DM_VERSION_MAJOR: u32 = 4;
const DM_NAME_LEN: usize = 128;
const DM_UUID_LEN: usize = 129;
const DM_MAX_TYPE_NAME: usize = 16;
const DM_LIST_DEVICES: c_ulong = 0xc138_fd02;
const DM_DEV_CREATE: c_ulong = 0xc138_fd03;
const DM_DEV_REMOVE: c_ulong = 0xc138_fd04;
const DM_DEV_SUSPEND: c_ulong = 0xc138_fd06;
const DM_TABLE_LOAD: c_ulong = 0xc138_fd09;
const DM_TABLE_STATUS: c_ulong = 0xc138_fd0c;
const DM_READONLY_FLAG: u32 = 0x1;
const DM_SUSPEND_FLAG: u32 = 0x2;
const DM_STATUS_TABLE_FLAG: u32 = 0x10;
const DM_ACTIVE_PRESENT_FLAG: u32 = 0x20;
const DM_INACTIVE_PRESENT_FLAG: u32 = 0x40;
const DM_BUFFER_FULL_FLAG: u32 = 0x100;
const DM_DEFERRED_REMOVE: u32 = 0x2_0000;
const LOOP_CTL_GET_FREE: c_ulong = 0x4c82;
const LOOP_CONFIGURE: c_ulong = 0x4c0a;
const LOOP_GET_STATUS64: c_ulong = 0x4c05;
const LO_FLAGS_READ_ONLY: u32 = 1;
const LO_FLAGS_AUTOCLEAR: u32 = 4;
const LO_CRYPT_NONE: u32 = 0;
const BLKGETSIZE64: c_ulong = 0x8008_1272;
const BLKROGET: c_ulong = 0x125e;
const KEY_SPEC_THREAD_KEYRING: c_int = -1;
const KEYCTL_SETPERM: c_int = 5;
const MS_RDONLY: c_ulong = 1;
const MS_NOSUID: c_ulong = 2;
const MS_NODEV: c_ulong = 4;
const MS_NOEXEC: c_ulong = 8;

/// `struct dm_ioctl` of linux/dm-ioctl.h.
#[repr(C)]
#[derive(Clone, Copy)]
struct DmIoctl {
    version: [u32; 3],
    data_size: u32,
    data_start: u32,
    target_count: u32,
    open_count: i32,
    flags: u32,
    event_nr: u32,
    padding: u32,
    dev: u64,
    name: [u8; DM_NAME_LEN],
    uuid: [u8; DM_UUID_LEN],
    data: [u8; 7],
}

/// `union dm_buffer`: an ioctl's header and the data that follows it.
#[repr(C)]
union DmBuffer {
    io: DmIoctl,
    bytes: [u8; DM_BUFFER_SIZE],
}

/// `struct dm_target_spec`.
#[repr(C)]
struct DmTargetSpec {
    sector_start: u64,
    length: u64,
    status: i32,
    next: u32,
    target_type: [u8; DM_MAX_TYPE_NAME],
}

/// `struct loop_info64` of linux/loop.h.
#[repr(C)]
struct LoopInfo64 {
    lo_device: u64,
    lo_inode: u64,
    lo_rdevice: u64,
    lo_offset: u64,
    lo_sizelimit: u64,
    lo_number: u32,
    lo_encrypt_type: u32,
    lo_encrypt_key_size: u32,
    lo_flags: u32,
    lo_file_name: [u8; 64],
    lo_crypt_name: [u8; 64],
    lo_encrypt_key: [u8; 32],
    lo_init: [u64; 2],
}

/// `struct loop_config`.
#[repr(C)]
struct LoopConfig {
    fd: u32,
    block_size: u32,
    info: LoopInfo64,
    reserved: [u64; 8],
}

/// The header of a `struct dm_name_list`, before its name.
const NAME_LIST_HEADER: usize = 12;

const _: () = assert!(size_of::<DmIoctl>() == 312);
const _: () = assert!(size_of::<DmBuffer>() == DM_BUFFER_SIZE);
const _: () = assert!(size_of::<DmTargetSpec>() == 40);
const _: () = assert!(size_of::<LoopInfo64>() == 232);
const _: () = assert!(size_of::<LoopConfig>() == 304);

/// A mapping of an image, its device and the loop devices of its
/// parts, -1 for one not open.
pub struct DmVerity {
    pub(crate) image: ConfigImage,
    pub(crate) name: [u8; DM_NAME_LEN],
    pub(crate) path: [u8; PATH_MAX],
    pub(crate) device: u64,
    pub(crate) data_device: u64,
    pub(crate) hash_device: u64,
    pub(crate) data_loop_fd: c_int,
    pub(crate) hash_loop_fd: c_int,
}

/// A structure all of whose bits zeroed are a value of it, as `= {}`
/// gives it in C.
fn zeroed<T>() -> T {
    // SAFETY: called only for structures of integers and arrays, for
    // which all-zero bytes are a value.
    unsafe { MaybeUninit::zeroed().assume_init() }
}

impl DmVerity {
    /// A mapping not open: `{ .data_loop_fd = -1, .hash_loop_fd = -1 }`.
    pub(crate) fn empty() -> Self {
        let mut d: DmVerity = zeroed();
        d.data_loop_fd = -1;
        d.hash_loop_fd = -1;
        d
    }
}

/// glibc's major() of a dev_t.
fn major(dev: u64) -> u32 {
    (((dev & 0x0000_0000_000f_ff00) >> 8) | ((dev & 0xffff_f000_0000_0000) >> 32)) as u32
}

/// glibc's minor() of a dev_t.
pub(crate) fn minor(dev: u64) -> u32 {
    ((dev & 0x0000_0000_0000_00ff) | ((dev & 0x0000_0fff_fff0_0000) >> 12)) as u32
}

/// glibc's makedev().
fn makedev(major: u32, minor: u32) -> u64 {
    let (ma, mi) = (u64::from(major), u64::from(minor));

    ((ma & 0x0000_0fff) << 8)
        | ((ma & 0xffff_f000) << 32)
        | (mi & 0x0000_00ff)
        | ((mi & 0xffff_ff00) << 12)
}

/// A file's state, as fstat() gives the C: through statx() on its fd.
fn stat_fd(fd: c_int, st: &mut Statx) -> c_int {
    // SAFETY: the fd, an empty path, and room for the state.
    unsafe { statx(fd, c"".as_ptr(), AT_EMPTY_PATH, STATX_BASIC_STATS, st) }
}

/// A path's state, the link's own with `nofollow`, as lstat() and
/// stat() give the C.
///
/// # Safety
///
/// `path` is a C string.
unsafe fn stat_path(path: *const c_char, nofollow: bool, st: &mut Statx) -> c_int {
    let flags = if nofollow { AT_SYMLINK_NOFOLLOW } else { 0 };

    // SAFETY: the caller's C string, and room for the state.
    unsafe { statx(AT_FDCWD, path, flags, STATX_BASIC_STATS, st) }
}

fn file_type(st: &Statx) -> u16 {
    st.stx_mode & S_IFMT
}

fn rdev(st: &Statx) -> u64 {
    makedev(st.stx_rdev_major, st.stx_rdev_minor)
}

fn dev(st: &Statx) -> u64 {
    makedev(st.stx_dev_major, st.stx_dev_minor)
}

/// dm_name_ok(): 1 to 127 of `[A-Za-z0-9._-]`, not `.` or `..`.
fn dm_name_ok(name: &[u8]) -> bool {
    if name.is_empty() || name == b"." || name == b".." {
        return false;
    }
    name.iter()
        .enumerate()
        .all(|(n, &c)| n < 127 && (c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.')))
}

/// The buffer zeroed with the header of a command on `device`.
fn dm_init(buf: &mut DmBuffer, device: &DmVerity) {
    *buf = DmBuffer {
        bytes: [0; DM_BUFFER_SIZE],
    };
    // SAFETY: the header, which every bit pattern of the buffer is.
    let io = unsafe { &mut buf.io };
    io.version = [DM_VERSION_MAJOR, 0, 0];
    io.data_size = DM_BUFFER_SIZE as u32;
    io.data_start = size_of::<DmIoctl>() as u32;
    io.name = device.name;
}

/// The header of the buffer.
fn io(buf: &mut DmBuffer) -> &mut DmIoctl {
    // SAFETY: the header, which every bit pattern of the buffer is.
    unsafe { &mut buf.io }
}

/// dm_command(): the ioctl on the buffer, -EOVERFLOW when the answer did
/// not fit.
fn dm_command(fd: c_int, command: c_ulong, buf: &mut DmBuffer) -> c_int {
    // SAFETY: the control's fd, a device-mapper command and its buffer.
    if unsafe { ioctl(fd, command, ptr::from_mut(io(buf))) } != 0 {
        return -errno();
    }
    if io(buf).flags & DM_BUFFER_FULL_FLAG != 0 {
        return -EOVERFLOW;
    }
    0
}

/// The fd `open()` gave, owned from here, or -errno.
fn owned(fd: c_int) -> Result<OwnedFd, c_int> {
    if fd < 0 {
        return Err(-errno());
    }
    // SAFETY: an fd just opened, which nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The device-mapper control device, a character device 10:236.
fn dm_control_open() -> Result<OwnedFd, c_int> {
    let mut st = Statx::zeroed();

    // SAFETY: a C string.
    let fd = owned(unsafe {
        open(
            c"/dev/mapper/control".as_ptr(),
            O_RDWR | O_CLOEXEC | O_NOFOLLOW,
        )
    })?;
    if stat_fd(fd.as_raw_fd(), &mut st) != 0 {
        return Err(-errno());
    }
    if file_type(&st) != S_IFCHR || rdev(&st) != makedev(10, 236) {
        return Err(-ENODEV);
    }
    Ok(fd)
}

/// Each device-mapper device's name and number to `f`, until it returns
/// other than 0: 0, what it returned, or -errno.
pub(crate) fn list(mut f: impl FnMut(&CStr, u64) -> c_int) -> c_int {
    const CAPACITY: usize = 64 * 1024;
    let control = match dm_control_open() {
        Ok(fd) => fd,
        Err(err) => return err,
    };
    // Words, for the alignment of the header the kernel reads and writes.
    let mut words = vec![0u64; CAPACITY / 8];
    let io = words.as_mut_ptr().cast::<DmIoctl>();
    // SAFETY: the header at the start of the zeroed buffer, which holds
    // CAPACITY bytes and is aligned for it.
    unsafe {
        (*io).version[0] = DM_VERSION_MAJOR;
        (*io).data_size = CAPACITY as u32;
        (*io).data_start = size_of::<DmIoctl>() as u32;
    }
    // SAFETY: the control's fd, and the buffer of CAPACITY bytes the
    // header describes.
    if unsafe { ioctl(control.as_raw_fd(), DM_LIST_DEVICES, io) } != 0 {
        return -errno();
    }
    // SAFETY: the header the kernel left at the start of the buffer.
    let io = unsafe { io.read() };
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
    if io.flags & DM_BUFFER_FULL_FLAG != 0 {
        return -EOVERFLOW;
    }
    let (size, start) = (io.data_size as usize, io.data_start as usize);
    if size > CAPACITY || start < size_of::<DmIoctl>() || start > size || start % 8 != 0 {
        return -EINVAL;
    }
    let mut offset = start;
    while offset < size {
        let mut avail = size - offset;
        if avail < NAME_LIST_HEADER + 1 {
            return -EINVAL;
        }
        let entry = &bytes[offset..size];
        let device = u64::from_ne_bytes(entry[..8].try_into().unwrap_or_default());
        let next = u32::from_ne_bytes(entry[8..12].try_into().unwrap_or_default());
        if device == 0 {
            return if next != 0 || entry[NAME_LIST_HEADER] != 0 {
                -EINVAL
            } else {
                0
            };
        }
        if next != 0 {
            if next as usize > avail || next % 8 != 0 || (next as usize) < NAME_LIST_HEADER + 1 {
                return -EINVAL;
            }
            avail = next as usize;
        }
        let name = &entry[NAME_LIST_HEADER..avail];
        let name = &name[..name.len().min(DM_NAME_LEN)];
        let Ok(name) = CStr::from_bytes_until_nul(name) else {
            return -EINVAL;
        };
        if name.is_empty() {
            return -EINVAL;
        }
        let ret = f(name, device);
        if ret != 0 || next == 0 {
            return ret;
        }
        offset += next as usize;
    }
    0
}

/// A free loop device attached read-only to the file at `file_fd`, `bytes`
/// of it, its fd into `*out`.
fn loop_attach(file: &File, bytes: u64, out: &mut c_int) -> c_int {
    let mut config: LoopConfig = zeroed();
    let mut path = [0u8; 64];

    // SAFETY: a C string.
    let control = match owned(unsafe { open(c"/dev/loop-control".as_ptr(), O_RDWR | O_CLOEXEC) }) {
        Ok(fd) => fd,
        Err(err) => return err,
    };
    // SAFETY: the control's fd, and a command without an argument.
    let n = unsafe { ioctl(control.as_raw_fd(), LOOP_CTL_GET_FREE) };
    let ret = if n < 0 { -errno() } else { 0 };
    drop(control);
    if ret != 0 {
        return ret;
    }
    // SAFETY: the path's room, and the C's format with its argument.
    if unsafe {
        crate::text::csprintf!(
            path.as_mut_ptr().cast(),
            path.len(),
            c"/dev/loop%d".as_ptr(),
            n,
        )
    } < 0
    {
        return -ENAMETOOLONG;
    }
    // SAFETY: a C string.
    let lp = match owned(unsafe { open(path.as_ptr().cast(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW) }) {
        Ok(fd) => fd,
        Err(err) => return err,
    };
    config.fd = file.as_raw_fd() as u32;
    config.block_size = BLOCK_SIZE as u32;
    config.info.lo_sizelimit = bytes;
    config.info.lo_flags = LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR;
    // SAFETY: the loop device's fd, and its configuration.
    if unsafe { ioctl(lp.as_raw_fd(), LOOP_CONFIGURE, ptr::from_ref(&config)) } != 0 {
        return -errno();
    }
    // The mapping keeps it, and close_loops() closes it.
    *out = lp.into_raw_fd();
    0
}

/// The mapping's device `dev` and its node under /dev, made when missing.
fn device_path(device: &mut DmVerity, dev: u64) -> c_int {
    let mut st = Statx::zeroed();
    let path = device.path.as_mut_ptr().cast::<c_char>();

    device.device = dev;
    // SAFETY: the path's room, and the C's format with its argument.
    if unsafe {
        crate::text::csprintf!(
            path,
            device.path.len(),
            c"/dev/dm-%u".as_ptr(),
            minor(device.device),
        )
    } < 0
    {
        return -ENAMETOOLONG;
    }
    // SAFETY: the path just written, a C string, and room for its state.
    unsafe {
        if stat_path(path, true, &mut st) != 0 {
            if errno() != ENOENT {
                return -errno();
            }
            if mknod(path, u32::from(S_IFBLK) | 0o600, device.device) != 0 && errno() != EEXIST {
                return -errno();
            }
            if stat_path(path, true, &mut st) != 0 {
                return -errno();
            }
        }
    }
    if file_type(&st) == S_IFBLK && rdev(&st) == device.device {
        0
    } else {
        -ESTALE
    }
}

/// dm_number(): the decimal number `token` spells.
fn dm_number(token: &[u8], out: &mut u64) -> c_int {
    match crate::text::parse_u64(token, u64::MAX) {
        Ok(v) => {
            *out = v;
            0
        }
        Err(_) => -EINVAL,
    }
}

/// dm_device(): the device `major:minor` spells, into `*out`.
fn dm_device(token: &[u8], out: &mut u64) -> c_int {
    let (mut major_nr, mut minor_nr) = (0u64, 0u64);
    let Some(separator) = token.iter().position(|&c| c == b':') else {
        return -EINVAL;
    };

    if dm_number(&token[..separator], &mut major_nr) != 0
        || dm_number(&token[separator + 1..], &mut minor_nr) != 0
        || major_nr > u64::from(u32::MAX)
        || minor_nr > u64::from(u32::MAX)
    {
        return -EINVAL;
    }
    *out = makedev(major_nr as u32, minor_nr as u32);
    if u64::from(major(*out)) == major_nr && u64::from(minor(*out)) == minor_nr {
        0
    } else {
        -EINVAL
    }
}

/// check_table(): whether the table in the buffer maps the image's data
/// whole through verity, read-only and live, with the image's root hash
/// and salt; its loop devices into the mapping.
fn check_table(buf: &mut DmBuffer, image: &ConfigImage, device: &mut DmVerity) -> c_int {
    let io = *io(buf);
    let mut root = [0u8; 65];
    let mut salt = [0u8; 65];
    let mut tokens: [&[u8]; 13] = [&[]; 13];
    let mut count = 0usize;
    let mut value = 0u64;

    if io.flags & DM_READONLY_FLAG == 0
        || io.flags & (DM_SUSPEND_FLAG | DM_INACTIVE_PRESENT_FLAG) != 0
        || io.flags & DM_ACTIVE_PRESENT_FLAG == 0
        || io.target_count != 1
    {
        return -EKEYREJECTED;
    }
    let offset = io.data_start as usize;
    if io.data_size as usize > DM_BUFFER_SIZE
        || offset > io.data_size as usize
        || io.data_size as usize - offset < size_of::<DmTargetSpec>()
    {
        return -EINVAL;
    }
    // SAFETY: the bytes of the buffer, every one initialised.
    let bytes = unsafe { &buf.bytes };
    // SAFETY: a target spec within the data the kernel reported.
    let target = unsafe {
        bytes
            .as_ptr()
            .add(offset)
            .cast::<DmTargetSpec>()
            .read_unaligned()
    };
    if target.sector_start != 0
        || target.length != image.data_blocks.wrapping_mul(BLOCK_SIZE / 512)
        || cstr(&target.target_type) != b"verity"
    {
        return -EKEYREJECTED;
    }
    let params = &bytes[offset + size_of::<DmTargetSpec>()..io.data_size as usize];
    let Some(end) = params.iter().position(|&c| c == 0) else {
        return -EINVAL;
    };
    for token in params[..end]
        .split(|&c| c == b' ')
        .filter(|t| !t.is_empty())
    {
        if count == 13 {
            return -EKEYREJECTED;
        }
        tokens[count] = token;
        count += 1;
    }
    if image.signed_root {
        if count != 13 || tokens[10] != b"2" || tokens[11] != b"root_hash_sig_key_desc" {
            return -EKEYREJECTED;
        }
    } else if (count != 10 && count != 11) || (count == 11 && tokens[10] != b"0") {
        return -EKEYREJECTED;
    }
    for (i, token) in tokens.iter().enumerate().take(7) {
        if i == 1 || i == 2 {
            continue;
        }
        if dm_number(token, &mut value) != 0 {
            return -EINVAL;
        }
        if (i == 0 && value != 1)
            || ((i == 3 || i == 4) && value != BLOCK_SIZE)
            || (i == 5 && value != image.data_blocks)
            || (i == 6 && value != 1)
        {
            return -EKEYREJECTED;
        }
    }
    // SAFETY: the digests, and rooms for their hex and a NUL.
    unsafe {
        hex_encode(image.root_hash.as_ptr(), 32, root.as_mut_ptr().cast());
        hex_encode(image.salt.as_ptr(), 32, salt.as_mut_ptr().cast());
    }
    if tokens[7] != b"sha256" || tokens[8] != cstr(&root) || tokens[9] != cstr(&salt) {
        return -EKEYREJECTED;
    }
    if dm_device(tokens[1], &mut device.data_device) != 0
        || dm_device(tokens[2], &mut device.hash_device) != 0
    {
        return -EINVAL;
    }
    0
}

/// The live mapping `name` checked against `image`.
pub(crate) fn inspect(name: &CStr, image: &ConfigImage) -> Result<DmVerity, c_int> {
    let name = name.to_bytes();
    if !dm_name_ok(name) {
        return Err(-EINVAL);
    }
    let mut device = DmVerity::empty();
    strscpy(&mut device.name, name).map_err(|_| -EINVAL)?;
    let mut buf = DmBuffer {
        bytes: [0; DM_BUFFER_SIZE],
    };

    let control = dm_control_open()?;
    dm_init(&mut buf, &device);
    io(&mut buf).flags = DM_STATUS_TABLE_FLAG;
    let mut ret = dm_command(control.as_raw_fd(), DM_TABLE_STATUS, &mut buf);
    if ret == 0 {
        ret = check_table(&mut buf, image, &mut device);
    }
    if ret == 0 {
        ret = device_path(&mut device, io(&mut buf).dev);
    }
    drop(control);
    if ret != 0 {
        return Err(ret);
    }
    device.image = *image;
    Ok(device)
}

/// `made` into `device`, or an empty mapping in its place when it failed:
/// 0 or -errno, for the callers that keep a mapping across steps.
pub(crate) fn place(made: Result<DmVerity, c_int>, device: &mut DmVerity) -> c_int {
    match made {
        Ok(made) => {
            *device = made;
            0
        }
        Err(err) => {
            *device = DmVerity::empty();
            err
        }
    }
}

/// The live mapping of `device`'s name inspected against `image` into
/// `checked`: 0 or -errno.
fn recheck(device: &DmVerity, image: &ConfigImage, checked: &mut DmVerity) -> c_int {
    let Ok(name) = CStr::from_bytes_until_nul(&device.name) else {
        return -EINVAL;
    };
    match inspect(name, image) {
        Ok(live) => {
            *checked = live;
            0
        }
        Err(err) => err,
    }
}

/// The loop devices' fds closed.
pub(crate) fn close_loops(device: &mut DmVerity) {
    // SAFETY: the mapping's fds, each closed once.
    unsafe {
        if device.data_loop_fd >= 0 {
            close(device.data_loop_fd);
        }
        if device.hash_loop_fd >= 0 {
            close(device.hash_loop_fd);
        }
    }
    device.data_loop_fd = -1;
    device.hash_loop_fd = -1;
}

/// The mapping removed, at its last close with
/// `deferred`, and its loop devices closed.
pub(crate) fn remove(device: &mut DmVerity, deferred: bool) -> c_int {
    let mut buf = DmBuffer {
        bytes: [0; DM_BUFFER_SIZE],
    };
    let name = cstr(&device.name);

    if !dm_name_ok(name) {
        return -EINVAL;
    }
    let control = match dm_control_open() {
        Ok(fd) => fd,
        Err(err) => return err,
    };
    dm_init(&mut buf, device);
    if deferred {
        io(&mut buf).flags = DM_DEFERRED_REMOVE;
    }
    let ret = dm_command(control.as_raw_fd(), DM_DEV_REMOVE, &mut buf);
    drop(control);
    if ret == 0 {
        close_loops(device);
    }
    ret
}

/// signature_key(): the image's root hash signature as a "user" key on
/// the thread keyring, where request_key() finds it, with its permissions
/// fixed; its description into `description`.
fn signature_key(file: &File, description: &mut [u8; 64]) -> i32 {
    let mut signature = [0u8; SIG_MAX as usize];
    let mut random = [0u8; 16];
    let mut suffix = [0u8; 33];
    let mut st = Statx::zeroed();
    let mut done = 0usize;
    let fd = file.as_raw_fd();

    if stat_fd(fd, &mut st) != 0 {
        return -errno();
    }
    if file_type(&st) != S_IFREG || st.stx_size as i64 <= 0 || st.stx_size > signature.len() as u64
    {
        return -EINVAL;
    }
    let size = st.stx_size as usize;
    while done < size {
        // SAFETY: the file's fd, and the room left in the buffer.
        let n = unsafe {
            pread(
                fd,
                signature.as_mut_ptr().add(done).cast(),
                size - done,
                done as i64,
            )
        };
        if n < 0 {
            if errno() == EINTR {
                continue;
            }
            return -errno();
        }
        if n == 0 {
            return -EIO;
        }
        done += n as usize;
    }
    done = 0;
    while done < random.len() {
        // SAFETY: the room left in the buffer.
        let n = unsafe { getrandom(random.as_mut_ptr().add(done).cast(), random.len() - done, 0) };
        if n < 0 {
            if errno() == EINTR {
                continue;
            }
            return -errno();
        }
        if n == 0 {
            return -EIO;
        }
        done += n as usize;
    }
    // SAFETY: the bytes, and room for their hex and a NUL.
    unsafe { hex_encode(random.as_ptr(), random.len(), suffix.as_mut_ptr().cast()) };
    // SAFETY: the description's room, and the C's format with its
    // argument.
    if unsafe {
        crate::text::csprintf!(
            description.as_mut_ptr().cast(),
            description.len(),
            c"shirudo-verity-%s".as_ptr(),
            suffix.as_ptr(),
        )
    } < 0
    {
        return -ENAMETOOLONG;
    }
    // SAFETY: add_key(2) with C strings, the signature's bytes and a
    // keyring, as the C passes them.
    let key: c_long = unsafe {
        syscall(
            SYS_ADD_KEY,
            c"user".as_ptr(),
            description.as_ptr(),
            signature.as_ptr(),
            size,
            KEY_SPEC_THREAD_KEYRING,
        )
    };
    if key < 0 {
        return -errno();
    }
    // Keep possessor search, but prevent payload and permission changes.
    // SAFETY: keyctl(2) KEYCTL_SETPERM on the key, as the C passes it.
    if unsafe {
        syscall(
            SYS_KEYCTL,
            KEYCTL_SETPERM,
            key,
            0x0800_0000 as c_int,
            0 as c_int,
            0 as c_int,
        )
    } < 0
    {
        let ret = -errno();

        keyring::unlink_key(KEY_SPEC_THREAD_KEYRING, key as i32);
        return ret;
    }
    key as i32
}

/// The image's parts attached to loop devices and mapped through verity
/// as `name`, the mapping checked as live.
pub(crate) fn create(image: &ConfigImageOpen, name: &CStr) -> Result<DmVerity, c_int> {
    let name = name.to_bytes();
    if !dm_name_ok(name) {
        return Err(-EINVAL);
    }
    let mut device = DmVerity::empty();
    let mut root = [0u8; 65];
    let mut salt = [0u8; 65];
    let mut params = [0u8; 512];
    let mut signature = [0u8; 64];
    let mut guard = ConfigRootGuard::default();
    let mut data_st = Statx::zeroed();
    let mut hash_st = Statx::zeroed();
    let mut buf = DmBuffer {
        bytes: [0; DM_BUFFER_SIZE],
    };
    let mut created = false;
    let mut key: i32 = -1;
    let mut control = -1;
    let mut _control_fd: Option<OwnedFd> = None;
    let mut ret;

    ret = check_files(&image.data, &image.hash, &image.image);
    if ret != 0 {
        return Err(ret);
    }
    device.image = image.image;
    strscpy(&mut device.name, name).map_err(|_| -EINVAL)?;
    'out: {
        ret = loop_attach(
            &image.data,
            image.image.data_blocks.wrapping_mul(BLOCK_SIZE),
            &mut device.data_loop_fd,
        );
        if ret == 0 {
            ret = loop_attach(
                &image.hash,
                image.image.hash_blocks.wrapping_mul(BLOCK_SIZE),
                &mut device.hash_loop_fd,
            );
        }
        if ret != 0 {
            break 'out;
        }
        if stat_fd(device.data_loop_fd, &mut data_st) != 0
            || stat_fd(device.hash_loop_fd, &mut hash_st) != 0
        {
            ret = -errno();
            break 'out;
        }
        // SAFETY: the digests, and rooms for their hex and a NUL.
        unsafe {
            hex_encode(image.image.root_hash.as_ptr(), 32, root.as_mut_ptr().cast());
            hex_encode(image.image.salt.as_ptr(), 32, salt.as_mut_ptr().cast());
        }
        // SAFETY: the parameters' room, and the C's format with its
        // arguments.
        let mut n = unsafe {
            crate::text::csprintf!(
                params.as_mut_ptr().cast(),
                params.len(),
                c"1 %u:%u %u:%u 4096 4096 %llu 1 sha256 %s %s".as_ptr(),
                data_st.stx_rdev_major,
                data_st.stx_rdev_minor,
                hash_st.stx_rdev_major,
                hash_st.stx_rdev_minor,
                image.image.data_blocks,
                root.as_ptr(),
                salt.as_ptr(),
            )
        };
        if n < 0 {
            ret = -EOVERFLOW;
            break 'out;
        }
        if image.image.signed_root {
            let remaining = params.len() as c_int - n;

            key = match &image.signature {
                Some(file) => signature_key(file, &mut signature),
                None => -EBADF,
            };
            if key < 0 {
                ret = key;
                break 'out;
            }
            // SAFETY: the room left in the parameters, and the C's format
            // with its argument.
            let written = unsafe {
                crate::text::csprintf!(
                    params.as_mut_ptr().add(n as usize).cast(),
                    remaining as usize,
                    c" 2 root_hash_sig_key_desc %s".as_ptr(),
                    signature.as_ptr(),
                )
            };
            if written < 0 {
                ret = -EOVERFLOW;
                break 'out;
            }
            n += written;
        }
        match dm_control_open() {
            Ok(fd) => control = _control_fd.insert(fd).as_raw_fd(),
            Err(err) => {
                ret = err;
                break 'out;
            }
        }
        dm_init(&mut buf, &device);
        ret = dm_command(control, DM_DEV_CREATE, &mut buf);
        if ret != 0 {
            break 'out;
        }
        created = true;
        dm_init(&mut buf, &device);
        io(&mut buf).flags = DM_READONLY_FLAG;
        io(&mut buf).target_count = 1;
        let start = io(&mut buf).data_start as usize;
        let next = ((size_of::<DmTargetSpec>() + n as usize + 1 + 7) & !7) as u32;
        // SAFETY: the bytes of the buffer, a target spec at the data's
        // start and the parameters with their NUL after it, all within
        // the buffer.
        unsafe {
            let target = buf.bytes.as_mut_ptr().add(start).cast::<DmTargetSpec>();
            let mut spec = target.read_unaligned();

            spec.length = image.image.data_blocks.wrapping_mul(BLOCK_SIZE / 512);
            spec.target_type = *b"verity\0\0\0\0\0\0\0\0\0\0";
            spec.next = next;
            target.write_unaligned(spec);
            ptr::copy_nonoverlapping(params.as_ptr(), target.add(1).cast::<u8>(), n as usize + 1);
        }
        let io_hdr = io(&mut buf);
        io_hdr.data_size = io_hdr.data_start + next;
        if image.image.signed_root {
            ret = config_root_begin(&image.image.root_hash, &mut guard);
            if ret != 0 {
                break 'out;
            }
        }
        ret = dm_command(control, DM_TABLE_LOAD, &mut buf);
        if ret != 0 {
            break 'out;
        }
        dm_init(&mut buf, &device);
        io(&mut buf).flags = DM_READONLY_FLAG;
        ret = dm_command(control, DM_DEV_SUSPEND, &mut buf);
        if ret != 0 {
            break 'out;
        }
        dm_init(&mut buf, &device);
        io(&mut buf).flags = DM_STATUS_TABLE_FLAG;
        ret = dm_command(control, DM_TABLE_STATUS, &mut buf);
        if ret == 0 {
            ret = check_table(&mut buf, &image.image, &mut device);
        }
        if ret == 0 {
            ret = device_path(&mut device, io(&mut buf).dev);
        }
    }
    let cleanup = config_root_end(&mut guard);
    if ret == 0 {
        ret = cleanup;
    }
    if key >= 0 {
        keyring::unlink_key(KEY_SPEC_THREAD_KEYRING, key);
    }
    if ret != 0 {
        if created {
            dm_init(&mut buf, &device);
            dm_command(control, DM_DEV_REMOVE, &mut buf);
        }
        close_loops(&mut device);
    }
    if ret != 0 { Err(ret) } else { Ok(device) }
}

/// loop_open(): the loop device `device`, a block device of major 7.
fn loop_open(device: u64) -> Result<OwnedFd, c_int> {
    let mut st = Statx::zeroed();
    let mut path = [0u8; 64];

    if major(device) != 7 {
        return Err(-ENODEV);
    }
    // SAFETY: the path's room, and the C's format with its argument.
    if unsafe {
        crate::text::csprintf!(
            path.as_mut_ptr().cast(),
            path.len(),
            c"/dev/loop%u".as_ptr(),
            minor(device),
        )
    } < 0
    {
        return Err(-ENAMETOOLONG);
    }
    // SAFETY: a C string.
    let fd = owned(unsafe {
        open(
            path.as_ptr().cast(),
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
        )
    })?;
    if stat_fd(fd.as_raw_fd(), &mut st) != 0 {
        return Err(-errno());
    }
    if file_type(&st) != S_IFBLK || rdev(&st) != device {
        return Err(-ESTALE);
    }
    Ok(fd)
}

/// loop_check(): whether the loop device reads the file `bytes` long,
/// read-only, from its start and in the clear.
fn loop_check(loop_fd: c_int, file: &File, bytes: u64) -> c_int {
    let mut info: LoopInfo64 = zeroed();
    let mut st = Statx::zeroed();

    if stat_fd(file.as_raw_fd(), &mut st) != 0
        // SAFETY: the loop device's fd, and room for its status.
        || unsafe { ioctl(loop_fd, LOOP_GET_STATUS64, ptr::from_mut(&mut info)) } != 0
    {
        return -errno();
    }
    if file_type(&st) != S_IFREG
        || (st.stx_size as i64) < 0
        || st.stx_size != bytes
        || info.lo_device != dev(&st)
        || info.lo_inode != st.stx_ino
        || info.lo_offset != 0
        || info.lo_sizelimit != bytes
        || info.lo_flags & LO_FLAGS_READ_ONLY == 0
        || info.lo_encrypt_type != LO_CRYPT_NONE
    {
        return -ESTALE;
    }
    0
}

/// A buffer for O_DIRECT reads.
#[repr(C, align(4096))]
struct DirectBuffer([u8; 65536]);

/// The mapping read back whole through direct reads,
/// which verify all its logical data, including blocks outside live
/// files, and checked against the image before and after.
///
pub(crate) fn verify(device: &DmVerity, image: &ConfigImageOpen) -> c_int {
    let mut buffer = DirectBuffer([0; 65536]);
    let mut checked = DmVerity::empty();
    let mut st = Statx::zeroed();
    let mut size = 0u64;
    let mut readonly: c_int = 0;
    let mut offset = 0u64;

    let mut ret = check_files(&image.data, &image.hash, &image.image);
    if ret != 0 {
        return ret;
    }
    let bytes = image.image.data_blocks.wrapping_mul(BLOCK_SIZE);
    ret = recheck(device, &image.image, &mut checked);
    if ret != 0 {
        return ret;
    }
    if checked.device != device.device
        || checked.data_device != device.data_device
        || checked.hash_device != device.hash_device
    {
        return -ESTALE;
    }
    let data_fd = match loop_open(device.data_device) {
        Ok(fd) => fd,
        Err(err) => return err,
    };
    let data = data_fd.as_raw_fd();
    let mut hashes_fd: Option<OwnedFd> = None;
    let mut mapped: Option<OwnedFd> = None;
    'out: {
        let hashes = match loop_open(device.hash_device) {
            Ok(fd) => hashes_fd.insert(fd).as_raw_fd(),
            Err(err) => {
                ret = err;
                break 'out;
            }
        };
        ret = loop_check(data, &image.data, bytes);
        if ret == 0 {
            ret = loop_check(
                hashes,
                &image.hash,
                image.image.hash_blocks.wrapping_mul(BLOCK_SIZE),
            );
        }
        if ret != 0 {
            break 'out;
        }
        // SAFETY: the mapping's path, a C string within its array.
        let fd = match owned(unsafe {
            open(
                device.path.as_ptr().cast(),
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | O_DIRECT,
            )
        }) {
            Ok(fd) => mapped.insert(fd).as_raw_fd(),
            Err(err) => {
                ret = err;
                break 'out;
            }
        };
        if stat_fd(fd, &mut st) != 0
            // SAFETY: the device's fd, and room for its size.
            || unsafe { ioctl(fd, BLKGETSIZE64, ptr::from_mut(&mut size)) } != 0
            // SAFETY: the device's fd, and room for its flag.
            || unsafe { ioctl(fd, BLKROGET, ptr::from_mut(&mut readonly)) } != 0
        {
            ret = -errno();
            break 'out;
        }
        if file_type(&st) != S_IFBLK || rdev(&st) != device.device || size != bytes || readonly == 0
        {
            ret = -ESTALE;
            break 'out;
        }
        while offset < bytes {
            let count = if (buffer.0.len() as u64) > bytes - offset {
                (bytes - offset) as usize
            } else {
                buffer.0.len()
            };
            // SAFETY: the device's fd, and the buffer's room.
            let n = unsafe { pread(fd, buffer.0.as_mut_ptr().cast(), count, offset as i64) };
            if n < 0 {
                if errno() == EINTR {
                    continue;
                }
                ret = -errno();
                break 'out;
            }
            if n == 0 {
                ret = -EIO;
                break 'out;
            }
            offset += n as u64;
        }
        ret = recheck(device, &image.image, &mut checked);
        if ret == 0
            && (checked.device != device.device
                || checked.data_device != device.data_device
                || checked.hash_device != device.hash_device)
        {
            ret = -ESTALE;
        }
        if ret == 0 {
            ret = loop_check(data, &image.data, bytes);
        }
        if ret == 0 {
            ret = loop_check(
                hashes,
                &image.hash,
                image.image.hash_blocks.wrapping_mul(BLOCK_SIZE),
            );
        }
    }
    // The fds close as they go: the mapping's, the hashes', the data's.
    drop((mapped, hashes_fd, data_fd));
    ret
}

/// The mapping mounted read-only at `mountpoint`, with
/// no devices or setuid, and no execution unless `executable`, checked as
/// the live mapping before and after.
///
pub(crate) fn mount_at(device: &DmVerity, mountpoint: &CStr, executable: bool) -> c_int {
    let point = mountpoint.to_bytes();
    let mut flags = MS_RDONLY | MS_NODEV | MS_NOSUID;
    let mut checked = DmVerity::empty();
    let mut st = Statx::zeroed();

    if point.first() != Some(&b'/') {
        return -EINVAL;
    }
    let mut ret = recheck(device, &device.image, &mut checked);
    if ret != 0 {
        return ret;
    }
    if checked.device != device.device {
        return -ESTALE;
    }
    if !executable {
        flags |= MS_NOEXEC;
    }
    // SAFETY: the mapping's path and the caller's mountpoint, C strings,
    // and the options as the C passes them.
    if unsafe {
        mount(
            device.path.as_ptr().cast(),
            mountpoint.as_ptr(),
            c"ext4".as_ptr(),
            flags,
            c"noload".as_ptr().cast(),
        )
    } != 0
    {
        return -errno();
    }
    // SAFETY: the caller's C string, and room for its state.
    if unsafe { stat_path(mountpoint.as_ptr(), false, &mut st) } != 0 {
        ret = -errno();
    } else if dev(&st) != device.device {
        ret = -ESTALE;
    } else {
        ret = recheck(device, &device.image, &mut checked);
    }
    if ret != 0 {
        // SAFETY: the caller's C string.
        unsafe { umount2(mountpoint.as_ptr(), 0) };
    }
    ret
}
