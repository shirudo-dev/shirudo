// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! shirudo-image-fault: shirudo itself, static, for the image tests,
//! with the faults they need: `image update` dies right after its PCR
//! extend, as a crash would leave it, and `config-root` maps a config
//! image while the staging of its expected root is left out, staged off
//! by a bit, or left alone, and checks what the guards made of it.
//!
//!   shirudo-image-fault image update <prefix>
//!   shirudo-image-fault config-root missing|wrong|match <prefix>
//!   shirudo-image-fault archive-truncate <upatch>
//!
//! make links shirudo's main object with --wrap=main, --wrap=Esys_PCR_Extend
//! and --wrap=syscall.

use core::ffi::{CStr, c_char, c_int, c_long};
use core::sync::atomic::{AtomicI32, AtomicU8, AtomicU32, Ordering};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;

use super::{err, out, real_syscall, set_syscall_hook, strerror};
use crate::skel::bpf2::ExpectedRoot;
use crate::sys::identity::{DEVICE_CONFIG, DeviceAuthority};
use crate::sys::libc::PATH_MAX;
use crate::util::bpf_sys::Attr;
use crate::util::config_image::ConfigImageOpen;
use crate::util::dm_verity::{self, DmVerity};
use crate::util::io::kernel_dev;

const BPF_MAP_LOOKUP_ELEM: c_long = 1;
const BPF_MAP_UPDATE_ELEM: c_long = 2;
const BPF_MAP_GET_NEXT_KEY: c_long = 4;
const BPF_OBJ_GET: c_long = 7;
/// BPFFS_DIR "/config_roots" and "/devices" of util/paths.h.
const CONFIG_ROOTS: &CStr = c"/run/shirudo/bpffs/config_roots";
const DEVICES: &CStr = c"/run/shirudo/bpffs/devices";
/// _IOR(0x12, 128, __u64).
const BLKGETDISKSEQ: libc::c_ulong = (2 << 30) | (8 << 16) | (0x12 << 8) | 128;

const ROOT_NORMAL: u8 = 0;
const ROOT_MISSING: u8 = 1;
const ROOT_WRONG: u8 = 2;
const ROOT_MATCH: u8 = 3;

static ROOT_MODE: AtomicU8 = AtomicU8::new(ROOT_NORMAL);
static BEGIN_CALLS: AtomicU32 = AtomicU32::new(0);
static END_CALLS: AtomicU32 = AtomicU32::new(0);
static CONSUMED_VALID: AtomicI32 = AtomicI32::new(-1);
static ROOTS_FD: AtomicI32 = AtomicI32::new(-1);

fn set_errno(e: c_int) {
    // SAFETY: this thread's errno.
    unsafe { *libc::__errno_location() = e };
}

fn real_bpf(cmd: c_long, attr: *mut u8, size: c_long) -> c_long {
    // SAFETY: a bpf() call of the caller's attribute, of its size.
    unsafe { real_syscall(libc::SYS_bpf, [cmd, attr as c_long, size, 0, 0, 0]) }
}

/// The writes of config_root_begin() and config_root_end() to the map of
/// the roots tasks expect: the staging of the image's root is left out,
/// or staged off by a bit; its clearing first notes whether the guard
/// consumed it.
///
/// # Safety
///
/// `attr` is the caller's BPF_MAP_UPDATE_ELEM attribute of `size` bytes.
unsafe fn roots_update(attr: *mut u8, size: c_long) -> c_long {
    let mode = ROOT_MODE.load(Ordering::Relaxed);
    // SAFETY: the attribute's map, key and value, as the caller passes.
    unsafe {
        let want = attr.add(16).cast::<u64>().read_unaligned() as *const ExpectedRoot;
        if (*want).valid != 0 {
            BEGIN_CALLS.fetch_add(1, Ordering::Relaxed);
            if mode == ROOT_MISSING {
                return 0;
            }
            if !(0..=256).contains(&size) {
                set_errno(libc::E2BIG);
                return -1;
            }
            let mut staged = core::ptr::read(want);
            if mode == ROOT_WRONG {
                staged.root[0] ^= 1;
            }
            let mut changed = [0u8; 256];
            core::ptr::copy_nonoverlapping(attr, changed.as_mut_ptr(), size as usize);
            changed[16..24].copy_from_slice(&((&raw const staged) as u64).to_ne_bytes());
            return real_bpf(BPF_MAP_UPDATE_ELEM, changed.as_mut_ptr(), size);
        }
        END_CALLS.fetch_add(1, Ordering::Relaxed);
        let mut current = ExpectedRoot::zeroed();
        let map = attr.cast::<u32>().read_unaligned();
        let key = attr.add(8).cast::<u64>().read_unaligned();
        let mut lookup = match Attr::new()
            .u32(0, map)
            .u64(8, key)
            .ptr(16, &raw mut current)
            .run(BPF_MAP_LOOKUP_ELEM)
        {
            Ok(_) => 0,
            Err(e) => -e,
        };
        if mode == ROOT_MISSING && lookup == -libc::ENOENT {
            lookup = 0;
        }
        CONSUMED_VALID.store(current.valid as i32, Ordering::Relaxed);
        let ret = real_bpf(BPF_MAP_UPDATE_ELEM, attr, size);
        if lookup != 0 {
            set_errno(-lookup);
            return -1;
        }
        ret
    }
}

/// The bpf() calls of the image's config root: the map of the roots
/// tasks expect, opened, which the staging writes go to, and those
/// writes.
fn hook(number: c_long, a: [c_long; 6]) -> Option<c_long> {
    if number != libc::SYS_bpf {
        return None;
    }
    let attr = a[1] as *mut u8;
    // SAFETY: the caller's bpf() attribute, of the command it names.
    unsafe {
        if a[0] == BPF_OBJ_GET {
            let ret = real_bpf(BPF_OBJ_GET, attr, a[2]);
            let path = attr.cast::<u64>().read_unaligned() as *const c_char;
            if ret >= 0 && CStr::from_ptr(path) == CONFIG_ROOTS {
                ROOTS_FD.store(ret as c_int, Ordering::Relaxed);
            }
            return Some(ret);
        }
        if a[0] == BPF_MAP_UPDATE_ELEM
            && ROOT_MODE.load(Ordering::Relaxed) != ROOT_NORMAL
            && attr.cast::<u32>().read_unaligned() as c_int == ROOTS_FD.load(Ordering::Relaxed)
        {
            return Some(roots_update(attr, a[2]));
        }
    }
    None
}

fn pin(path: &CStr) -> Result<OwnedFd, c_int> {
    Attr::new()
        .ptr(0, path.as_ptr())
        .fd(BPF_OBJ_GET)
        .map_err(|e| -e)
}

fn lookup<K, V>(map: &OwnedFd, key: &K, value: &mut V) -> Result<(), c_int> {
    Attr::new()
        .u32(0, map.as_raw_fd() as u32)
        .ptr(8, key as *const K)
        .ptr(16, value as *mut V as *const V)
        .run(BPF_MAP_LOOKUP_ELEM)
        .map(drop)
        .map_err(|e| -e)
}

/// That this task's expected root was cleared after the mapping.
fn check_root_cleared() -> c_int {
    let map = match pin(CONFIG_ROOTS) {
        Ok(m) => m,
        Err(e) => return e,
    };
    // SAFETY: pidfd_open(2) of this process.
    let task = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
    if task < 0 {
        return -std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
    }
    // SAFETY: the descriptor just made, owned here.
    let task = unsafe { OwnedFd::from_raw_fd(task as c_int) };
    let mut expected = ExpectedRoot::zeroed();
    let mut ret = lookup(&map, &task.as_raw_fd(), &mut expected)
        .err()
        .unwrap_or(0);
    if ROOT_MODE.load(Ordering::Relaxed) == ROOT_MISSING && ret == -libc::ENOENT {
        ret = 0;
    }
    if ret == 0 && (expected.valid != 0 || expected.root != [0; 32]) {
        ret = -libc::EUCLEAN;
    }
    ret
}

/// What the guards' devices map says of the mapping: a config device of
/// its root for this disk sequence when the root was staged right, else
/// none.
fn check_classification(device: &DmVerity) -> c_int {
    let dev = kernel_dev(device.device);
    let path = std::ffi::OsStr::from_bytes(crate::text::cstr(&device.path));
    let block = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(b) => b,
        Err(e) => return -e.raw_os_error().unwrap_or(libc::EIO),
    };
    let mut diskseq = 0u64;
    // SAFETY: the block device and room for its disk sequence.
    if unsafe { libc::ioctl(block.as_raw_fd(), BLKGETDISKSEQ, &mut diskseq) } != 0 {
        return -std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
    }
    let map = match pin(DEVICES) {
        Ok(m) => m,
        Err(e) => return e,
    };
    let mode = ROOT_MODE.load(Ordering::Relaxed);
    let (mut ret, mut matches) = (0, 0u32);
    let mut cursor: Option<u64> = None;
    loop {
        let mut next = 0u64;
        let attr = Attr::new().u32(0, map.as_raw_fd() as u32);
        let attr = match &cursor {
            Some(key) => attr.ptr(8, key as *const u64),
            None => attr,
        };
        match attr
            .ptr(16, (&raw mut next).cast_const())
            .run(BPF_MAP_GET_NEXT_KEY)
        {
            Ok(_) => {}
            Err(libc::ENOENT) => break,
            Err(e) => {
                ret = -e;
                break;
            }
        }
        let mut entry = DeviceAuthority::zeroed();
        if let Err(e) = lookup(&map, &next, &mut entry) {
            ret = e;
            break;
        }
        let root_match = entry.root == device.image.root_hash;
        if entry.dev == dev {
            out(&format!(
                "device={dev} diskseq={diskseq} record_diskseq={} kind={} root_match={}\n",
                entry.diskseq,
                entry.kind,
                c_int::from(root_match)
            ));
        }
        if entry.dev == dev && entry.diskseq == diskseq {
            matches += 1;
            if entry.kind != DEVICE_CONFIG || !root_match {
                ret = -libc::EUCLEAN;
                break;
            }
        }
        cursor = Some(next);
    }
    if ret == 0 && matches != u32::from(mode == ROOT_MATCH) {
        ret = -libc::EACCES;
    }
    out(&format!(
        "classified={matches} consumed_valid={}\n",
        CONSUMED_VALID.load(Ordering::Relaxed)
    ));
    ret
}

fn config_root_test(mode: &[u8], prefix: &CStr) -> c_int {
    let mode = match mode {
        b"missing" => ROOT_MISSING,
        b"wrong" => ROOT_WRONG,
        b"match" => ROOT_MATCH,
        _ => return 2,
    };
    ROOT_MODE.store(mode, Ordering::Relaxed);
    let ret = match ConfigImageOpen::open(prefix, None) {
        Ok(opened) => {
            let mut device = Box::new(DmVerity::empty());
            let name =
                std::ffi::CString::new(format!("shirudo-verify-root-test-{}", std::process::id()))
                    .unwrap_or_default();
            let mut ret = dm_verity::place(dm_verity::create(&opened, &name), &mut device);
            let created = ret == 0;
            let consumed = i32::from(mode == ROOT_WRONG);
            if ret == 0
                && (BEGIN_CALLS.load(Ordering::Relaxed) != 1
                    || END_CALLS.load(Ordering::Relaxed) != 1
                    || CONSUMED_VALID.load(Ordering::Relaxed) != consumed)
            {
                ret = -libc::EUCLEAN;
            }
            if ret == 0 {
                ret = check_root_cleared();
            }
            if ret == 0 {
                ret = dm_verity::verify(&device, &opened);
            }
            if ret == 0 {
                ret = check_classification(&device);
            }
            if created {
                let cleanup = dm_verity::remove(&mut device, true);
                dm_verity::close_loops(&mut device);
                if ret == 0 {
                    ret = cleanup;
                }
            }
            ret
        }
        Err(e) => e,
    };
    if ret != 0 {
        err(&format!("config root test: {}\n", strerror(-ret)));
    }
    c_int::from(ret != 0)
}

/// Cut an archived upatch short, as a torn write could leave it.
fn archive_truncate(name: &CStr) -> c_int {
    let name = name.to_bytes();
    let bytes = [b"/var/lib/shirudo/upatches/".as_slice(), name, b".upatch"].concat();
    if name.contains(&b'/') || bytes.len() >= PATH_MAX {
        return 2;
    }
    let path = match std::ffi::CString::new(bytes) {
        Ok(path) => path,
        Err(_) => return 2,
    };
    // SAFETY: the path is a NUL-terminated string and the size is fixed.
    if unsafe { libc::truncate(path.as_ptr(), 16) } != 0 {
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        let mut message = b"archive truncate: ".to_vec();
        message.extend_from_slice(path.to_bytes());
        message.extend_from_slice(b": ");
        message.extend_from_slice(strerror(errno).as_bytes());
        message.push(b'\n');
        let _ = std::io::stderr().write_all(&message);
        return 1;
    }
    0
}

unsafe extern "C" {
    fn __real_main(argc: c_int, argv: *const *const c_char) -> c_int;
    fn __real_Esys_PCR_Extend(
        context: *mut crate::sys::tss2::EsysContext,
        pcr: crate::sys::tss2::EsysTr,
        first: crate::sys::tss2::EsysTr,
        second: crate::sys::tss2::EsysTr,
        third: crate::sys::tss2::EsysTr,
        digests: *const crate::sys::tss2::DigestValues,
    ) -> crate::sys::tss2::Rc;
}

/// # Safety
///
/// The arguments the C runtime passes main().
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __wrap_main(argc: c_int, argv: *const *const c_char) -> c_int {
    set_syscall_hook(hook);
    // SAFETY: main()'s arguments.
    let args = unsafe { crate::ffi::args(argc, argv) };
    let word = |i: usize| args.get(i).map(|a| a.to_bytes());
    if args.len() == 4 && word(1) == Some(b"config-root") {
        return config_root_test(args[2].to_bytes(), args[3]);
    }
    if args.len() == 3 && word(1) == Some(b"archive-truncate") {
        return archive_truncate(args[2]);
    }
    if args.len() != 4 || word(1) != Some(b"image") || word(2) != Some(b"update") {
        err(
            "usage: shirudo-image-fault image update <prefix>\n       shirudo-image-fault archive-truncate <upatch>\n",
        );
        return 2;
    }
    // SAFETY: shirudo's main, with main()'s arguments.
    unsafe { __real_main(argc, argv) }
}

/// The PCR extend of `image update`, after which the process dies as a
/// crash would leave it.
///
/// # Safety
///
/// As Esys_PCR_Extend().
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __wrap_Esys_PCR_Extend(
    context: *mut crate::sys::tss2::EsysContext,
    pcr: crate::sys::tss2::EsysTr,
    first: crate::sys::tss2::EsysTr,
    second: crate::sys::tss2::EsysTr,
    third: crate::sys::tss2::EsysTr,
    digests: *const crate::sys::tss2::DigestValues,
) -> crate::sys::tss2::Rc {
    // SAFETY: the caller's call, made.
    let ret = unsafe { __real_Esys_PCR_Extend(context, pcr, first, second, third, digests) };
    if ret == 0 {
        // SAFETY: the process gone, as a crash after the extend leaves it.
        unsafe { libc::_exit(99) };
    }
    ret
}
