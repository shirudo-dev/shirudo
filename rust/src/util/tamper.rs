// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The tamper counters: what the guards refused this boot, read back
//! from the map init pinned in the private bpffs, and what each point
//! counts; and the reader the integrity counters share.

use core::ffi::{CStr, c_int};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

use crate::sys::libc::errno;
use crate::util::bpf_sys::{bpf_map_lookup_elem, obj_get};
use crate::util::image_guards::{GUARD_MAPS, GUARD_TAMPER, GuardMap, guard_map_check};

/// `TAMPER_MAX` of `bpf/lib/tamper.h`: the tamper points there are.
pub(crate) const TAMPER_MAX: usize = 43;

/// The counters of a guard map: each point's refusals, and their sum,
/// as `struct tamper_counts` and `struct integrity_counts` lay them out.
#[repr(C)]
pub struct Counters<const N: usize> {
    pub(crate) count: [u64; N],
    pub(crate) total: u64,
}

pub(crate) type TamperCounts = Counters<TAMPER_MAX>;

/// A counter: its name, and what it counts.
pub(crate) struct Point {
    pub(crate) name: &'static CStr,
    pub(crate) meaning: &'static CStr,
}

/// Each point, in the order of `enum tamper_point` of bpf/lib/tamper.h,
/// under the member's name, which t6003 checks against the header.
const POINTS: [Point; TAMPER_MAX] = [
    // TAMPER_LOAD_NOT_LOADER
    Point {
        name: c"LoadNotLoader",
        meaning: c"program load that is not a signed loader",
    },
    // TAMPER_LOAD_UNSIGNED
    Point {
        name: c"LoadUnsigned",
        meaning: c"loader-type program load without a signature",
    },
    // TAMPER_LOAD_UNVERIFIED
    Point {
        name: c"LoadUnverified",
        meaning: c"program load whose signature the kernel did not verify",
    },
    // TAMPER_LOAD_KEYRING_KIND
    Point {
        name: c"LoadKeyringKind",
        meaning: c"program signed against a keyring of the wrong kind",
    },
    // TAMPER_LOAD_KEYRING
    Point {
        name: c"LoadKeyring",
        meaning: c"program signed against a keyring that is not the anchor",
    },
    // TAMPER_MAP_CREATE
    Point {
        name: c"MapCreate",
        meaning: c"map creation by another executable",
    },
    // TAMPER_MAP_WRITE
    Point {
        name: c"MapWrite",
        meaning: c"map update or freeze by another executable",
    },
    // TAMPER_MAP_FD
    Point {
        name: c"MapFdWrite",
        meaning: c"writable map descriptor for another executable",
    },
    // TAMPER_PROG_RUN
    Point {
        name: c"ProgRun",
        meaning: c"test run of a program by another executable",
    },
    // TAMPER_ATTACH
    Point {
        name: c"ProgAttach",
        meaning: c"link or raw tracepoint attach by another executable",
    },
    // TAMPER_OBJ_PIN
    Point {
        name: c"ObjPin",
        meaning: c"pin of a BPF object by another executable",
    },
    // TAMPER_BPF_CMD
    Point {
        name: c"BpfCommand",
        meaning: c"detach, update, delete or unclassified bpf() command",
    },
    // TAMPER_EXE_IDENTITY
    Point {
        name: c"ExeIdentity",
        meaning: c"executable change through PR_SET_MM",
    },
    // TAMPER_KEYRING
    Point {
        name: c"KeyringWrite",
        meaning: c"write, unlink, revoke or invalidate on the anchor keyring",
    },
    // TAMPER_PIN_UNLINK
    Point {
        name: c"PinUnlink",
        meaning: c"unlink of a pin in the private bpffs",
    },
    // TAMPER_PIN_RENAME
    Point {
        name: c"PinRename",
        meaning: c"rename of a pin in the private bpffs",
    },
    // TAMPER_PIN_XATTR
    Point {
        name: c"PinXattr",
        meaning: c"xattr change on a pin in the private bpffs",
    },
    // TAMPER_BPFFS_UMOUNT
    Point {
        name: c"BpffsUmount",
        meaning: c"unmount of the private bpffs",
    },
    // TAMPER_BPFFS_UMOUNT_ABOVE
    Point {
        name: c"BpffsUmountAbove",
        meaning: c"unmount of a mount above the private bpffs",
    },
    // TAMPER_BPFFS_MOUNT
    Point {
        name: c"BpffsMount",
        meaning: c"move, mount over or remount of the private bpffs",
    },
    // TAMPER_SEAL_WRITE
    Point {
        name: c"SealWrite",
        meaning: c"write open of a sealed file",
    },
    // TAMPER_SEAL_UNLINK
    Point {
        name: c"SealUnlink",
        meaning: c"unlink of a sealed file or removal of a sealed directory",
    },
    // TAMPER_SEAL_RENAME
    Point {
        name: c"SealRename",
        meaning: c"rename of or over a sealed file",
    },
    // TAMPER_SEAL_SETATTR
    Point {
        name: c"SealSetattr",
        meaning: c"truncate, chmod, chown, utimes or chattr of a sealed file",
    },
    // TAMPER_SEAL_XATTR
    Point {
        name: c"SealXattr",
        meaning: c"xattr or ACL change on a sealed file",
    },
    // TAMPER_SEAL_LABEL
    Point {
        name: c"SealLabel",
        meaning: c"seal or policy label changed by another executable",
    },
    // TAMPER_SEAL_PTRACE
    Point {
        name: c"SealPtrace",
        meaning: c"ptrace of a shirudo task",
    },
    // TAMPER_SEAL_PERF
    Point {
        name: c"SealPerf",
        meaning: c"perf event bound to a shirudo task",
    },
    // TAMPER_EXEC_TRACED
    Point {
        name: c"ExecTraced",
        meaning: c"exec of shirudo by a traced task",
    },
    // TAMPER_SEAL_ENTRY
    Point {
        name: c"SealEntry",
        meaning: c"entry into a sealed directory, or a sealed inode linked",
    },
    // TAMPER_PERF_ATTACH
    Point {
        name: c"PerfAttach",
        meaning: c"program attached to a perf event by another executable",
    },
    // TAMPER_PIN_ENTRY
    Point {
        name: c"PinEntry",
        meaning: c"directory or link made in the private bpffs by another executable",
    },
    // TAMPER_SEAL_COPY_UP
    Point {
        name: c"SealCopyUp",
        meaning: c"overlay copy-up of a sealed inode",
    },
    // TAMPER_KEXEC
    Point {
        name: c"Kexec",
        meaning: c"kexec image or initramfs load",
    },
    // TAMPER_TPM_EXTEND
    Point {
        name: c"TpmExtend",
        meaning: c"extension of shirudo's TPM NV index by another executable",
    },
    // TAMPER_OBJ_GET
    Point {
        name: c"ObjGet",
        meaning: c"pin, map or link opened by another executable",
    },
    // TAMPER_SEAL_SIGNAL
    Point {
        name: c"SealSignal",
        meaning: c"signal to a shirudo task (let through)",
    },
    // TAMPER_SEAL_CORE_DUMP
    Point {
        name: c"SealCoreDump",
        meaning: c"core dump of a shirudo task, which acts without authority",
    },
    // TAMPER_SEAL_UPROBE
    Point {
        name: c"SealUprobe",
        meaning: c"uprobe in a shirudo task, which acts without authority",
    },
    // TAMPER_EXEC_SHARED
    Point {
        name: c"ExecShared",
        meaning: c"exec of the runtime binary by a task that shares its file system context",
    },
    // TAMPER_XATTR_HANDLE
    Point {
        name: c"XattrHandle",
        meaning: c"XFS attribute change by file handle, which passes no xattr hook",
    },
    // TAMPER_SEAL_RLIMIT
    Point {
        name: c"SealRlimit",
        meaning: c"resource limit of a shirudo task changed by another task",
    },
    // SHIRUDO_TAMPER_TPM_WRITE
    Point {
        name: c"TpmWrite",
        meaning: c"protected TPM mutation by an unauthorized task",
    },
];

/// The name of tamper point `point`, "?" past the last.
pub(crate) fn name(point: usize) -> &'static [u8] {
    point_name(&POINTS, point).to_bytes()
}

/// What tamper point `point` counts, "?" past the last.
pub(crate) fn meaning(point: usize) -> &'static [u8] {
    point_meaning(&POINTS, point).to_bytes()
}

pub(crate) fn point_name(points: &[Point], point: usize) -> &'static CStr {
    points.get(point).map_or(c"?", |p| p.name)
}

pub(crate) fn point_meaning(points: &[Point], point: usize) -> &'static CStr {
    points.get(point).map_or(c"?", |p| p.meaning)
}

/// The tamper counters: -ENOENT before init, -EPROTO for a map of another
/// shape, or another -errno.
pub(crate) fn read() -> Result<TamperCounts, c_int> {
    counters_read(&GUARD_MAPS[GUARD_TAMPER])
}

/// The N counters of the array map pinned at `pin`, as read() reads the
/// tamper counters.
pub(crate) fn counters_read<const N: usize>(map: &GuardMap) -> Result<Counters<N>, c_int> {
    let mut count = [0u64; N];
    let total = counters_read_into(map, &mut count)?;
    Ok(Counters { count, total })
}

fn read_map(fd: BorrowedFd<'_>, map: &GuardMap, count: &mut [u64]) -> Result<u64, c_int> {
    guard_map_check(fd.as_raw_fd(), map)?;
    if count.len() != map.def.max_entries as usize {
        return Err(-crate::errno::EPROTO);
    }
    let mut total = 0u64;
    for (key, value) in (0u32..).zip(count.iter_mut()) {
        // SAFETY: the map, a key of its size and room for a value of its size.
        if unsafe {
            bpf_map_lookup_elem(
                fd.as_raw_fd(),
                (&raw const key).cast(),
                (&raw mut *value).cast(),
            )
        } != 0
        {
            return Err(-errno());
        }
        // The C's sum wraps; a counter is the kernel's to set.
        total = total.wrapping_add(*value);
    }
    Ok(total)
}

/// The counters of the array map pinned at `pin` into `count`, as many
/// as it holds, which must be the map's entries: their sum.
fn counters_read_into(map: &GuardMap, count: &mut [u64]) -> Result<u64, c_int> {
    let fd = obj_get(map.pin)?;
    read_map(fd.as_fd(), map, count)
}

#[cfg(test)]
mod tests;
