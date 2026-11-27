// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The guards the initrd installs. Each LSM program has its link pinned
//! in the private bpffs, and they share maps with init. A config image's
//! table loads under the root its task stages here as expected.
//! image_guards_ready() checks, before the runtime trusts them, that each
//! guard is still pinned, attached as an LSM hook to its own function of
//! the kernel's vmlinux, and shares the maps init made.

use core::ffi::{CStr, c_int};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use crate::bpf::btf::{Btf, KIND_FUNC};
use crate::errno::{EBUSY, ENAMETOOLONG, ENOENT, EPROTO, text};
use crate::skel::bpf2::{ExpectedRoot, def};
use crate::sys::libc::{SYS_PIDFD_OPEN, errno, syscall};
use crate::text::cstr;
use crate::util::bpf_info::{Info, LINK_INFO_SIZE, MAP_INFO_SIZE, PROG_INFO_SIZE};
use crate::util::bpf_sys::{
    self, bpf_btf_get_fd_by_id, bpf_map_get_fd_by_id, bpf_map_lookup_elem, bpf_map_update_elem,
    bpf_prog_get_fd_by_id,
};
use crate::util::identity;
use crate::util::kernel_btf;
use crate::util::lskel::MapDef;

/// A program and where its link is pinned.
pub(crate) struct ImageGuard {
    pub(crate) prog: &'static CStr,
    pub(crate) pin: &'static CStr,
}

/// A map the guards share, as bpf2 defines it, and where it is pinned.
pub(crate) struct GuardMap {
    pub(crate) def: MapDef,
    pub(crate) pin: &'static CStr,
}

pub(crate) const SEAL_HOOK_COUNT: usize = 29;
pub(crate) const IMAGE_SEAL_HOOK_COUNT: usize = 2;
pub(crate) const MOUNT_HOOK_COUNT: usize = 6;
pub(crate) const OBSERVER_HOOK_COUNT: usize = 10;
pub(crate) const IMAGE_OBSERVER_HOOK_COUNT: usize = 4;
/// `enum gate_guard`.
pub(crate) const GUARD_UNLINK: usize = 0;
pub(crate) const GUARD_SETXATTR: usize = 1;
pub(crate) const GUARD_REMOVEXATTR: usize = 2;
pub(crate) const GUARD_KEY_PERMISSION: usize = 3;
pub(crate) const GUARD_TPM_COMMAND: usize = 4;
pub(crate) const GUARD_BPF_MAP: usize = 5;
pub(crate) const GUARD_BPF_PROG: usize = 6;
pub(crate) const GUARD_PROG_LOAD: usize = 7;
pub(crate) const GUARD_BPF: usize = 8;
pub(crate) const GATE_HOOK_COUNT: usize = 9;
/// `enum guard_map_index`.
pub(crate) const GUARD_IDENTITY: usize = 0;
pub(crate) const GUARD_TASKS: usize = 1;
pub(crate) const GUARD_DEVICES: usize = 2;
pub(crate) const GUARD_ROOTS: usize = 3;
pub(crate) const GUARD_TAMPER: usize = 4;
pub(crate) const GUARD_INTEGRITY: usize = 7;
pub(crate) const GUARD_MAP_COUNT: usize = 9;

const fn guard_map(def: MapDef, pin: &'static CStr) -> GuardMap {
    GuardMap { def, pin }
}

const fn guard(prog: &'static CStr, pin: &'static CStr) -> ImageGuard {
    ImageGuard { prog, pin }
}

pub(crate) static GATE_GUARDS: [ImageGuard; GATE_HOOK_COUNT] = [
    guard(
        c"shirudo_lsm_inode_unlink",
        c"/run/shirudo/bpffs/bpf2_inode_unlink_link",
    ),
    guard(
        c"shirudo_lsm_inode_setxattr",
        c"/run/shirudo/bpffs/bpf2_inode_setxattr_link",
    ),
    guard(
        c"shirudo_lsm_inode_removexattr",
        c"/run/shirudo/bpffs/bpf2_inode_removexattr_link",
    ),
    guard(
        c"shirudo_lsm_key_permission",
        c"/run/shirudo/bpffs/bpf2_key_permission_link",
    ),
    guard(
        c"shirudo_lsm_tpm_command",
        c"/run/shirudo/bpffs/bpf2_tpm_command_link",
    ),
    guard(
        c"shirudo_lsm_bpf_map",
        c"/run/shirudo/bpffs/bpf2_bpf_map_link",
    ),
    guard(
        c"shirudo_lsm_bpf_prog",
        c"/run/shirudo/bpffs/bpf2_bpf_prog_link",
    ),
    guard(
        c"shirudo_lsm_bpf_prog_load",
        c"/run/shirudo/bpffs/bpf2_bpf_prog_load_link",
    ),
    guard(c"shirudo_lsm_bpf", c"/run/shirudo/bpffs/lsm_link"),
];

pub(crate) static OBSERVER_GUARDS: [ImageGuard; OBSERVER_HOOK_COUNT] = [
    guard(
        c"shirudo_lsm_task_prctl",
        c"/run/shirudo/bpffs/bpf2_task_prctl_link",
    ),
    guard(
        c"shirudo_lsm_bprm_check_security",
        c"/run/shirudo/bpffs/bpf2_bprm_check_security_link",
    ),
    guard(
        c"shirudo_lsm_inode_rmdir",
        c"/run/shirudo/bpffs/inode_rmdir_link",
    ),
    guard(
        c"shirudo_lsm_inode_rename",
        c"/run/shirudo/bpffs/bpf2_inode_rename_link",
    ),
    guard(
        c"shirudo_lsm_inode_mkdir",
        c"/run/shirudo/bpffs/inode_mkdir_link",
    ),
    guard(
        c"shirudo_lsm_inode_symlink",
        c"/run/shirudo/bpffs/inode_symlink_link",
    ),
    guard(
        c"shirudo_lsm_inode_link",
        c"/run/shirudo/bpffs/inode_link_link",
    ),
    guard(
        c"shirudo_lsm_kernel_load_data",
        c"/run/shirudo/bpffs/kernel_load_data_link",
    ),
    guard(
        c"shirudo_lsm_kernel_read_file",
        c"/run/shirudo/bpffs/kernel_read_file_link",
    ),
    guard(
        c"shirudo_lsm_locked_down",
        c"/run/shirudo/bpffs/locked_down_link",
    ),
];

pub(crate) static MOUNT_GUARDS: [ImageGuard; MOUNT_HOOK_COUNT] = [
    guard(
        c"shirudo_lsm_sb_umount",
        c"/run/shirudo/bpffs/bpf2_sb_umount_link",
    ),
    guard(
        c"shirudo_lsm_move_mount",
        c"/run/shirudo/bpffs/bpf2_move_mount_link",
    ),
    guard(
        c"shirudo_lsm_sb_mount",
        c"/run/shirudo/bpffs/bpf2_sb_mount_link",
    ),
    guard(
        c"shirudo_lsm_sb_remount",
        c"/run/shirudo/bpffs/bpf2_sb_remount_link",
    ),
    guard(
        c"shirudo_lsm_sb_pivotroot",
        c"/run/shirudo/bpffs/bpf2_sb_pivotroot_link",
    ),
    guard(
        c"shirudo_lsm_file_open",
        c"/run/shirudo/bpffs/bpf2_file_open_link",
    ),
];

pub(crate) static SEAL_GUARDS: [ImageGuard; SEAL_HOOK_COUNT] = [
    guard(
        c"shirudo_seal_socket_post_create",
        c"/run/shirudo/bpffs/seal_socket_post_create_link",
    ),
    guard(
        c"shirudo_seal_bprm_creds_for_exec",
        c"/run/shirudo/bpffs/seal_bprm_creds_link",
    ),
    guard(
        c"shirudo_seal_bprm_check_security",
        c"/run/shirudo/bpffs/seal_bprm_check_security_link",
    ),
    guard(
        c"shirudo_seal_bprm_committed_creds",
        c"/run/shirudo/bpffs/seal_bprm_committed_creds_link",
    ),
    guard(
        c"shirudo_seal_task_alloc",
        c"/run/shirudo/bpffs/seal_task_alloc_link",
    ),
    guard(
        c"shirudo_seal_file_open",
        c"/run/shirudo/bpffs/seal_file_open_link",
    ),
    guard(
        c"shirudo_seal_inode_unlink",
        c"/run/shirudo/bpffs/seal_inode_unlink_link",
    ),
    guard(
        c"shirudo_seal_inode_rmdir",
        c"/run/shirudo/bpffs/seal_inode_rmdir_link",
    ),
    guard(
        c"shirudo_seal_inode_rename",
        c"/run/shirudo/bpffs/seal_inode_rename_link",
    ),
    guard(
        c"shirudo_seal_inode_setattr",
        c"/run/shirudo/bpffs/seal_inode_setattr_link",
    ),
    guard(
        c"shirudo_seal_inode_file_setattr",
        c"/run/shirudo/bpffs/seal_inode_file_setattr_link",
    ),
    guard(
        c"shirudo_seal_inode_setxattr",
        c"/run/shirudo/bpffs/seal_inode_setxattr_link",
    ),
    guard(
        c"shirudo_seal_inode_removexattr",
        c"/run/shirudo/bpffs/seal_inode_removexattr_link",
    ),
    guard(
        c"shirudo_seal_inode_set_acl",
        c"/run/shirudo/bpffs/seal_inode_set_acl_link",
    ),
    guard(
        c"shirudo_seal_inode_remove_acl",
        c"/run/shirudo/bpffs/seal_inode_remove_acl_link",
    ),
    guard(
        c"shirudo_seal_inode_post_setxattr",
        c"/run/shirudo/bpffs/seal_inode_post_setxattr_link",
    ),
    guard(
        c"shirudo_seal_inode_post_removexattr",
        c"/run/shirudo/bpffs/seal_inode_post_removexattr_link",
    ),
    guard(
        c"shirudo_seal_inode_init_security",
        c"/run/shirudo/bpffs/seal_inode_init_security_link",
    ),
    guard(
        c"shirudo_seal_inode_create",
        c"/run/shirudo/bpffs/seal_inode_create_link",
    ),
    guard(
        c"shirudo_seal_inode_mkdir",
        c"/run/shirudo/bpffs/seal_inode_mkdir_link",
    ),
    guard(
        c"shirudo_seal_inode_symlink",
        c"/run/shirudo/bpffs/seal_inode_symlink_link",
    ),
    guard(
        c"shirudo_seal_inode_mknod",
        c"/run/shirudo/bpffs/seal_inode_mknod_link",
    ),
    guard(
        c"shirudo_seal_inode_link",
        c"/run/shirudo/bpffs/seal_inode_link_link",
    ),
    guard(
        c"shirudo_seal_inode_copy_up",
        c"/run/shirudo/bpffs/seal_inode_copy_up_link",
    ),
    guard(
        c"shirudo_seal_ptrace_access_check",
        c"/run/shirudo/bpffs/seal_ptrace_access_check_link",
    ),
    guard(
        c"shirudo_seal_mm_read_access",
        c"/run/shirudo/bpffs/seal_mm_read_access_link",
    ),
    guard(
        c"shirudo_seal_perf_event_alloc",
        c"/run/shirudo/bpffs/seal_perf_event_alloc_link",
    ),
    guard(
        c"shirudo_seal_task_kill",
        c"/run/shirudo/bpffs/seal_task_kill_link",
    ),
    guard(
        c"shirudo_seal_task_setrlimit",
        c"/run/shirudo/bpffs/seal_task_setrlimit_link",
    ),
];

pub(crate) static IMAGE_SEAL_GUARDS: [ImageGuard; IMAGE_SEAL_HOOK_COUNT] = [
    guard(
        c"shirudo_seal_mmap_file",
        c"/run/shirudo/bpffs/seal_mmap_link",
    ),
    guard(
        c"shirudo_seal_file_mprotect",
        c"/run/shirudo/bpffs/seal_mprotect_link",
    ),
];

pub(crate) static IMAGE_OBSERVER_GUARDS: [ImageGuard; IMAGE_OBSERVER_HOOK_COUNT] = [
    guard(
        c"shirudo_lsm_file_ioctl",
        c"/run/shirudo/bpffs/file_ioctl_link",
    ),
    guard(
        c"shirudo_lsm_file_ioctl_compat",
        c"/run/shirudo/bpffs/file_ioctl_compat_link",
    ),
    guard(
        c"shirudo_lsm_bdev_setintegrity",
        c"/run/shirudo/bpffs/bdev_integrity_link",
    ),
    guard(
        c"shirudo_lsm_bdev_free_security",
        c"/run/shirudo/bpffs/bdev_free_link",
    ),
];

pub(crate) static GUARD_MAPS: [GuardMap; GUARD_MAP_COUNT] = [
    guard_map(def::SHIRUDO_BPFFS_SB, c"/run/shirudo/bpffs/identity"),
    guard_map(def::SHIRUDO_TASKS, c"/run/shirudo/bpffs/task_authority"),
    guard_map(def::SHIRUDO_DEVICES, c"/run/shirudo/bpffs/devices"),
    guard_map(def::SHIRUDO_ROOTS, c"/run/shirudo/bpffs/config_roots"),
    guard_map(def::SHIRUDO_TAMPER, c"/run/shirudo/bpffs/tamper"),
    guard_map(def::SHIRUDO_TASK_POLICY, c"/run/shirudo/bpffs/task_policy"),
    guard_map(
        def::SHIRUDO_SOCK_POLICY,
        c"/run/shirudo/bpffs/socket_policy",
    ),
    guard_map(def::SHIRUDO_INTEGRITY, c"/run/shirudo/bpffs/integrity"),
    guard_map(
        def::SHIRUDO_UNLINK_GRANT,
        c"/run/shirudo/bpffs/unlink_grant",
    ),
];

/// The map and task descriptor kept open while a config root is staged.
#[derive(Default)]
pub(crate) struct ConfigRootGuard {
    map: Option<OwnedFd>,
    task: Option<OwnedFd>,
}

const BPF_ANY: u64 = 0;

/// Stages `root` as the one this task expects the config image's table
/// to carry, while the guards enforce: initial authenticated boot maps
/// its images before the guards exist. 0, -EBUSY with a root staged
/// already, or -errno.
pub(crate) fn config_root_begin(root: &[u8; 32], guard: &mut ConfigRootGuard) -> c_int {
    *guard = ConfigRootGuard::default();
    let mode = identity::enforcement_active();
    if mode <= 0 {
        return mode;
    }
    let map = match bpf_sys::obj_get(GUARD_MAPS[GUARD_ROOTS].pin) {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    let checked = guard_map_check(map.as_fd(), &GUARD_MAPS[GUARD_ROOTS]);
    guard.map = Some(map);
    let ret = match checked {
        Ok(_) => stage(root, guard),
        Err(e) => e,
    };
    if ret != 0 {
        *guard = ConfigRootGuard::default();
    }
    ret
}

fn stage(root: &[u8; 32], guard: &mut ConfigRootGuard) -> c_int {
    let Some(map) = guard.map.as_ref() else {
        return -EPROTO;
    };
    // SAFETY: pidfd_open() of this process.
    let fd = unsafe { syscall(SYS_PIDFD_OPEN, std::process::id() as c_int, 0 as c_int) } as c_int;
    if fd < 0 {
        return -errno();
    }
    // SAFETY: pidfd_open made this descriptor, and the guard owns it.
    let task = unsafe { OwnedFd::from_raw_fd(fd) };
    let task_fd = task.as_raw_fd();
    let map_fd = map.as_raw_fd();
    guard.task = Some(task);
    let mut previous = ExpectedRoot {
        root: [0; 32],
        valid: 0,
    };
    // SAFETY: the map, a task key and room for its value.
    if unsafe {
        bpf_map_lookup_elem(
            map_fd,
            (&raw const task_fd).cast(),
            (&raw mut previous).cast(),
        )
    } != 0
    {
        if errno() != ENOENT {
            return -errno();
        }
    } else if previous.valid != 0 {
        return -EBUSY;
    }
    let expected = ExpectedRoot {
        root: *root,
        valid: 1,
    };
    // SAFETY: the map, a task key and a value of its size.
    if unsafe {
        bpf_map_update_elem(
            map_fd,
            (&raw const task_fd).cast(),
            (&raw const expected).cast(),
            BPF_ANY,
        )
    } != 0
    {
        return -errno();
    }
    0
}

/// Takes the staged root back through the descriptors begin kept, on
/// every exit: 0, or -errno when it could not be cleared.
pub(crate) fn config_root_end(guard: &mut ConfigRootGuard) -> c_int {
    let Some(map) = guard.map.as_ref() else {
        return 0;
    };
    let Some(task) = guard.task.as_ref() else {
        *guard = ConfigRootGuard::default();
        return -EPROTO;
    };
    let task_fd = task.as_raw_fd();
    let empty = ExpectedRoot {
        root: [0; 32],
        valid: 0,
    };
    // SAFETY: the map, a task key and a value of its size.
    let ret = if unsafe {
        bpf_map_update_elem(
            map.as_raw_fd(),
            (&raw const task_fd).cast(),
            (&raw const empty).cast(),
            BPF_ANY,
        )
    } != 0
    {
        -errno()
    } else {
        0
    };
    *guard = ConfigRootGuard::default();
    ret
}

/// `struct bpf_map_info`, `struct bpf_prog_info`, `struct bpf_link_info`
/// and `struct bpf_btf_info`: where the fields checked here sit.
const MAP_TYPE: usize = 0;
const MAP_ID: usize = 4;
const MAP_KEY_SIZE: usize = 8;
const MAP_VALUE_SIZE: usize = 12;
const MAP_MAX_ENTRIES: usize = 16;
const MAP_FLAGS: usize = 20;
const MAP_NAME: usize = 24;
const PROG_TYPE: usize = 0;
const PROG_ID: usize = 4;
const PROG_NR_MAP_IDS: usize = 52;
const PROG_MAP_IDS: usize = 56;
const PROG_NAME: usize = 64;
const PROG_ATTACH_BTF_OBJ_ID: usize = 220;
const PROG_ATTACH_BTF_ID: usize = 224;
const LINK_TYPE: usize = 0;
const LINK_ID: usize = 4;
const LINK_PROG_ID: usize = 8;
const LINK_ATTACH_TYPE: usize = 16;
const LINK_TARGET_OBJ_ID: usize = 20;
const LINK_TARGET_BTF_ID: usize = 24;
const BTF_INFO_SIZE: usize = 32;
const BTF_NAME: usize = 16;
const BTF_NAME_LEN: usize = 24;
const BTF_KERNEL: usize = 28;
/// BPF_OBJ_NAME_LEN, and the map IDs a guard program may hold.
const OBJ_NAME_LEN: usize = 16;
const MAX_PROG_MAPS: usize = 16;
const BPF_LINK_TYPE_TRACING: u32 = 2;
const BPF_LSM_MAC: u32 = 27;
const BPF_PROG_TYPE_LSM: u32 = 29;

fn obj_name(info: &[u8], off: usize) -> &[u8] {
    &info[off..off + OBJ_NAME_LEN]
}

/// Refuse a pin of another map shape before passing a key or value buffer to
/// the kernel. A per-CPU map of the same value size needs a larger buffer.
fn guard_map_matches(info: &Info<MAP_INFO_SIZE>, expected: &GuardMap) -> bool {
    let def = &expected.def;
    info.u32_at(MAP_ID) != 0
        && info.u32_at(MAP_TYPE) == def.map_type
        && info.u32_at(MAP_KEY_SIZE) == def.key_size
        && info.u32_at(MAP_VALUE_SIZE) == def.value_size
        && info.u32_at(MAP_MAX_ENTRIES) == def.max_entries
        && info.u32_at(MAP_FLAGS) == def.flags
        && identity::guard_name_matches(obj_name(info.bytes(), MAP_NAME), def.name)
}

pub(crate) fn guard_map_check(fd: BorrowedFd<'_>, expected: &GuardMap) -> Result<u32, c_int> {
    let mut info = Info::<MAP_INFO_SIZE>::new();
    info.read(fd.as_raw_fd())?;
    if !guard_map_matches(&info, expected) {
        return Err(-EPROTO);
    }
    Ok(info.u32_at(MAP_ID))
}

/// Own a descriptor returned by a BPF id lookup, or keep its errno.
fn opened_fd(fd: c_int) -> Result<OwnedFd, c_int> {
    if fd < 0 {
        return Err(-errno());
    }
    // SAFETY: the lookup made this descriptor; the owner closes it once.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The IDs of the maps the guards share, each checked against its pin's
/// expected shape and name.
fn guard_map_ids() -> Result<[u32; GUARD_MAP_COUNT], c_int> {
    let mut ids = [0u32; GUARD_MAP_COUNT];
    for (id, expected) in ids.iter_mut().zip(&GUARD_MAPS) {
        let fd = bpf_sys::obj_get(expected.pin)?;
        let checked = guard_map_check(fd.as_fd(), expected);
        match checked {
            Ok(found) => *id = found,
            Err(e) => {
                crate::log::err(
                    &[
                        &b"image: invalid guard map "[..],
                        expected.pin.to_bytes(),
                        b": ",
                        text(e).as_bytes(),
                    ]
                    .concat(),
                );
                return Err(e);
            }
        }
    }
    Ok(ids)
}

/// Whether each of the program's maps that bears a shared map's name is
/// the one pinned: 0, -EPROTO, or -errno.
fn guard_program_maps(map_ids: &[u32], expected: &[u32; GUARD_MAP_COUNT]) -> c_int {
    for &id in map_ids {
        let fd = match opened_fd(bpf_map_get_fd_by_id(id)) {
            Ok(fd) => fd,
            Err(e) => return e,
        };
        let mut info = Info::<MAP_INFO_SIZE>::new();
        let read = info.read(fd.as_raw_fd());
        if let Err(e) = read {
            return e;
        }
        let name = obj_name(info.bytes(), MAP_NAME);
        let mismatch = GUARD_MAPS.iter().zip(expected).any(|(m, &want)| {
            identity::guard_name_matches(name, m.def.name) && info.u32_at(MAP_ID) != want
        });
        if mismatch {
            return -EPROTO;
        }
    }
    0
}

/// The kernel's vmlinux BTF of object `id`, or -errno: -EPROTO for one
/// that is a module's or not the kernel's.
fn guard_kernel_btf(id: u32) -> Result<Btf, c_int> {
    let fd = opened_fd(bpf_btf_get_fd_by_id(id))?;
    let mut name = [0u8; 16];
    let mut info = Info::<BTF_INFO_SIZE>::new();
    info.set(BTF_NAME, &(name.as_mut_ptr() as u64).to_ne_bytes());
    info.set(BTF_NAME_LEN, &(name.len() as u32).to_ne_bytes());
    let read = info.read(fd.as_raw_fd());
    read?;
    if info.u32_at(BTF_KERNEL) == 0 || !name.contains(&0) || cstr(&name) != b"vmlinux" {
        return Err(-EPROTO);
    }
    kernel_btf::by_id(id)
}

/// The vmlinux BTF the guards attach through, loaded with the first.
struct Kernel {
    btf: Option<Btf>,
    id: u32,
}

/// Whether the guard's link is pinned, an LSM link of its own program,
/// attached to bpf_lsm_<hook> of the vmlinux BTF, and its program shares
/// the maps `maps` names: 0, -EPROTO, or -errno.
fn guard_link(guard: &ImageGuard, maps: &[u32; GUARD_MAP_COUNT], kernel: &mut Kernel) -> c_int {
    let fd = match bpf_sys::obj_get(guard.pin) {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    let mut link = Info::<LINK_INFO_SIZE>::new();
    let read = link.read(fd.as_raw_fd());
    if let Err(e) = read {
        return e;
    }
    if link.u32_at(LINK_TYPE) != BPF_LINK_TYPE_TRACING
        || link.u32_at(LINK_ID) == 0
        || link.u32_at(LINK_PROG_ID) == 0
        || link.u32_at(LINK_ATTACH_TYPE) != BPF_LSM_MAC
    {
        return -EPROTO;
    }
    let prog = match opened_fd(bpf_prog_get_fd_by_id(link.u32_at(LINK_PROG_ID))) {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    let mut map_ids = [0u32; MAX_PROG_MAPS];
    let mut program = Info::<PROG_INFO_SIZE>::new();
    program.set(PROG_MAP_IDS, &(map_ids.as_mut_ptr() as u64).to_ne_bytes());
    program.set(PROG_NR_MAP_IDS, &(MAX_PROG_MAPS as u32).to_ne_bytes());
    let read = program.read(prog.as_raw_fd());
    if let Err(e) = read {
        return e;
    }
    let btf_id = program.u32_at(PROG_ATTACH_BTF_ID);
    let obj_id = program.u32_at(PROG_ATTACH_BTF_OBJ_ID);
    let nr_maps = program.u32_at(PROG_NR_MAP_IDS) as usize;
    if program.u32_at(PROG_TYPE) != BPF_PROG_TYPE_LSM
        || btf_id == 0
        || obj_id == 0
        || program.u32_at(PROG_ID) != link.u32_at(LINK_PROG_ID)
        || nr_maps > MAX_PROG_MAPS
        || !identity::guard_name_matches(obj_name(program.bytes(), PROG_NAME), guard.prog)
        || link.u32_at(LINK_TARGET_OBJ_ID) != obj_id
        || link.u32_at(LINK_TARGET_BTF_ID) != btf_id
    {
        return -EPROTO;
    }
    if kernel.btf.is_none() {
        match guard_kernel_btf(obj_id) {
            Ok(btf) => {
                *kernel = Kernel {
                    btf: Some(btf),
                    id: obj_id,
                }
            }
            Err(e) => return e,
        }
    }
    if kernel.id != obj_id {
        return -EPROTO;
    }
    let prog_name = guard.prog.to_bytes();
    let hook = prog_name
        .strip_prefix(b"shirudo_lsm_")
        .unwrap_or(&prog_name[13.min(prog_name.len())..]);
    let function = [&b"bpf_lsm_"[..], hook].concat();
    if function.len() >= 96 {
        return -ENAMETOOLONG;
    }
    let type_id = kernel
        .btf
        .as_ref()
        .and_then(|b| b.find_by_name_kind(&function, KIND_FUNC));
    if type_id.is_none_or(|t| t == 0 || t != btf_id) {
        return -EPROTO;
    }
    guard_program_maps(&map_ids[..nr_maps], maps)
}

/// Whether every guard the initrd installs is pinned, attached and
/// sharing the maps init made, as it left them: 0, or -errno with the
/// first guard that is not.
pub(crate) fn image_guards_ready() -> c_int {
    let maps = match guard_map_ids() {
        Ok(m) => m,
        Err(e) => return e,
    };
    let mut kernel = Kernel { btf: None, id: 0 };
    let groups: [&[ImageGuard]; 6] = [
        &GATE_GUARDS,
        &OBSERVER_GUARDS,
        &MOUNT_GUARDS,
        &SEAL_GUARDS,
        &IMAGE_SEAL_GUARDS,
        &IMAGE_OBSERVER_GUARDS,
    ];
    for guard in groups.iter().flat_map(|g| g.iter()) {
        let ret = guard_link(guard, &maps, &mut kernel);
        if ret != 0 {
            crate::log::err(
                &[
                    &b"image: missing or invalid guard "[..],
                    guard.pin.to_bytes(),
                    b": ",
                    text(ret).as_bytes(),
                ]
                .concat(),
            );
            return ret;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::{
        GUARD_MAPS, MAP_FLAGS, MAP_ID, MAP_KEY_SIZE, MAP_MAX_ENTRIES, MAP_NAME, MAP_TYPE,
        MAP_VALUE_SIZE, guard_map_matches,
    };
    use crate::util::bpf_info::{Info, MAP_INFO_SIZE};

    fn set_u32(info: &mut Info<MAP_INFO_SIZE>, offset: usize, value: u32) {
        info.set(offset, &value.to_ne_bytes());
    }

    #[test]
    fn pinned_map_shape_requires_every_field() {
        for map in &GUARD_MAPS {
            let mut info = Info::<MAP_INFO_SIZE>::new();
            let def = &map.def;
            set_u32(&mut info, MAP_ID, 1);
            set_u32(&mut info, MAP_TYPE, def.map_type);
            set_u32(&mut info, MAP_KEY_SIZE, def.key_size);
            set_u32(&mut info, MAP_VALUE_SIZE, def.value_size);
            set_u32(&mut info, MAP_MAX_ENTRIES, def.max_entries);
            set_u32(&mut info, MAP_FLAGS, def.flags);
            let name = def.name.to_bytes();
            info.set(MAP_NAME, &name[..name.len().min(15)]);
            assert!(guard_map_matches(&info, map));

            for (offset, value) in [
                (MAP_ID, 0),
                (MAP_TYPE, def.map_type ^ 1),
                (MAP_KEY_SIZE, def.key_size ^ 1),
                (MAP_VALUE_SIZE, def.value_size ^ 1),
                (MAP_MAX_ENTRIES, def.max_entries ^ 1),
                (MAP_FLAGS, def.flags ^ 1),
            ] {
                let mut altered = Info::<MAP_INFO_SIZE>::new();
                altered.set(0, info.bytes());
                set_u32(&mut altered, offset, value);
                assert!(!guard_map_matches(&altered, map));
            }
            let mut altered = Info::<MAP_INFO_SIZE>::new();
            altered.set(0, info.bytes());
            altered.set(MAP_NAME, b"wrong");
            assert!(!guard_map_matches(&altered, map));
        }
    }
}
