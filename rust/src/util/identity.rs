// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The identity init froze into the kernel this boot, read back from the
//! map it pinned in the private bpffs, and whether the boot enforces.

use core::ffi::{CStr, c_int};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use crate::errno::{EINVAL, ENOSYS, EPROTO, EXDEV};
use crate::sys::identity::Identity;
use crate::sys::libc::{O_CLOEXEC, O_DIRECTORY, O_RDONLY, S_IFDIR, S_IFMT, errno, open, prctl};
use crate::util::bpf_sys::{bpf_map_lookup_elem, obj_get, obj_get_at};
use crate::util::image_guards::{GUARD_IDENTITY, GUARD_MAPS, guard_map_check};
use crate::util::io::{kernel_dev, stat_fd};
use crate::util::seal;

/// IDENTITY_PIN of util/paths.h.
pub(crate) const IDENTITY_PIN: &CStr = c"/run/shirudo/bpffs/identity";
/// The root of the private bpffs and the identity pin under it.
const BPFFS_DIR: &CStr = c"/run/shirudo/bpffs";
const IDENTITY_PIN_NAME: &CStr = c"identity";
/// PR_GET_ENFORCEMENT and PR_ENFORCING_ERR of include/shirudo/enforcement.h.
const PR_GET_ENFORCEMENT: c_int = 0x5352_0001;
const PR_ENFORCING_ERR: c_int = 1002;
/// Whether a 16-byte kernel BPF object name is the complete expected
/// name, or the kernel's 15-byte truncation of it.
pub(crate) fn guard_name_matches(name: &[u8], expected: &CStr) -> bool {
    let Some(name) = name.get(..16) else {
        return false;
    };
    let Some(len) = name.iter().position(|&c| c == 0) else {
        return false;
    };
    let expected = expected.to_bytes();
    let expected_len = expected.len().min(15);

    len == expected_len && name[..len] == expected[..expected_len]
}

/// Whether this boot enforces, as the kernel's prctl answers: 1, 0 for a
/// kernel that does not know the question, or -errno.
pub(crate) fn enforcement_active() -> c_int {
    // SAFETY: a query that takes no pointer.
    if unsafe { prctl(PR_GET_ENFORCEMENT, 0, 0, 0, 0) } >= 0 {
        return -EPROTO;
    }
    match errno() {
        PR_ENFORCING_ERR => 1,
        EINVAL | ENOSYS => 0,
        e => -e,
    }
}

/// The identity init populated, froze and pinned this boot: -ENOENT
/// before init, -EPROTO for a map of another shape, or another -errno.
pub(crate) fn read() -> Result<Identity, c_int> {
    let fd = obj_get(IDENTITY_PIN)?;
    lookup(fd.as_fd())
}

/// The identity pin `name` relative to an already opened directory.
pub(crate) fn read_at(dir: BorrowedFd<'_>, name: &CStr) -> Result<Identity, c_int> {
    let fd = obj_get_at(dir, name)?;
    lookup(fd.as_fd())
}

/// The private bpffs root, checked against the device init froze in its
/// identity map. A mount over /run/shirudo may hide that root; it does
/// not make another directory into this boot's bpffs.
fn bpffs_open_identity() -> Result<(OwnedFd, Identity), c_int> {
    // SAFETY: a C path, flags without a creation mode.
    let fd = unsafe { open(BPFFS_DIR.as_ptr(), O_RDONLY | O_DIRECTORY | O_CLOEXEC) };
    if fd < 0 {
        return Err(-errno());
    }
    // SAFETY: open returned a new descriptor owned here alone.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let id = read_at(fd.as_fd(), IDENTITY_PIN_NAME)?;
    let st = stat_fd(fd.as_fd())?;
    let dev = kernel_dev(libc::makedev(st.stx_dev_major, st.stx_dev_minor));
    if dev != id.sb_dev {
        return Err(-EXDEV);
    }
    Ok((fd, id))
}

pub(crate) fn bpffs_root_open() -> Result<OwnedFd, c_int> {
    bpffs_open_identity().map(|(fd, _)| fd)
}

/// Require the opened state root to be the directory init recorded.
pub(crate) fn check_state_root(id: &Identity, fd: BorrowedFd<'_>) -> Result<(), c_int> {
    let st = stat_fd(fd)?;
    let dev = libc::makedev(st.stx_dev_major, st.stx_dev_minor);
    if st.stx_mode & S_IFMT != S_IFDIR || dev != id.state_dev || st.stx_ino != id.state_ino {
        return Err(-EXDEV);
    }
    Ok(())
}

/// The writable state directory init sealed and recorded for this boot.
pub(crate) fn state_root_open() -> Result<OwnedFd, c_int> {
    let (_, id) = bpffs_open_identity()?;
    let fd = seal::open_state_root()?;
    check_state_root(&id, fd.as_fd())?;
    Ok(fd)
}

fn lookup(fd: BorrowedFd<'_>) -> Result<Identity, c_int> {
    guard_map_check(fd, &GUARD_MAPS[GUARD_IDENTITY])?;
    let zero = 0u32;
    let mut id = Identity::zeroed();
    // SAFETY: the map, a key of its size, and room for a value of its
    // size, checked above.
    if unsafe {
        bpf_map_lookup_elem(
            fd.as_raw_fd(),
            (&raw const zero).cast(),
            (&raw mut id).cast(),
        )
    } != 0
    {
        return Err(-errno());
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::guard_name_matches;

    fn kernel_name(raw: &[u8]) -> [u8; 16] {
        let mut name = [0u8; 16];
        name[..raw.len()].copy_from_slice(raw);
        name
    }

    #[test]
    fn state_root_requires_recorded_directory() {
        use crate::sys::identity::Identity;
        use crate::util::io::stat_fd;
        use std::os::fd::AsFd;

        let root = std::fs::File::open(".").unwrap();
        let other = std::fs::File::open("..").unwrap();
        let st = stat_fd(root.as_fd()).unwrap();
        let mut id = Identity::zeroed();
        id.state_dev = libc::makedev(st.stx_dev_major, st.stx_dev_minor);
        id.state_ino = st.stx_ino;
        assert_eq!(super::check_state_root(&id, root.as_fd()), Ok(()));
        assert_eq!(
            super::check_state_root(&id, other.as_fd()),
            Err(-crate::errno::EXDEV)
        );
        id.state_dev += 1;
        assert_eq!(
            super::check_state_root(&id, root.as_fd()),
            Err(-crate::errno::EXDEV)
        );
    }

    #[test]
    fn kernel_name_is_the_start_of_a_long_one() {
        let name = kernel_name(b"shirudo_bpffs_s");

        assert!(guard_name_matches(&name, c"shirudo_bpffs_sb"));
        assert!(guard_name_matches(&name, c"shirudo_bpffs_s"));
        assert!(guard_name_matches(&name, c"shirudo_bpffs_s_and_more"));
        assert!(!guard_name_matches(&name, c"shirudo_bpffs_"));
        assert!(!guard_name_matches(&name, c"shirudo_bpffs_x"));
        assert!(!guard_name_matches(&name, c""));
    }

    #[test]
    fn short_name_is_the_whole_one() {
        let name = kernel_name(b"shirudo_tasks");

        assert!(guard_name_matches(&name, c"shirudo_tasks"));
        assert!(!guard_name_matches(&name, c"shirudo_task"));
        assert!(!guard_name_matches(&name, c"shirudo_tasks_"));
        assert!(!guard_name_matches(&name, c"shirudo_task_policy"));
        assert!(!guard_name_matches(&name, c"SHIRUDO_TASKS"));
    }

    #[test]
    fn unterminated_name_matches_nothing() {
        let name = [b'x'; 16];

        assert!(!guard_name_matches(&name, c"xxxxxxxxxxxxxxx"));
        assert!(!guard_name_matches(&name, c"xxxxxxxxxxxxxxxx"));
        assert!(guard_name_matches(&[0; 16], c""));
        assert!(!guard_name_matches(&[0; 16], c"x"));
    }
}
