// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The light skeletons of bpf2 and the seal, which init loads: the Rust
//! tools/bpf-lskel writes of each (bpf/*.skel.rs) when it generates the
//! loader, which that Rust embeds. Their map types are read from the
//! objects' BTF, so a layout the BPF C changes fails this build instead
//! of a boot; the seal names bpf2's types where they are laid out alike,
//! and takes bpf2's maps as `seal::Shared`, of those types.

/// bpf2: the guards, their maps and the identity the seal shares.
#[allow(dead_code)] // the skeleton has what bpf2 has; init uses some
pub(crate) mod bpf2 {
    include!("../../bpf/bpf2.skel.rs");
}

/// The seal: its hooks, its own maps, and bpf2's it takes.
#[allow(dead_code)]
pub(crate) mod seal {
    include!("../../bpf/seal.skel.rs");
}

use core::ffi::c_char;

/// An embedded skeleton, which the test helper test-mode-objects
/// inspects through bpf2_blob() and seal_blob().
pub struct EmbeddedBpf {
    name: *const c_char,
    #[cfg(feature = "test-helpers")]
    data: *const u8,
    size: usize,
}

// SAFETY: static C strings and static bytes, which nothing writes.
unsafe impl Sync for EmbeddedBpf {}

static BPF2_BLOB: EmbeddedBpf = EmbeddedBpf {
    name: c"bpf2".as_ptr(),
    #[cfg(feature = "test-helpers")]
    data: bpf2::LOADER.as_ptr(),
    size: bpf2::LOADER.len(),
};

static SEAL_BLOB: EmbeddedBpf = EmbeddedBpf {
    name: c"seal".as_ptr(),
    #[cfg(feature = "test-helpers")]
    data: seal::LOADER.as_ptr(),
    size: seal::LOADER.len(),
};

impl EmbeddedBpf {
    /// Its name, bpf2 or seal.
    pub(crate) fn name(&self) -> &'static [u8] {
        // SAFETY: a static C string of this module.
        unsafe { crate::ffi::c_str(self.name) }
    }

    /// The light skeleton's bytes.
    #[cfg(feature = "test-helpers")]
    pub(crate) fn data(&self) -> &'static [u8] {
        // SAFETY: a static slice of this module, as its size says.
        unsafe { crate::ffi::slice(self.data, self.size) }
    }

    /// Whether this build embeds no loader for it.
    pub(crate) fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// The LSM hooks its programs attach to, or none for an object this
    /// build does not embed.
    pub(crate) fn lsm_hooks(&self) -> Option<&'static [&'static str]> {
        if core::ptr::eq(self, &BPF2_BLOB) {
            Some(bpf2::LSM_HOOKS)
        } else if core::ptr::eq(self, &SEAL_BLOB) {
            Some(seal::LSM_HOOKS)
        } else {
            None
        }
    }
}

/// The objects init loads, bpf2 first.
pub(crate) fn embedded() -> [&'static EmbeddedBpf; 2] {
    [&BPF2_BLOB, &SEAL_BLOB]
}
