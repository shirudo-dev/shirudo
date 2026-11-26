// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Every Rust allocation starts zeroed and is scrubbed before release.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

use crate::sys::libc::{calloc, explicit_bzero, free, posix_memalign};

/// The alignment malloc gives every block on the supported targets.
const MALLOC_ALIGN: usize = 16;

struct Scrubbing;

// SAFETY: the C library allocates and frees every block; Scrubbing hands
// out zeroed blocks of the size and alignment asked, and zeroes a block
// handed back before freeing it.
unsafe impl GlobalAlloc for Scrubbing {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut block = ptr::null_mut();

        if layout.align() <= MALLOC_ALIGN {
            // SAFETY: calloc() takes any size.
            return unsafe { calloc(1, layout.size()) }.cast();
        }
        // SAFETY: a layout's alignment is a power of two, here above 16
        // and so a multiple of the pointer size posix_memalign() needs.
        if unsafe { posix_memalign(&mut block, layout.align(), layout.size()) } != 0 {
            return ptr::null_mut();
        }
        // SAFETY: posix_memalign() gave layout.size() bytes at block.
        unsafe { block.cast::<u8>().write_bytes(0, layout.size()) };
        block.cast()
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        // SAFETY: the caller hands back the layout.size() bytes at block
        // that alloc() gave, and touches them no more.
        unsafe {
            explicit_bzero(block.cast(), layout.size());
            free(block.cast());
        }
    }

    // Allocate a new zeroed block, then scrub and free the old one.
    unsafe fn realloc(&self, block: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: realloc's caller guarantees that new_size with the old
        // alignment is a valid layout.
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        // SAFETY: new_layout is valid and its size not zero.
        let new = unsafe { self.alloc(new_layout) };

        if !new.is_null() {
            // SAFETY: both blocks hold the bytes copied, and only the old
            // one, which the caller hands back, goes.
            unsafe {
                ptr::copy_nonoverlapping(block, new, layout.size().min(new_size));
                self.dealloc(block, layout);
            }
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Scrubbing = Scrubbing;
