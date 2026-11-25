/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_RUNTIME_ENTRY_ABI_H
#define SHIRUDO_RUNTIME_ENTRY_ABI_H

#define SHIRUDO_RUNTIME_ENTRY_VERSION 2
#define SHIRUDO_RUNTIME_ENTRY_MAX 16

/*
 * The verified runtime mapping and the executables of its usr/bin: the
 * entry usr/bin/shirudo first, then the image's other tools by inode.
 * Exec of one of them is what grants a fresh full task role; the image's
 * loader and libraries live outside usr/bin and grant none.
 */
struct shirudo_runtime_entry {
	__u32 version;
	__u32 size;
	__u64 diskseq;
	__u32 dev;
	__u32 count;
	__u64 inodes[SHIRUDO_RUNTIME_ENTRY_MAX];
};

static __always_inline bool
shirudo_runtime_entry_matches(const struct shirudo_runtime_entry *entry,
			      __u32 dev, __u64 diskseq)
{
	return entry && entry->version == SHIRUDO_RUNTIME_ENTRY_VERSION &&
	       entry->size == sizeof(*entry) && entry->count &&
	       entry->count <= SHIRUDO_RUNTIME_ENTRY_MAX && entry->inodes[0] &&
	       entry->dev && entry->dev == dev && entry->diskseq &&
	       entry->diskseq == diskseq;
}

static __always_inline bool
shirudo_runtime_entry_binds(const struct shirudo_runtime_entry *entry,
			    __u64 inode)
{
	__u32 i;

	for (i = 0; i < SHIRUDO_RUNTIME_ENTRY_MAX; i++) {
		if (i < entry->count && entry->inodes[i] == inode)
			return true;
	}
	return false;
}

static __always_inline bool
shirudo_runtime_may_exec(const struct shirudo_runtime_entry *entry,
			 __u64 inode, __u32 dev, __u64 diskseq,
			 bool trusted, __u32 current_dev)
{
	return inode && shirudo_runtime_entry_matches(entry, dev, diskseq) &&
	       (shirudo_runtime_entry_binds(entry, inode) ||
		(trusted && current_dev == dev));
}

#endif /* SHIRUDO_RUNTIME_ENTRY_ABI_H */
