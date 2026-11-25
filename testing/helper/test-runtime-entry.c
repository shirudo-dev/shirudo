// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util/runtime_entry.h"
#include "test-runtime-entry.h"

static struct shirudo_runtime_entry stored;
static int lookups, writes, freezes, lookup_error, write_error, freeze_error;
static bool corrupt_readback;

int __wrap_bpf_map_lookup_elem(int fd, const void *key, void *value)
{
	assert(fd == 42 && *(__u32 *)key == 0);
	lookups++;
	if (lookup_error) {
		errno = lookup_error;
		return -1;
	}
	memcpy(value, &stored, sizeof(stored));
	if (corrupt_readback && lookups == 2)
		((struct shirudo_runtime_entry *)value)->inodes[0]++;
	return 0;
}

int __wrap_bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags)
{
	assert(fd == 42 && *(__u32 *)key == 0 && flags == 0);
	assert(lookups == 1 && !freezes);
	writes++;
	if (write_error) {
		errno = write_error;
		return -1;
	}
	memcpy(&stored, value, sizeof(stored));
	return 0;
}

int __wrap_bpf_map_freeze(int fd)
{
	assert(fd == 42 && writes == 1);
	freezes++;
	if (freeze_error) {
		errno = freeze_error;
		return -1;
	}
	return 0;
}

static struct shirudo_runtime_entry record(void)
{
	struct shirudo_runtime_entry entry = {
		.version = SHIRUDO_RUNTIME_ENTRY_VERSION,
		.size = sizeof(struct shirudo_runtime_entry),
		.diskseq = 99,
		.dev = 7,
		.count = 2,
		.inodes = { 101, 103 },
	};

	return entry;
}

static void policy(void)
{
	struct shirudo_runtime_entry entry = record(), bad, empty = {};

	assert(sizeof(entry) == 24 + 8 * SHIRUDO_RUNTIME_ENTRY_MAX);
	assert(shirudo_runtime_may_exec(&entry, 101, 7, 99, false, 0));
	/* A tool of the image's usr/bin, bound beside the entry. */
	assert(shirudo_runtime_may_exec(&entry, 103, 7, 99, false, 0));
	assert(!shirudo_runtime_may_exec(&entry, 103, 7, 100, false, 0));
	assert(!shirudo_runtime_may_exec(&entry, 102, 7, 99, false, 0));
	assert(!shirudo_runtime_may_exec(&entry, 101, 8, 99, false, 0));
	assert(!shirudo_runtime_may_exec(&entry, 101, 7, 100, false, 0));
	assert(!shirudo_runtime_may_exec(&entry, 0, 7, 99, true, 7));
	assert(!shirudo_runtime_may_exec(NULL, 101, 7, 99, true, 7));
	assert(!shirudo_runtime_may_exec(&empty, 101, 7, 99, true, 7));
	assert(shirudo_runtime_may_exec(&entry, 102, 7, 99, true, 7));
	assert(!shirudo_runtime_may_exec(&entry, 102, 7, 99, true, 8));
	assert(!shirudo_runtime_may_exec(&entry, 102, 7, 100, true, 7));
	assert(shirudo_runtime_may_exec(&entry, 101, 7, 99, true, 8));
	bad = entry;
	bad.version++;
	assert(!shirudo_runtime_entry_matches(&bad, 7, 99));
	bad = entry;
	bad.size--;
	assert(!shirudo_runtime_entry_matches(&bad, 7, 99));
	bad = entry;
	bad.count = 0;
	assert(!shirudo_runtime_entry_matches(&bad, 7, 99));
	bad = entry;
	bad.count = SHIRUDO_RUNTIME_ENTRY_MAX + 1;
	assert(!shirudo_runtime_entry_matches(&bad, 7, 99));
	bad = entry;
	bad.inodes[0] = 0;
	assert(!shirudo_runtime_entry_matches(&bad, 7, 99));
	bad = entry;
	bad.diskseq = 0;
	assert(!shirudo_runtime_entry_matches(&bad, 7, 0));
	bad = entry;
	bad.dev = 0;
	assert(!shirudo_runtime_entry_matches(&bad, 0, 99));
}

static void reset(void)
{
	memset(&stored, 0, sizeof(stored));
	lookups = 0;
	writes = 0;
	freezes = 0;
	lookup_error = 0;
	write_error = 0;
	freeze_error = 0;
	corrupt_readback = false;
}

static void installation(void)
{
	struct shirudo_runtime_entry entry = record(), empty = {};

	reset();
	assert(shirudo_runtime_entry_install(42, NULL) == -EKEYREJECTED);
	assert(shirudo_runtime_entry_install(42, &empty) == -EKEYREJECTED);
	assert(!lookups && !writes && !freezes);
	assert(!shirudo_runtime_entry_install(42, &entry));
	assert(lookups == 2 && writes == 1 && freezes == 1);
	assert(!memcmp(&stored, &entry, sizeof(entry)));
	assert(shirudo_runtime_entry_install(42, &entry) == -EEXIST);
	assert(writes == 1 && freezes == 1);
	reset();
	stored.size = 32;
	assert(shirudo_runtime_entry_install(42, &entry) == -EEXIST);
	assert(!writes && !freezes);
	reset();
	lookup_error = EIO;
	assert(shirudo_runtime_entry_install(42, &entry) == -EIO);
	assert(!writes && !freezes);
	reset();
	write_error = EPERM;
	assert(shirudo_runtime_entry_install(42, &entry) == -EPERM);
	assert(writes == 1 && !freezes);
	reset();
	freeze_error = EIO;
	assert(shirudo_runtime_entry_install(42, &entry) == -EIO);
	assert(writes == 1 && freezes == 1);
	assert(shirudo_runtime_entry_install(42, &entry) == -EEXIST);
	reset();
	corrupt_readback = true;
	assert(shirudo_runtime_entry_install(42, &entry) == -EKEYREJECTED);
}

int main(int argc, char **argv)
{
	struct shirudo_runtime_entry entry;
	struct stat st;
	int root, ret;

	if (argc == 2 && !strcmp(argv[1], "policy")) {
		policy();
		return 0;
	}
	if (argc == 2 && !strcmp(argv[1], "install")) {
		installation();
		return 0;
	}
	if (argc < 2 || argc > 3)
		return 2;
	root = open(argv[1], O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (root < 0 || fstat(root, &st))
		return 2;
	ret = shirudo_runtime_worker_open(root, st.st_dev + (argc == 3), 99, &entry);
	close(root);
	printf("ret=%d inode=%llu count=%u\n", ret, entry.inodes[0], entry.count);
	return ret ? 1 : 0;
}
