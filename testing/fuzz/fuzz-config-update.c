// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The config activation history the target keeps in its state: one
 * record as the state file and as an event holds it, and the events file
 * as the replay reads it, line by line.
 */

#include <fcntl.h>
#include <stdlib.h>

#include "fuzz.h"

#include <shirudo/string.h>

#include "config_update.c"

static char dir[4096];
static int dir_fd = -1;

static void remove_dir(void)
{
	unlinkat(dir_fd, "events", 0);
	unlinkat(dir_fd, "next-boot", 0);
	rmdir(dir);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	const char *tmp = getenv("TMPDIR");

	if (strsprintf(dir, sizeof(dir), "%s/shirudo-fuzz-config-update-XXXXXX",
		       tmp && tmp[0] ? tmp : "/tmp") < 0 || !mkdtemp(dir))
		abort();
	dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dir_fd < 0 || atexit(remove_dir))
		abort();
	return 0;
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct config_update update = { .dir_fd = dir_fd, .lock_fd = -1 };
	struct config_update_record record, last;
	__u8 value[32];
	int fd;

	record_decode((const char *)data, size, true, &record);
	record_decode((const char *)data, size, false, &record);
	fd = openat(dir_fd, "events", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		    0600);
	if (fd < 0)
		return 0;
	if (write_complete(fd, data, size)) {
		close(fd);
		return 0;
	}
	close(fd);
	events_scan(&update, &last, value, NULL, false, NULL, NULL);
	events_scan(&update, &last, value, NULL, true, NULL, NULL);
	fd = openat(dir_fd, "next-boot", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		    0600);
	if (fd < 0)
		return 0;
	if (!write_complete(fd, data, size))
		config_update_stage_read(&update, &record);
	close(fd);
	return 0;
}
