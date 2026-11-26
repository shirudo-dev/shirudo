/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_TEST_ARCHIVE_H
#define SHIRUDO_TEST_ARCHIVE_H

#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include <linux/types.h>

#include <shirudo/string.h>

#include "unit.h"

/* One member of a test .bee: of type '0' a file with body, of '5' a directory. */
struct archive_member {
	const char	*name;
	char		type;
	const char	*body;
};

/* The members as a gzip'd ustar, which replaces what fd holds. */
static inline void archive_write(int fd, const struct archive_member *m, int n)
{
	static const __u8 zero[1024];
	gzFile gz;
	int copy;

	ASSERT_EQ(ftruncate(fd, 0), 0);
	ASSERT_EQ(lseek(fd, 0, SEEK_SET), 0);
	copy = dup(fd);
	ASSERT_TRUE(copy >= 0);
	gz = gzdopen(copy, "wb");
	ASSERT_TRUE(gz);
	for (int i = 0; i < n; i++) {
		__u32 len = m[i].body ? (__u32)strlen(m[i].body) : 0;
		__u32 pad = (512 - len % 512) % 512, sum = 0;
		__u8 h[512] = {};

		ASSERT_TRUE(strsprintf((char *)h, 100, "%s", m[i].name) > 0);
		ASSERT_TRUE(strsprintf((char *)h + 100, 8, "%07o", 0644) > 0);
		ASSERT_TRUE(strsprintf((char *)h + 124, 12, "%011o", len) > 0);
		memset(h + 148, ' ', 8);
		h[156] = (__u8)m[i].type;
		memcpy(h + 257, "ustar", 6);
		for (size_t j = 0; j < sizeof(h); j++)
			sum += h[j];
		ASSERT_TRUE(strsprintf((char *)h + 148, 7, "%06o", sum) > 0);
		ASSERT_EQ(gzwrite(gz, h, sizeof(h)), (int)sizeof(h));
		if (len)
			ASSERT_EQ(gzwrite(gz, m[i].body, len), (int)len);
		if (pad)
			ASSERT_EQ(gzwrite(gz, zero, pad), (int)pad);
	}
	ASSERT_EQ(gzwrite(gz, zero, sizeof(zero)), (int)sizeof(zero));
	ASSERT_EQ(gzclose(gz), Z_OK);
}

#endif /* SHIRUDO_TEST_ARCHIVE_H */
