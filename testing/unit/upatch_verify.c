// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "unit.h"
#include "upatch.h"
#include "upatch_verify.h"

#define FIXTURE "fuzz/corpus/upatch/xdp-virtual"

/* make -C testing runs from testing/, and by hand from the top of the tree. */
static __u8 *read_fixture(size_t *len)
{
	static __u8 buf[1 << 16];
	FILE *f = fopen(FIXTURE, "r");

	if (!f)
		f = fopen("testing/" FIXTURE, "r");
	ASSERT_TRUE(f);
	*len = fread(buf, 1, sizeof(buf), f);
	fclose(f);
	return buf;
}

static int memfd_of(const __u8 *buf, size_t len)
{
	char path[] = "/tmp/shirudo-unit-verify-XXXXXX";
	int fd = mkstemp(path);

	ASSERT_TRUE(fd >= 0);
	unlink(path);
	ASSERT_EQ(write(fd, buf, len), (ssize_t)len);
	return fd;
}

static void payload_of_fixture(const __u8 *buf, size_t len,
			       __u8 payload[UPATCH_PAYLOAD_HASH_LEN])
{
	int fd = memfd_of(buf, len);
	struct upatch u;

	ASSERT_EQ(upatch_open_fd(fd, &u), 0);
	close(fd);
	memcpy(payload, u.hdr.payload_sha256, UPATCH_PAYLOAD_HASH_LEN);
	upatch_close(&u);
}

static void the_loaded_bytes_verify(void)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN];
	size_t len = 0;
	const __u8 *buf = read_fixture(&len);
	struct upatch u;
	int fd;

	payload_of_fixture(buf, len, payload);
	fd = memfd_of(buf, len);
	ASSERT_EQ(upatch_verify_fd(fd, payload, &u), 0);
	close(fd);
	upatch_close(&u);
}

static void another_payload_is_stale(void)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN];
	size_t len = 0;
	const __u8 *buf = read_fixture(&len);
	struct upatch u;
	int fd;

	payload_of_fixture(buf, len, payload);
	payload[0] ^= 1;
	fd = memfd_of(buf, len);
	EXPECT_EQ(upatch_verify_fd(fd, payload, &u), -ESTALE);
	close(fd);
}

static void changed_data_under_an_intact_header_is_stale(void)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN], copy[1 << 16];
	size_t len = 0, off;
	const __u8 *buf = read_fixture(&len);
	struct upatch u;
	int fd;

	payload_of_fixture(buf, len, payload);
	fd = memfd_of(buf, len);
	ASSERT_EQ(upatch_open_fd(fd, &u), 0);
	close(fd);
	off = u.hdr.data_off;
	ASSERT_TRUE(u.hdr.data_len > 0);
	upatch_close(&u);
	memcpy(copy, buf, len);
	copy[off] ^= 1;
	fd = memfd_of(copy, len);
	EXPECT_EQ(upatch_verify_fd(fd, payload, &u), -ESTALE);
	close(fd);
}

static void a_truncated_file_is_stale(void)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN] = {};
	size_t len = 0;
	const __u8 *buf = read_fixture(&len);
	struct upatch u;
	int fd;

	fd = memfd_of(buf, 64);
	EXPECT_EQ(upatch_verify_fd(fd, payload, &u), -ESTALE);
	close(fd);
}

static void a_missing_archive_is_stale(void)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN] = {};
	struct upatch u;

	EXPECT_EQ(upatch_archive_verify("shirudo-unit-no-such-upatch",
					payload, &u), -ESTALE);
}

static void links_of_a_missing_archive_are_stale(void)
{
	EXPECT_EQ(upatch_links_complete("shirudo-unit-no-such-upatch",
					"/nonexistent/shirudo-unit.upatch"),
		  -ESTALE);
}

static const struct unit_case cases[] = {
	UNIT_CASE(the_loaded_bytes_verify),
	UNIT_CASE(another_payload_is_stale),
	UNIT_CASE(changed_data_under_an_intact_header_is_stale),
	UNIT_CASE(a_truncated_file_is_stale),
	UNIT_CASE(a_missing_archive_is_stale),
	UNIT_CASE(links_of_a_missing_archive_are_stale),
	{}
};

UNIT_SUITE(upatch_verify, cases);
