// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stddef.h>
#include <sys/syscall.h>

#include <linux/keyctl.h>

#include <shirudo/types.h>

#include "keyring.h"
#include "malloc.h"
#include "unit.h"

/*
 * keyring_links() reads a keyring, then reads it again with the size the
 * kernel said it needed. A test cannot link a key between the reads, so
 * these answer KEYCTL_READ from a keyring that grows as the case asks,
 * and let every other syscall through.
 */
static size_t fake_links;
static __u32 fake_grows;

long __wrap_syscall(long number, long arg1, long arg2, long arg3, long arg4,
		    long arg5)
{
	key_serial_t *serials = (key_serial_t *)arg3;
	size_t cap = (size_t)arg4;
	size_t bytes, i;

	if (number != __NR_keyctl || (int)arg1 != KEYCTL_READ)
		return __real_syscall(number, arg1, arg2, arg3, arg4, arg5);
	if (fake_grows) {
		fake_links++;
		fake_grows--;
	}
	bytes = fake_links * sizeof(*serials);
	if (bytes > cap)
		return (long)bytes;
	for (i = 0; i < fake_links; i++)
		serials[i] = (key_serial_t)(1000 + i);
	return (long)bytes;
}

/* The first read fills the buffer; the second finds the count it asked for. */
static void links_that_fit_are_read_whole(void)
{
	struct keyring_link *links = NULL;
	size_t n = 0;

	fake_links = 64;
	fake_grows = 0;
	ASSERT_EQ(keyring_links(0, &links, &n), 0);
	ASSERT_UEQ(n, 64);
	ASSERT_EQ(links[63].serial, 1063);
	xfree(links, n * sizeof(*links));
}

/*
 * A link added between the reads makes the buffer sized for the first
 * one too small: the read is retried, and the third read fits.
 */
static void links_that_grow_between_reads_are_read_whole(void)
{
	struct keyring_link *links = NULL;
	size_t n = 0;

	fake_links = 65;
	fake_grows = 2;
	ASSERT_EQ(keyring_links(0, &links, &n), 0);
	ASSERT_UEQ(n, 67);
	ASSERT_EQ(links[66].serial, 1066);
	xfree(links, n * sizeof(*links));
}

/* One that never fits is refused rather than reported short. */
static void a_keyring_that_keeps_growing_is_refused(void)
{
	struct keyring_link *links = NULL;
	size_t n = 0;

	fake_links = 100;
	fake_grows = 1u << 30;
	ASSERT_EQ(keyring_links(0, &links, &n), -EAGAIN);
	ASSERT_TRUE(!links);
	ASSERT_UEQ(n, 0);
}

static const struct unit_case cases[] = {
	UNIT_CASE(links_that_fit_are_read_whole),
	UNIT_CASE(links_that_grow_between_reads_are_read_whole),
	UNIT_CASE(a_keyring_that_keeps_growing_is_refused),
	{}
};

UNIT_SUITE(keyring, cases);
