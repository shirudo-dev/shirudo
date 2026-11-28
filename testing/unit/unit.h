/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_TESTING_UNIT_H
#define SHIRUDO_TESTING_UNIT_H

#include <stddef.h>
#include <string.h>

#include <shirudo/misc.h>


struct unit_case {
	const char *name;
	void (*run)(void);
};

struct unit_suite {
	const char *name;
	const struct unit_case *cases;
};

#define UNIT_CASE(fn)	{ #fn, fn }

/*
 * Each testing/unit/<module>.c names its cases in one table that ends with
 * an empty entry. A case left out of it is an unused static function,
 * which the build refuses.
 */
#define UNIT_SUITE(suite, table)					\
	const struct unit_suite unit_suite = { #suite, table }

extern const struct unit_suite unit_suite;

void unit_fail(const char *file, int line, const char *fmt, ...)
	__printf(3, 4);
__noreturn void unit_abort(void);
__noreturn void unit_skip(const char *reason);
void unit_fail_mem(const char *file, int line, const char *what,
		   const void *a, const void *b, size_t len);

#define UNIT_CHECK(fatal, cond, fmt, ...)				\
	do {								\
		if (!(cond)) {						\
			unit_fail(__FILE__, __LINE__, fmt, ##__VA_ARGS__); \
			if (fatal)					\
				unit_abort();				\
		}							\
	} while (0)

#define UNIT_CMP_S64(fatal, a, op, b)					\
	do {								\
		__s64 unit_a_ = (__s64)(a), unit_b_ = (__s64)(b);	\
		UNIT_CHECK(fatal, unit_a_ op unit_b_,			\
			   "%s %s %s: %lld vs %lld", #a, #op, #b,	\
			   unit_a_, unit_b_);				\
	} while (0)

#define UNIT_CMP_U64(fatal, a, op, b)					\
	do {								\
		__u64 unit_a_ = (__u64)(a), unit_b_ = (__u64)(b);	\
		UNIT_CHECK(fatal, unit_a_ op unit_b_,			\
			   "%s %s %s: %llu vs %llu", #a, #op, #b,	\
			   unit_a_, unit_b_);				\
	} while (0)

#define UNIT_STREQ(fatal, a, b)						\
	do {								\
		const char *unit_a_ = (a), *unit_b_ = (b);		\
		UNIT_CHECK(fatal, unit_a_ && unit_b_ &&			\
			   !strcmp(unit_a_, unit_b_),			\
			   "%s == %s: \"%s\" vs \"%s\"", #a, #b,	\
			   unit_a_ ? unit_a_ : "(null)",		\
			   unit_b_ ? unit_b_ : "(null)");		\
	} while (0)

#define UNIT_MEMEQ(fatal, a, b, len)					\
	do {								\
		const void *unit_a_ = (a), *unit_b_ = (b);		\
		size_t unit_n_ = (len);					\
		if (memcmp(unit_a_, unit_b_, unit_n_)) {		\
			unit_fail_mem(__FILE__, __LINE__, #a " == " #b,	\
				      unit_a_, unit_b_, unit_n_);	\
			if (fatal)					\
				unit_abort();				\
		}							\
	} while (0)

/* EXPECT_* records a failure and goes on; ASSERT_* ends the case. */
#define EXPECT_TRUE(c)		UNIT_CHECK(0, (c), "%s", #c)
#define EXPECT_FALSE(c)		UNIT_CHECK(0, !(c), "!(%s)", #c)
#define EXPECT_EQ(a, b)		UNIT_CMP_S64(0, a, ==, b)
#define EXPECT_NE(a, b)		UNIT_CMP_S64(0, a, !=, b)
#define EXPECT_LT(a, b)		UNIT_CMP_S64(0, a, <, b)
#define EXPECT_GT(a, b)		UNIT_CMP_S64(0, a, >, b)
#define EXPECT_UEQ(a, b)	UNIT_CMP_U64(0, a, ==, b)
#define EXPECT_STREQ(a, b)	UNIT_STREQ(0, a, b)
#define EXPECT_MEMEQ(a, b, n)	UNIT_MEMEQ(0, a, b, n)

#define ASSERT_TRUE(c)		UNIT_CHECK(1, (c), "%s", #c)
#define ASSERT_FALSE(c)		UNIT_CHECK(1, !(c), "!(%s)", #c)
#define ASSERT_EQ(a, b)		UNIT_CMP_S64(1, a, ==, b)
#define ASSERT_NE(a, b)		UNIT_CMP_S64(1, a, !=, b)
#define ASSERT_UEQ(a, b)	UNIT_CMP_U64(1, a, ==, b)
#define ASSERT_STREQ(a, b)	UNIT_STREQ(1, a, b)
#define ASSERT_MEMEQ(a, b, n)	UNIT_MEMEQ(1, a, b, n)

/*
 * A suite that wraps a libc function with the linker's --wrap defines
 * __wrap_<name> and calls __real_<name>, the one it replaced. Both are
 * declared here because a .c file carries no prototype of its own.
 */
long __real_syscall(long number, long arg1, long arg2, long arg3, long arg4,
		    long arg5);
long __wrap_syscall(long number, long arg1, long arg2, long arg3, long arg4,
		    long arg5);

#endif /* SHIRUDO_TESTING_UNIT_H */
