/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Attributes and compile-time checks spelled the kernel's way.
 */

#ifndef SHIRUDO_COMPILER_H
#define SHIRUDO_COMPILER_H

#define __printf(a, b)	__attribute__((format(printf, a, b)))
#define __must_check	__attribute__((warn_unused_result))
#define __noreturn	__attribute__((noreturn))
#define __sentinel	__attribute__((sentinel))
#define __cleanup(func)	__attribute__((cleanup(func)))
#define noinline	__attribute__((noinline))
/* A function with a large frame that inlining would add to its caller's. */
#define noinline_for_stack	noinline
/*
 * A struct member that holds a secret. It expands to nothing; it puts the
 * struct under testing/coccinelle/sensitive_scrub.cocci, which wants every
 * local of it scrubbed on each path out.
 */
#define __sensitive
/*
 * clang's -Wimplicit-fallthrough takes the attribute and never a comment.
 * Token for token as in bpf/lib/misc.h.
 */
#define fallthrough	__attribute__((__fallthrough__))

/*
 * An empty asm that may read memory through ptr, so that a store to that
 * memory before it is not dead. The pointer has to be an operand: the
 * memory clobber alone does not reach an object whose address never
 * escaped, and clang drops a store to a local then.
 */
#define barrier_data(ptr)	__asm__ __volatile__("" : : "r"(ptr) : "memory")

/*
 * var passes through an empty asm and comes back changed as far as the
 * compiler knows, so that it cannot reason from how var was computed,
 * such as by leaving a loop once var can no longer change.
 */
#define OPTIMIZER_HIDE_VAR(var)	__asm__ ("" : "+r"(var))

/* sparse's cast between a restricted type and its base; nothing otherwise. */
#ifdef __CHECKER__
#define __force		__attribute__((force))
#else
#define __force
#endif

/*
 * Declarations, so they stand at file scope as well as in a block.
 * Token for token as in bpf/lib/misc.h, which userspace also reaches
 * through bpf/lib/serializer.h: a redefinition that differs does not
 * compile.
 */
#define BUILD_BUG_ON_MSG(cond, msg)	_Static_assert(!(cond), msg)
#define BUILD_BUG_ON(cond)						\
	BUILD_BUG_ON_MSG(cond, "BUILD_BUG_ON failed: " #cond)

/* 0 as an int constant expression, or no build when e holds. */
#define BUILD_BUG_ON_ZERO(e)						\
	((int)(0 * sizeof(struct { _Static_assert(!(e), #e); char c; })))

#endif /* SHIRUDO_COMPILER_H */
