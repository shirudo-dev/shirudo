// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#define PROOF_MEMCPY_BYTEWISE
#include "proof.h"
#include "../../../util/string.c"
#include "../../../util/image_bootstrap.c"

#ifndef LEN
#define LEN KEYS_MAX
#endif

static struct image_bootstrap boot;

void harness(void)
{
	char candidate[] = RUNTIME_DIR "/key-A";
	char previous[] = RUNTIME_DIR "/key-A";
	const char *path = candidate;
	__u32 key, invalid;
	const __u32 count = LEN;
	size_t i;
	int ret;

	__CPROVER_assume(count <= KEYS_MAX && key <= KEYS_MAX && invalid <= 2);
	boot.n_certificates = count;
	for (i = 0; i < count; i++) {
		previous[sizeof(previous) - 2] = (char)('A' + i);
		memcpy(boot.certificates[i], previous, sizeof(previous));
	}
	candidate[sizeof(candidate) - 2] = (char)('A' + key);
	if (invalid == 1)
		path = "/outside/cert.der";
	if (invalid == 2)
		path = RUNTIME_DIR "/../cert.der";
	ret = bootstrap_add_certificate(&boot, path);
	if (invalid)
		__CPROVER_assert(ret == -EPERM,
				 "certificates cannot escape the runtime");
	else if (count == KEYS_MAX)
		__CPROVER_assert(ret == -E2BIG, "a full set cannot grow");
	else if (key < count)
		__CPROVER_assert(ret == -EEXIST, "duplicate paths are refused");
	else
		__CPROVER_assert(!ret, "a distinct path can join a non-full set");
	__CPROVER_assert(boot.n_certificates == count + (ret == 0),
			 "only a successful append changes the count");
	__CPROVER_assert(boot.n_certificates <= KEYS_MAX,
			 "the set never exceeds its capacity");
	for (i = 0; i < count; i++) {
		previous[sizeof(previous) - 2] = (char)('A' + i);
		__CPROVER_assert(!strcmp(boot.certificates[i], previous),
				 "earlier certificates keep their order and paths");
	}
	if (!ret)
		__CPROVER_assert(!strcmp(boot.certificates[count], candidate),
				 "the new path is appended exactly once");
}
