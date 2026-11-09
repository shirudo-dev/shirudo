// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Whether the archive of a loaded upatch is still what was loaded.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#include <shirudo/string.h>

#include "chain.h"
#include "paths.h"
#include "seal.h"
#include "upatch.h"
#include "upatch_verify.h"

static int stale_unless_resources(int err)
{
	return err == -ENOMEM || err == -EMFILE || err == -ENFILE ? err : -ESTALE;
}

int upatch_verify_fd(int fd, const __u8 payload[UPATCH_PAYLOAD_HASH_LEN],
		     struct upatch *out)
{
	__u8 digest[UPATCH_PAYLOAD_HASH_LEN];
	int ret;

	ret = upatch_open_fd(fd, out);
	if (ret)
		return stale_unless_resources(ret);
	ret = sha256_2(upatch_loader(out), out->hdr.loader_insns_len,
		       upatch_data(out), out->hdr.data_len, digest);
	if (!ret && (memneq_explicit(digest, payload, sizeof(digest)) ||
		     memneq_explicit(out->hdr.payload_sha256, payload,
				     sizeof(digest))))
		ret = -ESTALE;
	if (ret)
		upatch_close(out);
	return ret;
}

int upatch_archive_verify(const char *name,
			  const __u8 payload[UPATCH_PAYLOAD_HASH_LEN],
			  struct upatch *out)
{
	char header_name[UPATCH_NAME_MAX + 1];
	char path[PATH_MAX];
	int fd, ret;

	if (strsprintf(path, sizeof(path), "%s/%s.upatch", UPATCHES_DIR,
		       name) < 0)
		return -ENAMETOOLONG;
	fd = seal_open_read(path);
	if (fd < 0)
		return stale_unless_resources(fd);
	ret = upatch_verify_fd(fd, payload, out);
	close(fd);
	if (ret)
		return ret;
	upatch_header_name(out, header_name);
	if (strcmp(header_name, name) || !upatch_name_signed(out)) {
		upatch_close(out);
		return -ESTALE;
	}
	return 0;
}
