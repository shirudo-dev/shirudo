// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Read back the identity map init pinned in the private bpffs.
 */

#include <errno.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <linux/bpf.h>

#include <bpf/bpf.h>

#include <shirudo/misc.h>

#include "identity.h"
#include "shirudo_mode.h"
#include "paths.h"

int shirudo_identity_mode(void)
{
	int mode = prctl(SHIRUDO_PR_GET_MODE, 0, 0, 0, 0);

	if (mode >= 0)
		return -EPROTO;
	if (errno == SHIRUDO_PR_MODE_LEGACY_ERR)
		return SHIRUDO_MODE_LEGACY;
	if (errno == SHIRUDO_PR_MODE_IMAGE_ERR)
		return SHIRUDO_MODE_IMAGE;
	return errno == EINVAL || errno == ENOSYS ? SHIRUDO_MODE_NONE : -errno;
}

int identity_read(struct shirudo_identity *out)
{
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);
	__u32 zero = 0;
	int fd, rc;

	memset(out, 0, sizeof(*out));
	fd = bpf_obj_get(SHIRUDO_IDENTITY_PIN);
	if (fd < 0)
		return -errno;
	rc = bpf_map_get_info_by_fd(fd, &info, &len);
	if (rc) {
		rc = -errno;
	} else if (info.value_size != sizeof(*out)) {
		rc = -EPROTO;
	} else {
		rc = bpf_map_lookup_elem(fd, &zero, out);
		if (rc)
			rc = -errno;
	}
	close(fd);
	return rc;
}
