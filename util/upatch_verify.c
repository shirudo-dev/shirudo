// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Whether the archive of a loaded upatch is still what was loaded.
 */

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <shirudo/string.h>

#include "chain.h"
#include "hex.h"
#include "measured.h"
#include "paths.h"
#include "seal.h"
#include "upatch.h"
#include "upatch_pins.h"
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

static bool xdp_archive_changed(const struct measured_set *s, const char *name)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN];
	char hex[2 * UPATCH_PAYLOAD_HASH_LEN + 1];
	struct upatch_pins pins;
	char dir[PATH_MAX];
	struct upatch u;
	int ret;

	if (upatch_pins_read(name, &pins) || !pins.nr_xdp_progs ||
	    upatch_pin_path(dir, sizeof(dir), name, NULL) ||
	    getxattr(dir, XATTR_PAYLOAD, payload, sizeof(payload)) !=
	    (ssize_t)sizeof(payload))
		return false;
	hex_encode(payload, sizeof(payload), hex);
	if (!measured_holds(s, name, hex))
		return false;
	ret = upatch_archive_verify(name, payload, &u);
	if (!ret)
		upatch_close(&u);
	return ret == -ESTALE;
}

int upatch_xdp_archives_changed(const struct measured_set *s,
				int (*cb)(const char *name, void *ctx),
				void *ctx)
{
	struct dirent *e;
	int changed = 0;
	int ret = 0;
	DIR *d;

	d = opendir(BPFFS_UPATCHES_DIR);
	if (!d)
		return errno == ENOENT ? 0 : -errno;
	while (!ret && (e = readdir(d))) {
		char name[UPATCH_NAME_MAX + 1];

		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..") ||
		    upatch_name_from_bpffs(name, sizeof(name), e->d_name) ||
		    !xdp_archive_changed(s, name))
			continue;
		changed++;
		ret = cb(name, ctx);
	}
	closedir(d);
	return ret ? ret : changed;
}
