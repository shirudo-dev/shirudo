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
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <linux/bpf.h>

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

static int count_non_xdp_link(__u32 index, const char *pin, void *ctx)
{
	struct bpf_link_info info = {};
	__u32 len = sizeof(info);
	__u32 *found = ctx;
	int fd, ret;

	fd = bpf_obj_get(pin);
	if (fd < 0)
		return -errno;
	ret = bpf_link_get_info_by_fd(fd, &info, &len);
	close(fd);
	if (ret)
		return ret;
	if (info.type != BPF_LINK_TYPE_XDP)
		(*found)++;
	return 0;
}

/*
 * XDP links come and go with devices, so their number says nothing. What
 * cannot change is a program pin for each XDP program and a link for each
 * other attach program. Link numbers are shared and shift with the devices,
 * so the kernel says which links are which.
 */
static int xdp_upatch_complete(const char *name, const struct prog_spec *specs,
			       __u32 nr_progs, __u32 nr_attach)
{
	__u32 i, nr_xdp = 0, found = 0;
	char pin[PATH_MAX];
	char entry[32];
	struct stat st;
	int ret;

	for (i = 0; i < nr_progs; i++) {
		if (specs[i].kind != UPATCH_ATTACH_XDP)
			continue;
		nr_xdp++;
		if (strsprintf(entry, sizeof(entry), XDP_PROG_PIN_PREFIX "%u", i) < 0 ||
		    upatch_pin_path(pin, sizeof(pin), name, entry, NULL))
			return -ENAMETOOLONG;
		if (stat(pin, &st))
			return errno == ENOENT ? 0 : -errno;
	}
	if (nr_attach == nr_xdp)
		return 1;
	ret = upatch_each_link(name, count_non_xdp_link, &found);
	if (ret)
		return ret;
	return found == nr_attach - nr_xdp;
}

int upatch_links_complete(const char *name, const char *path)
{
	struct prog_spec *specs = NULL;
	struct upatch_pins pins;
	__u32 len, i, nr_attach = 0;
	const void *attach;
	bool has_xdp = false;
	struct upatch u;
	int ret;

	ret = upatch_open(path, &u);
	if (ret)
		return stale_unless_resources(ret);
	attach = upatch_signed_attach(&u, &len);
	ret = attach ? prog_specs_parse(attach, len, u.hdr.nr_maps,
					u.hdr.nr_progs, &specs) : -ESTALE;
	if (ret) {
		ret = stale_unless_resources(ret);
		goto out;
	}
	for (i = 0; i < u.hdr.nr_progs; i++) {
		if (specs[i].role == UPATCH_PROG_ROLE_ATTACH)
			nr_attach++;
		if (specs[i].kind == UPATCH_ATTACH_XDP)
			has_xdp = true;
	}
	if (has_xdp) {
		ret = xdp_upatch_complete(name, specs, u.hdr.nr_progs, nr_attach);
	} else {
		ret = upatch_pins_read(name, &pins);
		if (!ret)
			ret = upatch_pins_complete(&pins, nr_attach);
	}
	prog_specs_free(specs, u.hdr.nr_progs);
out:
	upatch_close(&u);
	return ret;
}

/* Whether the set holds name with the payload its pin directory records. */
static bool pin_measured(const struct measured_set *s, const char *name,
			 __u8 payload[UPATCH_PAYLOAD_HASH_LEN])
{
	char hex[2 * UPATCH_PAYLOAD_HASH_LEN + 1];
	char dir[PATH_MAX];

	if (upatch_pin_path(dir, sizeof(dir), name, NULL) ||
	    getxattr(dir, XATTR_PAYLOAD, payload, UPATCH_PAYLOAD_HASH_LEN) !=
	    UPATCH_PAYLOAD_HASH_LEN)
		return false;
	hex_encode(payload, UPATCH_PAYLOAD_HASH_LEN, hex);
	return measured_holds(s, name, hex);
}

/* These return 1 for a hit, 0 for none, or -errno when they could not tell. */
static int xdp_archive_changed(const struct measured_set *s, const char *name)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN];
	struct upatch_pins pins;
	struct upatch u;
	int ret;

	if (upatch_pins_read(name, &pins) || !pins.nr_xdp_progs ||
	    !pin_measured(s, name, payload))
		return 0;
	ret = upatch_archive_verify(name, payload, &u);
	if (!ret)
		upatch_close(&u);
	return ret == -ESTALE ? 1 : ret;
}

static int links_lost(const struct measured_set *s, const char *name)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN];
	char path[PATH_MAX];
	int ret;

	if (!pin_measured(s, name, payload))
		return 0;
	if (strsprintf(path, sizeof(path), "%s/%s.upatch", UPATCHES_DIR,
		       name) < 0)
		return -ENAMETOOLONG;
	ret = upatch_links_complete(name, path);
	if (ret == 1)
		return 0;
	return !ret || ret == -ESTALE ? 1 : ret;
}

static int walk_pinned(const struct measured_set *s,
		       int (*check)(const struct measured_set *s, const char *name),
		       int (*cb)(const char *name, void *ctx), void *ctx,
		       int *check_err)
{
	struct dirent *e;
	int found = 0;
	int ret = 0;
	DIR *d;

	d = opendir(BPFFS_UPATCHES_DIR);
	if (!d) {
		if (errno != ENOENT && !*check_err)
			*check_err = -errno;
		return 0;
	}
	while (!ret && (e = readdir(d))) {
		char name[UPATCH_NAME_MAX + 1];
		int result;

		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..") ||
		    upatch_name_from_bpffs(name, sizeof(name), e->d_name))
			continue;
		result = check(s, name);
		if (result < 0 && !*check_err)
			*check_err = result;
		if (result <= 0)
			continue;
		found++;
		ret = cb(name, ctx);
	}
	closedir(d);
	return ret ? ret : found;
}

int upatch_xdp_archives_changed(const struct measured_set *s,
				int (*cb)(const char *name, void *ctx),
				void *ctx, int *check_err)
{
	return walk_pinned(s, xdp_archive_changed, cb, ctx, check_err);
}

int upatch_links_lost(const struct measured_set *s,
		      int (*cb)(const char *name, void *ctx), void *ctx,
		      int *check_err)
{
	return walk_pinned(s, links_lost, cb, ctx, check_err);
}
