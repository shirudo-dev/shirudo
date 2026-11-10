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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/if_link.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include "chain.h"
#include "hex.h"
#include "malloc.h"
#include "measured.h"
#include "paths.h"
#include "seal.h"
#include "upatch.h"
#include "upatch_pins.h"
#include "upatch_verify.h"
#include "xdp.h"

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

int upatch_archive_specs(const char *name,
			 const __u8 payload[UPATCH_PAYLOAD_HASH_LEN],
			 struct upatch *u, struct prog_spec **specs)
{
	const void *attach;
	__u32 len;
	int ret;

	ret = upatch_archive_verify(name, payload, u);
	if (ret)
		return ret;
	attach = upatch_signed_attach(u, &len);
	ret = attach ? prog_specs_parse(attach, len, u->hdr.nr_maps,
					u->hdr.nr_progs, specs) : -ESTALE;
	if (ret) {
		upatch_close(u);
		return ret == -ENOMEM ? ret : -ESTALE;
	}
	return 0;
}

int upatch_xdp_prog_open(const char *name, __u32 index, __u32 *id)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	char pin[PATH_MAX];
	char entry[32];
	int fd, ret;

	if (strsprintf(entry, sizeof(entry), XDP_PROG_PIN_PREFIX "%u", index) < 0 ||
	    upatch_pin_path(pin, sizeof(pin), name, entry, NULL))
		return -ENAMETOOLONG;
	fd = bpf_obj_get(pin);
	if (fd < 0)
		return -errno;
	ret = bpf_prog_get_info_by_fd(fd, &info, &len);
	if (!ret && info.type != BPF_PROG_TYPE_XDP)
		ret = -ESTALE;
	if (ret) {
		close(fd);
		return ret;
	}
	*id = info.id;
	return fd;
}

int upatch_xdp_each_uncovered(const char *name, const struct prog_spec *specs,
			      __u32 nr_progs, const struct xdp_device *devices,
			      size_t count,
			      int (*cb)(int prog_fd, const struct prog_spec *spec,
					const struct xdp_device *dev,
					__u32 attached, void *ctx),
			      void *ctx)
{
	__u32 i;

	for (i = 0; i < nr_progs; i++) {
		__u32 prog_id = 0;
		size_t j;
		int fd;

		if (specs[i].kind != UPATCH_ATTACH_XDP)
			continue;
		fd = upatch_xdp_prog_open(name, i, &prog_id);
		if (fd < 0)
			return fd;
		for (j = 0; j < count; j++) {
			__u32 attached = 0;
			int ret;

			/* A device that cannot be queried went away. */
			if (!xdp_device_selected(devices, count, j,
						 specs[i].device_classes) ||
			    bpf_xdp_query_id((int)devices[j].ifindex,
					     XDP_FLAGS_DRV_MODE, &attached) ||
			    xdp_reconcile_action(true, attached, prog_id) ==
			    XDP_RECONCILE_COVERED)
				continue;
			ret = cb(fd, &specs[i], &devices[j], attached, ctx);
			if (ret) {
				close(fd);
				return ret;
			}
		}
		close(fd);
	}
	return 0;
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
static int xdp_archive_changed(const struct measured_set *s, const char *name,
			       void *ctx)
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

static int links_lost(const struct measured_set *s, const char *name,
		      void *ctx)
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

/* check gets ctx as well, and cb may be NULL. */
static int walk_pinned(const struct measured_set *s,
		       int (*check)(const struct measured_set *s, const char *name,
				    void *ctx),
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
		result = check(s, name, ctx);
		if (result < 0 && !*check_err)
			*check_err = result;
		if (result <= 0)
			continue;
		found++;
		if (cb)
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

struct uncovered_walk {
	int			(*cb)(const char *name, const char *dev,
				      const char *why, void *ctx);
	void			*ctx;
	const char		*name;
	struct xdp_device	*devices;
	size_t			count;
	bool			devices_read;
	int			found;
};

static int note_uncovered(int prog_fd, const struct prog_spec *spec,
			  const struct xdp_device *dev, __u32 attached,
			  void *ctx)
{
	struct uncovered_walk *w = ctx;
	__u64 features = 0;
	int err = 0;

	if (!attached)
		err = xdp_device_features(dev->ifindex, &features);
	w->found++;
	return w->cb(w->name, dev->name,
		     xdp_uncovered_reason(attached, err, features), w->ctx);
}

/* An archive that changed is upatch_xdp_archives_changed()'s to report. */
static int xdp_uncovered(const struct measured_set *s, const char *name,
			 void *ctx)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN];
	struct uncovered_walk *w = ctx;
	struct prog_spec *specs = NULL;
	struct upatch_pins pins;
	struct upatch u;
	int ret;

	if (upatch_pins_read(name, &pins) || !pins.nr_xdp_progs ||
	    !pin_measured(s, name, payload))
		return 0;
	ret = upatch_archive_specs(name, payload, &u, &specs);
	if (ret)
		return ret == -ESTALE ? 0 : ret;
	if (!w->devices_read) {
		ret = xdp_devices_read(&w->devices, &w->count);
		w->devices_read = !ret;
	}
	if (!ret) {
		w->name = name;
		ret = upatch_xdp_each_uncovered(name, specs, u.hdr.nr_progs,
						w->devices, w->count,
						note_uncovered, w);
	}
	prog_specs_free(specs, u.hdr.nr_progs);
	upatch_close(&u);
	return min(ret, 0);
}

int upatch_xdp_uncovered(const struct measured_set *s,
			 int (*cb)(const char *name, const char *dev,
				   const char *why, void *ctx),
			 void *ctx, int *check_err)
{
	struct uncovered_walk w = { .cb = cb, .ctx = ctx };
	int ret;

	ret = walk_pinned(s, xdp_uncovered, NULL, &w, check_err);
	xfree(w.devices, size_mul(w.count, sizeof(*w.devices)));
	return ret < 0 ? ret : w.found;
}
