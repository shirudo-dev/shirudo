// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Whether the archive of a loaded upatch is still what was loaded.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <linux/bpf.h>

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
#include "upatch_resolve.h"
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

static int count_non_xdp_link(__u32 index, const char *pin,
			      const struct bpf_link_info *info, void *ctx)
{
	__u32 *found = ctx;

	if (info->type != BPF_LINK_TYPE_XDP)
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
	struct stat st;
	int ret;

	for (i = 0; i < nr_progs; i++) {
		if (specs[i].kind != UPATCH_ATTACH_XDP)
			continue;
		nr_xdp++;
		if (upatch_xdp_prog_pin(pin, sizeof(pin), name, i))
			return -ENAMETOOLONG;
		if (stat(pin, &st))
			return errno == ENOENT ? 0 : -errno;
	}
	if (nr_attach == nr_xdp)
		return 1;
	ret = upatch_each_link_info(name, count_non_xdp_link, &found);
	if (ret)
		return ret;
	return found == nr_attach - nr_xdp;
}

static int links_complete_specs(const char *name,
				const struct prog_spec *specs, __u32 nr_progs)
{
	struct upatch_pins pins;
	__u32 i, nr_attach = 0;
	bool has_xdp = false;
	int ret;

	for (i = 0; i < nr_progs; i++) {
		if (specs[i].role == UPATCH_PROG_ROLE_ATTACH)
			nr_attach++;
		if (specs[i].kind == UPATCH_ATTACH_XDP)
			has_xdp = true;
	}
	if (has_xdp)
		return xdp_upatch_complete(name, specs, nr_progs, nr_attach);
	ret = upatch_pins_read(name, &pins);
	return ret ? ret : upatch_pins_complete(&pins, nr_attach);
}

int upatch_links_complete(const char *name, const char *path)
{
	struct prog_spec *specs = NULL;
	const void *attach;
	struct upatch u;
	__u32 len;
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
	ret = links_complete_specs(name, specs, u.hdr.nr_progs);
	prog_specs_free(specs, u.hdr.nr_progs);
out:
	upatch_close(&u);
	return ret;
}

/* -ESTALE for metadata that does not parse, -ENOMEM; u stays open. */
static int upatch_verified_specs(const struct upatch *u,
				 struct prog_spec **specs)
{
	const void *attach;
	__u32 len;
	int ret;

	attach = upatch_signed_attach(u, &len);
	ret = attach ? prog_specs_parse(attach, len, u->hdr.nr_maps,
					u->hdr.nr_progs, specs) : -ESTALE;
	return !ret || ret == -ENOMEM ? ret : -ESTALE;
}

int upatch_archive_specs(const char *name,
			 const __u8 payload[UPATCH_PAYLOAD_HASH_LEN],
			 struct upatch *u, struct prog_spec **specs)
{
	int ret;

	ret = upatch_archive_verify(name, payload, u);
	if (ret)
		return ret;
	ret = upatch_verified_specs(u, specs);
	if (ret)
		upatch_close(u);
	return ret;
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
			__u32 attached = xdp_device_attached(&devices[j]);
			int ret;

			if (!xdp_device_selected(devices, count, j,
						 specs[i].device_classes))
				continue;
			if (xdp_reconcile_action(true, attached, prog_id) ==
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

bool upatch_pin_measured(const struct measured_set *s, const char *name,
			 __u8 payload[UPATCH_PAYLOAD_HASH_LEN])
{
	char hex[2 * UPATCH_PAYLOAD_HASH_LEN + 1];

	if (upatch_pin_payload(name, payload))
		return false;
	hex_encode(payload, UPATCH_PAYLOAD_HASH_LEN, hex);
	return measured_holds(s, name, hex);
}

struct checks_walk {
	const struct measured_set	*s;
	struct upatch_checks		*c;
	struct xdp_device		*devices;
	size_t				count;
	bool				devices_tried;
	bool				devices_ok;
	const char			*name;
	char				why[128];
};

static void note_err(int *slot, int err)
{
	if (err < 0 && !*slot)
		*slot = err;
}

static int note_changed(struct checks_walk *w, const char *name)
{
	w->c->nr_changed++;
	return w->c->changed ? w->c->changed(name, w->c->changed_ctx) : 0;
}

/* complete is 1, 0 or -errno, as upatch_links_complete() returns. */
static int note_links(struct checks_walk *w, const char *name, int complete)
{
	if (complete == 1)
		return 0;
	if (complete < 0 && complete != -ESTALE) {
		note_err(&w->c->check_err, complete);
		return 0;
	}
	w->c->nr_lost++;
	return w->c->lost ? w->c->lost(name, w->c->lost_ctx) : 0;
}

/* Read from the archive as it is, for an upatch the hash does not vouch for. */
static int note_links_unverified(struct checks_walk *w, const char *name)
{
	char path[PATH_MAX];

	if (strsprintf(path, sizeof(path), "%s/%s.upatch", UPATCHES_DIR,
		       name) < 0) {
		note_err(&w->c->check_err, -ENAMETOOLONG);
		return 0;
	}
	return note_links(w, name, upatch_links_complete(name, path));
}

static int note_uncovered(int prog_fd, const struct prog_spec *spec,
			  const struct xdp_device *dev, __u32 attached,
			  void *ctx)
{
	struct checks_walk *w = ctx;
	__u64 features = 0;
	int err = 0;

	if (!attached) {
		err = xdp_device_verify(dev);
		/* The read finds nothing, not an error, for a device gone since. */
		if (err == -ENODEV || err == -EXDEV)
			return 0;
		err = xdp_device_features(dev->ifindex, &features);
	}
	w->c->nr_uncovered++;
	return w->c->uncovered(w->name, dev->name,
			       xdp_uncovered_reason(attached, err, features),
			       w->c->uncovered_ctx);
}

static bool runs_program_of(const char *name, const struct prog_spec *specs,
			    __u32 nr_progs, __u32 attached)
{
	__u32 i, id;
	int fd;

	for (i = 0; attached && i < nr_progs; i++) {
		if (specs[i].kind != UPATCH_ATTACH_XDP)
			continue;
		fd = upatch_xdp_prog_open(name, i, &id);
		if (fd < 0)
			continue;
		close(fd);
		if (id == attached)
			return true;
	}
	return false;
}

/*
 * Whether name selects it is not known, so unless it runs name's program
 * it may run without it.
 */
static int note_unclassified(struct checks_walk *w, const char *name,
			     const struct prog_spec *specs, __u32 nr_progs)
{
	size_t i;
	int ret;

	for (i = 0; i < w->count; i++) {
		const struct xdp_device *dev = &w->devices[i];

		if (!dev->unclassified_err ||
		    runs_program_of(name, specs, nr_progs, dev->xdp_drv_id))
			continue;
		if (strsprintf(w->why, sizeof(w->why), "not classified: %s",
			       strerror(-dev->unclassified_err)) < 0)
			return -E2BIG;
		w->c->nr_uncovered++;
		ret = w->c->uncovered(name, dev->name, w->why,
				      w->c->uncovered_ctx);
		if (ret)
			return ret;
	}
	return 0;
}

static int check_coverage(struct checks_walk *w, const char *name,
			  const struct prog_spec *specs, __u32 nr_progs)
{
	int ret;

	if (!w->c->uncovered)
		return 0;
	/*
	 * Under the lock, as the pins are: a load that attaches between the
	 * two reads would otherwise show its device as not attached.
	 */
	if (!w->devices_tried) {
		w->devices_tried = true;
		ret = xdp_devices_read(&w->devices, &w->count);
		note_err(&w->c->coverage_err, ret);
		w->devices_ok = !ret;
	}
	if (!w->devices_ok)
		return 0;
	w->name = name;
	ret = upatch_xdp_each_uncovered(name, specs, nr_progs, w->devices,
					w->count, note_uncovered, w);
	if (!ret)
		ret = note_unclassified(w, name, specs, nr_progs);
	if (ret < 0) {
		note_err(&w->c->coverage_err, ret);
		return 0;
	}
	return ret;
}

/*
 * One verified read of an XDP upatch's archive serves the three checks:
 * its hash, the links its metadata implies and the devices it selects.
 */
static int check_one(const char *name, void *ctx)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN];
	struct checks_walk *w = ctx;
	struct prog_spec *specs = NULL;
	struct upatch_pins pins;
	struct upatch u;
	int ret;

	if (!upatch_pin_measured(w->s, name, payload))
		return 0;
	if (upatch_pins_read(name, &pins) || !pins.nr_xdp_progs)
		return note_links_unverified(w, name);
	ret = upatch_archive_verify(name, payload, &u);
	if (ret == -ESTALE) {
		ret = note_changed(w, name);
		return ret ? ret : note_links_unverified(w, name);
	}
	if (ret) {
		note_err(&w->c->check_err, ret);
		note_err(&w->c->coverage_err, ret);
		return note_links_unverified(w, name);
	}
	/* The bytes are what was loaded; metadata it cannot parse is a lost link. */
	ret = upatch_verified_specs(&u, &specs);
	if (ret) {
		upatch_close(&u);
		if (ret != -ESTALE) {
			note_err(&w->c->check_err, ret);
			note_err(&w->c->coverage_err, ret);
			return 0;
		}
		return note_links(w, name, ret);
	}
	ret = note_links(w, name, links_complete_specs(name, specs,
						       u.hdr.nr_progs));
	if (!ret)
		ret = check_coverage(w, name, specs, u.hdr.nr_progs);
	prog_specs_free(specs, u.hdr.nr_progs);
	upatch_close(&u);
	return ret;
}

void upatch_checks_run(const struct measured_set *s, struct upatch_checks *c)
{
	struct checks_walk w = { .s = s, .c = c };
	int ret;

	/*
	 * Elsewhere the devices are another namespace's, whether or not an
	 * XDP upatch is found to check them against.
	 */
	if (c->uncovered) {
		ret = netns_initial();
		note_err(&c->coverage_err, ret);
		w.devices_tried = ret != 0;
	}
	ret = upatch_each_pinned(check_one, &w);
	/* Nothing walked is nothing checked, coverage included. */
	if (ret < 0) {
		note_err(&c->check_err, ret);
		note_err(&c->coverage_err, ret);
	}
	xfree(w.devices, size_mul(w.count, sizeof(*w.devices)));
}
