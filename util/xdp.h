/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_XDP_H
#define SHIRUDO_XDP_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>

#include <shirudo/misc.h>

#define XDP_IFNAME_MAX 16

/*
 * What shirudo makes of a failed XDP attach. Positive, so that no errno a
 * lookup or the kernel returns along the way can be read as one of them.
 */
enum xdp_attach_err {
	/* The driver has no native XDP: the device is passed over. */
	XDP_ERR_NO_NATIVE = 1,
	/* Every XDP program is loaded with frags, so the device must report them. */
	XDP_ERR_NO_MULTIBUF,
	/* A driver with native XDP that rules it out in its current settings. */
	XDP_ERR_DRIVER_SETTINGS,
	/* The device runs another XDP program: the link create says so. */
	XDP_ERR_OCCUPIED,
	/* The kernel made the link for another device. */
	XDP_ERR_LINK_SCOPE,
};

struct xdp_device {
	char devlink_device[128];
	char devlink_bus[128];
	char parent_bus[64];
	char kind[64];
	char driver[32];
	char name[XDP_IFNAME_MAX];
	__u32 ifindex;
	__u32 peer_ifindex;
	/* The driver-mode XDP program it runs, and a generic or offloaded one. */
	__u32 xdp_drv_id;
	__u32 xdp_other_id;
	/* Why the driver or devlink facts could not be read, or 0. */
	int unclassified_err;
	__u32 flags;
	__u32 port_index;
	__u16 port_flavour;
	bool peer_other_netns;
	bool devlink_port;
	bool unresolved;
};

enum xdp_reconcile {
	XDP_RECONCILE_NONE,
	XDP_RECONCILE_COVERED,
	XDP_RECONCILE_ATTACH,
	XDP_RECONCILE_OCCUPIED,
};

/* attached is what the device runs now, 0 for nothing. */
enum xdp_reconcile xdp_reconcile_action(bool selected, __u32 attached,
					__u32 prog_id);

/* Whether a failed attach is left for a later pass rather than fatal. */
bool xdp_attach_skippable(int err, const struct xdp_device *dev);

int xdp_device_parse(const void *data, size_t len, struct xdp_device *out);
__u32 xdp_device_class(const struct xdp_device *dev);

/*
 * The program the device runs, 0 for none. shirudo attaches in driver
 * mode only, so a generic or offloaded program is another's.
 */
__u32 xdp_device_attached(const struct xdp_device *dev);
bool xdp_device_selected(const struct xdp_device *devs, size_t count,
			 size_t index, __u32 mask);
/*
 * 0 in the initial network namespace, -EXDEV in another. Devices, and the
 * hook of a netfilter link, are the caller's namespace's.
 */
int netns_initial(void);

/*
 * A device whose facts cannot be read sits out, unresolved, rather than
 * failing the read: it need not be one any upatch selects.
 */
int xdp_devices_read(struct xdp_device **out, size_t *count);
void xdp_devices_warn_unclassified(const struct xdp_device *devs,
				   size_t count);
int xdp_device_verify(const struct xdp_device *expected);
int xdp_features_parse(const void *data, size_t len, __u64 *features);
int xdp_device_features(__u32 ifindex, __u64 *features);

/* Native XDP without multi-buffer; a device with neither fails on its own. */
bool xdp_multibuf_refused(__u64 features);

/*
 * Whether a failed link create says the device has no native XDP. A driver
 * that has it refuses with the same EOPNOTSUPP in some settings, such as
 * virtio_net under host GRO_HW or bnxt with header-data split.
 */
bool xdp_attach_unsupported(int err, __u64 features);

/*
 * Whether a failed link create is the driver refusing in its current
 * settings: mlx5 with LRO says EINVAL, veth with too few rx queues ENOSPC,
 * a driver whose MTU is too large ERANGE.
 */
bool xdp_driver_refused(int err);

/* err is an enum xdp_attach_err or a negative errno. */
const char *xdp_attach_strerror(int err);

/* The negative errno a report carries for err. */
int xdp_attach_errno(int err);

/*
 * Why a device a program selects does not run it: attached as above,
 * features as read, unless features_err says they could not be.
 */
const char *xdp_uncovered_reason(__u32 attached, int features_err,
				 __u64 features);

#endif /* SHIRUDO_XDP_H */
