/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_XDP_H
#define SHIRUDO_XDP_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/misc.h>

#define XDP_IFNAME_MAX 16

struct xdp_device {
	char devlink_device[128];
	char devlink_bus[128];
	char parent_bus[64];
	char kind[64];
	char driver[32];
	char name[XDP_IFNAME_MAX];
	__u32 ifindex;
	__u32 peer_ifindex;
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

int xdp_device_parse(const void *data, size_t len, struct xdp_device *out);
__u32 xdp_device_class(const struct xdp_device *dev);
bool xdp_device_selected(const struct xdp_device *devs, size_t count,
			 size_t index, __u32 mask);
int xdp_devices_read(struct xdp_device **out, size_t *count);
int xdp_device_verify(const struct xdp_device *expected);

#endif /* SHIRUDO_XDP_H */
