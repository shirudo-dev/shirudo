// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <net/if.h>
#include <linux/devlink.h>
#include <linux/rtnetlink.h>

#include <shirudo/upatch.h>

#include "unit.h"
#include "malloc.h"
#include "xdp.h"

static void classes_are_exclusive(void)
{
	struct xdp_device dev = {};

	EXPECT_UEQ(xdp_device_class(&dev), UPATCH_XDP_UNKNOWN);
	memcpy(dev.kind, "veth", sizeof("veth"));
	EXPECT_UEQ(xdp_device_class(&dev), UPATCH_XDP_VIRTUAL);
	memcpy(dev.parent_bus, "pci", sizeof("pci"));
	EXPECT_UEQ(xdp_device_class(&dev), UPATCH_XDP_NETWORK);
	dev.devlink_port = true;
	dev.port_flavour = DEVLINK_PORT_FLAVOUR_PCI_VF;
	EXPECT_UEQ(xdp_device_class(&dev), UPATCH_XDP_VIRTUAL);
	dev.port_flavour = DEVLINK_PORT_FLAVOUR_PHYSICAL;
	EXPECT_UEQ(xdp_device_class(&dev), UPATCH_XDP_NETWORK);
	dev.port_flavour = 65535;
	EXPECT_UEQ(xdp_device_class(&dev), UPATCH_XDP_UNKNOWN);
	memcpy(dev.driver, "virtio_net", sizeof("virtio_net"));
	EXPECT_UEQ(xdp_device_class(&dev), UPATCH_XDP_VM);
	dev.flags = IFF_LOOPBACK;
	EXPECT_UEQ(xdp_device_class(&dev), 0);
	EXPECT_FALSE(xdp_device_selected(&dev, 1, 0, UPATCH_XDP_ALL));
}

static void veth_peers_are_namespace_aware(void)
{
	struct xdp_device devs[4] = {};
	size_t i;

	for (i = 0; i < 4; i++) {
		memcpy(devs[i].kind, "veth", sizeof("veth"));
		devs[i].ifindex = (__u32)i + 10;
	}
	devs[0].peer_ifindex = 11;
	devs[1].peer_ifindex = 10;
	EXPECT_TRUE(xdp_device_selected(devs, 4, 0, UPATCH_XDP_VIRTUAL));
	EXPECT_FALSE(xdp_device_selected(devs, 4, 1, UPATCH_XDP_ALL));
	EXPECT_FALSE(xdp_device_selected(devs, 4, 0, UPATCH_XDP_UNKNOWN));
	devs[2].peer_ifindex = 13;
	devs[3].peer_ifindex = 12;
	devs[2].peer_other_netns = true;
	devs[3].peer_other_netns = true;
	EXPECT_TRUE(xdp_device_selected(devs, 4, 2, UPATCH_XDP_VIRTUAL));
	EXPECT_TRUE(xdp_device_selected(devs, 4, 3, UPATCH_XDP_VIRTUAL));
	devs[0].peer_other_netns = true;
	devs[1].peer_other_netns = true;
	EXPECT_TRUE(xdp_device_selected(devs, 4, 0, UPATCH_XDP_VIRTUAL));
	EXPECT_TRUE(xdp_device_selected(devs, 4, 1, UPATCH_XDP_VIRTUAL));
}

static void veth_without_a_peer_is_not_selected(void)
{
	struct xdp_device devs[2] = {};

	memcpy(devs[0].kind, "veth", sizeof("veth"));
	memcpy(devs[1].kind, "veth", sizeof("veth"));
	devs[0].ifindex = 10;
	devs[0].peer_ifindex = 99;
	devs[1].ifindex = 11;
	devs[1].peer_ifindex = 11;
	EXPECT_FALSE(xdp_device_selected(devs, 2, 0, UPATCH_XDP_ALL));
	EXPECT_FALSE(xdp_device_selected(devs, 2, 1, UPATCH_XDP_ALL));
}

static void unresolved_devices_sit_out(void)
{
	struct xdp_device devs[3] = {};
	size_t i;

	for (i = 0; i < 3; i++) {
		memcpy(devs[i].kind, "veth", sizeof("veth"));
		devs[i].ifindex = (__u32)i + 10;
	}
	devs[0].peer_ifindex = 11;
	devs[1].peer_ifindex = 10;
	devs[2].peer_ifindex = 7;
	devs[2].peer_other_netns = true;
	devs[1].unresolved = true;
	EXPECT_FALSE(xdp_device_selected(devs, 3, 0, UPATCH_XDP_ALL));
	EXPECT_FALSE(xdp_device_selected(devs, 3, 1, UPATCH_XDP_ALL));
	EXPECT_TRUE(xdp_device_selected(devs, 3, 2, UPATCH_XDP_ALL));
	devs[2].unresolved = true;
	EXPECT_FALSE(xdp_device_selected(devs, 3, 2, UPATCH_XDP_ALL));
}

static void reconcile_never_touches_another_program(void)
{
	EXPECT_EQ(xdp_reconcile_action(false, 0, 7), XDP_RECONCILE_NONE);
	EXPECT_EQ(xdp_reconcile_action(false, 7, 7), XDP_RECONCILE_NONE);
	EXPECT_EQ(xdp_reconcile_action(false, 9, 7), XDP_RECONCILE_NONE);
	EXPECT_EQ(xdp_reconcile_action(true, 0, 7), XDP_RECONCILE_ATTACH);
	EXPECT_EQ(xdp_reconcile_action(true, 7, 7), XDP_RECONCILE_COVERED);
	EXPECT_EQ(xdp_reconcile_action(true, 9, 7), XDP_RECONCILE_OCCUPIED);
}

static void restore_fails_on_a_driver_refusal(void)
{
	static const int skipped[] = { -EBUSY, -EEXIST, -EXDEV, -ENODEV };
	static const int refused[] = { -EINVAL, -ENOSPC, -ERANGE };
	/* No device has this index, so the kernel answers ENODEV. */
	struct xdp_device *devices = NULL, gone = { .ifindex = 0x7ffffff0 };
	/* Index 0 names no device, so the lookup itself fails with EINVAL. */
	struct xdp_device unaskable = {};
	size_t count = 0, i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(skipped); i++)
		EXPECT_TRUE(xdp_attach_skippable(skipped[i], &gone, true));
	EXPECT_TRUE(xdp_attach_skippable(-EINVAL, &gone, true));
	EXPECT_FALSE(xdp_attach_skippable(-EINVAL, &unaskable, true));
	EXPECT_FALSE(xdp_attach_skippable(-EINVAL, &unaskable, false));
	EXPECT_FALSE(xdp_attach_skippable(-EACCES, &gone, true));
	EXPECT_FALSE(xdp_attach_skippable(-EPERM, &gone, true));
	EXPECT_FALSE(xdp_attach_skippable(0, &gone, true));
	EXPECT_FALSE(xdp_attach_skippable(1, &gone, true));

	ret = xdp_devices_read(&devices, &count);
	if (ret == -EPERM || ret == -EACCES || ret == -EAFNOSUPPORT)
		unit_skip("kernel network discovery unavailable");
	ASSERT_EQ(ret, 0);
	ASSERT_TRUE(count > 0);
	for (i = 0; i < ARRAY_SIZE(refused); i++)
		EXPECT_FALSE(xdp_attach_skippable(refused[i], &devices[0], true));
	xfree(devices, count * sizeof(*devices));
}

static void load_stops_on_an_occupied_device(void)
{
	struct xdp_device dev = {};

	EXPECT_FALSE(xdp_attach_skippable(-EBUSY, &dev, false));
	EXPECT_FALSE(xdp_attach_skippable(-EEXIST, &dev, false));
	EXPECT_TRUE(xdp_attach_skippable(-EXDEV, &dev, false));
	EXPECT_TRUE(xdp_attach_skippable(-ENODEV, &dev, false));
	EXPECT_FALSE(xdp_attach_skippable(0, &dev, false));
}

static size_t add_attr(__u8 *buf, size_t len, __u16 type,
		       const void *value, size_t size)
{
	struct nlattr attr = {
		.nla_len = (__u16)(NLA_HDRLEN + size),
		.nla_type = type,
	};

	memcpy(buf + len, &attr, sizeof(attr));
	memcpy(buf + len + NLA_HDRLEN, value, size);
	return len + NLA_ALIGN(attr.nla_len);
}

static void link_messages_are_checked(void)
{
	struct ifinfomsg info = { .ifi_index = 12 };
	struct xdp_device dev;
	__u8 buf[256] = {};
	__u8 nested[32] = {};
	__u32 peer = 13;
	__s32 nsid = 4;
	size_t len, n;

	memcpy(buf, &info, sizeof(info));
	len = add_attr(buf, sizeof(info), IFLA_IFNAME, "veth0", sizeof("veth0"));
	len = add_attr(buf, len, IFLA_LINK, &peer, sizeof(peer));
	len = add_attr(buf, len, IFLA_LINK_NETNSID, &nsid, sizeof(nsid));
	n = add_attr(nested, 0, IFLA_INFO_KIND, "veth", sizeof("veth"));
	len = add_attr(buf, len, IFLA_LINKINFO | NLA_F_NESTED, nested, n);
	ASSERT_EQ(xdp_device_parse(buf, len, &dev), 0);
	EXPECT_STREQ(dev.name, "veth0");
	EXPECT_STREQ(dev.kind, "veth");
	EXPECT_UEQ(dev.ifindex, 12);
	EXPECT_UEQ(dev.peer_ifindex, 13);
	EXPECT_TRUE(dev.peer_other_netns);
	for (n = 0; n < sizeof(info) + NLA_HDRLEN + sizeof("veth0"); n++)
		EXPECT_EQ(xdp_device_parse(buf, n, &dev), -EINVAL);
	EXPECT_EQ(xdp_device_parse(buf, len - 1, &dev), -EINVAL);
	len = add_attr(buf, len, IFLA_IFNAME, "other", sizeof("other"));
	EXPECT_EQ(xdp_device_parse(buf, len, &dev), -EINVAL);
	memset(buf, 0, sizeof(buf));
	memcpy(buf, &info, sizeof(info));
	len = add_attr(buf, sizeof(info), IFLA_IFNAME, "no-nul", 6);
	EXPECT_EQ(xdp_device_parse(buf, len, &dev), -EINVAL);
}

static void kernel_discovery_revalidates_devices(void)
{
	struct xdp_device *devices = NULL;
	size_t count = 0, i;
	int ret;

	ret = xdp_devices_read(&devices, &count);
	if (ret == -EPERM || ret == -EACCES || ret == -EAFNOSUPPORT)
		unit_skip("kernel network discovery unavailable");
	ASSERT_EQ(ret, 0);
	EXPECT_TRUE(count > 0);
	for (i = 0; i < count; i++) {
		EXPECT_EQ(xdp_device_verify(&devices[i]), 0);
		if (i)
			EXPECT_TRUE(devices[i - 1].ifindex < devices[i].ifindex);
	}
	xfree(devices, count * sizeof(*devices));
}

static const struct unit_case cases[] = {
	UNIT_CASE(classes_are_exclusive),
	UNIT_CASE(veth_peers_are_namespace_aware),
	UNIT_CASE(veth_without_a_peer_is_not_selected),
	UNIT_CASE(unresolved_devices_sit_out),
	UNIT_CASE(reconcile_never_touches_another_program),
	UNIT_CASE(restore_fails_on_a_driver_refusal),
	UNIT_CASE(load_stops_on_an_occupied_device),
	UNIT_CASE(link_messages_are_checked),
	UNIT_CASE(kernel_discovery_revalidates_devices),
	{}
};

UNIT_SUITE(xdp, cases);
