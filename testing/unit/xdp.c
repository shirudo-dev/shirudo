// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <net/if.h>
#include <linux/devlink.h>
#include <linux/genetlink.h>
#include <linux/netdev.h>
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

static void netdevsim_is_virtual_whatever_its_port_says(void)
{
	struct xdp_device dev = {};

	memcpy(dev.driver, "netdevsim", sizeof("netdevsim"));
	memcpy(dev.parent_bus, "netdevsim", sizeof("netdevsim"));
	EXPECT_UEQ(xdp_device_class(&dev), UPATCH_XDP_VIRTUAL);
	dev.devlink_port = true;
	dev.port_flavour = DEVLINK_PORT_FLAVOUR_PHYSICAL;
	EXPECT_UEQ(xdp_device_class(&dev), UPATCH_XDP_VIRTUAL);
}

static void xen_netback_is_virtual_though_named_vif(void)
{
	struct xdp_device dev = {};

	memcpy(dev.driver, "vif", sizeof("vif"));
	memcpy(dev.parent_bus, "xen", sizeof("xen"));
	EXPECT_UEQ(xdp_device_class(&dev), UPATCH_XDP_VM);
	memcpy(dev.parent_bus, "xen-backend", sizeof("xen-backend"));
	EXPECT_UEQ(xdp_device_class(&dev), UPATCH_XDP_VIRTUAL);
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

static void attach_fails_on_a_refusal_of_a_device_still_there(void)
{
	static const int skipped[] = { -EXDEV, -ENODEV };
	static const int refused[] = {
		-EINVAL, -ENOSPC, -ERANGE, -EEXIST, -EBUSY, -EMEDIUMTYPE,
		-ENOPROTOOPT, -EREMOTE, XDP_ERR_NO_MULTIBUF,
		XDP_ERR_DRIVER_SETTINGS, XDP_ERR_LINK_SCOPE, XDP_ERR_OCCUPIED,
	};
	/* No device has this index, so the kernel answers ENODEV. */
	struct xdp_device *devices = NULL, gone = { .ifindex = 0x7ffffff0 };
	/* Index 0 names no device, so the lookup itself fails with EINVAL. */
	struct xdp_device unaskable = {};
	size_t count = 0, i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(skipped); i++)
		EXPECT_TRUE(xdp_attach_skippable(skipped[i], &gone));
	EXPECT_TRUE(xdp_attach_skippable(-EINVAL, &gone));
	EXPECT_FALSE(xdp_attach_skippable(-EINVAL, &unaskable));
	EXPECT_FALSE(xdp_attach_skippable(XDP_ERR_LINK_SCOPE, &gone));
	EXPECT_FALSE(xdp_attach_skippable(-EACCES, &gone));
	EXPECT_FALSE(xdp_attach_skippable(-EPERM, &gone));
	EXPECT_FALSE(xdp_attach_skippable(0, &gone));

	ret = xdp_devices_read(&devices, &count);
	if (ret == -EPERM || ret == -EACCES || ret == -EAFNOSUPPORT)
		unit_skip("kernel network discovery unavailable");
	ASSERT_EQ(ret, 0);
	ASSERT_TRUE(count > 0);
	for (i = 0; i < ARRAY_SIZE(refused); i++)
		EXPECT_FALSE(xdp_attach_skippable(refused[i], &devices[0]));
	xfree(devices, count * sizeof(*devices));
}

/* Gone or not, a device that answers busy runs another program. */
static void attach_stops_on_an_occupied_device(void)
{
	struct xdp_device dev = {}, gone = { .ifindex = 0x7ffffff0 };

	EXPECT_FALSE(xdp_attach_skippable(XDP_ERR_OCCUPIED, &dev));
	EXPECT_FALSE(xdp_attach_skippable(XDP_ERR_OCCUPIED, &gone));
	EXPECT_FALSE(xdp_attach_skippable(-EEXIST, &dev));
	EXPECT_FALSE(xdp_attach_skippable(-EBUSY, &dev));
	EXPECT_TRUE(xdp_attach_skippable(-EXDEV, &dev));
	EXPECT_TRUE(xdp_attach_skippable(-ENODEV, &dev));
	EXPECT_FALSE(xdp_attach_skippable(0, &dev));
}

static void multibuf_is_required_of_native_xdp_alone(void)
{
	const __u64 basic = NETDEV_XDP_ACT_BASIC;
	const __u64 sg = NETDEV_XDP_ACT_RX_SG;

	EXPECT_TRUE(xdp_multibuf_refused(basic));
	EXPECT_TRUE(xdp_multibuf_refused(basic | NETDEV_XDP_ACT_REDIRECT));
	EXPECT_FALSE(xdp_multibuf_refused(basic | sg));
	EXPECT_FALSE(xdp_multibuf_refused(0));
	EXPECT_FALSE(xdp_multibuf_refused(sg));
	EXPECT_STREQ(xdp_attach_strerror(XDP_ERR_NO_MULTIBUF),
		     "the device does not report multi-buffer XDP support");
	EXPECT_STREQ(xdp_attach_strerror(-EINVAL), strerror(EINVAL));
}

static void only_a_device_without_xdp_lacks_it(void)
{
	const __u64 basic = NETDEV_XDP_ACT_BASIC;

	EXPECT_TRUE(xdp_attach_unsupported(-EOPNOTSUPP, 0));
	EXPECT_FALSE(xdp_attach_unsupported(-EOPNOTSUPP, basic));
	EXPECT_FALSE(xdp_attach_unsupported(-EINVAL, 0));
	EXPECT_FALSE(xdp_attach_unsupported(0, 0));
	EXPECT_STREQ(xdp_attach_strerror(XDP_ERR_DRIVER_SETTINGS),
		     "the driver refuses XDP in its current settings");
	EXPECT_STREQ(xdp_attach_strerror(XDP_ERR_LINK_SCOPE),
		     "the link is not on the device it was made for");
}

static void a_driver_refusal_is_told_from_other_errors(void)
{
	EXPECT_TRUE(xdp_driver_refused(-EOPNOTSUPP));
	EXPECT_TRUE(xdp_driver_refused(-EINVAL));
	EXPECT_TRUE(xdp_driver_refused(-ENOSPC));
	EXPECT_TRUE(xdp_driver_refused(-ERANGE));
	EXPECT_FALSE(xdp_driver_refused(-EBUSY));
	EXPECT_FALSE(xdp_driver_refused(-ENOMEM));
	EXPECT_FALSE(xdp_driver_refused(-EPERM));
	EXPECT_FALSE(xdp_driver_refused(0));
}

static void attach_errors_never_alias_an_errno(void)
{
	EXPECT_EQ(xdp_attach_errno(XDP_ERR_NO_MULTIBUF), -EMEDIUMTYPE);
	EXPECT_EQ(xdp_attach_errno(XDP_ERR_DRIVER_SETTINGS), -ENOPROTOOPT);
	EXPECT_EQ(xdp_attach_errno(XDP_ERR_OCCUPIED), -EBUSY);
	EXPECT_EQ(xdp_attach_errno(XDP_ERR_LINK_SCOPE), -EREMOTE);
	EXPECT_EQ(xdp_attach_errno(-EBUSY), -EBUSY);
	EXPECT_TRUE(XDP_ERR_NO_NATIVE > 0);
	EXPECT_STREQ(xdp_attach_strerror(XDP_ERR_OCCUPIED),
		     "the device runs another XDP program");
	EXPECT_STREQ(xdp_attach_strerror(-EBUSY), strerror(EBUSY));
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

static void uncovered_devices_say_why(void)
{
	__u64 basic = NETDEV_XDP_ACT_BASIC, sg = NETDEV_XDP_ACT_RX_SG;

	EXPECT_STREQ(xdp_uncovered_reason(9, 0, basic | sg),
		     "another XDP program attached");
	EXPECT_STREQ(xdp_uncovered_reason(0, -EOPNOTSUPP, 0), "not attached");
	EXPECT_STREQ(xdp_uncovered_reason(0, 0, 0), "no native XDP");
	EXPECT_STREQ(xdp_uncovered_reason(0, 0, basic), "no multi-buffer XDP");
	EXPECT_STREQ(xdp_uncovered_reason(0, 0, basic | sg), "not attached");
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
	EXPECT_UEQ(xdp_device_attached(&dev), 0);
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

static void every_xdp_mode_is_read_from_the_dump(void)
{
	struct ifinfomsg info = { .ifi_index = 3 };
	__u32 drv = 21, skb = 22, hw = 23;
	__u8 buf[256] = {}, nested[64];
	struct xdp_device dev;
	size_t len, n, base;

	memcpy(buf, &info, sizeof(info));
	base = add_attr(buf, sizeof(info), IFLA_IFNAME, "eth0", sizeof("eth0"));
	memset(nested, 0, sizeof(nested));
	n = add_attr(nested, 0, IFLA_XDP_SKB_PROG_ID, &skb, sizeof(skb));
	len = add_attr(buf, base, IFLA_XDP | NLA_F_NESTED, nested, n);
	ASSERT_EQ(xdp_device_parse(buf, len, &dev), 0);
	EXPECT_UEQ(dev.xdp_drv_id, 0);
	EXPECT_UEQ(xdp_device_attached(&dev), skb);
	EXPECT_EQ(xdp_reconcile_action(true, xdp_device_attached(&dev), 7),
		  XDP_RECONCILE_OCCUPIED);

	memset(nested, 0, sizeof(nested));
	n = add_attr(nested, 0, IFLA_XDP_HW_PROG_ID, &hw, sizeof(hw));
	n = add_attr(nested, n, IFLA_XDP_DRV_PROG_ID, &drv, sizeof(drv));
	len = add_attr(buf, base, IFLA_XDP | NLA_F_NESTED, nested, n);
	ASSERT_EQ(xdp_device_parse(buf, len, &dev), 0);
	EXPECT_UEQ(xdp_device_attached(&dev), drv);
	EXPECT_UEQ(dev.xdp_other_id, hw);

	memset(nested, 0, sizeof(nested));
	n = add_attr(nested, 0, IFLA_XDP_DRV_PROG_ID, &drv, sizeof(__u16));
	len = add_attr(buf, base, IFLA_XDP | NLA_F_NESTED, nested, n);
	EXPECT_EQ(xdp_device_parse(buf, len, &dev), -EINVAL);
}

static void device_features_are_checked(void)
{
	__u64 value = NETDEV_XDP_ACT_BASIC | NETDEV_XDP_ACT_RX_SG, out = 0;
	__u32 ifindex = 7, small = 1;
	__u8 buf[64] = {};
	size_t len;

	len = add_attr(buf, GENL_HDRLEN, NETDEV_A_DEV_IFINDEX, &ifindex,
		       sizeof(ifindex));
	EXPECT_EQ(xdp_features_parse(buf, len, &out), -EINVAL);
	EXPECT_EQ(xdp_features_parse(buf, GENL_HDRLEN - 1, &out), -EINVAL);
	len = add_attr(buf, len, NETDEV_A_DEV_XDP_FEATURES, &value, sizeof(value));
	ASSERT_EQ(xdp_features_parse(buf, len, &out), 0);
	EXPECT_UEQ(out, value);
	len = add_attr(buf, GENL_HDRLEN, NETDEV_A_DEV_XDP_FEATURES, &small,
		       sizeof(small));
	EXPECT_EQ(xdp_features_parse(buf, len, &out), -EINVAL);
}

static void the_network_namespace_is_known(void)
{
	int ret;

	/* CI runs riscv64 under QEMU user emulation, which lacks the option. */
#ifdef __riscv
	unit_skip("SO_NETNS_COOKIE unavailable under emulation");
#endif
	ret = netns_initial();
	EXPECT_TRUE(ret == 0 || ret == -EXDEV);
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
	UNIT_CASE(netdevsim_is_virtual_whatever_its_port_says),
	UNIT_CASE(xen_netback_is_virtual_though_named_vif),
	UNIT_CASE(veth_peers_are_namespace_aware),
	UNIT_CASE(veth_without_a_peer_is_not_selected),
	UNIT_CASE(unresolved_devices_sit_out),
	UNIT_CASE(reconcile_never_touches_another_program),
	UNIT_CASE(attach_fails_on_a_refusal_of_a_device_still_there),
	UNIT_CASE(attach_stops_on_an_occupied_device),
	UNIT_CASE(multibuf_is_required_of_native_xdp_alone),
	UNIT_CASE(uncovered_devices_say_why),
	UNIT_CASE(only_a_device_without_xdp_lacks_it),
	UNIT_CASE(a_driver_refusal_is_told_from_other_errors),
	UNIT_CASE(attach_errors_never_alias_an_errno),
	UNIT_CASE(every_xdp_mode_is_read_from_the_dump),
	UNIT_CASE(device_features_are_checked),
	UNIT_CASE(link_messages_are_checked),
	UNIT_CASE(the_network_namespace_is_known),
	UNIT_CASE(kernel_discovery_revalidates_devices),
	{}
};

UNIT_SUITE(xdp, cases);
