// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <linux/devlink.h>
#include <linux/ethtool.h>
#include <linux/genetlink.h>
#include <linux/netdev.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>

#include <shirudo/overflow.h>
#include <shirudo/string.h>
#include <shirudo/upatch.h>

#include "malloc.h"
#include "xdp.h"

#define NETLINK_BUFFER_SIZE 65536U
#define DEVICES_READ_ATTEMPTS 5U

struct nl_request {
	struct nlmsghdr hdr;
	__u8 data[512];
};

typedef int (*nl_receive_fn)(const void *data, size_t len, void *ctx);

static int attr_find(const void *data, size_t len, __u16 type,
		     const struct nlattr **out)
{
	const __u8 *cursor = data;

	*out = NULL;
	while (len) {
		const struct nlattr *attr = (const void *)cursor;
		size_t step;

		if (len < NLA_HDRLEN || attr->nla_len < NLA_HDRLEN ||
		    attr->nla_len > len)
			return -EINVAL;
		step = NLA_ALIGN(attr->nla_len);
		if (step > len)
			return -EINVAL;
		if ((attr->nla_type & NLA_TYPE_MASK) == type) {
			if (*out)
				return -EINVAL;
			*out = attr;
		}
		cursor += step;
		len -= step;
	}
	return 0;
}

static int attr_string(const void *data, size_t len, __u16 type,
		       char *out, size_t cap)
{
	const struct nlattr *attr;
	const char *value;
	size_t size;
	int ret;

	ret = attr_find(data, len, type, &attr);
	if (ret || !attr)
		return ret;
	size = attr->nla_len - NLA_HDRLEN;
	value = (const char *)attr + NLA_HDRLEN;
	if (!size || size > cap || value[size - 1] ||
	    memchr(value, '\0', size - 1))
		return -EINVAL;
	memcpy(out, value, size);
	return 0;
}

static int attr_number(const void *data, size_t len, __u16 type,
		       void *out, size_t size, bool *present)
{
	const struct nlattr *attr;
	int ret;

	ret = attr_find(data, len, type, &attr);
	if (ret || !attr)
		return ret;
	if (attr->nla_len != NLA_HDRLEN + size)
		return -EINVAL;
	memcpy(out, (const __u8 *)attr + NLA_HDRLEN, size);
	if (present)
		*present = true;
	return 0;
}

static int attr_put(struct nl_request *req, __u16 type,
		    const void *data, size_t len)
{
	size_t size = size_add(NLA_HDRLEN, len);
	size_t end = size_add(req->hdr.nlmsg_len, NLA_ALIGN(size));
	struct nlattr *attr;

	if (end > sizeof(*req))
		return -E2BIG;
	attr = (void *)((__u8 *)req + req->hdr.nlmsg_len);
	attr->nla_type = type;
	attr->nla_len = (__u16)size;
	memcpy((__u8 *)attr + NLA_HDRLEN, data, len);
	req->hdr.nlmsg_len = (__u32)end;
	return 0;
}

static int nl_exchange(int protocol, struct nl_request *req,
		       nl_receive_fn receive, void *ctx)
{
	struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
	struct timeval timeout = { .tv_sec = 5 };
	__u8 *buf = NULL;
	int fd, ret;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, protocol);
	if (fd < 0)
		return -errno;
	ret = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	if (ret) {
		ret = -errno;
		goto out;
	}
	buf = xmalloc(NETLINK_BUFFER_SIZE);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}
	req->hdr.nlmsg_seq = 1;
	if (sendto(fd, req, req->hdr.nlmsg_len, 0,
		   (const struct sockaddr *)&kernel, sizeof(kernel)) < 0) {
		ret = -errno;
		goto out;
	}
	for (;;) {
		struct iovec iov = { .iov_base = buf, .iov_len = NETLINK_BUFFER_SIZE };
		struct sockaddr_nl sender = {};
		struct msghdr msg = {
			.msg_name = &sender,
			.msg_namelen = sizeof(sender),
			.msg_iov = &iov,
			.msg_iovlen = 1,
		};
		const __u8 *cursor = buf;
		ssize_t n;

		n = recvmsg(fd, &msg, 0);
		if (n < 0) {
			/* EAGAIN is SO_RCVTIMEO, not a dump to start again. */
			ret = errno == EAGAIN ? -ETIMEDOUT : -errno;
			goto out;
		}
		if (!n || msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC) ||
		    msg.msg_namelen != sizeof(sender) || sender.nl_pid ||
		    sender.nl_family != AF_NETLINK) {
			ret = -EBADMSG;
			goto out;
		}
		while (n) {
			const struct nlmsghdr *hdr = (const void *)cursor;
			size_t len, step;

			ret = -EBADMSG;
			if ((size_t)n < sizeof(*hdr) ||
			    hdr->nlmsg_len < sizeof(*hdr) || hdr->nlmsg_len > (__u32)n)
				goto out;
			step = NLMSG_ALIGN(hdr->nlmsg_len);
			if (step > (size_t)n || hdr->nlmsg_seq != 1)
				goto out;
			if (hdr->nlmsg_flags & NLM_F_DUMP_INTR) {
				ret = -EAGAIN;
				goto out;
			}
			len = hdr->nlmsg_len - sizeof(*hdr);
			if (hdr->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr err;

				if (len < sizeof(err))
					goto out;
				memcpy(&err, cursor + sizeof(*hdr), sizeof(err));
				ret = err.error <= 0 ? err.error : -EBADMSG;
				goto out;
			}
			if (hdr->nlmsg_type == NLMSG_DONE) {
				int err = 0;

				if (len && len < sizeof(err))
					goto out;
				if (len)
					memcpy(&err, cursor + sizeof(*hdr), sizeof(err));
				ret = err <= 0 ? err : -EBADMSG;
				goto out;
			}
			ret = receive(cursor + sizeof(*hdr), len, ctx);
			if (ret || !(hdr->nlmsg_flags & NLM_F_MULTI))
				goto out;
			cursor += step;
			n -= (ssize_t)step;
		}
	}
out:
	xfree(buf, NETLINK_BUFFER_SIZE);
	close(fd);
	return ret;
}

int xdp_device_parse(const void *data, size_t len, struct xdp_device *out)
{
	const struct nlattr *linkinfo, *port;
	bool port_present = false;
	struct ifinfomsg info;
	__s32 peer_netns = 0;
	const __u8 *attrs;
	int ret;

	memset(out, 0, sizeof(*out));
	out->port_flavour = UINT16_MAX;
	if (len < sizeof(info))
		return -EINVAL;
	memcpy(&info, data, sizeof(info));
	if (info.ifi_index <= 0)
		return -EINVAL;
	out->ifindex = (__u32)info.ifi_index;
	out->flags = info.ifi_flags;
	attrs = (const __u8 *)data + sizeof(info);
	len -= sizeof(info);
	ret = attr_string(attrs, len, IFLA_IFNAME, out->name, sizeof(out->name));
	if (ret || !out->name[0])
		return ret ? ret : -EINVAL;
	ret = attr_number(attrs, len, IFLA_LINK, &out->peer_ifindex,
			  sizeof(out->peer_ifindex), NULL);
	if (ret)
		return ret;
	ret = attr_number(attrs, len, IFLA_LINK_NETNSID, &peer_netns,
			  sizeof(peer_netns), &out->peer_other_netns);
	if (ret)
		return ret;
	ret = attr_string(attrs, len, IFLA_PARENT_DEV_BUS_NAME, out->parent_bus,
			  sizeof(out->parent_bus));
	if (ret)
		return ret;
	ret = attr_find(attrs, len, IFLA_LINKINFO, &linkinfo);
	if (ret)
		return ret;
	if (linkinfo) {
		ret = attr_string((const __u8 *)linkinfo + NLA_HDRLEN,
				  linkinfo->nla_len - NLA_HDRLEN, IFLA_INFO_KIND,
				  out->kind, sizeof(out->kind));
		if (ret)
			return ret;
	}
	ret = attr_find(attrs, len, IFLA_DEVLINK_PORT, &port);
	if (ret || !port || port->nla_len == NLA_HDRLEN)
		return ret;
	attrs = (const __u8 *)port + NLA_HDRLEN;
	len = port->nla_len - NLA_HDRLEN;
	out->devlink_port = true;
	ret = attr_string(attrs, len, DEVLINK_ATTR_BUS_NAME, out->devlink_bus,
			  sizeof(out->devlink_bus));
	if (ret)
		return ret;
	ret = attr_string(attrs, len, DEVLINK_ATTR_DEV_NAME, out->devlink_device,
			  sizeof(out->devlink_device));
	if (ret || !out->devlink_bus[0] || !out->devlink_device[0])
		return ret ? ret : -EINVAL;
	ret = attr_number(attrs, len, DEVLINK_ATTR_PORT_INDEX, &out->port_index,
			  sizeof(out->port_index), &port_present);
	return ret ? ret : port_present ? 0 : -EINVAL;
}

__u32 xdp_device_class(const struct xdp_device *dev)
{
	static const char * const vm_drivers[] = {
		"virtio_net", "vmxnet3", "hv_netvsc", "xen-netfront", "vif",
	};
	size_t i;

	if (dev->flags & IFF_LOOPBACK)
		return 0;
	for (i = 0; i < ARRAY_SIZE(vm_drivers); i++)
		if (!strcmp(dev->driver, vm_drivers[i]))
			return UPATCH_XDP_VM;
	/* Its ports are simulated, whatever flavour they claim. */
	if (!strcmp(dev->driver, "netdevsim"))
		return UPATCH_XDP_VIRTUAL;
	if (dev->devlink_port) {
		switch (dev->port_flavour) {
		case DEVLINK_PORT_FLAVOUR_PHYSICAL:
			return UPATCH_XDP_NETWORK;
		case DEVLINK_PORT_FLAVOUR_CPU:
		case DEVLINK_PORT_FLAVOUR_DSA:
		case DEVLINK_PORT_FLAVOUR_PCI_PF:
		case DEVLINK_PORT_FLAVOUR_PCI_VF:
		case DEVLINK_PORT_FLAVOUR_VIRTUAL:
		case DEVLINK_PORT_FLAVOUR_PCI_SF:
			return UPATCH_XDP_VIRTUAL;
		default:
			return UPATCH_XDP_UNKNOWN;
		}
	}
	if (dev->parent_bus[0])
		return UPATCH_XDP_NETWORK;
	if (dev->kind[0])
		return UPATCH_XDP_VIRTUAL;
	return UPATCH_XDP_UNKNOWN;
}

static const struct xdp_device *veth_peer(const struct xdp_device *devs,
					  size_t count,
					  const struct xdp_device *dev)
{
	size_t i;

	for (i = 0; i < count; i++) {
		const struct xdp_device *peer = &devs[i];

		if (peer->ifindex != dev->ifindex &&
		    peer->ifindex == dev->peer_ifindex &&
		    peer->peer_ifindex == dev->ifindex &&
		    !peer->peer_other_netns && !peer->unresolved &&
		    !strcmp(peer->kind, "veth"))
			return peer;
	}
	return NULL;
}

bool xdp_device_selected(const struct xdp_device *devs, size_t count,
			 size_t index, __u32 mask)
{
	const struct xdp_device *dev = &devs[index];
	const struct xdp_device *peer;

	if (dev->unresolved || !(xdp_device_class(dev) & mask))
		return false;
	if (strcmp(dev->kind, "veth") || dev->peer_other_netns)
		return true;
	peer = veth_peer(devs, count, dev);
	return peer && dev->ifindex < peer->ifindex;
}

enum xdp_reconcile xdp_reconcile_action(bool selected, __u32 attached,
					__u32 prog_id)
{
	if (!selected)
		return XDP_RECONCILE_NONE;
	if (!attached)
		return XDP_RECONCILE_ATTACH;
	return attached == prog_id ? XDP_RECONCILE_COVERED : XDP_RECONCILE_OCCUPIED;
}

struct device_list {
	struct xdp_device *devices;
	size_t count;
};

static int receive_device(const void *data, size_t len, void *ctx)
{
	struct device_list *list = ctx;
	struct xdp_device dev, *grown;
	size_t count;
	int ret;

	ret = xdp_device_parse(data, len, &dev);
	if (ret)
		return ret;
	if (check_add_overflow(list->count, 1, &count))
		return -EOVERFLOW;
	grown = xreallocarray(list->devices, list->count, count, sizeof(dev));
	if (!grown)
		return -ENOMEM;
	list->devices = grown;
	list->devices[list->count++] = dev;
	return 0;
}

static int receive_family(const void *data, size_t len, void *ctx)
{
	if (len < GENL_HDRLEN)
		return -EINVAL;
	return attr_number((const __u8 *)data + GENL_HDRLEN, len - GENL_HDRLEN,
			   CTRL_ATTR_FAMILY_ID, ctx, sizeof(__u16), NULL);
}

static int genl_family(const char *name, __u16 *id)
{
	struct nl_request req = {
		.hdr.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN),
		.hdr.nlmsg_type = GENL_ID_CTRL,
		.hdr.nlmsg_flags = NLM_F_REQUEST,
	};
	struct genlmsghdr genl = { .cmd = CTRL_CMD_GETFAMILY, .version = 1 };
	int ret;

	memcpy(req.data, &genl, sizeof(genl));
	ret = attr_put(&req, CTRL_ATTR_FAMILY_NAME, name, strlen(name) + 1);
	return ret ? ret : nl_exchange(NETLINK_GENERIC, &req, receive_family, id);
}

static int receive_port(const void *data, size_t len, void *ctx)
{
	struct xdp_device *dev = ctx;

	if (len < GENL_HDRLEN)
		return -EINVAL;
	return attr_number((const __u8 *)data + GENL_HDRLEN, len - GENL_HDRLEN,
			   DEVLINK_ATTR_PORT_FLAVOUR, &dev->port_flavour,
			   sizeof(dev->port_flavour), NULL);
}

static int device_details(struct xdp_device *dev)
{
	struct ethtool_drvinfo driver = { .cmd = ETHTOOL_GDRVINFO };
	struct ifreq identity = {};
	struct ifreq ifr = {};
	int fd, ret;

	if (strscpy(ifr.ifr_name, dev->name, sizeof(ifr.ifr_name)) < 0)
		return -EINVAL;
	identity = ifr;
	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	if (ioctl(fd, SIOCGIFINDEX, &identity) ||
	    identity.ifr_ifindex != (int)dev->ifindex) {
		close(fd);
		return -EXDEV;
	}
	ifr.ifr_data = (void *)&driver;
	ret = ioctl(fd, SIOCETHTOOL, &ifr) ? -errno : 0;
	if (ioctl(fd, SIOCGIFINDEX, &identity) ||
	    identity.ifr_ifindex != (int)dev->ifindex)
		ret = -EXDEV;
	close(fd);
	if (ret && ret != -EOPNOTSUPP && ret != -ENOTTY)
		return ret;
	if (!ret) {
		if (!memchr(driver.driver, '\0', sizeof(driver.driver)))
			return -EINVAL;
		memcpy(dev->driver, driver.driver, sizeof(dev->driver));
	}
	if (dev->devlink_port) {
		struct nl_request req = {
			.hdr.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN),
			.hdr.nlmsg_flags = NLM_F_REQUEST,
		};
		struct genlmsghdr genl = {
			.cmd = DEVLINK_CMD_PORT_GET,
			.version = DEVLINK_GENL_VERSION,
		};
		__u16 family = 0;

		ret = genl_family(DEVLINK_GENL_NAME, &family);
		if (ret || !family)
			return ret ? ret : -EINVAL;
		req.hdr.nlmsg_type = family;
		memcpy(req.data, &genl, sizeof(genl));
		ret = attr_put(&req, DEVLINK_ATTR_BUS_NAME, dev->devlink_bus,
			       strlen(dev->devlink_bus) + 1);
		if (!ret)
			ret = attr_put(&req, DEVLINK_ATTR_DEV_NAME,
				       dev->devlink_device,
				       strlen(dev->devlink_device) + 1);
		if (!ret)
			ret = attr_put(&req, DEVLINK_ATTR_PORT_INDEX,
				       &dev->port_index, sizeof(dev->port_index));
		if (ret)
			return ret;
		return nl_exchange(NETLINK_GENERIC, &req, receive_port, dev);
	}
	return 0;
}

int xdp_features_parse(const void *data, size_t len, __u64 *features)
{
	bool present = false;
	int ret;

	if (len < GENL_HDRLEN)
		return -EINVAL;
	ret = attr_number((const __u8 *)data + GENL_HDRLEN, len - GENL_HDRLEN,
			  NETDEV_A_DEV_XDP_FEATURES, features,
			  sizeof(*features), &present);
	return ret ? ret : present ? 0 : -EINVAL;
}

static int receive_features(const void *data, size_t len, void *ctx)
{
	return xdp_features_parse(data, len, ctx);
}

int xdp_device_features(__u32 ifindex, __u64 *features)
{
	struct nl_request req = {
		.hdr.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN),
		.hdr.nlmsg_flags = NLM_F_REQUEST,
	};
	struct genlmsghdr genl = {
		.cmd = NETDEV_CMD_DEV_GET,
		.version = NETDEV_FAMILY_VERSION,
	};
	__u16 family = 0;
	int ret;

	/* -ENOENT would read as a missing attach target and be skipped. */
	ret = genl_family(NETDEV_FAMILY_NAME, &family);
	if (ret == -ENOENT)
		return -EOPNOTSUPP;
	if (ret || !family)
		return ret ? ret : -EINVAL;
	req.hdr.nlmsg_type = family;
	memcpy(req.data, &genl, sizeof(genl));
	ret = attr_put(&req, NETDEV_A_DEV_IFINDEX, &ifindex, sizeof(ifindex));
	return ret ? ret : nl_exchange(NETLINK_GENERIC, &req, receive_features,
				       features);
}

bool xdp_multibuf_refused(__u64 features)
{
	return (features & NETDEV_XDP_ACT_BASIC) &&
	       !(features & NETDEV_XDP_ACT_RX_SG);
}

bool xdp_attach_unsupported(int err, __u64 features)
{
	return err == -EOPNOTSUPP && !(features & NETDEV_XDP_ACT_BASIC);
}

const char *xdp_attach_strerror(int err)
{
	if (err == XDP_ERR_NO_MULTIBUF)
		return "the device does not report multi-buffer XDP support";
	if (err == XDP_ERR_DRIVER_SETTINGS)
		return "the driver refuses XDP in its current settings";
	if (err == XDP_ERR_LINK_SCOPE)
		return "the link is not on the device and namespace it was made for";
	return strerror(-err);
}

const char *xdp_uncovered_reason(__u32 attached, int features_err,
				 __u64 features)
{
	if (attached)
		return "another XDP program attached";
	if (features_err)
		return "not attached";
	if (!(features & NETDEV_XDP_ACT_BASIC))
		return "no native XDP";
	if (xdp_multibuf_refused(features))
		return "no multi-buffer XDP";
	return "not attached";
}

static int device_compare(const void *a, const void *b)
{
	const struct xdp_device *left = a, *right = b;

	return (left->ifindex > right->ifindex) -
	       (left->ifindex < right->ifindex);
}

static int devices_read_once(struct device_list *list)
{
	struct nl_request req = {
		.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.hdr.nlmsg_type = RTM_GETLINK,
		.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
	};
	size_t i;
	int ret;

	ret = nl_exchange(NETLINK_ROUTE, &req, receive_device, list);
	if (ret)
		return ret;
	qsort(list->devices, list->count, sizeof(*list->devices),
	      device_compare);
	for (i = 0; i < list->count; i++) {
		struct xdp_device *dev = &list->devices[i];

		if (i && list->devices[i - 1].ifindex == dev->ifindex)
			return -EAGAIN;
		/*
		 * A rename or removal racing the dump says nothing about
		 * the other devices; without its facts this one can't be
		 * classified, so it sits out this discovery.
		 */
		ret = device_details(dev);
		if (ret == -EXDEV || ret == -ENODEV)
			dev->unresolved = true;
		else if (ret)
			return ret;
	}
	return 0;
}

int xdp_devices_read(struct xdp_device **out, size_t *count)
{
	struct device_list list = {};
	int ret = -EAGAIN;
	__u32 attempt;

	*out = NULL;
	*count = 0;
	for (attempt = 0; attempt < DEVICES_READ_ATTEMPTS && ret == -EAGAIN;
	     attempt++) {
		ret = devices_read_once(&list);
		if (ret) {
			xfree(list.devices,
			      size_mul(list.count, sizeof(*list.devices)));
			list = (struct device_list){};
		}
	}
	if (ret)
		return ret;
	*out = list.devices;
	*count = list.count;
	return 0;
}

/*
 * A driver refusal fails a restore as it fails a load: a setting that
 * survives a reboot must not take a device out of the upatch unreported.
 * Only an upatch restored before this one can hold the device then. The
 * kernel reports a vanished ifindex as EINVAL, so ask, and take only an
 * answer that the device is gone or changed: a lookup that itself fails
 * says nothing about the refusal.
 */
bool xdp_attach_skippable(int err, const struct xdp_device *dev,
			  bool restoring)
{
	if (err >= 0 || err == -EACCES || err == -EPERM ||
	    err == XDP_ERR_LINK_SCOPE)
		return false;
	if (err == XDP_ERR_OCCUPIED)
		return restoring;
	if (err == -EXDEV || err == -ENODEV)
		return true;
	err = xdp_device_verify(dev);
	return err == -EXDEV || err == -ENODEV;
}

int xdp_device_verify(const struct xdp_device *expected)
{
	struct nl_request req = {
		.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.hdr.nlmsg_type = RTM_GETLINK,
		.hdr.nlmsg_flags = NLM_F_REQUEST,
	};
	struct ifinfomsg info = { .ifi_index = (int)expected->ifindex };
	struct device_list list = {};
	struct xdp_device *dev;
	int ret;

	memcpy(req.data, &info, sizeof(info));
	ret = nl_exchange(NETLINK_ROUTE, &req, receive_device, &list);
	if (ret)
		goto out;
	if (list.count != 1) {
		ret = -EXDEV;
		goto out;
	}
	dev = list.devices;
	ret = device_details(dev);
	if (ret)
		goto out;
	if (dev->ifindex != expected->ifindex ||
	    dev->peer_ifindex != expected->peer_ifindex ||
	    dev->peer_other_netns != expected->peer_other_netns ||
	    strcmp(dev->kind, expected->kind) ||
	    xdp_device_class(dev) != xdp_device_class(expected))
		ret = -EXDEV;
out:
	xfree(list.devices, size_mul(list.count, sizeof(*list.devices)));
	return ret;
}
