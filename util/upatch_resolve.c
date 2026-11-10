// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The hook string and load time of a loaded upatch, from its pin.
 */

#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>
#include <shirudo/upatch.h>

#include "malloc.h"
#include "paths.h"
#include "hex.h"
#include "upatch_pins.h"
#include "upatch_resolve.h"
#include "timefmt.h"

#ifndef NFPROTO_IPV6
#define NFPROTO_IPV6			10
#endif
#ifndef NF_INET_PRE_ROUTING
#define NF_INET_PRE_ROUTING		0
#endif
#ifndef NF_IP6_PRI_RAW_BEFORE_DEFRAG
#define NF_IP6_PRI_RAW_BEFORE_DEFRAG	(-450)
#endif

int upatch_open_first_link(const char *name)
{
	char pin[PATH_MAX];
	int fd, first_errno;

	if (upatch_pin_path(pin, sizeof(pin), name, "link", NULL))
		return -ENAMETOOLONG;
	fd = bpf_obj_get(pin);
	if (fd >= 0)
		return fd;
	first_errno = errno;

	if (upatch_pin_path(pin, sizeof(pin), name, "link_0", NULL))
		return -ENAMETOOLONG;
	fd = bpf_obj_get(pin);
	if (fd >= 0)
		return fd;
	return errno == ENOENT ? -first_errno : -errno;
}

static const char *loc_prefix(__u32 prog_type, __u32 attach_type)
{
	if (prog_type == BPF_PROG_TYPE_LSM)
		return "lsm";
	if (prog_type == BPF_PROG_TYPE_NETFILTER)
		return "netfilter";
	if (prog_type == BPF_PROG_TYPE_TRACING) {
		switch (attach_type) {
		case BPF_TRACE_FENTRY:
			return "fentry";
		case BPF_TRACE_FEXIT:
			return "fexit";
		case BPF_MODIFY_RETURN:
			return "fmod_ret";
		case BPF_TRACE_RAW_TP:
			return "tp_btf";
		case BPF_TRACE_ITER:
			return "iter";
		default:
			return NULL;
		}
	}
	return NULL;
}

int upatch_first_prog_id(const char *name, __u32 *out)
{
	struct bpf_link_info linfo = {};
	struct bpf_prog_info info = {};
	__u32 len = sizeof(linfo);
	struct upatch_pins pins;
	char pin[PATH_MAX];
	int fd, ret;

	*out = 0;
	fd = upatch_open_first_link(name);
	if (fd >= 0) {
		ret = bpf_link_get_info_by_fd(fd, &linfo, &len);
		close(fd);
		if (ret)
			return ret;
		*out = linfo.prog_id;
		return linfo.prog_id ? 0 : -EINVAL;
	}
	if (fd != -ENOENT)
		return fd;
	ret = upatch_pins_read(name, &pins);
	if (ret)
		return ret;
	if (!pins.nr_xdp_progs)
		return -ENOENT;
	if (upatch_xdp_prog_pin(pin, sizeof(pin), name, pins.first_xdp_prog))
		return -ENAMETOOLONG;
	fd = bpf_obj_get(pin);
	if (fd < 0)
		return -errno;
	len = sizeof(info);
	ret = bpf_prog_get_info_by_fd(fd, &info, &len);
	close(fd);
	if (ret)
		return ret;
	*out = info.id;
	return info.id ? 0 : -EINVAL;
}

struct xdp_links {
	char	device[IF_NAMESIZE + 16];
	__u32	lowest;
	__u32	live;
};

struct link_info_walk {
	int	(*cb)(__u32 index, const char *pin,
		      const struct bpf_link_info *info, void *ctx);
	void	*ctx;
};

static int read_link_info(__u32 index, const char *pin, void *ctx)
{
	struct link_info_walk *w = ctx;
	struct bpf_link_info info = {};
	__u32 len = sizeof(info);
	int fd, ret;

	fd = bpf_obj_get(pin);
	if (fd < 0)
		return -errno;
	ret = bpf_link_get_info_by_fd(fd, &info, &len);
	close(fd);
	return ret ? ret : w->cb(index, pin, &info, w->ctx);
}

int upatch_each_link_info(const char *name,
			  int (*cb)(__u32 index, const char *pin,
				    const struct bpf_link_info *info, void *ctx),
			  void *ctx)
{
	struct link_info_walk w = { .cb = cb, .ctx = ctx };

	return upatch_each_link(name, read_link_info, &w);
}

static int note_xdp_link(__u32 index, const char *pin,
			 const struct bpf_link_info *info, void *ctx)
{
	struct xdp_links *l = ctx;
	char name[IF_NAMESIZE];

	/* The kernel clears the ifindex when the device goes away. */
	if (info->type != BPF_LINK_TYPE_XDP || !info->xdp.ifindex)
		return 0;
	if (!l->live || index < l->lowest) {
		l->lowest = index;
		if (if_indextoname(info->xdp.ifindex, name)) {
			if (strscpy(l->device, name, sizeof(l->device)) < 0)
				return -E2BIG;
		} else if (strsprintf(l->device, sizeof(l->device), "ifindex:%u",
				      info->xdp.ifindex) < 0) {
			return -E2BIG;
		}
	}
	l->live++;
	return 0;
}

static int xdp_location(const char *name, char *out, size_t cap)
{
	struct xdp_links links = {};
	int ret, n;

	ret = upatch_each_link_info(name, note_xdp_link, &links);
	if (ret)
		return ret;
	if (!links.live)
		n = strsprintf(out, cap, "xdp (waiting for a device)");
	else if (links.live == 1)
		n = strsprintf(out, cap, "xdp/%s", links.device);
	else
		n = strsprintf(out, cap, "xdp/%s (+%u)", links.device,
			       links.live - 1);
	return n < 0 ? -E2BIG : 0;
}

int upatch_resolve_location(struct btf *vbtf, const char *name,
			    char *out, size_t cap)
{
	struct bpf_link_info linfo = {};
	struct bpf_prog_info info = {};
	const char *attach_name = NULL;
	int link_fd, prog_fd, ret;
	__u32 attach_type = 0;
	struct upatch_pins pins;
	const char *prefix;
	__u32 len;

	out[0] = '\0';
	if (!upatch_pins_read(name, &pins) && pins.nr_xdp_progs)
		return xdp_location(name, out, cap);
	link_fd = upatch_open_first_link(name);
	if (link_fd < 0)
		return link_fd;
	len = sizeof(linfo);
	ret = bpf_link_get_info_by_fd(link_fd, &linfo, &len);
	if (ret != 0 || linfo.prog_id == 0) {
		close(link_fd);
		return ret ? ret : -EINVAL;
	}
	if (linfo.type == BPF_LINK_TYPE_UPROBE_MULTI) {
		struct bpf_link_info detail = {};
		__u32 count = linfo.uprobe_multi.count;
		__u32 path_size = linfo.uprobe_multi.path_size;
		char *path;

		if (!path_size || path_size > PATH_MAX) {
			close(link_fd);
			return -EINVAL;
		}
		path = xmalloc(path_size);
		if (!path) {
			close(link_fd);
			return -ENOMEM;
		}
		detail.uprobe_multi.path = ptr_to_u64(path);
		detail.uprobe_multi.path_size = path_size;
		len = sizeof(detail);
		ret = bpf_link_get_info_by_fd(link_fd, &detail, &len);
		close(link_fd);
		if (ret != 0) {
			xfree(path, path_size);
			return ret;
		}
		if (!memchr(path, '\0', path_size)) {
			xfree(path, path_size);
			return -EINVAL;
		}
		ret = strsprintf(out, cap, "uprobe.multi/%s (%u funcs)", path,
				 count) < 0 ? -E2BIG : 0;
		xfree(path, path_size);
		return ret;
	}
	close(link_fd);
	if (linfo.type == BPF_LINK_TYPE_TRACING)
		attach_type = linfo.tracing.attach_type;
	if (linfo.type == BPF_LINK_TYPE_NETFILTER &&
	    linfo.netfilter.pf == NFPROTO_IPV6 &&
	    linfo.netfilter.hooknum == NF_INET_PRE_ROUTING &&
	    linfo.netfilter.priority == NF_IP6_PRI_RAW_BEFORE_DEFRAG) {
		strscpy(out, "netfilter/ipv6-pre-routing", cap);
		return 0;
	}

	prog_fd = bpf_prog_get_fd_by_id(linfo.prog_id);
	if (prog_fd < 0)
		return -errno;
	len = sizeof(info);
	ret = bpf_prog_get_info_by_fd(prog_fd, &info, &len);
	close(prog_fd);
	if (ret != 0)
		return ret;

	if (vbtf && info.attach_btf_id &&
	    info.attach_btf_id < btf__type_cnt(vbtf)) {
		const struct btf_type *t = btf__type_by_id(vbtf,
							   info.attach_btf_id);

		if (t)
			attach_name = btf__name_by_offset(vbtf, t->name_off);
	}

	prefix = loc_prefix(info.type, attach_type);
	if (!prefix)
		prefix = libbpf_bpf_prog_type_str(info.type);
	if (!prefix)
		prefix = "?";

	/* Strip the bpf_lsm_ prefix the kernel mangles LSM hooks with. */
	if (info.type == BPF_PROG_TYPE_LSM && attach_name &&
	    strncmp(attach_name, "bpf_lsm_", 8) == 0)
		attach_name += 8;

	if (attach_name && *attach_name)
		return strsprintf(out, cap, "%s/%s", prefix, attach_name) < 0 ?
		       -E2BIG : 0;
	strscpy(out, prefix, cap);
	return 0;
}

void upatch_loaded_at(const char *name, char *out, size_t cap)
{
	struct upatch_pins pins;
	char dir[PATH_MAX];
	struct stat st;

	out[0] = '\0';
	if (upatch_pin_path(dir, sizeof(dir), name, NULL))
		return;
	/* Later XDP links change the directory's ctime; a program pin stays. */
	if (!upatch_pins_read(name, &pins) && pins.nr_xdp_progs &&
	    upatch_xdp_prog_pin(dir, sizeof(dir), name, pins.first_xdp_prog))
		return;
	if (stat(dir, &st) != 0)
		return;
	iso8601(st.st_ctim.tv_sec, out, cap);
}

void upatch_payload_sha256(const char *name, char *out, size_t cap)
{
	char dir[PATH_MAX];
	__u8 raw[32];
	ssize_t n;

	out[0] = '\0';
	if (cap < 65)
		return;
	if (upatch_pin_path(dir, sizeof(dir), name, NULL))
		return;
	n = getxattr(dir, XATTR_PAYLOAD, raw, sizeof(raw));
	if (n != (ssize_t)sizeof(raw))
		return;
	hex_encode(raw, sizeof(raw), out);
}
