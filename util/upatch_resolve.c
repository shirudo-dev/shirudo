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
	__u32 len = sizeof(linfo);
	struct upatch_pins pins;
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
	fd = upatch_xdp_prog_open(name, pins.first_xdp_prog, out);
	if (fd < 0)
		return fd;
	close(fd);
	return *out ? 0 : -EINVAL;
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

static bool link_is_uprobe(const struct bpf_link_info *linfo)
{
	return linfo->type == BPF_LINK_TYPE_PERF_EVENT &&
	       (linfo->perf_event.type == BPF_PERF_EVENT_UPROBE ||
		linfo->perf_event.type == BPF_PERF_EVENT_URETPROBE);
}

static int uprobe_location(int link_fd, char *out, size_t cap)
{
	struct bpf_link_info linfo = {};
	char path[PATH_MAX] = {};
	__u32 len = sizeof(linfo);

	linfo.perf_event.uprobe.file_name = ptr_to_u64(path);
	linfo.perf_event.uprobe.name_len = sizeof(path);
	if (bpf_link_get_info_by_fd(link_fd, &linfo, &len))
		return -errno;
	if (!link_is_uprobe(&linfo) || !memchr(path, '\0', sizeof(path)))
		return -EINVAL;
	return strsprintf(out, cap, "%s/%s+0x%x",
			  linfo.perf_event.type == BPF_PERF_EVENT_URETPROBE ? "uretprobe" : "uprobe",
			  path, linfo.perf_event.uprobe.offset) < 0 ? -E2BIG : 0;
}

static int uprobe_multi_location(int link_fd, const struct bpf_link_info *linfo,
				 char *out, size_t cap)
{
	__u32 path_size = linfo->uprobe_multi.path_size;
	struct bpf_link_info info = {};
	__u32 len = sizeof(info);
	char *path;
	int ret;

	if (!path_size || path_size > PATH_MAX)
		return -EINVAL;
	path = xmalloc(path_size);
	if (!path)
		return -ENOMEM;
	info.uprobe_multi.path = ptr_to_u64(path);
	info.uprobe_multi.path_size = path_size;
	ret = bpf_link_get_info_by_fd(link_fd, &info, &len);
	if (!ret && !memchr(path, '\0', path_size))
		ret = -EINVAL;
	if (!ret && strsprintf(out, cap, "%s/%s (%u funcs)",
			       linfo->uprobe_multi.flags & BPF_F_UPROBE_MULTI_RETURN ?
			       "uretprobe.multi" : "uprobe.multi", path,
			       linfo->uprobe_multi.count) < 0)
		ret = -E2BIG;
	xfree(path, path_size);
	return ret;
}

static int prog_info_by_id(__u32 prog_id, struct bpf_prog_info *info)
{
	__u32 len = sizeof(*info);
	int fd, ret;

	fd = bpf_prog_get_fd_by_id(prog_id);
	if (fd < 0)
		return -errno;
	ret = bpf_prog_get_info_by_fd(fd, info, &len);
	close(fd);
	return ret;
}

/* pinfo is the program's info when the caller has read it already. */
static int link_location(struct btf *vbtf, int link_fd,
			 const struct bpf_link_info *linfo,
			 const struct bpf_prog_info *pinfo, char *out, size_t cap)
{
	struct bpf_prog_info info = {};
	const char *attach_name = NULL;
	__u32 attach_type = 0;
	const char *prefix;
	int ret;

	if (linfo->type == BPF_LINK_TYPE_KPROBE_MULTI)
		return strsprintf(out, cap, "%s (%u funcs)",
				  linfo->kprobe_multi.flags & BPF_F_KPROBE_MULTI_RETURN ?
				  "kretprobe.multi" : "kprobe.multi",
				  linfo->kprobe_multi.count) < 0 ? -E2BIG : 0;
	if (linfo->type == BPF_LINK_TYPE_UPROBE_MULTI)
		return uprobe_multi_location(link_fd, linfo, out, cap);
	if (link_is_uprobe(linfo))
		return uprobe_location(link_fd, out, cap);
	if (linfo->type == BPF_LINK_TYPE_TRACING)
		attach_type = linfo->tracing.attach_type;
	if (linfo->type == BPF_LINK_TYPE_NETFILTER &&
	    linfo->netfilter.pf == NFPROTO_IPV6 &&
	    linfo->netfilter.hooknum == NF_INET_PRE_ROUTING &&
	    linfo->netfilter.priority == NF_IP6_PRI_RAW_BEFORE_DEFRAG) {
		strscpy(out, "netfilter/ipv6-pre-routing", cap);
		return 0;
	}

	if (!pinfo) {
		ret = prog_info_by_id(linfo->prog_id, &info);
		if (ret)
			return ret;
		pinfo = &info;
	}

	if (vbtf && pinfo->attach_btf_id &&
	    pinfo->attach_btf_id < btf__type_cnt(vbtf)) {
		const struct btf_type *t = btf__type_by_id(vbtf,
							   pinfo->attach_btf_id);

		if (t)
			attach_name = btf__name_by_offset(vbtf, t->name_off);
	}

	prefix = loc_prefix(pinfo->type, attach_type);
	if (!prefix)
		prefix = libbpf_bpf_prog_type_str(pinfo->type);
	if (!prefix)
		prefix = "?";

	/* Strip the bpf_lsm_ prefix the kernel mangles LSM hooks with. */
	if (pinfo->type == BPF_PROG_TYPE_LSM && attach_name)
		attach_name += str_has_prefix(attach_name, "bpf_lsm_");

	if (attach_name && *attach_name)
		return strsprintf(out, cap, "%s/%s", prefix, attach_name) < 0 ?
		       -E2BIG : 0;
	strscpy(out, prefix, cap);
	return 0;
}

int upatch_resolve_location(struct btf *vbtf, const char *name,
			    char *out, size_t cap)
{
	struct bpf_link_info linfo = {};
	__u32 len = sizeof(linfo);
	struct upatch_pins pins;
	int link_fd, ret;

	out[0] = '\0';
	if (!upatch_pins_read(name, &pins) && pins.nr_xdp_progs)
		return xdp_location(name, out, cap);
	link_fd = upatch_open_first_link(name);
	if (link_fd < 0)
		return link_fd;
	ret = bpf_link_get_info_by_fd(link_fd, &linfo, &len);
	if (!ret && !linfo.prog_id)
		ret = -EINVAL;
	if (!ret)
		ret = link_location(vbtf, link_fd, &linfo, NULL, out, cap);
	close(link_fd);
	return ret;
}

static bool link_is_kprobe(const struct bpf_link_info *info)
{
	return info->type == BPF_LINK_TYPE_PERF_EVENT &&
	       (info->perf_event.type == BPF_PERF_EVENT_KPROBE ||
		info->perf_event.type == BPF_PERF_EVENT_KRETPROBE);
}

bool upatch_link_counts_misses(const struct bpf_link_info *info)
{
	switch (info->type) {
	case BPF_LINK_TYPE_KPROBE_MULTI:
		return true;
	case BPF_LINK_TYPE_PERF_EVENT:
		return link_is_kprobe(info);
	case BPF_LINK_TYPE_TRACING:
		/* The kernel runs an lsm program without its recursion check. */
		return info->tracing.attach_type == BPF_TRACE_FENTRY ||
		       info->tracing.attach_type == BPF_TRACE_FEXIT ||
		       info->tracing.attach_type == BPF_MODIFY_RETURN;
	default:
		return false;
	}
}

__u64 upatch_link_missed(const struct bpf_link_info *info)
{
	if (info->type == BPF_LINK_TYPE_KPROBE_MULTI)
		return info->kprobe_multi.missed;
	if (link_is_kprobe(info))
		return info->perf_event.kprobe.missed;
	return 0;
}

/* 1 for a link of a kind whose skipped runs the kernel does not count. */
static int link_misses(struct btf *vbtf, int fd, bool with_location,
		       struct upatch_link_misses *m)
{
	struct bpf_link_info info = {};
	struct bpf_prog_info prog = {};
	__u32 len = sizeof(info);
	int ret;

	ret = bpf_link_get_info_by_fd(fd, &info, &len);
	if (ret)
		return ret;
	if (!upatch_link_counts_misses(&info))
		return 1;
	ret = prog_info_by_id(info.prog_id, &prog);
	if (ret)
		return ret;
	m->missed = prog.recursion_misses + upatch_link_missed(&info);
	if (with_location &&
	    link_location(vbtf, fd, &info, &prog, m->location, sizeof(m->location)))
		m->location[0] = '\0';
	return 0;
}

struct misses_walk {
	struct btf	*vbtf;
	bool		with_location;
	int		(*cb)(const struct upatch_link_misses *m, void *ctx);
	void		*ctx;
};

static int read_link_misses(__u32 index, const char *pin, void *ctx)
{
	struct upatch_link_misses m = {};
	struct misses_walk *w = ctx;
	int fd, ret;

	fd = bpf_obj_get(pin);
	if (fd < 0)
		return -errno;
	ret = link_misses(w->vbtf, fd, w->with_location, &m);
	close(fd);
	if (ret)
		return min(ret, 0);
	return w->cb(&m, w->ctx);
}

/* One link is pinned as "link", several as "link_<n>". */
static int walk_link_misses(const char *name, struct misses_walk *w)
{
	struct upatch_pins pins;
	char pin[PATH_MAX];
	int ret;

	ret = upatch_pins_read(name, &pins);
	if (ret)
		return ret;
	if (pins.has_link) {
		if (upatch_pin_path(pin, sizeof(pin), name, "link", NULL))
			return -ENAMETOOLONG;
		ret = read_link_misses(0, pin, w);
		if (ret)
			return ret;
	}
	return upatch_each_link(name, read_link_misses, w);
}

int upatch_each_link_misses(struct btf *vbtf, const char *name,
			    int (*cb)(const struct upatch_link_misses *m, void *ctx),
			    void *ctx)
{
	struct misses_walk w = {
		.vbtf = vbtf, .with_location = true, .cb = cb, .ctx = ctx,
	};

	return walk_link_misses(name, &w);
}

struct misses_sum {
	__u32	nr_counted;
	__u64	missed;
};

static int add_link_misses(const struct upatch_link_misses *m, void *ctx)
{
	struct misses_sum *sum = ctx;

	sum->nr_counted++;
	sum->missed += m->missed;
	return 0;
}

int upatch_missed_runs(const char *name, __u32 *nr_counted, __u64 *missed)
{
	struct misses_sum sum = {};
	struct misses_walk w = { .cb = add_link_misses, .ctx = &sum };
	int ret;

	*nr_counted = 0;
	*missed = 0;
	ret = walk_link_misses(name, &w);
	if (ret)
		return ret;
	*nr_counted = sum.nr_counted;
	*missed = sum.missed;
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
	__u8 raw[UPATCH_PAYLOAD_HASH_LEN];

	out[0] = '\0';
	if (cap < 2 * sizeof(raw) + 1 || upatch_pin_payload(name, raw))
		return;
	hex_encode(raw, sizeof(raw), out);
}
