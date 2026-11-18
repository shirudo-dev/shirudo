/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The hook string and load time of a loaded upatch, from its pin.
 */

#ifndef SHIRUDO_UTIL_UPATCH_RESOLVE_H
#define SHIRUDO_UTIL_UPATCH_RESOLVE_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/types.h>

struct bpf_link_info;
struct btf;

#define UPATCH_LOCATION_MAX	160

/*
 * Open the first pinned link for an upatch. Single-program upatches use
 * "link"; multi-program upatches use "link_0", "link_1", ...
 * Returns a link fd on success, negative errno on failure.
 */
int upatch_open_first_link(const char *name);

/*
 * As upatch_each_link(), with what the kernel says of each link; a link
 * whose pin cannot be opened or read ends the walk with its -errno.
 */
int upatch_each_link_info(const char *name,
			  int (*cb)(__u32 index, const char *pin,
				    const struct bpf_link_info *info, void *ctx),
			  void *ctx);

/* From the first link, or from an XDP program pin when it has none. */
int upatch_first_prog_id(const char *name, __u32 *out);

/* vbtf may be NULL; the location then degrades to the bare prefix. */
int upatch_resolve_location(struct btf *vbtf, const char *name,
			    char *out, size_t cap);

/*
 * The runs the kernel skipped of one program of an upatch: the program's
 * recursion_misses and what its kprobe or kprobe multi link counts itself.
 */
struct upatch_link_misses {
	char	location[UPATCH_LOCATION_MAX];	/* "" when it cannot be named */
	__u64	missed;
};

/*
 * Whether the runs the kernel skips of the program behind this link are
 * reported: kprobe, kretprobe and their multi forms. The kernel skips no
 * lsm, xdp, cgroup_skb or netfilter run, and counts none it skips of the
 * uprobe kinds.
 */
bool upatch_link_counts_misses(const struct bpf_link_info *info);

/* What the link counts itself, beside its program's recursion_misses. */
__u64 upatch_link_missed(const struct bpf_link_info *info);

/*
 * Calls cb for each link of name that upatch_link_counts_misses(), and
 * skips the others; a link or program that cannot be read ends the walk
 * with its -errno, as does a non-zero return of cb. vbtf names the
 * location as for upatch_resolve_location().
 */
int upatch_each_link_misses(struct btf *vbtf, const char *name,
			    int (*cb)(const struct upatch_link_misses *m, void *ctx),
			    void *ctx);

/*
 * The sum over upatch_each_link_misses(), with the number of links it
 * counted: 0 for an upatch of no kind the kernel counts, whose missed is
 * then 0 without meaning that nothing was skipped.
 */
int upatch_missed_runs(const char *name, __u32 *nr_counted, __u64 *missed);

void upatch_loaded_at(const char *name, char *out, size_t cap);

/* Empty on any failure. */
void upatch_payload_sha256(const char *name, char *out, size_t cap);

#endif /* SHIRUDO_UTIL_UPATCH_RESOLVE_H */
