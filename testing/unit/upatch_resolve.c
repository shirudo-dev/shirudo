// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <linux/bpf.h>

#include <shirudo/misc.h>

#include "unit.h"
#include "upatch_resolve.h"

static int never_called(__u32 index, const char *pin,
			const struct bpf_link_info *info, void *ctx)
{
	(*(int *)ctx)++;
	return 0;
}

static void links_of_an_absent_upatch_are_not_read(void)
{
	int calls = 0;

	EXPECT_EQ(upatch_each_link_info("shirudo-unit-no-such-upatch",
					never_called, &calls), -ENOENT);
	EXPECT_EQ(calls, 0);
}

static struct bpf_link_info tracing_link(__u32 attach_type)
{
	struct bpf_link_info info = {
		.type = BPF_LINK_TYPE_TRACING,
		.tracing.attach_type = attach_type,
	};

	return info;
}

static struct bpf_link_info perf_link(__u32 perf_type)
{
	struct bpf_link_info info = {
		.type = BPF_LINK_TYPE_PERF_EVENT,
		.perf_event.type = perf_type,
	};

	return info;
}

static void the_kinds_the_kernel_counts_skipped_runs_of_count(void)
{
	struct bpf_link_info info = { .type = BPF_LINK_TYPE_KPROBE_MULTI };

	EXPECT_TRUE(upatch_link_counts_misses(&info));
	info = perf_link(BPF_PERF_EVENT_KPROBE);
	EXPECT_TRUE(upatch_link_counts_misses(&info));
	info = perf_link(BPF_PERF_EVENT_KRETPROBE);
	EXPECT_TRUE(upatch_link_counts_misses(&info));
	info = tracing_link(BPF_TRACE_FENTRY);
	EXPECT_TRUE(upatch_link_counts_misses(&info));
	info = tracing_link(BPF_TRACE_FEXIT);
	EXPECT_TRUE(upatch_link_counts_misses(&info));
	info = tracing_link(BPF_MODIFY_RETURN);
	EXPECT_TRUE(upatch_link_counts_misses(&info));
	info = (struct bpf_link_info){ .type = BPF_LINK_TYPE_RAW_TRACEPOINT };
	EXPECT_TRUE(upatch_link_counts_misses(&info));
}

static void the_kinds_it_never_skips_or_never_counts_do_not(void)
{
	static const __u32 types[] = {
		BPF_LINK_TYPE_UPROBE_MULTI, BPF_LINK_TYPE_XDP,
		BPF_LINK_TYPE_CGROUP, BPF_LINK_TYPE_NETFILTER,
	};
	struct bpf_link_info info = tracing_link(BPF_LSM_MAC);
	size_t i;

	EXPECT_FALSE(upatch_link_counts_misses(&info));
	info = perf_link(BPF_PERF_EVENT_UPROBE);
	EXPECT_FALSE(upatch_link_counts_misses(&info));
	info = perf_link(BPF_PERF_EVENT_URETPROBE);
	EXPECT_FALSE(upatch_link_counts_misses(&info));
	for (i = 0; i < ARRAY_SIZE(types); i++) {
		info = (struct bpf_link_info){ .type = types[i] };
		EXPECT_FALSE(upatch_link_counts_misses(&info));
	}
}

static void a_kprobe_link_adds_what_it_counts_itself(void)
{
	struct bpf_link_info info = {
		.type = BPF_LINK_TYPE_KPROBE_MULTI,
		.kprobe_multi.missed = 7,
	};

	EXPECT_UEQ(upatch_link_missed(&info), 7);
	info = perf_link(BPF_PERF_EVENT_KRETPROBE);
	info.perf_event.kprobe.missed = 3;
	EXPECT_UEQ(upatch_link_missed(&info), 3);
	info = tracing_link(BPF_TRACE_FENTRY);
	EXPECT_UEQ(upatch_link_missed(&info), 0);
	/* The union's kprobe member is not a uprobe's count. */
	info = perf_link(BPF_PERF_EVENT_UPROBE);
	info.perf_event.kprobe.missed = 5;
	EXPECT_UEQ(upatch_link_missed(&info), 0);
}

static const struct unit_case cases[] = {
	UNIT_CASE(links_of_an_absent_upatch_are_not_read),
	UNIT_CASE(the_kinds_the_kernel_counts_skipped_runs_of_count),
	UNIT_CASE(the_kinds_it_never_skips_or_never_counts_do_not),
	UNIT_CASE(a_kprobe_link_adds_what_it_counts_itself),
	{}
};

UNIT_SUITE(upatch_resolve, cases);
