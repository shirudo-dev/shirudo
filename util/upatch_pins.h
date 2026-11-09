/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What the pin directory of a loaded upatch holds.
 */

#ifndef SHIRUDO_UTIL_UPATCH_PINS_H
#define SHIRUDO_UTIL_UPATCH_PINS_H

#include <stdbool.h>

#include <shirudo/types.h>

struct upatch_pins {
	bool	has_link;
	__u32	nr_links;
	__u32	first_link;
	__u32	nr_xdp_progs;
	__u32	first_xdp_prog;
};

void upatch_pins_note(struct upatch_pins *pins, const char *entry);
bool upatch_pins_loaded(const struct upatch_pins *pins);

/* 0, or a negative errno; -ENOENT when the upatch has no pin directory. */
int upatch_pins_read(const char *name, struct upatch_pins *out);

/*
 * By name alone, so a caller without the task mark adds no denied
 * BPF_OBJ_GET to the tamper counters.
 */
bool upatch_loaded_pins(const char *name);

/*
 * Calls cb for each link_<n> pin, in directory order, and stops at the
 * first nonzero return, which it returns.
 */
int upatch_each_link(const char *name,
		     int (*cb)(__u32 index, const char *pin, void *ctx),
		     void *ctx);

#endif /* SHIRUDO_UTIL_UPATCH_PINS_H */
