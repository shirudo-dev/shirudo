/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What the pin directory of a loaded upatch holds.
 */

#ifndef SHIRUDO_UTIL_UPATCH_PINS_H
#define SHIRUDO_UTIL_UPATCH_PINS_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/types.h>
#include <shirudo/upatch.h>

struct upatch_pins {
	bool	has_link;
	__u32	nr_links;
	__u32	first_link;
	__u32	last_link;
	__u32	nr_xdp_progs;
	__u32	first_xdp_prog;
};

void upatch_pins_note(struct upatch_pins *pins, const char *entry);
bool upatch_pins_loaded(const struct upatch_pins *pins);

/* Whether the pins are the links of an upatch of nr_attach non-XDP programs. */
bool upatch_pins_complete(const struct upatch_pins *pins, __u32 nr_attach);

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

/* Numbered link index in the pin directory dir: 0 or -ENAMETOOLONG. */
int upatch_link_pin(char *out, size_t cap, const char *dir, __u32 index);

/* The pin that keeps XDP program index of name loaded: 0 or -ENAMETOOLONG. */
int upatch_xdp_prog_pin(char *out, size_t cap, const char *name, __u32 index);

/*
 * The fd of XDP program index pinned for name, its id in *id, or -errno;
 * -ESTALE when the pin holds a program that is not XDP.
 */
int upatch_xdp_prog_open(const char *name, __u32 index, __u32 *id);

/*
 * The payload hash a load set on the pin directory of name: 0,
 * -ENAMETOOLONG, -EINVAL when it is not a hash, or the -errno of the read.
 */
int upatch_pin_payload(const char *name, __u8 out[UPATCH_PAYLOAD_HASH_LEN]);

/*
 * Calls cb with the name of each upatch that has a pin directory and stops
 * at the first nonzero return, which it returns. No directory at all is 0,
 * any other failure to read it -errno.
 */
int upatch_each_pinned(int (*cb)(const char *name, void *ctx), void *ctx);

#endif /* SHIRUDO_UTIL_UPATCH_PINS_H */
