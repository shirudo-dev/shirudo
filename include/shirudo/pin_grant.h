/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_PIN_GRANT_H
#define SHIRUDO_PIN_GRANT_H

/* The caller already checked runtime authority and the private superblock. */
enum pin_grant_action {
	PIN_GRANT_DENY,
	PIN_GRANT_ALLOW,
	PIN_GRANT_CONSUME,
};

static __always_inline enum pin_grant_action
pin_grant_delete(__u64 granted, __u64 target, __u64 parent, __u64 grandparent,
		 bool rmdir)
{
	if (!granted)
		return PIN_GRANT_DENY;
	if (rmdir && granted == target)
		return PIN_GRANT_CONSUME;
	if (granted == parent || granted == grandparent)
		return PIN_GRANT_ALLOW;
	return PIN_GRANT_DENY;
}

#endif /* SHIRUDO_PIN_GRANT_H */
