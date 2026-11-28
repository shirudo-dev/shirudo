/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_ENFORCEMENT_H
#define SHIRUDO_ENFORCEMENT_H

#ifndef __bpf__
#include <shirudo/types.h>
#endif

#define PR_GET_ENFORCEMENT 0x53520001
#define PR_ENFORCING_ERR 1002

/* Private bpffs directory requests acknowledged by the file_ioctl LSM. */
#define SHIRUDO_PIN_GRANT_BEGIN	0x53520002u
#define SHIRUDO_PIN_GRANT_END	0x53520003u
#define SHIRUDO_PIN_GRANT_ACK	1003

/*
 * The enforcement mode init freezes into the identity record. Strict is
 * zero, so that a record without a mode enforces in full.
 */
#define ENFORCEMENT_STRICT	0u
#define ENFORCEMENT_SHARED	1u

/*
 * A map or program bpf2 or seal created, which init records by id in
 * shirudo_boot_objects before the bpf() gates attach.
 */
#define BOOT_OBJECT_MAP		1u
#define BOOT_OBJECT_PROG	2u

struct boot_object {
	__u32	kind;	/* BOOT_OBJECT_MAP or _PROG */
	__u32	id;
};

/*
 * vmlinux.h carries no UAPI macros, so BPF code takes the ioctl number
 * from here: _IOW('$', 8, __u32) on every supported architecture.
 * Userspace includes the UAPI header first, which defines it as is.
 */
#ifdef __bpf__
#ifndef PERF_EVENT_IOC_SET_BPF
#define PERF_EVENT_IOC_SET_BPF 0x40042408u
#endif
#else
#include <linux/perf_event.h>
#endif

#endif /* SHIRUDO_ENFORCEMENT_H */
