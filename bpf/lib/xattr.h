/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_BPF_XATTR_H
#define SHIRUDO_BPF_XATTR_H

#define XATTR		"security.bpf.shirudo"
#define SHIRUDO_POLICY_XATTR "security.bpf.shirudo.policy"
/* The label is a SHA-256 hex string (util/seal.h) -- always 64 bytes. */
#define LABEL_LEN	64

#endif /* SHIRUDO_BPF_XATTR_H */
