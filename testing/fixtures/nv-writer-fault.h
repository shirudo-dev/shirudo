/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */
#ifndef SHIRUDO_TEST_NV_WRITER_FAULT_H
#define SHIRUDO_TEST_NV_WRITER_FAULT_H

struct nv_writer_fault {
	__u32 pid;
	__u32 command;
	__u32 fail_import;
	__u32 imports;
	__u32 failures;
};

#endif /* SHIRUDO_TEST_NV_WRITER_FAULT_H */
