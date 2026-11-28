// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <string.h>

#include <linux/btf.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>

#include "kernel_prereq.h"
#include "unit.h"

/* A BTF with a function of each name and nothing else of note. */
static struct btf *btf_with(const char *const *names, size_t n)
{
	int ret_type, proto;
	struct btf *btf;
	size_t i;

	btf = btf__new_empty();
	if (libbpf_get_error(btf))
		return NULL;
	ret_type = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	proto = btf__add_func_proto(btf, ret_type);
	if (ret_type < 0 || proto < 0)
		goto err;
	for (i = 0; i < n; i++)
		if (btf__add_func(btf, names[i], BTF_FUNC_GLOBAL, proto) < 0)
			goto err;
	return btf;
err:
	btf__free(btf);
	return NULL;
}

static void options_of(const char *const *names, size_t n,
		       struct kernel_options *opts)
{
	struct btf *btf = btf_with(names, n);

	ASSERT_TRUE(btf);
	memset(opts, 0xff, sizeof(*opts));
	kernel_prereq_options(btf, opts);
	btf__free(btf);
}

static void options_of_a_kernel_with_all(void)
{
	static const char *const names[] = {
		"__module_address", "mod_verify_sig", "compat_ptr_ioctl",
	};
	struct kernel_options opts;

	options_of(names, ARRAY_SIZE(names), &opts);
	EXPECT_TRUE(opts.modules);
	EXPECT_TRUE(opts.module_sig);
	EXPECT_TRUE(opts.compat);
}

static void options_of_a_kernel_with_none(void)
{
	static const char *const names[] = { "vfs_read", "module" };
	struct kernel_options opts;

	options_of(names, ARRAY_SIZE(names), &opts);
	EXPECT_FALSE(opts.modules);
	EXPECT_FALSE(opts.module_sig);
	EXPECT_FALSE(opts.compat);
}

static void modules_without_signatures(void)
{
	static const char *const names[] = { "__module_address" };
	struct kernel_options opts;

	options_of(names, ARRAY_SIZE(names), &opts);
	EXPECT_TRUE(opts.modules);
	EXPECT_FALSE(opts.module_sig);
}

static void hibernation_without_a_resume_device(void)
{
	EXPECT_FALSE(kernel_hibernation_resumes("[platform] shutdown reboot "
						"suspend disk", "0:0"));
	EXPECT_FALSE(kernel_hibernation_resumes("[platform] shutdown reboot "
						"suspend disk", NULL));
}

static void hibernation_with_a_resume_device(void)
{
	EXPECT_TRUE(kernel_hibernation_resumes("[platform] shutdown reboot "
					       "suspend disk", "259:2"));
}

static void no_hibernation(void)
{
	EXPECT_FALSE(kernel_hibernation_resumes(NULL, "259:2"));
	EXPECT_FALSE(kernel_hibernation_resumes("[disabled]", "259:2"));
}

static void the_root_mount_holds_the_state_tree(void)
{
	char source[64];
	size_t depth;

	EXPECT_TRUE(kernel_prereq_mount_source("/dev/sda2 / ext4 rw 0 0",
					       "/var/lib/shirudo", &depth,
					       source, sizeof(source)));
	EXPECT_UEQ(depth, 1);
	EXPECT_STREQ(source, "/dev/sda2");
}

static void a_mount_above_the_path_holds_it(void)
{
	char source[64];
	size_t depth;

	EXPECT_TRUE(kernel_prereq_mount_source("/dev/sdb1 /var ext4 rw 0 0",
					       "/var/lib/shirudo", &depth,
					       source, sizeof(source)));
	EXPECT_UEQ(depth, 4);
	EXPECT_STREQ(source, "/dev/sdb1");
}

static void a_mount_elsewhere_holds_nothing(void)
{
	char source[64];
	size_t depth;

	EXPECT_FALSE(kernel_prereq_mount_source("tmpfs /run tmpfs rw 0 0",
						"/var/lib/shirudo", &depth,
						source, sizeof(source)));
	EXPECT_FALSE(kernel_prereq_mount_source("/dev/sda2 /va ext4 rw 0 0",
						"/var/lib/shirudo", &depth,
						source, sizeof(source)));
}

static const struct unit_case cases[] = {
	UNIT_CASE(options_of_a_kernel_with_all),
	UNIT_CASE(options_of_a_kernel_with_none),
	UNIT_CASE(modules_without_signatures),
	UNIT_CASE(hibernation_without_a_resume_device),
	UNIT_CASE(hibernation_with_a_resume_device),
	UNIT_CASE(no_hibernation),
	UNIT_CASE(the_root_mount_holds_the_state_tree),
	UNIT_CASE(a_mount_above_the_path_holds_it),
	UNIT_CASE(a_mount_elsewhere_holds_nothing),
	{}
};

UNIT_SUITE(kernel_prereq, cases);
