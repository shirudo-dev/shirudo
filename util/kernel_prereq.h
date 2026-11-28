/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What the running kernel shows of the options the threat model assumes:
 * its BTF and /sys/power, not /proc/config.gz, which a target need not
 * have.
 */

#ifndef SHIRUDO_KERNEL_PREREQ_H
#define SHIRUDO_KERNEL_PREREQ_H

#include <stdbool.h>

struct btf;

struct kernel_options {
	bool	modules;	/* CONFIG_MODULES */
	bool	module_sig;	/* CONFIG_MODULE_SIG */
	bool	compat;		/* CONFIG_COMPAT */
};

/* The options btf shows, the BTF of vmlinux. */
void kernel_prereq_options(const struct btf *btf, struct kernel_options *out);

/*
 * Whether the boot may resume from a hibernation image: /sys/power/disk
 * says hibernation is available, and /sys/power/resume names a device.
 * Each is the file's first line, NULL when it is absent.
 */
bool kernel_hibernation_resumes(const char *disk, const char *resume);

/*
 * Whether the /proc/mounts line mounts a directory that holds path, and
 * the device the line names in source. *depth is the mount point's
 * length, which a caller comparing lines keeps the longest of. The
 * source is the mount's own string, "overlay" or "tmpfs" where the file
 * system is not one block device.
 */
bool kernel_prereq_mount_source(const char *line, const char *path,
				size_t *depth, char *source, size_t cap);

#endif /* SHIRUDO_KERNEL_PREREQ_H */
