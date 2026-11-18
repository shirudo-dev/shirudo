/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What the builder checks of a jar before it signs it as a Java agent.
 */

#ifndef SHIRUDO_BUILD_JAR_H
#define SHIRUDO_BUILD_JAR_H

#include <stddef.h>

#include <shirudo/misc.h>

/*
 * Whether the jar's manifest names a Premain-Class, without which a JVM
 * given the jar as -javaagent does not start: 0 when it does, -ENOENT
 * for no manifest or no such attribute, -ENOTSUP for a zip64 archive or
 * a manifest neither stored nor deflated, -EFBIG for a manifest past
 * 1 MiB, -EINVAL for a file that is no zip archive or a damaged one.
 */
int jar_premain_class(const __u8 *jar, size_t len) __must_check;

#endif /* SHIRUDO_BUILD_JAR_H */
