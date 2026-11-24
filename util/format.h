/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Human-readable formatters shared across status and keys renderers.
 */

#ifndef SHIRUDO_UTIL_FORMAT_H
#define SHIRUDO_UTIL_FORMAT_H

#include <stddef.h>
#include <stdio.h>

#include <shirudo/misc.h>

/*
 * The NAME column of a table is as wide as its longest name, and at
 * least this wide, so that a table of short names keeps its shape.
 */
#define NAME_COLUMN_MIN	24

/*
 * Format a byte count in IEC-binary human units: B/K/M/G. Precision is
 * picked so the rendered value stays within four significant digits
 * regardless of magnitude (16K / 1.8M / 5.57G / 1.23G / 124G).
 */
int human_size(__u64 bytes, char *out, size_t out_cap);

/*
 * Text from outside, such as the certificate subject in a key's
 * description, on f as text_sanitize() leaves it, on one line and cut
 * after 511 bytes.
 */
void fputs_sanitized(const char *s, FILE *f);

#endif /* SHIRUDO_UTIL_FORMAT_H */
