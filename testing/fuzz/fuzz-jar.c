// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * A jar as shirudo-build checks it before it signs a Java agent: the
 * input as the archive, and the input as the manifest of a jar written
 * around it, stored and deflated, which must give the manifest's answer.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.h"
#include "tools/shirudo-build/jar.c"

#define MANIFEST_NAME_LEN	(sizeof(manifest_name) - 1)
#define JAR_OVERHEAD		(ZIP_LOCAL_LEN + MANIFEST_NAME_LEN + \
				 ZIP_ENTRY_LEN + MANIFEST_NAME_LEN + \
				 ZIP_END_LEN)

static void put_le16(__u8 *p, __u16 v)
{
	__le16 le = cpu_to_le16(v);

	memcpy(p, &le, sizeof(le));
}

static void put_le32(__u8 *p, __u32 v)
{
	__le32 le = cpu_to_le32(v);

	memcpy(p, &le, sizeof(le));
}

/* A jar of one entry, the manifest, whose packed bytes are given. */
static __u8 *jar_around(__u16 method, const __u8 *packed, __u32 packed_len,
			__u32 len, size_t *jar_len)
{
	size_t dir_off = ZIP_LOCAL_LEN + MANIFEST_NAME_LEN + (size_t)packed_len;
	__u8 *jar, *dir, *end;

	*jar_len = JAR_OVERHEAD + (size_t)packed_len;
	jar = xcalloc(1, *jar_len);
	if (!jar)
		abort();
	put_le32(jar, ZIP_LOCAL_SIG);
	put_le16(jar + 8, method);
	put_le32(jar + 18, packed_len);
	put_le32(jar + 22, len);
	put_le16(jar + 26, MANIFEST_NAME_LEN);
	memcpy(jar + ZIP_LOCAL_LEN, manifest_name, MANIFEST_NAME_LEN);
	if (packed_len)
		memcpy(jar + ZIP_LOCAL_LEN + MANIFEST_NAME_LEN, packed,
		       packed_len);

	dir = jar + dir_off;
	put_le32(dir, ZIP_ENTRY_SIG);
	put_le16(dir + 10, method);
	put_le32(dir + 20, packed_len);
	put_le32(dir + 24, len);
	put_le16(dir + 28, MANIFEST_NAME_LEN);
	memcpy(dir + ZIP_ENTRY_LEN, manifest_name, MANIFEST_NAME_LEN);

	end = dir + ZIP_ENTRY_LEN + MANIFEST_NAME_LEN;
	put_le32(end, ZIP_END_SIG);
	put_le16(end + 8, 1);
	put_le16(end + 10, 1);
	put_le32(end + 12, ZIP_ENTRY_LEN + MANIFEST_NAME_LEN);
	put_le32(end + 16, (__u32)dir_off);
	return jar;
}

static int verdict_of_jar_around(__u16 method, const __u8 *packed,
				 __u32 packed_len, __u32 len)
{
	size_t jar_len;
	__u8 *jar;
	int ret;

	jar = jar_around(method, packed, packed_len, len, &jar_len);
	ret = jar_premain_class(jar, jar_len);
	xfree(jar, jar_len);
	return ret;
}

static int verdict_deflated(const __u8 *manifest, __u32 len)
{
	__u32 packed_len;
	z_stream z = {};
	__u8 *packed;
	uLong bound;
	int ret;

	if (deflateInit2(&z, Z_BEST_SPEED, Z_DEFLATED, -MAX_WBITS, 8,
			 Z_DEFAULT_STRATEGY) != Z_OK)
		abort();
	bound = deflateBound(&z, len);
	packed = xmalloc(bound);
	if (!packed)
		abort();
	z.next_in = (Bytef *)manifest;
	z.avail_in = len;
	z.next_out = packed;
	z.avail_out = (uInt)bound;
	if (deflate(&z, Z_FINISH) != Z_STREAM_END)
		abort();
	packed_len = (__u32)z.total_out;
	deflateEnd(&z);
	ret = verdict_of_jar_around(ZIP_DEFLATED, packed, packed_len, len);
	xfree(packed, bound);
	return ret;
}

/* The entry's bytes lie within the archive it was found in. */
static void check_entry_bounds(const __u8 *jar, size_t len)
{
	const __u8 *packed;
	struct zip_entry e;
	size_t off;

	if (zip_find(jar, len, manifest_name, &e) ||
	    zip_entry_data(jar, len, &e, &packed))
		return;
	if (packed < jar)
		abort();
	off = (size_t)(packed - jar);
	if (off > len || e.packed_len > len - off)
		abort();
}

static bool documented(int ret)
{
	return ret == 0 || ret == -ENOENT || ret == -ENOTSUP ||
	       ret == -EFBIG || ret == -EINVAL || ret == -ENOMEM;
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	int want, stored, deflated;

	if (!documented(jar_premain_class(data, size)))
		abort();
	check_entry_bounds(data, size);

	if (size > JAR_MANIFEST_MAX)
		return 0;
	want = manifest_has_premain(data, size) ? 0 : -ENOENT;
	stored = verdict_of_jar_around(ZIP_STORED, data, (__u32)size,
				       (__u32)size);
	deflated = verdict_deflated(data, (__u32)size);
	if (stored != want || deflated != want)
		abort();
	return 0;
}
