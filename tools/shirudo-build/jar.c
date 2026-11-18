// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The manifest of a jar, read from its zip central directory, and the
 * Premain-Class attribute a Java agent needs in it.
 */

#include <errno.h>
#include <string.h>
#include <zlib.h>

#include <shirudo/byteorder.h>
#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "jar.h"
#include "util/malloc.h"

#define ZIP_END_SIG		0x06054b50u
#define ZIP_END_LEN		22u
#define ZIP_COMMENT_MAX		65535u
#define ZIP_ENTRY_SIG		0x02014b50u
#define ZIP_ENTRY_LEN		46u
#define ZIP_LOCAL_SIG		0x04034b50u
#define ZIP_LOCAL_LEN		30u
#define ZIP_STORED		0
#define ZIP_DEFLATED		8
#define JAR_MANIFEST_MAX	(1u << 20)

static const char manifest_name[] = "META-INF/MANIFEST.MF";
static const char premain_attr[] = "Premain-Class:";

struct zip_entry {
	__u16	method;
	__u32	packed_len;
	__u32	len;
	__u32	local_off;
};

static bool in_bounds(size_t off, size_t need, size_t len)
{
	return off <= len && need <= len - off;
}

static char ascii_lower(char c)
{
	return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c;
}

/* A JVM finds the manifest and its attributes whatever their case. */
static bool same_ignoring_case(const __u8 *a, const char *b, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (ascii_lower((char)a[i]) != ascii_lower(b[i]))
			return false;
	}
	return true;
}

/* The end record is last but for a comment, so the search runs backward. */
static int zip_directory(const __u8 *zip, size_t len, size_t *off,
			 size_t *entries)
{
	size_t at, low;
	__u32 dir_off;

	if (len < ZIP_END_LEN)
		return -EINVAL;
	at = len - ZIP_END_LEN;
	low = at > ZIP_COMMENT_MAX ? at - ZIP_COMMENT_MAX : 0;
	while (get_le32(zip + at) != ZIP_END_SIG) {
		if (at == low)
			return -EINVAL;
		at--;
	}
	*entries = get_le16(zip + at + 10);
	dir_off = get_le32(zip + at + 16);
	if (*entries == 0xffff || dir_off == 0xffffffffu)
		return -ENOTSUP;
	if (dir_off > at)
		return -EINVAL;
	*off = dir_off;
	return 0;
}

/* 0 with *e the entry named name, -ENOENT for none. */
static int zip_find(const __u8 *zip, size_t len, const char *name,
		    struct zip_entry *e)
{
	size_t off, entries, name_len, skip, i;
	int ret;

	ret = zip_directory(zip, len, &off, &entries);
	if (ret)
		return ret;
	for (i = 0; i < entries; i++) {
		if (!in_bounds(off, ZIP_ENTRY_LEN, len) ||
		    get_le32(zip + off) != ZIP_ENTRY_SIG)
			return -EINVAL;
		name_len = get_le16(zip + off + 28);
		skip = (size_t)get_le16(zip + off + 30) +
		       get_le16(zip + off + 32);
		if (!in_bounds(off + ZIP_ENTRY_LEN, name_len + skip, len))
			return -EINVAL;
		if (name_len == strlen(name) &&
		    same_ignoring_case(zip + off + ZIP_ENTRY_LEN, name,
				       name_len)) {
			e->method = get_le16(zip + off + 10);
			e->packed_len = get_le32(zip + off + 20);
			e->len = get_le32(zip + off + 24);
			e->local_off = get_le32(zip + off + 42);
			return 0;
		}
		off += ZIP_ENTRY_LEN + name_len + skip;
	}
	return -ENOENT;
}

/* Where the entry's bytes start, past its local header. */
static int zip_entry_data(const __u8 *zip, size_t len,
			  const struct zip_entry *e, const __u8 **data)
{
	size_t off = e->local_off, skip;

	if (!in_bounds(off, ZIP_LOCAL_LEN, len) ||
	    get_le32(zip + off) != ZIP_LOCAL_SIG)
		return -EINVAL;
	skip = (size_t)get_le16(zip + off + 26) + get_le16(zip + off + 28);
	off += ZIP_LOCAL_LEN;
	if (!in_bounds(off, skip, len) ||
	    !in_bounds(off + skip, e->packed_len, len))
		return -EINVAL;
	*data = zip + off + skip;
	return 0;
}

static int inflate_entry(const __u8 *packed, const struct zip_entry *e,
			 __u8 *out)
{
	z_stream z = {};
	int ret;

	/* Negative window bits: a zip entry is a raw deflate stream. */
	if (inflateInit2(&z, -MAX_WBITS) != Z_OK)
		return -ENOMEM;
	z.next_in = (Bytef *)packed;
	z.avail_in = e->packed_len;
	z.next_out = out;
	z.avail_out = e->len;
	ret = inflate(&z, Z_FINISH);
	inflateEnd(&z);
	return ret == Z_STREAM_END && !z.avail_out ? 0 : -EINVAL;
}

/* The entry's bytes, xmalloc'd, e->len of them. */
static int zip_entry_read(const __u8 *zip, size_t len,
			  const struct zip_entry *e, __u8 **out)
{
	const __u8 *data;
	__u8 *buf;
	int ret;

	if (e->len > JAR_MANIFEST_MAX)
		return -EFBIG;
	if (e->method != ZIP_STORED && e->method != ZIP_DEFLATED)
		return -ENOTSUP;
	if (e->method == ZIP_STORED && e->packed_len != e->len)
		return -EINVAL;
	ret = zip_entry_data(zip, len, e, &data);
	if (ret)
		return ret;
	buf = xmalloc((size_t)e->len + 1);
	if (!buf)
		return -ENOMEM;
	if (e->method == ZIP_STORED)
		memcpy(buf, data, e->len);
	else
		ret = inflate_entry(data, e, buf);
	if (ret) {
		xfree(buf, (size_t)e->len + 1);
		return ret;
	}
	*out = buf;
	return 0;
}

static bool line_end(__u8 c)
{
	return c == '\n' || c == '\r';
}

/*
 * Whether the main section, which the first empty line ends, has a
 * Premain-Class with a value.
 */
static bool manifest_has_premain(const __u8 *m, size_t len)
{
	size_t attr = strlen(premain_attr), at = 0, end;

	while (at < len && !line_end(m[at])) {
		for (end = at; end < len && !line_end(m[end]); end++)
			;
		if (end - at > attr &&
		    same_ignoring_case(m + at, premain_attr, attr)) {
			for (at += attr; at < end; at++) {
				if (m[at] != ' ')
					return true;
			}
			return false;
		}
		at = end;
		if (at < len && m[at] == '\r')
			at++;
		if (at < len && m[at] == '\n')
			at++;
	}
	return false;
}

int jar_premain_class(const __u8 *jar, size_t len)
{
	struct zip_entry e;
	__u8 *manifest;
	int ret;

	ret = zip_find(jar, len, manifest_name, &e);
	if (!ret)
		ret = zip_entry_read(jar, len, &e, &manifest);
	if (ret)
		return ret;
	ret = manifest_has_premain(manifest, e.len) ? 0 : -ENOENT;
	xfree(manifest, (size_t)e.len + 1);
	return ret;
}
