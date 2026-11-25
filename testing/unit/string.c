// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdint.h>

#include <shirudo/string.h>

#include "malloc.h"
#include "unit.h"

/*
 * The span under test sits in a buffer of exactly its length, so a read
 * past it shows up under ASan.
 */
static char *span(const char *text, size_t len)
{
	char *buf = xmalloc(len ? len : 1);

	ASSERT_TRUE(buf);
	memcpy(buf, text, len);
	return buf;
}

static int u64_of(const char *text, size_t len, __u64 max, __u64 *v)
{
	char *buf = span(text, len);
	int ret;

	*v = 0;
	ret = parse_u64(buf, len, max, v);
	xfree(buf, len ? len : 1);
	return ret;
}

static int x64_of(const char *text, __u64 max, __u64 *v)
{
	size_t len = strlen(text);
	char *buf = span(text, len);
	int ret;

	*v = 0;
	ret = parse_x64(buf, len, max, v);
	xfree(buf, len ? len : 1);
	return ret;
}

static int s64_of(const char *text, __s64 min, __s64 max, __s64 *v)
{
	size_t len = strlen(text);
	char *buf = span(text, len);
	int ret;

	*v = 0;
	ret = parse_s64(buf, len, min, max, v);
	xfree(buf, len ? len : 1);
	return ret;
}

static int u64_str(const char *text, __u64 max, __u64 *v)
{
	return u64_of(text, strlen(text), max, v);
}

#define EXPECT_U64(text, max, ret, value)				\
	do {								\
		__u64 v_;						\
									\
		EXPECT_EQ(u64_str(text, max, &v_), ret);			\
		EXPECT_UEQ(v_, value);					\
	} while (0)

static void digits_counts_leading_digits(void)
{
	EXPECT_UEQ(digits("123abc", 6), 3);
	EXPECT_UEQ(digits("abc", 3), 0);
	EXPECT_UEQ(digits("", 0), 0);
}

static void decimal_fills_its_span(void)
{
	EXPECT_U64("0", UINT64_MAX, 0, 0);
	EXPECT_U64("007", UINT64_MAX, 0, 7);
	EXPECT_U64("18446744073709551615", UINT64_MAX, 0, UINT64_MAX);
}

static void nothing_past_the_span_is_read(void)
{
	__u64 v;

	EXPECT_EQ(u64_of("123456", 3, UINT64_MAX, &v), 0);
	EXPECT_UEQ(v, 123);
	EXPECT_EQ(u64_of("123", 0, UINT64_MAX, &v), -EINVAL);
	EXPECT_UEQ(v, 0);
}

static void sign_blank_or_prefix_is_no_number(void)
{
	static const char *const bad[] = {
		"", "-1", "+1", " 1", "1 ", "0x10", "1.5", "1e3", "12a",
	};

	for (size_t i = 0; i < ARRAY_SIZE(bad); i++)
		EXPECT_U64(bad[i], UINT64_MAX, -EINVAL, 0);
}

static void number_past_its_bound_is_out_of_range(void)
{
	EXPECT_U64("18446744073709551616", UINT64_MAX, -ERANGE, 0);
	EXPECT_U64("10", 10, 0, 10);
	EXPECT_U64("11", 10, -ERANGE, 0);
	EXPECT_U64("9", 5, -ERANGE, 0);
	EXPECT_U64("0", 0, 0, 0);
}

static void malformed_number_however_long(void)
{
	EXPECT_U64("99999999999999999999x", UINT64_MAX, -EINVAL, 0);
}

static void hex_takes_either_case_and_no_prefix(void)
{
	__u64 v;

	EXPECT_EQ(x64_of("ff", UINT64_MAX, &v), 0);
	EXPECT_UEQ(v, 255);
	EXPECT_EQ(x64_of("FF", UINT64_MAX, &v), 0);
	EXPECT_UEQ(v, 255);
	EXPECT_EQ(x64_of("ffffffffffffffff", UINT64_MAX, &v), 0);
	EXPECT_UEQ(v, UINT64_MAX);
	EXPECT_EQ(x64_of("10000000000000000", UINT64_MAX, &v), -ERANGE);
	EXPECT_UEQ(v, 0);
	EXPECT_EQ(x64_of("0x10", UINT64_MAX, &v), -EINVAL);
	EXPECT_UEQ(v, 0);
	EXPECT_EQ(x64_of("g", UINT64_MAX, &v), -EINVAL);
	EXPECT_UEQ(v, 0);
}

static void signed_number_spans_the_whole_range(void)
{
	__s64 v;

	EXPECT_EQ(s64_of("-9223372036854775808", INT64_MIN, INT64_MAX, &v), 0);
	EXPECT_EQ(v, INT64_MIN);
	EXPECT_EQ(s64_of("9223372036854775807", INT64_MIN, INT64_MAX, &v), 0);
	EXPECT_EQ(v, INT64_MAX);
	EXPECT_EQ(s64_of("-0", INT64_MIN, INT64_MAX, &v), 0);
	EXPECT_EQ(v, 0);
	EXPECT_EQ(s64_of("9223372036854775808", INT64_MIN, INT64_MAX, &v),
		  -ERANGE);
	EXPECT_EQ(v, 0);
	EXPECT_EQ(s64_of("-9223372036854775809", INT64_MIN, INT64_MAX, &v),
		  -ERANGE);
	EXPECT_EQ(v, 0);
}

static void signed_number_keeps_bounds_and_form(void)
{
	static const char *const bad[] = { "-", "--", "--1", "+1", " -1", "-x" };
	__s64 v;

	EXPECT_EQ(s64_of("0", 1, 10, &v), -ERANGE);
	EXPECT_EQ(v, 0);
	EXPECT_EQ(s64_of("-6", -5, 5, &v), -ERANGE);
	EXPECT_EQ(v, 0);
	EXPECT_EQ(s64_of("-5", -5, 5, &v), 0);
	EXPECT_EQ(v, -5);
	for (size_t i = 0; i < ARRAY_SIZE(bad); i++) {
		EXPECT_EQ(s64_of(bad[i], INT64_MIN, INT64_MAX, &v), -EINVAL);
		EXPECT_EQ(v, 0);
	}
}

static void strscpy_copies_what_fits_whole(void)
{
	char six[6], big[64], one[1];

	EXPECT_EQ(strscpy(six, "hello", sizeof(six)), 5);
	EXPECT_STREQ(six, "hello");
	EXPECT_EQ(strscpy(big, "hello", sizeof(big)), 5);
	EXPECT_STREQ(big, "hello");
	EXPECT_EQ(strscpy(one, "", sizeof(one)), 0);
	EXPECT_STREQ(one, "");
}

static void strscpy_cuts_and_says_so(void)
{
	char five[5], one[1], none[1] = { 'x' };

	EXPECT_EQ(strscpy(five, "hello", sizeof(five)), -E2BIG);
	EXPECT_STREQ(five, "hell");
	EXPECT_EQ(strscpy(one, "hello", sizeof(one)), -E2BIG);
	EXPECT_STREQ(one, "");
	EXPECT_EQ(strscpy(none, "hello", 0), -E2BIG);
	EXPECT_EQ(none[0], 'x');
}

static void strscpy_literal_copies_with_its_terminator(void)
{
	struct {
		char six[6];
		char after;
	} s;
	char big[8], one[1];

	memset(&s, 'x', sizeof(s));
	strscpy_literal(s.six, "hello");
	EXPECT_STREQ(s.six, "hello");
	EXPECT_EQ(s.after, 'x');
	memset(big, 'x', sizeof(big));
	strscpy_literal(big, "hi");
	EXPECT_STREQ(big, "hi");
	EXPECT_EQ(big[3], 'x');
	one[0] = 'x';
	strscpy_literal(one, "");
	EXPECT_STREQ(one, "");
}

static void strsprintf_writes_what_fits_whole(void)
{
	char eight[8], big[64];

	EXPECT_EQ(strsprintf(eight, sizeof(eight), "<%s>", "hello"), 7);
	EXPECT_STREQ(eight, "<hello>");
	EXPECT_EQ(strsprintf(big, sizeof(big), "<%s>", ""), 2);
	EXPECT_STREQ(big, "<>");
}

static void strsprintf_leaves_nothing_when_cut(void)
{
	char seven[7] = { 'x' }, one[1] = { 'x' }, none[1] = { 'x' };

	EXPECT_EQ(strsprintf(seven, sizeof(seven), "<%s>", "hello"), -E2BIG);
	EXPECT_STREQ(seven, "");
	EXPECT_EQ(strsprintf(one, sizeof(one), "<%s>", "hello"), -E2BIG);
	EXPECT_STREQ(one, "");
	EXPECT_EQ(strsprintf(none, 0, "<%s>", "hello"), -E2BIG);
	EXPECT_EQ(none[0], 'x');
}

static void xasprintf_allocates_the_size_needed(void)
{
	char text[301], want[310], *s;

	s = xasprintf("<%s|%d>", "hello", 42);
	ASSERT_TRUE(s);
	EXPECT_STREQ(s, "<hello|42>");
	xstrfree(s);

	s = xasprintf("<%s|%d>", "", 42);
	ASSERT_TRUE(s);
	EXPECT_STREQ(s, "<|42>");
	xstrfree(s);

	memset(text, '0', sizeof(text) - 1);
	text[sizeof(text) - 1] = '\0';
	ASSERT_EQ(strsprintf(want, sizeof(want), "<%s|42>", text), 305);
	s = xasprintf("<%s|%d>", text, 42);
	ASSERT_TRUE(s);
	EXPECT_STREQ(s, want);
	xstrfree(s);
}

static void dns_name_is_ldh_labels_and_no_address(void)
{
	char label[65], name[300];

	EXPECT_TRUE(dns_name_valid("registry.example.com"));
	EXPECT_TRUE(dns_name_valid("Reg-1.Example"));
	EXPECT_TRUE(dns_name_valid("localhost"));
	EXPECT_TRUE(dns_name_valid("1.2.3.example"));
	EXPECT_TRUE(dns_name_valid("0x.1"));
	EXPECT_FALSE(dns_name_valid(""));
	EXPECT_FALSE(dns_name_valid("."));
	EXPECT_FALSE(dns_name_valid("example..com"));
	EXPECT_FALSE(dns_name_valid("example.com."));
	EXPECT_FALSE(dns_name_valid("-example.com"));
	EXPECT_FALSE(dns_name_valid("example-.com"));
	EXPECT_FALSE(dns_name_valid("exa_mple.com"));
	EXPECT_FALSE(dns_name_valid("example.com:443"));
	EXPECT_FALSE(dns_name_valid("10.0.2.2"));
	EXPECT_FALSE(dns_name_valid("127.1"));
	EXPECT_FALSE(dns_name_valid("0x7f.1"));
	EXPECT_FALSE(dns_name_valid("2130706433"));

	memset(label, 'a', 63);
	label[63] = '\0';
	ASSERT_TRUE(strsprintf(name, sizeof(name), "%s.example", label) > 0);
	EXPECT_TRUE(dns_name_valid(name));
	memset(label, 'a', 64);
	label[64] = '\0';
	ASSERT_TRUE(strsprintf(name, sizeof(name), "%s.example", label) > 0);
	EXPECT_FALSE(dns_name_valid(name));

	memset(label, 'a', 63);
	label[63] = '\0';
	ASSERT_TRUE(strsprintf(name, sizeof(name), "%s.%s.%s.%.61s", label,
			       label, label, label) == 253);
	EXPECT_TRUE(dns_name_valid(name));
	ASSERT_TRUE(strsprintf(name, sizeof(name), "%s.%s.%s.%.62s", label,
			       label, label, label) == 254);
	EXPECT_FALSE(dns_name_valid(name));
}

static size_t width_of(const char *text, size_t len)
{
	char *buf = span(text, len);
	size_t width = utf8_width(buf, len);

	xfree(buf, len ? len : 1);
	return width;
}

static void utf8_width_takes_well_formed_characters_only(void)
{
	EXPECT_EQ(width_of("", 0), 0);
	EXPECT_EQ(width_of("a", 1), 1);
	EXPECT_EQ(width_of("\x7f", 1), 1);
	EXPECT_EQ(width_of("\xc2\x80", 2), 2);
	EXPECT_EQ(width_of("\xdf\xbf", 2), 2);
	EXPECT_EQ(width_of("\xe0\xa0\x80", 3), 3);
	EXPECT_EQ(width_of("\xed\x9f\xbf", 3), 3);
	EXPECT_EQ(width_of("\xee\x80\x80", 3), 3);
	EXPECT_EQ(width_of("\xef\xbf\xbf", 3), 3);
	EXPECT_EQ(width_of("\xf0\x90\x80\x80", 4), 4);
	EXPECT_EQ(width_of("\xf4\x8f\xbf\xbf", 4), 4);
	EXPECT_EQ(width_of("\xc3\xa9z", 3), 2);

	EXPECT_EQ(width_of("\x80", 1), 0);
	EXPECT_EQ(width_of("\xbf", 1), 0);
	EXPECT_EQ(width_of("\xc3", 1), 0);
	EXPECT_EQ(width_of("\xe2\x82", 2), 0);
	EXPECT_EQ(width_of("\xe2\x82z", 3), 0);
	EXPECT_EQ(width_of("\xc0\x80", 2), 0);
	EXPECT_EQ(width_of("\xc0\xaf", 2), 0);
	EXPECT_EQ(width_of("\xc1\xbf", 2), 0);
	EXPECT_EQ(width_of("\xe0\x80\xaf", 3), 0);
	EXPECT_EQ(width_of("\xe0\x9f\xbf", 3), 0);
	EXPECT_EQ(width_of("\xed\xa0\x80", 3), 0);
	EXPECT_EQ(width_of("\xed\xbf\xbf", 3), 0);
	EXPECT_EQ(width_of("\xf0\x8f\xbf\xbf", 4), 0);
	EXPECT_EQ(width_of("\xf4\x90\x80\x80", 4), 0);
	EXPECT_EQ(width_of("\xf5\x80\x80\x80", 4), 0);
	EXPECT_EQ(width_of("\xf8\x88\x80\x80\x80", 5), 0);
	EXPECT_EQ(width_of("\xff", 1), 0);
}

static size_t utf8_encode(__u32 cp, char *buf)
{
	if (cp < 0x80) {
		buf[0] = (char)cp;
		return 1;
	}
	if (cp < 0x800) {
		buf[0] = (char)(0xc0 | cp >> 6);
		buf[1] = (char)(0x80 | (cp & 0x3f));
		return 2;
	}
	if (cp < 0x10000) {
		buf[0] = (char)(0xe0 | cp >> 12);
		buf[1] = (char)(0x80 | (cp >> 6 & 0x3f));
		buf[2] = (char)(0x80 | (cp & 0x3f));
		return 3;
	}
	buf[0] = (char)(0xf0 | cp >> 18);
	buf[1] = (char)(0x80 | (cp >> 12 & 0x3f));
	buf[2] = (char)(0x80 | (cp >> 6 & 0x3f));
	buf[3] = (char)(0x80 | (cp & 0x3f));
	return 4;
}

/*
 * Every scalar value's encoding is taken, and there are no more 2-, 3-
 * and 4-byte sequences taken than scalar values of that length, so
 * those encodings are all there is.
 */
static void utf8_width_takes_the_scalar_values_alone(void)
{
	__u32 cp, i, wrong = 0, two = 0, three = 0, four = 0;
	char buf[4];

	for (cp = 0; cp <= 0x10ffff; cp++) {
		size_t len;

		if (cp >= 0xd800 && cp <= 0xdfff)
			continue;
		len = utf8_encode(cp, buf);
		if (utf8_width(buf, len) != len)
			wrong++;
	}
	EXPECT_EQ(wrong, 0);
	for (i = 0; i < 1u << 16; i++) {
		buf[0] = (char)(i >> 8);
		buf[1] = (char)i;
		two += utf8_width(buf, 2) == 2;
	}
	EXPECT_EQ(two, 0x780);
	for (i = 0; i < 1u << 24; i++) {
		buf[0] = (char)(i >> 16);
		buf[1] = (char)(i >> 8);
		buf[2] = (char)i;
		three += utf8_width(buf, 3) == 3;
	}
	EXPECT_EQ(three, 0xf000);
	for (i = 0; i < 1u << 22; i++) {
		buf[0] = (char)(0xf0 | i >> 18);
		buf[1] = (char)(0x80 | (i >> 12 & 0x3f));
		buf[2] = (char)(0x80 | (i >> 6 & 0x3f));
		buf[3] = (char)(0x80 | (i & 0x3f));
		four += utf8_width(buf, 4) == 4;
	}
	EXPECT_EQ(four, 0x100000);
}

static bool sanitized(const char *text, size_t len, bool lines,
		      const char *want)
{
	char *buf = span(text, len);
	bool same;

	text_sanitize(buf, len, lines);
	same = !memcmp(buf, want, len);
	xfree(buf, len ? len : 1);
	return same;
}

static void text_sanitize_replaces_controls_and_stray_bytes(void)
{
	EXPECT_TRUE(sanitized("", 0, false, ""));
	EXPECT_TRUE(sanitized("plain ~text", 11, false, "plain ~text"));
	EXPECT_TRUE(sanitized("\x1b[31mred", 8, false, "?[31mred"));
	EXPECT_TRUE(sanitized("a\0b\x7f", 4, false, "a?b?"));
	EXPECT_TRUE(sanitized("t\tl\n", 4, false, "t?l?"));
	EXPECT_TRUE(sanitized("t\tl\n", 4, true, "t\tl\n"));
	EXPECT_TRUE(sanitized("a\r\nb\rc\r", 7, true, "a\r\nb?c?"));
	EXPECT_TRUE(sanitized("\xc2\x9b\x33\x31m", 5, true, "??31m"));
	EXPECT_TRUE(sanitized("\xc2\x80\xc2\x9f\xc2\xa0", 6, false,
			      "????\xc2\xa0"));
	EXPECT_TRUE(sanitized("caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x90\x9d",
			      14, false,
			      "caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x90\x9d"));
	EXPECT_TRUE(sanitized("\xff\xc3z\xe2\x82", 5, false, "??z??"));
	EXPECT_TRUE(sanitized("\xed\xa0\x80", 3, false, "???"));
}

static void text_sanitize_replaces_hidden_formats(void)
{
	EXPECT_TRUE(sanitized("evil\342\200\256fdp.exe", 14, false,
			      "evil???fdp.exe"));
	EXPECT_TRUE(sanitized("a\342\201\246b\342\201\251", 8, true,
			      "a???b???"));
	EXPECT_TRUE(sanitized("x\xe2\x80\x8by\xd8\x9c", 7, false,
			      "x???y??"));
	EXPECT_TRUE(sanitized("\xe2\x80\xa8\xe2\x80\xa9", 6, true, "??????"));
	EXPECT_TRUE(sanitized("\xe2\x80\x8a\xe2\x80\x90\xe2\x80\xaf", 9,
			      false, "\xe2\x80\x8a\xe2\x80\x90\xe2\x80\xaf"));
}

static bool hidden_format_cp(__u32 cp)
{
	return cp == 0x061c || (cp >= 0x200b && cp <= 0x200f) ||
	       (cp >= 0x2028 && cp <= 0x202e) ||
	       (cp >= 0x2066 && cp <= 0x2069);
}

/*
 * Every scalar value but the controls and the hidden formats passes; one
 * of those leaves only '?'.
 */
static void text_sanitize_passes_all_but_the_controls(void)
{
	__u32 cp, wrong = 0;
	char buf[4];

	for (cp = 0; cp <= 0x10ffff; cp++) {
		bool control = cp < 0x20 || (cp >= 0x7f && cp <= 0x9f) ||
			       hidden_format_cp(cp);
		size_t len, i, marks = 0;
		char copy[4];

		if (cp >= 0xd800 && cp <= 0xdfff)
			continue;
		len = utf8_encode(cp, buf);
		memcpy(copy, buf, len);
		text_sanitize(buf, len, false);
		for (i = 0; i < len; i++)
			marks += buf[i] == '?';
		if (control ? marks != len : memcmp(buf, copy, len))
			wrong++;
	}
	EXPECT_EQ(wrong, 0);
}

static void memzero_explicit_clears_its_span_only(void)
{
	__u8 want[16], buf[16];

	memset(buf, 0xa5, sizeof(buf));
	memset(want, 0xa5, sizeof(want));
	memset(want + 4, 0, 8);
	memzero_explicit(buf + 4, 8);
	EXPECT_MEMEQ(buf, want, sizeof(buf));
}

static void memneq_explicit_tells_every_bit_apart(void)
{
	__u8 a[33], b[33];
	size_t i;
	int bit;

	for (i = 0; i < sizeof(a); i++)
		a[i] = (__u8)(i * 37 + 1);
	memcpy(b, a, sizeof(b));
	EXPECT_EQ(memneq_explicit(a, b, sizeof(a)), 0);
	EXPECT_EQ(memneq_explicit(a, b, 0), 0);
	for (i = 0; i < sizeof(a); i++) {
		for (bit = 0; bit < 8; bit++) {
			b[i] ^= 1u << bit;
			EXPECT_EQ(memneq_explicit(a, b, sizeof(a)), 1);
			EXPECT_EQ(memneq_explicit(a, b, i), 0);
			b[i] ^= 1u << bit;
		}
	}
}

static void name_has_suffix_wants_a_stem(void)
{
	EXPECT_TRUE(name_has_suffix("a.upatch", 8, ".upatch"));
	EXPECT_TRUE(name_has_suffix("a.upatch.x", 8, ".upatch"));
	EXPECT_FALSE(name_has_suffix(".upatch", 7, ".upatch"));
	EXPECT_FALSE(name_has_suffix("a.upatch.bak", 12, ".upatch"));
	EXPECT_FALSE(name_has_suffix("a.UPATCH", 8, ".upatch"));
	EXPECT_FALSE(name_has_suffix("", 0, ""));
	EXPECT_TRUE(name_has_suffix("a", 1, ""));
}

static bool glob(const char *pattern, const char *name)
{
	return name_glob_match(pattern, name, strlen(name));
}

static void name_glob_match_takes_stars_and_question_marks(void)
{
	EXPECT_TRUE(glob("php-fpm", "php-fpm"));
	EXPECT_FALSE(glob("php-fpm", "php-fpm8"));
	EXPECT_FALSE(glob("php-fpm8", "php-fpm"));
	EXPECT_TRUE(glob("php-fpm*", "php-fpm"));
	EXPECT_TRUE(glob("php-fpm*", "php-fpm8.3"));
	EXPECT_FALSE(glob("php-fpm*", "php-cgi8.3"));
	EXPECT_TRUE(glob("*.php", "index.php"));
	EXPECT_TRUE(glob("*.php", ".php"));
	EXPECT_FALSE(glob("*.php", "index.php.bak"));
	EXPECT_TRUE(glob("a*c", "ac"));
	EXPECT_TRUE(glob("a*c", "abcbc"));
	EXPECT_FALSE(glob("a*c", "abcb"));
	EXPECT_TRUE(glob("*a*b*", "xaybz"));
	EXPECT_TRUE(glob("a**b", "ab"));
	EXPECT_FALSE(glob("*a*b*", "xbya"));
	EXPECT_TRUE(glob("php?.?", "php8.3"));
	EXPECT_FALSE(glob("php?.?", "php8.31"));
	EXPECT_FALSE(glob("php?", "php"));
	EXPECT_TRUE(glob("*", "a"));
	EXPECT_TRUE(glob("*", ""));
	EXPECT_FALSE(glob("?", ""));
	EXPECT_FALSE(glob("", "a"));
	EXPECT_TRUE(glob("", ""));
}

/* A pattern is for the entries of a directory, which these two are not. */
static void name_glob_match_leaves_out_dot_and_dotdot(void)
{
	EXPECT_FALSE(glob("*", "."));
	EXPECT_FALSE(glob("*", ".."));
	EXPECT_FALSE(glob(".", "."));
	EXPECT_FALSE(glob("?", "."));
	EXPECT_FALSE(glob("??", ".."));
	EXPECT_TRUE(glob("*", "..."));
	EXPECT_TRUE(glob(".*", ".profile"));
	EXPECT_TRUE(glob("??", "a."));
}

/* The name comes with a length and need not end where its buffer does. */
static void name_glob_match_reads_len_bytes(void)
{
	EXPECT_TRUE(name_glob_match("php*", "php-fpm/junk", 7));
	EXPECT_FALSE(name_glob_match("*junk", "php-fpm/junk", 7));
	EXPECT_FALSE(name_glob_match("a", "a\0b", 3));
	EXPECT_TRUE(name_glob_match("a?b", "a\0b", 3));
}

#define TEST_DIR "/run"

static void str_has_prefix_gives_its_length(void)
{
	EXPECT_UEQ(str_has_prefix("oci://registry", "oci://"), 6);
	EXPECT_UEQ(str_has_prefix("oci://", "oci://"), 6);
	EXPECT_UEQ(str_has_prefix("oci:/", "oci://"), 0);
	EXPECT_UEQ(str_has_prefix("OCI://registry", "oci://"), 0);
	EXPECT_UEQ(str_has_prefix("", "oci://"), 0);
	EXPECT_UEQ(str_has_prefix("/run/x", TEST_DIR "/"), 5);
}

static void str_skip_prefix_moves_only_on_a_match(void)
{
	const char *p = "realm=\"x\"";
	char buf[] = "s3://bucket";
	char *q = buf;

	EXPECT_FALSE(str_skip_prefix(&p, "scope=\""));
	EXPECT_STREQ(p, "realm=\"x\"");
	EXPECT_TRUE(str_skip_prefix(&p, "realm=\""));
	EXPECT_STREQ(p, "x\"");
	EXPECT_TRUE(str_skip_prefix(&q, "s3://"));
	EXPECT_TRUE(q == buf + 5);
}

static void span_equals_wants_the_whole_literal(void)
{
	const char *path = "a/../b";

	EXPECT_TRUE(span_equals(path + 2, 2, ".."));
	EXPECT_FALSE(span_equals(path + 2, 3, ".."));
	EXPECT_FALSE(span_equals(path + 2, 1, ".."));
	EXPECT_TRUE(span_equals(path + 2, 1, "."));
	EXPECT_FALSE(span_equals(path, 1, "."));
	EXPECT_TRUE(span_equals(path, 0, ""));
}

static void span_to_str_copies_and_terminates(void)
{
	char *bytes = span("abc", 3);
	char dst[4] = "xxx";

	ASSERT_EQ(span_to_str(dst, sizeof(dst), bytes, 3), 0);
	EXPECT_STREQ(dst, "abc");
	ASSERT_EQ(span_to_str(dst, sizeof(dst), bytes, 2), 0);
	EXPECT_STREQ(dst, "ab");
	ASSERT_EQ(span_to_str(dst, 1, bytes, 0), 0);
	EXPECT_STREQ(dst, "");
	xfree(bytes, 3);
}

/* A string that ended at the NUL would be "ab", not the four bytes. */
static void span_to_str_refuses_a_nul_among_the_bytes(void)
{
	static const char first[] = { '\0', 'a', 'b', 'c' };
	static const char inner[] = { 'a', 'b', '\0', 'c' };
	static const char last[] = { 'a', 'b', 'c', '\0' };
	char dst[8] = "kept";

	EXPECT_EQ(span_to_str(dst, sizeof(dst), first, 4), -EINVAL);
	EXPECT_EQ(span_to_str(dst, sizeof(dst), inner, 4), -EINVAL);
	EXPECT_EQ(span_to_str(dst, sizeof(dst), last, 4), -EINVAL);
	EXPECT_STREQ(dst, "kept");
	ASSERT_EQ(span_to_str(dst, sizeof(dst), last, 3), 0);
	EXPECT_STREQ(dst, "abc");
}

static void span_to_str_wants_room_for_the_terminator(void)
{
	char *bytes = span("abcd", 4);
	char dst[8] = "kept";

	EXPECT_EQ(span_to_str(dst, 4, bytes, 4), -E2BIG);
	EXPECT_EQ(span_to_str(dst, 0, bytes, 0), -E2BIG);
	EXPECT_STREQ(dst, "kept");
	ASSERT_EQ(span_to_str(dst, 5, bytes, 4), 0);
	EXPECT_STREQ(dst, "abcd");
	xfree(bytes, 4);
}

/* As a reader of a whole file leaves it: len bytes and room for one more. */
static void span_to_str_takes_a_buffer_in_place(void)
{
	char text[5] = { 'a', 'b', 'c', 'd', 'x' };
	char cut[5] = { 'a', '\0', 'c', 'd', '\0' };

	ASSERT_EQ(span_to_str(text, sizeof(text), text, 4), 0);
	EXPECT_STREQ(text, "abcd");
	EXPECT_EQ(span_to_str(cut, sizeof(cut), cut, 4), -EINVAL);
	EXPECT_EQ(span_to_str(text, 4, text, 4), -E2BIG);
}

static void nocase_prefix_takes_a_letter_in_either_case(void)
{
	const char *p = "BEARER realm=\"x\"";

	EXPECT_UEQ(str_has_prefix_nocase("Location: /v2/", "location:"), 9);
	EXPECT_UEQ(str_has_prefix_nocase("LOCATION:", "Location:"), 9);
	EXPECT_UEQ(str_has_prefix_nocase("Locatio", "Location:"), 0);
	EXPECT_UEQ(str_has_prefix_nocase("Location;", "Location:"), 0);
	EXPECT_UEQ(str_has_prefix_nocase("", "Location:"), 0);
	EXPECT_FALSE(str_skip_prefix_nocase(&p, "Basic"));
	EXPECT_STREQ(p, "BEARER realm=\"x\"");
	EXPECT_TRUE(str_skip_prefix_nocase(&p, "Bearer"));
	EXPECT_STREQ(p, " realm=\"x\"");
}

static void str_after_prefix_gives_the_rest(void)
{
	const char *path = "/etc/shirudo/keys", *dir = "/etc/shirudo";

	EXPECT_TRUE(str_after_prefix(path, dir) == path + 12);
	EXPECT_STREQ(str_after_prefix(dir, dir), "");
	EXPECT_FALSE(str_after_prefix(dir, path));
	EXPECT_FALSE(str_after_prefix("/etc/shirudp/keys", dir));
	EXPECT_FALSE(str_after_prefix("/ETC/shirudo", dir));
	EXPECT_FALSE(str_after_prefix("", dir));
}

static void every_string_starts_with_the_empty_one(void)
{
	const char *s = "x", *none = "";

	EXPECT_TRUE(str_after_prefix(s, none) == s);
	EXPECT_TRUE(str_after_prefix(none, none) == none);
	EXPECT_TRUE(str_after_prefix_nocase(s, none) == s);
}

static void str_after_prefix_nocase_takes_either_case(void)
{
	const char *name = "ABCDEF01.der", *hex = "abcdef01";

	EXPECT_TRUE(str_after_prefix_nocase(name, hex) == name + 8);
	EXPECT_FALSE(str_after_prefix(name, hex));
	EXPECT_FALSE(str_after_prefix_nocase("ABCDEF0", hex));
	EXPECT_FALSE(str_after_prefix_nocase("ABCDEF02.der", hex));
}

static void span_equals_str_wants_the_whole_string(void)
{
	const char *arg = "--name=value", *name = "--name";
	char *exact = span("json", 4);

	EXPECT_TRUE(span_equals_str(arg, 6, name));
	EXPECT_FALSE(span_equals_str(arg, 5, name));
	EXPECT_FALSE(span_equals_str(arg, 7, name));
	EXPECT_FALSE(span_equals_str(arg, 6, "--nome"));
	EXPECT_FALSE(span_equals_str(arg, 6, "--NAME"));
	EXPECT_TRUE(span_equals_str(arg, 0, ""));
	EXPECT_FALSE(span_equals_str(arg, 0, name));
	EXPECT_TRUE(span_equals_str(exact, 4, "json"));
	EXPECT_FALSE(span_equals_str(exact, 4, "jsonl"));
	EXPECT_FALSE(span_equals_str(exact, 4, "jso"));
	xfree(exact, 4);
}

static void span_prefix_reads_no_more_than_the_span(void)
{
	char *line = span("retry-after: 3", 14), *cut = span("Retry-Afte", 10);
	char *exact = span("RETRY-AFTER:", 12);

	EXPECT_UEQ(span_has_prefix_nocase(line, 14, "Retry-After:"), 12);
	EXPECT_UEQ(span_has_prefix_nocase(line, 12, "Retry-After:"), 12);
	EXPECT_UEQ(span_has_prefix_nocase(line, 11, "Retry-After:"), 0);
	EXPECT_UEQ(span_has_prefix_nocase(line, 14, "Retry-Later:"), 0);
	EXPECT_UEQ(span_has_prefix_nocase(cut, 10, "Retry-After:"), 0);
	EXPECT_UEQ(span_has_prefix_nocase(cut, 0, "Retry-After:"), 0);
	EXPECT_UEQ(span_has_prefix_nocase(exact, 12, "Retry-After:"), 12);
	xfree(line, 14);
	xfree(cut, 10);
	xfree(exact, 12);
}

/* The tokens of the len bytes at text, each in brackets. */
static const char *tokens_of(const char *text, size_t len, const char *delims)
{
	static char out[64];
	char *buf = span(text, len);
	const char *tok;
	size_t n, at = 0;

	for_each_token(tok, n, buf, len, delims) {
		ASSERT_TRUE(tok >= buf && n <= len &&
			    (size_t)(tok - buf) <= len - n);
		ASSERT_TRUE(at + n + 3 <= sizeof(out));
		out[at++] = '[';
		memcpy(out + at, tok, n);
		at += n;
		out[at++] = ']';
	}
	out[at] = '\0';
	xfree(buf, len ? len : 1);
	return out;
}

static void tokens_are_the_runs_between_delimiters(void)
{
	EXPECT_STREQ(tokens_of("a,bc,d", 6, ","), "[a][bc][d]");
	EXPECT_STREQ(tokens_of("abc", 3, ","), "[abc]");
	EXPECT_STREQ(tokens_of("a b\tc\n", 6, " \t\n"), "[a][b][c]");
	EXPECT_STREQ(tokens_of("/var//lib/", 10, "/"), "[var][lib]");
}

static void no_token_is_empty(void)
{
	EXPECT_STREQ(tokens_of("", 0, ","), "");
	EXPECT_STREQ(tokens_of(",", 1, ","), "");
	EXPECT_STREQ(tokens_of(",,,", 3, ","), "");
	EXPECT_STREQ(tokens_of(",,a,,", 5, ","), "[a]");
	EXPECT_STREQ(tokens_of("\n\nx\n\ny\n", 7, "\n"), "[x][y]");
}

static void tokens_stop_at_the_length_not_at_a_nul(void)
{
	const char *tok;
	size_t n, count = 0;

	EXPECT_STREQ(tokens_of("a,b,c", 3, ","), "[a][b]");
	EXPECT_STREQ(tokens_of("a,b,c", 4, ","), "[a][b]");
	for_each_token(tok, n, "a\0b\nc", 5, "\n") {
		if (!count++) {
			EXPECT_UEQ(n, 3);
			EXPECT_MEMEQ(tok, "a\0b", 3);
		} else {
			EXPECT_UEQ(n, 1);
			EXPECT_TRUE(*tok == 'c');
		}
	}
	EXPECT_UEQ(count, 2);
	EXPECT_STREQ(tokens_of("abc", 3, ""), "[abc]");
}

static void token_may_be_ended_in_its_own_buffer(void)
{
	char words[] = "-O2  -g\t-Wall", *tok, *seen[4];
	size_t n, count = 0;

	for_each_token(tok, n, words, strlen(words), " \t") {
		tok[n] = '\0';
		ASSERT_TRUE(count < ARRAY_SIZE(seen));
		seen[count++] = tok;
	}
	ASSERT_EQ(count, 3);
	EXPECT_STREQ(seen[0], "-O2");
	EXPECT_STREQ(seen[1], "-g");
	EXPECT_STREQ(seen[2], "-Wall");
}

static void token_walks_nest(void)
{
	const char *text = "a=1,b=2\nc=3\n", *line, *pair;
	size_t line_len, pair_len, pairs = 0, lines = 0;

	for_each_token(line, line_len, text, strlen(text), "\n") {
		lines++;
		for_each_token(pair, pair_len, line, line_len, ",") {
			EXPECT_UEQ(pair_len, 3);
			EXPECT_TRUE(pair[1] == '=');
			pairs++;
		}
	}
	EXPECT_UEQ(lines, 2);
	EXPECT_UEQ(pairs, 3);
}

static void token_next_takes_any_cursor(void)
{
	size_t pos = 2, start = 9;

	EXPECT_UEQ(token_next("ab,cd", 5, ",", &pos, &start), 2);
	EXPECT_UEQ(start, 3);
	EXPECT_UEQ(pos, 5);
	EXPECT_UEQ(token_next("ab,cd", 5, ",", &pos, &start), 0);
	EXPECT_UEQ(pos, 5);
	pos = 9;
	EXPECT_UEQ(token_next("ab,cd", 5, ",", &pos, &start), 0);
	EXPECT_UEQ(pos, 5);
	pos = 0;
	EXPECT_UEQ(token_next("ab,cd", 5, ",", &pos, &start), 2);
	EXPECT_UEQ(start, 0);
	EXPECT_UEQ(pos, 3);
}

static void str_equals_nocase_wants_the_whole_string(void)
{
	EXPECT_TRUE(str_equals_nocase("Content-Type", "content-type"));
	EXPECT_TRUE(str_equals_nocase("https", "HTTPS"));
	EXPECT_TRUE(str_equals_nocase("", ""));
	EXPECT_FALSE(str_equals_nocase("https", "http"));
	EXPECT_FALSE(str_equals_nocase("http", "https"));
	EXPECT_FALSE(str_equals_nocase("host", "h0st"));
	EXPECT_FALSE(str_equals_nocase("", "x"));
}

static void span_until_stops_at_a_byte_of_the_set(void)
{
	char *line = span("text/html; q=1\r\n", 16), *plain = span("abc", 3);

	EXPECT_UEQ(span_until(line, 16, " ;\r\n"), 9);
	EXPECT_UEQ(span_until(line, 16, "\r\n"), 14);
	EXPECT_UEQ(span_until(line, 9, ";"), 9);
	EXPECT_UEQ(span_until(line, 5, "/"), 4);
	EXPECT_UEQ(span_until(line, 4, "/"), 4);
	EXPECT_UEQ(span_until(line, 16, "t"), 0);
	EXPECT_UEQ(span_until(plain, 3, "="), 3);
	EXPECT_UEQ(span_until(plain, 3, ""), 3);
	EXPECT_UEQ(span_until(plain, 0, "a"), 0);
	EXPECT_UEQ(span_until("a\0b=c", 5, "="), 3);
	xfree(line, 16);
	xfree(plain, 3);
}

static void span_find_reads_the_span_alone(void)
{
	char *doc = span("{\"token\":\"t\"}", 13), *found;
	const char *path = "a/../b", *at;

	found = span_find(doc, 13, "\"token\"");
	EXPECT_TRUE(found == doc + 1);
	EXPECT_TRUE(span_find(doc, 13, "}") == doc + 12);
	EXPECT_FALSE(span_find(doc, 12, "}"));
	EXPECT_FALSE(span_find(doc, 7, "\"token\""));
	EXPECT_FALSE(span_find(doc, 13, "\"Token\""));
	EXPECT_FALSE(span_find(doc, 0, "t"));
	EXPECT_TRUE(span_find(doc, 13, "") == doc);
	EXPECT_TRUE(span_find(doc, 0, "") == doc);
	at = span_find(path, strlen(path), "..");
	EXPECT_TRUE(at == path + 2);
	EXPECT_TRUE(span_find("a\0b..c", 6, ".."));
	xfree(doc, 13);
}

static void str_contains_stops_at_the_terminator(void)
{
	EXPECT_TRUE(str_contains("repo//name", "//"));
	EXPECT_TRUE(str_contains("a/..", ".."));
	EXPECT_TRUE(str_contains("..", ".."));
	EXPECT_TRUE(str_contains("x", ""));
	EXPECT_TRUE(str_contains("", ""));
	EXPECT_FALSE(str_contains("a/./b", ".."));
	EXPECT_FALSE(str_contains(".", ".."));
	EXPECT_FALSE(str_contains("", ".."));
	EXPECT_FALSE(str_contains("a\0b..c", ".."));
}

static const struct unit_case cases[] = {
	UNIT_CASE(digits_counts_leading_digits),
	UNIT_CASE(decimal_fills_its_span),
	UNIT_CASE(nothing_past_the_span_is_read),
	UNIT_CASE(sign_blank_or_prefix_is_no_number),
	UNIT_CASE(number_past_its_bound_is_out_of_range),
	UNIT_CASE(malformed_number_however_long),
	UNIT_CASE(hex_takes_either_case_and_no_prefix),
	UNIT_CASE(signed_number_spans_the_whole_range),
	UNIT_CASE(signed_number_keeps_bounds_and_form),
	UNIT_CASE(strscpy_copies_what_fits_whole),
	UNIT_CASE(strscpy_cuts_and_says_so),
	UNIT_CASE(strscpy_literal_copies_with_its_terminator),
	UNIT_CASE(strsprintf_writes_what_fits_whole),
	UNIT_CASE(strsprintf_leaves_nothing_when_cut),
	UNIT_CASE(xasprintf_allocates_the_size_needed),
	UNIT_CASE(dns_name_is_ldh_labels_and_no_address),
	UNIT_CASE(utf8_width_takes_well_formed_characters_only),
	UNIT_CASE(utf8_width_takes_the_scalar_values_alone),
	UNIT_CASE(text_sanitize_replaces_controls_and_stray_bytes),
	UNIT_CASE(text_sanitize_replaces_hidden_formats),
	UNIT_CASE(text_sanitize_passes_all_but_the_controls),
	UNIT_CASE(memzero_explicit_clears_its_span_only),
	UNIT_CASE(memneq_explicit_tells_every_bit_apart),
	UNIT_CASE(name_has_suffix_wants_a_stem),
	UNIT_CASE(name_glob_match_takes_stars_and_question_marks),
	UNIT_CASE(name_glob_match_leaves_out_dot_and_dotdot),
	UNIT_CASE(name_glob_match_reads_len_bytes),
	UNIT_CASE(str_has_prefix_gives_its_length),
	UNIT_CASE(str_skip_prefix_moves_only_on_a_match),
	UNIT_CASE(span_equals_wants_the_whole_literal),
	UNIT_CASE(span_to_str_copies_and_terminates),
	UNIT_CASE(span_to_str_refuses_a_nul_among_the_bytes),
	UNIT_CASE(span_to_str_wants_room_for_the_terminator),
	UNIT_CASE(span_to_str_takes_a_buffer_in_place),
	UNIT_CASE(nocase_prefix_takes_a_letter_in_either_case),
	UNIT_CASE(str_after_prefix_gives_the_rest),
	UNIT_CASE(every_string_starts_with_the_empty_one),
	UNIT_CASE(str_after_prefix_nocase_takes_either_case),
	UNIT_CASE(span_equals_str_wants_the_whole_string),
	UNIT_CASE(span_prefix_reads_no_more_than_the_span),
	UNIT_CASE(tokens_are_the_runs_between_delimiters),
	UNIT_CASE(no_token_is_empty),
	UNIT_CASE(tokens_stop_at_the_length_not_at_a_nul),
	UNIT_CASE(token_may_be_ended_in_its_own_buffer),
	UNIT_CASE(token_walks_nest),
	UNIT_CASE(token_next_takes_any_cursor),
	UNIT_CASE(str_equals_nocase_wants_the_whole_string),
	UNIT_CASE(span_until_stops_at_a_byte_of_the_set),
	UNIT_CASE(span_find_reads_the_span_alone),
	UNIT_CASE(str_contains_stops_at_the_terminator),
	{}
};

UNIT_SUITE(string, cases);
