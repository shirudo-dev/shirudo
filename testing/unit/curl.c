// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include "curl.h"
#include "curl_test.h"
#include "unit.h"

static struct curl_slist *freed_headers;

void __wrap_curl_slist_free_all(struct curl_slist *headers)
{
	freed_headers = headers;
}

static void sensitive_header_is_scrubbed_before_free(void)
{
	static const char header[] = "Authorization: Bearer secret";
	static const __u8 zero[sizeof(header)];
	struct curl_slist *headers;
	char *data;

	headers = curl_slist_append(NULL, header);
	ASSERT_TRUE(headers);
	data = headers->data;
	curl_slist_free_sensitive(headers);
	ASSERT_TRUE(freed_headers);
	EXPECT_MEMEQ(data, zero, sizeof(header));
	__real_curl_slist_free_all(freed_headers);
	freed_headers = NULL;
}

static const struct unit_case cases[] = {
	UNIT_CASE(sensitive_header_is_scrubbed_before_free),
	{}
};

UNIT_SUITE(curl, cases);
