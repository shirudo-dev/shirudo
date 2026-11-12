// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <string.h>

#include <shirudo/string.h>

#include "curl.h"

void curl_slist_free_sensitive(struct curl_slist *headers)
{
	struct curl_slist *entry, *next;

	for (entry = headers; entry; entry = next) {
		next = entry->next;
		if (entry->data)
			memzero_explicit(entry->data, strlen(entry->data) + 1);
	}
	curl_slist_free_all(headers);
}
