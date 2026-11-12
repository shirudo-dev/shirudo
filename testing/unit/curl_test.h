/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_TEST_CURL_H
#define SHIRUDO_TEST_CURL_H

#include <curl/curl.h>

void __wrap_curl_slist_free_all(struct curl_slist *headers);
void __real_curl_slist_free_all(struct curl_slist *headers);

#endif /* SHIRUDO_TEST_CURL_H */
