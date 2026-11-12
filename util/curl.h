/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * libcurl memory helpers.
 */

#ifndef SHIRUDO_CURL_H
#define SHIRUDO_CURL_H

#include <curl/curl.h>

/* Scrub copied headers before libcurl frees their list. */
void curl_slist_free_sensitive(struct curl_slist *headers);

#endif /* SHIRUDO_CURL_H */
