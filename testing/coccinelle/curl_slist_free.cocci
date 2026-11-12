// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// curl_slist_append() copies header contents into heap storage. Freeing a
// list directly can leave authorization headers in freed allocator memory.

virtual report

@r@
expression E;
position p;
@@
curl_slist_free_all@p(E)

@script:python depends on report@
p << r.p;
@@
if p[0].file != "util/curl.c":
    coccilib.report.print_report(p[0], "free curl header lists with curl_slist_free_sensitive()")
