#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0006 -- offline coverage for upatch map type labels and generic-read
# policy. Arena maps must be visible but require a serializer.

cd "$(dirname "$0")/.."
. ./test-lib.sh

H=helper/test-upatch-map-types

test_expect_success 'arena maps render with the arena type name' '
	[ "$("$H" arena-name)" = arena ]
'

test_expect_success 'arena maps are skipped when no serializer is pinned' '
	"$H" arena-skip | grep -q "serializer"
'

test_expect_success 'plain array maps are still generic-readable' '
	[ -z "$("$H" array-skip)" ]
'

test_expect_success 'existing skipped map type names remain stable' '
	[ "$("$H" ringbuf-name)" = ringbuf ]
'

test_done
