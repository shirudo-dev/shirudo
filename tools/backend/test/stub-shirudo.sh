#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# test/stub-shirudo.sh -- stand in for `shirudo bpm tree show` in the
# tests of jobs/tree-ingest. It fetches and verifies nothing: it names
# its arguments on standard error, prints the file STUB_SHOW_OUTPUT
# names and exits with STUB_SHOW_STATUS, 0 by default.

set -eu

printf 'stub-shirudo: %s\n' "$*" >&2
cat "$STUB_SHOW_OUTPUT"
exit "${STUB_SHOW_STATUS:-0}"
