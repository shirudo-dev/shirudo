#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/is-main-head.sh -- tell whether the commit a run was
# started for is still the head of main: writes current=true or
# current=false to $GITHUB_OUTPUT.
#
#   .github/scripts/is-main-head.sh
#
# The commit is SHA, the repository GITHUB_REPOSITORY, and gh reads the
# token from GH_TOKEN.

set -eu

head=$(gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/main" --jq .object.sha)
if [ "$head" = "$SHA" ]; then
	echo "current=true" >>"$GITHUB_OUTPUT"
else
	echo "::notice::main moved on from $SHA to $head, whose run takes over"
	echo "current=false" >>"$GITHUB_OUTPUT"
fi
