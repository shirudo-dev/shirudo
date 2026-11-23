#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -eu

if [ -n "${KERNEL_RUN_ID:-}" ]; then
	testing/vm/kernel-artifact.sh run-id >/dev/null
	echo "build=false" >>"$GITHUB_OUTPUT"
	exit 0
fi

base=${BASE_SHA:-}
case "$base" in
''|0000000000000000000000000000000000000000)
	base=HEAD
	;;
*)
	if ! git cat-file -e "$base^{commit}" 2>/dev/null; then
		git fetch --no-tags --depth=1 origin "$base"
	fi
	;;
esac

changed=$(git diff --name-only "$base" HEAD -- testing/kernel \
	.github/scripts/build-test-kernel.sh .github/workflows/build-kernel-packages.yml)
if [ -n "$changed" ]; then
	echo "build=true" >>"$GITHUB_OUTPUT"
else
	echo "build=false" >>"$GITHUB_OUTPUT"
fi
