#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/check-sparse.sh -- run sparse over the userspace sources
# the binaries are built from, through make sparse, and fail on any
# warning, above all on a value moved between host order and the __le
# and __be types of <shirudo/types.h> without the kernel byte-order
# helpers used by BPF code.
#
#   .github/scripts/check-sparse.sh
#
# Needs sparse and the build dependencies make needs, OpenSSL 3.5 among
# them; in CI, .github/scripts/vm-toolchain.sh sparse provides both.

set -eu

cd "$(dirname "$0")/../.."
command -v cgcc >/dev/null 2>&1 || {
	printf 'check-sparse: cgcc not found; install sparse\n' >&2
	exit 2
}
exec make sparse
