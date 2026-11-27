#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Install the pinned Kani release for CI. Run outside the checkout so
# its vendored cargo configuration does not redirect this installation.

set -eu
root=$(git rev-parse --show-toplevel)
version=$(cat "$root/testing/proofs/kani/version")
cd "$HOME"
cargo install --locked kani-verifier --version "$version"
cargo kani setup
