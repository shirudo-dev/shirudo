#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# testing/container/install-go.sh -- install into /usr/local/go the Go
# release pwru needs to build, newer than the one Ubuntu ships: the
# tarball of go.dev, checked against its SHA-256.

set -eu

GO_VERSION=1.27.4

case $(uname -m) in
x86_64)
	arch=amd64
	sha256=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840
	;;
aarch64)
	arch=arm64
	sha256=3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92
	;;
*)
	echo "install-go.sh: no Go $GO_VERSION for $(uname -m)" >&2
	exit 1
	;;
esac

tarball=/tmp/go.tar.gz
curl -fsSL -o "$tarball" "https://go.dev/dl/go$GO_VERSION.linux-$arch.tar.gz"
echo "$sha256  $tarball" | sha256sum -c - >/dev/null
tar -C /usr/local -xzf "$tarball"
rm -f "$tarball"
