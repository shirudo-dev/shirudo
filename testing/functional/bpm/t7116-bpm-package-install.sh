#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7116 -- bpm install works below the state root init recorded, through
# directories it opens once. A directory root binds over one of them is
# not followed: the install stops, and neither the archive nor the
# version lands in what the bind shows, nor is anything loaded from it.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

WORK=$(mktemp -d)
PKG=install-fixture
NAME=shirudo-test-lifecycle
VERSION=1.0.0
ARCHIVE=$PKG-$VERSION
TREE=$WORK/$ARCHIVE
REPO=$WORK/registry/test/$PKG
REF=oci://127.0.0.1:5443/test/$PKG:$VERSION
BPM=/var/lib/shirudo/bpm
STORE=$BPM/packages/$PKG
SEALED=/var/lib/shirudo/upatches
PIN=/run/shirudo/bpffs/upatches/$NAME/link
TREE_SERVER_PID=

cleanup() {
	tree_registry_stop
	rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$TREE/upatches" "$REPO/manifests" "$REPO/blobs"
cp /var/lib/shirudo/keys/cert.der "$TREE/"
cp "$SHIRUDO_TEST_FIXTURES_DIR/$NAME.upatch" \
	"$SHIRUDO_TEST_FIXTURES_DIR/$NAME.unload.upatch" "$TREE/upatches/"
printf '[package]\nname = "%s"\n' "$PKG" >"$TREE/Beefile"
tar --format=ustar -czf "$WORK/package.bee" -C "$WORK" "$ARCHIVE"
digest=sha256:$(sha256sum "$WORK/package.bee" | cut -d' ' -f1)
size=$(wc -c <"$WORK/package.bee")
mv "$WORK/package.bee" "$REPO/blobs/$digest"
cat >"$REPO/manifests/$VERSION" <<EOF
{"schemaVersion":2,"layers":[{"mediaType":"application/vnd.shirudo.bpm.package.v1+gzip",
"digest":"$digest","size":$size}]}
EOF

tree_registry_start "$WORK/registry" "$WORK"
export BPM_OCI_SCHEME=http NO_PROXY=127.0.0.1 no_proxy=127.0.0.1

test_expect_success 'install extracts the version, loads it and keeps the archive' '
	"$SHIRUDO_BIN" bpm install "$REF" &&
	test -e "$PIN" &&
	test -s "$STORE/$VERSION/upatches/$NAME.unload.upatch" &&
	test -f "$STORE/$ARCHIVE.bee" &&
	test ! -e "$BPM/staging/$ARCHIVE.bee" &&
	"$SHIRUDO_BIN" bpm uninstall "$PKG" &&
	test ! -e "$PIN" &&
	test ! -e "$STORE"
'

# The bind is made in a mount namespace of root's own, over a directory
# the first install left behind.
RUNTIME=$(runtime_binary)
bound_install() {
	unshare -m sh -c "mount --bind \"$1\" \"$2\" &&
		! \"$RUNTIME\" bpm install \"$REF\"" >"$WORK/out" 2>&1
}
not_installed() {
	test ! -e "$PIN" &&
	test ! -e "$STORE/$VERSION" &&
	test ! -e "$SEALED/$ARCHIVE.bee" &&
	test ! -e "$SEALED/$PKG" &&
	test -e /run/shirudo/bpffs/lsm_link &&
	"$SHIRUDO_BIN" bpm list >"$WORK/list" &&
	! grep -q "$PKG" "$WORK/list"
}

test_expect_success 'install refuses a sealed directory bound over the staging directory' '
	bound_install "$SEALED" "$BPM/staging" &&
	grep -q "cross-device" "$WORK/out" &&
	not_installed
'

test_expect_success 'and bound over the package store' '
	bound_install "$SEALED" "$BPM/packages" &&
	grep -q "cross-device" "$WORK/out" &&
	not_installed
'

test_expect_success 'and the private bpffs bound over the package store' '
	bound_install /run/shirudo/bpffs "$BPM/packages" &&
	not_installed
'

test_expect_success 'with no bind the install goes through again' '
	"$SHIRUDO_BIN" bpm install "$REF" &&
	test -e "$PIN" &&
	test -f "$STORE/$ARCHIVE.bee" &&
	"$SHIRUDO_BIN" bpm uninstall "$PKG" &&
	test ! -e "$PIN"
'

test_done
