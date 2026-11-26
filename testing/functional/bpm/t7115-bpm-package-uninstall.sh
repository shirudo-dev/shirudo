#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

WORK=$(mktemp -d)
PKG=uninstall-fixture
NAME=shirudo-test-lifecycle
VERSION=1.0.0
ARCHIVE=$PKG-$VERSION
TREE=$WORK/$ARCHIVE
REPO=$WORK/registry/test/$PKG
STORE=/var/lib/shirudo/bpm/packages/$PKG
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

test_expect_success 'install records the version and attaches its signed upatch' '
	"$SHIRUDO_BIN" bpm install "oci://127.0.0.1:5443/test/$PKG:$VERSION" &&
	test -e "$PIN" &&
	test -f "$STORE/$ARCHIVE.bee" &&
	"$SHIRUDO_BIN" bpm list | grep -q "$PKG"
'

# Root binds another directory over the directives, or over the package,
# in a mount namespace of its own. Uninstall then finds no directive to
# apply and must not go on to delete what the bind shows instead.
RUNTIME=$(runtime_binary)
bound_uninstall() {
	unshare -m sh -c "mount --bind \"$1\" \"$2\" &&
		! \"$RUNTIME\" bpm uninstall \"$PKG\"" >"$WORK/out" 2>&1
}
still_installed() {
	test -e "$PIN" &&
	test -e /run/shirudo/bpffs/lsm_link &&
	test -s "/var/lib/shirudo/upatches/$NAME.upatch" &&
	test -s "$STORE/$VERSION/upatches/$NAME.unload.upatch" &&
	test -f "$STORE/$ARCHIVE.bee" &&
	"$SHIRUDO_BIN" bpm list | grep -q "$PKG"
}

test_expect_success 'uninstall refuses the private bpffs bound over the directives' '
	bound_uninstall /run/shirudo/bpffs "$STORE/$VERSION/upatches" &&
	still_installed
'

test_expect_success 'and bound over the package directory' '
	bound_uninstall /run/shirudo/bpffs "$STORE" &&
	still_installed
'

test_expect_success 'a sealed directory bound over the directives is no empty package' '
	bound_uninstall /var/lib/shirudo/upatches "$STORE/$VERSION/upatches" &&
	still_installed
'

test_expect_success 'uninstall detaches and removes the package, archive and state' '
	"$SHIRUDO_BIN" bpm uninstall "$PKG" &&
	test ! -e "$PIN" &&
	test ! -e "$STORE" &&
	"$SHIRUDO_BIN" bpm list >"$WORK/list" &&
	! grep -q "$PKG" "$WORK/list"
'

test_done
