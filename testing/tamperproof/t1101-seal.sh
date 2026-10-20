#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1101 -- filesystem-sealing LSM (bpf/seal.c): a non-shirudo process
# cannot modify a labelled file under /var/lib/shirudo, even as root.
# Non-destructive: the seal denies the tamper, so the file survives.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

CERT=/var/lib/shirudo/keys/cert.der
ARCHIVE=/var/lib/shirudo/upatches/shirudo-test-basic.upatch
FIXTURES=$SHIRUDO_TEST_FIXTURES_DIR
[ -e "$CERT" ] || test_skip_all "no cert at $CERT"
[ -s "$ARCHIVE" ] || test_skip_all "no archived basic upatch"
before=$(sha256sum "$CERT" | cut -d' ' -f1)
archive_before=$(sha256sum "$ARCHIVE" | cut -d' ' -f1)
WORK=$(mktemp -d /root/.t1101.XXXXXX) ||
	test_skip_all "cannot make a scratch directory"
[ "$(stat -c %d "$WORK")" = "$(stat -c %d "$ARCHIVE")" ] || {
	rm -rf "$WORK"
	test_skip_all "no unlabelled scratch directory on the archive filesystem"
}
replacement="$WORK/replacement"
trap 'rm -f "$replacement"; rm -rf "$WORK"' EXIT

test_expect_success 'seal denies a non-shirudo write to a labelled file' '
	! dd if=/dev/zero of=/var/lib/shirudo/keys/cert.der bs=1 count=1 \
	     conv=notrunc 2>/dev/null &&
	[ "$(sha256sum /var/lib/shirudo/keys/cert.der | cut -d" " -f1)" = "$before" ]
'

test_expect_success 'seal denies a non-shirudo setxattr on a labelled file' '
	! python3 -c "import os,sys; os.setxattr(sys.argv[1], \"user.sealprobe\", b\"x\")" \
	    /var/lib/shirudo/keys/cert.der 2>/dev/null
'

test_expect_success 'seal denies changes to an archived upatch' '
	! dd if=/dev/zero of="$ARCHIVE" bs=1 count=1 conv=notrunc 2>/dev/null &&
	! python3 -c "import os,sys; os.setxattr(sys.argv[1], \\"user.sealprobe\\", b\\"x\\")" \
		"$ARCHIVE" 2>/dev/null &&
	! python3 -c "import os,sys; os.removexattr(sys.argv[1], \\"security.bpf.shirudo\\")" \
		"$ARCHIVE" 2>/dev/null &&
	[ "$(sha256sum "$ARCHIVE" | cut -d" " -f1)" = "$archive_before" ]
'
test_expect_success 'seal denies unlink, rename-away, and replacement of an archived upatch' '
	cp "$ARCHIVE" "$replacement" &&
	! rm "$ARCHIVE" 2>/dev/null &&
	! mv "$ARCHIVE" "$WORK/moved.upatch" 2>/dev/null &&
	! python3 -c "import os,sys; os.replace(sys.argv[1],sys.argv[2])" \
		"$replacement" "$ARCHIVE" 2>/dev/null &&
	[ "$(sha256sum "$ARCHIVE" | cut -d" " -f1)" = "$archive_before" ]
'
test_done
