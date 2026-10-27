#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1142 -- an artifact brought into the archive after the register was
# bound. Rename brings an inode into a sealed directory without creating
# one, so root used to place any operator-signed .upatch there and a
# re-run of init restored it, attached and pinned, without a register
# event. The seal now refuses the rename; one that slips in while the
# directory's mark is evicted carries no label, and init leaves it alone
# instead of labelling, following or restoring it. The restore also
# must not take a state directory hidden behind a mount that carries no
# eventlog for the real one, nor a root file system for the initramfs
# because root wrote /etc/initrd-release.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-scope-kprobe
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
ARCHIVE=/var/lib/shirudo/upatches
STAGE=/var/lib/t1142-stage
PIN="/run/shirudo/bpffs/upatches/$NAME/link"
CERT=/etc/shirudo/keys/cert.der
[ -s "$LOAD" ] && [ -s "$UNLOAD" ] || test_skip_all "missing scope fixtures"
[ ! -e "$PIN" ] || test_skip_all "$NAME is loaded"
[ ! -e /etc/initrd-release ] || test_skip_all "running in an initrd"

# Under the library's errexit a failing step would end the cleanup.
restore() {
	! mountpoint -q /var/lib/shirudo || umount /var/lib/shirudo || true
	! mountpoint -q "$STAGE/shadow" || umount "$STAGE/shadow" || true
	rm -f /etc/initrd-release
	[ ! -e "$STAGE/cert-planted" ] || rm -f "$CERT" || true
	rmdir -p /sysroot/var/lib/shirudo 2>/dev/null || true
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 || true
	rm -f "$ARCHIVE/$NAME.upatch"
	rm -rf "$STAGE"
	"$SHIRUDO_BIN" init >/dev/null 2>&1 || true
}
trap restore EXIT

chain() {
	"$SHIRUDO_BIN" status --json 2>/dev/null |
		python3 -c "import json,sys; print(json.load(sys.stdin)[\"tpm\"][\"chain\"])"
}
CHAIN=$(chain)

counter() {
	"$SHIRUDO_BIN" status --json 2>/dev/null |
		python3 -c "import json,sys; print(json.load(sys.stdin)[\"tamper_attempts\"][\"counters\"][\"SealEntry\"])"
}

# Rename while the directory's mark is evicted, the gap the seal keeps
# (residual risk 15); the entry comes in unlabelled.
plant() {
	i=0
	while [ "$i" -lt 8 ]; do
		sync && echo 2 >/proc/sys/vm/drop_caches &&
			mv "$1" "$2" 2>/dev/null && return 0
		i=$((i + 1))
	done
	return 1
}

labelled() {
	python3 -c "import os,sys
try:
    os.getxattr(sys.argv[1], \"security.bpf.shirudo\", follow_symlinks=False)
except OSError:
    sys.exit(1)" "$1"
}

test_expect_success 'root cannot rename a signed artifact into the archive' '
	before=$(counter) &&
	mkdir -p "$STAGE" && cp "$LOAD" "$STAGE/$NAME.upatch" &&
	! mv "$STAGE/$NAME.upatch" "$ARCHIVE/$NAME.upatch" 2>/dev/null &&
	[ ! -e "$ARCHIVE/$NAME.upatch" ] &&
	[ "$(counter)" -gt "$before" ]
'

test_expect_success 'one that slips in while the mark is evicted is ignored by init' '
	plant "$STAGE/$NAME.upatch" "$ARCHIVE/$NAME.upatch" &&
	! labelled "$ARCHIVE/$NAME.upatch" &&
	"$SHIRUDO_BIN" init >/dev/null 2>"$STAGE/init.err" &&
	grep -q "$NAME.upatch is not shirudo.s own (foreign entry); ignored" \
		"$STAGE/init.err" &&
	[ ! -e "$PIN" ] &&
	! labelled "$ARCHIVE/$NAME.upatch" &&
	[ "$(chain)" = "$CHAIN" ]
'

test_expect_success 'the foreign entry is root'"'"'s to remove' '
	rm "$ARCHIVE/$NAME.upatch" &&
	[ ! -e "$ARCHIVE/$NAME.upatch" ] &&
	"$SHIRUDO_BIN" init >/dev/null 2>&1 &&
	[ "$(chain)" = "$CHAIN" ]
'

# A copy of the state less its eventlog, bound over the real one: the
# register says the restore happened whatever the log says.
test_expect_success 'a state directory hidden behind a mount without its eventlog restores nothing' '
	mkdir -p "$STAGE/shadow" && mount -t tmpfs tmpfs "$STAGE/shadow" &&
	cp -r --preserve=mode,timestamps /var/lib/shirudo/. "$STAGE/shadow/" &&
	rm -f "$STAGE/shadow/eventlog" &&
	cp "$LOAD" "$STAGE/shadow/upatches/$NAME.upatch" &&
	mount --bind "$STAGE/shadow" /var/lib/shirudo &&
	rc=0; "$SHIRUDO_BIN" init >/dev/null 2>"$STAGE/shadow.err" || rc=$?;
	umount /var/lib/shirudo &&
	[ "$rc" != 0 ] &&
	grep -q "archived but not loaded after the register was bound" \
		"$STAGE/shadow.err" &&
	[ ! -e "$PIN" ] &&
	[ "$(chain)" = "$CHAIN" ]
'

test_expect_success 'a root file system is not an initramfs because of /etc/initrd-release' '
	if [ ! -e "$CERT" ]; then
		mkdir -p "$(dirname "$CERT")" &&
		cp /run/shirudo/runtime/keys/cert.der "$CERT" &&
		touch "$STAGE/cert-planted"
	fi &&
	mkdir -p /sysroot/var/lib/shirudo && touch /etc/initrd-release &&
	rc=0; "$SHIRUDO_BIN" init >/dev/null 2>"$STAGE/initrd.err" || rc=$?;
	rm -f /etc/initrd-release &&
	[ "$rc" != 0 ] &&
	grep -q "not an initramfs" "$STAGE/initrd.err" &&
	! mountpoint -q /var/lib/shirudo &&
	[ "$(chain)" = "$CHAIN" ]
'

test_done
