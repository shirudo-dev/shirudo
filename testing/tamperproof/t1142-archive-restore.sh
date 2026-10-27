#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1142 -- an artifact renamed into the archive after the register was
# bound. Rename brings an inode into a sealed directory without creating
# one, so root can place any operator-signed .upatch there; a re-run of
# init used to restore it, attached and pinned, without a register event,
# since this boot's init event was already on record. init must now
# refuse the restore and leave the artifact unloaded, also when the
# state directory is hidden behind a mount that carries no eventlog, and
# must not take a root file system for the initramfs because root wrote
# /etc/initrd-release. Cleaned up through the artifact's own unload
# directive, which removes the archive copy.

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
	rm -rf "$STAGE"
	"$SHIRUDO_BIN" init >/dev/null 2>&1 || true
}
trap restore EXIT

chain() {
	"$SHIRUDO_BIN" status --json 2>/dev/null |
		python3 -c "import json,sys; print(json.load(sys.stdin)[\"tpm\"][\"chain\"])"
}
CHAIN=$(chain)

test_expect_success 'root can rename a signed artifact into the archive' '
	mkdir -p "$STAGE" && cp "$LOAD" "$STAGE/$NAME.upatch" &&
	mv "$STAGE/$NAME.upatch" "$ARCHIVE/$NAME.upatch" &&
	[ -e "$ARCHIVE/$NAME.upatch" ]
'

test_expect_success 'a re-run of init refuses to restore it unmeasured' '
	! "$SHIRUDO_BIN" init >/dev/null 2>"$STAGE/init.err" &&
	grep -q "archived but not loaded after the register was bound" \
		"$STAGE/init.err" &&
	[ ! -e "$PIN" ] &&
	[ "$(chain)" = "$CHAIN" ]
'

test_expect_success 'the unload directive removes the planted copy and init completes again' '
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck --report=- 2>/dev/null |
		report_field category | grep -qx already_unloaded &&
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
