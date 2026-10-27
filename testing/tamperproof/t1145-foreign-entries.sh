#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1145 -- entries root brings into sealed state. A sealed directory
# takes new entries from shirudo alone: a file, directory, symbolic link
# or device root creates there is refused, and so is a rename or hard
# link, which would bring an inode in with its contents. One that slips
# in while the directory's mark is evicted carries no label: shirudo
# never follows it, adopts it or reads it as its own, and a re-run of
# init completes with it in place. Non-destructive.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-scope-kprobe
LOAD="$FIXTURES/$NAME.upatch"
S=/var/lib/shirudo
ARCHIVE=$S/upatches
STAGE=/var/lib/t1145-stage
PIN="/run/shirudo/bpffs/upatches/$NAME/link"
[ -s "$LOAD" ] || test_skip_all "missing scope fixture"
[ ! -e "$PIN" ] || test_skip_all "$NAME is loaded"
[ -d "$ARCHIVE" ] || test_skip_all "no archive at $ARCHIVE"

# Under the library's errexit a failing step would end the cleanup.
restore() {
	rm -f "$ARCHIVE/t1145.upatch" "$ARCHIVE/t1145-link.upatch" \
		"$ARCHIVE/t1145-linked.upatch" "$S/t1145-link" \
		"$S/incoming/t1145-stage" 2>/dev/null || true
	rmdir "$S/t1145-dir" 2>/dev/null || true
	rm -rf "$STAGE"
}
trap restore EXIT

counter() {
	"$SHIRUDO_BIN" status --json 2>/dev/null |
		python3 -c "import json,sys; print(json.load(sys.stdin)[\"tamper_attempts\"][\"counters\"][\"SealEntry\"])"
}

chain() {
	"$SHIRUDO_BIN" status --json 2>/dev/null |
		python3 -c "import json,sys; print(json.load(sys.stdin)[\"tpm\"][\"chain\"])"
}

labelled() {
	python3 -c "import os,sys
try:
    os.getxattr(sys.argv[1], \"security.bpf.shirudo\", follow_symlinks=False)
except OSError:
    sys.exit(1)" "$1"
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

CHAIN=$(chain)

test_expect_success 'root cannot create a file, a directory or a symbolic link in sealed state' '
	before=$(counter) &&
	! touch "$ARCHIVE/t1145.upatch" 2>/dev/null &&
	! mkdir "$S/t1145-dir" 2>/dev/null &&
	! ln -s /tmp "$S/t1145-link" 2>/dev/null &&
	[ ! -e "$ARCHIVE/t1145.upatch" ] && [ ! -e "$S/t1145-dir" ] &&
	[ ! -L "$S/t1145-link" ] &&
	[ "$(counter)" -ge $((before + 3)) ]
'

test_expect_success 'root cannot rename or hard-link content into sealed state' '
	before=$(counter) &&
	mkdir -p "$STAGE" && cp "$LOAD" "$STAGE/t1145.upatch" &&
	! mv "$STAGE/t1145.upatch" "$ARCHIVE/t1145.upatch" 2>/dev/null &&
	! ln "$STAGE/t1145.upatch" "$ARCHIVE/t1145-linked.upatch" 2>/dev/null &&
	[ ! -e "$ARCHIVE/t1145.upatch" ] &&
	[ ! -e "$ARCHIVE/t1145-linked.upatch" ] &&
	[ -s "$STAGE/t1145.upatch" ] &&
	[ "$(counter)" -ge $((before + 2)) ]
'

# The archive entry is a link to a signed artifact root keeps elsewhere:
# init must neither follow it nor label it.
test_expect_success 'a link that slipped in while the mark was evicted is not followed' '
	mkdir -p "$STAGE" && cp "$LOAD" "$STAGE/$NAME.upatch" &&
	ln -s "$STAGE/$NAME.upatch" "$STAGE/t1145-link.upatch" &&
	plant "$STAGE/t1145-link.upatch" "$ARCHIVE/t1145-link.upatch" &&
	[ -L "$ARCHIVE/t1145-link.upatch" ] &&
	"$SHIRUDO_BIN" init >/dev/null 2>"$STAGE/init.err" &&
	grep -q "t1145-link.upatch is not shirudo.s own (foreign entry); ignored" \
		"$STAGE/init.err" &&
	[ ! -e "$PIN" ] &&
	! labelled "$ARCHIVE/t1145-link.upatch" &&
	[ "$(chain)" = "$CHAIN" ] &&
	rm "$ARCHIVE/t1145-link.upatch"
'

test_expect_success 'root cannot plant a link where shirudo stages' '
	[ -d "$S/incoming" ] &&
	! ln -s "$STAGE" "$S/incoming/t1145-stage" 2>/dev/null &&
	[ ! -L "$S/incoming/t1145-stage" ]
'

test_done
