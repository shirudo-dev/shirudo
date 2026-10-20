#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1133 -- labelling at creation (bpf/seal.c inode_init_security): an
# inode created under a labelled directory the seal has seen is born
# with the label, whoever creates it, and is sealed from that instant.
# Per-run probes live directly under /var/lib/shirudo and stay there:
# sealed inodes cannot be removed by the test. Non-destructive otherwise.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

LABEL=94442b45cfcdc59aabc2a91364ed2ae129418e05a5c1985231b9c032e673f469
LOCKS=/var/lib/shirudo/locks.t1133.$(cat /proc/sys/kernel/random/uuid)
[ -e /run/shirudo/bpffs/seal_inode_init_security_link ] ||
	test_skip_all "the seal does not label at creation on this target"

label_of() {
	python3 -c '
import errno, os, sys
try:
    print(os.getxattr(sys.argv[1], "security.bpf.shirudo",
                      follow_symlinks=False).decode())
except OSError as e:
    print("unsupported" if e.errno == errno.EOPNOTSUPP else "none")' "$1"
}

RUN_LABEL=$(label_of /run/shirudo)
if [ "$RUN_LABEL" = unsupported ]; then
	echo "# SKIP /run does not support security xattrs"
else
	test_expect_success 'the run directory carries the label' '
		[ "$(label_of /run/shirudo)" = "$LABEL" ]
	'
fi

# Opening the directory records its label for inode_init_security.
# The write open is expected to fail after inode creation; test it in
# a child shell so set -e does not skip the xattr assertion.
test_expect_success 'a file root creates under a sealed directory is born labelled' '
	ls /var/lib/shirudo >/dev/null &&
	mkdir -p "$LOCKS" &&
	ls "$LOCKS" >/dev/null &&
	if ( : > "$LOCKS/t1133.probe" ) 2>/dev/null; then
		:
	fi
	label=$(label_of "$LOCKS/t1133.probe")
	[ -e "$LOCKS/t1133.probe" ] && [ "$label" = "$LABEL" ] || {
		echo "probe label: $label; directory label: $(label_of "$LOCKS")" >&2
		false
	}
'

test_expect_success 'and is sealed from that instant: no write, unlink or rename' '
	! sh -c "echo x > \"$LOCKS/t1133.probe\"" 2>/dev/null &&
	! rm "$LOCKS/t1133.probe" 2>/dev/null &&
	! mv "$LOCKS/t1133.probe" "$LOCKS/t1133.moved" 2>/dev/null &&
	[ -e "$LOCKS/t1133.probe" ] &&
	[ ! -s "$LOCKS/t1133.probe" ]
'

test_expect_success 'a new directory is marked in turn: its child needs no reopen' '
	mkdir "$LOCKS/t1133.dir" &&
	[ "$(label_of "$LOCKS/t1133.dir")" = "$LABEL" ] &&
	mkfifo "$LOCKS/t1133.dir/child" &&
	[ "$(label_of "$LOCKS/t1133.dir/child")" = "$LABEL" ]
'

test_expect_success 'a symlink is born labelled as well' '
	ln -s t1133.probe "$LOCKS/t1133.link" &&
	[ "$(label_of "$LOCKS/t1133.link")" = "$LABEL" ]
'

test_expect_success 'an O_TMPFILE under the tree cannot be opened for writing' '
	! python3 -c "import os,sys; os.open(sys.argv[1], os.O_TMPFILE | os.O_WRONLY, 0o600)" \
	    "$LOCKS" 2>/dev/null
'

test_expect_success 'a file created outside the tree stays unlabelled' '
	f=$(mktemp /root/t1133.XXXXXX) &&
	[ "$(label_of "$f")" = none ] &&
	rm -f "$f"
'

test_done
