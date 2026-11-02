#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6111 -- the filesystem seal against root, on scratch files a mounted
# image labels. The label is the same public value on every build; root
# may not set it, but a file system it mounts can present it, so a binary
# that carries it must not become shirudo to the seal. A failure here is
# a bypass of the seal. Non-destructive: the probes open files for write
# without changing them and act on scratch files only.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
for c in python3 mkfs.ext4 debugfs; do
	command -v "$c" >/dev/null 2>&1 || test_skip_all "no $c"
done

STATE=/var/lib/shirudo/eventlog
POLICY=/run/shirudo/runtime/usr/bin/shirudo-policy-probe
[ -e "$STATE" ] || test_skip_all "no labelled state at $STATE"
[ -x "$POLICY" ] || test_skip_all "runtime policy probe is missing"
WORK=$(mktemp -d) || test_skip_all "cannot make a scratch directory"
MNT=$WORK/mnt
trap 'umount "$MNT" 2>/dev/null; rm -rf "$WORK" 2>/dev/null || :' EXIT
SH=$(readlink -f /bin/sh)
PY=$(readlink -f "$(command -v python3)")

python3 -c '
import os, sys
sys.stdout.buffer.write(os.getxattr(sys.argv[1], "security.bpf.shirudo"))
' "$STATE" >"$WORK/label" 2>/dev/null
[ "$(wc -c <"$WORK/label")" = 64 ] ||
	test_skip_all "$STATE does not carry a 64-byte seal label"

# Write the label into an image offline, as a mounted file system presents
# it without any setxattr the seal could refuse.
SEALED="sealed1 sealed2 sealed3 sealed4 sealed5 sealed6 sealed7"
echo scratch >"$WORK/scratch"
{
	echo "write $SH sh"
	echo "write $PY py"
	echo "write $WORK/scratch plain"
	for f in $SEALED; do
		echo "write $WORK/scratch $f"
	done
	for f in sh py $SEALED; do
		echo "ea_set -f $WORK/label /$f security.bpf.shirudo"
	done
} >"$WORK/cmds"
{
	truncate -s 64M "$WORK/img" &&
	mkfs.ext4 -q -F "$WORK/img" &&
	debugfs -w -f "$WORK/cmds" "$WORK/img" &&
	mkdir "$MNT" &&
	mount -o loop "$WORK/img" "$MNT"
} >/dev/null 2>&1 || test_skip_all "cannot build and mount an ext4 image"
python3 -c '
import os, sys
sys.exit(any(len(os.getxattr(f, "security.bpf.shirudo")) != 64
	     for f in sys.argv[1:]))
' "$MNT/sh" "$MNT/py" "$MNT/sealed1" 2>/dev/null ||
	test_skip_all "the image does not present the seal label"

# What the labelled copy of python3 tries, each on a labelled file of its own
# so that one success cannot make the next attempt look denied.
cat >"$WORK/ops.py" <<'PYEOF'
import os
import sys

w = sys.argv[1]
ops = [
    ("rename", lambda: os.rename(w + "/sealed1", w + "/moved")),
    ("unlink", lambda: os.unlink(w + "/sealed2")),
    ("setxattr", lambda: os.setxattr(w + "/sealed3", "security.bpf.shirudo.t", b"x")),
    ("removexattr", lambda: os.removexattr(w + "/sealed4", "security.bpf.shirudo")),
]
bad = 0
for name, op in ops:
    try:
        op()
    except OSError:
        continue
    print("the labelled copy was allowed to", name, file=sys.stderr)
    bad = 1
sys.exit(bad)
PYEOF

cat >"$WORK/policy.py" <<'PYEOF'
import errno
import os
import struct
import sys

path, operation = sys.argv[1:]
name = "security.bpf.shirudo.policy"


def value():
    return os.getxattr(path, name)


def denied(call):
    try:
        call()
    except OSError as exc:
        if exc.errno != errno.EACCES:
            raise
    else:
        raise AssertionError("untrusted root changed the policy xattr")


if operation == "add":
    denied(lambda: os.setxattr(path, name, struct.pack("=Q", 1)))
    try:
        value()
    except OSError as exc:
        if exc.errno != errno.ENODATA:
            raise
    else:
        raise AssertionError("policy xattr appeared after denied setxattr")
elif operation == "change-remove":
    assert value() == struct.pack("=Q", 1)
    denied(lambda: os.setxattr(path, name, struct.pack("=Q", 2)))
    denied(lambda: os.removexattr(path, name))
    assert value() == struct.pack("=Q", 1)
elif operation == "verify":
    assert value() == struct.pack("=Q", 3)
else:
    raise AssertionError(operation)
PYEOF

test_expect_success 'control: an unlabelled copy of a shell cannot open a labelled file for write' '
	cp "$SH" "$WORK/ctl" &&
	"$WORK/ctl" -c ":" &&
	! "$WORK/ctl" -c ": >> $STATE" 2>/dev/null
'

test_expect_success 'root cannot put the seal label on a file' '
	! python3 -c "
import os, sys
os.setxattr(sys.argv[1], \"security.bpf.shirudo\", open(sys.argv[2], \"rb\").read())
" "$MNT/plain" "$WORK/label" 2>/dev/null
'

test_expect_success 'only a runtime-authorized task can add, change or remove a policy label' '
	python3 "$WORK/policy.py" "$MNT/plain" add &&
	"$POLICY" set-policy "$MNT/plain" 0x1 &&
	python3 "$WORK/policy.py" "$MNT/plain" change-remove &&
	"$POLICY" set-policy "$MNT/plain" 0x3 &&
	python3 "$WORK/policy.py" "$MNT/plain" verify
'

test_expect_success 'a binary its file system labels cannot open a labelled file for write' '
	"$MNT/sh" -c ":" &&
	! "$MNT/sh" -c ": >> $STATE" 2>/dev/null
'

test_expect_success 'a binary its file system labels cannot rename, unlink or relabel a labelled file' '
	"$MNT/py" "$WORK/ops.py" "$MNT"
'

test_expect_success 'root cannot rename a file over a labelled file' '
	echo replacement >"$MNT/replacement" &&
	! python3 -c "import os, sys; os.rename(sys.argv[1], sys.argv[2])" \
	    "$MNT/replacement" "$MNT/sealed5" 2>/dev/null &&
	[ "$(cat "$MNT/sealed5")" = scratch ]
'

test_expect_success 'root cannot truncate, chmod or chown a labelled file' '
	! python3 -c "import os, sys; os.truncate(sys.argv[1], 0)" \
	    "$MNT/sealed6" 2>/dev/null &&
	[ "$(cat "$MNT/sealed6")" = scratch ] &&
	! chmod 0200 "$MNT/sealed7" 2>/dev/null &&
	! chown 1:1 "$MNT/sealed7" 2>/dev/null
'

test_done
