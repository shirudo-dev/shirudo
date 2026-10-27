#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1144 -- the attach metadata, the name and the unload target are
# signed. Root used to edit the symbol a signed kprobe attached at, or
# the name and expected payload of a signed unload directive, and load
# the result as the trusted task: the kernel verified the loader, the
# edited bytes were outside the signature. Now the kernel refuses an
# artifact whose signed sections were touched, and the target refuses
# one whose header disagrees with them. Non-destructive: nothing loads
# and the basic fixture stays pinned.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
KP="$FIXTURES/shirudo-test-scope-kprobe.upatch"
KP_UNLOAD="$FIXTURES/shirudo-test-scope-kprobe.unload.upatch"
BASIC_PIN=/run/shirudo/bpffs/upatches/shirudo-test-basic/link
B=/run/shirudo/bpffs/upatches
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
[ -s "$KP" ] && [ -s "$KP_UNLOAD" ] || test_skip_all "missing scope kprobe fixture"
[ -e "$BASIC_PIN" ] || test_skip_all "basic fixture is not loaded"
[ ! -e "$B/shirudo-test-scope-kprobe" ] || test_skip_all "scope kprobe fixture is loaded"

# Rewrite the header name, or a string inside one signed section named
# by its tag, keeping payload_sha256 consistent so only the signature or
# the signed name can refuse the result.
mutate() {
	python3 - "$@" <<'PY'
import hashlib, pathlib, struct, sys
src, dst, what = sys.argv[1:4]
data = bytearray(pathlib.Path(src).read_bytes())
loader_off, loader_len = struct.unpack_from("<II", data, 304)
data_off, data_len = struct.unpack_from("<II", data, 328)
if what == "header-name":
    name = sys.argv[4].encode()
    data[16:272] = name + bytes(256 - len(name))
elif what == "section":
    tag, (old, new) = sys.argv[4].encode(), sys.argv[5].split("=")
    magic, version, dir_off, nr = struct.unpack_from(
        "<4sIII", data, data_off + data_len - 16)
    assert magic == b"SGTR" and version == 1
    for i in range(nr):
        t, _, off, length = struct.unpack_from(
            "<4sIII", data, data_off + dir_off + 16 * i)
        if t == tag:
            break
    else:
        raise SystemExit("no section " + tag.decode())
    start = data_off + off
    i = bytes(data[start:start + length]).find(old.encode())
    assert i >= 0, "pattern not in the section"
    data[start + i:start + i + len(old)] = new.encode().ljust(len(old), b"\0")
    payload = bytes(data[loader_off:loader_off + loader_len]) + bytes(data[data_off:data_off + data_len])
    data[272:304] = hashlib.sha256(payload).digest()
pathlib.Path(dst).write_bytes(data)
PY
}

category() {
	"$SHIRUDO_BIN" "$@" --no-precheck --report=- 2>/dev/null | report_field category
}

test_expect_success 'the kernel refuses a load whose kprobe symbol was edited' '
	mutate "$KP" "$WORK/resited.upatch" section UPGM do_nanosleep=do_exit &&
	[ "$(category upatch load "$WORK/resited.upatch")" = signature_rejected ] &&
	[ ! -e "$B/shirudo-test-scope-kprobe" ]
'

test_expect_success 'a load whose header name differs from the signed name is refused' '
	mutate "$KP" "$WORK/renamed.upatch" header-name shirudo-test-renamed &&
	[ "$(category upatch load "$WORK/renamed.upatch")" = parser_rejected ] &&
	[ ! -e "$B/shirudo-test-renamed" ] &&
	[ ! -e "$B/shirudo-test-scope-kprobe" ]
'

test_expect_success 'an unload directive cannot be pointed at another upatch' '
	mutate "$KP_UNLOAD" "$WORK/repointed.unload.upatch" header-name shirudo-test-basic &&
	[ "$(category upatch unload "$WORK/repointed.unload.upatch")" = parser_rejected ] &&
	[ -e "$BASIC_PIN" ]
'

test_expect_success 'the kernel refuses an unload directive whose signed target was edited' '
	mutate "$KP_UNLOAD" "$WORK/retargeted.unload.upatch" section NAME shirudo-test-scope-kprobe=shirudo-test-basic &&
	mutate "$WORK/retargeted.unload.upatch" "$WORK/retargeted.unload.upatch" header-name shirudo-test-basic &&
	[ "$(category upatch unload "$WORK/retargeted.unload.upatch")" = signature_rejected ] &&
	[ -e "$BASIC_PIN" ]
'

test_done
