#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6117 -- the attach metadata, the name and the unload target are
# signed. Root used to edit the symbol a signed kprobe attached at, or
# the name and expected payload of a signed unload directive, and load
# the result as the trusted task: the kernel verified the loader, the
# edited bytes were outside the signature. Now the kernel refuses an
# artifact whose signed sections were touched, and the target refuses
# one whose header disagrees with them. Non-destructive: nothing loads
# and the basic fixture stays pinned.

cd "$(dirname "$0")/../.."
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
require_loaded shirudo-test-basic || test_skip_all "cannot load the basic fixture"
[ ! -e "$B/shirudo-test-scope-kprobe" ] || test_skip_all "scope kprobe fixture is loaded"

# Rewrite the header name or map count, or a string inside one signed
# section named by its tag, keeping payload_sha256 consistent so only the
# signature or the signed sections can refuse the result.
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
elif what == "header-maps":
    struct.pack_into("<I", data, 340, struct.unpack_from("<I", data, 340)[0] + 1)
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
elif what == "xdp-mask":
    magic, version, directory, count = struct.unpack_from(
        "<4sIII", data, data_off + data_len - 16)
    assert magic == b"SGTR" and version == 1
    for i in range(count):
        tag, _, off, length = struct.unpack_from(
            "<4sIII", data, data_off + directory + i * 16)
        if tag == b"UPGM":
            assert struct.unpack_from("<I", data, data_off + off + 20)[0] == 8
            struct.pack_into("<I", data, data_off + off + 24, 27)
            break
    else:
        raise AssertionError("no signed XDP metadata")
    payload = data[loader_off:loader_off + loader_len] + data[data_off:data_off + data_len]
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

test_expect_success 'the kernel refuses a widened signed XDP device mask' '
	mutate "$FIXTURES/shirudo-test-xdp-virtual.upatch" \
		"$WORK/xdp-widened.upatch" xdp-mask &&
	[ "$(category upatch load "$WORK/xdp-widened.upatch")" = signature_rejected ] &&
	[ ! -e "$B/shirudo-test-xdp-virtual" ]
'

test_expect_success 'a load whose header name differs from the signed name is refused' '
	mutate "$KP" "$WORK/renamed.upatch" header-name shirudo-test-renamed &&
	[ "$(category upatch load "$WORK/renamed.upatch")" = parser_rejected ] &&
	[ ! -e "$B/shirudo-test-renamed" ] &&
	[ ! -e "$B/shirudo-test-scope-kprobe" ]
'

test_expect_success 'a load whose header map count differs from the signed count is refused' '
	mutate "$KP" "$WORK/remapped.upatch" header-maps &&
	[ "$(category upatch load "$WORK/remapped.upatch")" = parser_rejected ] &&
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
