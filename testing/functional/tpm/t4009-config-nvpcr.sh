#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./test-lib.sh

H=${SHIRUDO_TEST_CONFIG_ATTEST_HELPER:-$(pwd)/helper/test-config-attest}
[ -x "$H" ] || test_skip_all "test-config-attest helper not built"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
NVPCR=25267716
ROOT_A=$(python3 -c 'print("41" * 32)')
ROOT_B=$(python3 -c 'print("42" * 32)')

# A history in the config NvPCR (0x01818e04): it starts at the value systemd's
# initializing write leaves, SHA256 of 64 zero bytes, and the verifier checks
# it against the certified NvPCR value instead of a quoted PCR.
python3 - "$WORK" "$NVPCR" <<'PY'
import hashlib, json, sys
from pathlib import Path
root, index = Path(sys.argv[1]), int(sys.argv[2])
sha = lambda data: hashlib.sha256(data).digest()

def event(kind, root_hash):
    return sha(b"shirudo-config-root-v1\0" + kind.to_bytes(4, "big") + bytes.fromhex(root_hash))

def document(initial, events, pcr=index):
    value = bytes.fromhex(initial)
    for e in events:
        value = sha(value + event(e["kind"], e["root_hash"]))
    return {"config": {"schema": 1, "pcr": pcr, "reset_count": 7, "restart_count": 0,
                       "initial_pcr": initial, "events": events}}, value.hex()

events = [{"sequence": 1, "kind": 1, "root_hash": "41" * 32},
          {"sequence": 2, "kind": 2, "root_hash": "42" * 32}]
initial = sha(bytes(64)).hex()
for name, (doc, value) in {"good": document(initial, events),
                           "zero-start": document("00" * 32, events)}.items():
    (root / (name + ".json")).write_text(json.dumps(doc))
    (root / (name + ".value")).write_text(value)
PY
GOOD=$(cat "$WORK/good.value")

test_expect_success 'a config NvPCR history verifies against the certified NvPCR' '
	"$H" replay "$WORK/good.json" "$ROOT_B" "$NVPCR" 7 0 "$GOOD" >"$WORK/out" &&
	grep -qx "reason=config root history matches the certified NvPCR" "$WORK/out"
'

test_expect_success 'a certified value the history does not reach is refused' '
	! "$H" replay "$WORK/good.json" "$ROOT_B" "$NVPCR" 7 0 "$(printf %064d 5)" >"$WORK/out" &&
	grep -qx "reason=config history does not match the certified NvPCR" "$WORK/out"
'

test_expect_success 'a history that chooses its own start is refused' '
	! "$H" replay "$WORK/zero-start.json" "$ROOT_B" "$NVPCR" 7 0 \
		"$(cat "$WORK/zero-start.value")" >"$WORK/out" &&
	grep -qx "reason=config history does not start at the NvPCR'"'"'s initial value" "$WORK/out"
'

test_expect_success 'an NvPCR history is not a PCR 15 history, nor approved for another root' '
	! "$H" replay "$WORK/good.json" "$ROOT_B" 15 7 0 "$GOOD" >/dev/null &&
	! "$H" replay "$WORK/good.json" "$ROOT_A" "$NVPCR" 7 0 "$GOOD" >/dev/null &&
	! "$H" replay "$WORK/good.json" "$ROOT_B" "$NVPCR" 8 0 "$GOOD" >/dev/null
'

test_done
