#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1108 -- measured operations and attestation through the installed
# binary, real kernel-held writer and the VM's TPM device.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

tpm_chain() {
	"$SHIRUDO_BIN" status --json 2>/dev/null | python3 -c '
import sys, json
d = json.load(sys.stdin)
t = d.get("tpm") or {}
print(t.get(sys.argv[1], "") if t.get(sys.argv[1], None) is not None else "")
' "$1"
}

[ -n "$(tpm_chain chain)" ] ||
	test_skip_all "no bound register (init not run / no usable TPM)"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-lifecycle
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME/link"
CERT="$FIXTURES/cert.der"
PREDICT=./helper/test-register-cli
NONCE=0102030405060708090a0b0c0d0e0f10
W=$(mktemp -d) || exit 1

cleanup() {
	result=$?
	if [ -e "$PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck || result=1
	fi
	rm -f "$W"/* || result=1
	rmdir "$W" || result=1
	exit "$result"
}
trap cleanup EXIT HUP INT TERM

evidence_field() {
	python3 - "$W/evidence.json" "$1" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
keys = sys.argv[2].split(".")
if keys[0] == "init":
    d = next(r for r in d["eventlog"] if r.get("type") == "init")
    keys = keys[1:]
for key in keys:
    d = d[key]
print(d)
PY
}

PAYLOAD=$("$SHIRUDO_BIN" upatch info "$LOAD" --json | report_field payload_sha256) || exit 1

test_expect_success 'eventlog replay reproduces the live register value' '
	[ "$(tpm_chain chain_matches_eventlog)" = "True" ]
'

test_expect_success 'initialization reuses the kernel writer and register without another event' '
	before=$(tpm_chain chain) &&
	lines=$(wc -l </var/lib/shirudo/eventlog) &&
	"$SHIRUDO_BIN" init &&
	[ "$(tpm_chain chain)" = "$before" ] &&
	[ "$(wc -l </var/lib/shirudo/eventlog)" = "$lines" ]
'

test_expect_success 'a real signed load extends the register by exactly its measured event' '
	before=$(tpm_chain chain) &&
	expected=$(python3 -c "import hashlib; event=hashlib.sha256(b\"shirudo-upatch\0\" + bytes.fromhex(\"$PAYLOAD\") + b\"$NAME\").digest(); print(hashlib.sha256(bytes.fromhex(\"$before\") + event).hexdigest())") &&
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck &&
	[ -e "$PIN" ] &&
	[ "$(tpm_chain chain)" = "$expected" ] &&
	[ "$(tpm_chain chain_matches_eventlog)" = "True" ]
'

test_expect_success 'a real signed unload extends the register and remains replayable' '
	before=$(tpm_chain chain) &&
	expected=$(python3 -c "import hashlib; event=hashlib.sha256(b\"shirudo-unload\0\" + bytes.fromhex(\"$PAYLOAD\") + b\"$NAME\").digest(); print(hashlib.sha256(bytes.fromhex(\"$before\") + event).hexdigest())") &&
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck &&
	[ ! -e "$PIN" ] &&
	[ "$(tpm_chain chain)" = "$expected" ] &&
	[ "$(tpm_chain chain_matches_eventlog)" = "True" ]
'

test_expect_success 'the installed binary emits evidence that verifies against the live register' '
	"$SHIRUDO_BIN" attest --nonce="$NONCE" --out="$W/evidence.json" &&
	AK=$(evidence_field ak.name) &&
	EK=$(evidence_field ek.name) &&
	CHAIN=$(tpm_chain chain) &&
	"$SHIRUDO_BIN" attest verify --evidence="$W/evidence.json" --nonce="$NONCE" \
		--ak-name="$AK" --ek-name="$EK" --expect-chain="$CHAIN" \
		--strict-anchor >"$W/report" &&
	grep -qx "verdict: ok" "$W/report" &&
	grep -q "^ok:   register: public area is bound to PCRs 9 and 11" "$W/report"
'

AK=$(evidence_field ak.name) || exit 1
EK=$(evidence_field ek.name) || exit 1
CHAIN=$(tpm_chain chain) || exit 1
WRITER=$(evidence_field init.nv_writer_public) || exit 1
PCR_BEFORE=$(evidence_field init.pcr_before) || exit 1
PHASE_BEFORE=$(evidence_field init.phase_before) || exit 1
NV_NAME=$(evidence_field init.nv_name) || exit 1

test_expect_success 'prediction reconstructs the certified name from the real writer and binding' '
	[ "${#WRITER}" = 768 ] &&
	"$PREDICT" attest predict --cert="$CERT" --writer-public="$WRITER" \
		--bind-pcr=9="$PCR_BEFORE" --bind-pcr=11="$PHASE_BEFORE" >"$W/predict" &&
	grep -qx "register_name: $NV_NAME" "$W/predict" &&
	grep -qx "pcr9_after_anchor: $(tr A-F a-f </sys/class/tpm/tpm0/pcr-sha256/9)" "$W/predict"
'

test_expect_success 'prediction requires the public key and rejects invalid encodings' '
	! "$PREDICT" attest predict --cert="$CERT" \
		--bind-pcr=9="$PCR_BEFORE" --bind-pcr=11="$PHASE_BEFORE" &&
	! "$PREDICT" attest predict --cert="$CERT" --writer-public=00 \
		--bind-pcr=9="$PCR_BEFORE" --bind-pcr=11="$PHASE_BEFORE" &&
	area=$(./helper/test-tpm-wire writer-public "$WRITER") &&
	! "$PREDICT" attest predict --cert="$CERT" --writer-public="$area" \
		--bind-pcr=9="$PCR_BEFORE" --bind-pcr=11="$PHASE_BEFORE"
'

test_expect_success 'a fabricated positive event cannot establish an expected register state' '
	python3 - "$W/evidence.json" "$W/forged.json" "$PAYLOAD" >"$W/forged-chain" <<"PY"
import hashlib, json, sys
d = json.load(open(sys.argv[1]))
event = hashlib.sha256(b"shirudo-upatch\0" + bytes.fromhex(sys.argv[3]) + b"absent-fix").digest()
d["eventlog"].append({"type": "upatch_load", "digest": event.hex(),
                     "upatch": {"name": "absent-fix", "payload_sha256": sys.argv[3]}})
print(hashlib.sha256(bytes.fromhex(d["register"]["value"]) + event).hexdigest())
json.dump(d, open(sys.argv[2], "w"))
PY
	! "$SHIRUDO_BIN" attest verify --evidence="$W/forged.json" --nonce="$NONCE" \
		--ak-name="$AK" --expect-chain="$(cat "$W/forged-chain")" \
		>"$W/forged-report" &&
	grep -q "^FAIL: eventlog:" "$W/forged-report" &&
	grep -q "^FAIL: state:" "$W/forged-report"
'

test_expect_success 'the certified name binds the writer public key and its exact encoding' '
	python3 - "$W/evidence.json" "$W" <<"PY"
import copy, json, struct, sys
d = json.load(open(sys.argv[1]))
record = next(r for r in d["eventlog"] if r.get("type") == "init")
key = bytes.fromhex(record["nv_writer_public"])
header = struct.pack(">HHIHHHHHIH", 1, 11, 0x40000, 0, 16, 20, 11, 3072, 65537, 384)
changed = bytearray(key)
changed[25] ^= 1
cases = [("swapped", bytes(changed)), ("header", header + key), ("short", key[:-1]),
         ("even", key[:-1] + bytes([key[-1] & 0xfe])), ("zero", bytes(384)), ("missing", None)]
for name, public in cases:
    doc = copy.deepcopy(d)
    init = next(r for r in doc["eventlog"] if r.get("type") == "init")
    if public is None:
        del init["nv_writer_public"]
    else:
        init["nv_writer_public"] = public.hex()
    json.dump(doc, open(f"{sys.argv[2]}/writer-{name}.json", "w"))
PY
	failed=0 &&
	for kind in swapped header short even zero missing; do
		rc=0
		"$SHIRUDO_BIN" attest verify --evidence="$W/writer-$kind.json" \
			--nonce="$NONCE" --ak-name="$AK" --allow-runtime-events \
			>"$W/writer-$kind.report" || rc=$?
		case "$kind" in
		header|short|missing)
			[ "$rc" = 2 ] || failed=1
			;;
		*)
			[ "$rc" = 1 ] &&
			grep -q "^FAIL: register: public area" "$W/writer-$kind.report" || failed=1
			;;
		esac
	done &&
	[ "$failed" = 0 ]
'

test_done
