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

test_expect_success 'a challenge requires the correct pinned endorsement and attestation keys' '
	! "$SHIRUDO_BIN" attest challenge --evidence="$W/evidence.json" \
		--out="$W/challenge-none.json" >"$W/challenge-none.out" &&
	grep -q "^FAIL: no endorsement certificate: pin the key" "$W/challenge-none.out" &&
	[ ! -e "$W/challenge-none.json" ] &&
	! "$SHIRUDO_BIN" attest challenge --evidence="$W/evidence.json" \
		--ek-name=000b$(printf "%064d" 0) --out="$W/challenge-wrong.json" \
		>"$W/challenge-wrong.out" &&
	grep -q "^FAIL: endorsement key: the pinned key" "$W/challenge-wrong.out" &&
	! "$SHIRUDO_BIN" attest challenge --evidence="$W/evidence.json" \
		--ak-name=000b$(printf "%064d" 0) --trust-presented-ek \
		--out="$W/challenge-wrong.json" >"$W/challenge-wrong-ak.out" &&
	grep -q "^FAIL: attestation key: the pinned key" "$W/challenge-wrong-ak.out"
'

test_expect_success 'the production target activates an ECC endorsement-key challenge' '
	"$SHIRUDO_BIN" attest challenge --evidence="$W/evidence.json" \
		--ak-name="$AK" --ek-name="$EK" --out="$W/challenge.json" >"$W/challenge.out" &&
	credential=$(sed -n "s/^credential: //p" "$W/challenge.out") &&
	[ "${#credential}" = 64 ] &&
	"$SHIRUDO_BIN" attest --nonce=1112 --challenge="$W/challenge.json" \
		--out="$W/evidence-credential.json" &&
	"$SHIRUDO_BIN" attest verify --evidence="$W/evidence-credential.json" --nonce=1112 \
		--ak-name="$AK" --ek-name="$EK" --allow-runtime-events \
		--expect-credential="$credential" >"$W/credential.report" &&
	grep -qx "verdict: ok" "$W/credential.report"
'

test_expect_success 'wrong credentials, corrupted blobs and foreign challenges are rejected' '
	! "$SHIRUDO_BIN" attest verify --evidence="$W/evidence-credential.json" --nonce=1112 \
		--ak-name="$AK" --allow-runtime-events --expect-credential=$(printf "%064d" 0) \
		>"$W/wrong-credential.report" &&
	grep -q "^FAIL: attestation key: activated the credential" "$W/wrong-credential.report" &&
	python3 - "$W/challenge.json" "$W" <<"PY"
import copy, json, sys
d = json.load(open(sys.argv[1]))
corrupt = copy.deepcopy(d)
blob = bytearray.fromhex(corrupt["credential_blob"])
blob[-1] ^= 1
corrupt["credential_blob"] = blob.hex()
json.dump(corrupt, open(sys.argv[2] + "/challenge-corrupt.json", "w"))
foreign = copy.deepcopy(d)
foreign["ak_name"] = "000b" + "00" * 32
json.dump(foreign, open(sys.argv[2] + "/challenge-foreign.json", "w"))
PY
	! "$SHIRUDO_BIN" attest --nonce=1112 --challenge="$W/challenge-corrupt.json" \
		--out="$W/corrupt-evidence.json" &&
	! "$SHIRUDO_BIN" attest --nonce=1112 --challenge="$W/challenge-foreign.json" \
		--out="$W/foreign-evidence.json"
'

test_expect_success 'an RSA endorsement key activates the challenge through the production target' '
	tpm2_createek -T device:/dev/tpmrm0 -G rsa -c "$W/rsa.ctx" -u "$W/rsa-public" &&
	python3 - "$W/rsa-public" "$W/evidence.json" "$W/rsa.json" <<"PY"
import hashlib, json, sys
encoded = open(sys.argv[1], "rb").read()
assert int.from_bytes(encoded[:2], "big") == len(encoded) - 2
public = encoded[2:]
d = json.load(open(sys.argv[2]))
doc = {"ak": {"name": d["ak"]["name"]},
       "ek": {"type": "rsa", "public": public.hex(),
              "name": (b"\x00\x0b" + hashlib.sha256(public).digest()).hex()}}
json.dump(doc, open(sys.argv[3], "w"))
PY
	"$SHIRUDO_BIN" attest challenge --evidence="$W/rsa.json" --trust-presented-ek \
		--out="$W/challenge-rsa.json" >"$W/challenge-rsa.out" &&
	credential=$(sed -n "s/^credential: //p" "$W/challenge-rsa.out") &&
	"$SHIRUDO_BIN" attest --nonce=1314 --challenge="$W/challenge-rsa.json" \
		--out="$W/evidence-rsa.json" &&
	"$SHIRUDO_BIN" attest verify --evidence="$W/evidence-rsa.json" --nonce=1314 \
		--ak-name="$AK" --allow-runtime-events --expect-credential="$credential" \
		>"$W/rsa.report" &&
	grep -qx "verdict: ok" "$W/rsa.report"
'

test_expect_success 'a non-endorsement public key cannot establish endorsement trust' '
	python3 - "$W/evidence.json" "$W/fake-ek.json" <<"PY"
import json, sys
d = json.load(open(sys.argv[1]))
d["ek"] = {"type": "ecc", "public": d["ak"]["public"], "name": d["ak"]["name"]}
json.dump(d, open(sys.argv[2], "w"))
PY
	! "$SHIRUDO_BIN" attest challenge --evidence="$W/fake-ek.json" --trust-presented-ek \
		--out="$W/challenge-fake.json" >"$W/fake-ek.out" &&
	grep -q "^FAIL: endorsement key: TCG default template" "$W/fake-ek.out" &&
	[ ! -e "$W/challenge-fake.json" ]
'

test_done
