#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0034 -- register lifecycle with a real kernel writer in a pre-init VM.

cd "$(dirname "$0")/.."
. ./test-lib.sh

R=./helper/test-register
SIM=$(pwd)/helper/tpmsim-cmd
S=./helper/test-register-cli
. ./tpm/register-lib.sh
[ "$(id -u)" = 0 ] && [ -x "$SIM" ] && [ -x "$R" ] && [ -x "$S" ] || {
	echo "register VM requires root and the built TPM helpers" >&2
	exit 1
}
WORK=$(mktemp -d) || exit 1
cleanup() {
	result=$?
	register_writer_stop || result=1
	rm -rf "$WORK"
	exit "$result"
}
trap cleanup EXIT HUP INT TERM
register_writer_start || exit 1
WRITER=$(./$R writer-public) || exit 1
mkdir -p "$WORK/keys"
head -c 700 /dev/urandom >"$WORK/keys/cert.der"
: >"$WORK/initrd-release"
export SHIRUDO_TPM_TCTI="cmd:$SIM $WORK/tpm"
export SHIRUDO_EVENTLOG_PATH="$WORK/eventlog"
export SHIRUDO_KEYS_DIR="$WORK/keys"
export SHIRUDO_INITRD_RELEASE="$WORK/initrd-release"

py() { python3 -c "$1"; }
sha() { py "import hashlib; print(hashlib.sha256(bytes.fromhex(\"$1\")).hexdigest())"; }
field() { sed -n "s/^$1=//p"; }
Z=0000000000000000000000000000000000000000000000000000000000000000
PAYLOAD=$(py "print(\"ab\"*32)")
ENTER=$(py "import hashlib; print(hashlib.sha256(b\"enter-initrd\").hexdigest())")
LEAVE=$(py "import hashlib; print(hashlib.sha256(b\"leave-initrd\").hexdigest())")
PHASE=$(sha "$Z$ENTER")

test_expect_success 'attest names a register that is not bound yet' '
	! $S attest --nonce=00 >/dev/null 2>"$WORK/attest-unbound.err" &&
	grep -qx "attest: register 0x01818E00 is not bound this boot (tpm_error); run shirudo init first" \
		"$WORK/attest-unbound.err" &&
	[ "$(grep -c "not bound" "$WORK/attest-unbound.err")" = 1 ]
'

test_expect_success 'attest tells no TPM apart from an unbound register' '
	! SHIRUDO_TPM_TCTI=device:/nonexistent/tpm $S attest --nonce=00 \
		>/dev/null 2>"$WORK/attest-notpm.err" &&
	grep -qx "attest: no TPM answered (tpm_error)" "$WORK/attest-notpm.err" &&
	! grep -q "shirudo init" "$WORK/attest-notpm.err"
'

test_expect_success 'init binds the register to PCRs 9 and 11 from the initrd and anchors in PCR 9' '
	./$R pcr-extend 11 "$ENTER" | grep -qx "rc=0" &&
	[ "$(./$R pcr 11)" = "$PHASE" ] &&
	init=$($S attest predict --cert="$WORK/keys/cert.der" | sed -n "s/^init_event: //p") &&
	out=$(./$R init "$init") &&
	echo "$out" | grep -qx "rc=0" &&
	echo "$out" | grep -qx "reused=0" &&
	echo "$out" | grep -qx "pcr_before=$Z" &&
	echo "$out" | grep -qx "phase_before=$PHASE" &&
	echo "$out" | grep -qx "bound_in=initrd" &&
	name=$(echo "$out" | field name) &&
	[ "$(echo "$out" | field anchor)" = "nvpcr-init:shirudo:0x1818e00:$name" ] &&
	anchor_digest=$(py "import hashlib; print(hashlib.sha256(b\"nvpcr-init:shirudo:0x1818e00:$name\").hexdigest())") &&
	[ "$(./$R pcr 9)" = "$(sha "$Z$anchor_digest")" ] &&
	[ "$(echo "$out" | field value)" = "$(sha "$Z$init")" ] &&
	echo "$init" >"$WORK/init" && echo "$name" >"$WORK/name"
'

test_expect_success 'predict names the register from the binding values and kernel writer' '
	$S attest predict --cert="$WORK/keys/cert.der" --bind-pcr=9=$Z \
		--bind-pcr=11=$PHASE --writer-public="$WRITER" >"$WORK/predict" &&
	grep -qx "register_name: $(cat "$WORK/name")" "$WORK/predict" &&
	grep -qx "pcr9_after_anchor: $(./$R pcr 9)" "$WORK/predict"
'

test_expect_success 'status reports the register bound, logged and anchored' '
	./$R status | grep -qx "tpm=1 defined=1 written=1 logged=1 anchored=1" &&
	$S status --json >"$WORK/status.json" &&
	python3 - "$WORK/status.json" <<"PY"
import json, sys
t = json.load(open(sys.argv[1]))["tpm"]
assert t["register_bound"] and t["register_anchored"], t
assert t["chain_matches_eventlog"] is True, t
assert t["pcr"] == 9 and t["phase_pcr"] == 11, t
assert t["bound_in"] == "initrd", t
PY
'

test_expect_success 'a re-run of init reuses the register and adds no event' '
	out=$(./$R init "$(cat "$WORK/init")") &&
	echo "$out" | grep -qx "reused=1" &&
	[ "$(wc -l <"$WORK/eventlog")" = 1 ]
'

test_expect_success 'leaving the initrd closes the init branch for good' '
	./$R pcr-extend 11 "$LEAVE" | grep -qx "rc=0" &&
	./$R first-write "$PAYLOAD" | grep -qx "rc=-13"
'

test_expect_success 'a load extends through the written branch and replays' '
	before=$(./$R read | field value) &&
	event=$(py "import hashlib; print(hashlib.sha256(b\"shirudo-upatch\\0\" + bytes.fromhex(\"$PAYLOAD\") + b\"foo\").hexdigest())") &&
	out=$(./$R load foo "$PAYLOAD") &&
	echo "$out" | grep -qx "rc=0" &&
	[ "$(echo "$out" | field value)" = "$(sha "$before$event")" ] &&
	./$R status | grep -qx "tpm=1 defined=1 written=1 logged=1 anchored=1"
'

test_expect_success 'evidence verifies against the pinned key, the binding and the predicted state' '
	nonce=0102030405060708090a0b0c0d0e0f10 &&
	./$R evidence $nonce >"$WORK/evidence.json" &&
	ak=$(py "import json; print(json.load(open(\"$WORK/evidence.json\"))[\"ak\"][\"name\"])") &&
	echo "$ak" >"$WORK/ak" &&
	py "import json; print(json.load(open(\"$WORK/evidence.json\"))[\"ek\"][\"name\"])" >"$WORK/ek" &&
	value=$(./$R read | field value) &&
	$S attest verify --evidence="$WORK/evidence.json" --nonce=$nonce \
		--ak-name="$ak" --ek-name="$(cat "$WORK/ek")" \
		--expect-chain="$value" --strict-anchor --require-initrd \
		--expect-bind-pcr=9=$Z --expect-bind-pcr=11=$PHASE \
		>"$WORK/report" &&
	grep -qx "verdict: ok" "$WORK/report" &&
	grep -q "^ok:   register: public area is bound to PCRs 9 and 11" "$WORK/report" &&
	grep -q "^ok:   binding: PCR 11 held the expected value" "$WORK/report" &&
	grep -q "^ok:   binding: made while the initrd ran" "$WORK/report" &&
	grep -q "^ok:   endorsement key: the pinned key" "$WORK/report" &&
	! grep -q "^FAIL" "$WORK/report"
'

test_expect_success 'verify computes the state from cert and set, flags runtime events' '
	nonce=0102030405060708090a0b0c0d0e0f10 &&
	$S attest verify --evidence="$WORK/evidence.json" --nonce=$nonce \
		--ak-name="$(cat "$WORK/ak")" --cert="$WORK/keys/cert.der" \
		>"$WORK/report3"; rc=$? &&
	[ "$rc" = 1 ] &&
	grep -q "^ok:   state: init event covers" "$WORK/report3" &&
	grep -q "^FAIL: state: 1 event after boot" "$WORK/report3" &&
	$S attest verify --evidence="$WORK/evidence.json" --nonce=$nonce \
		--ak-name="$(cat "$WORK/ak")" --cert="$WORK/keys/cert.der" \
		--allow-runtime-events | grep -qx "verdict: ok"
'

test_expect_success 'predict reproduces the register after the load' '
	value=$(./$R read | field value) &&
	$S attest predict --cert="$WORK/keys/cert.der" --event="load:foo=$PAYLOAD" |
		grep -qx "register_after_events: $value"
'

test_expect_success 'a wrong nonce, key name, binding value or tampered value fails' '
	nonce=0102030405060708090a0b0c0d0e0f10 &&
	value=$(./$R read | field value) &&
	ak=$(cat "$WORK/ak") &&
	! $S attest verify --evidence="$WORK/evidence.json" --nonce=ffff \
		--ak-name="$ak" --expect-chain="$value" >/dev/null &&
	! $S attest verify --evidence="$WORK/evidence.json" --nonce=$nonce \
		--ak-name="000b$(py "print(\"00\"*32)")" --expect-chain="$value" >/dev/null &&
	! $S attest verify --evidence="$WORK/evidence.json" --nonce=$nonce \
		--ak-name="$ak" --expect-chain="$value" --expect-bind-pcr=11=$Z \
		>"$WORK/report4b" &&
	grep -q "^FAIL: binding: PCR 11 held the expected value" "$WORK/report4b" &&
	sed "s/\"value\":\"$value\"/\"value\":\"$Z\"/" "$WORK/evidence.json" >"$WORK/tampered.json" &&
	! $S attest verify --evidence="$WORK/tampered.json" --nonce=$nonce \
		--ak-name="$ak" --expect-chain="$value" >"$WORK/report4" &&
	grep -q "^FAIL: register: certified contents" "$WORK/report4"
'

# The pre-init fixture uses the kernel writer to certify a substitute
# register bound to resettable PCRs. Even otherwise valid writer evidence
# must not select the verifier's register handle or binding PCRs.
test_expect_success 'a register of the target'"'"'s own, bound to PCRs it controls, is refused' '
	nonce=0102030405060708090a0b0c0d0e0f10 &&
	./$R forge 01818e01 16 23 "$(cat "$WORK/init")" $nonce >"$WORK/forged.json" &&
	python3 - "$WORK/forged.json" "$WRITER" <<"PY" &&
import json, sys
evidence = json.load(open(sys.argv[1]))
assert evidence["eventlog"][0]["nv_writer_public"] == sys.argv[2]
assert evidence["register"]["nv_index"] == "0x01818E01"
assert evidence["eventlog"][0]["pcr"] == 16
assert evidence["eventlog"][0]["phase_pcr"] == 23
PY
	[ "$(py "import json; print(json.load(open(\"$WORK/forged.json\"))[\"register\"][\"value\"])")" = \
		"$(sha "$Z$(cat "$WORK/init")")" ] &&
	! $S attest verify --evidence="$WORK/forged.json" --nonce=$nonce \
		--ak-name="$(cat "$WORK/ak")" --ek-name="$(cat "$WORK/ek")" \
		--cert="$WORK/keys/cert.der" --strict-anchor --require-initrd \
		>"$WORK/report-forged" &&
	grep -q "^FAIL: register: the document names index 0x01818E00 and PCRs 9 and 11" \
		"$WORK/report-forged" &&
	grep -q "^ok:   register: certified contents match the listed value" \
		"$WORK/report-forged"
'

test_expect_success 'an event relabelled after the fact fails although the replay closes' '
	nonce=0102030405060708090a0b0c0d0e0f10 &&
	sed "s/\"type\":\"upatch_load\"/\"type\":\"upatch_unload\"/" \
		"$WORK/evidence.json" >"$WORK/relabelled.json" &&
	! $S attest verify --evidence="$WORK/relabelled.json" --nonce=$nonce \
		--ak-name="$(cat "$WORK/ak")" --cert="$WORK/keys/cert.der" \
		--allow-runtime-events >"$WORK/report-relabelled" &&
	grep -q "^ok:   eventlog: 2 records replay to the certified value" \
		"$WORK/report-relabelled" &&
	grep -q "^FAIL: eventlog: event 1 (upatch_unload foo) digest does not derive from its fields" \
		"$WORK/report-relabelled" &&
	$S attest verify --evidence="$WORK/evidence.json" --nonce=$nonce \
		--ak-name="$(cat "$WORK/ak")" --cert="$WORK/keys/cert.der" \
		--allow-runtime-events >"$WORK/report-labelled" &&
	! grep -q "does not derive" "$WORK/report-labelled"
'

test_expect_success 'a tree operation records its digest as the target writes it' '
	nonce=0102030405060708090a0b0c0d0e0f10 &&
	before=$(./$R read | field value) &&
	op=$(py "print(\"cd\"*32)") &&
	event=$(py "import hashlib; print(hashlib.sha256(b\"shirudo-tree\\0\" + (1).to_bytes(8, \"big\") + bytes.fromhex(\"$op\")).hexdigest())") &&
	out=$(./$R tree 1 append shirudo-test-tree "sha256:$op") &&
	echo "$out" | grep -qx "rc=0" &&
	[ "$(echo "$out" | field value)" = "$(sha "$before$event")" ] &&
	./$R evidence $nonce >"$WORK/evidence-tree.json" &&
	$S attest verify --evidence="$WORK/evidence-tree.json" --nonce=$nonce \
		--ak-name="$(cat "$WORK/ak")" --cert="$WORK/keys/cert.der" \
		--allow-runtime-events >"$WORK/report-tree" &&
	grep -qx "verdict: ok" "$WORK/report-tree" &&
	grep -q "^ok:   eventlog: 3 records replay to the certified value" "$WORK/report-tree" &&
	! grep -q "does not derive" "$WORK/report-tree"
'

test_expect_success 'a challenge needs a vouched-for endorsement key' '
	! $S attest challenge --evidence="$WORK/evidence.json" \
		--out="$WORK/challenge-none.json" >"$WORK/challenge-none.out" &&
	grep -q "^FAIL: no endorsement certificate: pin the key" "$WORK/challenge-none.out" &&
	[ ! -e "$WORK/challenge-none.json" ] &&
	! $S attest challenge --evidence="$WORK/evidence.json" \
		--ek-name="000b$(py "print(\"00\"*32)")" \
		--out="$WORK/challenge-wrong.json" >"$WORK/challenge-wrong.out" &&
	grep -q "^FAIL: endorsement key: the pinned key" "$WORK/challenge-wrong.out" &&
	! $S attest challenge --evidence="$WORK/evidence.json" \
		--ak-name="000b$(py "print(\"00\"*32)")" --trust-presented-ek \
		--out="$WORK/challenge-wrong.json" >"$WORK/challenge-wrong2.out" &&
	grep -q "^FAIL: attestation key: the pinned key" "$WORK/challenge-wrong2.out"
'

test_expect_success 'a challenge made from the evidence activates on the target' '
	nonce=1112 &&
	$S attest challenge --evidence="$WORK/evidence.json" \
		--ak-name="$(cat "$WORK/ak")" --ek-name="$(cat "$WORK/ek")" \
		--out="$WORK/challenge.json" >"$WORK/challenge.out" &&
	grep -q "^ok:   attestation key: the pinned key" "$WORK/challenge.out" &&
	grep -q "^ok:   endorsement key: the pinned key" "$WORK/challenge.out" &&
	grep -q "^ok:   endorsement key: TCG default template" "$WORK/challenge.out" &&
	grep -q "^note: no endorsement certificate" "$WORK/challenge.out" &&
	sed -n "s/^credential: //p" "$WORK/challenge.out" >"$WORK/credential" &&
	[ "$(wc -c <"$WORK/credential")" = 65 ] &&
	./helper/test-tpm-wire public "$(py "import json; print(json.load(open(\"$WORK/evidence.json\"))[\"ek\"][\"public\"])")" |
		grep -q "same=1" &&
	./$R evidence $nonce "$WORK/challenge.json" >"$WORK/evidence-cred.json" &&
	[ "$(py "import json; print(json.load(open(\"$WORK/evidence-cred.json\"))[\"credential\"][\"value\"])")" = "$(cat "$WORK/credential")" ] &&
	$S attest verify --evidence="$WORK/evidence-cred.json" --nonce=$nonce \
		--ak-name="$(cat "$WORK/ak")" --cert="$WORK/keys/cert.der" \
		--allow-runtime-events \
		--expect-credential="$(cat "$WORK/credential")" >"$WORK/report-cred" &&
	grep -qx "verdict: ok" "$WORK/report-cred" &&
	grep -q "^ok:   attestation key: activated the credential" "$WORK/report-cred" &&
	grep -q "^ok:   endorsement key: TCG default template" "$WORK/report-cred"
'

test_expect_success 'a credential expectation needs the pinned attestation key' '
	nonce=1112 &&
	$S attest verify --evidence="$WORK/evidence-cred.json" --nonce=$nonce \
		--cert="$WORK/keys/cert.der" --allow-runtime-events \
		--expect-credential="$(cat "$WORK/credential")" \
		>/dev/null 2>"$WORK/cred-unpinned.err"; rc=$? &&
	[ "$rc" = 2 ] &&
	grep -q "give --ak-name" "$WORK/cred-unpinned.err"
'

test_expect_success 'a wrong credential, a tampered blob and a foreign challenge are refused' '
	nonce=1112 &&
	! $S attest verify --evidence="$WORK/evidence-cred.json" --nonce=$nonce \
		--ak-name="$(cat "$WORK/ak")" --allow-runtime-events \
		--expect-credential="$(py "print(\"00\"*32)")" >"$WORK/report-cred2" &&
	grep -q "^FAIL: attestation key: activated the credential" "$WORK/report-cred2" &&
	sed "s/\"credential_blob\":\"\([0-9a-f]\{4\}\)[0-9a-f]\{4\}/\"credential_blob\":\"\10000/" \
		"$WORK/challenge.json" >"$WORK/challenge-tampered.json" &&
	! ./$R evidence $nonce "$WORK/challenge-tampered.json" >/dev/null 2>&1 &&
	sed "s/\"ak_name\":\"000b[0-9a-f]\{4\}/\"ak_name\":\"000b0000/" \
		"$WORK/challenge.json" >"$WORK/challenge-foreign.json" &&
	! ./$R evidence $nonce "$WORK/challenge-foreign.json" >/dev/null 2>&1
'

test_expect_success 'an RSA endorsement key protects and activates the challenge too' '
	out=$(./$R ek-public rsa) &&
	echo "$out" | grep -qx "rc=0" &&
	./helper/test-tpm-wire public "$(echo "$out" | field public)" |
		grep -q "^type=0x0001 attrs=0x000300b2 policy_len=32 sym=0x0006/128/0x0043" &&
	printf "{\"ak\":{\"name\":\"%s\"},\"ek\":{\"type\":\"rsa\",\"public\":\"%s\",\"name\":\"%s\"}}\n" \
		"$(cat "$WORK/ak")" "$(echo "$out" | field public)" \
		"$(echo "$out" | field name)" >"$WORK/rsa.json" &&
	$S attest challenge --evidence="$WORK/rsa.json" --trust-presented-ek \
		--out="$WORK/challenge-rsa.json" |
		sed -n "s/^credential: //p" >"$WORK/credential-rsa" &&
	nonce=1314 &&
	./$R evidence $nonce "$WORK/challenge-rsa.json" >"$WORK/evidence-rsa.json" &&
	[ "$(py "import json; d=json.load(open(\"$WORK/evidence-rsa.json\")); print(d[\"ek\"][\"type\"], d[\"credential\"][\"value\"])")" = "rsa $(cat "$WORK/credential-rsa")" ]
'

test_expect_success 'challenge refuses a key that is not an endorsement key' '
	py "import json; d=json.load(open(\"$WORK/evidence.json\")); d[\"ek\"]={\"type\":\"ecc\",\"public\":d[\"ak\"][\"public\"],\"name\":d[\"ak\"][\"name\"]}; open(\"$WORK/fake-ek.json\",\"w\").write(json.dumps(d))" &&
	! $S attest challenge --evidence="$WORK/fake-ek.json" --trust-presented-ek \
		--out="$WORK/challenge-fake.json" >"$WORK/fake.out" &&
	grep -q "^FAIL: endorsement key: TCG default template" "$WORK/fake.out" &&
	grep -qx "verdict: FAIL" "$WORK/fake.out" &&
	[ ! -e "$WORK/challenge-fake.json" ]
'

test_expect_success 'a recreated index is unwritable and no longer anchored' '
	out=$(./$R recreate) &&
	echo "$out" | grep -qx "rc=0" &&
	echo "$out" | grep -qx "written=0" &&
	[ "$(echo "$out" | field name)" != "$(cat "$WORK/name")" ] &&
	./$R extend-raw "$PAYLOAD" | grep -qx "rc=-19" &&
	./$R first-write "$PAYLOAD" | grep -qx "rc=-13" &&
	./$R status | grep -qx "tpm=1 defined=1 written=0 logged=1 anchored=0"
'

test_expect_success 'init refuses a second binding before the next TPM reset' '
	./$R init "$(cat "$WORK/init")" | grep -qx "rc=-17" &&
	[ "$(wc -l <"$WORK/eventlog")" = 3 ] &&
	./$R status | grep -qx "rebound=0"
'

test_expect_success 'a TPM reset clears the register; a late init binds it in the root file system' '
	rm -f "$WORK/tpm/volatile" &&
	./$R read | grep -qx "rc=-19" &&
	out=$(env -u SHIRUDO_INITRD_RELEASE ./$R init "$(cat "$WORK/init")") &&
	echo "$out" | grep -qx "rc=0" &&
	echo "$out" | grep -qx "reused=0" &&
	echo "$out" | grep -qx "bound_in=root" &&
	echo "$out" | grep -qx "phase_before=$Z" &&
	[ "$(echo "$out" | field name)" != "$(cat "$WORK/name")" ] &&
	[ "$(echo "$out" | field value)" = "$(sha "$Z$(cat "$WORK/init")")" ] &&
	./$R status | grep -qx "tpm=1 defined=1 written=1 logged=1 anchored=1" &&
	./$R status | grep -qx "rebound=0" &&
	python3 - "$WORK/eventlog" <<"PY"
import json, sys
inits = [json.loads(l) for l in open(sys.argv[1]) if json.loads(l)["type"] == "init"]
assert len(inits) == 2, inits
assert inits[0]["tpm_reset_count"] != inits[1]["tpm_reset_count"], inits
assert inits[0]["bound_in"] == "initrd" and inits[1]["bound_in"] == "root", inits
assert inits[0]["nv_writer_public"] == inits[1]["nv_writer_public"], inits
PY
'

test_expect_success 'a late binding is told apart by the phase value and the initrd requirement' '
	nonce=cafe &&
	./$R evidence $nonce >"$WORK/evidence2.json" &&
	$S attest verify --evidence="$WORK/evidence2.json" --nonce=$nonce \
		--ak-name="$(cat "$WORK/ak")" --cert="$WORK/keys/cert.der" \
		--strict-anchor >"$WORK/report6" &&
	grep -qx "verdict: ok" "$WORK/report6" &&
	grep -q "^note: binding: made in the root file system" "$WORK/report6" &&
	grep -q "^ok:   eventlog: one init record for this TPM reset (2 this boot)" "$WORK/report6" &&
	grep -q "^ok:   register: init record is of the TPM" "$WORK/report6" &&
	grep -q "^ok:   quote and certification are of one TPM reset" "$WORK/report6" &&
	! $S attest verify --evidence="$WORK/evidence2.json" --nonce=$nonce \
		--ak-name="$(cat "$WORK/ak")" --cert="$WORK/keys/cert.der" \
		--require-initrd --expect-bind-pcr=11=$PHASE >"$WORK/report6b" &&
	grep -q "^FAIL: binding: PCR 11 held the expected value" "$WORK/report6b" &&
	grep -q "^FAIL: binding: made while the initrd ran" "$WORK/report6b"
'

test_expect_success 'a second init record for one TPM reset fails status and verify' '
	nonce=f00d &&
	cp "$WORK/eventlog" "$WORK/eventlog.orig" &&
	tail -n 1 "$WORK/eventlog" >>"$WORK/eventlog" &&
	./$R status | grep -qx "rebound=1" &&
	$S status --json >"$WORK/status2.json" &&
	python3 - "$WORK/status2.json" <<"PY"
import json, sys
t = json.load(open(sys.argv[1]))["tpm"]
assert t["register_rebound"] is True, t
assert t["init_records"] == 3, t
assert t["chain_matches_eventlog"] is False, t
PY
	./$R evidence $nonce >"$WORK/evidence3.json" &&
	$S attest verify --evidence="$WORK/evidence3.json" --nonce=$nonce \
		--ak-name="$(cat "$WORK/ak")" --cert="$WORK/keys/cert.der" \
		>"$WORK/report7"; rc=$? &&
	[ "$rc" = 1 ] &&
	grep -q "^FAIL: eventlog: one init record for this TPM reset" "$WORK/report7" &&
	cp "$WORK/eventlog.orig" "$WORK/eventlog" &&
	./$R status | grep -qx "rebound=0"
'

test_expect_success 'an init record of another TPM reset fails verification' '
	nonce=cafe &&
	sed "s/\"tpm_reset_count\":[0-9]*/\"tpm_reset_count\":4000000000/g" \
		"$WORK/evidence2.json" >"$WORK/evidence4.json" &&
	$S attest verify --evidence="$WORK/evidence4.json" --nonce=$nonce \
		--ak-name="$(cat "$WORK/ak")" --cert="$WORK/keys/cert.der" \
		>"$WORK/report8"; rc=$? &&
	[ "$rc" = 1 ] &&
	grep -q "^FAIL: register: init record is of the TPM" "$WORK/report8"
'

test_done
