#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./test-lib.sh

H=${SHIRUDO_TEST_CONFIG_ATTEST_HELPER:-$(pwd)/helper/test-config-attest}
U=${SHIRUDO_TEST_CONFIG_HELPER:-$(pwd)/helper/test-config-update}
R=$(pwd)/helper/test-register
SIM=$(pwd)/helper/tpmsim-cmd
S=${SHIRUDO_IMAGE_TEST_SHIRUDO:-$(pwd)/helper/test-register-cli}
. ./functional/tpm/register-lib.sh
for helper in "$H" "$U" "$R" "$SIM" "$S"; do
	[ -x "$helper" ] || test_skip_all "missing helper: $helper"
done
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
WORK=$(mktemp -d)
cleanup() {
	result=$?
	register_writer_stop || result=1
	rm -rf "$WORK"
	exit "$result"
}
trap cleanup EXIT HUP INT TERM
export SHIRUDO_TPM_TCTI="cmd:exec $SIM $WORK/tpm"
export SHIRUDO_EVENTLOG_PATH="$WORK/eventlog"
export SHIRUDO_KEYS_DIR="$WORK/keys"
export SHIRUDO_INITRD_RELEASE="$WORK/initrd-release"
register_writer_start || exit 1
mkdir -m 700 "$WORK/config" "$WORK/keys"
head -c 700 /dev/urandom >"$WORK/keys/cert.der"
: >"$WORK/initrd-release"
NONCE=0102030405060708090a0b0c0d0e0f10
ROOT_A=$(python3 -c 'print("41" * 32)')
ROOT_B=$(python3 -c 'print("42" * 32)')

field() {
	python3 -c 'import json,sys; d=json.load(open(sys.argv[1]));
for key in sys.argv[2].split("."): d=d[int(key)] if isinstance(d, list) else d[key]
print(d)' "$1" "$2"
}

verify() {
	"$S" attest verify --evidence="$1" --nonce="$NONCE" \
		--ak-name="$(field "$WORK/b.json" ak.name)" \
		--expect-chain="$CHAIN" --strict-anchor --require-initrd \
		--expect-config-root="$ROOT_B" --expect-config-pcr=15
}

fixture_failed() {
	test_expect_success "$*" "false"
	test_done
}

INIT=$("$S" attest predict --cert="$WORK/keys/cert.der" | sed -n 's/^init_event: //p')
[ -n "$INIT" ] && "$R" init "$INIT" >"$WORK/nv-init" ||
	fixture_failed "TPM register fixture initialization failed"
CHAIN=$(sed -n 's/^value=//p' "$WORK/nv-init")
SHIRUDO_TEST_CONFIG_TPM=1 "$U" "$WORK/config" boot A >/dev/null ||
	fixture_failed "TPM config fixture boot failed"
"$H" render "$WORK/config" "$NONCE" >"$WORK/a.json" ||
	fixture_failed "config evidence fixture collection failed"
SHIRUDO_TEST_CONFIG_TPM=1 "$U" "$WORK/config" update B >/dev/null ||
	fixture_failed "TPM config fixture update failed"
"$H" render "$WORK/config" "$NONCE" >"$WORK/b.json" ||
	fixture_failed "updated config evidence fixture collection failed"

RESET=$(field "$WORK/b.json" config.reset_count)
RESTART=$(field "$WORK/b.json" config.restart_count)
PCR_VALUE=$(field "$WORK/b.json" pcrs.2.value)

test_expect_success 'collector adds the reserved config PCR and includes this boot selections' '
	python3 - "$WORK/b.json" <<"PY"
import json, sys
d = json.load(open(sys.argv[1])); c = d["config"]
assert d["pcr_mask"] == (1 << 9) | (1 << 11) | (1 << 15)
assert c["pcr"] == 15 and c["schema"] == 1
assert set(c) == {"schema", "pcr", "reset_count", "restart_count", "initial_pcr", "events"}
assert [event["kind"] for event in c["events"]] == [1, 2]
assert c["events"][-1]["root_hash"] == "42" * 32
PY
'

test_expect_success 'genuine TPM evidence verifies against the operator root and PCR choice' '
	verify "$WORK/b.json" >"$WORK/verified" &&
	grep -q "^  OK    config: config root history matches the quoted PCR" "$WORK/verified" &&
	grep -qx "  OK    register after quote: same index and value on both sides of the PCR quote" "$WORK/verified" &&
	grep -qx "verdict: ok" "$WORK/verified"
'

test_expect_success 'the TPM signatures order the two register readings around the quote' '
	python3 - "$WORK/b.json" "$NONCE" <<"PY"
import hashlib, json, sys
with open(sys.argv[1]) as source:
    d = json.load(source)
def digest(s):
    return hashlib.sha256(bytes.fromhex(s)).digest()
def extra(s):
    attest = bytes.fromhex(s)
    pos = 8 + int.from_bytes(attest[6:8], "big")
    size = int.from_bytes(attest[pos:pos+2], "big")
    return attest[pos+2:pos+2+size]
r, q = d["register"], d["quote"]
assert d["schema"] == 1
assert extra(r["attest"]) == bytes.fromhex(sys.argv[2])
assert extra(q["attest"]) == hashlib.sha256(digest(r["signature"]) + bytes(32)).digest()
assert extra(r["after_attest"]) == digest(q["signature"])
PY
'

test_expect_success 'the verifier requires the closing TPM certification' '
	python3 - "$WORK/b.json" "$WORK/incomplete.json" <<"PY" &&
import json, sys
with open(sys.argv[1]) as source:
    d = json.load(source)
del d["register"]["after_signature"]
with open(sys.argv[2], "w") as output:
    json.dump(d, output)
PY
	! verify "$WORK/incomplete.json" >/dev/null
'

test_expect_success 'the standalone bounded parser replays the same signed-PCR selection' '
	"$H" replay "$WORK/b.json" "$ROOT_B" 15 "$RESET" "$RESTART" "$PCR_VALUE" >/dev/null
'

test_expect_success 'the earlier boot selection also verifies against its correct expected root' '
	"$S" attest verify --evidence="$WORK/a.json" --nonce="$NONCE" \
		--ak-name="$(field "$WORK/a.json" ak.name)" --expect-chain="$CHAIN" \
		--expect-config-root="$ROOT_A" --expect-config-pcr=15 >"$WORK/a-verified" &&
	grep -qx "verdict: ok" "$WORK/a-verified"
'

test_expect_success 'wrong expected roots, PCR choices and incomplete approval flags are refused' '
	! "$S" attest verify --evidence="$WORK/b.json" --nonce="$NONCE" \
		--ak-name="$(field "$WORK/b.json" ak.name)" --expect-chain="$CHAIN" \
		--expect-config-root="$ROOT_A" --expect-config-pcr=15 >/dev/null &&
	! "$S" attest verify --evidence="$WORK/b.json" --nonce="$NONCE" \
		--ak-name="$(field "$WORK/b.json" ak.name)" --expect-chain="$CHAIN" \
		--expect-config-root="$ROOT_B" --expect-config-pcr=14 >/dev/null &&
	! "$S" attest verify --evidence="$WORK/b.json" --nonce="$NONCE" \
		--expect-config-root="$ROOT_B" >/dev/null
'

test_expect_success 'without operator approval the report names its limit explicitly' '
	"$S" attest verify --evidence="$WORK/b.json" --nonce="$NONCE" \
		--ak-name="$(field "$WORK/b.json" ak.name)" --expect-chain="$CHAIN" \
		>"$WORK/unapproved" &&
	grep -q "^  NOTE  config root has no operator approval" "$WORK/unapproved" &&
	grep -q "operation completion depends on trusted runtime guards" "$WORK/unapproved"
'

python3 - "$WORK/b.json" "$WORK" <<'PY'
from copy import deepcopy
from pathlib import Path
import json, sys
base = json.load(open(sys.argv[1])); root = Path(sys.argv[2])

def save(name, change):
    d = deepcopy(base); change(d); (root / ("bad-" + name + ".json")).write_text(json.dumps(d))

def event(d):
    return d["config"]["events"][-1]

def flip_hex(value):
    return ("0" if value[0] != "0" else "1") + value[1:]

save("event-root", lambda d: event(d).__setitem__("root_hash", flip_hex(event(d)["root_hash"])))
for key in ("sequence", "kind"):
    save("event-" + key, lambda d, key=key: event(d).__setitem__(key, event(d)[key] + 1))
for key in ("schema", "reset_count", "pcr"):
    save("meta-" + key, lambda d, key=key: d["config"].__setitem__(key, d["config"][key] + 1))
save("initial-pcr", lambda d: d["config"].__setitem__("initial_pcr", "55" * 32))
save("missing-field", lambda d: event(d).pop("root_hash"))
save("missing-config", lambda d: d.pop("config"))
save("missing-boot", lambda d: d["config"]["events"].pop(0))
save("duplicate", lambda d: d["config"]["events"].append(deepcopy(event(d))))
save("reordered", lambda d: d["config"]["events"].reverse())
save("null", lambda d: d.__setitem__("config", None))
save("trailing-root", lambda d: event(d).__setitem__("root_hash", event(d)["root_hash"] + "00"))
save("too-many", lambda d: d["config"].__setitem__("events", d["config"]["events"] * 2049))
save("quoted-pcr", lambda d: next(p for p in d["pcrs"] if p["index"] == 15).__setitem__("value", "55" * 32))
PY

for document in "$WORK"/bad-*.json; do
	label=${document##*/}
	test_expect_success "tampered evidence $label is refused" '
		! verify '"$document"' >/dev/null &&
		if [ '"$label"' != bad-quoted-pcr.json ]; then
			! "$H" replay '"$document"' "$ROOT_B" 15 "$RESET" "$RESTART" "$PCR_VALUE" >/dev/null
		fi
	'
done

test_expect_success 'a config string longer than its field is a malformed document' '
	status=0 &&
	verify "$WORK/bad-trailing-root.json" >/dev/null \
		2>"$WORK/trailing-root-err" || status=$? &&
	test "$status" -eq 2 &&
	grep -q "is not a shirudo evidence document" "$WORK/trailing-root-err"
'

test_expect_success 'an inconsistent config history names the check it fails' '
	! verify "$WORK/bad-reordered.json" >"$WORK/reordered-report" 2>/dev/null &&
	grep -qx "  FAIL  config: the events are one boot event followed by updates in sequence" \
		"$WORK/reordered-report" &&
	grep -qx "verdict: fail" "$WORK/reordered-report"
'

# An isolated extend index with an unwritten branch for its first extend
# and the same written branch config updates use on a provisioned target.
provision_config_nv() (
	set -e
	export TPM2TOOLS_TCTI="$SHIRUDO_TPM_TCTI"
	cd "$WORK"
	for written in c s; do
		tpm2_startauthsession -S session
		tpm2_policynvwritten -S session -L "policy-$written" "$written"
		tpm2_flushcontext session
	done
	tpm2_startauthsession -S session
	tpm2_policyor -S session -L policy sha256:policy-c,policy-s
	tpm2_flushcontext session
	tpm2_nvdefine -C o -s 32 -a "nt=extend|authread|policywrite" \
		-L policy 0x01818e04
	tpm2_startauthsession --policy-session -S session
	tpm2_policynvwritten -S session c
	tpm2_policyor -S session sha256:policy-c,policy-s
	head -c 32 /dev/zero > zero
	tpm2_nvextend 0x01818e04 -P session:session -i zero
	tpm2_flushcontext session
)

test_expect_success 'both NV registers are certified across the same PCR quote' '
	mkdir -m 700 "$WORK/config-nv" &&
	provision_config_nv &&
	SHIRUDO_TEST_CONFIG_TPM=1 "$U" "$WORK/config-nv" boot A 25267716 &&
	"$H" render "$WORK/config-nv" "$NONCE" >"$WORK/nvpcr.json" &&
	"$S" attest verify --evidence="$WORK/nvpcr.json" --nonce="$NONCE" \
		--ak-name="$(field "$WORK/b.json" ak.name)" --expect-chain="$CHAIN" \
		--expect-config-root="$ROOT_A" \
		--expect-config-nvpcr="$(field "$WORK/nvpcr.json" config_nvpcr.name)" \
		>"$WORK/nvpcr-report" &&
	grep -q "^  OK    config NvPCR after quote: same index and value" "$WORK/nvpcr-report" &&
	grep -qx "verdict: ok" "$WORK/nvpcr-report"
'

test_expect_success 'pending effects prevent evidence collection despite a measured selection' '
	! SHIRUDO_TEST_CONFIG_TPM=1 SHIRUDO_TEST_CONFIG_ACTIVATE_FAIL=1 \
		"$U" "$WORK/config" update C >/dev/null &&
	! "$H" render "$WORK/config" "$NONCE" >"$WORK/pending.json" &&
	test ! -s "$WORK/pending.json" &&
	! SHIRUDO_TEST_CONFIG_TPM=1 "$U" "$WORK/config" boot C >/dev/null &&
	! SHIRUDO_TEST_CONFIG_TPM=1 "$U" "$WORK/config" update C >/dev/null
'

test_expect_success 'evidence without config verifies the patch register alone' '
	"$R" evidence "$NONCE" >"$WORK/legacy.json" &&
	"$S" attest verify --evidence="$WORK/legacy.json" --nonce="$NONCE" \
		--ak-name="$(field "$WORK/legacy.json" ak.name)" \
		--expect-chain="$CHAIN" >"$WORK/legacy-report" &&
	grep -qx "verdict: ok" "$WORK/legacy-report" &&
	! verify "$WORK/legacy.json" >/dev/null
'

test_expect_success 'real TPM reset exports only the fresh BOOT selection' '
	rm "$WORK/tpm/volatile" &&
	"$R" init "$INIT" >"$WORK/nv-reset" &&
	SHIRUDO_TEST_CONFIG_TPM=1 "$U" "$WORK/config" boot C >/dev/null &&
	"$H" render "$WORK/config" "$NONCE" >"$WORK/fresh.json" &&
	python3 - "$WORK/fresh.json" <<"PY"
import json, sys
d = json.load(open(sys.argv[1])); c = d["config"]
assert len(c["events"]) == 1 and c["events"][0]["kind"] == 1
assert c["initial_pcr"] == "00" * 32
assert c["events"][0]["root_hash"] == "43" * 32
PY
'

test_done
