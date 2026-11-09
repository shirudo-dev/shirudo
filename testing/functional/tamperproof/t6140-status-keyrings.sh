#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6140 -- status reports both keyrings init froze as the kernel holds
# them: the serials keyctl names, each certificate with the key that
# holds it, the config certificate the runtime image carries, and no
# link init did not freeze.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v keyctl >/dev/null 2>&1 || test_skip_all "no keyctl"

W=$(mktemp -d) || exit 1
trap 'rm -rf "$W"' EXIT
"$SHIRUDO_BIN" status --json >"$W/status.json" 2>/dev/null ||
	test_skip_all "status --json failed"
RING=$(report_field keyring_serial <"$W/status.json")
case "$RING" in
	''|None|0|-*) test_skip_all "no anchor keyring frozen this boot" ;;
esac
DM_RING=$(awk '$8 == "keyring" && $9 == ".dm-verity:" { print $1 }' /proc/keys)
[ -n "$DM_RING" ] || test_skip_all "no dm-verity keyring"
DM_RING=$((0x$DM_RING))
RUNTIME_CONF=/run/shirudo/runtime/etc/shirudo/shirudo.conf

test_expect_success 'both keyrings are the ones init froze, with nothing added' '
	python3 - "$W/status.json" "$RING" "$DM_RING" <<"PY"
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
rings = (("bpf_keyring", int(sys.argv[2])),
         ("dm_verity_keyring", int(sys.argv[3])))
for key, serial in rings:
    k = d[key]
    assert k["present"] and k["serial_matches"], (key, k)
    assert k["serial"] == serial == k["serial_pinned"], (key, k)
    assert k["other_links"] == [], (key, k["other_links"])
sealed = [c for c in d["conditions"] if c["type"] == "KeyringSealed"][0]
assert sealed["status"] == "OK", sealed
assert sealed["detail"] == "bpf serial %d, dm-verity serial %d, pins match" % (
    rings[0][1], rings[1][1]), sealed
assert d["status"] != "tampered", d["status"]
PY
'

test_expect_success 'each key status names is the one keyctl lists' '
	python3 - "$W/status.json" "$RING" "$DM_RING" <<"PY"
import json, subprocess, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
def links(ring):
    out = subprocess.run(["keyctl", "rlist", ring], check=True,
                         capture_output=True, text=True).stdout
    return sorted(int(s) for s in out.split())
bpf = d["bpf_keyring"]
held = sorted(c["key_serial"] for c in bpf["certs"] if c["key_serial"])
assert held and held == links(sys.argv[2]), (held, links(sys.argv[2]))
assert any(c["primary"] and c["key_serial"] for c in bpf["certs"]), bpf
assert d["certs_enrolled"] == len(held), d["certs_enrolled"]
for c in bpf["certs"]:
    assert c["frozen"] is (True if c["key_serial"] else None), c
    assert c["subject"] and c["algorithm"] and c["not_before"], c
dmv = d["dm_verity_keyring"]
assert dmv["certs"], dmv["certs"]
for c in dmv["certs"]:
    assert c["config"] and c["frozen"] is True, c
held = sorted(c["key_serial"] for c in dmv["certs"])
assert held == links(sys.argv[3]), (held, links(sys.argv[3]))
PY
'

test_expect_success 'config certificates are the exact set the runtime image designates' '
	[ -s "$RUNTIME_CONF" ] &&
	python3 - "$W/status.json" "$RUNTIME_CONF" <<"PY"
import hashlib, json, sys
from pathlib import Path
d = json.load(open(sys.argv[1], encoding="utf-8"))
paths = [line.split("=", 1)[1].strip()
         for line in Path(sys.argv[2]).read_text().splitlines()
         if line.split("=", 1)[0].strip() == "config.verification_key"]
expected = {hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in paths}
actual = {cert["sha256"] for cert in d["dm_verity_keyring"]["certs"]}
assert expected and len(expected) == len(paths) and expected == actual, (expected, actual)
PY
'

test_expect_success 'the report shows each certificate with its frozen key' '
	"$SHIRUDO_BIN" status --show-full >"$W/status.txt" &&
	grep -qx "Keyring (.bpf):" "$W/status.txt" &&
	grep -qx "Keyring (.dm-verity):" "$W/status.txt" &&
	[ "$(grep -c "^  Frozen serial: .*  (matches)$" "$W/status.txt")" = 2 ] &&
	grep -Eqx "    [0-9a-f]{64}  \(config\)" "$W/status.txt" &&
	grep -Eqx "    [0-9a-f]{64}  \(primary\)" "$W/status.txt" &&
	grep -Eq "^      key [0-9]+  .*  \(frozen\)$" "$W/status.txt" &&
	! grep -q "not frozen\|Other links:" "$W/status.txt"
'

test_done
