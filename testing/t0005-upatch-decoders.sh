#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0005 -- signed Lua decoders: `shirudo upatch info` reports the decoder
# metadata embedded in a .upatch, offline (no kernel, no root), and the
# decoder runs under the sandbox limits. Builds a tiny fentry program
# from a .bpf.c that declares a decoder manifest, signs it with a
# throwaway key, and exercises the decoder through the test helper.
# Needs clang + shirudo-build (skips otherwise).

cd "$(dirname "$0")"
. ./test-lib.sh

S=../shirudo
SHB=../tools/shirudo-build/shirudo-build

command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
[ -x "$S" ] || test_skip_all "shirudo not built"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built (make shirudo-build)"
[ -e ../vendor/linux/vmlinux.h ] || test_skip_all "no vendor/linux/vmlinux.h (build the tree)"
[ -e ../vendor/libbpf/bpf/bpf_helpers.h ] || test_skip_all "no vendored bpf headers"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/decoders"

cat > "$WORK/decoders/t0005.lua" <<'EOF'
function decode(input)
	if input.data.serialized_bytes == 997 then
		return string.rep("x", 64 * 1024 * 1024)
	end
	if input.data.serialized_bytes == 998 then
		return string.char(255)
	end
	if input.data.serialized_bytes == 999 then
		while true do end
	end
	return {
		schema = 1,
		records = {{ name = "bash", count = 5, ratio = 1.5,
			enabled = true, ids = {"7", "9"} }},
	}
end
EOF

# shirudo signs with ML-DSA-87 only (needs OpenSSL >= 3.5 to mint it).
openssl req -x509 -newkey ML-DSA-87 -nodes -keyout "$WORK/k.pem" \
	-outform DER -out "$WORK/c.der" -days 1 -subj "/CN=t0005" \
	>/dev/null 2>&1 || test_skip_all "openssl ML-DSA keygen failed (needs OpenSSL >= 3.5)"

cat > "$WORK/t.bpf.c" <<'EOF'
// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "shirudo_decoder.h"

char _license[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} t0005_map SEC(".maps");

const struct shirudo_decoder_manifest t0005_decoder SEC(".rodata") = {
	.magic = SHIRUDO_DECODER_MANIFEST_MAGIC,
	.version = SHIRUDO_UPATCH_DECODER_VERSION,
	.language = SHIRUDO_UPATCH_DECODER_LANG_LUA,
	.api_version = 1,
	.input_format = SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1,
	.export_signal = SHIRUDO_UPATCH_DECODER_EXPORT_LOG,
	.upatch = "t0005",
	.map = "t0005_map",
	.source = "decoders/t0005.lua",
	.entrypoint = "decode",
};

SEC("fentry/do_nanosleep")
int BPF_PROG(t0005_marker_fn)
{
	return 0;
}
EOF

case "$SHB" in
/*) B="$SHB" ;;
*)  B="$(pwd)/$SHB" ;;
esac
( cd .. && "$B" "$WORK/t.bpf.c" -o "$WORK/u.upatch" --vmlinux vendor/linux/vmlinux.h \
	--name t0005 --key "$WORK/k.pem" --cert "$WORK/c.der" ) >/dev/null 2>&1 ||
	test_skip_all "build failed (clang/headers?)"

test_expect_success 'upatch info --json reports signed decoder metadata' '
	"$S" upatch info "$WORK/u.upatch" --json 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
decoders = d.get(\"decoders\")
assert isinstance(decoders, list), decoders
assert len(decoders) == 1, decoders
dec = decoders[0]
assert dec[\"language\"] == \"lua\", dec
assert dec[\"input_format\"] == \"shirudo.map.v1\", dec
assert dec[\"upatch\"] == \"t0005\", dec
assert dec[\"map\"] == \"t0005_map\", dec
assert dec[\"source_file\"] == \"decoders/t0005.lua\", dec
assert dec[\"entrypoint\"] == \"decode\", dec
assert dec[\"source_len\"] > 0, dec
"
'

test_expect_success 'signed Lua decoder returns JSON' '
	./helper/test-upatch-decode json "$WORK/u.upatch" |
	python3 -c "
import json, sys
d = json.load(sys.stdin)
assert d == {\"schema\": 1, \"records\": [{\"name\": \"bash\",
    \"count\": 5, \"ratio\": 1.5, \"enabled\": True,
    \"ids\": [\"7\", \"9\"]}]}, d
"
'

test_expect_success 'signed Lua decoder maps tables to OTLP AnyValue' '
	./helper/test-upatch-decode otel "$WORK/u.upatch" |
	python3 -c "
import json, sys
d = json.load(sys.stdin)
values = d[\"kvlistValue\"][\"values\"]
fields = {item[\"key\"]: item[\"value\"] for item in values}
assert fields[\"schema\"] == {\"intValue\": \"1\"}, fields
record = fields[\"records\"][\"arrayValue\"][\"values\"][0]
record = {item[\"key\"]: item[\"value\"]
          for item in record[\"kvlistValue\"][\"values\"]}
assert record[\"name\"] == {\"stringValue\": \"bash\"}, record
assert record[\"count\"] == {\"intValue\": \"5\"}, record
assert record[\"ratio\"] == {\"doubleValue\": 1.5}, record
assert record[\"enabled\"] == {\"boolValue\": True}, record
assert record[\"ids\"] == {\"arrayValue\": {\"values\": [
    {\"stringValue\": \"7\"}, {\"stringValue\": \"9\"}]}}, record
"
'

test_expect_success 'Lua decoder enforces instruction and memory limits' '
	if ./helper/test-upatch-decode loop "$WORK/u.upatch"; then false; fi &&
	if ./helper/test-upatch-decode memory "$WORK/u.upatch"; then false; fi
'

test_expect_success 'Lua decoder output replaces invalid UTF-8' '
	[ "$(./helper/test-upatch-decode utf8 "$WORK/u.upatch")" = \
	  "\"\\ufffd\"" ]
'

python3 - "$WORK/u.upatch" "$WORK" <<'PY'
import pathlib, struct, sys
src, root = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
original = bytearray(src.read_bytes())
data_off, data_len = struct.unpack_from("<II", original, 328)
trailer = data_off + data_len - 16
decoder_off, decoder_len = struct.unpack_from("<II", original, trailer + 8)
blob, entry = data_off + decoder_off, data_off + decoder_off + 16
def write(name, changes):
    data = bytearray(original)
    for off, fmt, value in changes:
        struct.pack_into(fmt, data, off, value)
    (root / name).write_bytes(data)
write("bad-decoder-trailer", [(trailer, "<I", 0)])
write("bad-decoder-offset", [(trailer + 8, "<I", 0xffffffff)])
write("bad-decoder-count", [(blob + 8, "<I", 0xffffffff)])
write("bad-decoder-source-range",
      [(entry + 192, "<I", decoder_len), (entry + 196, "<I", 1)])
data = bytearray(original)
data[entry + 96:entry + 160] = b"X" * 64
(root / "bad-decoder-string").write_bytes(data)
PY
cat >"$WORK/check-no-decoder.py" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert not doc.get("decoders"), doc
PY
test_expect_success 'malformed decoder trailer and entries are treated as absent' '
	for f in bad-decoder-trailer bad-decoder-offset bad-decoder-count \
		 bad-decoder-source-range bad-decoder-string; do
		"$S" upatch info "$WORK/$f" --json >"$WORK/info.json" 2>/dev/null &&
		python3 "$WORK/check-no-decoder.py" "$WORK/info.json" || exit 1
	done
'
test_done
