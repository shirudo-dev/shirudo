#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./test-lib.sh

H=${SHIRUDO_IMAGE_TEST_HELPER:-./helper/test-config-image}
S=${SHIRUDO_IMAGE_TEST_SHIRUDO:-../shirudo}
B=${SHIRUDO_IMAGE_TEST_BUILDER:-../tools/shirudo-build/shirudo-build}
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
ZERO=0000000000000000000000000000000000000000000000000000000000000000
SALT=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

flip()
{
	python3 - "$1" "$2" <<'PYTEST'
import sys
p, n = sys.argv[1], int(sys.argv[2])
with open(p, "r+b") as f:
    f.seek(n)
    b = f.read(1)
    f.seek(n)
    f.write(bytes([b[0] ^ 1]))
PYTEST
}

copy_bundle()
{
	for suffix in .img .verity .roothash .p7s; do
		rm -f "$W/change$suffix" &&
		cp "$W/good$suffix" "$W/change$suffix" || return
	done
}

test_expect_success 'operator image tools are available' '
	[ -x "$H" ] && [ -x "$S" ] && [ -x "$B" ] &&
	command -v python3 >/dev/null 2>&1 &&
	command -v mkfs.ext4 >/dev/null 2>&1 &&
	command -v debugfs >/dev/null 2>&1 &&
	command -v veritysetup >/dev/null 2>&1
'
if [ ! -x "$H" ] || [ ! -x "$S" ] || [ ! -x "$B" ] ||
   ! command -v python3 >/dev/null 2>&1 ||
   ! command -v mkfs.ext4 >/dev/null 2>&1 ||
   ! command -v debugfs >/dev/null 2>&1 ||
   ! command -v veritysetup >/dev/null 2>&1; then
	test_done
fi
REAL_VERITY=$(command -v veritysetup)
"$S" genkey --keys-dir "$W/keys" >/dev/null 2>&1 || exit 1
"$S" genkey --keys-dir "$W/other" >/dev/null 2>&1 || exit 1

verify()
{
	SHIRUDO_BUILD="$B" "$S" image verify "$1" --cert "$2"
}

test_expect_success 'standard veritysetup format matches signed images at every level boundary' '
	for blocks in 1 2 127 128 129 16384 16385; do
		truncate -s "$((blocks * 4096))" "$W/data" &&
		"$B" image build "$W/data" -o "$W/level-$blocks" \
			--keys-dir "$W/keys" --salt "$SALT" >"$W/root-$blocks" &&
		verify "$W/level-$blocks" "$W/keys/cert.der" &&
		veritysetup format --format=1 --hash=sha256 \
			--data-block-size=4096 --hash-block-size=4096 --salt="$SALT" \
			--root-hash-file="$W/standard-root" "$W/data" "$W/standard-tree" &&
		[ "$(cat "$W/root-$blocks")" = "$(cat "$W/standard-root")" ] &&
		cmp -i 4096 "$W/level-$blocks.verity" "$W/standard-tree" || exit 1
		rm -f "$W/standard-tree" "$W/standard-root"
	done
'

test_expect_success 'empty, unaligned and oversized images are refused' '
	truncate -s 0 "$W/bad" &&
	! "$B" image build "$W/bad" -o "$W/bad-image" --keys-dir "$W/keys" &&
	truncate -s 4097 "$W/bad" &&
	! "$B" image build "$W/bad" -o "$W/bad-image" --keys-dir "$W/keys" &&
	truncate -s 1099511631872 "$W/bad" &&
	! "$B" image build "$W/bad" -o "$W/bad-image" --keys-dir "$W/keys"
'

truncate -s 528384 "$W/data"
test_expect_success 'signed image builder produces the test fixture' '
	"$B" image build "$W/data" -o "$W/good" --keys-dir "$W/keys" \
		--salt "$ZERO" >"$W/root" &&
	cp "$W/good.verity" "$W/header"
'

test_expect_success 'standard superblock rejects truncation and unsupported format fields' '
	python3 - "$W/header" "$W" <<'PYTEST'
from pathlib import Path
import struct, sys
b = Path(sys.argv[1]).read_bytes()
d = Path(sys.argv[2])
for i in [0, 8, 12, 32, 64, 68, 80]:
    v = bytearray(b)
    v[i] ^= 1
    (d / ("invalid-%d" % i)).write_bytes(v)
(d / "short").write_bytes(b[:511])
v = bytearray(b)
struct.pack_into("<Q", v, 72, (1 << 64) - 1)
(d / "overflow").write_bytes(v)
PYTEST
	for f in "$W"/invalid-* "$W/short" "$W/overflow"; do
		! "$H" decode "$f" || exit 1
	done
'

test_expect_success 'root files contain exactly 64 lowercase hex bytes' '
	[ "$(wc -c <"$W/good.roothash")" -eq 64 ] &&
	for value in short uppercase newline nonhex trailing; do
		copy_bundle && python3 - "$W/change.roothash" "$value" <<'PYTEST'
from pathlib import Path
import sys
p = Path(sys.argv[1]); b = p.read_bytes()
b = {"short": b[:-1], "uppercase": b.upper(), "newline": b + b"\n",
     "nonhex": b"g" + b[1:], "trailing": b + b"0"}[sys.argv[2]]
p.write_bytes(b)
PYTEST
		! verify "$W/change" "$W/keys/cert.der" || exit 1
	done
'

test_expect_success 'standard verification detects data and used or padding hash corruption' '
	copy_bundle && flip "$W/change.img" 4095 &&
	! verify "$W/change" "$W/keys/cert.der" &&
	copy_bundle && flip "$W/change.verity" 8191 &&
	! verify "$W/change" "$W/keys/cert.der" &&
	copy_bundle && flip "$W/change.verity" 12288 &&
	! verify "$W/change" "$W/keys/cert.der"
'

test_expect_success 'exact image and hash sizes are enforced before standard verification' '
	for spec in img:524288 img:532480 verity:12288 verity:20480; do
		copy_bundle && truncate -s "${spec#*:}" "$W/change.${spec%:*}" &&
		! verify "$W/change" "$W/keys/cert.der" || exit 1
	done
'

test_expect_success 'valid detached ML-DSA-87 config signature verifies' '
	verify "$W/good" "$W/keys/cert.der" >"$W/verified-root" &&
	cmp "$W/root" "$W/verified-root" &&
	! verify "$W/good" "$W/other/cert.der"
'

test_expect_success 'root and signature tampering are refused' '
	copy_bundle && flip "$W/change.roothash" 0 &&
	! verify "$W/change" "$W/keys/cert.der" &&
	copy_bundle && flip "$W/change.p7s" 100 &&
	! verify "$W/change" "$W/keys/cert.der" &&
	copy_bundle && truncate -s 100 "$W/change.p7s" &&
	! verify "$W/change" "$W/keys/cert.der" &&
	copy_bundle && printf x >>"$W/change.p7s" &&
	! verify "$W/change" "$W/keys/cert.der" &&
	copy_bundle && cat "$W/good.p7s" >>"$W/change.p7s" &&
	! verify "$W/change" "$W/keys/cert.der"
'

test_expect_success 'signed images still fail on data/hash tampering and symlinks' '
	copy_bundle && flip "$W/change.img" 0 &&
	! verify "$W/change" "$W/keys/cert.der" &&
	copy_bundle && flip "$W/change.verity" 0 &&
	! verify "$W/change" "$W/keys/cert.der" &&
	copy_bundle && rm "$W/change.img" && ln -s "$W/good.img" "$W/change.img" &&
	! verify "$W/change" "$W/keys/cert.der"
'

test_expect_success 'runtime acceptance uses only the exact UKI root, independent of packaging hint' '
	"$B" image build "$W/data" -o "$W/runtime" --kind runtime \
		--keys-dir "$W/keys" --salt "$ZERO" >"$W/runtime-root" &&
	"$H" root "$W/runtime" "$(cat "$W/runtime-root")" &&
	! "$H" root "$W/runtime" "$ZERO" &&
	"$H" root "$W/good" "$(cat "$W/root")" &&
	rm "$W/runtime.p7s" &&
	"$H" root "$W/runtime" "$(cat "$W/runtime-root")"
'

test_expect_success 'builder never overwrites existing outputs and cleans partial output' '
	printf sentinel >"$W/existing.roothash" &&
	! "$B" image build "$W/data" -o "$W/existing" --keys-dir "$W/keys" &&
	[ "$(cat "$W/existing.roothash")" = sentinel ] &&
	[ ! -e "$W/existing.img" ] && [ ! -e "$W/existing.verity" ] &&
	[ ! -e "$W/existing.p7s" ]
'

test_expect_success 'failed format, signing or verification leaves no output files' '
	mkdir "$W/build-wrapper" &&
	ln -s "$(pwd)/fixtures/image-veritysetup-failure.sh" "$W/build-wrapper/veritysetup" &&
	for stage in format verify; do
		! PATH="$W/build-wrapper:$PATH" IMAGE_BUILD_FAILURE="$stage" REAL_VERITY="$REAL_VERITY" \
			"$B" image build "$W/data" -o "$W/failed-$stage" --keys-dir "$W/keys" || exit 1
	done &&
	! "$B" image build "$W/data" -o "$W/failed-sign" \
		--key "$W/missing-key" --cert "$W/keys/cert.der" &&
	for stage in format sign verify; do
		for suffix in img verity roothash p7s; do
			[ ! -e "$W/failed-$stage.$suffix" ] || exit 1
		done
	done &&
	[ -z "$(find "$W" -name ".shirudo-image.*" -print -quit)" ]
'

test_expect_success 'a late output conflict preserves that file and removes partial output' '
	! PATH="$W/build-wrapper:$PATH" IMAGE_BUILD_FAILURE=publish REAL_VERITY="$REAL_VERITY" \
		IMAGE_OUTPUT="$W/late" "$B" image build "$W/data" -o "$W/late" --keys-dir "$W/keys" &&
	[ "$(cat "$W/late.roothash")" = sentinel ] &&
	[ ! -e "$W/late.img" ] && [ ! -e "$W/late.verity" ] && [ ! -e "$W/late.p7s" ] &&
	[ -z "$(find "$W" -name ".shirudo-image.*" -print -quit)" ]
'

test_expect_success 'installed helper finds the image scripts beside it' '
	mkdir -p "$W/operator/gen-image" &&
	cp "$B" "$W/operator/shirudo-build" &&
	cp ../tools/gen-image/shirudo-gen-* ../tools/gen-image/common.sh \
		../tools/gen-image/runtime-service*.conf.in "$W/operator/gen-image/" &&
	"$W/operator/shirudo-build" image build "$W/data" -o "$W/installed" --keys-dir "$W/keys" &&
	verify "$W/installed" "$W/keys/cert.der"
'

test_expect_success 'offline verification retains its authenticated file descriptors' '
	copy_bundle && mkdir "$W/wrapper" &&
	printf "%s\n" "#!/bin/sh" \
		"mv \"\$IMAGE_PREFIX.img\" \"\$IMAGE_PREFIX.saved-img\"" \
		"mv \"\$IMAGE_PREFIX.verity\" \"\$IMAGE_PREFIX.saved-tree\"" \
		"printf bad >\"\$IMAGE_PREFIX.img\"" \
		"printf bad >\"\$IMAGE_PREFIX.verity\"" \
		"exec \"\$REAL_VERITY\" \"\$@\"" >"$W/wrapper/veritysetup" &&
	chmod +x "$W/wrapper/veritysetup" &&
	PATH="$W/wrapper:$PATH" IMAGE_PREFIX="$W/change" REAL_VERITY="$REAL_VERITY" \
		SHIRUDO_BUILD="$B" "$S" image verify "$W/change" --cert "$W/keys/cert.der" &&
	[ "$(cat "$W/change.img")" = bad ]
'

test_expect_success 'missing veritysetup fails clearly and removes incomplete build output' '
	mkdir "$W/empty-path" &&
	! PATH="$W/empty-path" "$B" image build "$W/data" -o "$W/missing-tool" \
		--keys-dir "$W/keys" >"$W/missing.out" 2>"$W/missing.err" &&
	grep -q veritysetup "$W/missing.err" &&
	[ ! -e "$W/missing-tool.img" ] && [ ! -e "$W/missing-tool.verity" ] &&
	[ ! -e "$W/missing-tool.roothash" ] && [ ! -e "$W/missing-tool.p7s" ]
'

test_expect_success 'offline verification requires the operator helper and veritysetup' '
	! SHIRUDO_BUILD="$W/no-helper" "$S" image verify "$W/good" \
		--cert "$W/keys/cert.der" >"$W/no-helper.out" 2>"$W/no-helper.err" &&
	grep -q operator-only "$W/no-helper.err" &&
	! PATH="$W/empty-path" SHIRUDO_BUILD="$B" "$S" image verify "$W/good" \
		--cert "$W/keys/cert.der" >"$W/no-verify.out" 2>"$W/no-verify.err" &&
	grep -q veritysetup "$W/no-verify.err"
'

test_expect_success 'config source generator rejects symlinks and private keys' '
	mkdir "$W/source" && ln -s /etc/passwd "$W/source/link" &&
	! ../tools/gen-image/shirudo-gen-image --source "$W/source" \
		--output "$W/generated" --keys-dir "$W/keys" --builder "$B" &&
	rm "$W/source/link" && cp "$W/keys/signing_key.pem" "$W/source/signing_key.pem" &&
	! ../tools/gen-image/shirudo-gen-image --source "$W/source" \
		--output "$W/generated" --keys-dir "$W/keys" --builder "$B"
'

if command -v mkfs.ext4 >/dev/null 2>&1 && command -v debugfs >/dev/null 2>&1; then
	test_expect_success 'operator generates a mountable ext4 config image with signed tree' '
		mkdir -p "$W/config-root/etc/shirudo" &&
		printf "eventlog.max_bytes = 12345\n" >"$W/config-root/etc/shirudo/shirudo.conf" &&
		../tools/gen-image/shirudo-gen-image --source "$W/config-root" \
			--output "$W/generated-config" --keys-dir "$W/keys" --builder "$B" &&
		test "$(stat -c %s "$W/generated-config.img")" -eq 1048576 &&
		verify "$W/generated-config" "$W/keys/cert.der" &&
		debugfs -R "cat /etc/shirudo/shirudo.conf" "$W/generated-config.img" 2>/dev/null |
			grep -qx "eventlog.max_bytes = 12345"
	'
	test_expect_success 'an image size below 1 MiB is refused' '
		! ../tools/gen-image/shirudo-gen-image --source "$W/config-root" \
			--output "$W/zero" --keys-dir "$W/keys" --builder "$B" --size 0 \
			2>"$W/zero.err" &&
		grep -q "between 1 and 1048576 MiB" "$W/zero.err" &&
		! test -e "$W/zero.img"
	'

	test_expect_success 'runtime generator includes interpreter, public keys and trusted probe' '
		cp fixtures/image-runtime.conf "$W/bootstrap.conf" &&
		${CC:-cc} -static fixtures/image-static-probe.c -o "$W/static-probe" &&
		../tools/gen-image/shirudo-gen-runtime --binary "$S" \
			--bootstrap-conf "$W/bootstrap.conf" --cert "$W/keys/cert.der" \
			--config-cert "$W/other/cert.der" --keys-dir "$W/keys" --builder "$B" \
			--extra-binary /bin/true --extra-binary "$W/static-probe" \
			--unit-output "$W/runtime-service.conf" \
			--unit-dir "$W/dyn-units" \
			--output "$W/generated-runtime" --size 128 &&
		verify "$W/generated-runtime" "$W/keys/cert.der" &&
		grep -q -- "--inhibit-cache --library-path /run/shirudo/runtime/" "$W/runtime-service.conf" &&
		cmp "$W/runtime-service.conf" "$W/dyn-units/shirudo.service.d/runtime.conf" &&
		for unit in shirudo-keepalive shirudo-map-export \
			shirudo-xdp-reconcile shirudo-bpm-repo-update \
			shirudo-bpm-tree-sync; do
			grep -q -- "--inhibit-cache --library-path /run/shirudo/runtime/" \
				"$W/dyn-units/$unit.service.d/runtime.conf" || return 1
		done &&
		grep -qE "^ExecStart=-/run/shirudo/runtime/.* bpm repo update$" \
			"$W/dyn-units/shirudo-bpm-repo-update.service.d/runtime.conf" &&
		grep -qE "^ExecStart=/run/shirudo/runtime/.* bpm upgrade$" \
			"$W/dyn-units/shirudo-bpm-repo-update.service.d/runtime.conf" &&
		debugfs -R "stat /usr/bin/true" "$W/generated-runtime.img" 2>/dev/null |
			grep -q "Type: regular" &&
		debugfs -R "stat /usr/bin/static-probe" "$W/generated-runtime.img" 2>/dev/null |
			grep -q "Type: regular" &&
		debugfs -R "cat /etc/shirudo/config-cert.der" "$W/generated-runtime.img" \
			>"$W/extracted.der" 2>/dev/null &&
		cmp "$W/extracted.der" "$W/other/cert.der"
	'
	test_expect_success 'runtime generator packages both config verification keys and their settings' '
		../tools/gen-image/shirudo-gen-runtime --binary "$W/static-probe" \
			--bootstrap-conf "$W/bootstrap.conf" --cert "$W/keys/cert.der" \
			--config-cert "$W/keys/cert.der" --config-cert "$W/other/cert.der" \
			--keys-dir "$W/keys" --builder "$B" --output "$W/runtime-overlap" --size 8 &&
		verify "$W/runtime-overlap" "$W/keys/cert.der" &&
		debugfs -R "cat /etc/shirudo/shirudo.conf" "$W/runtime-overlap.img" \
			>"$W/overlap.conf" 2>/dev/null &&
		sed -n "s/^[[:space:]]*config.verification_key[[:space:]]*=[[:space:]]*//p" \
			"$W/overlap.conf" >"$W/config-keys" &&
		printf "%s\n" \
			/run/shirudo/runtime/etc/shirudo/config-cert.der \
			/run/shirudo/runtime/etc/shirudo/config-cert-2.der >"$W/expected-keys" &&
		cmp "$W/config-keys" "$W/expected-keys" &&
		debugfs -R "cat /etc/shirudo/config-cert.der" "$W/runtime-overlap.img" \
			>"$W/first.der" 2>/dev/null &&
		debugfs -R "cat /etc/shirudo/config-cert-2.der" "$W/runtime-overlap.img" \
			>"$W/second.der" 2>/dev/null &&
		cmp "$W/first.der" "$W/keys/cert.der" &&
		cmp "$W/second.der" "$W/other/cert.der"
	'

	test_expect_success 'retired runtime keeps only its supplied config key' '
		../tools/gen-image/shirudo-gen-runtime --binary "$W/static-probe" \
			--bootstrap-conf "$W/overlap.conf" --cert "$W/keys/cert.der" \
			--config-cert "$W/other/cert.der" \
			--keys-dir "$W/keys" --builder "$B" --output "$W/runtime-retired" --size 8 &&
		verify "$W/runtime-retired" "$W/keys/cert.der" &&
		debugfs -R "cat /etc/shirudo/shirudo.conf" "$W/runtime-retired.img" \
			>"$W/retired.conf" 2>/dev/null &&
		sed -n "s/^[[:space:]]*config.verification_key[[:space:]]*=[[:space:]]*//p" \
			"$W/retired.conf" >"$W/retired-keys" &&
		printf "%s\n" /run/shirudo/runtime/etc/shirudo/config-cert.der \
			>"$W/expected-retired-key" &&
		cmp "$W/retired-keys" "$W/expected-retired-key" &&
		debugfs -R "cat /etc/shirudo/config-cert.der" "$W/runtime-retired.img" \
			>"$W/retired.der" 2>/dev/null &&
		cmp "$W/retired.der" "$W/other/cert.der"
	'

	test_expect_success 'runtime generator refuses the same config certificate twice' '
		! ../tools/gen-image/shirudo-gen-runtime --binary "$W/static-probe" \
			--bootstrap-conf "$W/bootstrap.conf" --cert "$W/keys/cert.der" \
			--config-cert "$W/keys/cert.der" --config-cert "$W/keys/cert.der" \
			--keys-dir "$W/keys" --builder "$B" --output "$W/runtime-duplicate" --size 8 &&
		! test -e "$W/runtime-duplicate.img"
	'

	test_expect_success 'static runtime images run directly without a packaged loader' '
		../tools/gen-image/shirudo-gen-runtime --binary "$W/static-probe" \
			--bootstrap-conf "$W/bootstrap.conf" --cert "$W/keys/cert.der" \
			--config-cert "$W/other/cert.der" --keys-dir "$W/keys" --builder "$B" \
			--unit-output "$W/static-runtime.service" \
			--unit-dir "$W/static-units" \
			--output "$W/static-runtime" --size 8 &&
		verify "$W/static-runtime" "$W/keys/cert.der" &&
		grep -qx "ExecStart=/run/shirudo/runtime/usr/bin/shirudo init" \
			"$W/static-runtime.service" &&
		cmp "$W/static-runtime.service" \
			"$W/static-units/shirudo.service.d/runtime.conf" &&
		grep -qx "ExecStart=/run/shirudo/runtime/usr/bin/shirudo status --otel" \
			"$W/static-units/shirudo-keepalive.service.d/runtime.conf" &&
		grep -qx "ExecStart=/run/shirudo/runtime/usr/bin/shirudo upatch map --all" \
			"$W/static-units/shirudo-map-export.service.d/runtime.conf" &&
		grep -qx "ExecStart=/run/shirudo/runtime/usr/bin/shirudo upatch reconcile" \
			"$W/static-units/shirudo-xdp-reconcile.service.d/runtime.conf" &&
		grep -qx "ExecStart=-/run/shirudo/runtime/usr/bin/shirudo bpm repo update" \
			"$W/static-units/shirudo-bpm-repo-update.service.d/runtime.conf" &&
		grep -qx "ExecStart=/run/shirudo/runtime/usr/bin/shirudo bpm upgrade" \
			"$W/static-units/shirudo-bpm-repo-update.service.d/runtime.conf" &&
		grep -qx "ExecStart=/run/shirudo/runtime/usr/bin/shirudo bpm tree sync" \
			"$W/static-units/shirudo-bpm-tree-sync.service.d/runtime.conf" &&
		grep -qx "EnvironmentFile=" \
			"$W/static-units/shirudo.service.d/runtime.conf" &&
		for unit in shirudo-keepalive shirudo-map-export \
			shirudo-xdp-reconcile shirudo-bpm-repo-update \
			shirudo-bpm-tree-sync; do
			! grep -q "^EnvironmentFile=" \
				"$W/static-units/$unit.service.d/runtime.conf" || return 1
		done &&
		! ../tools/gen-image/shirudo-gen-runtime --binary "$W/static-probe" \
			--bootstrap-conf "$W/bootstrap.conf" --cert "$W/keys/cert.der" \
			--config-cert "$W/other/cert.der" --keys-dir "$W/keys" --builder "$B" \
			--unit-dir "$W/static-units" \
			--output "$W/static-runtime-dup" --size 8 &&
		! test -e "$W/static-runtime-dup.img" &&
		: >"$W/not-a-dir" &&
		! ../tools/gen-image/shirudo-gen-runtime --binary "$W/static-probe" \
			--bootstrap-conf "$W/bootstrap.conf" --cert "$W/keys/cert.der" \
			--config-cert "$W/other/cert.der" --keys-dir "$W/keys" --builder "$B" \
			--unit-dir "$W/not-a-dir" \
			--output "$W/static-runtime-nodir" --size 8 &&
		! test -e "$W/static-runtime-nodir.img" &&
		debugfs -R "dump /usr/bin/shirudo $W/extracted-static" \
			"$W/static-runtime.img" >/dev/null 2>&1 &&
		llvm-strip -o "$W/static-probe.stripped" "$W/static-probe" &&
		cmp "$W/static-probe.stripped" "$W/extracted-static" &&
		debugfs -R "ls /" "$W/static-runtime.img" >"$W/static-root" 2>/dev/null &&
		! grep -Eq "(lib|lib64)" "$W/static-root"
	'
	# The generator keeps its own copy of each unit's commands; a unit
	# added or changed without it must fail here, not on a target.
	test_expect_success 'the generated drop-ins start what the shipped units start' '
		for f in ../systemd/*.service.in; do
			if grep -q "^ExecStart=-\{0,1\}/run/shirudo/runtime/usr/bin/shirudo " "$f"; then
				basename "$f" .in
			fi
		done | sort >"$W/units.runtime" &&
		(cd "$W/static-units" && ls -d *.service.d) | sed "s/\.d$//" |
			sort >"$W/units.generated" &&
		cmp "$W/units.runtime" "$W/units.generated" &&
		for u in $(cat "$W/units.runtime"); do
			grep "^ExecStart=." "../systemd/$u.in" |
				sed "s/ \$SHIRUDO_INIT_ARGS$//" >"$W/$u.want" &&
			grep "^ExecStart=." "$W/static-units/$u.d/runtime.conf" \
				>"$W/$u.static" &&
			cmp "$W/$u.want" "$W/$u.static" &&
			grep "^ExecStart=." "$W/dyn-units/$u.d/runtime.conf" |
				sed -E "s#^(ExecStart=-?)/run/shirudo/runtime/[^ ]* --inhibit-cache --library-path [^ ]* #\1#" \
				>"$W/$u.dyn" &&
			cmp "$W/$u.want" "$W/$u.dyn" || return 1
		done
	'
	test_expect_success 'the runtime image holds the binary without its symbols' '
		LC_ALL=C readelf -S "$W/static-probe" | grep -q "\.symtab" &&
		! LC_ALL=C readelf -S "$W/extracted-static" | grep -q "\.symtab"
	'
	test_expect_success 'files that do not fit the image size are refused with their size' '
		mkdir -p "$W/big-root" &&
		head -c 9437184 /dev/urandom >"$W/big-root/big" &&
		! ../tools/gen-image/shirudo-gen-image --source "$W/big-root" \
			--output "$W/big" --keys-dir "$W/keys" --builder "$B" --size 8 \
			2>"$W/big.err" &&
		grep -Eq "[0-9]+ KiB of files do not fit an image of 8 MiB; raise --size" \
			"$W/big.err" &&
		! test -e "$W/big.img"
	'
	test_expect_success 'check-runtime-image.sh reports the space left in the default image' '
		SHIRUDO="$S" SHIRUDO_BUILD="$B" sh ../.github/scripts/check-runtime-image.sh \
			"$W/static-probe" >"$W/check.out" &&
		grep -Eq "^shirudo: the default runtime image of [0-9]+ MiB holds .* with [0-9]+ KiB free$" \
			"$W/check.out"
	'
	test_expect_success 'check-runtime-image.sh fails once a binary outgrows the default' '
		head -c 16777216 /dev/urandom >"$W/blob" &&
		printf ".section .rodata\n.incbin \"%s\"\n.section .note.GNU-stack,\"\",%%progbits\n" \
			"$W/blob" >"$W/blob.s" &&
		printf "int main(void) { return 0; }\n" >"$W/big-probe.c" &&
		${CC:-cc} -static -o "$W/big-probe" "$W/big-probe.c" "$W/blob.s" &&
		! SHIRUDO="$S" SHIRUDO_BUILD="$B" sh ../.github/scripts/check-runtime-image.sh \
			"$W/big-probe" 2>"$W/check.err" &&
		grep -q "raise size= in tools/gen-image/shirudo-gen-runtime" "$W/check.err"
	'

fi

test_done
