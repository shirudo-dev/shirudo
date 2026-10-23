#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -euo pipefail
umask 077

source_dir=$(cd "$(dirname "$0")/.." && pwd)
templates="$source_dir/contrib/verity-vm"
keys_dir=
boot_keys_dir=
output=
builtin_key=${TEST_VM_BUILTIN_SIGNING_KEY:-}
builtin_cert=${TEST_VM_BUILTIN_SIGNING_CERT:-}
while [ $# -gt 0 ]; do
	case "$1" in
	--boot-keys-dir) boot_keys_dir=${2:?}; shift 2 ;;
	--keys-dir) keys_dir=${2:?}; shift 2 ;;
	--output) output=${2:?}; shift 2 ;;
	*)
		printf 'usage: %s --keys-dir <operator-keys> [--boot-keys-dir <operator-keys>] --output <new-directory>\n' \
			"$0" >&2
		exit 2
		;;
	esac
done
[ -n "$keys_dir" ] && [ -n "$output" ] || exit 2
keys_dir=$(realpath "$keys_dir")
[ -s "$keys_dir/cert.der" ] && [ -s "$keys_dir/signing_key.pem" ]
[ ! -e "$output" ] && [ ! -L "$output" ] || {
	printf 'Refusing existing output: %s\n' "$output" >&2
	exit 1
}
if [ -n "$builtin_key$builtin_cert" ]; then
	[ -r "$builtin_key" ] && [ -r "$builtin_cert" ] || {
		printf 'both built-in signing key and certificate are required\n' >&2
		exit 1
	}
fi
operator="$source_dir/shirudo"
builder="$source_dir/tools/shirudo-build/shirudo-build"
validator="$source_dir/testing/helper/test-image-keys"
[ -x "$operator" ] && [ -x "$builder" ] && [ -x "$validator" ]
mkdir -m 0700 "$output"
output=$(realpath "$output")
mkdir "$output/private" "$output/public" "$output/source"

for name in boot live; do
	if [ "$name" = boot ] && [ -n "$boot_keys_dir" ]; then
		mkdir "$output/private/boot"
		cp "$boot_keys_dir/cert.der" "$boot_keys_dir/signing_key.pem" \
			"$output/private/boot/"
	else
		"$operator" genkey --keys-dir "$output/private/$name" \
			>"$output/$name-genkey.log" 2>&1
	fi
	"$operator" bpm key fingerprint "$output/private/$name/cert.der" \
		>"$output/public/$name.fingerprint"
	cp "$output/private/$name/cert.der" "$output/public/$name.der"
done
boot_fp=$(cat "$output/public/boot.fingerprint")
live_fp=$(cat "$output/public/live.fingerprint")
[[ "$boot_fp" =~ ^[a-f0-9]{64}$ ]] && [[ "$live_fp" =~ ^[a-f0-9]{64}$ ]]
[ "$boot_fp" != "$live_fp" ]
cp "$keys_dir/cert.der" "$output/public/primary.der"

for name in config-boot-keys config-live-new-key config-a config-b config-bad config-revoke \
	config-tree-stable config-tree-updated config-tree-deleted config-tree-restored \
	config-otel config-jsonl config-jsonl-bad config-interrupted config-builtin; do
	[ "$name" != config-builtin ] || [ -n "$builtin_key" ] || continue
	root="$output/source/$name"
	mkdir -p "$root/etc/shirudo" "$root/keys/trusted" "$root/keys/revoked"
	sed "s/@tenant@/$name/g" "$templates/config.conf.in" \
		>"$root/etc/shirudo/shirudo.conf"
	case "$name" in
	config-tree-*)
		mkdir -p "$root/etc/shirudo/bpm"
		cp "$templates/node.labels" "$root/etc/shirudo/node.labels"
		sed "s/@reference@/${name#config-tree-}/g" \
			"$templates/upatch-tree.conf.in" \
			>"$root/etc/shirudo/bpm/upatch-tree.conf"
		;;
	config-otel)
		cp "$templates/otel.conf" "$root/etc/shirudo/shirudo.conf"
		;;
	config-jsonl|config-jsonl-bad)
		cp "$templates/${name#config-}.conf" "$root/etc/shirudo/shirudo.conf"
		;;
	esac
	cp "$output/public/boot.der" "$root/keys/trusted/$boot_fp.der"
	"$builder" keys vouch "$output/public/boot.der" \
		-o "$root/keys/trusted/$boot_fp.vouch" --keys-dir "$keys_dir" \
		>"$output/$name-boot-vouch.log" 2>&1
	if [ "$name" = config-live-new-key ]; then
		cp "$output/public/live.der" "$root/keys/trusted/$live_fp.der"
		"$builder" keys vouch "$output/public/live.der" \
			-o "$root/keys/trusted/$live_fp.vouch" \
			--keys-dir "$output/private/boot" \
			>"$output/$name-live-vouch.log" 2>&1
	fi
	if [[ "$name" == config-revoke || "$name" == config-interrupted ]]; then
		cp "$output/public/boot.der" "$root/keys/revoked/$boot_fp.der"
	elif [ "$name" = config-bad ]; then
		printf 'invalid certificate\n' >"$root/keys/revoked/$boot_fp.der"
	fi
	if [ "$name" != config-bad ]; then
		"$validator" "$keys_dir/cert.der" "$root" >"$output/$name-validation.log"
		expected=2
		[[ "$name" != config-revoke && "$name" != config-interrupted ]] || expected=1
		[ "$name" != config-live-new-key ] || expected=3
		grep -q "signers=$expected" "$output/$name-validation.log"
	fi
	verify_cert="$keys_dir/cert.der"
	if [ "$name" = config-builtin ]; then
		truncate -s 8M "$output/private/builtin.img"
		mkfs.ext4 -q -F -b 4096 -O '^has_journal' -E root_owner=0:0 \
			-d "$root" "$output/private/builtin.img"
		"$builder" image build "$output/private/builtin.img" \
			-o "$output/public/$name" --key "$builtin_key" \
			--cert "$builtin_cert" >"$output/$name-build.log" 2>&1
		verify_cert="$builtin_cert"
		cp "$builtin_cert" "$output/public/builtin.der"
	else
		"$source_dir/tools/gen-image/shirudo-gen-image" --source "$root" \
			--output "$output/public/$name" --keys-dir "$keys_dir" --size 8 \
			--builder "$builder" >"$output/$name-build.log" 2>&1
	fi
	SHIRUDO_BUILD="$builder" "$operator" image verify "$output/public/$name" \
		--cert "$verify_cert" >"$output/public/$name.root"

done

"$builder" "$source_dir/testing/fixtures/basic.bpf.c" \
	-o "$output/public/shirudo-test-revoked-key.upatch" \
	--name shirudo-test-revoked-key \
	--vmlinux "$source_dir/vendor/linux/vmlinux.h" \
	--key "$output/private/boot/signing_key.pem" \
	--cert "$output/public/boot.der"

# These host checks validate the fixture graph before the real target test.
mkdir "$output/check-live" "$output/check-boot"
"$validator" "$keys_dir/cert.der" "$output/source/config-boot-keys" \
	"$output/check-boot" "$keys_dir/cert.der" "$output/public/boot.der" \
	>"$output/check-boot.log"
grep -qx 'extends=1 activations=1' "$output/check-boot.log"
grep -qx 'rc=0 mutations=0 signers=2' "$output/check-boot.log"
if "$validator" "$keys_dir/cert.der" "$output/source/config-live-new-key" \
	"$output/check-live" "$keys_dir/cert.der" "$output/public/boot.der" \
	>"$output/check-live.log"; then
	printf 'Unexpected acceptance of missing live signer\n' >&2
	exit 1
fi
grep -qx 'extends=0 activations=0' "$output/check-live.log"
grep -qx 'rc=-126 mutations=0 signers=3' "$output/check-live.log"
printf 'Target artifacts only: %s/public\n' "$output"
printf 'Private operator keys remain in: %s/private\n' \
	"$output"
