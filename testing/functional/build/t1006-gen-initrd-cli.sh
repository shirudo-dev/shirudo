#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1006 -- the initrd generator and the installer: the parts that need
# neither root nor dracut, which is their option handling, the plan
# the installer prints for --dry-run and the parameter they agree on.

cd "$(dirname "$0")/../.."
. ./test-lib.sh
G=../tools/gen-initrd/shirudo-gen-initrd
I=../tools/gen-initrd/install.sh
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
printf 'not a certificate\n' >"$W/cert.der"
: >"$W/shirudo-target_0_amd64.deb"
SUM=$(sha256sum <"$W/cert.der" | cut -d' ' -f1)
ZERO=0000000000000000000000000000000000000000000000000000000000000000
test_expect_success 'the generator always enables boot enrollment in both keyrings' '
	[ "$(bash $G --print-cmdline)" = "bpf.keyring_unsealed=1 dm_verity.keyring_unsealed=1" ]
'

test_expect_success 'the generator refuses an unknown option' '
	! bash $G --bogus >/dev/null 2>&1 &&
	bash $G --help | grep -q -- "--binary-path"
'

test_expect_success 'the generator check refuses a missing initrd' '
	! bash $G --check "$W/none.img" >/dev/null 2>&1
'

if [ "$(id -u)" != 0 ]; then
	test_expect_success 'the generator needs root only to replace the host initrd' '
		! bash $G --kver 0 >/dev/null 2>"$W/err" &&
		grep -q "run as root, or name an --output" "$W/err"
	'
fi

test_expect_success 'the installer plans the package, the certificate and the initrd' '
	bash $I --dry-run --package "$W/shirudo-target_0_amd64.deb" \
		--cert "$W/cert.der" --no-cmdline --no-initrd >"$W/plan" &&
	grep -q "dpkg -i $W/shirudo-target_0_amd64.deb" "$W/plan" &&
	grep -q "install -m 0644 $W/cert.der /var/lib/shirudo/keys/cert.der" "$W/plan" &&
	grep -q "reboot\|production configuration" "$W/plan"
'

test_expect_success 'the installer refuses a certificate URL without its SHA-256' '
	! bash $I --dry-run --package "$W/shirudo-target_0_amd64.deb" \
		--cert https://example.invalid/cert.der --no-cmdline \
		--no-initrd >"$W/url" 2>&1 &&
	grep -q "needs --cert-sha256" "$W/url" &&
	! grep -q "dpkg -i" "$W/url"
'

test_expect_success 'the installer plans to check a certificate URL against its SHA-256' '
	bash $I --dry-run --package "$W/shirudo-target_0_amd64.deb" \
		--cert https://example.invalid/cert.der --cert-sha256 "$SUM" \
		--no-cmdline --no-initrd >"$W/pinned" &&
	grep -q "curl -fsSL -o .*/cert.der https://example.invalid/cert.der" "$W/pinned" &&
	grep -q "check sha256 $SUM of" "$W/pinned"
'

test_expect_success 'the installer checks a local certificate against its SHA-256' '
	bash $I --dry-run --package "$W/shirudo-target_0_amd64.deb" \
		--cert "$W/cert.der" --cert-sha256 "$(printf %s "$SUM" | tr a-f A-F)" \
		--no-cmdline --no-initrd >"$W/match" &&
	grep -q "install -m 0644 $W/cert.der" "$W/match" &&
	! bash $I --dry-run --package "$W/shirudo-target_0_amd64.deb" \
		--cert "$W/cert.der" --cert-sha256 "$ZERO" \
		--no-cmdline --no-initrd >"$W/mismatch" 2>&1 &&
	grep -q "does not have SHA-256 $ZERO" "$W/mismatch" &&
	! grep -q "dpkg -i" "$W/mismatch"
'

test_expect_success 'the installer refuses a malformed SHA-256 or one without a certificate' '
	! bash $I --dry-run --cert "$W/cert.der" --cert-sha256 "${SUM%?}" \
		>/dev/null 2>&1 &&
	! bash $I --dry-run --cert "$W/cert.der" --cert-sha256 "${SUM%?}g" \
		>/dev/null 2>&1 &&
	! bash $I --dry-run --package "$W/shirudo-target_0_amd64.deb" \
		--cert-sha256 "$SUM" >"$W/alone" 2>&1 &&
	grep -q "needs --cert" "$W/alone"
'

test_expect_success 'the installer refuses to start the removed root-only mode' '
	! bash $I --dry-run --now >"$W/now" 2>&1 &&
	grep -q "unknown option" "$W/now"
'

test_expect_success 'the installer refuses an unknown option' '
	! bash $I --dry-run --bogus >/dev/null 2>&1
'

test_done
