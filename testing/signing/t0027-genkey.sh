#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0027 -- `shirudo genkey`: the only key type is ML-DSA-87 (FIPS 204),
# the certificate is self-signed with the same key and carries matching
# subject/authority key identifiers, and there is no algorithm option
# at all. The ML-DSA cases need an OpenSSL (>= 3.5) that knows the
# algorithm; on older toolchains genkey must refuse with an upgrade hint.
# A --force that cannot put the new pair in place leaves the old one.

cd "$(dirname "$0")/.."
. ./test-lib.sh

SHIRUDO=${SHIRUDO_GENKEY_TEST_BINARY:-../shirudo}
if ! command -v openssl >/dev/null 2>&1 || [ ! -x "$SHIRUDO" ]; then
	test_skip_all 'shirudo and openssl are needed to test generated certificates'
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/shirudo-genkey.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

have_mldsa=0
if openssl list -public-key-algorithms 2>/dev/null | grep -qi 'ML-DSA'; then
	have_mldsa=1
fi

cert_text() {
	openssl x509 -inform DER -in "$1" -noout -text
}

test_expect_success 'genkey has no algorithm option' '
	! "$SHIRUDO" genkey --keys-dir "$tmp/opt" --algorithm rsa-2048 >"$tmp/opt.out" 2>&1 &&
	grep -q "unknown option" "$tmp/opt.out" &&
	! "$SHIRUDO" genkey --keys-dir "$tmp/opt" --algorithm=ml-dsa-65 >/dev/null 2>&1 &&
	! test -e "$tmp/opt/signing_key.pem"
'

if [ "$have_mldsa" = 1 ]; then
	test_expect_success 'genkey produces an ML-DSA-87 key and certificate' '
		"$SHIRUDO" genkey --keys-dir "$tmp/keys" >"$tmp/genkey.out" 2>&1 &&
		grep -q "ML-DSA-87" "$tmp/genkey.out" &&
		cert_text "$tmp/keys/cert.der" | grep -q "Public Key Algorithm: ML-DSA-87" &&
		cert_text "$tmp/keys/cert.der" | grep -q "Signature Algorithm: ML-DSA-87"
	'

	test_expect_success 'certificate carries an Authority Key Identifier' '
		openssl x509 -inform DER -in "$tmp/keys/cert.der" \
			-noout -ext authorityKeyIdentifier | grep -Eq "([0-9A-F]{2}:){19}[0-9A-F]{2}"
	'

	test_expect_success 'subject and authority key identifiers match' '
		subject=$(openssl x509 -inform DER -in "$tmp/keys/cert.der" \
			-noout -ext subjectKeyIdentifier | tail -1 | tr -d "[:space:]") &&
		authority=$(openssl x509 -inform DER -in "$tmp/keys/cert.der" \
			-noout -ext authorityKeyIdentifier | tail -1 | tr -d "[:space:]") &&
		test -n "$subject" && test "$subject" = "$authority"
	'

	test_expect_success 'private key is a PEM private key the toolchain can read' '
		openssl pkey -in "$tmp/keys/signing_key.pem" -noout -text 2>/dev/null |
			head -1 | grep -qi "ML-DSA-87"
	'

	test_expect_success 'keys reports ML-DSA-87 and a matching key/cert pair' '
		"$SHIRUDO" keys --keys-dir "$tmp/keys" >"$tmp/keys.out" 2>&1 &&
		grep -q "Public-key: *ML-DSA-87" "$tmp/keys.out" &&
		grep -q "Algorithm: *ML-DSA-87" "$tmp/keys.out" &&
		grep -q "signing key matches cert" "$tmp/keys.out"
	'

	test_expect_success 'genkey refuses to overwrite without --force' '
		! "$SHIRUDO" genkey --keys-dir "$tmp/keys" >/dev/null 2>&1 &&
		"$SHIRUDO" genkey --keys-dir "$tmp/keys" --force >/dev/null 2>&1
	'

	test_expect_success 'a --force that cannot finish keeps the old pair' '
		cp "$tmp/keys/signing_key.pem" "$tmp/old.pem" &&
		mv "$tmp/keys/cert.der" "$tmp/old.der" &&
		mkdir "$tmp/keys/cert.der" &&
		! "$SHIRUDO" genkey --keys-dir "$tmp/keys" --force >"$tmp/force.out" 2>&1 &&
		cmp "$tmp/old.pem" "$tmp/keys/signing_key.pem" &&
		! test -e "$tmp/keys/signing_key.pem.old" &&
		! test -e "$tmp/keys/signing_key.pem.new" &&
		! test -e "$tmp/keys/cert.der.new" &&
		rmdir "$tmp/keys/cert.der" &&
		mv "$tmp/old.der" "$tmp/keys/cert.der" &&
		"$SHIRUDO" keys --keys-dir "$tmp/keys" >"$tmp/keys.out" 2>&1 &&
		grep -q "signing key matches cert" "$tmp/keys.out"
	'
else
	test_expect_success 'genkey refuses with an upgrade hint on an OpenSSL without ML-DSA' '
		! "$SHIRUDO" genkey --keys-dir "$tmp/keys" >"$tmp/genkey.out" 2>&1 &&
		grep -q "OpenSSL 3.5" "$tmp/genkey.out" &&
		! grep -q "rsa" "$tmp/genkey.out" &&
		! test -e "$tmp/keys/signing_key.pem"
	'
fi

test_done
