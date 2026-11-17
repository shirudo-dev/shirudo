#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# A stand-in for shirudo-quote-check that verifies nothing, so that the
# SQL tests need neither a TPM nor the shirudo tree. It reads the same
# rows and prints the same lines; a test steers the answer through the
# fields, which only have to look like base64:
#
#   attest  <reset_count>/<clock>/<body_sha256>
#   sig     "good", or anything else for bad_signature
#   ak      any text; ak_name is 000b and the SHA-256 of that text

set -u

tab=$(printf '\t')

answer()
{
	attest=${1%%"$tab"*}
	rest=${1#*"$tab"}
	sig=${rest%%"$tab"*}
	rest=${rest#*"$tab"}
	ak=${rest%%"$tab"*}
	body_sha256=${rest#*"$tab"}

	reset_count=${attest%%/*}
	rest=${attest#*/}
	clock=${rest%%/*}
	extra=${rest#*/}

	case "$1" in
	*"$tab"*"$tab"*"$tab"*"$tab"*) reset_count= ;;
	*"$tab"*"$tab"*"$tab"*) ;;
	*) reset_count= ;;
	esac
	case "$attest" in
	*/*/*/*) reset_count= ;;
	*/*/*) ;;
	*) reset_count= ;;
	esac
	case "$reset_count$clock" in
	''|*[!0-9]*) reset_count= ;;
	esac
	if [ -z "$reset_count" ] || [ -z "$clock" ] || [ -z "$sig" ] ||
	   [ -z "$ak" ]; then
		printf '{"ok":0,"reason":"malformed"}\n'
	elif [ "$sig" != good ]; then
		printf '{"ok":0,"reason":"bad_signature"}\n'
	elif [ "$extra" != "$body_sha256" ]; then
		printf '{"ok":0,"reason":"body_mismatch"}\n'
	else
		digest=$(printf '%s' "$ak" | sha256sum)
		printf '{"ok":1,"ak_name":"000b%s","ak_public":"%s","reset_count":%s,"clock":%s}\n' \
			"${digest%% *}" "$ak" "$reset_count" "$clock"
	fi
}

while IFS= read -r row; do
	answer "$row"
done
