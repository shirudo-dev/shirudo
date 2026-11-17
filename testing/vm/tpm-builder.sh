#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
# testing/vm/tpm-builder.sh <state-dir> <names> -- act as the builder of
# "Enroll from a builder's records": create the attestation key and the
# endorsement key in the vTPM state before the guest boots, with the
# commands that page gives, and write their names to <names>.

set -euo pipefail

state=$1
names=$2
work=$(mktemp -d)

stop() {
	swtpm_ioctl --unix "$work/tpm.ctrl" -s >/dev/null 2>&1 || :
	rm -rf -- "$work"
}
trap stop EXIT

name() {
	printf '000b%s\n' "$(tail -c +3 "$1" | sha256sum | cut -c1-64)"
}

swtpm socket --tpm2 --tpmstate "dir=$state,mode=0700" \
	--server "type=unixio,path=$work/tpm" \
	--ctrl "type=unixio,path=$work/tpm.ctrl" \
	--flags not-need-init,startup-clear --daemon
for _ in {1..50}; do
	[[ -S "$work/tpm" ]] && break
	sleep 0.1
done
export TPM2TOOLS_TCTI="swtpm:path=$work/tpm"
cd "$work"
tpm2_createprimary -C e -g sha256 -G ecc256:ecdsa-sha256:null \
	-a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign' \
	-c ak.ctx >/dev/null
tpm2_readpublic -c ak.ctx -o ak.pub >/dev/null
tpm2_flushcontext -t
tpm2_createek -c - -G ecc -u ek.pub >/dev/null
printf 'ak-name %s\nek-name %s\n' "$(name ak.pub)" "$(name ek.pub)" >"$names"
swtpm_ioctl --unix "$work/tpm.ctrl" -s
