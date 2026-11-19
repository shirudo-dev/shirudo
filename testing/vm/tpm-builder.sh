#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
# testing/vm/tpm-builder.sh <state-dir> <names> <ek-ca> <enroll> <node-id> --
# act as the builder of "Enroll from a builder's records": create the keys in
# the vTPM state before the guest boots, with the commands that page gives,
# write their names to <names> and the file jobs/enroll-put loads, naming
# the node <node-id>, to <enroll>. As the vTPM's maker, it also stores an
# endorsement certificate from a CA of its own, in <ek-ca>.

set -euo pipefail

state=$1
names=$2
ek_ca=$3
enroll=$4
node_id=$5
work=$(mktemp -d)

# swtpm drops the lock on the state directory only when it exits, and the
# guest's swtpm opens that directory next.
stop() {
	local pid

	pid=$(cat "$work/tpm.pid" 2>/dev/null) || pid=
	swtpm_ioctl --unix "$work/tpm.ctrl" -s >/dev/null 2>&1 || :
	rm -rf -- "$work"
	[[ -n "$pid" ]] || return 0
	for _ in {1..100}; do
		kill -0 "$pid" 2>/dev/null || return 0
		sleep 0.1
	done
	kill -KILL "$pid" 2>/dev/null || :
	echo "tpm-builder: swtpm $pid did not exit" >&2
	exit 1
}
trap stop EXIT
trap 'exit 1' INT TERM HUP

name() {
	printf '000b%s\n' "$(tail -c +3 "$1" | sha256sum | cut -c1-64)"
}

swtpm socket --tpm2 --tpmstate "dir=$state,mode=0700" \
	--server "type=unixio,path=$work/tpm" \
	--ctrl "type=unixio,path=$work/tpm.ctrl" \
	--pid "file=$work/tpm.pid" \
	--flags not-need-init,startup-clear --daemon
for _ in {1..50}; do
	[[ -S "$work/tpm" && -s "$work/tpm.pid" ]] && break
	sleep 0.1
done
[[ -S "$work/tpm" && -s "$work/tpm.pid" ]] || {
	echo "tpm-builder: swtpm did not open $work/tpm" >&2
	exit 1
}
export TPM2TOOLS_TCTI="swtpm:path=$work/tpm"
cd "$work"
tpm2_createprimary -C e -g sha256 -G ecc256:ecdsa-sha256:null \
	-a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign' \
	-c ak.ctx >/dev/null
tpm2_readpublic -c ak.ctx -o ak.pub >/dev/null
tpm2_flushcontext -t
tpm2_createek -c - -G ecc -u ek.pub >/dev/null
printf 'ak-name %s\nek-name %s\n' "$(name ak.pub)" "$(name ek.pub)" >"$names"
# node_id is a VM name, which needs no JSON escape.
printf '{"source": "test-vm", "nodes": [{"ak_name": "%s", "ek_name": "%s", "node_id": "%s"}]}\n' \
	"$(name ak.pub)" "$(name ek.pub)" "$node_id" >"$enroll"

# The certificate goes where a TPM's maker puts it, the ECC index of the TCG
# EK credential profile, written under the platform hierarchy the firmware
# has not yet locked; the CA's key is thrown away with $work.
tpm2_print -t TPM2B_PUBLIC -f pem ek.pub >ek.pem
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	-keyout ca.key -out ca.pem -days 3650 \
	-subj "/CN=shirudo test endorsement CA $(od -An -N8 -tx1 /dev/urandom | tr -d ' ')" \
	2>/dev/null
openssl x509 -new -subj "/CN=shirudo test endorsement key" \
	-force_pubkey ek.pem -CA ca.pem -CAkey ca.key -days 3650 \
	-outform DER -out ek.der
tpm2_nvdefine -C p -s "$(stat -c %s ek.der)" \
	-a 'ppwrite|ppread|ownerread|authread|no_da|platformcreate' 0x01c0000a \
	>/dev/null
tpm2_nvwrite -C p -i ek.der 0x01c0000a
cp ca.pem "$ek_ca"
tpm2_shutdown
