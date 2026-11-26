#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./test-lib.sh

SHIRUDO=../shirudo
BPM_SOURCE_HELPER=helper/test-bpm-source

test_expect_success 'bpm exposes native subcommands to completion' '
	out=$($SHIRUDO bpm --list-cmds) &&
	echo "$out" | grep -qx config &&
	echo "$out" | grep -qx repo &&
	echo "$out" | grep -qx key &&
	echo "$out" | grep -qx pull &&
	echo "$out" | grep -qx info &&
	echo "$out" | grep -qx install &&
	echo "$out" | grep -qx upgrade &&
	echo "$out" | grep -qx list &&
	echo "$out" | grep -qx uninstall
'

test_expect_success 'bpm help describes the target package workflow' '
	out=$($SHIRUDO bpm --help 2>&1) &&
	echo "$out" | grep -q "signed target-local BPM packages" &&
	echo "$out" | grep -q "refresh signed repository indexes" &&
	echo "$out" | grep -q "download an OCI package"
'

test_expect_success 'target bpm does not expose operator-only commands' '
	! $SHIRUDO bpm --list-cmds | grep -qx push &&
	! $SHIRUDO bpm --list-cmds | grep -qx build &&
	! $SHIRUDO bpm push >/dev/null 2>&1 &&
	! $SHIRUDO bpm build >/dev/null 2>&1
'

test_expect_success 'bpm pull validates package references before network access' '
	! $SHIRUDO bpm pull ./package.bee >/dev/null 2>&1 &&
	! $SHIRUDO bpm pull oci://registry.example/repository >/dev/null 2>&1
'

test_expect_success 'bpm pull without a reference prints OCI usage' '
	if out=$($SHIRUDO bpm pull 2>&1); then
		false
	else
		echo "$out" | grep -q "a package reference starting with oci://" &&
		echo "$out" | grep -q "oci://quay.io/namespace/package:tag"
	fi
'

test_expect_success 'bpm rejects an unknown subcommand' '
	! $SHIRUDO bpm not-a-command >/dev/null 2>&1
'

test_expect_success 'bpm tree help covers sync and append' '
	out=$($SHIRUDO bpm tree --help 2>&1) &&
	echo "$out" | grep -q "tree sync \[--dry-run\]" &&
	echo "$out" | grep -q "tree append <package-file> <repository>" &&
	! $SHIRUDO bpm tree not-a-command >/dev/null 2>&1
'

test_expect_success 'bpm config register add takes --cert and refuses other options' '
	rc=0 &&
	out=$($SHIRUDO bpm config register add src oci://registry.example \
		--key-file x.der 2>&1) || rc=$? &&
	[ "$rc" -eq 2 ] &&
	echo "$out" | grep -q "unknown option .--key-file." &&
	$SHIRUDO bpm config --help 2>&1 | grep -q -- "--cert <certificate>"
'

test_expect_success 'bpm uninstall and list validate their arguments' '
	! $SHIRUDO bpm uninstall >/dev/null 2>&1 &&
	! $SHIRUDO bpm uninstall ../etc >/dev/null 2>&1 &&
	! $SHIRUDO bpm list extra >/dev/null 2>&1 &&
	$SHIRUDO bpm uninstall --help 2>&1 | grep -q "usage: shirudo bpm uninstall <package>"
'

# A host that ran no init has nothing to load a package into. The suite
# also runs in the target guest, where these commands go on.
if [ ! -e /run/shirudo/bpffs/lsm_link ]; then
	test_expect_success 'bpm install, upgrade and uninstall need enforcement' '
		for cmd in "install example/pkg" upgrade "uninstall pkg"; do
			rc=0
			out=$($SHIRUDO bpm $cmd 2>&1) || rc=$?
			[ "$rc" -eq 1 ] || return 1
			echo "$out" | grep -q "bpm ${cmd%% *}: enforcement is not active; run shirudo init first" ||
				return 1
		done
	'
fi

test_expect_success 'bpm parses repository source and tree configuration lines' '
	out=$($BPM_SOURCE_HELPER) &&
	echo "$out" | grep -qx "endpoint=oci://registry.test:5443" &&
	echo "$out" | grep -qx "key_file=/etc/shirudo/bpm/keys/jbrust.pem" &&
	echo "$out" | grep -qx "tree endpoint=oci://registry.test/tree" &&
	echo "$out" | grep -qx "tree reference=sha256:feed"
'

test_done
