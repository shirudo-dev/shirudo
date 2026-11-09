#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6112 -- the trust anchors in the kernel's keyrings are root's to look
# at and nobody's but shirudo's to change: keyctl cannot unlink, clear,
# revoke, invalidate or re-permission the sealed bpf and dm-verity
# keyrings init froze or the certificate keys they hold, while viewing
# and listing them and loading against them keep working.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

command -v keyctl >/dev/null 2>&1 || test_skip_all "no keyctl"
RING=$("$SHIRUDO_BIN" status --json 2>/dev/null | report_field keyring_serial)
case "$RING" in
	''|None|0|-*) test_skip_all "no anchor keyring frozen this boot" ;;
esac
KEYS=$(keyctl rlist "$RING" 2>/dev/null)
[ -n "$KEYS" ] || test_skip_all "cannot list the anchor keyring $RING"
N_BEFORE=$(set -- $KEYS; echo $#)
keys_now() { set -- $(keyctl rlist "$RING" 2>/dev/null); echo $#; }
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

bpf_keys_visible()
{
	for bpf_key in $KEYS; do
		keyctl describe "$bpf_key" >/dev/null || return 1
		keyctl rlist "$RING" | grep -qw "$bpf_key" || return 1
		grep -q "^0*$(printf %08x "$bpf_key") " /proc/keys || return 1
	done
}

bpf_keys_unlink_protected()
{
	for bpf_key in $KEYS; do
		! keyctl unlink "$bpf_key" "$RING" 2>"$W/err" || return 1
		grep -qi "permission denied" "$W/err" || return 1
	done
}

bpf_keys_revoke_protected()
{
	for bpf_key in $KEYS; do
		! keyctl revoke "$bpf_key" 2>/dev/null || return 1
		! keyctl invalidate "$bpf_key" 2>/dev/null || return 1
		keyctl describe "$bpf_key" >/dev/null || return 1
	done
}

bpf_keys_permissions_protected()
{
	for bpf_key in $KEYS; do
		! keyctl setperm "$bpf_key" 0x3f3f3f3f 2>/dev/null || return 1
		! keyctl timeout "$bpf_key" 1 2>/dev/null || return 1
		! keyctl chown "$bpf_key" 1 2>/dev/null || return 1
	done
}

test_expect_success 'the anchor keyring and all its keys are visible' '
	keyctl describe "$RING" >/dev/null &&
	bpf_keys_visible
'

test_expect_success 'root cannot unlink any key from the anchor keyring' '
	bpf_keys_unlink_protected &&
	[ "$(keys_now)" = "$N_BEFORE" ]
'

test_expect_success 'root cannot clear the anchor keyring' '
	! keyctl clear "$RING" 2>/dev/null &&
	[ "$(keys_now)" = "$N_BEFORE" ]
'

test_expect_success 'root cannot revoke or invalidate any key' '
	bpf_keys_revoke_protected &&
	! keyctl invalidate "$RING" 2>/dev/null &&
	[ "$(keys_now)" = "$N_BEFORE" ]
'

test_expect_success 'root cannot change any key permissions or timeout' '
	bpf_keys_permissions_protected &&
	! keyctl setperm "$RING" 0x3f3f3f3f 2>/dev/null &&
	sleep 2 &&
	bpf_keys_visible
'

test_expect_success 'root cannot link a key into the anchor keyring' '
	k=$(keyctl add user shirudo-test-t6112 x @s) &&
	! keyctl link "$k" "$RING" 2>/dev/null &&
	keyctl unlink "$k" @s &&
	[ "$(keys_now)" = "$N_BEFORE" ]
'

DM_RING=$(awk '$8 == "keyring" && $9 == ".dm-verity:" { print $1 }' /proc/keys)
[ -n "$DM_RING" ] && DM_RING=$((0x$DM_RING))
DM_KEYS=$([ -n "$DM_RING" ] && keyctl rlist "$DM_RING" 2>/dev/null)
dm_keys_now() { set -- $(keyctl rlist "$DM_RING" 2>/dev/null); echo $#; }

dm_keys_describe()
{
	for dm_key in $DM_KEYS; do
		keyctl rdescribe "$dm_key" | grep -q "^asymmetric;" || return 1
	done
}

dm_keys_protected()
{
	for dm_key in $DM_KEYS; do
		! keyctl unlink "$dm_key" "$DM_RING" 2>/dev/null || return 1
		! keyctl revoke "$dm_key" 2>/dev/null || return 1
		! keyctl invalidate "$dm_key" 2>/dev/null || return 1
		keyctl describe "$dm_key" >/dev/null || return 1
	done
}

dm_keys_permissions_protected()
{
	for dm_key in $DM_KEYS; do
		! keyctl setperm "$dm_key" 0x3f3f3f3f 2>/dev/null || return 1
		! keyctl timeout "$dm_key" 1 2>/dev/null || return 1
	done
}

test_expect_success 'the dm-verity keyring holds both config keys' '
	[ -n "$DM_RING" ] && [ -n "$DM_KEYS" ] &&
	[ "$(dm_keys_now)" = 2 ] &&
	dm_keys_describe
'

test_expect_success 'root cannot unlink, clear, revoke or invalidate either key' '
	[ -n "$DM_RING" ] && [ -n "$DM_KEYS" ] &&
	dm_keys_protected &&
	! keyctl clear "$DM_RING" 2>/dev/null &&
	! keyctl revoke "$DM_RING" 2>/dev/null &&
	! keyctl invalidate "$DM_RING" 2>/dev/null &&
	[ "$(dm_keys_now)" = 2 ]
'

test_expect_success 'root cannot change either key or link into the keyring' '
	[ -n "$DM_RING" ] && [ -n "$DM_KEYS" ] &&
	dm_keys_permissions_protected &&
	! keyctl setperm "$DM_RING" 0x3f3f3f3f 2>/dev/null &&
	! keyctl timeout "$DM_RING" 1 2>/dev/null &&
	! keyctl chown "$DM_RING" 1 2>/dev/null &&
	k=$(keyctl add user shirudo-test-t6112 x @s) &&
	! keyctl link "$k" "$DM_RING" 2>/dev/null &&
	keyctl unlink "$k" @s &&
	sleep 2 &&
	keyctl describe "$DM_RING" >/dev/null &&
	dm_keys_describe &&
	[ "$(dm_keys_now)" = 2 ]
'

test_expect_success 'status still finds the anchor it froze' '
	m=$("$SHIRUDO_BIN" status --json 2>/dev/null | report_field keyring_serial_matches) &&
	[ "$m" = "True" ]
'

test_done
