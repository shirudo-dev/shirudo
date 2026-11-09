#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./test-lib.sh

H=${SHIRUDO_TEST_CONFIG_HELPER:-$(pwd)/helper/test-config-update}
[ -x "$H" ] || test_skip_all "test-config-update helper not built"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

fresh() {
	mkdir -m 700 "$WORK/$1" &&
	"$H" "$WORK/$1" boot A >"$WORK/$1.out"
}

field() {
	sed -n "s/^$2=//p" "$1"
}

save_active() {
	(cd "$WORK/$1" && sha256sum state events simulator) >"$WORK/$1.active"
}

unchanged() {
	(cd "$WORK/$1" && sha256sum -c "$WORK/$1.active") >/dev/null
}

test_expect_success 'staging B leaves A, its PCR and its event log unchanged' '
	fresh stage && save_active stage &&
	"$H" "$WORK/stage" stage B >"$WORK/staged" &&
	unchanged stage &&
	grep -qx "stage_prefix=/verified/config-B" "$WORK/staged" &&
	"$H" "$WORK/stage" staged >"$WORK/eligible" &&
	grep -qx "eligible=0" "$WORK/eligible" &&
	! "$H" "$WORK/stage" boot B >/dev/null &&
	"$H" "$WORK/stage" check >/dev/null
'

for action in reset restart; do
	test_expect_success "$action selects B only on the next TPM boot and measures it once" '
		fresh boot-'"$action"' &&
		"$H" "$WORK/boot-'"$action"'" stage B >/dev/null &&
		"$H" "$WORK/boot-'"$action"'" '"$action"' >/dev/null &&
		"$H" "$WORK/boot-'"$action"'" staged >"$WORK/eligible" &&
		grep -qx "eligible=1" "$WORK/eligible" &&
		grep -qx "candidate=/verified/config-B" "$WORK/eligible" &&
		"$H" "$WORK/boot-'"$action"'" boot B >"$WORK/selected" &&
		grep -qx "prefix=/verified/config-B" "$WORK/selected" &&
		grep -qx "extends=2" "$WORK/selected" &&
		[ ! -e "$WORK/boot-'"$action"'/next-boot" ] &&
		"$H" "$WORK/boot-'"$action"'" boot B >"$WORK/repeated" &&
		grep -qx "extends=2" "$WORK/repeated"
	'
done

test_expect_success 'canceling a staged config is idempotent and leaves A active' '
	fresh cancel && save_active cancel &&
	"$H" "$WORK/cancel" stage B >/dev/null &&
	"$H" "$WORK/cancel" cancel-stage >/dev/null &&
	"$H" "$WORK/cancel" cancel-stage >/dev/null &&
	[ ! -e "$WORK/cancel/next-boot" ] && unchanged cancel
'

test_expect_success 'updating to the current root preserves the staged selection' '
	fresh same-root && "$H" "$WORK/same-root" stage B >/dev/null &&
	save_active same-root && cp "$WORK/same-root/next-boot" "$WORK/same-root.before" &&
	"$H" "$WORK/same-root" update A >/dev/null &&
	cmp "$WORK/same-root.before" "$WORK/same-root/next-boot" &&
	unchanged same-root
'

test_expect_success 'a completed live update removes an obsolete staged config' '
	fresh live && "$H" "$WORK/live" stage B >/dev/null &&
	"$H" "$WORK/live" update C >"$WORK/live.out" &&
	grep -qx "prefix=/verified/config-C" "$WORK/live.out" &&
	[ ! -e "$WORK/live/next-boot" ]
'

test_expect_success 'a staged record restored after its parent changed is ignored' '
	fresh stale && "$H" "$WORK/stale" stage B >/dev/null &&
	cp "$WORK/stale/next-boot" "$WORK/saved-stage" &&
	"$H" "$WORK/stale" update C >/dev/null &&
	cp "$WORK/saved-stage" "$WORK/stale/next-boot" &&
	"$H" "$WORK/stale" reset >/dev/null &&
	"$H" "$WORK/stale" staged >"$WORK/eligible" &&
	grep -qx "eligible=0" "$WORK/eligible" &&
	! "$H" "$WORK/stale" boot B >/dev/null &&
	"$H" "$WORK/stale" boot C >/dev/null &&
	[ ! -e "$WORK/stale/next-boot" ]
'

test_expect_success 'a pending update or PCR drift cannot stage another config' '
	fresh pending &&
	! SHIRUDO_TEST_CONFIG_EXTEND=before "$H" "$WORK/pending" update B >/dev/null &&
	! "$H" "$WORK/pending" stage C >/dev/null &&
	[ ! -e "$WORK/pending/next-boot" ] &&
	fresh drift && "$H" "$WORK/drift" drift >/dev/null &&
	! "$H" "$WORK/drift" stage B >/dev/null &&
	[ ! -e "$WORK/drift/next-boot" ]
'

test_expect_success 'process death while writing a replacement preserves the previous stage' '
	fresh interrupted && "$H" "$WORK/interrupted" stage B >/dev/null &&
	save_active interrupted && cp "$WORK/interrupted/next-boot" "$WORK/stage-before" &&
	SHIRUDO_TEST_CONFIG_STAGE_CRASH=1 "$H" "$WORK/interrupted" stage C >/dev/null;
	rc=$? && [ "$rc" = 99 ] &&
	unchanged interrupted && cmp "$WORK/stage-before" "$WORK/interrupted/next-boot" &&
	"$H" "$WORK/interrupted" stage C >"$WORK/replacement" &&
	grep -qx "stage_prefix=/verified/config-C" "$WORK/replacement" &&
	unchanged interrupted
'

test_expect_success 'an incomplete temporary record is ignored at the next boot' '
	fresh temporary && printf incomplete >"$WORK/temporary/.next-boot.tmp" &&
	"$H" "$WORK/temporary" reset >/dev/null &&
	"$H" "$WORK/temporary" boot A >"$WORK/temporary.out" &&
	grep -qx "prefix=/verified/config-A" "$WORK/temporary.out"
'

for invalid in malformed oversize symlink fifo; do
	test_expect_success "$invalid staged record fails without extending the PCR" '
		fresh invalid-'"$invalid"' &&
		case '"$invalid"' in
		malformed) printf invalid >"$WORK/invalid-'"$invalid"'/next-boot" ;;
		oversize) head -c 65536 /dev/zero >"$WORK/invalid-'"$invalid"'/next-boot" ;;
		symlink) ln -s state "$WORK/invalid-'"$invalid"'/next-boot" ;;
		fifo) mkfifo "$WORK/invalid-'"$invalid"'/next-boot" ;;
		esac &&
		"$H" "$WORK/invalid-'"$invalid"'" reset >/dev/null &&
		save_active invalid-'"$invalid"' &&
		! "$H" "$WORK/invalid-'"$invalid"'" staged >"$WORK/invalid.out" &&
		unchanged invalid-'"$invalid"'
	'
done

test_done
