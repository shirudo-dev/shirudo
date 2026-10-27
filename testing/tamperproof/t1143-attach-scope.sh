#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1143 -- the site a load attaches at is the caller's to arrange: a
# netfilter program hooks the caller's network namespace, a cgroup_skb
# program the root of the caller's cgroup namespace, and a kprobe is
# opened through the PMU number sysfs names. Root running the load in a
# namespace of its own, or with a uprobe PMU bound over the kprobe one,
# got a shield that guards nothing or the wrong thing, measured as loaded.
# The load must compare the link the kernel made with the metadata and
# refuse with attach_scope_mismatch; the same loads succeed in place.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NF="$FIXTURES/shirudo-test-scope-netfilter.upatch"
CG="$FIXTURES/shirudo-test-scope-cgroup.upatch"
KP="$FIXTURES/shirudo-test-scope-kprobe.upatch"
B=/run/shirudo/bpffs/upatches
KPROBE_TYPE=/sys/bus/event_source/devices/kprobe/type
WORK=/tmp/t1143
for f in "$NF" "$CG" "$KP"; do
	[ -s "$f" ] && [ -s "${f%.upatch}.unload.upatch" ] ||
		test_skip_all "missing scope fixture $f"
done
command -v unshare >/dev/null 2>&1 || test_skip_all "no unshare"
[ -r /sys/bus/event_source/devices/uprobe/type ] ||
	test_skip_all "no uprobe PMU"
# The kprobe cases need the kprobe PMU; the test kernel has none while
# unloading beside it oopses this bpf-next (shared LSM trampolines).
HAVE_KPROBE=0
[ -r "$KPROBE_TYPE" ] && HAVE_KPROBE=1

# Under the library's errexit a failing step would end the cleanup.
restore() {
	! mountpoint -q "$KPROBE_TYPE" || umount "$KPROBE_TYPE" || true
	for f in "$NF" "$CG" "$KP"; do
		"$SHIRUDO_BIN" upatch unload "${f%.upatch}.unload.upatch" \
			--no-precheck >/dev/null 2>&1 || true
	done
	rmdir /sys/fs/cgroup/t1143 2>/dev/null || true
	rm -rf "$WORK"
}
trap restore EXIT

category() {
	"$@" --no-precheck --report=- 2>/dev/null | report_field category
}

test_expect_success 'a netfilter load in another network namespace is refused' '
	[ "$(unshare -n "$SHIRUDO_BIN" upatch load "$NF" --no-precheck \
		--report=- 2>/dev/null | report_field category)" = attach_scope_mismatch ] &&
	[ ! -e "$B/shirudo-test-scope-netfilter" ]
'

# The child joins a cgroup of its own, so that the namespace root it then
# unshares is not the hierarchy's root; in a mount namespace of its own it
# replaces the cgroup tree with one mounted afresh, rooted at the
# namespace root, for the load to find.
test_expect_success 'a cgroup_skb load under a cgroup namespace root is refused' '
	mkdir -p "$WORK" /sys/fs/cgroup/t1143 &&
	cat >"$WORK/inner.sh" <<-EOF &&
	umount /sys/fs/cgroup && mount -t cgroup2 cgroup2 /sys/fs/cgroup || exit 1
	exec "$SHIRUDO_BIN" upatch load "$CG" --no-precheck --report=-
	EOF
	cat >"$WORK/cgns.sh" <<-EOF &&
	echo \$\$ >/sys/fs/cgroup/t1143/cgroup.procs
	exec unshare -Cm sh "$WORK/inner.sh"
	EOF
	[ "$(sh "$WORK/cgns.sh" 2>/dev/null | report_field category)" = attach_scope_mismatch ] &&
	[ ! -e "$B/shirudo-test-scope-cgroup" ]
'

if [ "$HAVE_KPROBE" = 1 ]; then
test_expect_success 'a kprobe load through a sysfs that names the uprobe PMU is refused' '
	mkdir -p "$WORK" && cp /bin/true "$WORK/do_nanosleep" &&
	cat /sys/bus/event_source/devices/uprobe/type >"$WORK/type" &&
	mount --bind "$WORK/type" "$KPROBE_TYPE" &&
	cat=$(cd "$WORK" && category "$SHIRUDO_BIN" upatch load "$KP") &&
	umount "$KPROBE_TYPE" &&
	[ "$cat" = attach_scope_mismatch ] &&
	[ ! -e "$B/shirudo-test-scope-kprobe" ]
'
fi

test_expect_success 'the same loads succeed in the initial namespaces' '
	[ "$(category "$SHIRUDO_BIN" upatch load "$NF")" = ok ] &&
	[ "$(category "$SHIRUDO_BIN" upatch load "$CG")" = ok ] &&
	[ -e "$B/shirudo-test-scope-netfilter/link" ] &&
	[ -e "$B/shirudo-test-scope-cgroup/link" ] &&
	{ [ "$HAVE_KPROBE" = 0 ] ||
	  { [ "$(category "$SHIRUDO_BIN" upatch load "$KP")" = ok ] &&
	    [ -e "$B/shirudo-test-scope-kprobe/link" ]; }; }
'

test_done
