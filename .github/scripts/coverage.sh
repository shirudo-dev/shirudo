#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/coverage.sh -- after the tests of a COVERAGE=1 build,
# write coverage/shirudo.lcov from the counters of the host's binaries
# and, where the test VMs ran, of the target in each guest.
#
#   .github/scripts/coverage.sh [--sudo-container]

set -eu

cd "$(dirname "$0")/../.."
mkdir -p coverage

capture() {
	suffix=$1
	shift

	# VM state under build/ may be inaccessible and holds no host counters.
	# Helpers write production counters alongside the linked objects.
	for dir in \
		. \
		util \
		tools/shirudo-build \
		tools/quote-check \
		build/unit \
		build/quote-check/util \
		build/quote-check/tools/quote-check
	do
		for profile in "$dir"/*."$suffix"; do
			[ -f "$profile" ] || continue
			set -- "$@" --directory "$dir"
			break
		done
	done
	lcov --capture --no-recursion "$@"
}

# The counters of the guests of one bundle, as one tracefile. gcov reads
# counters beside the notes of their build, with the gcov of the compiler
# that wrote them and the sources where the build had them: this runs in
# the build container, which mounts the checkout at its own path.
capture_target() {
	bundle=$1
	srcdir=$(cat "$bundle/coverage/srcdir")
	work=$(mktemp -d)
	n=0

	[ -e "$srcdir" ] || ln -s "$PWD" "$srcdir"
	mkdir -p "$work/notes$srcdir"
	tar -C "$work/notes$srcdir" -xf "$bundle/coverage/gcno.tar"
	lcov --capture --initial --directory "$work/notes" \
		--output-file "$work/notes.lcov"
	set -- --add-tracefile "$work/notes.lcov"
	for counters in build/test-vm/coverage/*.tar; do
		[ -f "$counters" ] || continue
		n=$((n + 1))
		cp -a "$work/notes" "$work/$n"
		tar -C "$work/$n" -xf "$counters"
		lcov --capture --ignore-errors inconsistent \
			--directory "$work/$n" --output-file "$work/$n.lcov"
		rm -rf "$work/$n"
		set -- "$@" --add-tracefile "$work/$n.lcov"
	done
	[ "$n" -gt 0 ] || {
		echo "coverage.sh: no guest left counters in build/test-vm/coverage" >&2
		exit 1
	}
	lcov --ignore-errors inconsistent "$@" --output-file "$work/target.lcov"
	sed "s#^SF:$srcdir/#SF:$PWD/#" "$work/target.lcov" >coverage/target.lcov
	rm -rf "$work"
}

if [ "${1:-}" = target ]; then
	capture_target "$2"
	exit 0
fi

sudo_container=${1:-}

capture_guest() {
	set -- testing/container/run.sh -v "$PWD/coverage" -- \
		"$PWD/.github/scripts/coverage.sh" target "$1"
	if [ "$sudo_container" = --sudo-container ]; then
		set -- sudo "$@"
	fi
	# Keep the tracefile owned by the caller even if the container runs as root.
	: >coverage/target.lcov
	"$@"
}

capture gcno --initial --output-file coverage/baseline.lcov
capture gcda --output-file coverage/run.lcov
set -- --add-tracefile coverage/baseline.lcov --add-tracefile coverage/run.lcov

for bundle in build/test-vm/host-bundle-*; do
	[ -d "$bundle/coverage" ] || continue
	capture_guest "$PWD/$bundle"
	set -- "$@" --add-tracefile coverage/target.lcov
	break
done

# Optimized code can give gcov different hit counts for a function and its
# lines, and the host and the target compile one source with other options.
lcov --ignore-errors inconsistent "$@" --output-file coverage/combined.lcov
lcov --ignore-errors inconsistent \
	--extract coverage/combined.lcov "$PWD/*" --output-file coverage/repo.lcov
lcov --ignore-errors inconsistent,unused \
	--remove coverage/repo.lcov "$PWD/testing/*" "$PWD/vendor/*" \
	"$PWD/build/*" "$PWD/util/version_id.c" \
	--output-file coverage/shirudo.lcov
