#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# tools/bpf-deps/bpf-deps.sh [KERNEL_SRC] -- refresh vendor/libbpf from a
# kernel tree. Without an argument (or KERNEL_SRC in the environment) a
# shallow clone of bpf-next is used. Overwrites the copied sources and UAPI
# headers, regenerates bpf_helper_defs.h, records the commit in COMMIT and
# rebuilds libbpf.a as a check. Run on demand only; builds never call it.

set -eu

REPO_ROOT=$(CDPATH= cd "$(dirname "$0")/../.." && pwd)
VENDOR="$REPO_ROOT/vendor/libbpf"
REPOSITORY="${BPF_NEXT_REPOSITORY:-git://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git}"
KERNEL_SRC="${1:-${KERNEL_SRC:-}}"
tmp=""

# UAPI headers libbpf includes, plus the ones they include in turn that
# the kernel keeps under tools/include/uapi. Anything else resolves to the
# system's linux-libc-dev, which is stable enough for it.
UAPI_HEADERS="bpf.h bpf_common.h btf.h bpf_perf_event.h perf_event.h
	netlink.h rtnetlink.h genetlink.h if_link.h if_addr.h neighbour.h
	netdev.h pkt_cls.h pkt_sched.h types.h const.h bits.h stddef.h"

die()
{
	printf 'bpf-deps: %s\n' "$*" >&2
	exit 1
}

cleanup()
{
	if [ -n "$tmp" ]; then
		rm -rf "$tmp"
	fi
}
trap cleanup EXIT HUP INT TERM

if [ -z "$KERNEL_SRC" ]; then
	tmp=$(mktemp -d)
	printf 'bpf-deps: cloning %s\n' "$REPOSITORY"
	git clone --depth 1 --single-branch "$REPOSITORY" "$tmp/bpf-next"
	KERNEL_SRC="$tmp/bpf-next"
	source_desc="$REPOSITORY"
else
	source_desc="$KERNEL_SRC"
fi

for f in tools/lib/bpf/libbpf.c tools/lib/bpf/libbpf.h \
	 tools/include/uapi/linux/bpf.h scripts/bpf_doc.py; do
	[ -r "$KERNEL_SRC/$f" ] || die "not a kernel tree (missing $f): $KERNEL_SRC"
done
for h in $UAPI_HEADERS; do
	[ -r "$KERNEL_SRC/tools/include/uapi/linux/$h" ] ||
		die "kernel tree lacks tools/include/uapi/linux/$h"
done
command -v python3 >/dev/null 2>&1 || die "python3 is needed for scripts/bpf_doc.py"

mkdir -p "$VENDOR/bpf" "$VENDOR/include/uapi/linux"
rm -f "$VENDOR"/bpf/*.c "$VENDOR"/bpf/*.h "$VENDOR"/bpf/*.o "$VENDOR"/bpf/*.d \
	"$VENDOR"/include/uapi/linux/*.h "$VENDOR/libbpf.a"

cp "$KERNEL_SRC"/tools/lib/bpf/*.c "$KERNEL_SRC"/tools/lib/bpf/*.h "$VENDOR/bpf/"
for h in $UAPI_HEADERS; do
	cp "$KERNEL_SRC/tools/include/uapi/linux/$h" "$VENDOR/include/uapi/linux/"
done
# The tree may carry a stale generated copy; always regenerate from the
# UAPI header that was just copied.
python3 "$KERNEL_SRC/scripts/bpf_doc.py" --header \
	--file "$KERNEL_SRC/tools/include/uapi/linux/bpf.h" \
	> "$VENDOR/bpf/bpf_helper_defs.h"

commit=$(git -C "$KERNEL_SRC" rev-parse HEAD 2>/dev/null || echo unknown)
describe=$(git -C "$KERNEL_SRC" describe --always --tags 2>/dev/null || echo unknown)
{
	printf '# Written by tools/bpf-deps/bpf-deps.sh; do not edit.\n'
	printf 'source=%s\n' "$source_desc"
	printf 'commit=%s\n' "$commit"
	printf 'describe=%s\n' "$describe"
	printf 'updated=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$VENDOR/COMMIT"

printf 'bpf-deps: rebuilding vendor/libbpf/libbpf.a as a check\n'
make -C "$VENDOR" clean all
printf 'bpf-deps: vendor/libbpf now at %s (%s)\n' "$describe" "$commit"
