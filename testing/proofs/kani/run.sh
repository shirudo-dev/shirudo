#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Run one shard of the Kani harnesses. KANI_PROOFS selects named harnesses
# for a local run; CI uses the complete list.

set -eu
cd "$(dirname "$0")/../../.."
version=$(cat testing/proofs/kani/version)
installed=$(cargo kani --version | sed -n 's/^Kani Rust Verifier \([^ ]*\).*/\1/p')
[ "$installed" = "$version" ] || {
    printf 'kani: need version %s, found %s\n' "$version" "$installed" >&2
    exit 1
}
shard=${1:-1}
total=${2:-1}
case "$shard:$total" in
    *[!0-9:]*|:*|*:) echo 'kani: shard and total must be positive numbers' >&2; exit 1 ;;
esac
[ "$shard" -ge 1 ] && [ "$total" -ge "$shard" ] || {
    echo 'kani: shard must be between 1 and total' >&2
    exit 1
}
mkdir -p build/kani
# Proofs belong in kani.rs modules, where their module path is known.
if find rust/src -name '*.rs' ! -name kani.rs -exec grep -lF '#[kani::proof]' {} + |
    grep . >build/kani/unlisted-source.list; then
    cat build/kani/unlisted-source.list >&2
    echo 'kani: proof outside a kani.rs module' >&2
    exit 1
fi
# Every source harness must be named by the run list. Keep its module path
# for --exact, which otherwise matches another harness with the same suffix.
find rust/src -name kani.rs | while IFS= read -r source; do
    module=${source#rust/src/}
    module=${module%/kani.rs}
    module=$(printf '%s' "$module" | sed 's|/|::|g')
    awk -v module="$module" '
        /#\[kani::proof\]/ { proof = 1; next }
        proof && /^fn [A-Za-z0-9_]+\(/ {
            name = $2; sub(/\(.*/, "", name)
            print name, module "::proofs::" name
            proof = 0
        }
    ' "$source"
done | sort >build/kani/source.names
awk '{ print $1 }' build/kani/source.names | sort >build/kani/source.list
awk 'NF && $1 !~ /^#/ { print $1 }' testing/proofs/kani/proofs.list | sort >build/kani/declared.list
if ! diff -u build/kani/source.list build/kani/declared.list; then
    echo 'kani: source harnesses differ from proofs.list' >&2
    exit 1
fi
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$PWD/build/kani/target}
if [ -n "${KANI_PROOFS:-}" ]; then
    printf '%s\n' $KANI_PROOFS >build/kani/selected.list
else
    cp testing/proofs/kani/proofs.list build/kani/selected.list
fi
number=0
ran=0
while IFS= read -r proof; do
    case "$proof" in ''|\#*) continue ;; esac
    number=$((number + 1))
    [ $(((number - 1) % total + 1)) -eq "$shard" ] || continue
    full_name=$(awk -v name="$proof" '$1 == name { print $2 }' build/kani/source.names)
    [ -n "$full_name" ] || {
        printf 'kani: unknown harness %s\n' "$proof" >&2
        exit 1
    }
    start=$(date +%s)
    # A proof that grows past 6 GiB fails without exhausting Genoa or CI.
    if (cd rust && ulimit -v 6291456 && timeout -k 15s 600s cargo kani --default-unwind 16 --harness "$full_name" --exact) >"build/kani/$proof.log" 2>&1; then
        elapsed=$(($(date +%s) - start))
        printf 'kani: %s holds (%ss)\n' "$proof" "$elapsed"
    else
        cat "build/kani/$proof.log"
        printf 'kani: %s failed\n' "$proof" >&2
        exit 1
    fi
    ran=$((ran + 1))
done <build/kani/selected.list
printf 'kani: %s harnesses hold in shard %s/%s\n' "$ran" "$shard" "$total"
