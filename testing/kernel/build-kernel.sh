#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
# Build Debian packages from the pinned bpf-next source for the test VMs.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
	cat <<USAGE
usage: ${0##*/} [options]

  -a, --arch ARCH        x86-64 or arm64 (default: host arch)
  -o, --out DIR          work and output directory (default: build/test-kernel/)
  -j, --jobs N           parallel jobs (default: nproc)
      --llvm VER         LLVM version (default: newest complete version on PATH)
      --config-only      apply patches and verify .config, then stop
  -h, --help

Environment: CC/HOSTCC are not read; MAKEFLAGS is passed through.
USAGE
}

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "error: $*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

host_arch() {
	case "$(uname -m)" in
	x86_64) echo x86-64 ;;
	aarch64) echo arm64 ;;
	*) die "unsupported host architecture $(uname -m)" ;;
	esac
}

ARCH="$(host_arch)"
OUT="$(cd "$REPO/../.." && pwd)/build/test-kernel"
JOBS="$(nproc)"
LLVM_VER=""
CONFIG_ONLY=0

while [ $# -gt 0 ]; do
	case "$1" in
	-a|--arch) ARCH="$2"; shift 2 ;;
	-o|--out) OUT="$(mkdir -p "$2" && cd "$2" && pwd)"; shift 2 ;;
	-j|--jobs) JOBS="$2"; shift 2 ;;
	--llvm) LLVM_VER="$2"; shift 2 ;;
	--config-only) CONFIG_ONLY=1; shift ;;
	-h|--help) usage; exit 0 ;;
	*) usage >&2; die "unknown argument: $1" ;;
	esac
done

case "$ARCH" in
x86-64) KARCH=x86_64 ;;
arm64)  KARCH=arm64 ;;
*) die "unsupported --arch $ARCH (x86-64, arm64)" ;;
esac

[[ -z "$LLVM_VER" || "$LLVM_VER" =~ ^[0-9]+$ ]] || die "--llvm takes a version number"
for t in make flex bison bc pahole python3 cpio zstd xz pkg-config rsync; do
	have "$t" || die "$t is required"
done
if [ "$CONFIG_ONLY" = 0 ]; then
	for t in dpkg-deb fakeroot dh_listpackages; do
		have "$t" || die "$t is required for Debian packages"
	done
fi
FRAGMENTS=("$REPO/kernel-ci.conf" "$REPO/kernel-ci.$ARCH.conf")

# ---------------------------------------------------------------------------
# Toolchain
# ---------------------------------------------------------------------------
# One LLVM version throughout: the unversioned tools for suffix "", or
# clang-20, ld.lld-20 and so on for "-20".  The newest complete versioned
# install is the default because resolve_btfids's fmod_ret scan
# (BPF_FMODRET_SCAN) needs the headers of LLVM 17 or later, which the
# distribution default may lack, and Kbuild takes llvm-config with the
# same suffix.
llvm_complete() {
	local t
	for t in clang ld.lld llvm-objcopy llvm-ar llvm-nm; do have "$t$1" || return 1; done
}
newest_llvm() {
	local v best=""
	for v in $(compgen -c clang- | sed -n 's/^clang-\([0-9][0-9]*\)$/\1/p' | sort -n -u); do
		llvm_complete "-$v" && best="$v"
	done
	echo "$best"
}
[ -n "$LLVM_VER" ] || LLVM_VER="$(newest_llvm)"
LLVM_SFX="${LLVM_VER:+-$LLVM_VER}"
llvm_complete "$LLVM_SFX" || die "LLVM toolchain is incomplete ($LLVM_SFX)"
OBJCOPY="llvm-objcopy$LLVM_SFX"

# ---------------------------------------------------------------------------
# Pinned source and carried patches
# ---------------------------------------------------------------------------
read -r SHA <"$REPO/bpf-next.commit"
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || die "invalid bpf-next commit in bpf-next.commit"
UPSTREAM=https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git
SRC="$OUT/src"
OBJ="$OUT/obj-$ARCH"
if [ ! -d "$SRC/.git" ]; then
	git init -q "$SRC"
fi
if ! git -C "$SRC" cat-file -e "$SHA^{commit}" 2>/dev/null; then
	# Three-way patch application also needs the patch preimage blobs.
	git -C "$SRC" fetch --no-tags --shallow-since=2026-09-06 "$UPSTREAM" "$SHA"
fi
git -C "$SRC" checkout --detach --quiet "$SHA"
PATCHES=("$REPO"/patches/*.patch)
AM_DATE="$(git -C "$SRC" log -1 --format=%cd --date=raw "$SHA")"
for p in "${PATCHES[@]}"; do
	log "applying $(basename "$p")"
	if ! GIT_COMMITTER_NAME=shirudo GIT_COMMITTER_EMAIL=shirudo@build-kernel \
	     GIT_COMMITTER_DATE="$AM_DATE" git -C "$SRC" -c core.hooksPath=/dev/null am --quiet --3way "$p"; then
		git -C "$SRC" status --short >&2
		git -C "$SRC" diff --cc >&2
		git -C "$SRC" am --abort || true
		die "patch does not apply to $SHA: $p"
	fi
done
SRC_DESC="$(git -C "$SRC" describe --tags --always HEAD 2>/dev/null || echo "$SHA")"

# shirudo's signed-loader support (the bpf keyring, exclusive maps and the
# BPF_PROG_LOAD signature check) ships with Linux 7.4; warn when the tree
# predates it so nobody expects "shirudo init" to pass on this kernel.
if [ ! -f "$SRC/kernel/bpf/keys.c" ]; then
	log "warning: $SHA has no kernel/bpf/keys.c: no bpf keyring, shirudo init will refuse this kernel (needs Linux 7.4 or the bpf-next branch)"
fi

# ---------------------------------------------------------------------------
# Lint: every symbol named in the fragments must exist in this tree
# ---------------------------------------------------------------------------
KNOWN="$OBJ/.known-symbols"
mkdir -p "$OBJ"
grep -rhoE '^[[:space:]]*(menu)?config[[:space:]]+[A-Za-z0-9_]+' --include='Kconfig*' "$SRC" |
	awk '{print $2}' | sort -u > "$KNOWN"
lint_file() {
	local f="$1" sym
	while IFS= read -r sym; do
		grep -qx "$sym" "$KNOWN" || log "lint: $(basename "$f"): CONFIG_$sym does not exist in $SHA"
	done < <(sed -nE 's/^CONFIG_([A-Za-z0-9_]+)=.*/\1/p; s/^# CONFIG_([A-Za-z0-9_]+) is not set$/\1/p' "$f" | sort -u)
}
for f in "${FRAGMENTS[@]}"; do lint_file "$f"; done

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
kmake() { make -C "$SRC" O="$OBJ" ARCH="$KARCH" LLVM="${LLVM_SFX:-1}" "$@"; }

log "base: $KARCH allnoconfig"
kmake -s allnoconfig

log "merging ${FRAGMENTS[*]##*/}"
(cd "$SRC" && KCONFIG_CONFIG="$OBJ/.config" \
	scripts/kconfig/merge_config.sh -m -O "$OBJ" "$OBJ/.config" "${FRAGMENTS[@]}") >"$OBJ/merge.log" 2>&1 ||
	{ cat "$OBJ/merge.log" >&2; die "merge_config.sh failed"; }
grep -E 'Value of|redefined' "$OBJ/merge.log" | sed 's/^/merge: /' >&2 || true

LV_BASE="$(sed -nE 's/^CONFIG_LOCALVERSION="(.*)"$/\1/p' "${FRAGMENTS[@]}" | tail -1)"
LV="$LV_BASE-$(date -u +%Y%m%d)"
"$SRC/scripts/config" --file "$OBJ/.config" --set-str LOCALVERSION "$LV"
export LOCALVERSION=""

log "make olddefconfig"
kmake -s olddefconfig

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
declare -A WANT WANTSRC FINAL
for f in "${FRAGMENTS[@]}"; do
	fragment=${f##*/}
	while IFS= read -r line; do
		case "$line" in
		"# CONFIG_"*" is not set") sym="${line#\# CONFIG_}"; sym="${sym% is not set}"; WANT[$sym]=n ;;
		CONFIG_*=*) sym="${line%%=*}"; sym="${sym#CONFIG_}"; WANT[$sym]="${line#*=}" ;;
		*) continue ;;
		esac
		WANTSRC[$sym]="$fragment"
	done < "$f"
done
while IFS= read -r line; do
	case "$line" in
	"# CONFIG_"*" is not set") sym="${line#\# CONFIG_}"; FINAL[${sym% is not set}]=n ;;
	CONFIG_*=*) sym="${line%%=*}"; FINAL[${sym#CONFIG_}]="${line#*=}" ;;
	esac
done < "$OBJ/.config"

WANT[LOCALVERSION]="\"$LV\""

FAIL=0
for sym in $(printf '%s\n' "${!WANT[@]}" | sort); do
	want="${WANT[$sym]}"; got="${FINAL[$sym]:-unset}"; ok=1
	case "$want" in
	n) [ "$got" = y ] || [ "$got" = m ] && ok=0 ;;
	y) [ "$got" = y ] || ok=0 ;;
	m) [ "$got" = m ] || [ "$got" = y ] || ok=0 ;;
	*) [ "$got" = "$want" ] || ok=0 ;;
	esac
	[ "$ok" = 1 ] && continue
	log "error: CONFIG_$sym wanted $want by ${WANTSRC[$sym]}, final .config has $got"
	FAIL=$((FAIL + 1))
done
# Two invariants the whole setup rests on, checked on the final result
# regardless of what the fragments say. [S]
[ "${FINAL[LSM]:-}" = '"bpf"' ] || { log "error: CONFIG_LSM is ${FINAL[LSM]:-unset}, must be \"bpf\""; FAIL=$((FAIL + 1)); }
[ "${FINAL[DYNAMIC_FTRACE_WITH_DIRECT_CALLS]:-}" = y ] || { log "error: CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS is not y: shirudo cannot attach trampolines"; FAIL=$((FAIL + 1)); }
[ "$FAIL" = 0 ] || die "$FAIL configuration mismatch(es); .config left at $OBJ/.config"
log "configuration verified (${#WANT[@]} fragment symbols)"

# kernelrelease reads CONFIG_LOCALVERSION* from include/config/auto.conf,
# which only syncconfig writes.
kmake -s syncconfig
KREL="$(kmake -s kernelrelease)"
KVER="$(kmake -s kernelversion)"
cp "$OBJ/.config" "$OUT/kernel-$ARCH.config"

log "release: $KREL ($SRC_DESC)"
if [ "$CONFIG_ONLY" = 1 ]; then
	log "config written to $OUT/kernel-$ARCH.config"
	exit 0
fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
STAMP="$(date -u +%Y%m%d%H%M)"
PKGDIR="$OUT/pkgs/$ARCH/$KREL-$STAMP"
mkdir -p "$PKGDIR"
# Reproducible metadata: timestamp of the source commit, fixed user/host.
# Patch commits carry the pinned commit date, so with
# patches applied this is still the upstream date.
KBUILD_BUILD_TIMESTAMP="$(git -C "$SRC" log -1 --format=%cD HEAD)"
export KBUILD_BUILD_TIMESTAMP
export KBUILD_BUILD_USER=shirudo KBUILD_BUILD_HOST=build-kernel
SOURCE_DATE_EPOCH="$(git -C "$SRC" log -1 --format=%ct HEAD)"
export SOURCE_DATE_EPOCH

PKGVER="${KVER//-rc/\~rc}-${STAMP}.g${SHA:0:12}"
PROFILES=(pkg.linux-upstream.nokerneldbg)
# The headers package needs a GNU cross compiler to build the target tools.
[ "$(host_arch)" = "$ARCH" ] || PROFILES+=(pkg.linux-upstream.nokernelheaders)
DIST="$(lsb_release -cs 2>/dev/null || echo unstable)"
log "building bindeb-pkg $PKGVER for $ARCH (-j$JOBS)"
DEB_BUILD_PROFILES="${PROFILES[*]}" \
	kmake -j"$JOBS" bindeb-pkg KDEB_PKGVERSION="$PKGVER" KDEB_CHANGELOG_DIST="$DIST" \
		DPKG_FLAGS="--no-check-builddeps"
mv "$OUT"/*_"${PKGVER}"_*.deb "$OUT"/*_"${PKGVER}"_*.buildinfo "$OUT"/*_"${PKGVER}"_*.changes "$PKGDIR"/
ls "$PKGDIR"/*.deb >/dev/null 2>&1 || die "no .deb produced for $PKGVER"

# ---------------------------------------------------------------------------
# Side artifacts: config, BTF for vmlinux.h generation, build info
# ---------------------------------------------------------------------------
cp "$OBJ/.config" "$PKGDIR/config-$KREL"
cp "$OBJ/System.map" "$PKGDIR/System.map-$KREL"
# The module signing certificate (public half) travels with the packages;
# the private key stays where it was: the object tree when generated here.
if [ -f "$OBJ/certs/signing_key.x509" ]; then
	cp "$OBJ/certs/signing_key.x509" "$PKGDIR/module-signing-cert-$KREL.der"
fi
"$OBJCOPY" --dump-section .BTF="$PKGDIR/vmlinux-$KREL.btf" "$OBJ/vmlinux" /dev/null 2>/dev/null ||
	"$OBJCOPY" --dump-section .BTF="$PKGDIR/vmlinux-$KREL.btf" "$OBJ/vmlinux" "$OBJ/.vmlinux.btf-tmp"
rm -f "$OBJ/.vmlinux.btf-tmp"
[ -s "$PKGDIR/vmlinux-$KREL.btf" ] || die "vmlinux has no .BTF section"
# Use commit metadata for the kernel archive and fixed metadata for the recipe
# so both architecture jobs can verify the same source archive.
git -C "$SRC" archive --format=tar --prefix=linux/ HEAD >"$OUT/kernel-ci-source.tar"
tar --append --file="$OUT/kernel-ci-source.tar" --sort=name --owner=0 --group=0 \
	--numeric-owner --mtime="@$SOURCE_DATE_EPOCH" -C "$REPO/../.." testing/kernel
zstd -q -f "$OUT/kernel-ci-source.tar" -o "$OUT/kernel-ci-source.tar.zst"
rm -f "$OUT/kernel-ci-source.tar"
source_sha256=$(sha256sum "$OUT/kernel-ci-source.tar.zst")
{
	echo "ref=bpf-next"
	echo "commit=$SHA"
	echo "patched_commit=$(git -C "$SRC" rev-parse HEAD)"
	echo "describe=$SRC_DESC"
	echo "patches=${PATCHES[*]##*/}"
	echo "arch=$ARCH"
	echo "kernelrelease=$KREL"
	echo "toolchain=llvm"
	echo "compiler=$(grep -E '^CONFIG_CC_VERSION_TEXT=' "$OBJ/.config" | cut -d= -f2-)"
	echo "base=allnoconfig"
	echo "profile=ci"
	echo "fragments_sha256=$(cat "${FRAGMENTS[@]}" | sha256sum | cut -d' ' -f1)"
	echo "producer_commit=$(git -C "$REPO" rev-parse HEAD)"
	echo "run_id=${GITHUB_RUN_ID:-}"
	echo "run_attempt=${GITHUB_RUN_ATTEMPT:-}"
	echo "source_sha256=${source_sha256%% *}"
	echo "libcrypto=$(pkg-config --modversion libcrypto 2>/dev/null || echo unknown)"
	echo "built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$PKGDIR/BUILD-INFO"
(cd "$PKGDIR" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > ../SHA256SUMS && mv ../SHA256SUMS .)
log "packages in $PKGDIR:"
ls -1 "$PKGDIR" >&2
