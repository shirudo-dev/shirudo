#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
# build-kernel.sh: build bootable kernel packages from the upstream/bpf-next
# branch of this repository, the only base patches/ supports for now, with
# the hardened configuration assembled from kernel.conf, kernel.<arch>.conf
# and blacklist.conf.
#
# The source is checked out as a detached git worktree under build/src,
# patches/*.patch are applied on top, the configuration is assembled out
# of tree (build/obj-<arch>) and verified, and bindeb-pkg and/or
# binrpm-pkg produce the packages under build/pkgs/<arch>/<release>/.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
	cat <<USAGE
usage: ${0##*/} [options]

  -a, --arch ARCH        x86-64 | arm64 | riscv64 (default: host arch)
  -f, --format FORMAT    deb | rpm | both (default: deb when dpkg-deb
                         exists, otherwise rpm)
  -r, --ref REF          git ref to build (default and, for now, the only
                         one supported: upstream/bpf-next, see patches/)
  -o, --out DIR          work and output directory (default: build/)
  -j, --jobs N           parallel jobs (default: nproc)
  -t, --toolchain TC     llvm | gcc (default: llvm when clang and ld.lld
                         are installed, otherwise gcc)
  -b, --base BASE        defconfig (default) or a path to a .config to
                         start from instead of the arch defconfig
      --localversion S   use S verbatim as CONFIG_LOCALVERSION instead of
                         the kernel.conf value plus -YYYYMMDD (build day)
      --module-key PEM   sign modules with this key+certificate PEM
                         (ML-DSA-87, see kernel.conf) instead of a key
                         generated in the object tree
      --llvm VER         LLVM version for --toolchain llvm, e.g. 20 for
                         clang-20, ld.lld-20 and llvm-config-20 (default:
                         the newest one installed completely, else the
                         unversioned tools)
      --openssl DIR      OpenSSL >= 3.5 prefix for key generation and
                         sign-file (bin/ and lib*/pkgconfig/ are used);
                         also read from \$OPENSSL_PREFIX
      --config-only      assemble and verify .config, then stop
      --with-dbg         also build the debug-symbol package
      --no-patches       do not apply patches/*.patch
      --keep-src         do not reset the source worktree to REF
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
	riscv64) echo riscv64 ;;
	*) die "unsupported host architecture $(uname -m)" ;;
	esac
}

ARCH="$(host_arch)"
FORMAT=""
REF="upstream/bpf-next"
OUT="$REPO/build"
JOBS="$(nproc)"
TOOLCHAIN=""
BASE="defconfig"
LOCALVERSION=""
MODULE_KEY=""
OPENSSL_PREFIX="${OPENSSL_PREFIX:-}"
LLVM_VER=""
CONFIG_ONLY=0
WITH_DBG=0
APPLY_PATCHES=1
KEEP_SRC=0

while [ $# -gt 0 ]; do
	case "$1" in
	-a|--arch) ARCH="$2"; shift 2 ;;
	-f|--format) FORMAT="$2"; shift 2 ;;
	-r|--ref) REF="$2"; shift 2 ;;
	-o|--out) OUT="$(mkdir -p "$2" && cd "$2" && pwd)"; shift 2 ;;
	-j|--jobs) JOBS="$2"; shift 2 ;;
	-t|--toolchain) TOOLCHAIN="$2"; shift 2 ;;
	-b|--base) BASE="$2"; shift 2 ;;
	--localversion) LOCALVERSION="$2"; shift 2 ;;
	--module-key) MODULE_KEY="$(readlink -f "$2")"; shift 2 ;;
	--openssl) OPENSSL_PREFIX="$2"; shift 2 ;;
	--llvm) LLVM_VER="$2"; shift 2 ;;
	--config-only) CONFIG_ONLY=1; shift ;;
	--with-dbg) WITH_DBG=1; shift ;;
	--no-patches) APPLY_PATCHES=0; shift ;;
	--keep-src) KEEP_SRC=1; shift ;;
	-h|--help) usage; exit 0 ;;
	*) usage >&2; die "unknown argument: $1" ;;
	esac
done

# Apply the carried patches to their upstream bpf-next base.
[ "$REF" = upstream/bpf-next ] ||
	die "unsupported --ref $REF: patches/ targets upstream/bpf-next, the only tree supported for now"

# Architecture table: kernel ARCH, uname machine, Debian arch, GNU triplet
# prefix for a GCC cross build, the arch defconfig target.
case "$ARCH" in
x86-64)  KARCH=x86_64; UTS=x86_64;  DEBARCH=amd64;   CROSS=x86_64-linux-gnu- ;;
arm64)   KARCH=arm64;  UTS=aarch64; DEBARCH=arm64;   CROSS=aarch64-linux-gnu- ;;
riscv64) KARCH=riscv;  UTS=riscv64; DEBARCH=riscv64; CROSS=riscv64-linux-gnu- ;;
*) die "unsupported --arch $ARCH (x86-64, arm64, riscv64)" ;;
esac
DEFCONFIG=defconfig

if [ -z "$FORMAT" ]; then
	if have dpkg-deb; then FORMAT=deb; elif have rpmbuild; then FORMAT=rpm;
	else die "neither dpkg-deb nor rpmbuild found"; fi
fi
case "$FORMAT" in deb|rpm|both) ;; *) die "unsupported --format $FORMAT" ;; esac
[[ -z "$LLVM_VER" || "$LLVM_VER" =~ ^[0-9]+$ ]] || die "--llvm takes a version number such as 20, not $LLVM_VER"
[ "$FORMAT" = rpm ] || have dpkg-deb || die "dpkg-deb (dpkg-dev) is required for deb packages"
[ "$FORMAT" = rpm ] || have fakeroot || die "fakeroot is required for deb packages"
[ "$FORMAT" = rpm ] || have dh_listpackages || die "dh_listpackages (debhelper) is required for deb packages; install debhelper"
[ "$FORMAT" = deb ] || have rpmbuild || die "rpmbuild (rpm-build) is required for rpm packages"
for t in make flex bison bc pahole python3 cpio zstd xz pkg-config; do
	have "$t" || die "$t is required"
done
have rsync || die "rsync is required (install rsync; Linux headers_install uses it)"
if [ -n "$OPENSSL_PREFIX" ]; then
	[ -d "$OPENSSL_PREFIX" ] || die "--openssl prefix not found: $OPENSSL_PREFIX"
	export PATH="$OPENSSL_PREFIX/bin:$PATH"
	export PKG_CONFIG_PATH="$OPENSSL_PREFIX/lib64/pkgconfig:$OPENSSL_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
fi
if [ -n "$MODULE_KEY" ]; then
	[ -f "$MODULE_KEY" ] || die "module key not found: $MODULE_KEY"
	grep -q "PRIVATE KEY-----" "$MODULE_KEY" && grep -q "BEGIN CERTIFICATE-----" "$MODULE_KEY" ||
		die "module key must be one PEM file with the private key and its certificate: $MODULE_KEY"
fi

FRAGMENTS=("$REPO/kernel.conf" "$REPO/kernel.$ARCH.conf")
BLACKLIST="$REPO/blacklist.conf"
for f in "${FRAGMENTS[@]}" "$BLACKLIST"; do
	[ -f "$f" ] || die "missing $f"
done
# An ML-DSA module signing key (kernel.conf) is only selectable when
# Kconfig's OPENSSL_SUPPORTS_ML_DSA probe finds an openssl CLI with
# ML-DSA on PATH, so this must hold before the configuration is assembled,
# with or without --module-key.
if grep -qE '^CONFIG_MODULE_SIG_KEY_TYPE_MLDSA_[0-9]+=y' "${FRAGMENTS[@]}" &&
   ! openssl list -key-managers 2>/dev/null | grep -q 'ML-DSA-87'; then
	die "$(command -v openssl || echo openssl) ($(openssl version 2>/dev/null || echo missing)) has no ML-DSA; the ML-DSA module signing key in kernel.conf needs OpenSSL >= 3.5 on PATH (use --openssl DIR or \$OPENSSL_PREFIX)"
fi

# Symbols a fragment may ask for that only some compilers (or, for the
# arch-dependent ones, some architectures) can provide.  They are dropped
# with a warning instead of failing the build; everything else in the
# fragments must land in the final .config exactly as requested.
ALLOW_DROP=(
	# clang only
	CFI CFI_AUTO_DEFAULT SHADOW_CALL_STACK UNWIND_PATCH_PAC_INTO_SCS
	# GCC plugin or clang >= 21
	KSTACK_ERASE
	# GCC plugin or clang >= 15
	RANDSTRUCT_FULL
	# needs HAVE_LIVEPATCH, absent on riscv
	LIVEPATCH
	# needs ARCH_SUPPORTS_MSEAL_SYSTEM_MAPPINGS
	MSEAL_SYSTEM_MAPPINGS
	# riscv: -fzero-call-used-regs, -fcf-protection and the Zabha assembler
	# support arrive with clang 19 / binutils 2.42
	ZERO_CALL_USED_REGS RISCV_USER_CFI RISCV_ISA_ZABHA
)

# ---------------------------------------------------------------------------
# Toolchain
# ---------------------------------------------------------------------------
HOST="$(host_arch)"
# One LLVM version throughout: the unversioned tools for suffix "", or
# clang-20, ld.lld-20 and so on for "-20".  The newest complete versioned
# install is the default because the fmodret candidates plugin in patches/
# needs newer LLVM headers than the distribution default clang may have,
# and the plugin must be built against the compiler that loads it
# (Kbuild takes llvm-config with the same suffix).
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
if [ -z "$TOOLCHAIN" ]; then
	if llvm_complete "$LLVM_SFX"; then TOOLCHAIN=llvm; else TOOLCHAIN=gcc; fi
fi
MAKE_TC=()
case "$TOOLCHAIN" in
llvm)
	llvm_complete "$LLVM_SFX" ||
		die "LLVM toolchain incomplete (clang$LLVM_SFX, ld.lld$LLVM_SFX, llvm-objcopy$LLVM_SFX, llvm-ar$LLVM_SFX, llvm-nm$LLVM_SFX)"
	MAKE_TC=(LLVM="${LLVM_SFX:-1}")
	OBJCOPY="llvm-objcopy$LLVM_SFX"
	;;
gcc)
	if [ "$HOST" != "$ARCH" ]; then
		have "${CROSS}gcc" || die "cross compiler ${CROSS}gcc not found (install it or use --toolchain llvm)"
		MAKE_TC=(CROSS_COMPILE="$CROSS")
		OBJCOPY="${CROSS}objcopy"
	else
		OBJCOPY=objcopy
	fi
	;;
*) die "unsupported --toolchain $TOOLCHAIN (llvm, gcc)" ;;
esac

# ---------------------------------------------------------------------------
# Source worktree at REF plus patches/
# ---------------------------------------------------------------------------
SHA="$(git -C "$REPO" rev-parse --verify --quiet "${REF}^{commit}")" ||
	die "ref '$REF' not found in $REPO (git fetch torvalds/bpf/bpf-next first?)"
SRC="$OUT/src"
OBJ="$OUT/obj-$ARCH"
mkdir -p "$OUT"

log "source: $REF = $SHA"
git -C "$REPO" worktree prune
if [ -e "$SRC/.git" ]; then
	if [ "$KEEP_SRC" = 0 ]; then
		git -C "$SRC" checkout --detach --quiet "$SHA"
		git -C "$SRC" reset --hard --quiet
		git -C "$SRC" clean -fdxq
	fi
else
	git -C "$REPO" worktree add --detach --quiet "$SRC" "$SHA"
fi

PATCHES=()
if [ "$APPLY_PATCHES" = 1 ] && [ "$KEEP_SRC" = 0 ]; then
	while IFS= read -r p; do PATCHES+=("$p"); done < <(find "$REPO/patches" -maxdepth 1 -name '*.patch' -type f 2>/dev/null | sort)
	# git am would record whoever runs this, and now, as committer of each
	# patch commit, so HEAD, its describe string and the build timestamp
	# taken from HEAD below would change on every run.  Pin the committer
	# to the build identity and the date of REF's commit instead.
	AM_DATE="$(git -C "$REPO" log -1 --format=%cd --date=raw "$SHA")"
	for p in "${PATCHES[@]}"; do
		log "applying $(basename "$p")"
		if ! GIT_COMMITTER_NAME=shirudo GIT_COMMITTER_EMAIL=shirudo@build-kernel \
		     GIT_COMMITTER_DATE="$AM_DATE" git -C "$SRC" am --quiet --3way "$p"; then
			log "patch conflict details for $(basename "$p"):"
			git -C "$SRC" status --short >&2
			git -C "$SRC" diff --cc >&2
			git -C "$SRC" am --abort || true
			die "patch does not apply to $REF: $p"
		fi
	done
fi
SRC_DESC="$(git -C "$SRC" describe --tags --always HEAD 2>/dev/null || echo "$SHA")"

# shirudo's signed-loader support (the bpf keyring, exclusive maps and the
# BPF_PROG_LOAD signature check) ships with Linux 7.4; warn when the tree
# predates it so nobody expects "shirudo init" to pass on this kernel.
if [ ! -f "$SRC/kernel/bpf/keys.c" ]; then
	log "warning: $REF has no kernel/bpf/keys.c: no bpf keyring, shirudo init will refuse this kernel (needs Linux 7.4 or the bpf-next branch)"
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
		grep -qx "$sym" "$KNOWN" || log "lint: $(basename "$f"): CONFIG_$sym does not exist in $REF"
	done < <(sed -nE 's/^CONFIG_([A-Za-z0-9_]+)=.*/\1/p; s/^# CONFIG_([A-Za-z0-9_]+) is not set$/\1/p' "$f" | sort -u)
}
for f in "${FRAGMENTS[@]}" "$BLACKLIST"; do lint_file "$f"; done

# ---------------------------------------------------------------------------
# Configuration: base, fragments, blacklist, olddefconfig
# ---------------------------------------------------------------------------
kmake() { make -C "$SRC" O="$OBJ" ARCH="$KARCH" "${MAKE_TC[@]}" "$@"; }

if [ "$BASE" = defconfig ]; then
	log "base: $KARCH $DEFCONFIG"
	kmake -s "$DEFCONFIG"
else
	[ -f "$BASE" ] || die "base config not found: $BASE"
	log "base: $BASE"
	cp "$BASE" "$OBJ/.config"
	kmake -s olddefconfig
fi

log "merging ${FRAGMENTS[*]##*/}"
(cd "$SRC" && KCONFIG_CONFIG="$OBJ/.config" \
	scripts/kconfig/merge_config.sh -m -O "$OBJ" "$OBJ/.config" "${FRAGMENTS[@]}") >"$OBJ/merge.log" 2>&1 ||
	{ cat "$OBJ/merge.log" >&2; die "merge_config.sh failed"; }
grep -E 'Value of|redefined' "$OBJ/merge.log" | sed 's/^/merge: /' >&2 || true

# CONFIG_LOCALVERSION is the fragment's prefix plus the build day, so the
# release string says when a node's kernel was built; --localversion
# replaces the whole string.  The "+" that setlocalversion appends to an
# untagged tree is suppressed (LOCALVERSION in the environment), the
# date and the package version carry that information.
LV_BASE="$(sed -nE 's/^CONFIG_LOCALVERSION="(.*)"$/\1/p' "${FRAGMENTS[@]}" | tail -1)"
LV="${LOCALVERSION:-${LV_BASE}-$(date -u +%Y%m%d)}"
"$SRC/scripts/config" --file "$OBJ/.config" --set-str LOCALVERSION "$LV"
export LOCALVERSION=""
if [ -n "$MODULE_KEY" ]; then
	"$SRC/scripts/config" --file "$OBJ/.config" --set-str MODULE_SIG_KEY "$MODULE_KEY"
fi

log "applying blacklist.conf"
BLACKLISTED=()
while IFS= read -r sym; do BLACKLISTED+=("$sym"); done < <(sed -nE 's/^# CONFIG_([A-Za-z0-9_]+) is not set$/\1/p' "$BLACKLIST")
for sym in "${BLACKLISTED[@]}"; do
	"$SRC/scripts/config" --file "$OBJ/.config" --disable "$sym"
done

log "make olddefconfig"
kmake -s olddefconfig

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
declare -A WANT WANTSRC FINAL
for f in "${FRAGMENTS[@]}"; do
	while IFS= read -r line; do
		case "$line" in
		"# CONFIG_"*" is not set") sym="${line#\# CONFIG_}"; sym="${sym% is not set}"; WANT[$sym]=n ;;
		CONFIG_*=*) sym="${line%%=*}"; sym="${sym#CONFIG_}"; WANT[$sym]="${line#*=}" ;;
		*) continue ;;
		esac
		WANTSRC[$sym]="$(basename "$f")"
	done < "$f"
done
while IFS= read -r line; do
	case "$line" in
	"# CONFIG_"*" is not set") sym="${line#\# CONFIG_}"; FINAL[${sym% is not set}]=n ;;
	CONFIG_*=*) sym="${line%%=*}"; FINAL[${sym#CONFIG_}]="${line#*=}" ;;
	esac
done < "$OBJ/.config"

allowed_drop() { local s; for s in "${ALLOW_DROP[@]}"; do [ "$s" = "$1" ] && return 0; done; return 1; }
WANT[LOCALVERSION]="\"$LV\""

FAIL=0; WARN=0
for sym in $(printf '%s\n' "${!WANT[@]}" | sort); do
	want="${WANT[$sym]}"; got="${FINAL[$sym]:-unset}"; ok=1
	case "$want" in
	n) [ "$got" = y ] || [ "$got" = m ] && ok=0 ;;
	y) [ "$got" = y ] || ok=0 ;;
	m) [ "$got" = m ] || [ "$got" = y ] || ok=0 ;;
	*) [ "$got" = "$want" ] || ok=0 ;;
	esac
	[ "$ok" = 1 ] && continue
	if [ "$want" != n ] && allowed_drop "$sym"; then
		log "warning: CONFIG_$sym=$want (${WANTSRC[$sym]}) not available with this toolchain/arch (got $got)"
		WARN=$((WARN + 1))
	else
		log "error: CONFIG_$sym wanted $want by ${WANTSRC[$sym]}, final .config has $got"
		FAIL=$((FAIL + 1))
	fi
done
for sym in "${BLACKLISTED[@]}"; do
	got="${FINAL[$sym]:-unset}"
	if [ "$got" = y ] || [ "$got" = m ]; then
		log "error: blacklisted CONFIG_$sym is $got (selected by something; find it with 'make O=$OBJ ARCH=$KARCH menuconfig', search /$sym)"
		FAIL=$((FAIL + 1))
	fi
done
# Two invariants the whole setup rests on, checked on the final result
# regardless of what the fragments say. [S]
[ "${FINAL[LSM]:-}" = '"bpf"' ] || { log "error: CONFIG_LSM is ${FINAL[LSM]:-unset}, must be \"bpf\""; FAIL=$((FAIL + 1)); }
[ "${FINAL[DYNAMIC_FTRACE_WITH_DIRECT_CALLS]:-}" = y ] || { log "error: CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS is not y: shirudo cannot attach trampolines"; FAIL=$((FAIL + 1)); }
[ "$FAIL" = 0 ] || die "$FAIL configuration mismatch(es); .config left at $OBJ/.config"
log "configuration verified (${#WANT[@]} fragment symbols, ${#BLACKLISTED[@]} blacklisted, $WARN warning(s))"

# kernelrelease reads CONFIG_LOCALVERSION* from include/config/auto.conf,
# which only syncconfig writes.
kmake -s syncconfig
KREL="$(kmake -s kernelrelease)"
KVER="$(kmake -s kernelversion)"
cp "$OBJ/.config" "$OUT/kernel-$ARCH.config"

# Module signing with ML-DSA (kernel.conf) needs OpenSSL >= 3.5 on the
# build host twice: scripts/sign-file links libcrypto, and certs/Makefile
# runs "openssl req -newkey ml-dsa-87" unless --module-key supplies the key.
# A config-only run only warns; a build stops here instead of after an
# hour of compiling.
check_signing_host() {
	local ver
	grep -q '^CONFIG_MODULE_SIG_KEY_TYPE_MLDSA' "$OBJ/.config" || return 0
	ver="$(pkg-config --modversion libcrypto 2>/dev/null || echo 0)"
	if [ "$(printf '%s\n3.5\n' "$ver" | sort -V | head -1)" != 3.5 ]; then
		log "signing: libcrypto $ver via pkg-config is older than 3.5, sign-file cannot sign ML-DSA (use --openssl DIR)"
		return 1
	fi
	return 0
}
if ! check_signing_host; then
	if [ "$CONFIG_ONLY" = 1 ]; then
		log "warning: this host cannot sign modules for this configuration, see above"
	else
		die "this host cannot sign modules for this configuration, see above"
	fi
fi
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
# Patch commits carry REF's commit date (see git am above), so with
# patches applied this is still the upstream date.
export KBUILD_BUILD_TIMESTAMP="$(git -C "$SRC" log -1 --format=%cD HEAD)"
export KBUILD_BUILD_USER=shirudo KBUILD_BUILD_HOST=build-kernel
export SOURCE_DATE_EPOCH="$(git -C "$SRC" log -1 --format=%ct HEAD)"

if [ "$FORMAT" = deb ] || [ "$FORMAT" = both ]; then
	PKGVER="${KVER//-rc/\~rc}-${STAMP}.g${SHA:0:12}"
	PROFILES=()
	[ "$WITH_DBG" = 1 ] || PROFILES+=(pkg.linux-upstream.nokerneldbg)
	# The headers package rebuilds the host tools for the target with the
	# GNU cross compiler, which a cross build with LLVM does not have.
	[ "$HOST" = "$ARCH" ] || PROFILES+=(pkg.linux-upstream.nokernelheaders)
	DIST="$(lsb_release -cs 2>/dev/null || echo unstable)"
	log "building bindeb-pkg $PKGVER for $DEBARCH (-j$JOBS, $TOOLCHAIN)"
	DEB_BUILD_PROFILES="${PROFILES[*]}" \
	kmake -j"$JOBS" bindeb-pkg KDEB_PKGVERSION="$PKGVER" KDEB_CHANGELOG_DIST="$DIST" \
		DPKG_FLAGS="--no-check-builddeps"
	mv "$OUT"/*_"${PKGVER}"_*.deb "$OUT"/*_"${PKGVER}"_*.buildinfo "$OUT"/*_"${PKGVER}"_*.changes "$PKGDIR"/ 2>/dev/null || true
	ls "$PKGDIR"/*.deb >/dev/null 2>&1 || die "no .deb produced for $PKGVER"
fi
if [ "$FORMAT" = rpm ] || [ "$FORMAT" = both ]; then
	log "building binrpm-pkg for $UTS (-j$JOBS, $TOOLCHAIN)"
	rm -rf "$OBJ/rpmbuild/RPMS"
	kmake -j"$JOBS" binrpm-pkg
	find "$OBJ/rpmbuild/RPMS" -name '*.rpm' -exec cp {} "$PKGDIR"/ \;
	ls "$PKGDIR"/*.rpm >/dev/null 2>&1 || die "no .rpm produced"
fi

# ---------------------------------------------------------------------------
# Side artifacts: config, BTF for vmlinux.h generation, build info
# ---------------------------------------------------------------------------
cp "$OBJ/.config" "$PKGDIR/config-$KREL"
cp "$OBJ/System.map" "$PKGDIR/System.map-$KREL"
# The module signing certificate (public half) travels with the packages;
# the private key stays where it was: the object tree when generated here.
if [ -n "$MODULE_KEY" ]; then
	openssl x509 -in "$MODULE_KEY" -outform DER -out "$PKGDIR/module-signing-cert-$KREL.der" 2>/dev/null ||
		log "warning: could not extract the certificate from $MODULE_KEY"
elif [ -f "$OBJ/certs/signing_key.x509" ]; then
	cp "$OBJ/certs/signing_key.x509" "$PKGDIR/module-signing-cert-$KREL.der"
fi
"$OBJCOPY" --dump-section .BTF="$PKGDIR/vmlinux-$KREL.btf" "$OBJ/vmlinux" /dev/null 2>/dev/null ||
	"$OBJCOPY" --dump-section .BTF="$PKGDIR/vmlinux-$KREL.btf" "$OBJ/vmlinux" "$OBJ/.vmlinux.btf-tmp"
rm -f "$OBJ/.vmlinux.btf-tmp"
[ -s "$PKGDIR/vmlinux-$KREL.btf" ] || die "vmlinux has no .BTF section"
{
	echo "ref=$REF"
	echo "commit=$SHA"
	echo "describe=$SRC_DESC"
	echo "patches=${PATCHES[*]##*/}"
	echo "arch=$ARCH"
	echo "kernelrelease=$KREL"
	echo "toolchain=$TOOLCHAIN"
	echo "compiler=$(grep -E '^CONFIG_CC_VERSION_TEXT=' "$OBJ/.config" | cut -d= -f2-)"
	echo "base=$BASE"
	echo "fragments_sha256=$(cat "${FRAGMENTS[@]}" "$BLACKLIST" | sha256sum | cut -d' ' -f1)"
	echo "module_key=${MODULE_KEY:-generated in $OBJ/certs/signing_key.pem}"
	echo "libcrypto=$(pkg-config --modversion libcrypto 2>/dev/null || echo unknown)"
	echo "built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$PKGDIR/BUILD-INFO"
(cd "$PKGDIR" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
log "packages in $PKGDIR:"
ls -1 "$PKGDIR" >&2
