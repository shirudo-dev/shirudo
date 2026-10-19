#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
set -euo pipefail

KERNEL_TAG="${KERNEL_TAG:-bpf-next}"
KERNEL_COMMIT="${KERNEL_COMMIT:-}"
KERNEL_REPOSITORY="${KERNEL_REPOSITORY:-https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git}"
KERNEL_PATCHES="${KERNEL_PATCHES:-}"
KERNEL_CONFIG="${KERNEL_CONFIG:-}"
KERNEL_BUILD_JOBS="${KERNEL_BUILD_JOBS:-$(nproc)}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=contrib/test-vm-arch.sh
. "${REPO_ROOT}/contrib/test-vm-arch.sh"
KERNEL_SOURCE_DIR_INPUT="${KERNEL_SOURCE_DIR:-}"
if [[ "$KERNEL_TAG" =~ ^[0-9]+\.[0-9]+([.][0-9]+)?$ ]]; then
  KERNEL_TAG="v${KERNEL_TAG}"
fi
if [[ "$KERNEL_TAG" != "bpf-next" &&
      ! "$KERNEL_TAG" =~ ^v[0-9]+\.[0-9]+([.][0-9]+)?$ ]]; then
  echo "KERNEL_TAG must be bpf-next or a Linux release tag such as v6.18" >&2
  exit 1
fi
if [[ -n "$KERNEL_COMMIT" ]]; then
  if [[ "$KERNEL_TAG" == "bpf-next" ]]; then
    echo "KERNEL_COMMIT is supported only for stable/LTS kernel tags" >&2
    exit 1
  fi
  if [[ ! "$KERNEL_COMMIT" =~ ^[0-9a-fA-F]{7,40}$ ]]; then
    echo "KERNEL_COMMIT must contain 7 to 40 hexadecimal characters" >&2
    exit 1
  fi
  KERNEL_COMMIT="${KERNEL_COMMIT,,}"
fi
# After the argument checks, so that those report the same on every host.
if [[ "$TEST_VM_ARCH_SUPPORTED" != 1 ]]; then
  echo "the test VM kernel is built on x86_64 and aarch64 hosts only, not ${TEST_VM_ARCH}" >&2
  exit 1
fi
KERNEL_ARTIFACT_NAME="bpf-next"
if [[ "$KERNEL_TAG" != "bpf-next" ]]; then
  KERNEL_ARTIFACT_NAME="linux-${KERNEL_TAG}"
fi
if [[ -n "$KERNEL_COMMIT" ]]; then
  KERNEL_ARTIFACT_NAME="${KERNEL_ARTIFACT_NAME}-${KERNEL_COMMIT}"
fi
if [[ -z "${KERNEL_LOCALVERSION:-}" ]]; then
  if [[ "$KERNEL_TAG" == "bpf-next" ]]; then
    KERNEL_LOCALVERSION="-bpf-next"
  else
    KERNEL_LOCALVERSION="-shirudo-${KERNEL_TAG#v}"
  fi
fi
PACKAGE_FORMAT="${PACKAGE_FORMAT:-$TEST_VM_HOST_PKG_FORMAT}"
case "$PACKAGE_FORMAT" in
  deb)
    PACKAGE_SUFFIX="debs"
    ;;
  rpm)
    PACKAGE_SUFFIX="rpms"
    ;;
  *)
    echo "unsupported PACKAGE_FORMAT: ${PACKAGE_FORMAT} (expected deb or rpm)" >&2
    exit 1
    ;;
esac
WORK_DIR="${WORK_DIR:-${RUNNER_TEMP:-/tmp}/${KERNEL_ARTIFACT_NAME}-kernel-build}"
SOURCE_DIR="${WORK_DIR}/linux"
if [[ -n "$KERNEL_SOURCE_DIR_INPUT" ]]; then
  KERNEL_SOURCE_DIR="$KERNEL_SOURCE_DIR_INPUT"
elif [[ "$KERNEL_TAG" == "bpf-next" ]]; then
  # Reuse the managed shallow clone unless KERNEL_SOURCE_DIR names a checkout.
  KERNEL_SOURCE_DIR="$SOURCE_DIR"
else
  KERNEL_SOURCE_DIR="$SOURCE_DIR"
fi
OUTPUT_DIR="${OUTPUT_DIR:-${REPO_ROOT}/artifacts/${KERNEL_ARTIFACT_NAME}-kernel-${PACKAGE_SUFFIX}}"
BUNDLE_PATH="${BUNDLE_PATH:-${OUTPUT_DIR}.tar.gz}"
VMLINUX_PATH="${OUTPUT_DIR}/${TEST_VM_ARCH_KIMAGE}"
VMLINUX_BTF_PATH="${OUTPUT_DIR}/vmlinux.btf"

if [[ "$PACKAGE_FORMAT" == deb ]]; then
  BUILD_DEPENDENCIES=(
    bc
    bison
    build-essential
    ca-certificates
    cpio
    debhelper
    dpkg-dev
    dwarves
    fakeroot
    flex
    git
    kmod
    libdw-dev
    libelf-dev
    libncurses-dev
    libssl-dev
    llvm
    openssl
    pahole
    python3
    rsync
    xz-utils
    zstd
  )
else
  BUILD_DEPENDENCIES=(
    bc
    bison
    ca-certificates
    cpio
    dwarves
    elfutils-devel
    elfutils-libelf-devel
    flex
    gcc
    git
    gzip
    hostname
    kmod
    make
    ncurses-devel
    openssl
    openssl-devel
    perl
    python3
    rpm-build
    rsync
    tar
    xz
    zstd
  )
fi

run_as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    echo "installing kernel build dependencies requires root or sudo" >&2
    exit 1
  fi
}

install_build_dependencies() {
  local missing_dependencies=()
  if [[ "$PACKAGE_FORMAT" == deb ]]; then
    if ! command -v apt-get >/dev/null 2>&1; then
      echo "cannot install Debian kernel build dependencies: apt-get is not installed" >&2
      exit 1
    fi
    if command -v dpkg-query >/dev/null 2>&1; then
      for dependency in "${BUILD_DEPENDENCIES[@]}"; do
        if ! dpkg-query -W -f='${Status}\n' "$dependency" 2>/dev/null |
          grep -q 'install ok installed'; then
          missing_dependencies+=("$dependency")
        fi
      done
    else
      missing_dependencies=("${BUILD_DEPENDENCIES[@]}")
    fi
    if [[ ${#missing_dependencies[@]} -eq 0 ]]; then
      echo "All kernel build dependencies are already installed"
      return
    fi
    run_as_root apt-get update
    run_as_root apt-get install -y --no-install-recommends "${missing_dependencies[@]}"
  else
    if ! command -v dnf >/dev/null 2>&1; then
      echo "cannot install RPM kernel build dependencies: dnf is not installed" >&2
      exit 1
    fi
    if command -v rpm >/dev/null 2>&1; then
      for dependency in "${BUILD_DEPENDENCIES[@]}"; do
        rpm -q "$dependency" >/dev/null 2>&1 ||
          missing_dependencies+=("$dependency")
      done
    else
      missing_dependencies=("${BUILD_DEPENDENCIES[@]}")
    fi
    if [[ ${#missing_dependencies[@]} -eq 0 ]]; then
      echo "All kernel build dependencies are already installed"
      return
    fi
    run_as_root dnf install -y "${missing_dependencies[@]}"
  fi
}

install_build_dependencies

if [[ "$KERNEL_TAG" == "bpf-next" && "$KERNEL_SOURCE_DIR" == "$SOURCE_DIR" ]]; then
  mkdir -p "$WORK_DIR"
else
  rm -rf "$WORK_DIR"
  mkdir -p "$WORK_DIR"
fi
rm -rf "$OUTPUT_DIR" "$BUNDLE_PATH" "${BUNDLE_PATH}.sha256sum"
mkdir -p "$WORK_DIR" "$OUTPUT_DIR"

if [[ "$KERNEL_TAG" == "bpf-next" && "$KERNEL_SOURCE_DIR" == "$SOURCE_DIR" ]]; then
  repository="${BPF_NEXT_REPOSITORY:-https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git}"
  if git -C "$KERNEL_SOURCE_DIR" rev-parse --is-inside-work-tree \
      >/dev/null 2>&1; then
    echo "Updating bpf-next"
    git -C "$KERNEL_SOURCE_DIR" remote set-url origin "$repository"
    git -C "$KERNEL_SOURCE_DIR" fetch --depth 1 origin HEAD
    git -C "$KERNEL_SOURCE_DIR" reset --hard FETCH_HEAD
    git -C "$KERNEL_SOURCE_DIR" clean -fdx
  else
    echo "Fetching bpf-next"
    rm -rf "$KERNEL_SOURCE_DIR"
    git clone --depth 1 --single-branch "$repository" "$KERNEL_SOURCE_DIR"
  fi
elif [[ "$KERNEL_TAG" != "bpf-next" && -z "$KERNEL_SOURCE_DIR_INPUT" ]]; then
  echo "Fetching third-party Linux kernel ${KERNEL_TAG}"
  if [[ -n "$KERNEL_COMMIT" ]]; then
    git clone --filter=blob:none --no-checkout \
      "$KERNEL_REPOSITORY" "$KERNEL_SOURCE_DIR"
  else
    git clone --depth 1 --branch "$KERNEL_TAG" \
      "$KERNEL_REPOSITORY" "$KERNEL_SOURCE_DIR"
  fi
fi
if [[ ! -d "$KERNEL_SOURCE_DIR" ]]; then
  echo "kernel source directory not found: ${KERNEL_SOURCE_DIR}" >&2
  exit 1
fi
if ! git -C "$KERNEL_SOURCE_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "kernel source directory is not a git checkout: ${KERNEL_SOURCE_DIR}" >&2
  exit 1
fi
# An exact-commit clone is intentionally created with --no-checkout. Select
# the requested commit before checking cleanliness; otherwise Git reports the
# intentionally absent worktree files as staged deletions.
if [[ -n "$KERNEL_COMMIT" && -z "$KERNEL_SOURCE_DIR_INPUT" ]]; then
  git -C "$KERNEL_SOURCE_DIR" checkout --detach "$KERNEL_COMMIT"
fi
if [[ -n "$(git -C "$KERNEL_SOURCE_DIR" status --porcelain)" ]]; then
  echo "kernel source checkout is dirty: ${KERNEL_SOURCE_DIR}" >&2
  echo "commit or stash its changes before running make -C testing kernel" >&2
  exit 1
fi

if [[ "$KERNEL_SOURCE_DIR" == "$SOURCE_DIR" ]]; then
  cd "$SOURCE_DIR"
else
  submodule_commit="$(git -C "$KERNEL_SOURCE_DIR" rev-parse HEAD)"
  git clone --no-checkout "$KERNEL_SOURCE_DIR" "$SOURCE_DIR"
  cd "$SOURCE_DIR"
  if [[ -n "$KERNEL_COMMIT" ]]; then
    git rev-parse --verify "$KERNEL_COMMIT^{commit}" >/dev/null 2>&1 || {
      echo "KERNEL_COMMIT is not available in KERNEL_SOURCE_DIR: ${KERNEL_COMMIT}" >&2
      exit 1
    }
    git checkout --detach "$KERNEL_COMMIT"
  else
    git checkout --detach "$submodule_commit"
  fi
fi

if [[ -n "$KERNEL_COMMIT" ]]; then
  git rev-parse --verify "$KERNEL_COMMIT^{commit}" >/dev/null 2>&1 || {
    echo "kernel commit not found in ${KERNEL_REPOSITORY}: ${KERNEL_COMMIT}" >&2
    exit 1
  }
  git checkout --detach "$KERNEL_COMMIT"
fi

upstream_commit="$(git rev-parse HEAD)"
applied_patches=()

apply_kernel_patch() {
  local patch_path="$1"
  local patch_subject

  if [[ "$patch_path" != /* ]]; then
    patch_path="${REPO_ROOT}/${patch_path}"
  fi
  if [[ ! -f "$patch_path" ]]; then
    echo "kernel patch not found: ${patch_path}" >&2
    exit 1
  fi

  echo "Applying kernel patch: ${patch_path}"
  if git apply --reverse --check "$patch_path" >/dev/null 2>&1; then
    echo "Kernel patch already applied: ${patch_path}"
    applied_patches+=("$patch_path")
    return
  fi

  git config user.name "shirudo workflow"
  git config user.email "shirudo@localhost"
  if ! git apply --index "$patch_path"; then
    echo "failed to apply kernel patch: ${patch_path}" >&2
    exit 1
  fi
  patch_subject="$(
    sed -n \
      -e 's/^Subject: \[PATCH[^]]*\] //p' \
      -e 's/^Subject: //p' \
      "$patch_path" | head -n 1
  )"
  if [[ -z "$patch_subject" ]]; then
    patch_subject="Apply $(basename "$patch_path")"
  fi
  git commit -m "$patch_subject"
  applied_patches+=("$patch_path")
}

expand_kernel_patches() {
  local patch_entry="$1"
  local patch_path="$patch_entry"

  if [[ "$patch_path" != /* ]]; then
    patch_path="${REPO_ROOT}/${patch_path}"
  fi

  if [[ -d "$patch_path" ]]; then
    find "$patch_path" -maxdepth 1 -type f -name '*.patch' | sort
  else
    printf '%s\n' "$patch_path"
  fi
}

for patch_entry in $KERNEL_PATCHES; do
  while IFS= read -r patch_path; do
    [[ -n "$patch_path" ]] || continue
    apply_kernel_patch "$patch_path"
  done < <(expand_kernel_patches "$patch_entry")
done

kernel_commit="$(git rev-parse HEAD)"
if [[ -n "$KERNEL_CONFIG" ]]; then
  if [[ "$KERNEL_CONFIG" != /* ]]; then
    KERNEL_CONFIG="${REPO_ROOT}/${KERNEL_CONFIG}"
  fi
  if [[ ! -f "$KERNEL_CONFIG" ]]; then
    echo "kernel config not found: ${KERNEL_CONFIG}" >&2
    exit 1
  fi
  cp "$KERNEL_CONFIG" .config
  config_source="$KERNEL_CONFIG"
  config_profile=custom
else
  config_fragment="${WORK_DIR}/kernel-slim.config"
  cat > "$config_fragment" <<'EOF'
CONFIG_64BIT=y
CONFIG_SMP=y
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_LSM=y
CONFIG_BPF_EVENTS=y
CONFIG_UPROBE_EVENTS=y
CONFIG_CGROUPS=y
CONFIG_CGROUP_BPF=y
CONFIG_FTRACE=y
CONFIG_FTRACE_SYSCALLS=y
CONFIG_FUNCTION_TRACER=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y
CONFIG_UPROBES=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=n
CONFIG_KEYS=y
CONFIG_ASYMMETRIC_KEY_TYPE=y
CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y
CONFIG_X509_CERTIFICATE_PARSER=y
CONFIG_PKCS7_MESSAGE_PARSER=y
CONFIG_SYSTEM_DATA_VERIFICATION=y
CONFIG_SYSTEM_TRUSTED_KEYS=""
CONFIG_SYSTEM_REVOCATION_KEYS=""
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_ALL=n
CONFIG_CRYPTO_RSA=y
CONFIG_CRYPTO_SHA256=y
CONFIG_CRYPTO_MLDSA=y
CONFIG_CRYPTO_SHA512=y
CONFIG_TCG_TPM=y
CONFIG_TCG_TIS_CORE=y
CONFIG_TCG_TIS=y
CONFIG_TCG_CRB=y
CONFIG_SECURITY=y
CONFIG_SECURITY_NETWORK=y
CONFIG_SECURITYFS=y
CONFIG_LSM="bpf"
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_BINFMT_ELF=y
CONFIG_BINFMT_SCRIPT=y
CONFIG_INOTIFY_USER=y
CONFIG_MODULES=y
CONFIG_MODULE_UNLOAD=y
CONFIG_BLK_DEV=y
CONFIG_BLOCK=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_RD_GZIP=y
CONFIG_RD_XZ=y
CONFIG_RD_ZSTD=y
CONFIG_BLK_DEV_LOOP=y
CONFIG_BLK_DEV_NVME=y
CONFIG_PARTITION_ADVANCED=y
CONFIG_EFI=y
CONFIG_EFI_STUB=y
CONFIG_EFI_PARTITION=y
CONFIG_FAT_FS=y
CONFIG_VFAT_FS=y
CONFIG_ISO9660_FS=y
CONFIG_NLS_CODEPAGE_437=y
CONFIG_NLS_ASCII=y
CONFIG_NLS_ISO8859_1=y
CONFIG_NLS_UTF8=y
CONFIG_NLS_DEFAULT="utf8"
CONFIG_VIRTIO_MENU=y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_PCI_LEGACY=y
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_NET=y
CONFIG_PCI=y
CONFIG_PCI_MSI=y
CONFIG_PCIEPORTBUS=y
CONFIG_NET=y
CONFIG_NET_NS=y
CONFIG_USER_NS=y
CONFIG_PACKET=y
CONFIG_NETDEVICES=y
CONFIG_NET_CORE=y
CONFIG_ETHERNET=y
CONFIG_NET_VENDOR_AMAZON=y
CONFIG_ENA_ETHERNET=y
CONFIG_INET=y
CONFIG_IPV6=y
CONFIG_UNIX=y
CONFIG_NETWORK_FILESYSTEMS=y
CONFIG_NET_9P=y
CONFIG_NET_9P_VIRTIO=y
CONFIG_9P_FS=y
CONFIG_OVERLAY_FS=y
CONFIG_MISC_FILESYSTEMS=y
CONFIG_SQUASHFS=y
CONFIG_SQUASHFS_ZLIB=y
CONFIG_SQUASHFS_XZ=y
CONFIG_SQUASHFS_ZSTD=y
CONFIG_EXT4_FS=y
CONFIG_EXT4_FS_SECURITY=y
CONFIG_TMPFS=y
CONFIG_TTY=y
CONFIG_ACPI=y
CONFIG_PNP=y
CONFIG_PNPACPI=y
CONFIG_NETFILTER=y
CONFIG_NETFILTER_INGRESS=y
CONFIG_NF_CONNTRACK=y
CONFIG_NF_TABLES=m
CONFIG_VETH=m
CONFIG_BRIDGE=m
CONFIG_VLAN_8021Q=m
CONFIG_NF_FLOW_TABLE=m
CONFIG_NF_FLOW_TABLE_INET=m
CONFIG_NF_FLOW_TABLE_PROCFS=y
CONFIG_PROC_FS=y
CONFIG_CC_OPTIMIZE_FOR_SIZE=y
EOF
  # QEMU's arm64 virt machine needs the generic PCI host bridge for virtio,
  # PSCI to power off and the PL031 RTC, without which the guest clock
  # starts in the past and rejects certificates made today. x86 selects
  # PERF_EVENTS on its own; without it BPF_EVENTS and BPF_LSM drop out.
  case "$TEST_VM_ARCH" in
  x86_64)
    cat >> "$config_fragment" <<'EOF'
CONFIG_X86_64=y
CONFIG_X86=y
CONFIG_PARAVIRT=y
CONFIG_PARAVIRT_CLOCK=y
CONFIG_KVM_GUEST=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_KERNEL_XZ=y
CONFIG_KERNEL_GZIP=n
CONFIG_KERNEL_ZSTD=n
CONFIG_KERNEL_LZMA=n
CONFIG_KERNEL_LZO=n
CONFIG_KERNEL_LZ4=n
CONFIG_KERNEL_UNCOMPRESSED=n
EOF
    ;;
  aarch64)
    cat >> "$config_fragment" <<'EOF'
CONFIG_ARM64=y
CONFIG_OF=y
CONFIG_PERF_EVENTS=y
CONFIG_ARM_PSCI_FW=y
CONFIG_PCI_HOST_GENERIC=y
CONFIG_VIRTIO_MMIO=y
CONFIG_SERIAL_AMBA_PL011=y
CONFIG_SERIAL_AMBA_PL011_CONSOLE=y
CONFIG_RTC_CLASS=y
CONFIG_RTC_HCTOSYS=y
CONFIG_RTC_DRV_PL031=y
EOF
    ;;
  esac
  make KCONFIG_ALLCONFIG="$config_fragment" allnoconfig
  config_source="embedded slim kernel config (KCONFIG_ALLCONFIG)"
  config_profile=slim
fi

scripts/config --set-str LOCALVERSION "$KERNEL_LOCALVERSION"
make olddefconfig

require_config() {
  local symbol="$1"
  local expected_pattern="$2"

  if ! grep -Eq "^${symbol}=${expected_pattern}$" .config; then
    echo "required kernel config ${symbol} does not match ${expected_pattern}" >&2
    grep -E "^${symbol}=|^# ${symbol} is not set" .config >&2 || true
    exit 1
  fi
}

require_config CONFIG_BPF_LSM y
require_config CONFIG_BPF_SYSCALL y
require_config CONFIG_BPF_JIT y
require_config CONFIG_CGROUP_BPF y
require_config CONFIG_FUNCTION_TRACER y
require_config CONFIG_DYNAMIC_FTRACE y
require_config CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS y
require_config CONFIG_DEBUG_INFO_BTF y
require_config CONFIG_TCG_TPM y
require_config CONFIG_TCG_TIS_CORE y
require_config CONFIG_TCG_TIS y
require_config CONFIG_SYSTEM_DATA_VERIFICATION y
require_config CONFIG_UPROBES y
require_config CONFIG_SECURITY y
require_config CONFIG_SECURITY_NETWORK y
require_config CONFIG_SECURITYFS y
if [[ "$config_profile" == slim ]]; then
  require_config CONFIG_USER_NS y
  require_config CONFIG_TCG_CRB y
  require_config CONFIG_BLK_DEV_INITRD y
  require_config CONFIG_RD_GZIP y
  require_config CONFIG_RD_XZ y
  require_config CONFIG_RD_ZSTD y
  require_config CONFIG_BLK_DEV_LOOP y
  require_config CONFIG_BLK_DEV_NVME y
  require_config CONFIG_EFI y
  require_config CONFIG_EFI_STUB y
  require_config CONFIG_NET_VENDOR_AMAZON y
  require_config CONFIG_ENA_ETHERNET y
  require_config CONFIG_MISC_FILESYSTEMS y
  require_config CONFIG_SQUASHFS y
  require_config CONFIG_SQUASHFS_ZLIB y
  require_config CONFIG_SQUASHFS_XZ y
  require_config CONFIG_SQUASHFS_ZSTD y
fi
require_config CONFIG_MODULES y
require_config CONFIG_PCI y
require_config CONFIG_PCI_MSI y
require_config CONFIG_PCIEPORTBUS y
require_config CONFIG_NETDEVICES y
require_config CONFIG_ETHERNET y
require_config CONFIG_IPV6 y
require_config CONFIG_PACKET y
require_config CONFIG_ISO9660_FS y
require_config CONFIG_DEVTMPFS y
require_config CONFIG_DEVTMPFS_MOUNT y
require_config CONFIG_VIRTIO y
require_config CONFIG_VIRTIO_PCI y
require_config CONFIG_VIRTIO_BLK y
require_config CONFIG_VIRTIO_NET y
require_config CONFIG_NET_9P y
require_config CONFIG_NET_9P_VIRTIO y
require_config CONFIG_9P_FS y
require_config CONFIG_OVERLAY_FS y
require_config CONFIG_EXT4_FS y
require_config CONFIG_EXT4_FS_SECURITY y
require_config CONFIG_TMPFS y
require_config CONFIG_EFI_PARTITION y
case "$TEST_VM_ARCH" in
x86_64)
  require_config CONFIG_SERIAL_8250 y
  require_config CONFIG_SERIAL_8250_CONSOLE y
  ;;
aarch64)
  require_config CONFIG_ARM64 y
  require_config CONFIG_ARM_PSCI_FW y
  require_config CONFIG_PCI_HOST_GENERIC y
  require_config CONFIG_SERIAL_AMBA_PL011 y
  require_config CONFIG_SERIAL_AMBA_PL011_CONSOLE y
  require_config CONFIG_RTC_DRV_PL031 y
  require_config CONFIG_RTC_HCTOSYS y
  ;;
esac
require_config CONFIG_ACPI y
require_config CONFIG_PNP y
require_config CONFIG_PNPACPI y
require_config CONFIG_NETFILTER y
require_config CONFIG_NETFILTER_INGRESS y
require_config CONFIG_NET_NS y
require_config CONFIG_NF_CONNTRACK y
require_config CONFIG_NF_TABLES m
require_config CONFIG_VETH m
require_config CONFIG_BRIDGE m
require_config CONFIG_VLAN_8021Q m
require_config CONFIG_NF_FLOW_TABLE m
require_config CONFIG_NF_FLOW_TABLE_INET m
require_config CONFIG_NF_FLOW_TABLE_PROCFS y
require_config CONFIG_PROC_FS y
if [[ "$config_profile" == slim ]]; then
  require_config CONFIG_CC_OPTIMIZE_FOR_SIZE y
  if [[ "$TEST_VM_ARCH" == x86_64 ]]; then
    require_config CONFIG_KERNEL_XZ y
  fi
fi

# Refresh the generated release after the config edits above.  kernelrelease
# reads include/config/kernel.release, which may still contain the pre-config
# value until its FORCE target has run; the Debian package uses the refreshed
# value when it stages /lib/modules.
make -s include/config/kernel.release
kernel_release="$(<include/config/kernel.release)"
package_version="1+$(date -u +%Y%m%d%H%M%S)+g${kernel_commit:0:12}"
# GCC 15 defaults to GNU C23, while older stable snapshots still use `bool`
# and `false` as identifiers. KCFLAGS covers normal Kbuild CFLAGS, but x86
# EFI and realmode Makefiles replace KBUILD_CFLAGS for their special builds.
# Put GNU11 on the compiler command itself so those paths receive it too.
# Older stable snapshots can also trigger discarded-qualifier warnings in the
# bundled host-side libbpf, so keep that compatibility warning in host tools.
kernel_cc="${CC:-cc} -std=gnu11"
kernel_hostcflags="${HOSTCFLAGS:-} -std=gnu11 -Wno-error=discarded-qualifiers"
kernel_kcflags="${KCFLAGS:-} -std=gnu11"
# GCC rejects -Wno-error= for a warning it does not know, so only add the
# GCC 15 one where the compiler has it.
if ${CC:-cc} -Werror -Wunterminated-string-initialization -x c -c /dev/null \
    -o /dev/null >/dev/null 2>&1; then
  kernel_kcflags="$kernel_kcflags -Wno-error=unterminated-string-initialization"
fi
if [[ "$PACKAGE_FORMAT" == deb ]]; then
  make -j "$KERNEL_BUILD_JOBS" bindeb-pkg KDEB_PKGVERSION="$package_version" \
    CC="$kernel_cc" \
    HOSTCFLAGS="$kernel_hostcflags" \
    KCFLAGS="$kernel_kcflags"

  IMAGE_DEB="$(find "$WORK_DIR" -maxdepth 1 -type f \
    -name "linux-image-[0-9]*_${package_version}_*.deb" \
    ! -name '*-dbg*.deb' -print -quit)"
  if [[ -z "$IMAGE_DEB" ]]; then
    echo "kernel image deb for package version ${package_version} was not produced" >&2
    exit 1
  fi
  find "$WORK_DIR" -maxdepth 1 -type f \
    -name "*_${package_version}_*.deb" ! -name '*-dbg*.deb' \
    -exec cp {} "$OUTPUT_DIR/" \;
else
  rm -rf "$SOURCE_DIR/rpmbuild/RPMS"
  make -j "$KERNEL_BUILD_JOBS" binrpm-pkg

  IMAGE_RPM="$(find "$SOURCE_DIR/rpmbuild/RPMS" -type f \
    -name 'kernel-[0-9]*.rpm' \
    ! -name '*debug*' ! -name '*debuginfo*' \
    ! -name '*headers*' ! -name '*devel*' -print -quit)"
  if [[ -z "$IMAGE_RPM" ]]; then
    echo "kernel RPM was not produced" >&2
    exit 1
  fi
  find "$SOURCE_DIR/rpmbuild/RPMS" -type f -name '*.rpm' \
    ! -name '*debug*' ! -name '*debuginfo*' -exec cp {} "$OUTPUT_DIR/" \;
fi

# The VM boots the kernel image directly, so carry the matching module tree
# alongside it. This keeps module loading deterministic for a selected
# kernel commit.
MODULES_STAGE_DIR="${WORK_DIR}/modules"
rm -rf "$MODULES_STAGE_DIR"
mkdir -p "$MODULES_STAGE_DIR"
if [[ "$PACKAGE_FORMAT" == deb ]]; then
  dpkg-deb -x "$IMAGE_DEB" "$MODULES_STAGE_DIR"
else
  rpm2cpio "$IMAGE_RPM" |
    (cd "$MODULES_STAGE_DIR" && cpio -idm --quiet)
fi
MODULES_SOURCE_DIR=""
for candidate in \
  "$MODULES_STAGE_DIR/lib/modules/$kernel_release" \
  "$MODULES_STAGE_DIR/usr/lib/modules/$kernel_release"; do
  if [[ -d "$candidate" ]]; then
    MODULES_SOURCE_DIR="$candidate"
    break
  fi
done
if [[ -z "$MODULES_SOURCE_DIR" ]]; then
  echo "kernel image package has no modules for ${kernel_release}" >&2
  exit 1
else
  mkdir -p "$OUTPUT_DIR/lib/modules"
  rm -rf "$OUTPUT_DIR/lib/modules/$kernel_release"
  cp -a "$MODULES_SOURCE_DIR" "$OUTPUT_DIR/lib/modules/"
  depmod -b "$OUTPUT_DIR" "$kernel_release"
fi

if [[ ! -s "$TEST_VM_ARCH_KIMAGE_SRC" ]]; then
  echo "kernel ${TEST_VM_ARCH_KIMAGE} was not produced" >&2
  exit 1
fi
cp "$TEST_VM_ARCH_KIMAGE_SRC" "$VMLINUX_PATH"
cp .config "${OUTPUT_DIR}/kernel.config"

# Keep the exact detached BTF used by this kernel build.  It lets Shirudo
# generate vendor/linux/vmlinux.h against the artifact kernel before that kernel is
# booted, rather than accidentally using the build host's /sys BTF.
if [[ ! -s vmlinux ]]; then
  echo "kernel vmlinux was not produced" >&2
  exit 1
fi
if ! objcopy --dump-section .BTF="$VMLINUX_BTF_PATH" vmlinux; then
  echo "failed to extract .BTF from kernel vmlinux" >&2
  exit 1
fi
if [[ ! -s "$VMLINUX_BTF_PATH" ]]; then
  echo "kernel vmlinux has no usable .BTF section" >&2
  exit 1
fi

cat > "${OUTPUT_DIR}/${KERNEL_ARTIFACT_NAME}-kernel-build" <<EOF
source_dir=${KERNEL_SOURCE_DIR}
source_repository=${KERNEL_REPOSITORY}
tag=${KERNEL_TAG}
requested_commit=${KERNEL_COMMIT}
upstream_commit=${upstream_commit}
commit=${kernel_commit}
package_format=${PACKAGE_FORMAT}
patches_requested=${KERNEL_PATCHES}
patches_applied=${applied_patches[*]}
profile=${config_profile}
config_source=${config_source}
kernel_release=${kernel_release}
package_version=${package_version}
built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

(
  cd "$OUTPUT_DIR"
  sha256sum "$TEST_VM_ARCH_KIMAGE" > "${TEST_VM_ARCH_KIMAGE}.sha256sum"
  sha256sum vmlinux.btf > vmlinux.btf.sha256sum
  find . -type f ! -name SHA256SUMS -print0 | sort -z |
    xargs -0 sha256sum > SHA256SUMS
)

mkdir -p "$(dirname "$BUNDLE_PATH")"
tar -C "$OUTPUT_DIR" -czf "$BUNDLE_PATH" .
(
  cd "$(dirname "$BUNDLE_PATH")"
  sha256sum "$(basename "$BUNDLE_PATH")" > "$(basename "$BUNDLE_PATH").sha256sum"
)

echo "Built ${KERNEL_TAG} kernel ${TEST_VM_ARCH_KIMAGE}: ${VMLINUX_PATH}"
echo "Built kernel BTF: ${VMLINUX_BTF_PATH}"
echo "Built kernel ${PACKAGE_FORMAT} bundle: ${BUNDLE_PATH}"
