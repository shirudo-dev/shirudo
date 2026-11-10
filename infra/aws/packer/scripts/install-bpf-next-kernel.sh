#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

KERNEL_PACKAGE_PATH="${KERNEL_PACKAGE_PATH:-}"
KERNEL_PACKAGE_SHA256="${KERNEL_PACKAGE_SHA256:-}"
KERNEL_GITHUB_REPO="shirudo-dev/kernel"
KERNEL_GITHUB_WORKFLOW="build-kernel-packages.yml"
KERNEL_GITHUB_ARTIFACT="kernel-packages-x86-64-full"
KERNEL_GITHUB_RUN_ID="${KERNEL_GITHUB_RUN_ID:-}"
OTELCOL_INSTALL_PATH="/usr/local/bin/otelcol-contrib"
SSM_AGENT_DEB_URL="${SSM_AGENT_DEB_URL:-https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb}"
WORK_DIR="/usr/src/bpf-next"
PACKAGE_DIR="${WORK_DIR}/packages"
APT_GET=(
  sudo
  env
  DEBIAN_FRONTEND=noninteractive
  NEEDRESTART_MODE=l
  apt-get
  -o
  DPkg::Lock::Timeout=600
  -o
  Dpkg::Options::=--force-confdef
  -o
  Dpkg::Options::=--force-confold
)

cleanup_apt_policy() {
  sudo rm -f /usr/sbin/policy-rc.d
}

latest_successful_kernel_run() {
  local page=1 selection count run_id created_at head_sha

  # Filter locally: GitHub's server-side filters can omit recent runs.
  # Include workflow_dispatch runs, not just pushes.
  while true; do
    selection="$(gh api --method GET \
      "repos/${KERNEL_GITHUB_REPO}/actions/workflows/${KERNEL_GITHUB_WORKFLOW}/runs" \
      -f per_page=100 \
      -f "page=${page}" \
      --jq '.workflow_runs as $runs |
        ([$runs[] | select(.head_branch == "main" and
          .status == "completed" and .conclusion == "success")][0]) as $run |
        [($runs | length), ($run.id // 0), ($run.created_at // "-"),
          ($run.head_sha // "-")] | @tsv')" || return 1
    IFS=$'\t' read -r count run_id created_at head_sha <<< "$selection"
    if [[ "$run_id" != 0 ]]; then
      echo "Selected kernel Actions run ${run_id}: created ${created_at}, commit ${head_sha}" >&2
      printf '%s\n' "$run_id"
      return 0
    fi
    if [[ "$count" -lt 100 ]]; then
      echo "No successful ${KERNEL_GITHUB_WORKFLOW} run found on ${KERNEL_GITHUB_REPO}:main" >&2
      return 1
    fi
    page=$((page + 1))
  done
}

download_kernel_artifact() {
  local artifact_dir="$1"
  local run_id="$KERNEL_GITHUB_RUN_ID"

  if [[ -z "$run_id" ]]; then
    echo "Selecting the latest successful ${KERNEL_GITHUB_WORKFLOW} run on ${KERNEL_GITHUB_REPO}:main"
    run_id="$(latest_successful_kernel_run)" || return 1
  fi

  echo "Downloading ${KERNEL_GITHUB_ARTIFACT} from ${KERNEL_GITHUB_REPO} Actions run ${run_id}"
  gh run download "$run_id" \
    --repo "$KERNEL_GITHUB_REPO" \
    --name "$KERNEL_GITHUB_ARTIFACT" \
    --dir "$artifact_dir"
}

aws_cli_arch() {
  case "$(uname -m)" in
    x86_64)
      echo "x86_64"
      ;;
    aarch64 | arm64)
      echo "aarch64"
      ;;
    *)
      echo "Unsupported machine architecture for awscli: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

ensure_aws_cli() (
  local arch tmp_dir

  if command -v aws >/dev/null 2>&1; then
    return
  fi

  arch="$(aws_cli_arch)"
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT

  echo "Installing AWS CLI v2 for ${arch}"
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${arch}.zip" -o "${tmp_dir}/awscliv2.zip"
  unzip -q "${tmp_dir}/awscliv2.zip" -d "$tmp_dir"
  sudo "${tmp_dir}/aws/install" --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli --update
  aws --version
)

otel_collector_arch() {
  case "$(uname -m)" in
    x86_64)
      echo "amd64"
      ;;
    aarch64 | arm64)
      echo "arm64"
      ;;
    *)
      echo "Unsupported machine architecture for otelcol-contrib: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

latest_otel_collector_package_url() {
  local arch="$1"

  curl -fsSL "https://api.github.com/repos/open-telemetry/opentelemetry-collector-releases/releases/latest" |
    python3 -c '
import json
import sys

suffix = f"_linux_{sys.argv[1]}.deb"
for asset in json.load(sys.stdin)["assets"]:
    name = asset["name"]
    if name.startswith("otelcol-contrib_") and name.endswith(suffix):
        print(asset["browser_download_url"])
        break
' "$arch"
}

# Isolate temporary-file cleanup from the kernel installation's EXIT trap.
install_otel_collector() (
  local arch package_url tmp_dir package_path binary_path

  arch="$(otel_collector_arch)"
  package_url="$(latest_otel_collector_package_url "$arch")"
  if [[ -z "$package_url" ]]; then
    echo "No otelcol-contrib deb/${arch} package found in latest release" >&2
    exit 1
  fi

  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT

  package_path="${tmp_dir}/otelcol-contrib.deb"
  echo "Installing otelcol-contrib from ${package_url}"
  curl -fsSL "$package_url" -o "$package_path"
  "${APT_GET[@]}" install -y --no-install-recommends "$package_path"

  binary_path="$(command -v otelcol-contrib || true)"
  if [[ -z "$binary_path" ]]; then
    echo "otelcol-contrib package did not install an otelcol-contrib binary" >&2
    exit 1
  fi
  if [[ "$binary_path" != "$OTELCOL_INSTALL_PATH" ]]; then
    sudo ln -sf "$binary_path" "$OTELCOL_INSTALL_PATH"
  fi

  sudo systemctl disable --now otelcol-contrib.service >/dev/null 2>&1 || true
)

kernel_config_has() {
  local kernel_release="$1"
  local symbol="$2"

  grep -Eq "^${symbol}=[ym]$" "/boot/config-${kernel_release}"
}

require_kernel_config() {
  local kernel_release="$1"
  local symbol="$2"
  local description="$3"

  if kernel_config_has "$kernel_release" "$symbol"; then
    return
  fi

  echo "Expected kernel lacks ${description} (${symbol})." >&2
  echo "Rebuild the kernel artifact with ${symbol} enabled." >&2
  grep -E "^${symbol}=|^# ${symbol} is not set" "/boot/config-${kernel_release}" >&2 || true
  exit 1
}

require_kernel_config_value() {
  local kernel_release="$1"
  local symbol="$2"
  local expected="$3"
  local description="$4"

  if grep -Fqx "${symbol}=${expected}" "/boot/config-${kernel_release}"; then
    return
  fi

  echo "Expected kernel ${description} (${symbol}=${expected})." >&2
  grep -E "^${symbol}=|^# ${symbol} is not set" "/boot/config-${kernel_release}" >&2 || true
  exit 1
}

install_ssm_deb_agent() {
  local ssm_tmp

  if systemctl cat snap.amazon-ssm-agent.amazon-ssm-agent.service >/dev/null 2>&1; then
    sudo snap remove amazon-ssm-agent || true
  fi

  ssm_tmp="$(mktemp -d)"
  curl -fsSL "$SSM_AGENT_DEB_URL" -o "${ssm_tmp}/amazon-ssm-agent.deb"
  sudo dpkg -i "${ssm_tmp}/amazon-ssm-agent.deb"
  sudo systemctl enable amazon-ssm-agent.service
  rm -rf "$ssm_tmp"
}

ensure_ssm_agent_for_next_boot() {
  install_ssm_deb_agent
}

write_grub_defaults() {
  sudo tee /etc/default/grub.d/99-bpf-next.cfg >/dev/null <<'EOF'
GRUB_DEFAULT=0
unset GRUB_FORCE_PARTUUID
GRUB_CMDLINE_LINUX_DEFAULT="${GRUB_CMDLINE_LINUX_DEFAULT} lsm=landlock,lockdown,yama,integrity,apparmor,bpf bpf.keyring_unsealed=1 dm_verity.keyring_unsealed=1"
EOF
}

if [[ -n "$KERNEL_PACKAGE_PATH" && ! -f "$KERNEL_PACKAGE_PATH" && ! -d "$KERNEL_PACKAGE_PATH" ]]; then
  echo "Kernel package artifact not found: ${KERNEL_PACKAGE_PATH}" >&2
  exit 1
fi

if command -v cloud-init >/dev/null 2>&1; then
  cloud_init_status=0
  sudo cloud-init status --wait || cloud_init_status=$?
  case "$cloud_init_status" in
    0)
      ;;
    2)
      echo "cloud-init completed with recoverable errors; continuing with details:" >&2
      sudo cloud-init status --long || true
      ;;
    *)
      echo "cloud-init failed with status ${cloud_init_status}" >&2
      exit "$cloud_init_status"
      ;;
  esac
fi

sudo tee /usr/sbin/policy-rc.d >/dev/null <<'EOF'
#!/bin/sh
exit 101
EOF
sudo chmod +x /usr/sbin/policy-rc.d
trap cleanup_apt_policy EXIT

"${APT_GET[@]}" update
"${APT_GET[@]}" install -y --no-install-recommends \
  ca-certificates \
  coreutils \
  curl \
  gh \
  initramfs-tools \
  kmod \
  python3 \
  tar \
  tpm2-tools \
  unzip

ensure_aws_cli
install_otel_collector

sudo install -d -o "$USER" -g "$USER" "$WORK_DIR" "$PACKAGE_DIR"

if [[ -z "$KERNEL_PACKAGE_PATH" ]]; then
  KERNEL_PACKAGE_PATH="$(mktemp -d "${WORK_DIR}/artifact.XXXXXX")"
  download_kernel_artifact "$KERNEL_PACKAGE_PATH"
fi

if [[ -d "$KERNEL_PACKAGE_PATH" ]]; then
  package_file="$(find "$KERNEL_PACKAGE_PATH" -type f \
    \( -name 'bpf-next-kernel-debs-amd64.zip' -o -name 'bpf-next-kernel-debs.tar.gz' \) |
    sort | head -n 1)"

  if [[ -n "$package_file" ]]; then
    if [[ -n "$KERNEL_PACKAGE_SHA256" ]]; then
      printf '%s  %s\n' "$KERNEL_PACKAGE_SHA256" "$package_file" | sha256sum -c -
    elif [[ -f "${package_file}.sha256sum" ]]; then
      (cd "$(dirname "$package_file")" && sha256sum -c "$(basename "$package_file").sha256sum")
    fi

    case "$package_file" in
      *.zip)
        unzip -q "$package_file" -d "$PACKAGE_DIR"
        ;;
      *)
        tar -xzf "$package_file" -C "$PACKAGE_DIR"
        ;;
    esac
  else
    image_deb="$(find "$KERNEL_PACKAGE_PATH" -type f -name 'linux-image-[0-9]*.deb' ! -name '*-dbg*' | sort | head -n 1)"
    if [[ -z "$image_deb" ]]; then
      echo "No kernel package file found in ${KERNEL_PACKAGE_PATH}" >&2
      exit 1
    fi

    artifact_dir="$(dirname "$image_deb")"
    if [[ -f "${artifact_dir}/SHA256SUMS" ]]; then
      (cd "$artifact_dir" && sha256sum -c SHA256SUMS)
    fi
    find "$artifact_dir" -maxdepth 1 -type f -name '*.deb' -exec cp {} "$PACKAGE_DIR/" \;
    find "$artifact_dir" -maxdepth 1 -type f \( -name 'BUILD-INFO' -o -name 'bpf-next-kernel-build' -o -name 'config-*' \) -exec cp {} "$PACKAGE_DIR/" \;
  fi
elif [[ -f "$KERNEL_PACKAGE_PATH" ]]; then
  package_file="$KERNEL_PACKAGE_PATH"
  if [[ -n "$KERNEL_PACKAGE_SHA256" ]]; then
    printf '%s  %s\n' "$KERNEL_PACKAGE_SHA256" "$package_file" | sha256sum -c -
  elif [[ -f "${package_file}.sha256sum" ]]; then
    (cd "$(dirname "$package_file")" && sha256sum -c "$(basename "$package_file").sha256sum")
  fi

  case "$package_file" in
    *.deb)
      cp "$package_file" "$PACKAGE_DIR/"
      ;;
    *.zip)
      unzip -q "$package_file" -d "$PACKAGE_DIR"
      ;;
    *)
      tar -xzf "$package_file" -C "$PACKAGE_DIR"
      ;;
  esac
else
  echo "No kernel package file found in ${KERNEL_PACKAGE_PATH}" >&2
  exit 1
fi

bundle_file="$(find "$PACKAGE_DIR" -type f -name 'bpf-next-kernel-debs.tar.gz' | sort | head -n 1)"
if [[ -n "$bundle_file" ]]; then
  if [[ -f "${bundle_file}.sha256sum" ]]; then
    (cd "$(dirname "$bundle_file")" && sha256sum -c "$(basename "$bundle_file").sha256sum")
  fi
  tar -xzf "$bundle_file" -C "$PACKAGE_DIR"
fi

if [[ -f "${PACKAGE_DIR}/SHA256SUMS" ]]; then
  (cd "$PACKAGE_DIR" && sha256sum -c SHA256SUMS)
fi

mapfile -t debs < <(
  find "$PACKAGE_DIR" -type f \
    \( -name 'linux-image-[0-9]*.deb' -o -name 'linux-headers-[0-9]*.deb' \) \
    ! -name '*-dbg*' |
    sort
)

if [[ "${#debs[@]}" -eq 0 ]]; then
  echo "No linux-image or linux-headers deb packages found in ${KERNEL_PACKAGE_PATH}" >&2
  exit 1
fi

image_deb="$(find "$PACKAGE_DIR" -type f -name 'linux-image-[0-9]*.deb' ! -name '*-dbg*' | sort | head -n 1)"
if [[ -z "$image_deb" ]]; then
  echo "No linux-image kernel package found in ${KERNEL_PACKAGE_PATH}" >&2
  exit 1
fi
image_package="$(dpkg-deb -f "$image_deb" Package)"
kernel_release="${image_package#linux-image-}"

write_grub_defaults
"${APT_GET[@]}" install -y --no-install-recommends "${debs[@]}"
artifact_config="${PACKAGE_DIR}/config-${kernel_release}"
if [[ ! -f "$artifact_config" && -f "${PACKAGE_DIR}/kernel.config" ]]; then
  artifact_config="${PACKAGE_DIR}/kernel.config"
fi
boot_config="/boot/config-${kernel_release}"
if [[ ! -f "$artifact_config" ]]; then
  echo "Kernel artifact is missing config-${kernel_release} and kernel.config; refusing an unverified AMI kernel" >&2
  exit 1
fi
if ! cmp -s "$artifact_config" "$boot_config"; then
  echo "Installed kernel config differs from config-${kernel_release} in the kernel artifact" >&2
  diff -u "$artifact_config" "$boot_config" | sed -n '1,120p' >&2 || true
  exit 1
fi

require_kernel_config "$kernel_release" CONFIG_BPF_SYSCALL "BPF syscall support"
require_kernel_config "$kernel_release" CONFIG_BPF_LSM "BPF LSM support"
require_kernel_config "$kernel_release" CONFIG_DEBUG_INFO_BTF "BTF support for Shirudo's CO-RE programs"
require_kernel_config "$kernel_release" CONFIG_KEYS "kernel keyrings"
require_kernel_config "$kernel_release" CONFIG_MODULES "loadable kernel modules"
require_kernel_config "$kernel_release" CONFIG_TCG_TPM "TPM support"
require_kernel_config "$kernel_release" CONFIG_TCG_CRB "NitroTPM CRB driver"
require_kernel_config "$kernel_release" CONFIG_DEVTMPFS "device filesystem support"
require_kernel_config "$kernel_release" CONFIG_EXT4_FS "ext4 root filesystem support"
require_kernel_config "$kernel_release" CONFIG_EXT4_FS_SECURITY "ext4 security xattrs for Shirudo seals"
require_kernel_config "$kernel_release" CONFIG_NAMESPACES "namespace support for systemd services"
require_kernel_config "$kernel_release" CONFIG_UTS_NS "UTS namespaces for systemd services"
require_kernel_config "$kernel_release" CONFIG_SECCOMP "seccomp support for systemd services"
require_kernel_config "$kernel_release" CONFIG_SECCOMP_FILTER "seccomp filter support for systemd services"
require_kernel_config "$kernel_release" CONFIG_TMPFS_XATTR "tmpfs xattrs for Shirudo bpffs pins"
require_kernel_config "$kernel_release" CONFIG_DM_VERITY "dm-verity support for authenticated images"
require_kernel_config "$kernel_release" CONFIG_BLK_DEV_LOOP "loop devices for authenticated images"
require_kernel_config "$kernel_release" CONFIG_BLK_DEV_NVME "NVMe root disk support"
require_kernel_config "$kernel_release" CONFIG_ENA_ETHERNET "ENA network driver"
require_kernel_config_value "$kernel_release" CONFIG_BLK_DEV_DM y "built-in device mapper support"
ensure_ssm_agent_for_next_boot

cleanup_apt_policy
trap - EXIT

metadata_file="$(find "$PACKAGE_DIR" -type f \( -name bpf-next-kernel-build -o -name BUILD-INFO \) | sort | head -n 1)"
if [[ -n "$metadata_file" ]]; then
  metadata_kernel_release="$(awk -F= '$1 == "kernel_release" || $1 == "kernelrelease" { print $2; exit }' "$metadata_file")"
  if [[ -n "$metadata_kernel_release" && "$metadata_kernel_release" != "$kernel_release" ]]; then
    echo "Kernel metadata release ${metadata_kernel_release} does not match image package ${kernel_release}; using image package" >&2
  fi
fi

write_grub_defaults
sudo depmod -a "$kernel_release"
sudo sed -i '/^ena$/d; /^nvme$/d; /^nvme_core$/d' /etc/initramfs-tools/modules
printf 'ena\nnvme\nnvme_core\n' | sudo tee -a /etc/initramfs-tools/modules >/dev/null
sudo update-initramfs -u -k "$kernel_release"
sudo update-grub

sudo tee /etc/bpf-next-kernel-release >/dev/null <<<"$kernel_release"
if [[ -n "$metadata_file" ]]; then
  sudo install -m 0644 "$metadata_file" /etc/bpf-next-kernel-build
else
  sudo tee /etc/bpf-next-kernel-build >/dev/null <<EOF
commit=unknown
kernel_release=${kernel_release}
installed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
fi

test -f "/boot/vmlinuz-${kernel_release}"
test -d "/lib/modules/${kernel_release}"

sudo rm -rf "$WORK_DIR"
sudo apt-get clean
sudo rm -rf /var/lib/apt/lists/*
