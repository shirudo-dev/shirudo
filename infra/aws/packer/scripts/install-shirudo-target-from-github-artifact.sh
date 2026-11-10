#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -euo pipefail

SHIRUDO_GITHUB_REPO="shirudo-dev/shirudo"
SHIRUDO_GITHUB_WORKFLOW="packages.yml"
SHIRUDO_GITHUB_ARTIFACT="shirudo-deb"
SHIRUDO_GITHUB_RUN_ID="${SHIRUDO_GITHUB_RUN_ID:-}"
SHIRUDO_INSTALL_PATH="${SHIRUDO_INSTALL_PATH:-/usr/local/bin/shirudo}"

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

package_arch() {
  case "$(uname -m)" in
    x86_64)
      echo "amd64"
      ;;
    aarch64 | arm64)
      echo "arm64"
      ;;
    *)
      echo "Unsupported machine architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

latest_successful_run() {
  local page=1 selection count run_id created_at head_sha

  # Server-side branch/status filters can omit recent runs. Filter all metadata
  # locally and paginate until a matching run is found.
  while true; do
    selection="$(gh api --method GET \
      "repos/${SHIRUDO_GITHUB_REPO}/actions/workflows/${SHIRUDO_GITHUB_WORKFLOW}/runs" \
      -f per_page=100 \
      -f "page=${page}" \
      --jq '.workflow_runs as $runs |
        ([$runs[] | select(.head_branch == "main" and
          .event == "push" and .status == "completed" and
          .conclusion == "success")][0]) as $run |
        [($runs | length), ($run.id // 0), ($run.created_at // "-"),
          ($run.head_sha // "-")] | @tsv')" || return 1
    IFS=$'\t' read -r count run_id created_at head_sha <<< "$selection"
    if [[ "$run_id" != 0 ]]; then
      echo "Selected Actions run ${run_id}: created ${created_at}, commit ${head_sha}" >&2
      printf '%s\n' "$run_id"
      return 0
    fi
    if [[ "$count" -lt 100 ]]; then
      echo "No successful ${SHIRUDO_GITHUB_WORKFLOW} push run found on ${SHIRUDO_GITHUB_REPO}:main" >&2
      return 1
    fi
    page=$((page + 1))
  done
}

install_shirudo_deb() {
  local artifact_dir="$1"
  local arch="$2"
  local package_path
  local binary_path

  package_path="$(find "$artifact_dir" -type f -name "shirudo-target_*_${arch}.deb" | sort | tail -n 1)"
  if [[ -z "$package_path" ]]; then
    package_path="$(find "$artifact_dir" -type f -name "shirudo-target_*.deb" | sort | tail -n 1)"
  fi
  if [[ -z "$package_path" ]]; then
    echo "No shirudo-target deb package found in ${artifact_dir}" >&2
    exit 1
  fi

  echo "Installing shirudo-target from ${package_path}"
  "${APT_GET[@]}" install -y --no-install-recommends "$package_path"

  binary_path="$(command -v shirudo || true)"
  if [[ -z "$binary_path" ]]; then
    echo "shirudo-target package did not install a shirudo binary" >&2
    exit 1
  fi
  if [[ "$binary_path" != "$SHIRUDO_INSTALL_PATH" ]]; then
    sudo ln -sf "$binary_path" "$SHIRUDO_INSTALL_PATH"
  fi
}

"${APT_GET[@]}" update
"${APT_GET[@]}" install -y --no-install-recommends \
  ca-certificates \
  coreutils \
  gh \
  libtss2-tctildr0

arch="$(package_arch)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

if [[ -z "$SHIRUDO_GITHUB_RUN_ID" ]]; then
  echo "Selecting the latest successful ${SHIRUDO_GITHUB_WORKFLOW} push run on ${SHIRUDO_GITHUB_REPO}:main"
  SHIRUDO_GITHUB_RUN_ID="$(latest_successful_run)"
fi

echo "Downloading ${SHIRUDO_GITHUB_ARTIFACT} from ${SHIRUDO_GITHUB_REPO} Actions run ${SHIRUDO_GITHUB_RUN_ID}"
gh run download "$SHIRUDO_GITHUB_RUN_ID" \
  --repo "$SHIRUDO_GITHUB_REPO" \
  --name "$SHIRUDO_GITHUB_ARTIFACT" \
  --dir "${tmp_dir}/shirudo-deb"

install_shirudo_deb "${tmp_dir}/shirudo-deb" "$arch"

"$SHIRUDO_INSTALL_PATH" --help >/dev/null || true
ls -l "$SHIRUDO_INSTALL_PATH"
