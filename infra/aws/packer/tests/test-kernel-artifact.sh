#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
installer="$script_dir/../scripts/install-bpf-next-kernel.sh"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

command -v jq >/dev/null
eval "$(sed -n \
  '/^latest_successful_kernel_run() {/,/^}/p; /^download_kernel_artifact() {/,/^}/p' \
  "$installer")"

KERNEL_GITHUB_REPO=shirudo-dev/kernel
KERNEL_GITHUB_WORKFLOW=build-kernel-packages.yml
KERNEL_GITHUB_ARTIFACT=kernel-packages-x86-64-full
KERNEL_GITHUB_RUN_ID=
scenario=success

# Exercise the actual jq selection against mock GitHub API responses.
gh() {
  printf '%s\n' "$*" >> "$tmp_dir/gh.log"
  if [[ "$1" == api ]]; then
    local page query response arg
    [[ "$scenario" != api_failure ]] || return 1
    [[ "$*" == *"repos/$KERNEL_GITHUB_REPO/actions/workflows/$KERNEL_GITHUB_WORKFLOW/runs"* ]]
    page=1
    query=
    while [[ "$#" -gt 0 ]]; do
      arg="$1"
      shift
      case "$arg" in
        page=*) page="${arg#page=}" ;;
        branch=* | status=* | event=* | exclude_pull_requests=*)
          echo "Unexpected server-side filter: $arg" >&2
          return 1
          ;;
        --jq) query="$1"; shift ;;
      esac
    done
    if [[ "$scenario" == no_match || "$page" == 1 && "$scenario" == paginated ]]; then
      response=$(jq -n --argjson count "$([[ "$scenario" == paginated ]] && echo 100 || echo 1)" \
        '{workflow_runs: [range($count) | {id: 999, head_branch: "feature", status: "completed", conclusion: "success"}]}')
    else
      response='{"workflow_runs":[
        {"id":104,"head_branch":"main","status":"in_progress","conclusion":null},
        {"id":103,"head_branch":"main","status":"completed","conclusion":"failure"},
        {"id":102,"head_branch":"feature","status":"completed","conclusion":"success"},
        {"id":101,"head_branch":"main","event":"workflow_dispatch","status":"completed","conclusion":"success","created_at":"2026-10-16T23:16:57Z","head_sha":"abc123"},
        {"id":100,"head_branch":"main","event":"push","status":"completed","conclusion":"success"}
      ]}'
    fi
    jq -r "$query" <<< "$response"
  elif [[ "$1 $2" == "run download" ]]; then
    [[ "$scenario" != download_failure ]] || return 1
  else
    echo "Unexpected gh command: $*" >&2
    return 1
  fi
}

assert_contains() {
  grep -Fq -- "$1" "$2" || {
    echo "Expected '$1' in $2" >&2
    exit 1
  }
}

run_id=$(latest_successful_kernel_run 2> "$tmp_dir/selection.log")
[[ "$run_id" == 101 ]]
assert_contains 'commit abc123' "$tmp_dir/selection.log"
echo 'ok: selects latest successful main workflow_dispatch run'

export KERNEL_GITHUB_BRANCH=feature
[[ "$(latest_successful_kernel_run 2>/dev/null)" == 101 ]]
unset KERNEL_GITHUB_BRANCH
echo 'ok: always selects main despite branch environment'

scenario=paginated
: > "$tmp_dir/gh.log"
[[ "$(latest_successful_kernel_run 2>/dev/null)" == 101 ]]
assert_contains 'page=2' "$tmp_dir/gh.log"
echo 'ok: paginates past 100 non-matching runs'

scenario=no_match
if latest_successful_kernel_run > "$tmp_dir/result" 2> "$tmp_dir/error"; then
  echo 'Expected selection failure when no successful run exists' >&2
  exit 1
fi
assert_contains 'No successful build-kernel-packages.yml run found' "$tmp_dir/error"
echo 'ok: reports no matching run'

scenario=success
: > "$tmp_dir/gh.log"
download_kernel_artifact "$tmp_dir/artifact" > "$tmp_dir/download.log" 2>&1
assert_contains "run download 101 --repo $KERNEL_GITHUB_REPO --name $KERNEL_GITHUB_ARTIFACT --dir $tmp_dir/artifact" "$tmp_dir/gh.log"
echo 'ok: downloads selected artifact into requested directory'

KERNEL_GITHUB_RUN_ID=42
: > "$tmp_dir/gh.log"
download_kernel_artifact "$tmp_dir/artifact" > "$tmp_dir/download.log" 2>&1
assert_contains 'run download 42' "$tmp_dir/gh.log"
if grep -q '^api ' "$tmp_dir/gh.log"; then
  echo 'Explicit run id must bypass workflow selection' >&2
  exit 1
fi
KERNEL_GITHUB_RUN_ID=
echo 'ok: explicit run id bypasses selection'

scenario=api_failure
: > "$tmp_dir/gh.log"
if download_kernel_artifact "$tmp_dir/artifact" > "$tmp_dir/download.log" 2>&1; then
  echo 'Expected API failure to propagate' >&2
  exit 1
fi
if grep -q '^run download ' "$tmp_dir/gh.log"; then
  echo 'Download must not continue after API failure' >&2
  exit 1
fi
echo 'ok: API failure prevents download'

scenario=download_failure
if download_kernel_artifact "$tmp_dir/artifact" > "$tmp_dir/download.log" 2>&1; then
  echo 'Expected artifact download failure to propagate' >&2
  exit 1
fi
echo 'ok: artifact download failure propagates'
