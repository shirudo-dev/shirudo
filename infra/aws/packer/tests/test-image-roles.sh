#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
packer_dir=$(cd "$script_dir/.." && pwd)
registrar="$packer_dir/scripts/register-nitrotpm-ami.sh"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

command -v packer >/dev/null
command -v jq >/dev/null

selection() {
  printf 'jsonencode({prefix=local.ami_prefix, except=local.target_provisioner_except, run_tags=local.packer_run_tags, volume_tags=local.packer_run_volume_tags})\n' |
    packer console \
      -var 'iam_instance_profile=validation-only' \
      "$@" "$packer_dir"
}

assert_contains() {
  grep -Fq -- "$1" "$2" || {
    echo "Expected '$1' in $2" >&2
    exit 1
  }
}

validate() {
  packer validate \
    -var 'iam_instance_profile=validation-only' \
    "$@" "$packer_dir" > "$tmp_dir/validate.log" 2>&1 || {
    cat "$tmp_dir/validate.log" >&2
    return 1
  }
}

selection | jq -e '.prefix == "shirudo-target-ubuntu" and .except == [] and (.run_tags | has("expiry") | not) and (.volume_tags | has("expiry") | not)' >/dev/null
echo 'ok: target is the default role and expiry tags are omitted by default'

selection -var 'additional_build_tags={owner="test", expiry="2099-12-31"}' |
  jq -e '.run_tags.owner == "test" and .volume_tags.owner == "test" and .run_tags.expiry == "2099-12-31" and .volume_tags.expiry == "2099-12-31"' >/dev/null
echo 'ok: owner and expiry tags reach the builder and root volume'

selection -var 'additional_build_tags={svic_osquery_supported="no"}' |
  jq -e '.run_tags.svic_osquery_supported == "no" and .volume_tags.svic_osquery_supported == "no"' >/dev/null
echo 'ok: additional build tags reach the builder and root volume'

selection -var 'image_role=dev' |
  jq -e '.prefix == "shirudo-dev-ubuntu" and .except == ["amazon-ebs.bpf_next_ubuntu"]' >/dev/null
validate -var 'image_role=dev'
echo 'ok: dev uses a separate name prefix and excludes target provisioning'

selection -var 'image_role=target' |
  jq -e '.prefix == "shirudo-target-ubuntu" and .except == []' >/dev/null
validate
echo 'ok: target preserves all provisioning steps'

if packer validate \
  -var 'iam_instance_profile=validation-only' \
  -var 'image_role=invalid' "$packer_dir" > "$tmp_dir/error.log" 2>&1; then
  echo 'Expected invalid image role to fail validation' >&2
  exit 1
fi
assert_contains 'The image_role must be dev or target.' "$tmp_dir/error.log"
echo 'ok: Packer rejects invalid image roles'

awk '
  /^  provisioner / { block = $0; next }
  block != "" {
    block = block "\n" $0
    if ($0 == "  }") {
      if (block ~ /install-shirudo-target|configure-shirudo-initrd|local.shirudo_cert_path|\/var\/lib\/shirudo\/keys/) {
        if (block ~ /configure-shirudo-initrd/) {
          if (block !~ /except[[:space:]]*=[[:space:]]*local[.]target_provisioner_except/)
            failed = 1
        } else if (block !~ /except[[:space:]]*=[[:space:]]*local[.]target_provisioner_except/) {
          failed = 1
        }
        checked++
      }
      block = ""
    }
  }
  END { exit failed || checked != 5 }
' "$packer_dir/bpf-next-ubuntu.pkr.hcl"
echo 'ok: package, certificate and initrd provisioners are all role-gated'

export AWS_REGION=us-west-2
export PACKER_MANIFEST_PATH="$tmp_dir/manifest.json"
export UBUNTU_VERSION=26.04
export KERNEL_ARTIFACT_NAME=kernel-packages-x86-64-full
export TEST_AWS_LOG="$tmp_dir/aws.log"
export MOCK_AMI_PREFIX=shirudo-target-ubuntu
export MOCK_EXISTING_AMI=None
printf '{"builds":[{"artifact_id":"us-west-2:ami-source"}]}\n' > "$PACKER_MANIFEST_PATH"

aws() {
  local operation="$1 $2" query= image_id=

  printf '%s\n' "$*" >> "$TEST_AWS_LOG"
  shift 2
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --query) query="$2"; shift ;;
      --image-ids) image_id="$2"; shift ;;
    esac
    shift
  done
  case "$operation" in
    'ec2 describe-images')
      if [[ -z "$image_id" ]]; then
        printf '%s\n' "$MOCK_EXISTING_AMI"
        return
      fi
      case "$query" in
        'Images[0].Name') echo "$MOCK_AMI_PREFIX-26.04-123" ;;
        'Images[0].Architecture') echo x86_64 ;;
        'Images[0].RootDeviceName') echo /dev/sda1 ;;
        'Images[0].VirtualizationType') echo hvm ;;
        'Images[0].EnaSupport') echo True ;;
        *Ebs.SnapshotId*) echo snap-test ;;
        *Ebs.VolumeSize*) echo 30 ;;
        *Ebs.VolumeType*) echo gp3 ;;
        *Ebs.DeleteOnTermination*) echo True ;;
        *Ebs.Iops*) echo 3000 ;;
        *Ebs.Throughput*) echo 125 ;;
        *ImageId*) echo '{}' ;;
        *) echo "Unexpected image query: $query" >&2; return 1 ;;
      esac
      ;;
    'ec2 register-image') echo ami-registered ;;
    'ec2 create-tags' | 'ec2 wait') ;;
    *) echo "Unexpected AWS operation: $operation" >&2; return 1 ;;
  esac
}
export -f aws

for role in dev target; do
  if [[ "$role" == dev ]]; then
    MOCK_AMI_PREFIX=shirudo-dev-ubuntu
  else
    MOCK_AMI_PREFIX=shirudo-target-ubuntu
  fi
  : > "$TEST_AWS_LOG"
  SHIRUDO_IMAGE_ROLE="$role" bash "$registrar" > "$tmp_dir/register.log"
  assert_contains "--name $MOCK_AMI_PREFIX-26.04-123-nitrotpm-v2" "$TEST_AWS_LOG"
  assert_contains "{Key=ShirudoRole,Value=$role}" "$TEST_AWS_LOG"
  assert_contains '--boot-mode uefi --tpm-support v2.0' "$TEST_AWS_LOG"
  if grep -Eq 'Key=(owner|expiry)' "$TEST_AWS_LOG"; then
    echo 'NitroTPM AMI must not receive owner or expiry tags' >&2
    exit 1
  fi
  echo "ok: $role NitroTPM AMI is registered with its role tag"

  MOCK_EXISTING_AMI=ami-existing
  : > "$TEST_AWS_LOG"
  SHIRUDO_IMAGE_ROLE="$role" bash "$registrar" > "$tmp_dir/register.log"
  assert_contains "--resources ami-existing --tags Key=ShirudoRole,Value=$role" "$TEST_AWS_LOG"
  if grep -q '^ec2 register-image ' "$TEST_AWS_LOG"; then
    echo 'An existing NitroTPM AMI must not be registered again' >&2
    exit 1
  fi
  MOCK_EXISTING_AMI=None
  echo "ok: rerunning registration tags the existing $role AMI"

done

: > "$TEST_AWS_LOG"
if SHIRUDO_IMAGE_ROLE=invalid bash "$registrar" > "$tmp_dir/error.log" 2>&1; then
  echo 'Expected registration to reject an invalid image role' >&2
  exit 1
fi
[[ ! -s "$TEST_AWS_LOG" ]]
assert_contains 'SHIRUDO_IMAGE_ROLE must be dev or target' "$tmp_dir/error.log"
echo 'ok: invalid registration role fails before any AWS calls'
