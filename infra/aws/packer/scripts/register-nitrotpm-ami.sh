#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -euo pipefail

: "${AWS_REGION:?AWS_REGION is required}"
: "${PACKER_MANIFEST_PATH:?PACKER_MANIFEST_PATH is required}"
: "${UBUNTU_VERSION:?UBUNTU_VERSION is required}"
: "${KERNEL_ARTIFACT_NAME:?KERNEL_ARTIFACT_NAME is required}"

SHIRUDO_IMAGE_ROLE="${SHIRUDO_IMAGE_ROLE:-target}"
case "$SHIRUDO_IMAGE_ROLE" in
  dev | target) ;;
  *)
    echo "SHIRUDO_IMAGE_ROLE must be dev or target" >&2
    exit 1
    ;;
esac

require_command() {
  local command_name="$1"

  command -v "$command_name" >/dev/null 2>&1 || {
    echo "${command_name} is required" >&2
    exit 1
  }
}

image_field() {
  local image_id="$1"
  local query="$2"

  aws ec2 describe-images \
    --region "$AWS_REGION" \
    --image-ids "$image_id" \
    --query "$query" \
    --output text
}

require_command aws

if [[ ! -r "$PACKER_MANIFEST_PATH" ]]; then
  echo "Packer manifest not found: ${PACKER_MANIFEST_PATH}" >&2
  exit 1
fi

artifact_id="$(
  sed -n 's/.*"artifact_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$PACKER_MANIFEST_PATH" |
    tail -n 1
)"

if [[ -z "$artifact_id" || "$artifact_id" == "null" ]]; then
  echo "Could not find artifact_id in ${PACKER_MANIFEST_PATH}" >&2
  exit 1
fi

artifact_region="${artifact_id%%:*}"
source_ami_id="${artifact_id##*:}"

if [[ -n "$artifact_region" && "$artifact_region" != "$source_ami_id" ]]; then
  AWS_REGION="$artifact_region"
fi

source_name="$(image_field "$source_ami_id" 'Images[0].Name')"
architecture="$(image_field "$source_ami_id" 'Images[0].Architecture')"
root_device_name="$(image_field "$source_ami_id" 'Images[0].RootDeviceName')"
virtualization_type="$(image_field "$source_ami_id" 'Images[0].VirtualizationType')"
ena_support="$(image_field "$source_ami_id" 'Images[0].EnaSupport')"
snapshot_id="$(image_field "$source_ami_id" "Images[0].BlockDeviceMappings[?DeviceName=='${root_device_name}'].Ebs.SnapshotId | [0]")"
volume_size="$(image_field "$source_ami_id" "Images[0].BlockDeviceMappings[?DeviceName=='${root_device_name}'].Ebs.VolumeSize | [0]")"
volume_type="$(image_field "$source_ami_id" "Images[0].BlockDeviceMappings[?DeviceName=='${root_device_name}'].Ebs.VolumeType | [0]")"
delete_on_termination="$(image_field "$source_ami_id" "Images[0].BlockDeviceMappings[?DeviceName=='${root_device_name}'].Ebs.DeleteOnTermination | [0]")"
iops="$(image_field "$source_ami_id" "Images[0].BlockDeviceMappings[?DeviceName=='${root_device_name}'].Ebs.Iops | [0]")"
throughput="$(image_field "$source_ami_id" "Images[0].BlockDeviceMappings[?DeviceName=='${root_device_name}'].Ebs.Throughput | [0]")"

if [[ -z "$source_name" || "$source_name" == "None" || -z "$snapshot_id" || "$snapshot_id" == "None" ]]; then
  echo "Could not derive source AMI metadata from ${source_ami_id}" >&2
  exit 1
fi

tpm_ami_name="${source_name}-nitrotpm-v2"
existing_tpm_ami_id="$(
  aws ec2 describe-images \
    --region "$AWS_REGION" \
    --owners self \
    --filters "Name=name,Values=${tpm_ami_name}" "Name=tpm-support,Values=v2.0" \
    --query 'Images | sort_by(@, &CreationDate)[-1].ImageId' \
    --output text
)"

if [[ -n "$existing_tpm_ami_id" && "$existing_tpm_ami_id" != "None" ]]; then
  aws ec2 create-tags \
    --region "$AWS_REGION" \
    --resources "$existing_tpm_ami_id" \
    --tags "Key=ShirudoRole,Value=${SHIRUDO_IMAGE_ROLE}"
  echo "NitroTPM AMI already exists: ${existing_tpm_ami_id} (${tpm_ami_name})"
  exit 0
fi

block_device_mapping="DeviceName=${root_device_name},Ebs={SnapshotId=${snapshot_id},DeleteOnTermination=${delete_on_termination},VolumeType=${volume_type},VolumeSize=${volume_size}"
if [[ -n "$iops" && "$iops" != "None" ]]; then
  block_device_mapping="${block_device_mapping},Iops=${iops}"
fi
if [[ -n "$throughput" && "$throughput" != "None" ]]; then
  block_device_mapping="${block_device_mapping},Throughput=${throughput}"
fi
block_device_mapping="${block_device_mapping}}"

register_args=(
  ec2
  register-image
  --region "$AWS_REGION"
  --name "$tpm_ami_name"
  --description "NitroTPM-enabled ${source_name}"
  --architecture "$architecture"
  --root-device-name "$root_device_name"
  --virtualization-type "$virtualization_type"
  --boot-mode uefi
  --tpm-support v2.0
  --block-device-mappings "$block_device_mapping"
  --tag-specifications "ResourceType=image,Tags=[{Key=Name,Value=${tpm_ami_name}},{Key=BaseOS,Value=ubuntu-${UBUNTU_VERSION}},{Key=KernelFlavor,Value=bpf-next},{Key=ShirudoRole,Value=${SHIRUDO_IMAGE_ROLE}},{Key=TpmSupport,Value=v2.0}]"
  --query ImageId
  --output text
)

if [[ "$ena_support" == "True" || "$ena_support" == "true" ]]; then
  register_args+=(--ena-support)
fi

echo "Registering NitroTPM AMI from ${source_ami_id} (${source_name})..."
tpm_ami_id="$(aws "${register_args[@]}")"

aws ec2 create-tags \
  --region "$AWS_REGION" \
  --resources "$tpm_ami_id" \
  --tags \
    "Key=KernelDebs,Value=${KERNEL_ARTIFACT_NAME}" \
    "Key=SourceAmi,Value=${source_ami_id}"

aws ec2 wait image-available \
  --region "$AWS_REGION" \
  --image-ids "$tpm_ami_id"

aws ec2 describe-images \
  --region "$AWS_REGION" \
  --image-ids "$tpm_ami_id" \
  --query 'Images[0].{ImageId:ImageId,Name:Name,BootMode:BootMode,TpmSupport:TpmSupport}' \
  --output table
