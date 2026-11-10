#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
packer_dir=$(cd "$script_dir/.." && pwd)
profile_name="packer-shirudo-$(date -u +%Y%m%d%H%M%S)-$$"
role_name="$profile_name"
policy_name="$profile_name"
ssm_audit_bucket=${SSM_AUDIT_BUCKET:-}

image_assets_run_id=${SHIRUDO_IMAGE_ASSETS_RUN_ID:-}
packer_args=()

while [ "$#" -gt 0 ]; do
	case "$1" in
		--shirudo-image-assets-run-id)
			if [ "$#" -lt 2 ]; then
				echo "Missing run id after --shirudo-image-assets-run-id" >&2
				exit 2
			fi
			image_assets_run_id=$2
			shift 2
			;;
		--shirudo-image-assets-run-id=*)
			image_assets_run_id=${1#*=}
			shift
			;;
		*)
			packer_args+=("$1")
			shift
			;;
	esac
done

if [ "${#packer_args[@]}" -eq 0 ]; then
	packer_args=(.)
fi

needs_image_assets=true
if [ "${PKR_VAR_image_role:-target}" = dev ]; then
	needs_image_assets=false
fi
for ((i = 0; i < ${#packer_args[@]}; i++)); do
	arg="${packer_args[i]}"
	case "$arg" in
		-var)
			if [ "$((i + 1))" -lt "${#packer_args[@]}" ]; then
				next_arg="${packer_args[i + 1]}"
				case "$next_arg" in
					image_role=dev)
						needs_image_assets=false
						;;
					esac
			fi
			;;
		image_role=dev|-var=image_role=dev)
			needs_image_assets=false
			;;
	esac
done

if ! GH_TOKEN=$(gh auth token --hostname github.com); then
	echo "GitHub token unavailable: run 'gh auth login --hostname github.com'." >&2
	exit 1
fi
export GH_TOKEN

latest_successful_image_assets_run()
{
	local page=1 selection count run_id run_number run_attempt created_at head_sha

	while true; do
		selection="$(gh api --method GET \
			"repos/shirudo-dev/shirudo/actions/workflows/packages.yml/runs" \
			-f per_page=100 \
			-f "page=${page}" \
			--jq '[.workflow_runs[] | select(.head_branch == "main" and .event == "push" and
			  .status == "completed" and .conclusion == "success")][0] |
			  [.id // 0, .run_number // 0, .run_attempt // 0,
			   .created_at // "-", .head_sha // "-"] | @tsv')" || return 1
		IFS=$'\t' read -r run_id run_number run_attempt created_at head_sha <<< "$selection"
		if [ "$run_id" != 0 ]; then
			echo "Selected image-assets run ${run_id}: created ${created_at}, commit ${head_sha}" >&2
			printf '%s\t%s\t%s\n' "$run_id" "$run_number" "$run_attempt"
			return 0
		fi
		count="$(gh api --method GET \
			"repos/shirudo-dev/shirudo/actions/workflows/packages.yml/runs" \
			-f per_page=100 -f "page=${page}" --jq '.workflow_runs | length')" || return 1
		if [ "$count" -lt 100 ]; then
			echo "No successful packages workflow run with image assets found on shirudo-dev/shirudo:main" >&2
			return 1
		fi
		page=$((page + 1))
	done
}

image_assets_run_by_id()
{
	local run_id=$1 selection selected_id run_number run_attempt status conclusion created_at head_sha

	case "$run_id" in
		''|*[!0-9]*)
			echo "Invalid image-assets run id: ${run_id}" >&2
			return 1
			;;
	esac
	selection="$(gh api --method GET \
		"repos/shirudo-dev/shirudo/actions/runs/${run_id}" \
		--jq '[.id // 0, .run_number // 0, .run_attempt // 0, .status // "", .conclusion // "", .created_at // "-", .head_sha // "-"] | @tsv')" || return 1
	IFS=$'\t' read -r selected_id run_number run_attempt status conclusion created_at head_sha <<< "$selection"
	if [ "$selected_id" != "$run_id" ] || [ ! "$run_number" -gt 0 ] ||
	   [ ! "$run_attempt" -gt 0 ] || [ "$status" != completed ] ||
	   [ "$conclusion" != success ]; then
		echo "Image-assets run ${run_id} is not a successful completed workflow run" >&2
		return 1
	fi
	echo "Selected image-assets run ${run_id}: created ${created_at}, commit ${head_sha}" >&2
	printf '%s\t%s\t%s\n' "$selected_id" "$run_number" "$run_attempt"
}

image_assets_dir=
image_assets_lock="$packer_dir/.shirudo-image-assets.lock"
image_assets_path="$packer_dir/.shirudo-image-assets.tar.gz"
image_assets_lock_acquired=false
cleanup_image_assets()
{
	if [ -n "$image_assets_dir" ]; then
		rm -rf "$image_assets_dir"
	fi
	if [ "$image_assets_lock_acquired" = true ]; then
		rm -f "$image_assets_path"
		rmdir "$image_assets_lock" 2>/dev/null || true
	fi
}
trap cleanup_image_assets EXIT

if [ "$needs_image_assets" = true ]; then
	if ! mkdir "$image_assets_lock"; then
		echo "Image-assets staging lock exists: ${image_assets_lock}" >&2
		exit 1
	fi
	image_assets_lock_acquired=true
	rm -f "$image_assets_path"
	image_assets_dir="$(mktemp -d "${TMPDIR:-/tmp}/shirudo-image-assets.XXXXXX")"
	if [ -n "$image_assets_run_id" ]; then
		run_fields="$(image_assets_run_by_id "$image_assets_run_id")"
	else
		run_fields="$(latest_successful_image_assets_run)"
	fi
	IFS=$'\t' read -r run_id run_number run_attempt <<< "$run_fields"
	if [ ! "$run_id" -gt 0 ] || [ ! "$run_number" -gt 0 ] || [ ! "$run_attempt" -gt 0 ]; then
		echo "Invalid image-assets workflow run metadata" >&2
		exit 1
	fi
	artifact_name="shirudo-image-assets-${run_number}-${run_attempt}"
	echo "Downloading ${artifact_name} from shirudo-dev/shirudo run ${run_id}"
	gh run download "$run_id" \
		--repo shirudo-dev/shirudo \
		--name "$artifact_name" \
		--dir "$image_assets_dir"
	if [ ! -s "$image_assets_dir/shirudo-image-assets.tar.gz" ] ||
	   [ ! -s "$image_assets_dir/shirudo-image-assets.tar.gz.sha256" ]; then
		echo "Image-assets artifact is missing its tarball or checksum" >&2
		exit 1
	fi
	(cd "$image_assets_dir" && sha256sum -c shirudo-image-assets.tar.gz.sha256)
	cp "$image_assets_dir/shirudo-image-assets.tar.gz" "$image_assets_path"
fi

trust_doc=$(mktemp)
policy_doc=$(mktemp)

cleanup()
{
	local i

	set +e
	aws iam delete-role-policy \
		--role-name "$role_name" \
		--policy-name "$policy_name" >/dev/null 2>&1
	aws iam remove-role-from-instance-profile \
		--instance-profile-name "$profile_name" \
		--role-name "$role_name" >/dev/null 2>&1
	for i in $(seq 1 12); do
		aws iam delete-instance-profile \
			--instance-profile-name "$profile_name" >/dev/null 2>&1 && break
		sleep 5
	done
	for i in $(seq 1 12); do
		aws iam delete-role --role-name "$role_name" >/dev/null 2>&1 && break
		sleep 5
	done
	rm -f "$trust_doc" "$policy_doc"
	cleanup_image_assets
}

trap cleanup EXIT

cat >"$trust_doc" <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
JSON

bucket_policy_statements=
if [ -n "$ssm_audit_bucket" ]; then
	bucket_policy_statements=$(cat <<JSON
,
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketLocation",
        "s3:GetEncryptionConfiguration"
      ],
      "Resource": "arn:aws:s3:::${ssm_audit_bucket}"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:PutObjectAcl",
        "s3:PutObjectTagging"
      ],
      "Resource": "arn:aws:s3:::${ssm_audit_bucket}/*"
    }
JSON
)
fi

cat >"$policy_doc" <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ssm:DescribeAssociation",
        "ssm:DescribeDocument",
        "ssm:GetDeployablePatchSnapshotForInstance",
        "ssm:GetDocument",
        "ssm:GetManifest",
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:ListAssociations",
        "ssm:ListInstanceAssociations",
        "ssm:PutComplianceItems",
        "ssm:PutConfigurePackageResult",
        "ssm:PutInventory",
        "ssm:UpdateAssociationStatus",
        "ssm:UpdateInstanceAssociationStatus",
        "ssm:UpdateInstanceInformation"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2messages:AcknowledgeMessage",
        "ec2messages:DeleteMessage",
        "ec2messages:FailMessage",
        "ec2messages:GetEndpoint",
        "ec2messages:GetMessages",
        "ec2messages:SendReply"
      ],
      "Resource": "*"
    }${bucket_policy_statements}
  ]
}
JSON

iam_tags=("Key=Name,Value=$profile_name")

echo "Creating temporary instance profile: $profile_name"
aws iam create-instance-profile \
	--instance-profile-name "$profile_name" \
	--tags "${iam_tags[@]}" >/dev/null
aws iam create-role \
	--role-name "$role_name" \
	--description "Temporary role for Packer" \
	--assume-role-policy-document "file://$trust_doc" \
	--tags "${iam_tags[@]}" >/dev/null
aws iam wait instance-profile-exists --instance-profile-name "$profile_name"
aws iam wait role-exists --role-name "$role_name"
aws iam put-role-policy \
	--role-name "$role_name" \
	--policy-name "$policy_name" \
	--policy-document "file://$policy_doc"
aws iam add-role-to-instance-profile \
	--instance-profile-name "$profile_name" \
	--role-name "$role_name"

for _ in $(seq 1 60); do
	if [ "$(aws iam get-instance-profile \
		--instance-profile-name "$profile_name" \
		--query "InstanceProfile.Roles[?RoleName=='$role_name'].RoleName | [0]" \
		--output text)" = "$role_name" ]; then
		break
	fi
	sleep 5
done

echo "Waiting 120s for IAM propagation"
sleep 120

cd "$packer_dir"
packer init .
packer build \
	-var "iam_instance_profile=$profile_name" \
	"${packer_args[@]}"
