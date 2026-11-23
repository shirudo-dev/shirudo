#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
# Publish both CI-profile bundles and their corresponding kernel source.

set -euo pipefail

die() {
	echo "$*" >&2
	exit 1
}

[[ "${RUN_ID:-}" =~ ^[0-9]+$ ]] || die "RUN_ID must be a numeric workflow run ID"

repo=shirudo-dev/shirudo
tag=test-kernel-$RUN_ID
run="repos/$repo/actions/runs/$RUN_ID"

metadata=$(gh api "$run" --jq '
	select(.path == ".github/workflows/build-kernel-packages.yml"
	       and .head_branch == "main" and .head_repository.id == .repository.id
	       and .event == "workflow_dispatch"
	       and .conclusion == "success")
	| [.head_sha, .run_attempt] | @tsv')
IFS=$'\t' read -r producer_commit attempt <<<"$metadata"
[[ "$producer_commit" =~ ^[0-9a-f]{40}$ && "$attempt" =~ ^[0-9]+$ ]] ||
	die "Run $RUN_ID is not a successful kernel package build on main"

existing=$(gh api "repos/$repo/git/matching-refs/tags/$tag" \
	--jq ".[].ref | select(. == \"refs/tags/$tag\")")
if [[ -n "$existing" ]] || gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
	die "Tag or release $tag already exists"
fi

work=$(mktemp -d "${RUNNER_TEMP:?}/test-kernel.XXXXXX")
trap 'rm -rf "$work"' EXIT
cd "$work"

download_artifact() {
	local name=$1 metadata id digest
	metadata=$(gh api "$run/artifacts?name=$name" --jq '
		.artifacts | map(select(.expired == false))
		| select(length == 1) | .[0] | [.id, .digest] | @tsv')
	IFS=$'\t' read -r id digest <<<"$metadata"
	if [[ ! "$id" =~ ^[0-9]+$ || ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
		if [[ "$name" == kernel-ci-source ]]; then
			die "Run $RUN_ID lacks a matching kernel-ci-source artifact with a SHA-256 digest. Select a new build with CI source export enabled."
		fi
		die "Expected one available $name artifact with a SHA-256 digest in run $RUN_ID"
	fi
	gh api "repos/$repo/actions/artifacts/$id/zip" >"$name.zip"
	printf '%s  %s\n' "${digest#sha256:}" "$name.zip" | sha256sum --check >&2
}

download_artifact kernel-ci-source
for arch in arm64 x86-64; do
	download_artifact "kernel-packages-$arch-ci"
done

upstream=$(python3 - "$RUN_ID" "$attempt" "$producer_commit" <<'PY'
import hashlib
import re
import shutil
import sys
import zipfile
from pathlib import PurePosixPath

run, attempt, producer = sys.argv[1:]
source_name = "kernel-ci-source.tar.zst"
with zipfile.ZipFile("kernel-ci-source.zip") as archive:
    if archive.namelist() != [source_name]:
        sys.exit(f"Expected only {source_name} in the kernel-ci-source artifact")
    with archive.open(source_name) as source, open(source_name, "wb") as output:
        shutil.copyfileobj(source, output)
with open(source_name, "rb") as source:
    source_sha256 = hashlib.file_digest(source, "sha256").hexdigest()

upstream, patched = None, None
for arch, deb_arch in (("arm64", "arm64"), ("x86-64", "amd64")):
    bundle = f"kernel-packages-{arch}-ci.zip"
    with zipfile.ZipFile(bundle) as archive:
        images = [PurePosixPath(name) for name in archive.namelist()
                  if PurePosixPath(name).match(f"linux-image-*_{deb_arch}.deb")]
        if len(images) != 1:
            sys.exit(f"Expected one {deb_arch} kernel image in {bundle}")
        name = str(images[0].with_name("BUILD-INFO"))
        if archive.namelist().count(name) != 1:
            sys.exit(f"Expected one BUILD-INFO next to the kernel image in {bundle}")
        fields = {}
        for line in archive.read(name).decode().splitlines():
            key, sep, value = line.partition("=")
            if not sep or key in fields:
                sys.exit(f"Invalid BUILD-INFO in {bundle}")
            fields[key] = value

    expected = {
        "arch": arch, "profile": "ci", "producer_commit": producer,
        "run_id": run, "run_attempt": attempt, "source_sha256": source_sha256,
    }
    for key, value in expected.items():
        if fields.get(key) != value:
            sys.exit(f"Source provenance mismatch in {bundle}: {key}")
    commit = fields.get("commit", "")
    patched_commit = fields.get("patched_commit", "")
    if not all(re.fullmatch(r"[0-9a-f]{40}", rev) for rev in (commit, patched_commit)):
        sys.exit(f"Missing upstream or patched revision in {bundle}")
    if upstream is not None and (upstream, patched) != (commit, patched_commit):
        sys.exit(f"Source revisions disagree between the CI bundles in run {run}")
    upstream, patched = commit, patched_commit
print(upstream)
PY
)

assets=(kernel-packages-arm64-ci.zip kernel-packages-x86-64-ci.zip kernel-ci-source.tar.zst)
sha256sum "${assets[@]}" >SHA256SUMS
gh release create "$tag" --repo "$repo" --target "$producer_commit" --prerelease --latest=false \
	--title "Test kernel build $RUN_ID" \
	--notes "CI-profile kernels and corresponding source from bpf-next $upstream (build run $RUN_ID)." \
	"${assets[@]}" SHA256SUMS
