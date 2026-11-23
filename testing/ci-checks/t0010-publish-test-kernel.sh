#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
# shellcheck disable=SC2016,SC2329 # test_expect_success evaluates the body.

cd "$(dirname "$0")/.." || exit 1
# shellcheck source=testing/test-lib.sh
. ./test-lib.sh
for tool in bash jq python3 sha256sum zstd; do
	command -v "$tool" >/dev/null 2>&1 || test_skip_all "$tool is required"
done

publisher=$(cd .. && pwd)/.github/scripts/publish-test-kernel.sh
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
export fixture
mkdir "$fixture/bin" "$fixture/source" "$fixture/source/linux"
printf 'VERSION = 7\n' >"$fixture/source/linux/Makefile"
tar -C "$fixture/source" -cf "$fixture/source.tar" linux
zstd -q "$fixture/source.tar" -o "$fixture/kernel-ci-source.tar.zst"

python3 - "$fixture" <<'PY'
import hashlib
import sys
import zipfile
from pathlib import Path

fixture = Path(sys.argv[1])
source_name = "kernel-ci-source.tar.zst"
source = (fixture / source_name).read_bytes()
with zipfile.ZipFile(fixture / "1.zip", "w") as archive:
    archive.writestr(source_name, source)
with zipfile.ZipFile(fixture / "4.zip", "w") as archive:
    archive.writestr(source_name, source + b"different source")

for artifact_id, arch, deb_arch in ((2, "arm64", "arm64"), (3, "x86-64", "amd64")):
    with zipfile.ZipFile(fixture / f"{artifact_id}.zip", "w") as archive:
        archive.writestr(f"7.4/linux-image-7.4_1_{deb_arch}.deb", b"package")
        archive.writestr(
            "7.4/BUILD-INFO",
            f"arch={arch}\n"
            "profile=ci\n"
            f"source_sha256={hashlib.sha256(source).hexdigest()}\n"
            f"producer_commit={'a' * 40}\n"
            f"commit={'b' * 40}\n"
            f"patched_commit={'c' * 40}\n"
            "run_id=42\n"
            "run_attempt=1\n",
        )
PY

cat >"$fixture/bin/gh" <<'SH'
#!/bin/sh
set -eu

case "$1/$2" in
api/repos/shirudo-dev/shirudo/*|release/*) test "$GH_TOKEN" = release-write ;;
*) exit 1 ;;
esac

case "$1/$2" in
api/repos/shirudo-dev/shirudo/actions/runs/42)
	jq -r "$4" <<'JSON'
{"path":".github/workflows/build-kernel-packages.yml","head_branch":"main",
 "head_repository":{"id":1},"repository":{"id":1},"event":"workflow_dispatch",
 "conclusion":"success","head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
 "run_attempt":1}
JSON
	;;
api/repos/shirudo-dev/shirudo/git/matching-refs/tags/test-kernel-42)
	echo '[]' | jq -r "$4"
	;;
api/repos/shirudo-dev/shirudo/actions/runs/42/artifacts?name=*)
	case "${2##*=}" in
	kernel-ci-source)
		case "$MODE" in
		missing-source) echo '{"artifacts":[]}' | jq -r "$4"; exit ;;
		wrong-source) id=4 ;;
		*) id=1 ;;
		esac
		;;
	kernel-packages-arm64-ci) id=2 ;;
	kernel-packages-x86-64-ci) id=3 ;;
	*) exit 1 ;;
	esac
	sum=$(sha256sum "$fixture/$id.zip")
	if [ "$MODE/$id" = bad-checksum/2 ]; then
		sum=$(sha256sum "$fixture/3.zip")
	fi
	printf '{"artifacts":[{"id":%s,"expired":false,"digest":"sha256:%s"}]}\n' \
		"$id" "${sum%% *}" | jq -r "$4"
	;;
api/repos/shirudo-dev/shirudo/actions/artifacts/*/zip)
	id=${2%/zip}
	cat "$fixture/${id##*/}.zip"
	;;
release/view) exit 1 ;;
release/create)
	printf '%s\n' "$@" >"$fixture/write"
	cmp "$fixture/2.zip" kernel-packages-arm64-ci.zip
	cmp "$fixture/3.zip" kernel-packages-x86-64-ci.zip
	cmp "$fixture/kernel-ci-source.tar.zst" kernel-ci-source.tar.zst
	sha256sum --check SHA256SUMS
	;;
*) exit 1 ;;
esac
SH
chmod +x "$fixture/bin/gh"

publish() {
	rm -f "$fixture/write"
	env PATH="$fixture/bin:$PATH" MODE="$1" RUNNER_TEMP="$fixture" \
		GH_TOKEN=release-write RUN_ID=42 \
		bash "$publisher"
}

test_expect_success 'publish the original bundles and matching source as a shirudo prerelease' '
	publish valid &&
	grep -Fx test-kernel-42 "$fixture/write" &&
	grep -Fx shirudo-dev/shirudo "$fixture/write" &&
	grep -Fx aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$fixture/write" &&
	grep -Fx -- --prerelease "$fixture/write"
'

test_expect_success 'refuse a run without a corresponding source artifact' '
	! publish missing-source 2>"$fixture/error" &&
	test ! -e "$fixture/write" &&
	grep -F "lacks a matching kernel-ci-source artifact" "$fixture/error"
'

test_expect_success 'refuse a source artifact that disagrees with the bundle metadata' '
	! publish wrong-source 2>"$fixture/error" &&
	test ! -e "$fixture/write" &&
	grep -F "Source provenance mismatch" "$fixture/error"
'

test_expect_success 'refuse a bundle that fails its Actions checksum' '
	! publish bad-checksum 2>"$fixture/error" &&
	test ! -e "$fixture/write" &&
	grep -F "kernel-packages-arm64-ci.zip: FAILED" "$fixture/error"
'

test_done
