#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Write the CycloneDX SBOM of a prepared runtime image: its dpkg database,
# read from the image without booting it, as trivy rootfs lists it.
#
#   runtime-sbom.sh <runtime image> <sbom.cdx.json>

set -euo pipefail

# shellcheck source=testing/vm/arch.sh
. "$(dirname "${BASH_SOURCE[0]}")/arch.sh"
# shellcheck source=testing/vm/guestfs.sh
. "$(dirname "${BASH_SOURCE[0]}")/guestfs.sh"

die() { printf '[test-vm-sbom] error: %s\n' "$*" >&2; exit 1; }

[[ $# -eq 2 ]] || die "usage: runtime-sbom.sh <runtime image> <sbom.cdx.json>"
IMAGE=$1
SBOM=$2
[[ -s "$IMAGE" ]] || die "runtime image is missing: $IMAGE"
command -v guestfish >/dev/null 2>&1 ||
	die "guestfish is required; install it with: $(test_vm_install_cmd "$(test_vm_pkg libguestfs-tools guestfish)")"
command -v trivy >/dev/null 2>&1 ||
	die "trivy is required: https://trivy.dev/latest/getting-started/installation/"

WORK=$(mktemp -d)
TMP_SBOM="$SBOM.tmp.$$"
trap 'rm -rf -- "$WORK" "$TMP_SBOM"' EXIT
mkdir -p "$WORK/root/etc" "$WORK/root/var/lib/dpkg"

# Trivy tells Ubuntu from Debian by lsb-release and needs no more than the
# release files and dpkg's status to list the packages.
guestfs_setup
guestfs_run guestfish --ro -a "$IMAGE" -i <<EOF ||
download /etc/os-release $WORK/root/etc/os-release
download /etc/lsb-release $WORK/root/etc/lsb-release
download /etc/debian_version $WORK/root/etc/debian_version
download /var/lib/dpkg/status $WORK/root/var/lib/dpkg/status
EOF
	die "cannot read the dpkg database of $IMAGE"

trivy rootfs --format cyclonedx --quiet --output "$TMP_SBOM" \
	"$WORK/root" </dev/null || die "trivy rootfs failed"
mv -f -- "$TMP_SBOM" "$SBOM"
