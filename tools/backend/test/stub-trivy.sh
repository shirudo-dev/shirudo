#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# test/stub-trivy.sh -- stand in for Trivy in the tests of jobs/sbom-scan.
# It matches nothing against any database. `version` prints the version
# of a made-up database. `sbom <options> <file>` prints the report in
# test/trivy/ named by the SHA-256 of the file, or one without findings
# when there is none, and fails when STUB_TRIVY_FAIL is that SHA-256.
# Each call is appended to the file STUB_TRIVY_LOG names, with the SBOM
# by its name alone, since it lies in a directory of the job's own.

set -eu

reports=$(cd "$(dirname "$0")" && pwd)/trivy

log()
{
	[ -z "${STUB_TRIVY_LOG:-}" ] || printf 'stub-trivy: %s\n' "$*" >>"$STUB_TRIVY_LOG"
}

case "${1:-}" in
version)
	log "$@"
	printf '%s\n' '{"Version":"0.0.0-stub","VulnerabilityDB":{"Version":2,"NextUpdate":"2026-11-11T12:00:00Z","UpdatedAt":"2026-11-11T06:00:00Z","DownloadedAt":"2026-11-11T07:00:00Z"}}' ;;
sbom)
	for file; do :; done
	sha=$(sha256sum "$file" | cut -d ' ' -f 1)
	args=
	for arg; do
		[ "$arg" = "$file" ] && arg=${file##*/}
		args="$args $arg"
	done
	log "${args# }"
	if [ "$sha" = "${STUB_TRIVY_FAIL:-}" ]; then
		echo 'FATAL stub: the scan failed' >&2
		exit 1
	fi
	if [ -f "$reports/$sha.json" ]; then
		cat "$reports/$sha.json"
	else
		printf '%s\n' '{"SchemaVersion":2,"ArtifactType":"cyclonedx","Results":[]}'
	fi ;;
*)
	echo "stub-trivy: no command $*" >&2
	exit 2 ;;
esac
