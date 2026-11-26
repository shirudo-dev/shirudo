#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# testing/container/run.sh [-v <dir>]... [-e <name>]... -- <command>...
# testing/container/run.sh --image
# -- run a command in the build image, built from the Containerfile beside
# this script unless it exists. The checkout is mounted read-only at its own
# path and each <dir> writable at its own; each named variable of the
# environment is passed on, and the command runs as the caller, in the
# caller's directory. --image prints the image's name.

set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
inputs=("$here/Containerfile" "$here/packages" "$here/install-go.sh"
	"$root/.github/scripts/install-clang.sh"
	"$root/.github/scripts/install-static-libcrypto-deps.sh")
image="shirudo-build:$(cat "${inputs[@]}" | sha256sum | cut -c1-16)"

die()
{
	printf 'testing/container/run.sh: %s\n' "$*" >&2
	exit 1
}

if [[ "${1:-}" == --image ]]; then
	printf '%s\n' "$image"
	exit 0
fi

engine=${CONTAINER:-$(command -v podman || command -v docker || true)}
[[ -n "$engine" ]] ||
	die "podman or docker is required; BUILD_CONTAINER=0 builds on the host"

args=(--rm --init -v "$root:$root:ro" -w "$PWD" -e HOME=/tmp)
# Under sudo, git trusts a repository that SUDO_UID owns; in here it cannot
# tell, and a mounted cache that another user restored, such as the source
# trees of the target dependencies in CI, would be refused.
args+=(-e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory
	-e "GIT_CONFIG_VALUE_0=*")
while [[ $# -gt 0 ]]; do
	case "$1" in
	-v)
		[[ $# -ge 2 && "$2" == /* ]] || die "-v takes an absolute directory"
		args+=(-v "$2:$2")
		shift 2
		;;
	-e)
		[[ $# -ge 2 ]] || die "-e takes the name of a variable"
		args+=(-e "$2")
		shift 2
		;;
	--)
		shift
		break
		;;
	*)
		die "usage: $0 [-v <dir>]... [-e <name>]... -- <command>..."
		;;
	esac
done
[[ $# -gt 0 ]] || die "no command to run"

# Rootless podman maps the caller to root in the container unless told to
# keep the caller's IDs, and cannot raise the memory lock limit shirudo
# needs beyond the caller's.
if [[ "$(basename "$engine")" == podman* &&
      "$("$engine" info --format '{{.Host.Security.Rootless}}' 2>/dev/null)" == true ]]; then
	args+=(--userns=keep-id)
else
	args+=(--user "$(id -u):$(id -g)" --ulimit memlock=-1:-1)
fi

if ! "$engine" image inspect "$image" >/dev/null 2>&1; then
	# One lock per user: under fs.protected_regular, nobody but its owner,
	# root included, can open for writing a file someone else made in /tmp.
	exec 9>"${TMPDIR:-/tmp}/shirudo-build-image-$(id -u).lock"
	flock 9
	if ! "$engine" image inspect "$image" >/dev/null 2>&1; then
		ctx=$(mktemp -d)
		trap 'rm -rf "$ctx"' EXIT
		cp "${inputs[@]}" "$ctx/"
		printf '[build-image] building %s\n' "$image" >&2
		# Registries and mirrors answer 5xx now and then, and a retry
		# starts from the layers already built.
		for attempt in 1 2 3; do
			"$engine" build -q -t "$image" -f "$ctx/Containerfile" "$ctx" \
				>/dev/null && break
			[[ "$attempt" -lt 3 ]] || die "could not build $image"
			printf '[build-image] build failed; retrying in %ss\n' \
				$((attempt * 15)) >&2
			sleep $((attempt * 15))
		done
		rm -rf "$ctx"
		trap - EXIT
	fi
	exec 9>&-
fi
exec "$engine" run "${args[@]}" "$image" "$@"
