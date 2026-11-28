#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build the exec guard agent jar with Maven, then the package into the
# current directory:
#   upatches/java-exec/build.sh [--jar-only] <version> [bpm build options...]
#
# Needs Maven and a JDK of release 9 or newer on PATH, and fetches Byte
# Buddy on first use. The agent is built for release 8, so it loads on a
# JVM of release 8. Byte Buddy inlines the check into ProcessBuilder, and
# the check uses java.base classes alone, so the agent appends nothing to
# the bootstrap loader; the whole agent is one signed Java upatch.

set -eu

# With a CDPATH of the caller, cd could pick another directory.
unset CDPATH

jar_only=0
if [ "${1:-}" = --jar-only ]; then jar_only=1; shift; fi
if [ "$jar_only" -eq 0 ]; then
	[ $# -ge 1 ] || { echo "usage: $0 [--jar-only] <version> [bpm build options...]" >&2; exit 2; }
	version=$1
	shift
fi
pkg=$(cd "$(dirname "$0")" && pwd)
start=$PWD

cd "$pkg"
mvn -q -DskipTests clean package
cp target/shirudo-exec-agent-1.0-SNAPSHOT.jar java-exec.jar

[ "$jar_only" -eq 0 ] || exit 0
cd "$start"
exec shirudo bpm build "$pkg" --version "$version" "$@"
