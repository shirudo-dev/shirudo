#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build the XXE guard agent jar, then the package into the current
# directory:
#   upatches/java-xxe/build.sh [--jar-only] <version> [bpm build options...]
#
# Needs a JDK of release 9 or newer (javac and jar on PATH). The agent,
# XxeGuardAgent, is built for release 8, so that every JVM from that
# release on loads it; XxeGuardAttach, the launcher for a running JVM,
# is built for release 9, the first with the jdk.attach module.

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
rm -rf target
mkdir -p target/classes
javac --release 8 -Xlint:-options -d target/classes src/com/shirudo/xxeguard/XxeGuardAgent.java
javac --release 9 -Xlint:-options -d target/classes src/com/shirudo/xxeguard/XxeGuardAttach.java
cat > target/MANIFEST.MF <<'MF'
Manifest-Version: 1.0
Premain-Class: com.shirudo.xxeguard.XxeGuardAgent
Agent-Class: com.shirudo.xxeguard.XxeGuardAgent
Main-Class: com.shirudo.xxeguard.XxeGuardAttach
MF
jar cfm java-xxe.jar target/MANIFEST.MF -C target/classes .

[ "$jar_only" -eq 0 ] || exit 0
cd "$start"
exec shirudo bpm build "$pkg" --version "$version" "$@"
