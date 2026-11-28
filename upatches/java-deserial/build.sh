#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build the deserialization guard agent jar, then the package into the
# current directory:
#   upatches/java-deserial/build.sh [--jar-only] <version> [bpm build options...]
#
# Needs a JDK of release 9 or newer (javac and jar on PATH). The guard
# uses only java.io.ObjectInputFilter and rewrites no bytecode, so the
# installer is built for release 9. DeserialGuardAgent, the premain, is
# built for release 8, so that an older JVM loads it and starts without
# the guard rather than failing to start.

set -eu

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
javac --release 8 -Xlint:-options -d target/classes src/com/shirudo/deserialguard/DeserialGuardAgent.java
javac --release 9 -Xlint:-options -cp target/classes -d target/classes \
	src/com/shirudo/deserialguard/DeserialGuardInstaller.java
cat > target/MANIFEST.MF <<'MF'
Manifest-Version: 1.0
Premain-Class: com.shirudo.deserialguard.DeserialGuardAgent
Agent-Class: com.shirudo.deserialguard.DeserialGuardAgent
Main-Class: com.shirudo.deserialguard.DeserialGuardInstaller
MF
jar cfm java-deserial.jar target/MANIFEST.MF -C target/classes .

[ "$jar_only" -eq 0 ] || exit 0
cd "$start"
exec shirudo bpm build "$pkg" --version "$version" "$@"
