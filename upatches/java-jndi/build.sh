#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build the JNDI guard agent jar, then the package into the current
# directory:
#   upatches/java-jndi/build.sh [--jar-only] <version> [bpm build options...]
#
# Needs a JDK of release 24 or newer for the Class-File API (javac and
# jar on PATH). The agent carries JndiCheck in a nested jndi-check.jar
# that premain appends to the bootstrap loader, so javax.naming can call
# it; the whole agent is one signed Java upatch. JndiGuardAgent, the
# premain, is built for release 8, so that an older JVM loads it and
# starts without the guard rather than failing to start.

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
mkdir -p target/classes target/stage/com/shirudo/jndiguard
javac --release 8 -Xlint:-options -d target/classes src/com/shirudo/jndiguard/JndiGuardAgent.java
javac --release 24 -cp target/classes -d target/classes \
	src/com/shirudo/jndiguard/JndiCheck.java src/com/shirudo/jndiguard/JndiGuardInstaller.java
# JndiCheck rides alone in a nested jar for the bootstrap loader.
jar cf target/jndi-check.jar -C target/classes com/shirudo/jndiguard/JndiCheck.class
cp target/classes/com/shirudo/jndiguard/JndiGuard*.class \
	target/stage/com/shirudo/jndiguard/
cp target/jndi-check.jar target/stage/com/shirudo/jndiguard/jndi-check.jar
cat > target/MANIFEST.MF <<'MF'
Manifest-Version: 1.0
Premain-Class: com.shirudo.jndiguard.JndiGuardAgent
Agent-Class: com.shirudo.jndiguard.JndiGuardAgent
Main-Class: com.shirudo.jndiguard.JndiGuardInstaller
Can-Retransform-Classes: true
MF
jar cfm java-jndi.jar target/MANIFEST.MF -C target/stage .

[ "$jar_only" -eq 0 ] || exit 0
cd "$start"
exec shirudo bpm build "$pkg" --version "$version" "$@"
