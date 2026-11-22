#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build the Base64 guard agent jar, then the package into the current
# directory:
#   upatches/java-base64/build.sh [--jar-only] <version> [bpm build options...]
#
# Needs a JDK of release 24 or newer for the Class-File API (javac and
# jar on PATH). The agent carries GuardCheck in a nested guard-check.jar
# that premain appends to the bootstrap loader, so java.util.Base64 can
# call it; the whole agent is one signed Java upatch.

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
mkdir -p target/classes target/stage/com/shirudo/base64guard
javac --release 24 -d target/classes src/com/shirudo/base64guard/*.java
# GuardCheck rides alone in a nested jar for the bootstrap loader.
jar cf target/guard-check.jar -C target/classes com/shirudo/base64guard/GuardCheck.class
cp target/classes/com/shirudo/base64guard/Base64GuardAgent*.class \
	target/stage/com/shirudo/base64guard/
cp target/guard-check.jar target/stage/com/shirudo/base64guard/guard-check.jar
cat > target/MANIFEST.MF <<'MF'
Manifest-Version: 1.0
Premain-Class: com.shirudo.base64guard.Base64GuardAgent
Agent-Class: com.shirudo.base64guard.Base64GuardAgent
Main-Class: com.shirudo.base64guard.Base64GuardAgent
Can-Retransform-Classes: true
MF
jar cfm java-base64.jar target/MANIFEST.MF -C target/stage .

[ "$jar_only" -eq 0 ] || exit 0
cd "$start"
exec shirudo bpm build "$pkg" --version "$version" "$@"
