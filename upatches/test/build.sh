#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build badDecoder.jar and xxeRead.jar, the programs that show whether
# the java-base64 guard is in a JVM and whether the property the java-xxe
# guard sets holds in one:
#   upatches/test/build.sh
#   java -jar upatches/test/badDecoder.jar
#   java -jar upatches/test/xxeRead.jar
#
# Needs javac and jar on PATH. badDecoder.jar runs on a JRE of release 17
# or newer, which is all a test VM has; xxeRead.jar on one of release 8
# or newer, as the guard it checks does.

set -eu

cd "$(dirname "$0")"
rm -rf target
mkdir -p target/bad-decoder target/xxe-read
javac --release 17 -d target/bad-decoder BadDecoder.java
jar cfe badDecoder.jar BadDecoder -C target/bad-decoder .
javac --release 8 -Xlint:-options -d target/xxe-read XxeRead.java
jar cfe xxeRead.jar XxeRead -C target/xxe-read .
