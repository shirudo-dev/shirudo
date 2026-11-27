#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build badDecoder.jar, the program that shows whether the java-base64
# guard is in a JVM, and retransform.jar, an agent that has the JVM
# retransform a class without changing it, as a second agent in the JVM
# would:
#   upatches/test/build.sh
#   java -jar upatches/test/badDecoder.jar
#
# Needs javac and jar on PATH. The jars run on a JRE of release 17 or
# newer, which is all a test VM has.

set -eu

cd "$(dirname "$0")"
rm -rf target
mkdir -p target/bad-decoder target/retransform
javac --release 17 -d target/bad-decoder BadDecoder.java
jar cfe badDecoder.jar BadDecoder -C target/bad-decoder .
javac --release 17 -d target/retransform Retransform.java
printf 'Premain-Class: Retransform\nCan-Retransform-Classes: true\n' > target/retransform.mf
jar cfm retransform.jar target/retransform.mf -C target/retransform .
