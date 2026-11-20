#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build badDecoder.jar, the program that shows whether the java-base64
# guard is in a JVM:
#   upatches/test/build.sh
#   java -jar upatches/test/badDecoder.jar
#
# Needs javac and jar on PATH. The jar runs on a JRE of release 17 or
# newer, which is all a test VM has.

set -eu

cd "$(dirname "$0")"
rm -rf target
mkdir -p target
javac --release 17 -d target BadDecoder.java
jar cfe badDecoder.jar BadDecoder -C target .
