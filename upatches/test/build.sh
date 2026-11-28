#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build badDecoder.jar and execShell.jar, the programs that show
# whether the java-base64 and the java-exec guards are in a JVM:
#   upatches/test/build.sh
#   java -jar upatches/test/badDecoder.jar
#   java -jar upatches/test/execShell.jar
#
# Needs javac and jar on PATH. badDecoder.jar runs on a JRE of release
# 17 or newer, which is all a test VM has, and execShell.jar on one of
# release 9 or newer.

set -eu

cd "$(dirname "$0")"
rm -rf target
mkdir -p target
javac --release 17 -d target/bad-decoder BadDecoder.java
jar cfe badDecoder.jar BadDecoder -C target/bad-decoder .
javac --release 9 -Xlint:-options -d target/exec-shell ExecShell.java
jar cfe execShell.jar ExecShell -C target/exec-shell .
