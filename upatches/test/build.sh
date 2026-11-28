#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build badDecoder.jar and deserialRead.jar, the programs that show
# whether the java-base64 and the java-deserial guards are in a JVM:
#   upatches/test/build.sh
#   java -jar upatches/test/badDecoder.jar
#   java -jar upatches/test/deserialRead.jar
#
# Needs javac and jar on PATH. badDecoder.jar runs on a JRE of release
# 17 or newer, which is all a test VM has, and deserialRead.jar on one
# of release 9 or newer.

set -eu

cd "$(dirname "$0")"
rm -rf target
mkdir -p target
javac --release 17 -d target/bad-decoder BadDecoder.java
jar cfe badDecoder.jar BadDecoder -C target/bad-decoder .
javac --release 9 -Xlint:-options -d target/deserial-read DeserialRead.java gadget/InvokerTransformer.java
jar cfe deserialRead.jar DeserialRead -C target/deserial-read .
