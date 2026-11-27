#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build badDecoder.jar and xmlDecode.jar, the programs that show whether
# the java-base64 and the java-xmldecoder guards are in a JVM:
#   upatches/test/build.sh
#   java -jar upatches/test/badDecoder.jar
#   java -jar upatches/test/xmlDecode.jar
#
# Needs javac and jar on PATH. badDecoder.jar runs on a JRE of release 17
# or newer, which is all a test VM has. xmlDecode.jar is built for release
# 8, so that it runs in the JVMs of release 8 and 11 that the
# java-xmldecoder agent reaches too.

set -eu

# With a CDPATH of the caller, cd could pick another directory.
unset CDPATH

cd "$(dirname "$0")"
rm -rf target
mkdir -p target
javac --release 17 -d target/bad-decoder BadDecoder.java
jar cfe badDecoder.jar BadDecoder -C target/bad-decoder .
javac --release 8 -Xlint:-options -d target/xml-decode XmlDecode.java
jar cfe xmlDecode.jar XmlDecode -C target/xml-decode .
