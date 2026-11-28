#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build badDecoder.jar and jndiLookup.jar, the programs that show
# whether the java-base64 and the java-jndi guards are in a JVM:
#   upatches/test/build.sh
#   java -jar upatches/test/badDecoder.jar
#   java -jar upatches/test/jndiLookup.jar
#
# Needs javac and jar on PATH. The jar runs on a JRE of release 17 or
# newer, which is all a test VM has.

set -eu

cd "$(dirname "$0")"
rm -rf target
mkdir -p target
javac --release 17 -d target/bad-decoder BadDecoder.java
jar cfe badDecoder.jar BadDecoder -C target/bad-decoder .
javac --release 17 -d target/jndi-lookup JndiLookup.java
jar cfe jndiLookup.jar JndiLookup -C target/jndi-lookup .
