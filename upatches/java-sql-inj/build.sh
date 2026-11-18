#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build the agent and the application with Maven, then the package into
# the current directory:
#   upatches/java-sql-inj/build.sh <version> [bpm build options...]

set -eu

[ $# -ge 1 ] || { echo "usage: $0 <version> [bpm build options...]" >&2; exit 2; }
version=$1
shift
pkg=$(cd "$(dirname "$0")" && pwd)

(
	cd "$pkg"
	mvn -q -DskipTests package
	cp agent/target/shirudo-sqli-agent-1.0-SNAPSHOT.jar java-sql-inj.jar
	cp app/target/shirudo-sqli-app-1.0-SNAPSHOT.jar vulnerable-app.jar
)
exec shirudo bpm build "$pkg" --version "$version" "$@"
