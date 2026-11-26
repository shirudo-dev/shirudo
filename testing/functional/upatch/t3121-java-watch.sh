#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3121 -- the java-watch upatch of upatches/java-watch lists every JVM
# that runs with the Java upatch agents it opened: one started without
# options has none, one started with the installed agent has it, one
# started with a copy of the jar outside the sealed directory has none,
# and a JVM that exits leaves the list. A read takes nothing away.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v java >/dev/null 2>&1 || test_skip_all "no java"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
WATCH=java-watch
AGENT=shirudo-test-java-watch
JAR="$FIXTURES/idle-agent.jar"
SEALED=/run/shirudo-java/$AGENT.jar
WORK=$(mktemp -d)
PIDS=

for f in "$FIXTURES/$WATCH.upatch" "$FIXTURES/$WATCH.unload.upatch" \
	"$FIXTURES/$AGENT.upatch" "$FIXTURES/$AGENT.unload.upatch" "$JAR"; do
	[ -s "$f" ] || test_skip_all "missing fixture $f"
done

restore() {
	for pid in $PIDS; do
		kill "$pid" 2>/dev/null || true
	done
	"$SHIRUDO_BIN" upatch unload "$FIXTURES/$AGENT.unload.upatch" \
		--no-precheck >/dev/null 2>&1 || true
	"$SHIRUDO_BIN" upatch unload "$FIXTURES/$WATCH.unload.upatch" \
		--no-precheck >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap restore EXIT HUP INT TERM

# start_jvm <var> [<java option>...]: run the idle class in a JVM that
# takes no options from the environment, and keep its pid in <var>.
start_jvm() {
	var=$1
	shift
	env -u JAVA_TOOL_OPTIONS -u JDK_JAVA_OPTIONS java "$@" \
		-cp "$JAR" shirudo.test.Idle >/dev/null 2>&1 &
	eval "$var=$!"
	PIDS="$PIDS $!"
}

jvms() {
	"$SHIRUDO_BIN" upatch map "$WATCH" jvms --json --peek 2>/dev/null
}

# jvm_has <pid> <agents>: the list names <pid> with exactly the agent
# jars of the comma-separated <agents>, or none for "-".
jvm_has() {
	jvms | python3 -c '
import json, sys
pid, want = int(sys.argv[1]), sys.argv[2]
d = json.loads(sys.stdin.read())
j = [j for j in d["jvms"] if j["pid"] == pid]
names = sorted(a["name"] for a in j[0]["agents"]) if j else None
want = [] if want == "-" else sorted(want.split(","))
sys.exit(0 if names == want and j[0]["patched"] == bool(want) else 1)
' "$1" "$2"
}

jvm_gone() {
	jvms | python3 -c '
import json, sys
d = json.loads(sys.stdin.read())
sys.exit(1 if [j for j in d["jvms"] if j["pid"] == int(sys.argv[1])] else 0)
' "$1"
}

# A JVM maps libjvm.so and opens its agents before main() runs.
eventually() {
	i=0
	while [ $i -lt 60 ]; do
		"$@" && return 0
		sleep 0.5
		i=$((i + 1))
	done
	return 1
}

test_expect_success 'java-watch loads' '
	"$SHIRUDO_BIN" upatch load "$FIXTURES/$WATCH.upatch" --no-precheck \
		>/dev/null 2>&1 &&
	jvms >"$WORK/empty.json" &&
	python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
assert d[\"schema\"] == 1 and d[\"overflow\"] == 0, d
" "$WORK/empty.json"
'

# Each test runs in a subshell: the JVMs start out here, so that their
# pids outlive it.
start_jvm PLAIN

test_expect_success 'a JVM without options is listed without an agent' '
	eventually jvm_has "$PLAIN" -
'

test_expect_success 'the Java upatch of the agent loads' '
	"$SHIRUDO_BIN" upatch load "$FIXTURES/$AGENT.upatch" --no-precheck \
		>/dev/null 2>&1 &&
	[ -s "$SEALED" ]
'

start_jvm PATCHED "-javaagent:$SEALED"

test_expect_success 'a JVM started with the installed agent is listed with it' '
	eventually jvm_has "$PATCHED" "$AGENT.jar" &&
	jvm_has "$PLAIN" -
'

mkdir "$WORK/shirudo-java"
cp "$JAR" "$WORK/shirudo-java/$AGENT.jar"
start_jvm COPY "-javaagent:$WORK/shirudo-java/$AGENT.jar"

test_expect_success 'an unsealed copy of the agent jar does not count' '
	eventually jvm_has "$COPY" - &&
	sleep 2 &&
	jvm_has "$COPY" -
'

test_expect_success 'a read takes nothing away' '
	"$SHIRUDO_BIN" upatch map "$WATCH" jvms --json >/dev/null 2>&1 &&
	jvm_has "$PATCHED" "$AGENT.jar" &&
	jvm_has "$PLAIN" - &&
	jvms | python3 -c "
import json, sys
d = json.loads(sys.stdin.read())
assert d[\"unpatched\"] >= 2, d
"
'

kill "$PLAIN"
wait "$PLAIN" 2>/dev/null

test_expect_success 'a JVM that exits leaves the list' '
	eventually jvm_gone "$PLAIN" &&
	jvm_has "$PATCHED" "$AGENT.jar"
'

test_expect_success 'java-watch unloads' '
	"$SHIRUDO_BIN" upatch unload "$FIXTURES/$WATCH.unload.upatch" \
		--no-precheck >/dev/null 2>&1 &&
	[ ! -e "/run/shirudo/bpffs/upatches/$WATCH" ]
'

test_done
