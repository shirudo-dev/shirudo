#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3114 -- a Java agent upatch: its load installs the jar sealed and
# readable by any user, names it in JAVA_TOOL_OPTIONS and measures a
# java_load; one signed by another key, or relabelled BPF, is refused, as
# a BPF unload directive naming it is; its unload measures a java_unload,
# takes the options out and leaves a jar that is an agent doing nothing.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-java
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
BPF_UNLOAD="$FIXTURES/$NAME.bpf-unload.upatch"
FOREIGN="$FIXTURES/$NAME-foreign.upatch"
JAR=/run/shirudo-java/$NAME.jar
ENV_FILE=/run/environment.d/shirudo.conf
EVENTLOG=/var/lib/shirudo/eventlog
WORK=$(mktemp -d)

for f in "$LOAD" "$UNLOAD" "$BPF_UNLOAD" "$FOREIGN" "$FIXTURES/$NAME.jar"; do
	[ -s "$f" ] || test_skip_all "missing fixture $f"
done

restore() {
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
		>/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap restore EXIT HUP INT TERM

last_event() {
	tail -n 1 "$EVENTLOG" | python3 -c '
import json, sys
r = json.loads(sys.stdin.read())
print(r["type"], r.get("upatch", {}).get("name", ""))'
}

load_report() {
	"$SHIRUDO_BIN" upatch load "$1" --no-precheck --report=- 2>/dev/null |
		report_field category
}

test_expect_success 'load installs the jar sealed and measures a java_load' '
	( umask 077 &&
	  "$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 ) &&
	cmp "$JAR" "$FIXTURES/$NAME.jar" &&
	[ "$(stat -c %a "$JAR")" = 644 ] &&
	[ "$(last_event)" = "java_load $NAME" ] &&
	"$SHIRUDO_BIN" upatch list --json | python3 -c "
import json, sys
u = [x for x in json.load(sys.stdin)[\"upatches\"] if x[\"name\"] == \"$NAME\"]
assert u and u[0][\"loaded\"] and u[0][\"payload_type\"] == \"java\", u
"
'

test_expect_success 'JAVA_TOOL_OPTIONS names the agent' '
	grep -qxF "JAVA_TOOL_OPTIONS=\"\${JAVA_TOOL_OPTIONS:+\$JAVA_TOOL_OPTIONS }-javaagent:$JAR\"" "$ENV_FILE" &&
	[ "$(stat -c %a "$ENV_FILE")" = 644 ] &&
	[ "$(stat -c %a /run/environment.d)" = 755 ]
'

test_expect_success 'a user without privileges reads the jar' '
	setpriv --reuid=65534 --regid=65534 --clear-groups \
		cat "$JAR" >"$WORK/read.jar" &&
	cmp "$WORK/read.jar" "$JAR"
'

test_expect_success 'root cannot change or remove the sealed jar' '
	! sh -c "printf x >>\"$JAR\"" 2>/dev/null &&
	! rm -f "$JAR" 2>/dev/null &&
	cmp "$JAR" "$FIXTURES/$NAME.jar"
'

test_expect_success 'root cannot move the jar directory; the state root stays closed' '
	[ "$(stat -c %a /run/shirudo-java)" = 755 ] &&
	! mv /run/shirudo-java /run/shirudo-java.moved 2>/dev/null &&
	[ -d /run/shirudo-java ] &&
	[ "$(stat -c %a /var/lib/shirudo)" = 700 ]
'

test_expect_success 'status counts the loaded agent as measured and in place' '
	"$SHIRUDO_BIN" status --json >"$WORK/status.json" 2>/dev/null
	python3 - "$WORK/status.json" <<-PY
	import json, sys
	d = json.load(open(sys.argv[1], encoding="utf-8"))
	c = [c for c in d["conditions"] if c["type"] == "UpatchesMeasured"]
	assert c and c[0]["status"] == "OK", c
	u = [u for u in d["upatches_loaded"] if u["name"] == "$NAME"]
	assert u and u[0]["location"] == "java" and u[0]["n_maps"] == 0, u
	PY
'

test_expect_success 'a second load is refused as already_loaded' '
	[ "$(load_report "$LOAD")" = already_loaded ]
'

test_expect_success 'a Java upatch another key signed is refused' '
	[ "$(load_report "$FOREIGN")" = signature_rejected ] &&
	[ ! -e /run/shirudo-java/$NAME-foreign.jar ] &&
	[ ! -e /var/lib/shirudo/upatches/$NAME-foreign.upatch ]
'

# A loader of one instruction over the signature's first bytes passes the
# bounds of a BPF header, so that only the signed type refuses the file.
test_expect_success 'a Java upatch relabelled BPF does not open' '
	python3 -c "
import struct, sys
b = bytearray(open(sys.argv[1], \"rb\").read())
struct.pack_into(\"<II\", b, 304, 360, 8)
struct.pack_into(\"<I\", b, 352, 1)
open(sys.argv[2], \"wb\").write(b)
" "$LOAD" "$WORK/relabelled.upatch" &&
	[ "$(load_report "$WORK/relabelled.upatch")" = parser_rejected ]
'

test_expect_success 'a BPF unload directive that names the agent is refused' '
	[ "$("$SHIRUDO_BIN" upatch unload "$BPF_UNLOAD" --no-precheck \
		--report=- 2>/dev/null | report_field category)" = \
		payload_mismatch ] &&
	cmp "$JAR" "$FIXTURES/$NAME.jar" &&
	[ -e /var/lib/shirudo/upatches/$NAME.upatch ] &&
	[ "$(last_event)" = "java_load $NAME" ]
'

test_expect_success 'unload takes the agent and the options out and measures a java_unload' '
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
		>/dev/null 2>&1 &&
	[ ! -e "$ENV_FILE" ] &&
	[ ! -e /var/lib/shirudo/upatches/$NAME.upatch ] &&
	[ "$(last_event)" = "java_unload $NAME" ]
'

# A user manager started before the unload still names the jar.
test_expect_success 'the jar left behind is an agent that does nothing' '
	[ "$(stat -c %a "$JAR")" = 644 ] &&
	python3 -c "
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
assert z.namelist() == [\"META-INF/MANIFEST.MF\", \"shirudo/Unloaded.class\"]
assert b\"Premain-Class: shirudo.Unloaded\" in z.read(\"META-INF/MANIFEST.MF\")
" "$JAR" &&
	if command -v java >/dev/null 2>&1; then
		java "-javaagent:$JAR" -version >/dev/null 2>&1
	fi &&
	"$SHIRUDO_BIN" upatch list --json | python3 -c "
import json, sys
assert not [x for x in json.load(sys.stdin)[\"upatches\"] if x[\"name\"] == \"$NAME\"]
"
'

test_done
