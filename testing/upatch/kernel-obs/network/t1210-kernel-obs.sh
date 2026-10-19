#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=kernel-obs
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME/link_0"
TABLES="exec net listen watch dns priv file"
WORK=$(mktemp -d)

cleanup()
{
	if [ -e "$PIN" ] || [ -e "/run/shirudo/bpffs/upatches/$NAME/link" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -f "/var/lib/shirudo/upatches/$NAME.upatch"
	rm -rf "$WORK"
}
trap cleanup EXIT

[ -s "$LOAD" ] || test_skip_all "missing kernel-obs fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing kernel-obs unload fixture"

export_maps()
{
	output="$1"
	for map in $TABLES watch_stat; do
		"$SHIRUDO_BIN" upatch map "$NAME" "$map" \
			--json="$output" >/dev/null
	done
}

load_observability()
{
	if "$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck --report=- \
		>"$WORK/load.log" 2>&1; then
		return 0
	fi
	cat "$WORK/load.log" >&2
	if [ -d /mnt/shirudo-out ]; then
		cp "$WORK/load.log" /mnt/shirudo-out/kernel-obs-load.log
	fi
	return 1
}

cat >"$WORK/check.py" <<'PY'
import json
import sys

documents = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
records = [document for document in documents
           if isinstance(document, dict) and "map" in document]
metrics = [document for document in documents if isinstance(document, list)]
expected = {"exec", "net", "listen", "watch", "dns", "priv", "file"}
assert {record["map"] for record in records} == expected, documents
assert len(metrics) == 1, documents
assert metrics[0][0]["name"] == "kernel_obs.watch_attempts", metrics
for record in records:
    assert record["schema"] == 2, record
    assert record["upatch"] == "kernel-obs", record
    assert isinstance(record["records"], list), record
    interval = record["interval"]
    assert isinstance(interval, dict), record
    for key in ("used", "overflow", "lost"):
        assert isinstance(interval[key], int), record
    assert interval["overflow"] == 0, record
    assert interval["lost"] == 0, record
    for item in record["records"]:
        assert isinstance(item["first_seen_unix_nano"], str), item
        assert isinstance(item["last_seen_unix_nano"], str), item
        assert int(item["first_seen_unix_nano"]) > 0, item
PY

cat >"$WORK/check_events.py" <<'PY'
import json
import sys

documents = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
tables = {record["map"]: record["records"] for record in documents
          if isinstance(record, dict)}
exec_ids = {(r["executable"]["dev"], r["executable"]["ino"])
            for r in tables["exec"]}
assert any(r["name"] == "true" and r["path"].endswith("/true")
           for r in tables["exec"]), tables["exec"]
assert any("caller" in r for r in tables["exec"]), tables["exec"]
assert any(r["caller_inferred"] and "caller" in r
           for r in tables["exec"]), tables["exec"]
helper_records = [r for r in tables["exec"]
                  if r["path"].endswith("/kernel-obs/exec/exec-paths")]
helper = next(r for r in helper_records
              if (r.get("caller", {}).get("dev"),
                  r.get("caller", {}).get("ino")) !=
              (r["executable"]["dev"], r["executable"]["ino"]))
helper_id = (helper["executable"]["dev"], helper["executable"]["ino"])
self_exec = [r for r in tables["exec"]
             if (r["executable"]["dev"], r["executable"]["ino"]) == helper_id
             and (r.get("caller", {}).get("dev"),
                  r.get("caller", {}).get("ino")) == helper_id]
assert sum(int(r["exec_count"]) for r in self_exec) == 5, self_exec
assert all(not r["caller_inferred"] and "caller" in r
           for r in self_exec), self_exec
assert any(r["uid"] == 0 and r["euid"] == 0 and
           int(r["cap_effective"]) > 0 for r in self_exec), self_exec
replace_exec = [r for r in tables["exec"]
                if r["path"].endswith("/true") and
                (r.get("caller", {}).get("dev"),
                 r.get("caller", {}).get("ino")) == helper_id]
assert replace_exec and any(r["pid"] == helper["pid"]
                             for r in replace_exec), (helper, replace_exec)
for method in ("execveat-empty", "fexecve"):
    fd_exec = [r for r in tables["exec"]
               if r["path"].endswith(f"/true-{method}") and
               (r.get("caller", {}).get("dev"),
                r.get("caller", {}).get("ino")) == helper_id]
    assert len(fd_exec) == 1 and int(fd_exec[0]["exec_count"]) == 1, fd_exec
dirfd_exec = [r for r in tables["exec"]
              if r["path"].endswith("/true-execveat-dirfd") and
              (r.get("caller", {}).get("dev"),
               r.get("caller", {}).get("ino")) == helper_id]
assert len(dirfd_exec) == 1 and int(dirfd_exec[0]["exec_count"]) == 1, dirfd_exec
drop_euid_exec = [r for r in tables["exec"]
                  if r["path"].endswith("/true-drop-euid") and
                  (r.get("caller", {}).get("dev"),
                   r.get("caller", {}).get("ino")) == helper_id]
assert len(drop_euid_exec) == 1, drop_euid_exec
assert (drop_euid_exec[0]["uid"] == 65534 and
        drop_euid_exec[0]["euid"] == 65534 and
        int(drop_euid_exec[0]["cap_effective"]) == 0), drop_euid_exec
for name in ("exec-script", "exec-script-fd"):
    scripts = [r for r in tables["exec"]
               if r["path"].endswith("/" + name) and
               (r.get("caller", {}).get("dev"),
                r.get("caller", {}).get("ino")) == helper_id]
    assert len(scripts) == 1 and not scripts[0]["interpreter"], scripts
    assert int(scripts[0]["exec_count"]) == 1, scripts
    script_id = (scripts[0]["executable"]["dev"],
                 scripts[0]["executable"]["ino"])
    interpreters = [r for r in tables["exec"]
                    if r["interpreter"] and
                    (r.get("caller", {}).get("dev"),
                     r.get("caller", {}).get("ino")) == script_id and
                    r["pid"] == scripts[0]["pid"]]
    assert len(interpreters) == 1, (scripts, interpreters)
for name in ("net", "dns"):
    assert any((r["executable"]["dev"], r["executable"]["ino"]) in exec_ids
               for r in tables[name]), (name, tables[name])
assert any(r["address"] == "127.0.0.1" and r["proto"] == "tcp" and
           r["role"] == "initiator" and int(r["count"]) >= 1 and
           int(r["tx_packets"]) >= 1 and int(r["rx_packets"]) >= 1
           for r in tables["net"]), tables["net"]
assert any(r["address"] == "127.0.0.1" and r["proto"] == "tcp" and
           r.get("role") == "acceptor" for r in tables["net"]), tables["net"]
assert any(r["address"] == "127.0.0.1" and r["proto"] == "udp" and
           int(r["count"]) >= 1 for r in tables["net"]), tables["net"]
assert any(r["kind"] == "listen" and r["proto"] == "tcp" and
           r["address"] == "127.0.0.1" and r["port"] > 0
           for r in tables["listen"]), tables["listen"]
assert any(r["kind"] == "bind" and r["proto"] == "udp" and
           r["port"] == 35353 for r in tables["listen"]), tables["listen"]
assert any(n["name"] == "example.com"
           for r in tables["dns"] for n in r["names"]), tables["dns"]
long_name = ".".join(["a"] * 127)
assert any(n["name"] == long_name
           for r in tables["dns"] for n in r["names"]), tables["dns"]
assert any(r["address"] == "203.0.113.75" and
           any(n["name"] == "many.example" for n in r["names"])
           for r in tables["dns"]), tables["dns"]
assert any(r["kind"] == "userns_create"
           for r in tables["priv"]), tables["priv"]
assert any(r["kind"] == "mount" and r["name"] == "tmpfs"
           for r in tables["priv"]), tables["priv"]
assert any(r["path"] == "/etc/shadow" and r["mode"] == "r"
           for r in tables["file"]), tables["file"]
assert any(r["path"].endswith("/environ")
           for r in tables["file"]), tables["file"]
PY

cat >"$WORK/check_watch.py" <<'PY'
import json
import sys

documents = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
tables = {record["map"]: record["records"] for record in documents
          if isinstance(record, dict)}
metrics = [document for document in documents if isinstance(document, list)]
assert any(r["address"] == "203.0.113.10" and r["proto"] == "tcp" and
           r["port"] == 80 and int(r["attempts"]) >= 1
           for r in tables["watch"]), tables["watch"]
assert any(r["address"] == "2001:0db8:0000:0000:0000:0000:0000:0010" and
           r["proto"] == "udp" for r in tables["watch"]), tables["watch"]
assert any(r["address"] == "203.0.113.10" and
           r.get("role") == "initiator" for r in tables["net"]), tables["net"]
metric = metrics[0][0]
assert metric["name"] == "kernel_obs.watch_attempts", metric
values = {point["attributes"][0]["value"]["stringValue"]: int(point["asInt"])
          for point in metric["sum"]["dataPoints"]}
assert values["matched"] >= 2, values
assert values["checked"] >= values["matched"], values
PY

cat >"$WORK/check_drained.py" <<'PY'
import json
import sys

documents = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
tables = {record["map"]: record["records"] for record in documents
          if isinstance(record, dict)}
for name in ("listen", "watch", "file"):
    assert not tables[name], (name, tables[name])
# The guest's own resolver traffic may land in the window; the test's
# names must be gone.
test_names = {"example.com", "many.example", ".".join(["a"] * 127)}
assert not any(n["name"] in test_names
               for r in tables["dns"] for n in r["names"]), tables["dns"]
PY

cat >"$WORK/check_exec_only.py" <<'PY'
import json
import sys

documents = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
tables = {record["map"]: record["records"] for record in documents
          if isinstance(record, dict)}
assert tables["exec"], tables
for name in ("listen", "watch", "file"):
    assert not tables[name], (name, tables)
test_names = {"example.com", "many.example", ".".join(["a"] * 127)}
assert not any(n["name"] in test_names
               for r in tables["dns"] for n in r["names"]), tables["dns"]
assert not any(r["kind"] in ("userns_create", "mount")
               for r in tables["priv"]), tables["priv"]
PY

test_expect_success 'kernel-obs upatch loads with seven serializers' '
	load_observability &&
	for map in $TABLES; do
		[ -e "/run/shirudo/bpffs/upatches/$NAME/serializers/$map" ] ||
			exit 1
	done
'

test_expect_success 'exec, net, listen, DNS, privilege and file events produce records' '
	python3 upatch/kernel-obs/network/kernel_obs_events.py all &&
	python3 upatch/kernel-obs/network/kernel_obs_events.py dns-long &&
	python3 upatch/kernel-obs/network/kernel_obs_events.py dns-many &&
	export_maps "$WORK/events.ndjson" &&
	python3 "$WORK/check.py" "$WORK/events.ndjson" &&
	python3 "$WORK/check_events.py" "$WORK/events.ndjson"
'

test_expect_success 'watched destinations are recorded with the metric' '
	python3 upatch/kernel-obs/network/kernel_obs_events.py watch &&
	export_maps "$WORK/watch.ndjson" &&
	python3 "$WORK/check_watch.py" "$WORK/watch.ndjson"
'

test_expect_success 'an export drains the tables' '
	export_maps "$WORK/drained.ndjson" &&
	python3 "$WORK/check_drained.py" "$WORK/drained.ndjson"
'

test_expect_success 'only the touched tables carry records' '
	python3 upatch/kernel-obs/network/kernel_obs_events.py exec &&
	export_maps "$WORK/exec-only.ndjson" &&
	python3 "$WORK/check_exec_only.py" "$WORK/exec-only.ndjson"
'

test_done
