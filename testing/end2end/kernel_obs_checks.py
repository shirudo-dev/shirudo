#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import json
import sys

from snapshots import read_documents, tables_from


def t9101_check(argv):
    documents = read_documents(argv[1])
    records = [document for document in documents
               if isinstance(document, dict) and "map" in document]
    metrics = [document for document in documents if isinstance(document, list)]
    expected = {"exec", "net", "socket", "listen", "watch", "dns", "priv", "file"}
    assert {record["map"] for record in records} == expected, documents
    assert len(metrics) == 1, documents
    assert metrics[0][0]["name"] == "kernel_obs.watch_attempts", metrics
    for record in records:
        for item in record["records"]:
            assert isinstance(item["first_seen_unix_nano"], str), item
            assert isinstance(item["last_seen_unix_nano"], str), item
            assert int(item["first_seen_unix_nano"]) > 0, item


def t9101_check_events(argv):
    documents = read_documents(argv[1])
    tables = tables_from(documents)
    exec_ids = {(r["executable"]["dev"], r["executable"]["ino"])
                for r in tables["exec"]}
    assert any(r["name"] == "true" and r["path"].endswith("/true")
               for r in tables["exec"]), tables["exec"]
    assert any("caller" in r for r in tables["exec"]), tables["exec"]
    assert any(r["caller_inferred"] and "caller" in r
               for r in tables["exec"]), tables["exec"]
    helper_records = [r for r in tables["exec"]
                      if r["path"].endswith("/end2end/exec-paths")]
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
    assert any(r["path"] == "/etc/shadow" and r["mode"] == "r"
               for r in tables["file"]), tables["file"]
    assert any(r["path"].endswith("/environ")
               for r in tables["file"]), tables["file"]


def t9101_check_watch(argv):
    documents = read_documents(argv[1])
    tables = tables_from(documents)
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


def t9101_check_drained(argv):
    documents = read_documents(argv[1])
    tables = tables_from(documents)
    for name in ("listen", "watch", "file"):
        assert not tables[name], (name, tables[name])
    # The guest's own resolver traffic may land in the window; the test's
    # names must be gone.
    test_names = {"example.com", "many.example", ".".join(["a"] * 127)}
    assert not any(n["name"] in test_names
                   for r in tables["dns"] for n in r["names"]), tables["dns"]


def t9101_check_exec_only(argv):
    documents = read_documents(argv[1])
    tables = tables_from(documents)
    assert tables["exec"], tables
    for name in ("listen", "watch", "file"):
        assert not tables[name], (name, tables)
    test_names = {"example.com", "many.example", ".".join(["a"] * 127)}
    assert not any(n["name"] in test_names
                   for r in tables["dns"] for n in r["names"]), tables["dns"]
    assert not any(r["kind"] in ("userns_create", "mount")
                   for r in tables["priv"]), tables["priv"]


def t9102_check(argv):
    expected = json.load(open(argv[1], encoding="utf-8"))
    documents = read_documents(argv[2])
    tables = tables_from(documents)
    assert set(tables) == {"net", "socket"}, documents
    net = tables["net"]
    sockets = tables["socket"]
    assert any(r["address"] == "127.0.0.1" and r["proto"] == "tcp" and
               r["role"] == "initiator" and int(r["tx_packets"]) >= 1 and
               int(r["rx_packets"]) >= 1 for r in net), net
    assert any(r["address"] == "127.0.0.1" and r["proto"] == "udp" and
               int(r["count"]) >= 1 for r in net), net
    for item in expected["creations"]:
        assert any(r["operation"] == "create" and
                   r["family"] == item["family"] and
                   r["type"] == item["type"] and
                   r["protocol"] == item["protocol"]
                   for r in sockets), (item, sockets)
    for family, operation in ((2, "sendmsg"), (1, "bind"),
                              (16, "sendmsg")):
        assert any(r["family"] == family and r["operation"] == operation
                   for r in sockets), (family, operation, sockets)
    for operation in ("bind", "connect", "listen", "accept", "sendmsg",
                      "recvmsg", "setsockopt", "shutdown", "socketpair"):
        assert any(r["family"] == 1 and r["operation"] == operation
                   for r in sockets), (1, operation, sockets)
    if expected["raw_created"]:
        assert any(r["family"] == 2 and r["type"] == 3 and
                   r["protocol"] == 1 and r["operation"] == "sendmsg"
                   for r in sockets), sockets
    if any(r["family"] == 17 for r in sockets):
        assert any(r["family"] == 17 and
                   r["operation"] in ("setsockopt", "sendmsg")
                   for r in sockets), sockets
    if any(r["family"] == 44 for r in sockets):
        assert any(r["family"] == 44 and
                   r["operation"] in ("bind", "sendmsg")
                   for r in sockets), sockets
    if any(r["family"] == 40 for r in sockets):
        assert any(r["family"] == 40 and r["operation"] in
                   ("bind", "connect", "sendmsg") for r in sockets), sockets
    pass_ids = expected["fd_pass"]
    assert any(r["operation"] == "sendmsg" and
               r["owner"]["known"] and
               r["owner"]["pid"] == pass_ids["owner_pid"] and
               r["actor"]["pid"] == pass_ids["actor_pid"]
               for r in sockets), (pass_ids, sockets)
    for record in documents:
        if isinstance(record, dict):
            for item in record["records"]:
                assert "path" not in item and "payload" not in item, item


def t9104_check(argv):
    records = read_documents(argv[1])
    assert len(records) == 1 and records[0].get("map") == "dns", records
    addresses = {item["address"]: item for item in records[0].get("records", [])}
    for address, name in (("203.0.113.10", ".".join(["a"] * 127)),
                          ("203.0.113.75", "many.example")):
        record = addresses.get(address)
        assert record is not None, records
        assert any(item["name"] == name for item in record["names"]), record


def t9104_check_empty(argv):
    records = read_documents(argv[1])
    assert len(records) == 1 and records[0].get("map") == "dns", records
    assert records[0].get("records") == [], records


CHECKS = {
    "t9101_check": t9101_check,
    "t9101_check_events": t9101_check_events,
    "t9101_check_watch": t9101_check_watch,
    "t9101_check_drained": t9101_check_drained,
    "t9101_check_exec_only": t9101_check_exec_only,
    "t9102_check": t9102_check,
    "t9104_check": t9104_check,
    "t9104_check_empty": t9104_check_empty,
}


if __name__ == "__main__":
    CHECKS[sys.argv[1]]([sys.argv[0]] + sys.argv[2:])
