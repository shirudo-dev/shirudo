#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import json
from pathlib import Path
import sys


def main():
    path, default_path, requested_path, *tail = sys.argv[1:]
    data = Path(path).read_bytes()
    assert data.endswith(b"\n"), "expected a complete eventlog"
    records = [json.loads(line) for line in data.split(b"\n")[:-1]]
    assert any(r["type"] == "init" for r in records), "missing init record"

    default, requested = (json.loads(Path(p).read_bytes())["tpm"]["eventlog"]
                          for p in (default_path, requested_path))
    for mode, log in (("default", default), ("requested", requested)):
        assert log["present"] is True, mode
        assert log["entries"] == len(records), (mode, log["entries"], len(records))
        assert log["bytes"] == len(data), (mode, log["bytes"], len(data))
    assert "events" not in default, "default status listed eventlog records"

    events = requested["events"]
    assert len(events) == len(records), (len(events), len(records))
    for n, (event, record) in enumerate(zip(events, records), 1):
        for key in ("ts", "type", "digest"):
            assert event[key] == record[key], (n, key, event[key], record[key])
        if record["type"] == "init":
            assert event["set_digest"] == record["set_digest"], (n, "set_digest")
        if "upatch" in record:
            for key in ("name", "payload_sha256"):
                assert event["upatch"][key] == record["upatch"][key], (n, key)

    if tail:
        kind, name, payload = tail
        last = records[-1]
        assert last["type"] == kind, (last["type"], kind)
        assert last["upatch"]["name"] == name, (last["upatch"]["name"], name)
        assert last["upatch"]["payload_sha256"] == payload, (kind, "payload_sha256")


if __name__ == "__main__":
    main()
