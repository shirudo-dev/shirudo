#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import collections
import glob
import json
import os
import sys


def value(item):
    if "stringValue" in item:
        return item["stringValue"]
    if "intValue" in item:
        return int(item["intValue"])
    if "doubleValue" in item:
        return item["doubleValue"]
    if "boolValue" in item:
        return item["boolValue"]
    if "arrayValue" in item:
        return [value(entry) for entry in item["arrayValue"].get("values", [])]
    if "kvlistValue" in item:
        return {entry["key"]: value(entry["value"])
                for entry in item["kvlistValue"].get("values", [])}
    if not item:
        return None
    raise ValueError(f"unexpected OTLP value: {item}")


def key(item):
    return json.dumps(item, sort_keys=True, separators=(",", ":"))


def log_body(body):
    since = int(body["interval"]["since_unix_nano"])

    def relative(item):
        if isinstance(item, dict):
            return {name: str(int(value) - since) if name.endswith("_unix_nano")
                    else relative(value) for name, value in item.items()}
        if isinstance(item, list):
            return [relative(value) for value in item]
        return item

    return relative(body)


def metric_body(metric):
    def without_export_time(item):
        if isinstance(item, dict):
            return {name: without_export_time(value)
                    for name, value in item.items() if name != "timeUnixNano"}
        if isinstance(item, list):
            return [without_export_time(value) for value in item]
        return item

    return without_export_time(metric)


def collected(path):
    logs = collections.Counter()
    metrics = collections.Counter()
    with open(path, encoding="utf-8") as stream:
        for line in stream:
            document = json.loads(line)
            for resource in document.get("resourceLogs", []):
                for scope in resource.get("scopeLogs", []):
                    for record in scope.get("logRecords", []):
                        attrs = {entry["key"]: value(entry["value"])
                                 for entry in record.get("attributes", [])}
                        if attrs.get("shirudo.upatch.name") != "kernel-obs":
                            continue
                        logs[key((attrs.get("shirudo.map.name"),
                                  log_body(value(record["body"]))))] += 1
            for resource in document.get("resourceMetrics", []):
                for scope in resource.get("scopeMetrics", []):
                    for metric in scope.get("metrics", []):
                        metrics[key(metric_body(metric))] += 1
    return logs, metrics


def expected(directory):
    paths = sorted(glob.glob(os.path.join(directory, "t910[1-4]-*.ndjson")))
    if not paths:
        raise AssertionError("no t9101-t9104 JSON snapshots")
    logs = collections.Counter()
    metrics = collections.Counter()
    for path in paths:
        with open(path, encoding="utf-8") as stream:
            for line in stream:
                document = json.loads(line)
                if isinstance(document, list):
                    for metric in document:
                        metrics[key(metric_body(metric))] += 1
                else:
                    assert document["upatch"] == "kernel-obs", path
                    logs[key((document["map"], log_body(document)))] += 1
    return logs, metrics


def check(want, got, signal):
    missing = want - got
    if missing:
        sample, count = next(iter(missing.items()))
        raise AssertionError(f"missing {count} {signal} export(s): {sample[:500]}")


def main():
    want_logs, want_metrics = expected(sys.argv[1])
    got_logs, got_metrics = collected(sys.argv[2])
    check(want_logs, got_logs, "log")
    check(want_metrics, got_metrics, "metric")
    print(f"verified {sum(want_logs.values())} map logs and "
          f"{sum(want_metrics.values())} metrics in the collector")


if __name__ == "__main__":
    main()
