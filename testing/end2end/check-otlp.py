#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import collections
import glob
import json
import os
import sys
import time
import urllib.request

from snapshots import read_documents


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


def collected(path, require_delivery=False):
    delivery_seen = False
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
                        body = value(record["body"])
                        if attrs.get("shirudo.map.name") == "exec":
                            delivery_seen |= any("end2end/exec-paths" in entry.get("path", "")
                                                 for entry in body["records"])
                        logs[key((attrs.get("shirudo.map.name"), log_body(body)))] += 1
            for resource in document.get("resourceMetrics", []):
                for scope in resource.get("scopeMetrics", []):
                    for metric in scope.get("metrics", []):
                        metrics[key(metric_body(metric))] += 1
    if require_delivery:
        assert delivery_seen, "no exec record of the test program in the collector"
    return logs, metrics


def expected(directory):
    paths = sorted(glob.glob(os.path.join(directory, "t910[1-4]-*.ndjson")))
    if not paths:
        raise AssertionError("no t9101-t9104 JSON snapshots")
    logs = collections.Counter()
    metrics = collections.Counter()
    for path in paths:
        for document in read_documents(path):
            if isinstance(document, list):
                for metric in document:
                    metrics[key(metric_body(metric))] += 1
            else:
                logs[key((document["map"], log_body(document)))] += 1
    return logs, metrics


def check(want, got, signal):
    missing = want - got
    if missing:
        sample, count = next(iter(missing.items()))
        raise AssertionError(f"missing {count} {signal} export(s): {sample[:500]}")


def metric_points(metrics):
    points = collections.Counter()
    for encoded, count in metrics.items():
        metric = json.loads(encoded)
        total = metric["sum"]
        for point in total["dataPoints"]:
            attrs = {entry["key"]: value(entry["value"])
                     for entry in point.get("attributes", [])}
            number = point.get("asInt", point.get("asDouble"))
            item = (metric["name"], metric["description"], metric["unit"],
                    attrs["outcome"], int(point["startTimeUnixNano"]) // 10**9,
                    float(number), total["aggregationTemporality"],
                    total["isMonotonic"])
            points[key(item)] += count
    return points


def query(endpoint, sql):
    request = urllib.request.Request(endpoint, data=sql.encode("utf-8"))
    with urllib.request.urlopen(request, timeout=5) as response:
        return [json.loads(line) for line in response]


def clickhouse(endpoint):
    logs = collections.Counter()
    metrics = collections.Counter()
    rows = query(endpoint, """
SELECT LogAttributes['shirudo.map.name'] AS map_name, Body AS body
FROM shirudo.otel_logs
WHERE ServiceName = 'shirudo'
  AND EventName = 'shirudo.bpf.map.snapshot'
  AND LogAttributes['shirudo.upatch.name'] = 'kernel-obs'
FORMAT JSONEachRow
""")
    for row in rows:
        logs[key((row["map_name"], log_body(json.loads(row["body"]))))] += 1
    rows = query(endpoint, """
SELECT MetricName AS name, MetricDescription AS description,
       MetricUnit AS unit, Attributes['outcome'] AS outcome,
       toUnixTimestamp(StartTimeUnix) AS start_time,
       Value AS value, AggregationTemporality AS temporality,
       IsMonotonic AS monotonic
FROM shirudo.otel_metrics_sum
WHERE ServiceName = 'shirudo' AND MetricName = 'kernel_obs.watch_attempts'
FORMAT JSONEachRow
""")
    for row in rows:
        item = (row["name"], row["description"], row["unit"],
                row["outcome"], row["start_time"], float(row["value"]),
                row["temporality"], bool(row["monotonic"]))
        metrics[key(item)] += 1
    return logs, metrics


def check_clickhouse(endpoint, want_logs, want_metrics, got_logs, got_metrics):
    want_points = metric_points(want_metrics)
    got_points = metric_points(got_metrics)
    deadline = time.monotonic() + 20
    while True:
        db_logs, db_points = clickhouse(endpoint)
        if db_logs == got_logs and db_points == got_points:
            check(want_logs, db_logs, "ClickHouse log")
            check(want_points, db_points, "ClickHouse metric point")
            print(f"verified {sum(db_logs.values())} logs and "
                  f"{sum(db_points.values())} metric points in ClickHouse")
            return
        if time.monotonic() >= deadline:
            check(got_logs, db_logs, "ClickHouse log")
            check(got_points, db_points, "ClickHouse metric point")
            check(db_logs, got_logs, "collector log")
            check(db_points, got_points, "collector metric point")
        time.sleep(0.5)


def main():
    want_logs, want_metrics = expected(sys.argv[1])
    got_logs, got_metrics = collected(sys.argv[2], require_delivery=True)
    check(want_logs, got_logs, "log")
    check(want_metrics, got_metrics, "metric")
    print(f"verified {sum(want_logs.values())} map logs and "
          f"{sum(want_metrics.values())} metrics in the collector")
    if len(sys.argv) > 3:
        check_clickhouse(sys.argv[3], want_logs, want_metrics,
                         got_logs, got_metrics)


if __name__ == "__main__":
    main()
