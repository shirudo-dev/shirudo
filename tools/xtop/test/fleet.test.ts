// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Rows shaped like those of sql/nodes.sql in
// tools/backend/test/xtop-nodes.expected, turned into nodes and rolled up
// by image.

import { describe, expect, test } from "bun:test";
import { toFleetNode, toFleetReport, type NodeRow } from "../src/lib/backend.ts";
import { configFromEnv, queryRows } from "../src/lib/clickhouse.ts";
import { failedCheckName, groupByImage, healthPercent, imageLabel, labelPairs } from "../src/lib/fleet.ts";

const BUILD = "d6d918ad22ff597579e6678bef75adca84d30f9661e0b7bbdbf534eebc138c1f";
const LOG = [
  "1 signed: pass, untrusted, 0 rejected in the last hour",
  "2 fresh: pass, last record 12 s ago",
  "3 reported: pass, verdict ok, cond 0x1555, flags 0, tamper +0, build d6d918ad",
  "4 chain: pass, root 15452248",
  "5 head: pass, seq 3 of 3, generation 3",
  "6 set: pass, 1 loaded",
  "7 peers: pass, 2 in group",
];

function row(over: Partial<NodeRow>): NodeRow {
  return {
    node_id: "node-a",
    ak_name: "000b23602ab98bfb",
    host_name: "edge-01",
    status: "healthy",
    trust: "untrusted",
    failed_check: 0,
    log: LOG,
    last_seen_ms: 1_795_000_000_000,
    updated_ms: 1_795_000_030_000,
    generation: 3,
    last_seq: 3,
    head_seq: 3,
    loaded: 1,
    kernel_release: "7.4.2",
    version_id: BUILD,
    image_id: "fleet-os",
    image_version: "2026.11.1",
    shields_applied: 1,
    shields_pending: 0,
    shields_idle: 0,
    exposed: 1,
    unknown: 0,
    labels: { role: "edge", site: "fra" },
    label_sources: { role: "node_id", site: "node_id" },
    label_conflicts: [],
    enroll_ek_name: "",
    enroll_source: "",
    enrolled_ms: 0,
    ...over,
  };
}

const ROWS: NodeRow[] = [
  row({}),
  row({
    node_id: "node-b",
    ak_name: "000b9d72e08380a1",
    host_name: "core-01",
    loaded: 0,
    shields_applied: 0,
    shields_idle: 1,
    exposed: 2,
    labels: { role: "core" },
    label_sources: { role: "ak_name" },
  }),
  row({
    node_id: "node-c",
    ak_name: "000b0c",
    host_name: "lab-01",
    generation: null,
    last_seq: null,
    head_seq: null,
    loaded: 0,
    kernel_release: "7.5.1",
    image_id: null,
    image_version: null,
    shields_applied: 0,
    exposed: 0,
    unknown: 1,
    labels: {},
    label_sources: {},
  }),
  row({
    node_id: "node-d",
    ak_name: "000b0d",
    host_name: "edge-02",
    status: "unhealthy",
    failed_check: 3,
    log: LOG.map((l, i) => (i === 2 ? "3 reported: FAIL, verdict degraded, cond 0x1555, flags 0, tamper +0, build d6d918ad" : l)),
  }),
  row({ labels: {}, label_sources: {}, node_id: "node-e", ak_name: "000b0e", host_name: "core-02", status: "stale", failed_check: 2, last_seq: 2, loaded: 0, shields_applied: 0, shields_idle: 1, exposed: 2 }),
];

describe("toFleetNode", () => {
  test("maps every column", () => {
    const n = toFleetNode(ROWS[0]!);
    expect(n.name).toBe("node-a");
    expect(n.hostName).toBe("edge-01");
    expect(n.status).toBe("healthy");
    expect(n.trust).toBe("untrusted");
    expect(n.lastSeen.getTime()).toBe(1_795_000_000_000);
    expect(n.tree).toEqual({ generation: 3, lastSeq: 3, headSeq: 3 });
    expect(n.shields).toEqual({ applied: 1, pending: 0, idle: 0 });
    expect(n.version).toBe(BUILD);
  });

  test("a node with no image or tree keeps its nulls", () => {
    const n = toFleetNode(ROWS[2]!);
    expect(n.imageId).toBeNull();
    expect(n.tree.lastSeq).toBeNull();
    expect(imageLabel(n.imageId, n.imageVersion)).toBe("—");
  });

  test("an empty image from a missing join reads as none", () => {
    expect(toFleetNode(row({ image_id: "", image_version: "" })).imageId).toBeNull();
  });

  test("keeps the labels the operator put", () => {
    expect(toFleetNode(ROWS[0]!).labels).toEqual({ role: "edge", site: "fra" });
    expect(toFleetNode(ROWS[0]!).labelSources).toEqual({ role: "node_id", site: "node_id" });
    expect(toFleetNode(ROWS[2]!).labels).toEqual({});
    expect(() => toFleetNode(row({ label_sources: { role: "host_name" } }))).toThrow(/unknown label source/);
  });

  test("keeps the keys whose sets disagree", () => {
    const n = toFleetNode(
      row({
        labels: { image: "base", role: "edge", site: "fra" },
        label_sources: { image: "config_root", role: "node_id", site: "node_id" },
        label_conflicts: [
          [
            "role",
            "edge",
            "node_id",
            [
              [2, "node_id", "edge"],
              [1, "config_root", "lab"],
            ],
          ],
        ],
      }),
    );
    expect(n.labelConflicts).toEqual([
      {
        key: "role",
        value: "edge",
        by: "node_id",
        given: [
          { by: "node_id", value: "edge" },
          { by: "config_root", value: "lab" },
        ],
      },
    ]);
  });

  test("keeps the builder's record of an enrolled key", () => {
    const ek = `000b${"e".repeat(64)}`;
    const n = toFleetNode(
      row({ trust: "enrolled", enroll_ek_name: ek, enroll_source: "vm-host-1", enrolled_ms: 1_793_527_200_000 }),
    );
    expect(n.enrollment).toEqual({ ekName: ek, source: "vm-host-1", at: new Date(1_793_527_200_000) });
    expect(toFleetNode(row({ enroll_source: "vm-host-1", enrolled_ms: 1 })).enrollment?.ekName).toBeNull();
    expect(toFleetNode(ROWS[0]!).enrollment).toBeNull();
  });

  test("refuses a status the view does not know", () => {
    expect(() => toFleetNode(row({ status: "degraded" }))).toThrow(/unknown status/);
    expect(() => toFleetNode(row({ trust: "maybe" }))).toThrow(/unknown trust/);
  });

  test("names the failed check from its log line", () => {
    expect(failedCheckName(toFleetNode(ROWS[3]!))).toBe("3 reported");
    expect(failedCheckName(toFleetNode(ROWS[4]!))).toBe("2 fresh");
    expect(failedCheckName(toFleetNode(ROWS[0]!))).toBe("");
  });
});

describe("health", () => {
  test("is the percent of nodes healthy", () => {
    const nodes = ROWS.map(toFleetNode);
    expect(healthPercent(nodes)).toBe(60);
    expect(healthPercent(nodes.filter((n) => n.status === "healthy"))).toBe(100);
    expect(healthPercent(nodes.filter((n) => n.status !== "healthy"))).toBe(0);
    expect(healthPercent([])).toBeNull();
  });
});

describe("groupByImage", () => {
  const groups = groupByImage(ROWS.map(toFleetNode));
  const fleetOs = groups.find((g) => g.key === "fleet-os 2026.11.1")!;
  const none = groups.find((g) => g.key === "—")!;

  test("groups by image id and version", () => {
    expect(groups.map((g) => g.key).sort()).toEqual(["fleet-os 2026.11.1", "—"]);
    expect(fleetOs.nodes).toBe(4);
    expect(none.nodes).toBe(1);
  });

  test("takes the worst status and the share healthy", () => {
    expect(fleetOs.status).toBe("unhealthy");
    expect(fleetOs.statuses).toEqual({ unhealthy: 1, stale: 1, healthy: 2 });
    expect(fleetOs.health).toBe(50);
    expect(none.status).toBe("healthy");
    expect(none.health).toBe(100);
  });

  test("rolls up kernel, tree, shields and exposure", () => {
    expect(fleetOs.kernel).toBe("7.4.2");
    expect(fleetOs.tree).toEqual({ lastSeq: 2, headSeq: 3 });
    expect(fleetOs.shields).toEqual({ applied: 2, pending: 0, idle: 2 });
    expect(fleetOs.exposed).toBe(2);
    expect(none.tree).toEqual({ lastSeq: null, headSeq: null });
    expect(none.unknown).toBe(1);
  });

  test("rolls up the role labels, ? for a member without one", () => {
    expect(fleetOs.roles).toEqual(["?", "core", "edge"]);
    expect(none.roles).toEqual(["?"]);
  });

  test("reports a mixed kernel as null", () => {
    const mixed = groupByImage([toFleetNode(ROWS[0]!), toFleetNode(row({ ak_name: "x", kernel_release: "7.5.0" }))]);
    expect(mixed[0]!.kernel).toBeNull();
  });

  test("reports the tree of the member furthest behind, never a mixed pair", () => {
    const member = (over: Partial<NodeRow>) => toFleetNode(row({ ...over }));
    // Two members on independent trees, each at its own head: caught up.
    const heads = groupByImage([
      member({ ak_name: "000b001", last_seq: 3, head_seq: 3 }),
      member({ ak_name: "000b002", last_seq: 8, head_seq: 8 }),
    ]);
    expect(heads[0]!.tree).toEqual({ lastSeq: 3, headSeq: 3 });
    // A member a step behind its tree reports its real position.
    const behind = groupByImage([
      member({ ak_name: "000b001", last_seq: 2, head_seq: 3 }),
      member({ ak_name: "000b002", last_seq: 8, head_seq: 8 }),
    ]);
    expect(behind[0]!.tree).toEqual({ lastSeq: 2, headSeq: 3 });
    // A member without a tree does not hide the position of one that has it.
    const mixed = groupByImage([
      member({ ak_name: "000b001", generation: null, last_seq: null, head_seq: null }),
      member({ ak_name: "000b002", last_seq: 5, head_seq: 5 }),
    ]);
    expect(mixed[0]!.tree).toEqual({ lastSeq: 5, headSeq: 5 });
  });
});

describe("toFleetReport", () => {
  test("dates the report by the newest computation", () => {
    expect(toFleetReport(ROWS).generatedAt.getTime()).toBe(1_795_000_030_000);
  });
});

describe("clickhouse", () => {
  test("defaults to the local HTTP interface", () => {
    expect(configFromEnv({}).url.href).toBe("http://127.0.0.1:8123/");
  });

  test("refuses credentials in the URL and other schemes", () => {
    expect(() => configFromEnv({ CLICKHOUSE_URL: "http://u:p@host:8123/" })).toThrow(/credentials/);
    expect(() => configFromEnv({ CLICKHOUSE_URL: "tcp://host:9000" })).toThrow(/http or https/);
  });

  test("posts the query and parses JSONEachRow", async () => {
    let seen: { url: string; init: RequestInit } | null = null;
    const fake = (async (url: URL, init: RequestInit) => {
      seen = { url: String(url), init };
      return new Response('{"a":1}\n{"a":2}\n');
    }) as unknown as typeof fetch;
    const cfg = configFromEnv({ CLICKHOUSE_URL: "http://ch:8123/", CLICKHOUSE_USER: "ro", CLICKHOUSE_PASSWORD: "pw" });
    expect(await queryRows<{ a: number }>(cfg, "SELECT 1", fake)).toEqual([{ a: 1 }, { a: 2 }]);
    expect(seen!.url).toContain("default_format=JSONEachRow");
    expect(seen!.init.body).toBe("SELECT 1");
    expect((seen!.init.headers as Record<string, string>)["X-ClickHouse-User"]).toBe("ro");
  });

  test("turns a ClickHouse error into its first line", async () => {
    const fake = (async () => new Response("Code: 60. DB::Exception: Unknown table\nstack", { status: 404 })) as unknown as typeof fetch;
    await expect(queryRows(configFromEnv({}), "SELECT 1", fake)).rejects.toThrow("404 Code: 60. DB::Exception: Unknown table");
  });
});

describe("labelPairs", () => {
  test("key=value in key order", () => {
    expect(labelPairs({ site: "fra", role: "edge" })).toEqual(["role=edge", "site=fra"]);
    expect(labelPairs({})).toEqual([]);
  });
});
