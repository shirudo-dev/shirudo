// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// What the views ask of the backend, and the client that asks ClickHouse.

import NODES_SQL from "../../sql/nodes.sql" with { type: "text" };
import { queryRows, type ClickHouseConfig } from "./clickhouse.ts";
import { STATUSES, TRUSTS, type FleetNode, type FleetReport, type NodeStatus, type Trust } from "./fleet.ts";

export interface Backend {
  /** Every node of shirudo.node_status. */
  getFleet(): Promise<FleetReport>;
}

/** A row of sql/nodes.sql. */
export type NodeRow = {
  node_id: string;
  ak_name: string;
  host_name: string;
  status: string;
  trust: string;
  failed_check: number;
  log: string[];
  last_seen_ms: number;
  updated_ms: number;
  generation: number | null;
  last_seq: number | null;
  head_seq: number | null;
  loaded: number;
  kernel_release: string;
  version_id: string;
  image_id: string | null;
  image_version: string | null;
  shields_applied: number;
  shields_pending: number;
  shields_idle: number;
  exposed: number;
  unknown: number;
};

function oneOf<T extends string>(allowed: readonly T[], value: string, what: string): T {
  if (!(allowed as readonly string[]).includes(value)) throw new Error(`unknown ${what} "${value}"`);
  return value as T;
}

export function toFleetNode(r: NodeRow): FleetNode {
  return {
    name: r.node_id,
    akName: r.ak_name,
    hostName: r.host_name,
    status: oneOf<NodeStatus>(STATUSES, r.status, "status"),
    trust: oneOf<Trust>(TRUSTS, r.trust, "trust"),
    failedCheck: r.failed_check,
    log: r.log,
    lastSeen: new Date(r.last_seen_ms),
    kernel: r.kernel_release,
    version: r.version_id,
    // A node the backend has no record for joins as an empty string.
    imageId: r.image_id || null,
    imageVersion: r.image_version || null,
    tree: { generation: r.generation, lastSeq: r.last_seq, headSeq: r.head_seq },
    loaded: r.loaded,
    shields: { applied: r.shields_applied, pending: r.shields_pending, idle: r.shields_idle },
    exposed: r.exposed,
    unknown: r.unknown,
  };
}

export function toFleetReport(rows: readonly NodeRow[]): FleetReport {
  const updated = Math.max(0, ...rows.map((r) => r.updated_ms));
  return { generatedAt: updated ? new Date(updated) : new Date(), nodes: rows.map(toFleetNode) };
}

export class ClickHouseBackend implements Backend {
  constructor(private readonly cfg: ClickHouseConfig) {}

  async getFleet(): Promise<FleetReport> {
    return toFleetReport(await queryRows<NodeRow>(this.cfg, NODES_SQL));
  }
}
