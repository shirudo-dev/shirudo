// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// The nodes as the backend's shirudo.node_status judges them, and their
// roll-up by the image they booted.

/** node_status.status, worst first in STATUS_RANK. */
export type NodeStatus = "unhealthy" | "stale" | "healthy";
export type Trust = "untrusted" | "enrolled";
export type LabelsBy = "ak_name" | "node_id" | "config_root" | "none";

export const STATUS_RANK: Record<NodeStatus, number> = { unhealthy: 0, stale: 1, healthy: 2 };
export const STATUSES = ["unhealthy", "stale", "healthy"] as const;
export const TRUSTS = ["untrusted", "enrolled"] as const;
export const LABELS_BY = ["ak_name", "node_id", "config_root", "none"] as const;

export type Shields = {
  /** Upatches loaded that shield a finding of the node. */
  applied: number;
  /** Upatches published for a finding the node has not reached yet. */
  pending: number;
  /** Upatches published for a finding that do nothing on the node. */
  idle: number;
};

export type FleetNode = {
  name: string;
  akName: string;
  hostName: string;
  status: NodeStatus;
  trust: Trust;
  /** 0 when every check passed, 2 for stale, 3 to 7 for unhealthy. */
  failedCheck: number;
  /** One line per check, in order. */
  log: string[];
  lastSeen: Date;
  kernel: string;
  version: string;
  imageId: string | null;
  imageVersion: string | null;
  tree: { generation: number | null; lastSeq: number | null; headSeq: number | null };
  loaded: number;
  shields: Shields;
  /** Findings no loaded upatch shields. */
  exposed: number;
  /** Findings the backend cannot place: no image, no SBOM. */
  unknown: number;
  /** What jobs/labels-put gave the node, not its own node.labels. */
  labels: Record<string, string>;
  /** The name the labels were put under. */
  labelsBy: LabelsBy;
};

export type FleetReport = {
  /** When node_status was last computed. */
  generatedAt: Date;
  nodes: FleetNode[];
};

export type ImageGroup = {
  /** Image id and version, the drill-down query. */
  key: string;
  imageId: string | null;
  imageVersion: string | null;
  nodes: number;
  statuses: Record<NodeStatus, number>;
  /** The worst member's status. */
  status: NodeStatus;
  health: number;
  /** Shared by every member, null when members differ. */
  kernel: string | null;
  tree: { minLastSeq: number | null; headSeq: number | null };
  shields: Shields;
  /** Exposed findings of the worst member. */
  exposed: number;
  unknown: number;
  /** The members' role labels, each once; "?" for a member without one. */
  roles: string[];
  lastSeen: Date;
};

export const NO_IMAGE = "—";

/** key=value, in key order: how the labels show and are searched. */
export const labelPairs = (labels: Record<string, string>) =>
  Object.keys(labels)
    .sort()
    .map((k) => `${k}=${labels[k]}`);

export const imageLabel = (id: string | null, version: string | null) =>
  id === null ? NO_IMAGE : version ? `${id} ${version}` : id;

/** The check a node failed, as its log line names it: "3 reported". */
export function failedCheckName(n: Pick<FleetNode, "failedCheck" | "log">): string {
  if (!n.failedCheck) return "";
  const m = /^(\d+ [a-z]+):/.exec(n.log[n.failedCheck - 1] ?? "");
  return m ? m[1]! : String(n.failedCheck);
}

/** The fleet's scorecard: percent of nodes healthy, null with no nodes. */
export function healthPercent(nodes: readonly Pick<FleetNode, "status">[]): number | null {
  if (!nodes.length) return null;
  return Math.round((100 * nodes.filter((n) => n.status === "healthy").length) / nodes.length);
}

const minOrNull = (xs: (number | null)[]) => {
  const v = xs.filter((x): x is number => x !== null);
  return v.length ? Math.min(...v) : null;
};
const maxOrNull = (xs: (number | null)[]) => {
  const v = xs.filter((x): x is number => x !== null);
  return v.length ? Math.max(...v) : null;
};

export function groupByImage(nodes: readonly FleetNode[]): ImageGroup[] {
  const byImage = new Map<string, FleetNode[]>();
  for (const n of nodes) {
    const key = imageLabel(n.imageId, n.imageVersion);
    byImage.set(key, [...(byImage.get(key) ?? []), n]);
  }
  return [...byImage].map(([key, members]) => {
    const first = members[0]!;
    const statuses: Record<NodeStatus, number> = { unhealthy: 0, stale: 0, healthy: 0 };
    for (const m of members) statuses[m.status]++;
    const sum = (k: keyof Shields) => members.reduce((t, m) => t + m.shields[k], 0);
    return {
      key,
      imageId: first.imageId,
      imageVersion: first.imageVersion,
      nodes: members.length,
      statuses,
      status: members.reduce<NodeStatus>(
        (w, m) => (STATUS_RANK[m.status] < STATUS_RANK[w] ? m.status : w),
        "healthy",
      ),
      health: healthPercent(members) ?? 0,
      kernel: members.every((m) => m.kernel === first.kernel) ? first.kernel : null,
      tree: {
        minLastSeq: minOrNull(members.map((m) => m.tree.lastSeq)),
        headSeq: maxOrNull(members.map((m) => m.tree.headSeq)),
      },
      shields: { applied: sum("applied"), pending: sum("pending"), idle: sum("idle") },
      exposed: Math.max(...members.map((m) => m.exposed)),
      unknown: members.reduce((t, m) => t + m.unknown, 0),
      roles: [...new Set(members.map((m) => m.labels.role ?? "?"))].sort(),
      lastSeen: new Date(Math.max(...members.map((m) => m.lastSeen.getTime()))),
    };
  });
}
