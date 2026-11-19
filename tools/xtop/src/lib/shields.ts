// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// The upatches of every tree the backend has loaded: what each fixes and
// how far its newest operation has rolled out.

/**
 * pending while a node following the tree has not reached the newest
 * operation, deployed once every one has, withdrawn when that operation
 * is a delete.
 */
export type ShieldStatus = "pending" | "deployed" | "withdrawn";

export const SHIELD_STATUS_RANK: Record<ShieldStatus, number> = { pending: 0, deployed: 1, withdrawn: 2 };

/** Worst first; a severity the scanner gave that is not listed sorts last. */
export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

export const severityRank = (s: string) => {
  const i = (SEVERITIES as readonly string[]).indexOf(s.toUpperCase());
  return i < 0 ? SEVERITIES.length : i;
};

export type Advisory = {
  id: string;
  /** Empty when neither kernel_vulns nor sbom_vulns knows the advisory. */
  severity: string;
  package: string;
  source: "kernel" | "sbom" | "";
  /** Nodes affected by it that this upatch shields. */
  shielded: number;
  /** Nodes affected by it that this upatch does not shield yet, or not at all. */
  exposed: number;
};

export type Rollout = {
  /** Nodes following the tree. */
  nodes: number;
  /** Applied the newest operation. */
  applied: number;
  /** Reached it; the selector left them out. */
  notSelected: number;
  /** Reached it; the module it attaches to is not loaded. */
  noTarget: number;
  /** Have not reached it. */
  pending: number;
};

export type Shield = {
  treeId: string;
  id: string;
  /** The newest operation of the upatch. */
  seq: number;
  op: "add" | "delete";
  /** The newest add, whose fixes the advisories are; 0 when there is none. */
  addSeq: number;
  /** Operations of the upatch in the tree. */
  ops: number;
  manifestDigest: string;
  repository: string;
  selector: string;
  /** When the backend first loaded the publication holding the newest operation. */
  publishedAt: Date | null;
  advisories: Advisory[];
  /** Images, as "id version", of the nodes an advisory affects. */
  images: string[];
  rollout: Rollout;
  status: ShieldStatus;
  /** The worst severity of its advisories, "" when none is known. */
  severity: string;
};

export type ShieldsReport = { generatedAt: Date; shields: Shield[] };

export function shieldStatus(op: Shield["op"], rollout: Rollout): ShieldStatus {
  if (op === "delete") return "withdrawn";
  return rollout.pending ? "pending" : "deployed";
}

export function worstSeverity(advisories: readonly Pick<Advisory, "severity">[]): string {
  return advisories
    .map((a) => a.severity)
    .filter((s) => s)
    .reduce((w, s) => (w === "" || severityRank(s) < severityRank(w) ? s : w), "");
}

/** What the vulnerable code is: the kernel, or the packages of an SBOM. */
export function shieldTarget(advisories: readonly Pick<Advisory, "package" | "source">[]): string {
  const names = advisories.map((a) => (a.source === "kernel" ? "kernel" : a.package)).filter((n) => n);
  return [...new Set(names)].sort().join(", ");
}

/** Nodes the newest operation can still apply on: all but those it left out. */
export const targeted = (r: Rollout) => r.nodes - r.notSelected;
