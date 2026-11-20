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

// ---- shields available to append -----------------------------------------

/** An advisory an available shield fixes, and the nodes it leaves exposed now. */
export type AvailableAdvisory = Pick<Advisory, "id" | "severity" | "package" | "source"> & { exposed: number };

/** A shield of shirudo.shield_catalog, at the version put last. */
export type AvailableShield = {
  id: string;
  package: string;
  version: string;
  /** oci://<registry>/<repository>:<version>, which bpm tree append takes. */
  reference: string;
  /** 64 hex digits, without "sha256:". */
  manifestDigest: string;
  selector: string;
  description: string;
  putAt: Date | null;
  /** Versions put of it. */
  versions: number;
  advisories: AvailableAdvisory[];
  /** Trees whose newest operation of it is an add. */
  trees: string[];
  /** The worst severity of its advisories, "" when none is known. */
  severity: string;
  /** The most nodes one of its advisories leaves exposed: a node exposed to two counts once. */
  exposed: number;
};

export type AvailableReport = { generatedAt: Date; shields: AvailableShield[] };

export const mostExposed = (advisories: readonly Pick<AvailableAdvisory, "exposed">[]) =>
  advisories.reduce((most, a) => Math.max(most, a.exposed), 0);

/** The bpm tree append that takes the shield, less the tree to fill in. */
export const appendCommand = (s: Pick<AvailableShield, "reference" | "manifestDigest">) =>
  `shirudo bpm tree append ${s.reference} --package-digest sha256:${s.manifestDigest} ` +
  "oci://<registry>/<tree> --tree-id <tree-id>";
