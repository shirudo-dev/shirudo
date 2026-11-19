// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// What the SBOMs of the images, and the kernels, say is vulnerable on the
// nodes, from node_vulns, and how far the SBOM store is scanned, from
// sbom_images.

/** node_vulns.exposure of one node. */
export type Exposure =
  | "shielded"
  | "shield_pending"
  | "shield_module_absent"
  | "shield_excludes_node"
  | "shield_withdrawn"
  | "exposed_no_shield"
  | "none"
  | "unknown";

export const EXPOSURES: readonly Exposure[] = [
  "shielded",
  "shield_pending",
  "shield_module_absent",
  "shield_excludes_node",
  "shield_withdrawn",
  "exposed_no_shield",
  "none",
  "unknown",
];

export type FindingNode = {
  name: string;
  akName: string;
  exposure: Exposure;
  imageId: string;
  imageVersion: string;
  installed: string;
  /** How the node's image was bound to an SBOM: verified, declared, ... */
  binding: string;
  /** The node's status in node_status. */
  status: string;
};

/**
 * no_shield when no upatch is linked to the advisory, shielded when it
 * shields every affected node, pending while it is still coming to one,
 * partial when it leaves some out.
 */
export type FindingStatus = "no_shield" | "partial" | "pending" | "shielded";

export const FINDING_STATUS_RANK: Record<FindingStatus, number> = { no_shield: 0, partial: 1, pending: 2, shielded: 3 };

export type Finding = {
  vulnId: string;
  package: string;
  severity: string;
  /** kernel for an advisory matched on the kernel release, sbom for one in an image's SBOM. */
  source: string;
  fixed: string;
  installed: string[];
  affected: number;
  /** Nodes in node_status. */
  total: number;
  upatchId: string;
  shielded: number;
  pending: number;
  /** Selector left the node out, or the module the shield attaches to is not loaded. */
  idle: number;
  withdrawn: number;
  unshielded: number;
  /** An image's newest scan is older than sbom_stale_seconds. */
  stale: boolean;
  nodes: FindingNode[];
  status: FindingStatus;
};

export type SbomReport = { generatedAt: Date; findings: Finding[] };

export type ImageState = "ok" | "missing" | "hash_mismatch" | "parse_error" | "unsupported_format" | "no_sbom";

export const IMAGE_STATES: readonly ImageState[] = [
  "parse_error",
  "hash_mismatch",
  "missing",
  "unsupported_format",
  "no_sbom",
  "ok",
];

export type SbomImage = {
  imageId: string;
  imageVersion: string;
  /** Empty for an image built without verity. */
  imageRoot: string;
  state: ImageState;
  sbomFormat: string;
  sbomSha256: string;
  builtAt: Date | null;
  scannedAt: Date | null;
  dbVersion: string;
  stale: boolean;
  vulns: number;
  critical: number;
  high: number;
  /** Nodes whose newest record names the image. */
  nodes: number;
};

export type ImagesReport = { generatedAt: Date; images: SbomImage[] };

export function findingStatus(f: Pick<Finding, "upatchId" | "affected" | "shielded" | "pending">): FindingStatus {
  if (!f.upatchId) return "no_shield";
  if (f.shielded >= f.affected) return "shielded";
  return f.pending ? "pending" : "partial";
}

export const imageKey = (i: Pick<SbomImage, "imageId" | "imageVersion">) => `${i.imageId} ${i.imageVersion}`;
