// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// The rows of sql/sbom.sql and sql/sbom-images.sql as
// tools/backend/test/xtop-sbom.expected has them, turned into findings
// and images.

import { describe, expect, test } from "bun:test";
import { toFinding, toSbomImage, type FindingRow, type ImageRow } from "../src/lib/backend.ts";
import { findingStatus } from "../src/lib/sbom.ts";

const ROOT = "a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c";

function finding(over: Partial<FindingRow>): FindingRow {
  return {
    vuln_id: "EXAMPLE-0101",
    package: "linux",
    severity: "CRITICAL",
    source: "kernel",
    fixed: "7.4.5",
    installed: ["7.4.2"],
    affected: 4,
    total: 5,
    upatch_id: "xfs-fix",
    shielded: 2,
    pending: 0,
    idle: 2,
    withdrawn: 0,
    unshielded: 0,
    stale: false,
    nodes: [
      ["node-a", "000b23602ab98bfb", "shielded", "fleet-os", "2026.11.1", "7.4.2", "verified", "healthy"],
      ["node-b", "000b9d72e08380a1", "shield_excludes_node", "fleet-os", "2026.11.1", "7.4.2", "declared", "healthy"],
    ],
    ...over,
  };
}

function image(over: Partial<ImageRow>): ImageRow {
  return {
    image_id: "fleet-os",
    image_version: "2026.11.1",
    image_root: ROOT,
    state: "ok",
    sbom_format: "cyclonedx-json",
    sbom_sha256: "5b0e2c8a4f6d1e3b7a9c0d2e4f6a8b1c3d5e7f9a0b2c4d6e8f1a3b5c7d9e91d4",
    built_ms: 1_793_606_400_000,
    scanned_ms: 1_795_053_039_000,
    db_version: "2",
    stale: 0,
    vulns: 1,
    critical: 0,
    high: 1,
    nodes: 4,
    ...over,
  };
}

describe("toFinding", () => {
  test("a kernel finding the shield covers on some nodes is partial", () => {
    const f = toFinding(finding({}));
    expect(f.status).toBe("partial");
    expect(f.nodes[1]).toEqual({
      name: "node-b",
      akName: "000b9d72e08380a1",
      exposure: "shield_excludes_node",
      imageId: "fleet-os",
      imageVersion: "2026.11.1",
      installed: "7.4.2",
      binding: "declared",
      status: "healthy",
    });
  });

  test("a shield still coming is pending", () => {
    const f = toFinding(finding({ vuln_id: "EXAMPLE-0202", upatch_id: "ssl-fix", shielded: 0, pending: 4, idle: 0 }));
    expect(f.status).toBe("pending");
  });

  test("no linked upatch is no shield; one on every node shielded", () => {
    expect(toFinding(finding({ upatch_id: "", shielded: 0, idle: 0, unshielded: 4 })).status).toBe("no_shield");
    expect(toFinding(finding({ shielded: 4, idle: 0 })).status).toBe("shielded");
  });

  test("reads stale as a Bool or a number", () => {
    expect(toFinding(finding({ stale: 1 })).stale).toBe(true);
    expect(toFinding(finding({ stale: false })).stale).toBe(false);
  });

  test("refuses an exposure it does not know", () => {
    expect(() =>
      toFinding(finding({ nodes: [["n", "k", "patched", "", "", "", "verified", "healthy"]] })),
    ).toThrow(/unknown exposure/);
  });
});

describe("findingStatus", () => {
  test("ranks by what the shield does", () => {
    expect(findingStatus({ upatchId: "", affected: 2, shielded: 0, pending: 0 })).toBe("no_shield");
    expect(findingStatus({ upatchId: "u", affected: 2, shielded: 1, pending: 1 })).toBe("pending");
    expect(findingStatus({ upatchId: "u", affected: 2, shielded: 1, pending: 0 })).toBe("partial");
    expect(findingStatus({ upatchId: "u", affected: 2, shielded: 2, pending: 0 })).toBe("shielded");
  });
});

describe("toSbomImage", () => {
  test("a scanned image", () => {
    const i = toSbomImage(image({}));
    expect(i.state).toBe("ok");
    expect(i.stale).toBe(false);
    expect(i.builtAt?.getTime()).toBe(1_793_606_400_000);
    expect(i.scannedAt?.getTime()).toBe(1_795_053_039_000);
    expect(i.nodes).toBe(4);
  });

  test("an image nodes run without an SBOM has no times", () => {
    const i = toSbomImage(
      image({ image_root: "", state: "no_sbom", sbom_format: "", sbom_sha256: "", built_ms: 0, scanned_ms: 0, db_version: "", vulns: 0, high: 0, nodes: 1 }),
    );
    expect(i.state).toBe("no_sbom");
    expect(i.builtAt).toBeNull();
    expect(i.scannedAt).toBeNull();
  });

  test("refuses a state it does not know", () => {
    expect(() => toSbomImage(image({ state: "scanning" }))).toThrow(/unknown image state/);
  });
});
