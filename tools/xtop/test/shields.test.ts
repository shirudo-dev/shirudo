// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// The rows of sql/shields.sql as tools/backend/test/xtop-shields.expected
// has them, turned into shields.

import { describe, expect, test } from "bun:test";
import { toShield, type ShieldRow } from "../src/lib/backend.ts";
import { severityRank, shieldStatus, shieldTarget, targeted, worstSeverity } from "../src/lib/shields.ts";

function row(over: Partial<ShieldRow>): ShieldRow {
  return {
    tree_id: "fleet-base",
    id: "xfs-fix",
    seq: 3,
    op: "add",
    add_seq: 3,
    ops: 3,
    manifest_digest: "b25c835b353ba101d51c4473d602764c2f8746a6e60342bcf49d510a868cb62a",
    repository: "oci://registry.example.com/shirudo/fleet-base",
    selector: '{"labels":{"role":["edge"]}}',
    published_ms: 1_795_053_774_291,
    advisories: [["EXAMPLE-0101", "CRITICAL", "linux", "kernel", 2, 2]],
    images: ["fleet-os 2026.11.1"],
    nodes: 4,
    applied: 2,
    not_selected: 2,
    no_target: 0,
    pending: 0,
    ...over,
  };
}

const SSL_FIX = row({
  id: "ssl-fix",
  seq: 4,
  add_seq: 4,
  ops: 1,
  selector: "{}",
  advisories: [["EXAMPLE-0202", "HIGH", "openssl", "sbom", 0, 4]],
  applied: 0,
  not_selected: 0,
  pending: 4,
});

describe("toShield", () => {
  test("maps a deployed kernel shield", () => {
    const s = toShield(row({}));
    expect(s.status).toBe("deployed");
    expect(s.severity).toBe("CRITICAL");
    expect(shieldTarget(s.advisories)).toBe("kernel");
    expect(s.rollout).toEqual({ nodes: 4, applied: 2, notSelected: 2, noTarget: 0, pending: 0 });
    expect(targeted(s.rollout)).toBe(2);
    expect(s.advisories[0]).toEqual({
      id: "EXAMPLE-0101",
      severity: "CRITICAL",
      package: "linux",
      source: "kernel",
      shielded: 2,
      exposed: 2,
    });
    expect(s.publishedAt?.getTime()).toBe(1_795_053_774_291);
  });

  test("maps a pending package shield", () => {
    const s = toShield(SSL_FIX);
    expect(s.status).toBe("pending");
    expect(s.severity).toBe("HIGH");
    expect(shieldTarget(s.advisories)).toBe("openssl");
    expect(targeted(s.rollout)).toBe(4);
  });

  test("a delete withdraws it, whatever the rollout", () => {
    expect(toShield(row({ op: "delete", seq: 5, pending: 3 })).status).toBe("withdrawn");
  });

  test("an upatch without fixes or a publication", () => {
    const s = toShield(row({ advisories: [], images: [], published_ms: 0 }));
    expect(s.severity).toBe("");
    expect(shieldTarget(s.advisories)).toBe("");
    expect(s.publishedAt).toBeNull();
  });

  test("refuses an operation or source it does not know", () => {
    expect(() => toShield(row({ op: "move" }))).toThrow(/unknown operation/);
    expect(() => toShield(row({ advisories: [["X", "LOW", "p", "rpm", 0, 0]] }))).toThrow(/unknown advisory source/);
  });
});

describe("helpers", () => {
  test("severity ranks worst first and unknown last", () => {
    expect(severityRank("CRITICAL")).toBeLessThan(severityRank("HIGH"));
    expect(severityRank("low")).toBe(3);
    expect(severityRank("NEGLIGIBLE")).toBe(4);
  });

  test("the worst severity of several advisories", () => {
    expect(worstSeverity([{ severity: "LOW" }, { severity: "" }, { severity: "HIGH" }])).toBe("HIGH");
    expect(worstSeverity([])).toBe("");
  });

  test("the target names each package once, the kernel as kernel", () => {
    expect(
      shieldTarget([
        { package: "openssl", source: "sbom" },
        { package: "linux", source: "kernel" },
        { package: "openssl", source: "sbom" },
      ]),
    ).toBe("kernel, openssl");
  });

  test("status follows the newest operation and the nodes not reached", () => {
    const r = { nodes: 2, applied: 1, notSelected: 0, noTarget: 0, pending: 1 };
    expect(shieldStatus("add", r)).toBe("pending");
    expect(shieldStatus("add", { ...r, pending: 0 })).toBe("deployed");
    expect(shieldStatus("delete", r)).toBe("withdrawn");
  });
});
