// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

import { Text } from "ink";
import type { NodeStatus } from "../lib/fleet.ts";
import type { ShieldStatus } from "../lib/shields.ts";

export const STATUS_STYLE: Record<NodeStatus, { icon: string; color: string }> = {
  unhealthy: { icon: "✗", color: "red" },
  stale: { icon: "○", color: "gray" },
  healthy: { icon: "●", color: "green" },
};

export const SHIELD_STATUS_COLOR: Record<ShieldStatus, string> = {
  pending: "yellow",
  deployed: "green",
  withdrawn: "gray",
};

export const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: "red",
  HIGH: "red",
  MEDIUM: "yellow",
  LOW: "gray",
};

export function SeverityText({ severity }: { severity: string }) {
  if (!severity) return <Text dimColor>—</Text>;
  return (
    <Text color={SEVERITY_COLOR[severity.toUpperCase()]} bold={severity.toUpperCase() === "CRITICAL"}>
      {severity.toLowerCase()}
    </Text>
  );
}
