// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

import type { NodeStatus } from "../lib/fleet.ts";

export const STATUS_STYLE: Record<NodeStatus, { icon: string; color: string }> = {
  unhealthy: { icon: "✗", color: "red" },
  stale: { icon: "○", color: "gray" },
  healthy: { icon: "●", color: "green" },
};
