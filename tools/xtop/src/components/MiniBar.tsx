// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A share drawn in eighths of a cell, green to red.

import { Text } from "ink";

export const healthColor = (h: number) => (h >= 80 ? "green" : h >= 50 ? "yellow" : "red");
const EIGHTHS = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉"];

export function MiniBar({ value, width }: { value: number; width: number }) {
  const eighths = Math.round((Math.max(0, Math.min(100, value)) / 100) * width * 8);
  const full = Math.floor(eighths / 8);
  const partial = EIGHTHS[eighths % 8]!;
  return (
    <>
      <Text color={healthColor(value)}>{"█".repeat(full) + partial}</Text>
      <Text dimColor>{"░".repeat(width - full - (partial ? 1 : 0))}</Text>
    </>
  );
}

/** A bar and its percent. */
export function HealthCell({ health, bar }: { health: number; bar: number }) {
  return (
    <>
      <MiniBar value={health} width={bar} />
      <Text color={healthColor(health)}> {String(health).padStart(3)}%</Text>
    </>
  );
}
