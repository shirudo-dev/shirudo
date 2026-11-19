// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// One upatch: its newest operation, what it fixes and how it rolled out.

import type { ReactNode } from "react";
import { Box, Text, useInput } from "ink";
import type { Shield } from "../lib/shields.ts";
import { SHIELD_STATUS_COLOR, SeverityText } from "./style.tsx";

type Props = {
  /** null when the upatch left tree_ops since it was opened. */
  shield: Shield | null;
  height: number;
  active: boolean;
  onClose: () => void;
};

function Field({ name, children }: { name: string; children: ReactNode }) {
  return (
    <Box>
      <Box width={12} flexShrink={0}>
        <Text dimColor>{name}</Text>
      </Box>
      <Text wrap="truncate-end">{children}</Text>
    </Box>
  );
}

export function ShieldDetail({ shield: s, height, active, onClose }: Props) {
  useInput(
    (input, key) => {
      if (key.escape || key.return || input === "h" || key.leftArrow) onClose();
    },
    { isActive: active },
  );

  if (!s)
    return (
      <Box flexDirection="column" height={height}>
        <Text color="yellow">the upatch is no longer in tree_ops</Text>
        <Text dimColor>esc back</Text>
      </Box>
    );

  const r = s.rollout;
  return (
    <Box flexDirection="column" height={height} overflow="hidden">
      <Text>
        <Text bold>{s.id}</Text>
        <Text color={SHIELD_STATUS_COLOR[s.status]}>  {s.status}</Text>
        <Text dimColor> · tree {s.treeId}</Text>
      </Text>
      <Field name="newest op">
        {s.op} at #{s.seq}
        {s.ops > 1 ? `, ${s.ops} operations in all` : ""}
        {s.op === "delete" && s.addSeq ? `, last added at #${s.addSeq}` : ""}
      </Field>
      <Field name="published">{s.publishedAt ? s.publishedAt.toLocaleString() : "—"}</Field>
      <Field name="repository">{s.repository}</Field>
      <Field name="manifest">{s.manifestDigest}</Field>
      <Field name="selector">{s.selector}</Field>
      <Field name="rollout">
        <Text color="green">{r.applied} applied</Text>
        {" · "}
        <Text color={r.pending ? "yellow" : undefined}>{r.pending} not reached</Text>
        {" · "}
        {r.notSelected} left out by the selector
        {" · "}
        <Text color={r.noTarget ? "red" : undefined}>{r.noTarget} module not loaded</Text>
        <Text dimColor> · of {r.nodes} nodes following the tree</Text>
      </Field>
      <Field name="images">{s.images.length ? s.images.join(", ") : "—"}</Field>
      <Box marginTop={1} flexDirection="column">
        <Text dimColor>fixes{s.op === "delete" && s.addSeq ? ` (the add at #${s.addSeq})` : ""}</Text>
        {s.advisories.length === 0 && <Text dimColor>no advisory linked</Text>}
        {s.advisories.map((a) => (
          <Text key={a.id} wrap="truncate-end">
            <Text bold>{a.id}</Text> <SeverityText severity={a.severity} />{" "}
            <Text color={a.source === "kernel" ? "magenta" : "cyan"}>{a.source === "kernel" ? "kernel" : a.package || "?"}</Text>
            <Text dimColor> · </Text>
            <Text color="green">{a.shielded} shielded</Text>
            <Text dimColor> · </Text>
            <Text color={a.exposed ? "yellow" : undefined}>{a.exposed} not shielded</Text>
          </Text>
        ))}
      </Box>
      <Box marginTop={1}>
        <Text dimColor>esc back</Text>
      </Box>
    </Box>
  );
}
