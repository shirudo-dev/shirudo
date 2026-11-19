// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// One finding: the advisory, its shield, and every node it affects with
// how exposed that node is.

import type { ReactNode } from "react";
import { Box, Text, useInput } from "ink";
import type { Exposure, Finding } from "../lib/sbom.ts";
import { FINDING_STATUS_STYLE, SeverityText } from "./style.tsx";

type Props = {
  /** null when the finding left node_vulns since it was opened. */
  finding: Finding | null;
  height: number;
  active: boolean;
  onClose: () => void;
};

const EXPOSURE_TEXT: Record<Exposure, { text: string; color?: string }> = {
  shielded: { text: "shielded", color: "green" },
  shield_pending: { text: "shield coming", color: "yellow" },
  shield_module_absent: { text: "module not loaded", color: "red" },
  shield_excludes_node: { text: "left out by selector", color: "red" },
  shield_withdrawn: { text: "shield withdrawn", color: "red" },
  exposed_no_shield: { text: "no shield", color: "red" },
  none: { text: "not affected" },
  unknown: { text: "unknown", color: "yellow" },
};

function Field({ name, children }: { name: string; children: ReactNode }) {
  return (
    <Box>
      <Box width={10} flexShrink={0}>
        <Text dimColor>{name}</Text>
      </Box>
      <Text wrap="truncate-end">{children}</Text>
    </Box>
  );
}

export function FindingDetail({ finding: f, height, active, onClose }: Props) {
  useInput(
    (input, key) => {
      if (key.escape || key.return || input === "h" || key.leftArrow) onClose();
    },
    { isActive: active },
  );

  if (!f)
    return (
      <Box flexDirection="column" height={height}>
        <Text color="yellow">the finding is no longer in node_vulns</Text>
        <Text dimColor>esc back</Text>
      </Box>
    );

  const style = FINDING_STATUS_STYLE[f.status];
  // Header, fields, the line before the nodes and the hint.
  const room = Math.max(1, height - 9);
  const shown = f.nodes.slice(0, room);
  return (
    <Box flexDirection="column" height={height} overflow="hidden">
      <Text>
        <Text bold>{f.vulnId}</Text> <SeverityText severity={f.severity} />
        <Text color={style.color}>  {style.label}</Text>
      </Text>
      <Field name="package">
        {f.source === "kernel" ? "the kernel" : f.package} {f.installed.join(", ")}
        {f.fixed ? `, fixed in ${f.fixed}` : ", no fixed version yet"}
      </Field>
      <Field name="source">{f.source === "kernel" ? "kernel_vulns, by kernel release" : "the image's SBOM, by its scan"}</Field>
      <Field name="shield">{f.upatchId || "no upatch is linked to the advisory"}</Field>
      <Field name="nodes">
        {f.affected} of {f.total} affected · <Text color="green">{f.shielded} shielded</Text> · {f.pending} coming ·{" "}
        {f.idle} not taking it · {f.withdrawn} withdrawn · {f.unshielded} without one
      </Field>
      {f.stale && <Text color="red">an image's newest scan is older than sbom_stale_seconds</Text>}
      <Box marginTop={1} flexDirection="column">
        <Text dimColor>
          {"NODE".padEnd(14)}
          {"EXPOSURE".padEnd(22)}
          {"IMAGE".padEnd(22)}
          {"INSTALLED".padEnd(12)}
          {"BINDING".padEnd(14)}STATUS
        </Text>
        {shown.map((n) => {
          const e = EXPOSURE_TEXT[n.exposure];
          return (
            <Text key={n.akName} wrap="truncate-end">
              <Text bold>{n.name.padEnd(14)}</Text>
              <Text color={e.color}>{e.text.padEnd(22)}</Text>
              <Text color="cyan">{`${n.imageId} ${n.imageVersion}`.trim().padEnd(22)}</Text>
              {n.installed.padEnd(12)}
              <Text dimColor>{n.binding.padEnd(14)}</Text>
              {n.status}
            </Text>
          );
        })}
        {f.nodes.length > shown.length && <Text dimColor>and {f.nodes.length - shown.length} more</Text>}
      </Box>
      <Text dimColor>esc back</Text>
    </Box>
  );
}
