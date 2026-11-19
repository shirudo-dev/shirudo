// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// One node: what it runs and the line of each check the backend ran.

import type { ReactNode } from "react";
import { Box, Text, useInput } from "ink";
import { imageLabel, type FleetNode } from "../lib/fleet.ts";
import { STATUS_STYLE } from "./style.tsx";

type Props = {
  /** null when the node left node_status since it was opened. */
  node: FleetNode | null;
  height: number;
  active: boolean;
  onClose: () => void;
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

const checkColor = (line: string) => (/^\d+ [a-z]+: FAIL/.test(line) ? "red" : /: pass/.test(line) ? "green" : undefined);

export function NodeDetail({ node, height, active, onClose }: Props) {
  useInput(
    (input, key) => {
      if (key.escape || key.return || input === "h" || key.leftArrow) onClose();
    },
    { isActive: active },
  );

  if (!node)
    return (
      <Box flexDirection="column" height={height}>
        <Text color="yellow">the node is no longer in node_status</Text>
        <Text dimColor>esc back</Text>
      </Box>
    );

  const style = STATUS_STYLE[node.status];
  const t = node.tree;
  return (
    <Box flexDirection="column" height={height} overflow="hidden">
      {/* Lines keep their height and the pane clips them, rather than squeeze them onto each other. */}
      <Box flexDirection="column" flexShrink={0}>
        <Text>
          <Text bold>{node.name}</Text>
          <Text color={style.color}>
            {"  "}
            {style.icon} {node.status}
          </Text>
          <Text color={node.trust === "enrolled" ? "green" : "yellow"}> · {node.trust}</Text>
        </Text>
        <Field name="host">{node.hostName}</Field>
        <Field name="key">{node.akName}</Field>
        <Field name="labels">
          {Object.keys(node.labels).length === 0 && "none put"}
          {Object.keys(node.labels)
            .sort()
            .map((k, i) => (
              <Text key={k}>
                {i ? " " : ""}
                {k}={node.labels[k]}
                <Text dimColor> ({node.labelSources[k]})</Text>
              </Text>
            ))}
        </Field>
        {node.labelConflicts.map((c) => (
          <Field key={c.key} name="conflict">
            <Text color="yellow">
              {c.key}={c.value} from {c.by} over{" "}
              {c.given
                .filter((g) => g.value !== c.value)
                .map((g) => `${g.value} from ${g.by}`)
                .join(", ")}
            </Text>
          </Field>
        ))}
        <Field name="image">{imageLabel(node.imageId, node.imageVersion)}</Field>
        <Field name="kernel">{node.kernel}</Field>
        <Field name="build">{node.version}</Field>
        <Field name="tree">
          {t.lastSeq === null
            ? "follows no tree"
            : `seq ${t.lastSeq} of ${t.headSeq ?? "?"}, generation ${t.generation ?? "?"}, ${node.loaded} loaded`}
        </Field>
        <Field name="seen">{node.lastSeen.toLocaleString()}</Field>
        <Box marginTop={1} flexDirection="column">
          <Text dimColor>checks</Text>
          {node.log.map((line, i) => (
            <Text key={i} color={checkColor(line)} wrap="truncate-end">
              {line}
            </Text>
          ))}
        </Box>
        <Box marginTop={1}>
          <Text dimColor>esc back</Text>
        </Box>
      </Box>
    </Box>
  );
}
