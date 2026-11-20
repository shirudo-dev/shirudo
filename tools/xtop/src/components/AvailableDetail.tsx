// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// One shield available to append: where it is, what it fixes, which trees
// carry it and the command that appends it.

import type { ReactNode } from "react";
import { Box, Text, useInput } from "ink";
import { appendCommand, type AvailableShield } from "../lib/shields.ts";
import { ago } from "../lib/format.ts";
import { SeverityText } from "./style.tsx";

type Props = {
  /** null when the shield left shield_catalog since it was opened. */
  shield: AvailableShield | null;
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

export function AvailableDetail({ shield: s, height, active, onClose }: Props) {
  useInput(
    (input, key) => {
      if (key.escape || key.return || input === "h" || key.leftArrow) onClose();
    },
    { isActive: active },
  );

  if (!s)
    return (
      <Box flexDirection="column" height={height}>
        <Text color="yellow">the shield is no longer in shield_catalog</Text>
        <Text dimColor>esc back</Text>
      </Box>
    );

  return (
    <Box flexDirection="column" height={height} overflow="hidden">
      <Box flexDirection="column" flexShrink={0}>
        <Text>
          <Text bold>{s.id}</Text>
          <Text dimColor>
            {" "}
            · {s.package} {s.version}
          </Text>
        </Text>
        {s.description && <Text wrap="truncate-end">{s.description}</Text>}
        <Field name="reference">{s.reference}</Field>
        <Field name="manifest">sha256:{s.manifestDigest}</Field>
        <Field name="selector">{s.selector}</Field>
        <Field name="put">
          {s.putAt ? `${s.putAt.toLocaleString()} (${ago(s.putAt)} ago)` : "—"}
          {s.versions > 1 ? `, ${s.versions} versions in all` : ""}
        </Field>
        <Field name="in trees">{s.trees.length ? s.trees.join(", ") : <Text dimColor>none</Text>}</Field>
        <Box marginTop={1} flexDirection="column">
          <Text dimColor>fixes</Text>
          {s.advisories.length === 0 && <Text dimColor>no advisory linked</Text>}
          {s.advisories.map((a) => (
            <Text key={a.id} wrap="truncate-end">
              <Text bold>{a.id}</Text> <SeverityText severity={a.severity} />{" "}
              <Text color={a.source === "kernel" ? "magenta" : "cyan"}>{a.source === "kernel" ? "kernel" : a.package || "?"}</Text>
              <Text dimColor> · </Text>
              <Text color={a.exposed ? "yellow" : undefined}>{a.exposed} nodes exposed</Text>
            </Text>
          ))}
        </Box>
        <Box marginTop={1} flexDirection="column">
          <Text dimColor>append it with</Text>
          <Text wrap="wrap">{appendCommand(s)}</Text>
        </Box>
        <Box marginTop={1}>
          <Text dimColor>esc back</Text>
        </Box>
      </Box>
    </Box>
  );
}
