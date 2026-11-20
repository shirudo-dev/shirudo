// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A tree to create: its repository, the available shields to start it
// with, and the commands that publish it, which xtop runs when it has the
// operator's keys.

import { useState } from "react";
import { Box, Text, useInput } from "ink";
import { createTreeCommands, type AvailableShield } from "../lib/shields.ts";
import { run, type Operator } from "../lib/operator.ts";
import { SeverityText } from "./style.tsx";

type Props = {
  shields: readonly AvailableShield[];
  /** null when xtop was not given the keys: the commands are only shown. */
  operator: Operator | null;
  /** The tree is published and loaded. */
  onCreated: () => void;
  height: number;
  active: boolean;
  /** The repository field takes every key while it is edited. */
  onEditingChange: (editing: boolean) => void;
  onClose: () => void;
};

// Several at once when pasted.
const REPOSITORY_CHARS = /^[a-z0-9._\/-]+$/;

type Step = { state: "running" | "ok" | "failed"; output: string };

const STEP_MARK = { running: "…", ok: "✓", failed: "✗" } as const;
const STEP_COLOR = { running: "yellow", ok: "green", failed: "red" } as const;
const FAILURE_LINES = 6;

export function CreateTree({ shields, operator, onCreated, height, active, onEditingChange, onClose }: Props) {
  const [repository, setRepository] = useState("");
  const [editing, setEditingState] = useState(true);
  const [cursor, setCursor] = useState(0);
  const [picked, setPicked] = useState<readonly string[]>([]);

  // One per command started, in order: a failure stops the rest.
  const [steps, setSteps] = useState<readonly Step[]>([]);
  const running = steps.some((s) => s.state === "running");

  const runAll = async (commands: readonly string[][]) => {
    // A retry leaves out what succeeded: an append run twice is two operations.
    const done = steps.filter((s) => s.state === "ok");
    for (const argv of commands.slice(done.length)) {
      setSteps([...done, { state: "running", output: "" }]);
      const result = await run(argv);
      done.push({ state: result.ok ? "ok" : "failed", output: result.output });
      setSteps([...done]);
      if (!result.ok) return;
    }
    onCreated();
    close();
  };

  const setEditing = (e: boolean) => {
    setEditingState(e);
    onEditingChange(e);
  };
  const close = () => {
    onEditingChange(false);
    onClose();
  };

  const chosen = picked.flatMap((id) => shields.find((s) => s.id === id) ?? []);
  const commands = createTreeCommands(repository, chosen, operator);
  const runnable = operator !== null && chosen.length > 0 && repository !== "";

  useInput(
    (input, key) => {
      if (running) return;
      if (editing) {
        if (key.escape) return repository ? setEditing(false) : close();
        if (key.return || key.tab || key.downArrow) return setEditing(false);
        if (key.backspace || key.delete) return setRepository((r) => r.slice(0, -1));
        if (REPOSITORY_CHARS.test(input)) {
          setRepository((r) => r + input);
          setSteps([]);
        }
        return;
      }
      if (key.escape || input === "h" || key.leftArrow) return close();
      if (input === "n" || (cursor === 0 && (input === "k" || key.upArrow))) return setEditing(true);
      if (input === "j" || key.downArrow) return setCursor((c) => Math.min(c + 1, shields.length - 1));
      if (input === "k" || key.upArrow) return setCursor((c) => Math.max(c - 1, 0));
      const id = shields[cursor]?.id;
      if (input === "x" && runnable) return void runAll(commands);
      if (id && (input === " " || key.return)) {
        setSteps([]);
        setPicked((p) => (p.includes(id) ? p.filter((x) => x !== id) : [...p, id]));
      }
    },
    { isActive: active },
  );

  const listLines = Math.max(3, Math.min(shields.length, Math.floor((height - 6) / 2)));
  const first = Math.max(0, Math.min(cursor - listLines + 1, shields.length - listLines));

  return (
    <Box flexDirection="column" height={height} overflow="hidden">
      <Text bold>create tree</Text>
      <Text>
        <Text dimColor>repository </Text>
        <Text inverse={editing}>{repository || (editing ? " " : "")}</Text>
        {!repository && <Text dimColor> a path under the shields' registry, such as shirudo/fleet-base</Text>}
      </Text>
      <Box marginTop={1} flexDirection="column">
        <Text dimColor>shields, appended in the order picked</Text>
        {shields.slice(first, first + listLines).map((s, i) => {
          const order = picked.indexOf(s.id);
          return (
            <Text key={s.id} inverse={!editing && first + i === cursor} wrap="truncate-end">
              {order < 0 ? "[ ]" : `[${order + 1}]`} {s.id} <Text dimColor>{s.version}</Text> <SeverityText severity={s.severity} />
              {s.trees.length > 0 && <Text dimColor> · in {s.trees.join(", ")}</Text>}
            </Text>
          );
        })}
      </Box>
      <Box marginTop={1} flexDirection="column">
        <Text dimColor>
          {operator ? "x runs, with the keys of XTOP_KEYS_DIR" : "run, with the operator's keys directory for <keys>; xtop runs them when XTOP_KEYS_DIR names it"}
        </Text>
        {chosen.length === 0 ? (
          <Text dimColor>pick a shield to see the commands</Text>
        ) : (
          commands.map((argv, i) => {
            const step = steps[i];
            const output = step?.output.split("\n") ?? [];
            return (
              <Box key={argv.join(" ")} flexDirection="column">
                <Text wrap="wrap">
                  {step ? <Text color={STEP_COLOR[step.state]}>{STEP_MARK[step.state]}</Text> : "$"} {argv.join(" ")}
                </Text>
                {step?.state === "ok" && <Text dimColor wrap="truncate-end">  {output.at(-1)}</Text>}
                {step?.state === "failed" &&
                  output.slice(-FAILURE_LINES).map((line, n) => (
                    <Text key={n} color="red" wrap="truncate-end">
                      {"  "}
                      {line}
                    </Text>
                  ))}
              </Box>
            );
          })
        )}
      </Box>
      <Box marginTop={1}>
        <Text dimColor>
          {running
            ? "running…"
            : editing
              ? "type the repository · enter shields · esc back"
              : `j/k move · space pick · n repository${runnable ? " · x run" : ""} · esc back`}
        </Text>
      </Box>
    </Box>
  );
}
