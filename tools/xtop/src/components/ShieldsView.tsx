// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Every upatch of every tree the backend has loaded, with what it fixes
// and how its newest operation rolled out, and every shield published and
// available to append. Enter shows one.

import { useState } from "react";
import { Box, Text, useInput } from "ink";
import type { ReactNode } from "react";
import type { Backend } from "../lib/backend.ts";
import { ago } from "../lib/format.ts";
import { useRefreshing } from "../lib/useRefreshing.ts";
import {
  SHIELD_STATUS_RANK,
  type AvailableReport,
  type AvailableShield,
  severityRank,
  shieldTarget,
  targeted,
  type Rollout,
  type Shield,
  type ShieldStatus,
  type ShieldsReport,
} from "../lib/shields.ts";
import { DataTable, Tabs, type Column } from "./DataTable.tsx";
import { ViewMessage } from "./ViewMessage.tsx";
import { MiniBar } from "./MiniBar.tsx";
import { ShieldDetail } from "./ShieldDetail.tsx";
import { AvailableDetail } from "./AvailableDetail.tsx";
import { SHIELD_STATUS_COLOR, SeverityText } from "./style.tsx";

/** The upatches of the trees, or the shields available to append. */
export type ShieldsMode = "trees" | "available";

type Props = {
  backend: Backend;
  mode: ShieldsMode;
  onModeChange: (mode: ShieldsMode) => void;
  /** Lines available inside the panel. */
  height: number;
  active: boolean;
  onClose: () => void;
  onSearchingChange: (searching: boolean) => void;
  /** A shield's detail is open. */
  onDetailChange?: (open: boolean) => void;
};

function RolloutCell({ r }: { r: Rollout }) {
  const of = targeted(r);
  if (!of) return <Text dimColor>—</Text>;
  return (
    <>
      <MiniBar value={(r.applied / of) * 100} width={6} />
      <Text> {`${r.applied}/${of}`.padEnd(5)}</Text>
      {r.pending > 0 && <Text color="yellow"> {r.pending}…</Text>}
      {r.noTarget > 0 && <Text color="red"> {r.noTarget}✗</Text>}
    </>
  );
}

const COLUMNS: readonly Column<Shield>[] = [
  {
    id: "status",
    title: "STATUS",
    width: 11,
    defaultDir: "asc",
    sortKey: (s) => SHIELD_STATUS_RANK[s.status],
    render: (s) => <Text color={SHIELD_STATUS_COLOR[s.status]}>{s.status}</Text>,
  },
  {
    id: "name",
    title: "SHIELD",
    defaultDir: "asc",
    sortKey: (s) => s.id,
    render: (s) => (
      <>
        <Text bold>{s.id}</Text>
        <Text dimColor> {s.manifestDigest.slice(0, 8)}</Text>
      </>
    ),
  },
  {
    id: "severity",
    title: "SEVERITY",
    width: 10,
    defaultDir: "asc",
    sortKey: (s) => severityRank(s.severity),
    render: (s) => <SeverityText severity={s.severity} />,
  },
  {
    id: "target",
    title: "TARGET",
    width: 16,
    defaultDir: "asc",
    sortKey: (s) => shieldTarget(s.advisories),
    render: (s) => {
      const t = shieldTarget(s.advisories);
      return t ? <Text color={t === "kernel" ? "magenta" : "cyan"}>{t}</Text> : <Text dimColor>—</Text>;
    },
  },
  {
    id: "images",
    title: "IMAGES",
    width: 22,
    defaultDir: "desc",
    sortKey: (s) => s.images.length,
    render: (s) =>
      s.images.length === 0 ? (
        <Text dimColor>—</Text>
      ) : (
        <>
          <Text color="cyan">{s.images[0]}</Text>
          {s.images.length > 1 && <Text dimColor> +{s.images.length - 1}</Text>}
        </>
      ),
  },
  {
    id: "rollout",
    title: "ROLLOUT",
    width: 20,
    defaultDir: "asc",
    sortKey: (s) => (targeted(s.rollout) ? s.rollout.applied / targeted(s.rollout) : 2),
    render: (s) => <RolloutCell r={s.rollout} />,
  },
  {
    id: "tree",
    title: "TREE",
    width: 6,
    align: "right",
    defaultDir: "asc",
    sortKey: (s) => s.seq,
    render: (s) => <Text color={s.op === "delete" ? "gray" : undefined}>#{s.seq}</Text>,
  },
];

const shieldFields = (s: Shield) =>
  [
    s.id,
    s.treeId,
    s.status,
    s.severity,
    s.manifestDigest,
    s.repository,
    ...s.advisories.flatMap((a) => [a.id, a.package, a.source]),
    ...s.images,
  ];

// Ties: worst severity first, then name.
const tiebreak = (a: Shield, b: Shield) => severityRank(a.severity) - severityRank(b.severity) || a.id.localeCompare(b.id);

// ---- available shields ----------------------------------------------------

const AVAILABLE_COLUMNS: readonly Column<AvailableShield>[] = [
  {
    id: "severity",
    title: "SEVERITY",
    width: 10,
    defaultDir: "asc",
    sortKey: (s) => severityRank(s.severity),
    render: (s) => <SeverityText severity={s.severity} />,
  },
  {
    id: "name",
    title: "SHIELD",
    defaultDir: "asc",
    sortKey: (s) => s.id,
    render: (s) => <Text bold>{s.id}</Text>,
  },
  {
    id: "fixes",
    title: "FIXES",
    width: 18,
    defaultDir: "asc",
    sortKey: (s) => s.advisories.map((a) => a.id).join(" "),
    render: (s) =>
      s.advisories.length === 0 ? (
        <Text dimColor>—</Text>
      ) : (
        <>
          <Text>{s.advisories[0]!.id}</Text>
          {s.advisories.length > 1 && <Text dimColor> +{s.advisories.length - 1}</Text>}
        </>
      ),
  },
  {
    id: "target",
    title: "TARGET",
    width: 12,
    defaultDir: "asc",
    sortKey: (s) => shieldTarget(s.advisories),
    render: (s) => {
      const t = shieldTarget(s.advisories);
      return t ? <Text color={t === "kernel" ? "magenta" : "cyan"}>{t}</Text> : <Text dimColor>—</Text>;
    },
  },
  {
    id: "exposed",
    title: "EXPOSED",
    width: 8,
    align: "right",
    defaultDir: "desc",
    sortKey: (s) => s.exposed,
    render: (s) => (s.exposed ? <Text color="yellow">{s.exposed}</Text> : <Text dimColor>0</Text>),
  },
  {
    id: "version",
    title: "VERSION",
    width: 16,
    defaultDir: "desc",
    sortKey: (s) => s.version,
    render: (s) => <Text dimColor>{s.version}</Text>,
  },
  {
    id: "trees",
    title: "IN TREES",
    width: 16,
    defaultDir: "desc",
    sortKey: (s) => s.trees.length,
    render: (s) => (s.trees.length ? <Text color="green">{s.trees.join(", ")}</Text> : <Text dimColor>—</Text>),
  },
  {
    id: "put",
    title: "PUT",
    width: 6,
    align: "right",
    defaultDir: "desc",
    sortKey: (s) => s.putAt?.getTime() ?? 0,
    render: (s) => (s.putAt ? <Text>{ago(s.putAt)}</Text> : <Text dimColor>—</Text>),
  },
];

const availableFields = (s: AvailableShield) =>
  [
    s.id,
    s.package,
    s.version,
    s.reference,
    s.selector,
    s.description,
    ...s.advisories.flatMap((a) => [a.id, a.severity, a.package, a.source]),
    ...s.trees,
  ];

// Ties: most nodes exposed first, then name.
const availableTiebreak = (a: AvailableShield, b: AvailableShield) => b.exposed - a.exposed || a.id.localeCompare(b.id);

// ---- view ------------------------------------------------------------------

export function ShieldsView({ backend, mode, onModeChange, height, active, onClose, onSearchingChange, onDetailChange }: Props) {
  const [reload, setReload] = useState(0);
  const trees = useRefreshing<ShieldsReport>(mode === "trees", reload, () => backend.getShields());
  const available = useRefreshing<AvailableReport>(mode === "available", reload, () => backend.getAvailableShields());
  const [searching, setSearching] = useState(false);
  const [onTabs, setOnTabs] = useState(false);
  const [detail, setDetail] = useState<string | null>(null);
  const keyOf = (s: Shield) => `${s.treeId}\0${s.id}`;

  const showDetail = (key: string | null) => {
    setDetail(key);
    onDetailChange?.(key !== null);
  };
  const reportSearching = (s: boolean) => {
    setSearching(s);
    onSearchingChange(s);
  };
  const switchTo = (m: ShieldsMode, fromTabs = false) => {
    setOnTabs(fromTabs);
    showDetail(null);
    onModeChange(m);
  };
  const modes: ShieldsMode[] = ["trees", "available"];
  const tabs = {
    labels: ["in trees", "available"],
    selected: modes.indexOf(mode),
    onSelect: (i: number) => switchTo(modes[i]!, true),
  };

  useInput(
    (input) => {
      if (input === "t") switchTo(mode === "trees" ? "available" : "trees");
      if (input === "r") setReload((r) => r + 1);
    },
    { isActive: active && !searching && !detail },
  );

  const query = mode === "trees" ? trees : available;
  const message = (color: string | undefined, text: ReactNode) => (
    <Box flexDirection="column">
      <Tabs labels={tabs.labels} selected={tabs.selected} />
      <ViewMessage active={active && !searching} onClose={onClose} color={color}>
        {text}
      </ViewMessage>
    </Box>
  );
  if (!query.data)
    return query.error ? message("red", `${mode} query failed: ${query.error}`) : message(undefined, "querying backend…");
  const tableHeight = Math.max(4, height);
  const failed = query.error && <Text color="red">refresh failed: {query.error} · </Text>;
  const status = (generatedAt: Date) => (
    <>
      <Text dimColor> · as of {generatedAt.toTimeString().slice(0, 8)}</Text>
      {query.loading && <Text dimColor> · querying…</Text>}
    </>
  );

  if (mode === "available") {
    const report = available.data!;
    if (report.shields.length === 0)
      return message(
        undefined,
        "no shield in shirudo.shield_catalog: run make shields, or tools/put-shields --catalog and tools/backend/jobs/shields-put",
      );
    const detailShield = detail ? (report.shields.find((s) => s.id === detail) ?? null) : null;
    return (
      <Box flexDirection="column">
        {detail && <AvailableDetail shield={detailShield} height={tableHeight} active={active} onClose={() => showDetail(null)} />}
        <Box flexDirection="column" display={detail ? "none" : "flex"}>
          <DataTable
            tabs={tabs}
            startOnTabs={onTabs}
            footerHint="t in trees · r refresh"
            rows={report.shields}
            columns={AVAILABLE_COLUMNS}
            rowKey={(s) => s.id}
            height={tableHeight}
            active={active && !detail}
            initialSort={{ col: "severity", dir: "asc" }}
            tiebreak={availableTiebreak}
            searchFields={availableFields}
            onSearchingChange={reportSearching}
            onClose={onClose}
            onOpen={(s) => showDetail(s.id)}
            summary={(rows, sortedBy) => (
              <>
                {failed}
                <Text bold>{rows.length}</Text> available · <Text color="green">{rows.filter((s) => s.trees.length).length} in a tree</Text> ·{" "}
                <Text color="yellow">{rows.filter((s) => s.exposed).length} fix exposed nodes</Text>
                <Text dimColor> · sorted by {sortedBy}</Text>
                {status(report.generatedAt)}
              </>
            )}
          />
        </Box>
      </Box>
    );
  }

  const report = trees.data!;
  if (report.shields.length === 0)
    return message(undefined, "no upatch in shirudo.tree_ops: load a tree with jobs/tree-ingest");
  const detailShield = detail ? (report.shields.find((s) => keyOf(s) === detail) ?? null) : null;
  const treeIds = new Set(report.shields.map((s) => s.treeId));

  return (
    <Box flexDirection="column">
      {detail && <ShieldDetail shield={detailShield} height={tableHeight} active={active} onClose={() => showDetail(null)} />}
      {/* Hidden, not unmounted, so the table keeps its cursor, sort and search. */}
      <Box flexDirection="column" display={detail ? "none" : "flex"}>
        <DataTable
          tabs={tabs}
          startOnTabs={onTabs}
          rows={report.shields}
          columns={COLUMNS}
          rowKey={keyOf}
          height={tableHeight}
          active={active && !detail}
          initialSort={{ col: "status", dir: "asc" }}
          tiebreak={tiebreak}
          searchFields={shieldFields}
          footerHint="t available · r refresh"
          onSearchingChange={reportSearching}
          onClose={onClose}
          onOpen={(s) => showDetail(keyOf(s))}
          summary={(rows, sortedBy) => {
            const count = (st: ShieldStatus) => rows.filter((s) => s.status === st).length;
            return (
              <>
                {failed}
                <Text bold>{rows.length}</Text> shields · <Text color="green">{count("deployed")} deployed</Text> ·{" "}
                <Text color="yellow">{count("pending")} pending</Text> · <Text color="gray">{count("withdrawn")} withdrawn</Text>
                <Text dimColor>
                  {" "}
                  · {treeIds.size} tree{treeIds.size === 1 ? "" : "s"} · sorted by {sortedBy}
                </Text>
                {status(report.generatedAt)}
              </>
            );
          }}
        />
      </Box>
    </Box>
  );
}
