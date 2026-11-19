// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Every upatch of every tree the backend has loaded, with what it fixes
// and how its newest operation rolled out. Enter shows one.

import { useState } from "react";
import { Box, Text, useInput } from "ink";
import type { ReactNode } from "react";
import type { Backend } from "../lib/backend.ts";
import { useRefreshing } from "../lib/useRefreshing.ts";
import {
  SHIELD_STATUS_RANK,
  severityRank,
  shieldTarget,
  targeted,
  type Rollout,
  type Shield,
  type ShieldStatus,
  type ShieldsReport,
} from "../lib/shields.ts";
import { DataTable, type Column } from "./DataTable.tsx";
import { ViewMessage } from "./ViewMessage.tsx";
import { MiniBar } from "./MiniBar.tsx";
import { ShieldDetail } from "./ShieldDetail.tsx";
import { SHIELD_STATUS_COLOR, SeverityText } from "./style.tsx";

type Props = {
  backend: Backend;
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

const matches = (s: Shield, q: string) =>
  [
    s.id,
    s.treeId,
    s.status,
    s.severity,
    s.manifestDigest,
    s.repository,
    ...s.advisories.flatMap((a) => [a.id, a.package, a.source]),
    ...s.images,
  ].some((x) => x.toLowerCase().includes(q));

// Ties: worst severity first, then name.
const tiebreak = (a: Shield, b: Shield) => severityRank(a.severity) - severityRank(b.severity) || a.id.localeCompare(b.id);

export function ShieldsView({ backend, height, active, onClose, onSearchingChange, onDetailChange }: Props) {
  const [reload, setReload] = useState(0);
  const query = useRefreshing<ShieldsReport>(true, reload, () => backend.getShields());
  const [searching, setSearching] = useState(false);
  const [detail, setDetail] = useState<string | null>(null);
  const keyOf = (s: Shield) => `${s.treeId}\0${s.id}`;
  const detailShield = detail ? (query.data?.shields.find((s) => keyOf(s) === detail) ?? null) : null;

  const showDetail = (key: string | null) => {
    setDetail(key);
    onDetailChange?.(key !== null);
  };
  const reportSearching = (s: boolean) => {
    setSearching(s);
    onSearchingChange(s);
  };

  useInput(
    (input) => {
      if (input === "r") setReload((r) => r + 1);
    },
    { isActive: active && !searching && !detail },
  );

  const message = (color: string | undefined, text: ReactNode) => (
    <ViewMessage active={active && !searching} onClose={onClose} color={color}>
      {text}
    </ViewMessage>
  );
  if (!query.data)
    return query.error ? message("red", `shields query failed: ${query.error}`) : message(undefined, "querying backend…");
  const report = query.data;
  if (report.shields.length === 0)
    return message(undefined, "no upatch in shirudo.tree_ops: load a tree with jobs/tree-ingest");
  const tableHeight = Math.max(4, height);
  const trees = new Set(report.shields.map((s) => s.treeId));

  return (
    <Box flexDirection="column">
      {detail && <ShieldDetail shield={detailShield} height={tableHeight} active={active} onClose={() => showDetail(null)} />}
      {/* Hidden, not unmounted, so the table keeps its cursor, sort and search. */}
      <Box flexDirection="column" display={detail ? "none" : "flex"}>
        <DataTable
          rows={report.shields}
          columns={COLUMNS}
          rowKey={keyOf}
          height={tableHeight}
          active={active && !detail}
          initialSort={{ col: "status", dir: "asc" }}
          tiebreak={tiebreak}
          matches={matches}
          footerHint="r refresh"
          onSearchingChange={reportSearching}
          onClose={onClose}
          onOpen={(s) => showDetail(keyOf(s))}
          summary={(rows, sortedBy) => {
            const count = (st: ShieldStatus) => rows.filter((s) => s.status === st).length;
            return (
              <>
                {query.error && <Text color="red">refresh failed: {query.error} · </Text>}
                <Text bold>{rows.length}</Text> shields · <Text color="green">{count("deployed")} deployed</Text> ·{" "}
                <Text color="yellow">{count("pending")} pending</Text> · <Text color="gray">{count("withdrawn")} withdrawn</Text>
                <Text dimColor>
                  {" "}
                  · {trees.size} tree{trees.size === 1 ? "" : "s"} · sorted by {sortedBy} · as of{" "}
                  {report.generatedAt.toTimeString().slice(0, 8)}
                </Text>
                {query.loading && <Text dimColor> · querying…</Text>}
              </>
            );
          }}
        />
      </Box>
    </Box>
  );
}
