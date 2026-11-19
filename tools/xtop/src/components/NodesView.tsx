// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// The fleet from shirudo.node_status: one row per node, or one per image
// with its members rolled up. Enter on a node shows its check lines.

import { useMemo, useState } from "react";
import { Box, Text, useInput } from "ink";
import type { Backend } from "../lib/backend.ts";
import {
  STATUS_RANK,
  STATUSES,
  failedCheckName,
  groupByImage,
  healthPercent,
  imageLabel,
  type FleetNode,
  type FleetReport,
  type ImageGroup,
  type NodeStatus,
  type Shields,
} from "../lib/fleet.ts";
import { DataTable, Tabs, type Column } from "./DataTable.tsx";
import { NodeDetail } from "./NodeDetail.tsx";
import { HealthCell } from "./MiniBar.tsx";
import { ago } from "../lib/format.ts";
import { useRefreshing } from "../lib/useRefreshing.ts";
import { STATUS_STYLE } from "./style.tsx";

export type NodesMode = "nodes" | "images";

type Props = {
  backend: Backend;
  mode: NodesMode;
  onModeChange: (mode: NodesMode) => void;
  /** Lines available inside the panel. */
  height: number;
  active: boolean;
  onClose: () => void;
  onSearchingChange: (searching: boolean) => void;
  /** The check lines of a node are open. */
  onDetailChange?: (open: boolean) => void;
};

function StatusCell({ status }: { status: NodeStatus }) {
  return (
    <Text color={STATUS_STYLE[status].color}>
      {STATUS_STYLE[status].icon} {status}
    </Text>
  );
}

function ShieldsCell({ s }: { s: Shields }) {
  return (
    <>
      <Text color={s.applied ? "green" : "gray"}>{s.applied}✓</Text>
      {s.pending > 0 && <Text color="yellow"> {s.pending}…</Text>}
      {s.idle > 0 && <Text color="red"> {s.idle}✗</Text>}
    </>
  );
}

function ExposedCell({ exposed, unknown }: { exposed: number; unknown: number }) {
  return (
    <>
      {unknown > 0 && <Text color="yellow">? </Text>}
      <Text color={exposed ? "yellow" : "green"}>{exposed}</Text>
    </>
  );
}

function TreeCell({ last, head, atLeast = false }: { last: number | null; head: number | null; atLeast?: boolean }) {
  if (last === null) return <Text dimColor>no tree</Text>;
  if (head === null) return <Text dimColor>#{last}</Text>;
  if (last < head)
    return (
      <Text color="yellow">
        {atLeast ? "≥" : ""}#{last}/#{head}
      </Text>
    );
  return <Text color="green">✓ #{head}</Text>;
}

const shieldsKey = (s: Shields) => s.idle * 1000 + s.pending;
const imageCell = (id: string | null, version: string | null) =>
  id === null ? <Text dimColor>{imageLabel(id, version)}</Text> : <Text color="cyan">{imageLabel(id, version)}</Text>;

// ---- per-node table --------------------------------------------------------

const NODE_COLUMNS: readonly Column<FleetNode>[] = [
  { id: "status", title: "STATUS", width: 12, defaultDir: "asc", sortKey: (n) => STATUS_RANK[n.status], render: (n) => <StatusCell status={n.status} /> },
  {
    id: "trust",
    title: "TRUST",
    width: 10,
    defaultDir: "asc",
    sortKey: (n) => n.trust,
    render: (n) => <Text color={n.trust === "enrolled" ? "green" : "yellow"}>{n.trust}</Text>,
  },
  { id: "name", title: "NODE", defaultDir: "asc", sortKey: (n) => n.name, render: (n) => <Text bold>{n.name}</Text> },
  {
    id: "check",
    title: "CHECK",
    width: 13,
    defaultDir: "desc",
    sortKey: (n) => n.failedCheck,
    render: (n) => (n.failedCheck ? <Text color="red">{failedCheckName(n)}</Text> : <Text dimColor>—</Text>),
  },
  { id: "image", title: "IMAGE", width: 20, defaultDir: "asc", sortKey: (n) => imageLabel(n.imageId, n.imageVersion), render: (n) => imageCell(n.imageId, n.imageVersion) },
  { id: "kernel", title: "KERNEL", width: 10, defaultDir: "asc", sortKey: (n) => n.kernel, render: (n) => <Text>{n.kernel}</Text> },
  { id: "version", title: "BUILD", width: 9, defaultDir: "asc", sortKey: (n) => n.version, render: (n) => <Text dimColor>{n.version.slice(0, 8)}</Text> },
  {
    id: "tree",
    title: "TREE",
    width: 10,
    defaultDir: "asc",
    sortKey: (n) => (n.tree.lastSeq === null ? -1 : n.tree.lastSeq - (n.tree.headSeq ?? n.tree.lastSeq)),
    render: (n) => <TreeCell last={n.tree.lastSeq} head={n.tree.headSeq} />,
  },
  { id: "shields", title: "SHIELDS", width: 12, defaultDir: "desc", sortKey: (n) => shieldsKey(n.shields), render: (n) => <ShieldsCell s={n.shields} /> },
  {
    id: "exposed",
    title: "EXPOSED",
    width: 8,
    align: "right",
    defaultDir: "desc",
    sortKey: (n) => n.exposed * 1000 + n.unknown,
    render: (n) => <ExposedCell exposed={n.exposed} unknown={n.unknown} />,
  },
  {
    id: "seen",
    title: "SEEN",
    width: 6,
    align: "right",
    defaultDir: "desc",
    sortKey: (n) => n.lastSeen.getTime(),
    render: (n) => <Text color={n.status === "stale" ? "red" : undefined}>{ago(n.lastSeen)}</Text>,
  },
];

const nodeMatches = (n: FleetNode, q: string) =>
  [
    n.name,
    n.hostName,
    n.akName,
    n.status,
    n.trust,
    imageLabel(n.imageId, n.imageVersion),
    n.kernel,
    n.version,
    n.failedCheck ? (n.log[n.failedCheck - 1] ?? "") : "",
  ].some((s) => s.toLowerCase().includes(q));

// ---- per-image table -------------------------------------------------------

const IMAGE_COLUMNS: readonly Column<ImageGroup>[] = [
  { id: "status", title: "STATUS", width: 12, defaultDir: "asc", sortKey: (g) => STATUS_RANK[g.status], render: (g) => <StatusCell status={g.status} /> },
  { id: "image", title: "IMAGE", defaultDir: "asc", sortKey: (g) => g.key, render: (g) => imageCell(g.imageId, g.imageVersion) },
  {
    id: "nodes",
    title: "NODES",
    width: 11,
    defaultDir: "desc",
    sortKey: (g) => g.nodes,
    render: (g) => (
      <>
        <Text bold>{String(g.nodes).padStart(2)}</Text>
        {STATUSES.filter((s) => s !== "healthy" && g.statuses[s] > 0).map((s) => (
          <Text key={s} color={STATUS_STYLE[s].color}>
            {" "}
            {g.statuses[s]}
            {STATUS_STYLE[s].icon}
          </Text>
        ))}
      </>
    ),
  },
  { id: "health", title: "HEALTH", width: 12, defaultDir: "asc", sortKey: (g) => g.health, render: (g) => <HealthCell health={g.health} bar={5} /> },
  {
    id: "kernel",
    title: "KERNEL",
    width: 10,
    defaultDir: "asc",
    sortKey: (g) => g.kernel ?? "~",
    render: (g) => (g.kernel === null ? <Text color="yellow">mixed</Text> : <Text>{g.kernel}</Text>),
  },
  {
    id: "tree",
    title: "TREE",
    width: 11,
    defaultDir: "asc",
    sortKey: (g) => (g.tree.minLastSeq === null ? -1 : g.tree.minLastSeq - (g.tree.headSeq ?? g.tree.minLastSeq)),
    render: (g) => <TreeCell last={g.tree.minLastSeq} head={g.tree.headSeq} atLeast />,
  },
  { id: "shields", title: "SHIELDS", width: 12, defaultDir: "desc", sortKey: (g) => shieldsKey(g.shields), render: (g) => <ShieldsCell s={g.shields} /> },
  {
    id: "exposed",
    title: "EXPOSED",
    width: 8,
    align: "right",
    defaultDir: "desc",
    sortKey: (g) => g.exposed * 1000 + g.unknown,
    render: (g) => <ExposedCell exposed={g.exposed} unknown={g.unknown} />,
  },
  {
    id: "seen",
    title: "SEEN",
    width: 6,
    align: "right",
    defaultDir: "desc",
    sortKey: (g) => g.lastSeen.getTime(),
    render: (g) => <Text color={g.statuses.stale === g.nodes ? "red" : undefined}>{ago(g.lastSeen)}</Text>,
  },
];

const imageMatches = (g: ImageGroup, q: string) =>
  [g.key, g.status, g.kernel ?? "mixed"].some((s) => s.toLowerCase().includes(q));

// ---- view ------------------------------------------------------------------

function HealthSummary({ health }: { health: number | null }) {
  if (health === null) return <Text dimColor>health —</Text>;
  return (
    <>
      health <HealthCell health={health} bar={8} />
    </>
  );
}

export function NodesView({ backend, mode, onModeChange, height, active, onClose, onSearchingChange, onDetailChange }: Props) {
  const [reload, setReload] = useState(0);
  const fleet = useRefreshing<FleetReport>(true, reload, () => backend.getFleet());
  const images = useMemo(() => (fleet.data ? groupByImage(fleet.data.nodes) : []), [fleet.data]);
  const [searching, setSearching] = useState(false);
  // Set when drilling into an image; seeds the nodes table's search.
  const [drill, setDrill] = useState("");
  // After switching from the tabs, keep the cursor there in the new table.
  const [onTabs, setOnTabs] = useState(false);
  const [detail, setDetail] = useState<string | null>(null);
  // The open node as of the newest query, so a refresh updates the pane.
  const detailNode = detail ? (fleet.data?.nodes.find((n) => n.akName === detail) ?? null) : null;

  const showDetail = (ak: string | null) => {
    setDetail(ak);
    onDetailChange?.(ak !== null);
  };
  const reportSearching = (s: boolean) => {
    setSearching(s);
    onSearchingChange(s);
  };
  const switchTo = (m: NodesMode, fromTabs = false) => {
    setDrill("");
    setOnTabs(fromTabs);
    onModeChange(m);
  };
  const modes: NodesMode[] = ["nodes", "images"];
  const tabs = {
    labels: ["nodes", "by image"],
    selected: modes.indexOf(mode),
    onSelect: (i: number) => switchTo(modes[i]!, true),
  };

  useInput(
    (input) => {
      if (input === "t") switchTo(mode === "nodes" ? "images" : "nodes");
      if (input === "r") setReload((r) => r + 1);
    },
    { isActive: active && !searching && !detail },
  );

  const tableHeight = Math.max(4, height);
  const asOf = (r: FleetReport) => (
    <>
      <Text dimColor> · as of {r.generatedAt.toTimeString().slice(0, 8)}</Text>
      {fleet.loading && <Text dimColor> · querying…</Text>}
    </>
  );

  // First on the line, so a narrow terminal does not cut the reason off.
  const failed = fleet.error && <Text color="red">refresh failed: {fleet.error} · </Text>;

  if (!fleet.data)
    return (
      <Box flexDirection="column">
        <Tabs labels={tabs.labels} selected={tabs.selected} />
        {fleet.error ? <Text color="red">node query failed: {fleet.error}</Text> : <Text dimColor>querying backend…</Text>}
      </Box>
    );
  const report = fleet.data;

  return (
    <Box flexDirection="column">
      {detail && (
        <NodeDetail node={detailNode} height={tableHeight} active={active} onClose={() => showDetail(null)} />
      )}
      {/* Hidden, not unmounted, so the table keeps its cursor, sort and search. */}
      <Box flexDirection="column" display={detail ? "none" : "flex"}>
        {mode === "nodes" ? (
          <DataTable
            key={`nodes:${drill}`}
            tabs={tabs}
            startOnTabs={onTabs}
            footerHint="t by image · r refresh"
            rows={report.nodes}
            columns={NODE_COLUMNS}
            rowKey={(n) => n.akName}
            height={tableHeight}
            active={active && !detail}
            initialSort={{ col: "status", dir: "asc" }}
            initialQuery={drill}
            tiebreak={(a, b) => b.failedCheck - a.failedCheck || a.name.localeCompare(b.name)}
            matches={nodeMatches}
            onSearchingChange={reportSearching}
            onClose={onClose}
            onOpen={(n) => showDetail(n.akName)}
            summary={(rows, sortedBy) => {
              const count = (s: NodeStatus) => rows.filter((n) => n.status === s).length;
              return (
                <>
                  {failed}
                  <Text bold>{rows.length}</Text> nodes · <HealthSummary health={healthPercent(rows)} /> ·{" "}
                  <Text color="green">{count("healthy")} healthy</Text> · <Text color="red">{count("unhealthy")} unhealthy</Text> ·{" "}
                  <Text color="gray">{count("stale")} stale</Text> ·{" "}
                  <Text color="yellow">{rows.filter((n) => n.trust === "untrusted").length} untrusted</Text>
                  <Text dimColor> · sorted by {sortedBy}</Text>
                  {asOf(report)}
                </>
              );
            }}
          />
        ) : (
          <DataTable
            tabs={tabs}
            startOnTabs={onTabs}
            footerHint="t nodes · r refresh"
            rows={images}
            columns={IMAGE_COLUMNS}
            rowKey={(g) => g.key}
            height={tableHeight}
            active={active && !detail}
            initialSort={{ col: "status", dir: "asc" }}
            tiebreak={(a, b) => a.health - b.health || b.nodes - a.nodes}
            matches={imageMatches}
            onSearchingChange={reportSearching}
            onClose={onClose}
            onOpen={(g) => {
              setOnTabs(false);
              setDrill(g.key);
              onModeChange("nodes");
            }}
            summary={(rows, sortedBy) => {
              const members = report.nodes.filter((n) => rows.some((g) => g.key === imageLabel(n.imageId, n.imageVersion)));
              return (
                <>
                  {failed}
                  <Text bold>{rows.length}</Text> images · {members.length} nodes · <HealthSummary health={healthPercent(members)} />{" "}
                  · <Text color="red">{rows.filter((g) => g.statuses.unhealthy).length} with unhealthy</Text> ·{" "}
                  <Text color="gray">{rows.filter((g) => g.statuses.stale).length} with stale</Text>
                  <Text dimColor> · sorted by {sortedBy}</Text>
                  {asOf(report)}
                </>
              );
            }}
          />
        )}
      </Box>
    </Box>
  );
}
