// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// What the SBOMs and kernels say is vulnerable on the nodes, one row per
// finding, or the images of the SBOM store and how far they are scanned.
// Enter on a finding shows its nodes; on an image, its findings.

import { useState } from "react";
import { Box, Text, useInput } from "ink";
import type { Backend } from "../lib/backend.ts";
import { ago } from "../lib/format.ts";
import { useRefreshing } from "../lib/useRefreshing.ts";
import { literalSearch } from "../lib/search.ts";
import {
  FINDING_STATUS_RANK,
  IMAGE_STATES,
  imageKey,
  type Finding,
  type FindingStatus,
  type ImageState,
  type ImagesReport,
  type SbomImage,
  type SbomReport,
} from "../lib/sbom.ts";
import { severityRank } from "../lib/shields.ts";
import { DataTable, Tabs, type Column } from "./DataTable.tsx";
import { ViewMessage } from "./ViewMessage.tsx";
import { FindingDetail } from "./FindingDetail.tsx";
import { FINDING_STATUS_STYLE, IMAGE_STATE_COLOR, SeverityText } from "./style.tsx";

export type SbomMode = "findings" | "images";

type Props = {
  backend: Backend;
  mode: SbomMode;
  onModeChange: (mode: SbomMode) => void;
  /** Lines available inside the panel. */
  height: number;
  active: boolean;
  onClose: () => void;
  onSearchingChange: (searching: boolean) => void;
  /** A finding's nodes are open. */
  onDetailChange?: (open: boolean) => void;
};

function FindingStatusCell({ f }: { f: Finding }) {
  const style = FINDING_STATUS_STYLE[f.status];
  return (
    <>
      <Text color={style.color}>{style.label}</Text>
      {f.status !== "no_shield" && f.status !== "shielded" && (
        <Text dimColor>
          {" "}
          {f.shielded}/{f.affected}
        </Text>
      )}
    </>
  );
}

// ---- findings --------------------------------------------------------------

const FINDING_COLUMNS: readonly Column<Finding>[] = [
  {
    id: "severity",
    title: "SEVERITY",
    width: 10,
    defaultDir: "asc",
    sortKey: (f) => severityRank(f.severity),
    render: (f) => <SeverityText severity={f.severity} />,
  },
  {
    id: "id",
    title: "VULNERABILITY",
    width: 18,
    defaultDir: "asc",
    sortKey: (f) => f.vulnId,
    render: (f) => <Text bold>{f.vulnId}</Text>,
  },
  {
    id: "package",
    title: "PACKAGE",
    defaultDir: "asc",
    sortKey: (f) => f.package,
    render: (f) => (
      <>
        <Text color={f.source === "kernel" ? "magenta" : "cyan"}>{f.source === "kernel" ? "kernel" : f.package}</Text>
        <Text dimColor> {f.installed.join(", ")}</Text>
      </>
    ),
  },
  {
    id: "fixed",
    title: "FIXED IN",
    width: 12,
    defaultDir: "asc",
    sortKey: (f) => f.fixed,
    render: (f) => (f.fixed ? <Text color="green">{f.fixed}</Text> : <Text dimColor>none yet</Text>),
  },
  {
    id: "nodes",
    title: "NODES",
    width: 9,
    align: "right",
    defaultDir: "desc",
    sortKey: (f) => f.affected,
    render: (f) => (
      <Text>
        <Text bold>{f.affected}</Text>
        <Text dimColor>/{f.total}</Text>
      </Text>
    ),
  },
  {
    id: "shield",
    title: "SHIELD",
    width: 14,
    defaultDir: "asc",
    sortKey: (f) => f.upatchId || "~",
    render: (f) => (f.upatchId ? <Text>{f.upatchId}</Text> : <Text dimColor>—</Text>),
  },
  {
    id: "status",
    title: "STATUS",
    width: 15,
    defaultDir: "asc",
    sortKey: (f) => FINDING_STATUS_RANK[f.status],
    render: (f) => <FindingStatusCell f={f} />,
  },
];

const findingFields = (f: Finding) =>
  [
    f.vulnId,
    f.package,
    f.severity,
    f.source,
    f.upatchId,
    f.status,
    ...f.installed,
    ...f.nodes.flatMap((n) => [n.name, `${n.imageId} ${n.imageVersion}`]),
  ];

const findingTiebreak = (a: Finding, b: Finding) =>
  severityRank(a.severity) - severityRank(b.severity) || b.affected - a.affected || a.vulnId.localeCompare(b.vulnId);

// ---- images ----------------------------------------------------------------

const STATE_RANK = Object.fromEntries(IMAGE_STATES.map((s, i) => [s, i])) as Record<ImageState, number>;

const IMAGE_COLUMNS: readonly Column<SbomImage>[] = [
  {
    id: "state",
    title: "STATE",
    width: 19,
    defaultDir: "asc",
    sortKey: (i) => STATE_RANK[i.state] * 2 + (i.stale ? 0 : 1),
    render: (i) => (
      <>
        <Text color={IMAGE_STATE_COLOR[i.state]}>{i.state}</Text>
        {i.stale && <Text color="red"> stale</Text>}
      </>
    ),
  },
  {
    id: "image",
    title: "IMAGE",
    defaultDir: "asc",
    sortKey: imageKey,
    render: (i) => (
      <>
        <Text color="cyan">{imageKey(i)}</Text>
        <Text dimColor> {i.imageRoot ? i.imageRoot.slice(0, 8) : "no root"}</Text>
      </>
    ),
  },
  {
    id: "nodes",
    title: "NODES",
    width: 6,
    align: "right",
    defaultDir: "desc",
    sortKey: (i) => i.nodes,
    render: (i) => <Text>{i.nodes}</Text>,
  },
  {
    id: "findings",
    title: "FINDINGS",
    width: 16,
    defaultDir: "desc",
    sortKey: (i) => i.critical * 1e6 + i.high * 1e3 + i.vulns,
    render: (i) =>
      i.state !== "ok" ? (
        <Text dimColor>—</Text>
      ) : (
        <>
          <Text>{i.vulns}</Text>
          {i.critical > 0 && <Text color="red"> {i.critical} crit</Text>}
          {i.high > 0 && <Text color="red"> {i.high} high</Text>}
        </>
      ),
  },
  {
    id: "scanned",
    title: "SCANNED",
    width: 8,
    align: "right",
    defaultDir: "desc",
    sortKey: (i) => i.scannedAt?.getTime() ?? 0,
    render: (i) =>
      i.scannedAt ? <Text color={i.stale ? "red" : undefined}>{ago(i.scannedAt)}</Text> : <Text dimColor>never</Text>,
  },
  {
    id: "db",
    title: "DATABASE",
    width: 21,
    defaultDir: "desc",
    sortKey: (i) => i.dbVersion,
    render: (i) => <Text dimColor>{i.dbVersion || "—"}</Text>,
  },
];

const imageFields = (i: SbomImage) =>
  [imageKey(i), i.imageRoot, i.state, i.sbomSha256, i.dbVersion, i.stale ? "stale" : ""];

// ---- view ------------------------------------------------------------------

export function SbomView({ backend, mode, onModeChange, height, active, onClose, onSearchingChange, onDetailChange }: Props) {
  const [reload, setReload] = useState(0);
  const findings = useRefreshing<SbomReport>(mode === "findings", reload, () => backend.getSbom());
  const images = useRefreshing<ImagesReport>(mode === "images", reload, () => backend.getSbomImages());
  const [searching, setSearching] = useState(false);
  // Set when drilling into an image; seeds the findings table's search.
  const [drill, setDrill] = useState("");
  const [onTabs, setOnTabs] = useState(false);
  const [detail, setDetail] = useState<string | null>(null);
  const keyOf = (f: Finding) => `${f.vulnId}\0${f.package}`;
  const detailFinding = detail ? (findings.data?.findings.find((f) => keyOf(f) === detail) ?? null) : null;

  const showDetail = (key: string | null) => {
    setDetail(key);
    onDetailChange?.(key !== null);
  };
  const reportSearching = (s: boolean) => {
    setSearching(s);
    onSearchingChange(s);
  };
  const switchTo = (m: SbomMode, fromTabs = false) => {
    setDrill("");
    setOnTabs(fromTabs);
    onModeChange(m);
  };
  const modes: SbomMode[] = ["findings", "images"];
  const tabs = {
    labels: ["findings", "images"],
    selected: modes.indexOf(mode),
    onSelect: (i: number) => switchTo(modes[i]!, true),
  };

  useInput(
    (input) => {
      if (input === "t") switchTo(mode === "findings" ? "images" : "findings");
      if (input === "r") setReload((r) => r + 1);
    },
    { isActive: active && !searching && !detail },
  );

  const tableHeight = Math.max(4, height);
  const query = mode === "findings" ? findings : images;
  if (!query.data)
    return (
      <Box flexDirection="column">
        <Tabs labels={tabs.labels} selected={tabs.selected} />
        <ViewMessage active={active && !searching} onClose={onClose} color={query.error ? "red" : undefined}>
          {query.error ? `${mode} query failed: ${query.error}` : "querying backend…"}
        </ViewMessage>
      </Box>
    );
  const status = (generatedAt: Date) => (
    <>
      <Text dimColor> · as of {generatedAt.toTimeString().slice(0, 8)}</Text>
      {query.loading && <Text dimColor> · querying…</Text>}
    </>
  );
  const failed = query.error && <Text color="red">refresh failed: {query.error} · </Text>;

  if (mode === "images") {
    const report = images.data!;
    return (
      <DataTable
        tabs={tabs}
        startOnTabs={onTabs}
        footerHint="t findings · r refresh"
        rows={report.images}
        columns={IMAGE_COLUMNS}
        rowKey={(i) => `${imageKey(i)} ${i.imageRoot}`}
        height={tableHeight}
        active={active}
        initialSort={{ col: "state", dir: "asc" }}
        tiebreak={(a, b) => b.nodes - a.nodes || imageKey(a).localeCompare(imageKey(b))}
        searchFields={imageFields}
        onSearchingChange={reportSearching}
        onClose={onClose}
        onOpen={(i) => {
          setOnTabs(false);
          setDrill(literalSearch(imageKey(i)));
          onModeChange("findings");
        }}
        summary={(rows, sortedBy) => {
          const count = (s: ImageState) => rows.filter((i) => i.state === s).length;
          const bad = rows.filter((i) => i.state !== "ok" && i.state !== "no_sbom").length;
          return (
            <>
              {failed}
              <Text bold>{rows.length}</Text> images · <Text color="green">{count("ok")} scanned</Text> ·{" "}
              <Text color="red">{rows.filter((i) => i.stale).length} stale</Text> · <Text color="red">{bad} refused</Text> ·{" "}
              <Text color="yellow">{count("no_sbom")} without an SBOM</Text>
              <Text dimColor> · sorted by {sortedBy}</Text>
              {status(report.generatedAt)}
            </>
          );
        }}
      />
    );
  }

  const report = findings.data!;
  return (
    <Box flexDirection="column">
      {detail && <FindingDetail finding={detailFinding} height={tableHeight} active={active} onClose={() => showDetail(null)} />}
      {/* Hidden, not unmounted, so the table keeps its cursor, sort and search. */}
      <Box flexDirection="column" display={detail ? "none" : "flex"}>
        <DataTable
          key={`findings:${drill}`}
          tabs={tabs}
          startOnTabs={onTabs}
          footerHint="t images · r refresh"
          rows={report.findings}
          columns={FINDING_COLUMNS}
          rowKey={keyOf}
          height={tableHeight}
          active={active && !detail}
          initialSort={{ col: "status", dir: "asc" }}
          initialQuery={drill}
          tiebreak={findingTiebreak}
          searchFields={findingFields}
          onSearchingChange={reportSearching}
          onClose={onClose}
          onOpen={(f) => showDetail(keyOf(f))}
          summary={(rows, sortedBy) => {
            const count = (s: FindingStatus) => rows.filter((f) => f.status === s).length;
            const stale = rows.some((f) => f.stale);
            return (
              <>
                {failed}
                <Text bold>{rows.length}</Text> findings · <Text color="red">{count("no_shield")} no shield</Text> ·{" "}
                <Text color="yellow">{count("partial")} partial</Text> · <Text color="yellow">{count("pending")} pending</Text> ·{" "}
                <Text color="green">{count("shielded")} shielded</Text>
                {stale && <Text color="red"> · from a stale scan</Text>}
                <Text dimColor> · sorted by {sortedBy}</Text>
                {status(report.generatedAt)}
              </>
            );
          }}
        />
      </Box>
    </Box>
  );
}
