// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// The menu of views beside the open one, and the key hints below.

import { useRef, useState } from "react";
import { Box, Text, measureElement, useApp, useInput, useWindowSize, type DOMElement } from "ink";
import type { Backend } from "./lib/backend.ts";
import { useMouse } from "./lib/useMouse.ts";
import { Panel } from "./components/Panel.tsx";
import { Sidebar, type MenuItem } from "./components/Sidebar.tsx";
import { NodesView, type NodesMode } from "./components/NodesView.tsx";
import { ShieldsView } from "./components/ShieldsView.tsx";
import { SbomView, type SbomMode } from "./components/SbomView.tsx";

type ViewId = "nodes" | "shields" | "sbom";

const MENU: readonly (MenuItem & { id: ViewId; title: string })[] = [
  { id: "nodes", label: "Nodes", title: "nodes · status from shirudo.node_status" },
  { id: "shields", label: "Shields", title: "shields · upatches of the trees in shirudo.tree_ops" },
  { id: "sbom", label: "SBOM", title: "sbom · findings from shirudo.node_vulns, images from shirudo.sbom_images" },
];
const SIDEBAR_WIDTH = 16;

type Focus = "menu" | "menu-open" | ViewId | "detail" | "search";

const HINTS: Record<Focus, string> = {
  menu: "j/k menu · l/enter open · 1 nodes · 2 shields · 3 sbom · q quit",
  "menu-open": "j/k menu · l/enter open · tab back to view · esc close view · q quit",
  nodes: "j/k scroll · k past top → sort, then tabs · / search · enter node checks, image → nodes · t by image · r refresh · tab menu · esc close · q quit",
  shields: "j/k scroll · k past top → sort · / search · enter details · r refresh · tab menu · esc close · q quit",
  sbom: "j/k scroll · k past top → sort, then tabs · / search · enter finding nodes, image → findings · t images · r refresh · tab menu · esc close · q quit",
  detail: "esc back · q quit",
  search: "type to filter · enter keep · esc clear",
};

export function App({ backend }: { backend: Backend }) {
  const { exit } = useApp();
  const { columns, rows } = useWindowSize();
  const [openView, setOpenView] = useState<ViewId | null>("nodes");
  const [menuFocused, setMenuFocused] = useState(false);
  const [menuCursor, setMenuCursor] = useState(0);
  const [searching, setSearching] = useState(false);
  const [detail, setDetail] = useState(false);
  // Kept while the app runs, so reopening Nodes keeps the toggle.
  const [nodesMode, setNodesMode] = useState<NodesMode>("nodes");
  const [sbomMode, setSbomMode] = useState<SbomMode>("findings");

  const open = (view: ViewId) => {
    setMenuCursor(MENU.findIndex((m) => m.id === view));
    setOpenView(view);
    setMenuFocused(false);
    setDetail(false);
  };
  const close = () => {
    setOpenView(null);
    setMenuFocused(true);
    setDetail(false);
  };

  const focus: Focus = searching
    ? "search"
    : !openView
      ? "menu"
      : menuFocused
        ? "menu-open"
        : detail
          ? "detail"
          : openView;
  const navActive = focus !== "search";

  useInput(
    (input, key) => {
      if (input === "q") return exit();
      if (key.tab && openView) return setMenuFocused((m) => !m);
      if (focus === "menu-open" && key.escape) return close();
      if (focus === "menu" && key.escape) return exit();
      if (focus === "menu" || focus === "menu-open") {
        const move = (d: number) => setMenuCursor((c) => Math.max(0, Math.min(MENU.length - 1, c + d)));
        if (key.upArrow) move(-1);
        if (key.downArrow) move(1);
        for (const ch of input) {
          if (ch === "k") move(-1);
          if (ch === "j") move(1);
        }
        if (key.return || input === "l") open(MENU[menuCursor]!.id);
      }
      for (const ch of input) {
        const item = MENU[Number(ch) - 1];
        if (/[1-9]/.test(ch) && item) open(item.id);
      }
    },
    { isActive: navActive },
  );

  const sidebarRef = useRef<DOMElement>(null);
  useMouse(
    (e) => {
      if (e.kind !== "press" || e.button !== "left" || !sidebarRef.current) return;
      const m = measureElement(sidebarRef.current);
      if (e.x < m.x || e.x >= m.x + m.width) return;
      // The border and the title line come before the first item.
      const item = MENU[e.y - (m.y + 2)];
      if (item) openView === item.id ? close() : open(item.id);
    },
    { isActive: navActive },
  );

  const viewHeight = Math.max(6, rows - 1);
  // Inside a panel: two border lines and a title line.
  const viewLines = viewHeight - 3;
  const view = MENU.find((m) => m.id === openView);

  return (
    <Box flexDirection="column" width={columns} height={rows}>
      <Box flexGrow={1}>
        <Box ref={sidebarRef} flexShrink={0}>
          <Sidebar items={MENU} cursor={menuCursor} openId={openView} focused={!openView || menuFocused} width={SIDEBAR_WIDTH} />
        </Box>
        {view && (
          <Panel
            title={view.title}
            borderColor={menuFocused ? "gray" : "cyan"}
            width={Math.max(20, columns - SIDEBAR_WIDTH)}
            height={viewHeight}
            overflow="hidden"
          >
            {view.id === "nodes" ? (
              <NodesView
                backend={backend}
                mode={nodesMode}
                onModeChange={setNodesMode}
                height={viewLines}
                active={!menuFocused}
                onClose={close}
                onSearchingChange={setSearching}
                onDetailChange={setDetail}
              />
            ) : view.id === "sbom" ? (
              <SbomView
                backend={backend}
                mode={sbomMode}
                onModeChange={setSbomMode}
                height={viewLines}
                active={!menuFocused}
                onClose={close}
                onSearchingChange={setSearching}
                onDetailChange={setDetail}
              />
            ) : (
              <ShieldsView
                backend={backend}
                height={viewLines}
                active={!menuFocused}
                onClose={close}
                onSearchingChange={setSearching}
                onDetailChange={setDetail}
              />
            )}
          </Panel>
        )}
      </Box>
      <Box justifyContent="center" flexShrink={0}>
        <Text dimColor wrap="truncate-end">
          {HINTS[focus]}
        </Text>
      </Box>
    </Box>
  );
}
