// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Box, Text, measureElement, useInput, usePaste, type DOMElement } from "ink";
import { useMouse } from "../lib/useMouse.ts";

export type SortDir = "asc" | "desc";

export type Column<T> = {
  id: string;
  title: string;
  /** Fixed width, or flexible when omitted. */
  width?: number;
  align?: "right";
  /** Direction used when the column is first sorted. */
  defaultDir: SortDir;
  sortKey: (row: T) => number | string;
  render: (row: T) => ReactNode;
};

type Props<T> = {
  rows: readonly T[];
  columns: readonly Column<T>[];
  rowKey: (row: T) => string;
  /** Lines available for the whole table: summary, search, header, rows, footer. */
  height: number;
  /** Whether keyboard and mouse drive this table. */
  active: boolean;
  initialSort: { col: string; dir: SortDir };
  /** Breaks ties after the sorted column. */
  tiebreak?: (a: T, b: T) => number;
  /** Line above the table; receives the visible (filtered, sorted) rows. */
  summary?: (rows: readonly T[], sortedBy: string) => ReactNode;
  /** Enables `/` search; returns whether a row matches the lowercased query. */
  matches?: (row: T, query: string) => boolean;
  /** Search text to start with (e.g. when drilling into a group). */
  initialQuery?: string;
  /**
   * Optional row of view tabs above the table. Keyboard: k past the header
   * reaches it, h/l picks, Enter switches. Clicking a tab switches.
   */
  tabs?: { labels: readonly string[]; selected: number; onSelect: (i: number) => void };
  /** Start with the cursor on the tabs (e.g. right after switching tab). */
  startOnTabs?: boolean;
  /** Dim text at the bottom right, on the scroll footer's line. */
  footerHint?: string;
  /** Search box takes every key while typing. */
  onSearchingChange?: (searching: boolean) => void;
  onClose: () => void;
  /** Enter or click on a row. */
  onOpen?: (row: T) => void;
};

const compare = (a: number | string, b: number | string) =>
  typeof a === "number" && typeof b === "number"
    ? a - b
    : String(a).localeCompare(String(b), undefined, { numeric: true });

function Cell<T>({
  col,
  children,
  inverse,
  cellRef,
}: {
  col: Column<T>;
  children: ReactNode;
  inverse?: boolean;
  cellRef?: (el: DOMElement | null) => void;
}) {
  return (
    <Box
      ref={cellRef}
      width={col.width}
      flexGrow={col.width ? 0 : 1}
      flexBasis={col.width ? undefined : 0}
      flexShrink={col.width ? 0 : 1}
      minWidth={col.width ? undefined : 8}
      justifyContent={col.align === "right" ? "flex-end" : undefined}
      paddingRight={1}
    >
      <Text inverse={inverse} wrap="truncate-end">
        {children}
      </Text>
    </Box>
  );
}

/** Cursor positions above the body rows. */
const HEADER = -1;
const TABS = -2;

/**
 * Sortable, scrollable, optionally searchable table. Keyboard: j/k ↑↓ rows,
 * k past the top reaches the header where h/l ←→ pick a column and Enter
 * sorts; g/G, ^d/^u, PgUp/PgDn; / searches; Enter or l opens a row; h or Esc
 * closes. Mouse: click a header to sort, click a row to open, wheel scrolls.
 */
export function DataTable<T>({
  rows: input,
  columns,
  rowKey,
  height,
  active,
  initialSort,
  tiebreak,
  summary,
  matches,
  initialQuery = "",
  tabs,
  startOnTabs = false,
  footerHint,
  onSearchingChange,
  onClose,
  onOpen,
}: Props<T>) {
  const [cursor, setCursor] = useState(tabs && startOnTabs ? TABS : 0);
  const [tabFocus, setTabFocus] = useState(tabs?.selected ?? 0);
  const tabRefs = useRef<(DOMElement | null)[]>([]);
  const [top, setTop] = useState(0);
  const [headerCol, setHeaderCol] = useState(0);
  const [sort, setSort] = useState(initialSort);
  const [query, setQuery] = useState(initialQuery);
  const [searching, setSearching] = useState(false);
  const headerRefs = useRef<(DOMElement | null)[]>([]);

  useEffect(() => onSearchingChange?.(searching), [searching, onSearchingChange]);
  useEffect(() => () => onSearchingChange?.(false), [onSearchingChange]);

  const rows = useMemo(() => {
    const col = columns.find((c) => c.id === sort.col) ?? columns[0]!;
    const sign = sort.dir === "asc" ? 1 : -1;
    const q = query.trim().toLowerCase();
    return input
      .filter((r) => !q || !matches || matches(r, q))
      .sort((a, b) => sign * compare(col.sortKey(a), col.sortKey(b)) || (tiebreak?.(a, b) ?? 0));
  }, [input, columns, sort, query, matches, tiebreak]);

  // Tabs, summary, search, header and scroll footer each take a line.
  const chrome = (tabs ? 1 : 0) + (summary ? 1 : 0) + (matches ? 1 : 0) + 2;
  const visible = Math.max(1, height - chrome);
  const last = rows.length - 1;

  useEffect(() => {
    const c = Math.max(0, cursor);
    setTop((t) => Math.max(0, Math.min(Math.max(t, c - visible + 1), c, Math.max(0, rows.length - visible))));
  }, [cursor, visible, rows.length]);

  // A new query starts at the top of the results (not on mount, which would
  // undo startOnTabs).
  const lastQuery = useRef(query);
  useEffect(() => {
    if (lastQuery.current === query) return;
    lastQuery.current = query;
    setCursor(0);
  }, [query]);

  const sortBy = (i: number) => {
    const col = columns[i]!;
    setHeaderCol(i);
    setSort((s) => (s.col === col.id ? { col: col.id, dir: s.dir === "asc" ? "desc" : "asc" } : { col: col.id, dir: col.defaultDir }));
  };
  const move = (d: number) => setCursor((c) => Math.max(tabs ? TABS : HEADER, Math.min(last, c + d)));
  const moveRows = (d: number) => setCursor((c) => Math.max(0, Math.min(last, Math.max(0, c) + d)));
  const moveCol = (d: number) => setHeaderCol((i) => (i + d + columns.length) % columns.length);

  useInput(
    (ch, key) => {
      if (searching) {
        if (key.return) setSearching(false);
        else if (key.escape) {
          setQuery("");
          setSearching(false);
        } else if (key.backspace || key.delete) setQuery((q) => q.slice(0, -1));
        else if (key.ctrl && ch === "u") setQuery("");
        else if (!key.ctrl && !key.meta && ch) setQuery((q) => q + ch.replace(/[\x00-\x1f]/g, ""));
        return;
      }
      const half = Math.max(1, Math.floor(visible / 2));
      if (key.escape) return query ? setQuery("") : onClose();
      if (cursor === TABS && tabs) {
        const n = tabs.labels.length;
        if (key.leftArrow || ch === "h") return setTabFocus((i) => (i + n - 1) % n);
        if (key.rightArrow || ch === "l") return setTabFocus((i) => (i + 1) % n);
        if (key.return) return tabFocus !== tabs.selected && tabs.onSelect(tabFocus);
      } else if (cursor === HEADER) {
        if (key.leftArrow || ch === "h") return moveCol(-1);
        if (key.rightArrow || ch === "l") return moveCol(1);
        if (key.return) return sortBy(headerCol);
      } else if (ch === "h") return onClose();
      else if (key.return || ch === "l") {
        const row = rows[cursor];
        if (row && onOpen) return onOpen(row);
      }
      if (key.upArrow) move(-1);
      else if (key.downArrow) move(1);
      else if (key.pageUp) moveRows(-visible);
      else if (key.pageDown) moveRows(visible);
      else if (key.home) setCursor(0);
      else if (key.end) setCursor(last);
      else if (key.ctrl && ch === "d") moveRows(half);
      else if (key.ctrl && ch === "u") moveRows(-half);
      else if (key.ctrl && ch === "f") moveRows(visible);
      else if (key.ctrl && ch === "b") moveRows(-visible);
      else if (!key.ctrl && !key.meta) {
        // Vim keys; fast typing can deliver several in one chunk.
        for (const c of ch) {
          if (c === "j") move(1);
          else if (c === "k") move(-1);
          else if (c === "g") setCursor(0);
          else if (c === "G") setCursor(last);
          else if (c === "/" && matches) setSearching(true);
        }
      }
    },
    { isActive: active },
  );

  usePaste((text) => setQuery((q) => q + text.replace(/\s+/g, " ").trim()), { isActive: active && searching });

  useMouse(
    (e) => {
      const header = headerRefs.current[0];
      if (!header) return;
      const headerY = measureElement(header).y;
      if (e.kind === "wheel") return moveRows(e.direction === "down" ? 3 : -3);
      if (e.kind !== "press" || e.button !== "left") return;
      if (tabs) {
        const i = tabRefs.current.findIndex((el) => {
          if (!el) return false;
          const m = measureElement(el);
          return e.y === m.y && e.x >= m.x && e.x < m.x + m.width;
        });
        if (i >= 0) return i !== tabs.selected && tabs.onSelect(i);
      }
      if (matches && e.y === headerY - 1) return setSearching(true);
      if (e.y === headerY) {
        const i = headerRefs.current.findIndex((el) => {
          if (!el) return false;
          const m = measureElement(el);
          return e.x >= m.x && e.x < m.x + m.width;
        });
        if (i >= 0) {
          sortBy(i);
          setCursor(HEADER);
        }
      } else if (e.y > headerY && e.y <= headerY + Math.min(visible, rows.length - top)) {
        const i = top + (e.y - headerY - 1);
        setCursor(i);
        if (rows[i] && onOpen) onOpen(rows[i]);
      }
    },
    { isActive: active },
  );

  const sortCol = columns.find((c) => c.id === sort.col) ?? columns[0]!;
  const sortedBy = `${sortCol.title.toLowerCase()} ${sort.dir === "asc" ? "▲" : "▼"}`;

  return (
    <Box flexDirection="column">
      {tabs && <Tabs labels={tabs.labels} selected={tabs.selected} focused={active && cursor === TABS ? tabFocus : null} tabRefs={tabRefs} />}
      {summary && <Text wrap="truncate-end">{summary(rows, sortedBy)}</Text>}
      {matches && (
        <Text wrap="truncate-end">
          <Text color={searching ? "cyan" : "gray"}>/ </Text>
          {query ? <Text>{query}</Text> : !searching && <Text dimColor>search</Text>}
          {searching && <Text inverse> </Text>}
          {query && !searching && <Text dimColor>  esc clears</Text>}
        </Text>
      )}
      <Box>
        {columns.map((col, i) => {
          const sorted = sort.col === col.id;
          const focused = active && cursor === HEADER && headerCol === i;
          return (
            <Cell key={col.id} col={col} inverse={focused} cellRef={(el) => (headerRefs.current[i] = el)}>
              <Text color={sorted ? "cyan" : "gray"} bold={sorted}>
                {col.title}
                {sorted ? (sort.dir === "asc" ? " ▲" : " ▼") : ""}
              </Text>
            </Cell>
          );
        })}
      </Box>
      {/* Rows live in their own fixed box so the footer below always stays below them. */}
      <Box flexDirection="column" height={Math.min(visible, Math.max(1, rows.length))} flexShrink={0} overflow="hidden">
        {rows.length === 0 && <Text dimColor>{query ? `nothing matches “${query}”` : "no rows"}</Text>}
        {rows.slice(top, top + visible).map((r, i) => {
          const selected = active && top + i === cursor;
          return (
            <Box key={rowKey(r)} flexShrink={0}>
              {columns.map((col) => (
                <Cell key={col.id} col={col} inverse={selected}>
                  {col.render(r)}
                </Cell>
              ))}
            </Box>
          );
        })}
      </Box>
      {(rows.length > visible || footerHint) && (
        <Box justifyContent="space-between">
          <Text dimColor>
            {rows.length > visible ? `${top + 1}–${Math.min(rows.length, top + visible)} of ${rows.length}` : ""}
          </Text>
          {footerHint && <Text dimColor>{footerHint}</Text>}
        </Box>
      )}
    </Box>
  );
}

/**
 * View tabs: the selected one is cyan with a filled dot; the one under the
 * keyboard cursor is inverse. Exported so a view can show the same row while
 * its data loads.
 */
export function Tabs({
  labels,
  selected,
  focused = null,
  tabRefs,
}: {
  labels: readonly string[];
  selected: number;
  focused?: number | null;
  tabRefs?: { current: (DOMElement | null)[] };
}) {
  return (
    <Box>
      {labels.map((label, i) => (
        <Box key={label} ref={(el) => void (tabRefs && (tabRefs.current[i] = el))} marginRight={1}>
          <Text inverse={focused === i} color={i === selected ? "cyan" : "gray"} bold={i === selected}>
            {i === selected ? "●" : "○"} {label}
          </Text>
        </Box>
      ))}
    </Box>
  );
}
