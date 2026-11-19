// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

import { Box, Text } from "ink";
import { Panel } from "./Panel.tsx";

export type MenuItem = { id: string; label: string; badge?: string };

type Props = {
  items: readonly MenuItem[];
  cursor: number;
  /** Id of the item whose view is open, if any. */
  openId: string | null;
  /** Whether the menu has keyboard focus. */
  focused: boolean;
  width: number;
};

export function Sidebar({ items, cursor, openId, focused, width }: Props) {
  return (
    <Panel title="menu" width={width}>
      {items.map((item, i) => {
        const open = item.id === openId;
        const selected = focused && i === cursor;
        return (
          <Box key={item.id}>
            <Text color={selected ? "cyan" : undefined} bold={selected || open} inverse={selected}>
              {open ? "▾ " : "▸ "}
              {item.label}
            </Text>
            {item.badge && <Text color="yellow"> {item.badge}</Text>}
          </Box>
        );
      })}
    </Panel>
  );
}
