// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// The line a view shows in place of its table, while it queries, after a
// failed query or with nothing to list: it closes the view as the table
// would, or h and esc would do nothing there.

import type { ReactNode } from "react";
import { Text, useInput } from "ink";

type Props = {
  active: boolean;
  onClose: () => void;
  color?: string;
  children: ReactNode;
};

export function ViewMessage({ active, onClose, color, children }: Props) {
  useInput(
    (input, key) => {
      if (key.escape || input === "h") onClose();
    },
    { isActive: active },
  );
  return (
    <Text color={color} dimColor={!color}>
      {children}
    </Text>
  );
}
