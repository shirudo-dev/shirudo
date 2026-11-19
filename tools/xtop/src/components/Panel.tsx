// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

import { forwardRef, type ReactNode } from "react";
import { Box, Text, type BoxProps, type DOMElement } from "ink";

type Props = BoxProps & { title: string; children: ReactNode };

/** Rounded bordered box with a title line. */
export const Panel = forwardRef<DOMElement, Props>(function Panel(
  { title, children, ...box },
  ref,
) {
  return (
    <Box
      ref={ref}
      borderStyle="round"
      borderColor="gray"
      flexDirection="column"
      paddingX={1}
      flexShrink={0}
      {...box}
    >
      <Text color="gray">{title}</Text>
      {children}
    </Box>
  );
});
