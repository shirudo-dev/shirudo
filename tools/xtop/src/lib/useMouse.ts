// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

import { createContext, useContext, useEffect, useRef } from "react";
import type { EventEmitter } from "node:events";
import type { MouseEvent } from "./mouse.ts";

export const MouseContext = createContext<EventEmitter | null>(null);

/** Subscribe to terminal mouse events while `isActive`. */
export function useMouse(handler: (e: MouseEvent) => void, { isActive = true } = {}) {
  const events = useContext(MouseContext);
  const latest = useRef(handler);
  latest.current = handler;
  useEffect(() => {
    if (!events || !isActive) return;
    const listener = (e: MouseEvent) => latest.current(e);
    events.on("mouse", listener);
    return () => {
      events.off("mouse", listener);
    };
  }, [events, isActive]);
}
