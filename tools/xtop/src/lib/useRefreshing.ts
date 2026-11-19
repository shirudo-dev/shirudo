// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

import { useEffect, useRef, useState } from "react";

/** The backend's views are recomputed once a minute; asking more often shows nothing new. */
const REFRESH_MS = 60_000;

export type Query<T> = { data: T | null; error: string | null; loading: boolean };

/**
 * Loads when enabled, again on every `reload` change and every REFRESH_MS.
 * A failed refresh keeps the rows it had and reports the error beside them.
 */
export function useRefreshing<T>(enabled: boolean, reload: number, load: () => Promise<T>): Query<T> {
  const [state, setState] = useState<Query<T>>({ data: null, error: null, loading: false });
  const loadRef = useRef(load);
  loadRef.current = load;
  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    const run = () => {
      setState((s) => ({ ...s, loading: true }));
      loadRef.current().then(
        (data) => alive && setState({ data, error: null, loading: false }),
        (e: unknown) =>
          alive && setState((s) => ({ ...s, error: e instanceof Error ? e.message : String(e), loading: false })),
      );
    };
    run();
    const id = setInterval(run, REFRESH_MS);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [enabled, reload]);
  return state;
}
