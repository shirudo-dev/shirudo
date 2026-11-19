// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// xtop: a terminal view of the shirudo backend's ClickHouse.

import { render } from "ink";
import { App } from "./App.tsx";
import { ClickHouseBackend } from "./lib/backend.ts";
import { configFromEnv } from "./lib/clickhouse.ts";
import { createMouseInput } from "./lib/mouse.ts";
import { MouseContext } from "./lib/useMouse.ts";
import { APP_TITLE, setTerminalTitle } from "./lib/terminal.ts";

let backend: ClickHouseBackend;
try {
  backend = new ClickHouseBackend(configFromEnv());
} catch (e) {
  console.error(`xtop: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(2);
}

const restoreTitle = setTerminalTitle(APP_TITLE);
const mouse = createMouseInput(process.stdin, process.stdout);
const cleanup = () => {
  mouse.disable();
  restoreTitle();
};
process.on("exit", cleanup);
// A killed terminal or a dropped SSH session still restores the terminal.
for (const sig of ["SIGTERM", "SIGHUP"] as const) process.on(sig, () => process.exit(0));

const app = render(
  <MouseContext.Provider value={mouse.events}>
    <App backend={backend} />
  </MouseContext.Provider>,
  { alternateScreen: true, stdin: mouse.input, kittyKeyboard: { mode: "auto" } },
);
await app.waitUntilExit();
cleanup();
process.exit(0);
