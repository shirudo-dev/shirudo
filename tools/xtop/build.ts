// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Compiles xtop into one executable, dist/xtop. Ink imports
// react-devtools-core, an optional package for DEV=true sessions, from a
// module the bundle evaluates at start; a stub stands in for it.

export {};

const result = await Bun.build({
  entrypoints: ["./src/index.tsx"],
  compile: { outfile: "dist/xtop" },
  plugins: [
    {
      name: "no-devtools",
      setup(build) {
        build.onResolve({ filter: /^react-devtools-core$/ }, () => ({ path: "react-devtools-core", namespace: "stub" }));
        build.onLoad({ filter: /.*/, namespace: "stub" }, () => ({
          contents: "export default { initialize() {}, connectToDevTools() {} };",
          loader: "js",
        }));
      },
    },
  ],
});
if (!result.success) {
  for (const log of result.logs) console.error(log);
  process.exit(1);
}
