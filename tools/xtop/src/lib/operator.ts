// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// What xtop needs to run an operator's commands itself: it does only
// when XTOP_KEYS_DIR names the keys, and otherwise shows the commands.

export type Operator = {
  /** The directory of signing_key.pem and cert.der. */
  keysDir: string;
  shirudo: string;
  treeIngest: string;
};

export const DEFAULT_SHIRUDO = "shirudo";
export const DEFAULT_TREE_INGEST = "tools/backend/jobs/tree-ingest";

export const operatorFromEnv = (env: Record<string, string | undefined>): Operator | null =>
  env.XTOP_KEYS_DIR
    ? {
        keysDir: env.XTOP_KEYS_DIR,
        shirudo: env.SHIRUDO || DEFAULT_SHIRUDO,
        treeIngest: env.XTOP_TREE_INGEST || DEFAULT_TREE_INGEST,
      }
    : null;

export type RunResult = { ok: boolean; output: string };

/** Runs argv without a shell, and gives what it printed. */
export async function run(argv: readonly string[]): Promise<RunResult> {
  try {
    const child = Bun.spawn([...argv], { stdin: "ignore", stdout: "pipe", stderr: "pipe" });
    const [out, err, status] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ]);
    return { ok: status === 0, output: (out + err).trim() || `exit status ${status}` };
  } catch (e) {
    return { ok: false, output: e instanceof Error ? e.message : String(e) };
  }
}
