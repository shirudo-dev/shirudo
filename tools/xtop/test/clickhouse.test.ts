// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// The requests of the ClickHouse client: read-only, also for a user whose
// profile refuses the setting that says so.

import { describe, expect, test } from "bun:test";
import { queryRows, type ClickHouseConfig } from "../src/lib/clickhouse.ts";

const config = (): ClickHouseConfig => ({ url: new URL("http://127.0.0.1:8123/"), timeoutMs: 1000 });

const REFUSED = "Code: 164. DB::Exception: Cannot modify 'readonly' setting in readonly mode. (READONLY)";

/** A server that answers each request with what answer makes of its URL. */
const server = (answer: (url: URL) => Response) => {
  const seen: URL[] = [];
  const fetchImpl = (async (url: URL) => {
    seen.push(url);
    return answer(url);
  }) as unknown as typeof fetch;
  return { seen, fetchImpl };
};

describe("queryRows", () => {
  test("sends readonly=1 and reads a row per line", async () => {
    const { seen, fetchImpl } = server(() => new Response('{"a":1}\n{"a":2}\n'));
    expect(await queryRows<{ a: number }>(config(), "SELECT 1", fetchImpl)).toEqual([{ a: 1 }, { a: 2 }]);
    expect(seen.map((u) => u.searchParams.get("readonly"))).toEqual(["1"]);
  });

  test("leaves readonly to the profile of a user who may not set it", async () => {
    const { seen, fetchImpl } = server((url) =>
      url.searchParams.has("readonly") ? new Response(REFUSED, { status: 500 }) : new Response('{"a":1}\n'),
    );
    const cfg = config();
    expect(await queryRows(cfg, "SELECT 1", fetchImpl)).toEqual([{ a: 1 }]);
    expect(await queryRows(cfg, "SELECT 1", fetchImpl)).toEqual([{ a: 1 }]);
    expect(seen.map((u) => u.searchParams.get("readonly"))).toEqual(["1", null, null]);
  });

  test("reports any other failure, with its first line", async () => {
    const { seen, fetchImpl } = server(() => new Response("Code: 60. no such table\nstack", { status: 404 }));
    expect(queryRows(config(), "SELECT 1", fetchImpl)).rejects.toThrow("404 Code: 60. no such table");
    expect(seen.length).toBe(1);
  });
});
