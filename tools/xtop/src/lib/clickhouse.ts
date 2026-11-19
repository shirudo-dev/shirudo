// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Queries over the HTTP interface of the backend's ClickHouse.

export type ClickHouseConfig = {
  url: URL;
  user?: string;
  password?: string;
  timeoutMs: number;
};

export const DEFAULT_URL = "http://127.0.0.1:8123/";

/**
 * CLICKHOUSE_URL, CLICKHOUSE_USER and CLICKHOUSE_PASSWORD. Credentials in
 * the URL are refused: they would show in the process list and the error
 * lines this tool prints.
 */
export function configFromEnv(env: Record<string, string | undefined> = process.env): ClickHouseConfig {
  const raw = env.CLICKHOUSE_URL || DEFAULT_URL;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`CLICKHOUSE_URL is not a URL: ${raw}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:")
    throw new Error(`CLICKHOUSE_URL must be http or https: ${raw}`);
  if (url.username || url.password)
    throw new Error("CLICKHOUSE_URL must not carry credentials; set CLICKHOUSE_USER and CLICKHOUSE_PASSWORD");
  return {
    url,
    ...(env.CLICKHOUSE_USER ? { user: env.CLICKHOUSE_USER } : {}),
    ...(env.CLICKHOUSE_PASSWORD ? { password: env.CLICKHOUSE_PASSWORD } : {}),
    timeoutMs: 10_000,
  };
}

/** Runs one SELECT and returns its rows as objects keyed by column name. */
export async function queryRows<T>(
  cfg: ClickHouseConfig,
  sql: string,
  fetchImpl: typeof fetch = fetch,
): Promise<T[]> {
  const url = new URL(cfg.url);
  url.searchParams.set("default_format", "JSONEachRow");
  url.searchParams.set("output_format_json_quote_64bit_integers", "0");
  url.searchParams.set("readonly", "1");
  const headers: Record<string, string> = { "Content-Type": "text/plain" };
  if (cfg.user) headers["X-ClickHouse-User"] = cfg.user;
  if (cfg.password) headers["X-ClickHouse-Key"] = cfg.password;

  const res = await fetchImpl(url, {
    method: "POST",
    headers,
    body: sql,
    signal: AbortSignal.timeout(cfg.timeoutMs),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${res.status} ${text.trim().split("\n")[0]?.slice(0, 300) ?? ""}`);
  return text
    .split("\n")
    .filter((line) => line.length)
    .map((line) => JSON.parse(line) as T);
}
