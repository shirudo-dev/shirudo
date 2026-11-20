// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// The search of every table: regular expressions, all of which a row must
// meet, and terms that exclude.

import { describe, expect, test } from "bun:test";
import { literalSearch, parseSearch } from "../src/lib/search.ts";

const kernel = ["CVE-2025-0001", "linux-modules-7.0.0-43-generic", "HIGH"];
const openssl = ["CVE-2025-0002", "openssl", "MEDIUM"];
const filter = (query: string) => [kernel, openssl].filter((row) => parseSearch(query).test(row));

describe("parseSearch", () => {
  test("an empty query keeps every row", () => {
    expect(filter("")).toEqual([kernel, openssl]);
    expect(filter("  ! ")).toEqual([kernel, openssl]);
  });

  test("a term is a regular expression that any field may match, ignoring case", () => {
    expect(filter("^linux-")).toEqual([kernel]);
    expect(filter("ssl$")).toEqual([openssl]);
    expect(filter("cve-2025-000[12]")).toEqual([kernel, openssl]);
  });

  test("a term after ! drops the rows it matches", () => {
    expect(filter("!^linux")).toEqual([openssl]);
    expect(filter("!cve")).toEqual([]);
  });

  test("every term must hold", () => {
    expect(filter("cve !linux")).toEqual([openssl]);
    expect(filter("high medium")).toEqual([]);
  });

  test("a term that is no regular expression is plain text", () => {
    const search = parseSearch("openssl (");
    expect(search.invalid).toEqual(["("]);
    expect(search.test(["openssl ("])).toBe(true);
    expect(search.test(openssl)).toBe(false);
  });
});

describe("literalSearch", () => {
  test("finds the text as it is", () => {
    const query = literalSearch("fleet-os 1.0+b1");
    expect(query).toBe("fleet-os 1\\.0\\+b1");
    expect(parseSearch(query).test(["fleet-os 1.0+b1"])).toBe(true);
    expect(parseSearch(query).test(["fleet-os 1x00b1"])).toBe(false);
  });

  test("a word starting with ! is searched for, not excluded", () => {
    expect(parseSearch(literalSearch("!x")).test(["!x"])).toBe(true);
  });
});
