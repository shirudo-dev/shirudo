// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

/**
 * A table search: terms separated by blanks, each of which a row must meet.
 * A term is a case-insensitive regular expression that one of the row's
 * fields must match, or, after a leading `!`, that none of them may. A term
 * that is not a valid expression is taken as plain text, and named in
 * `invalid`.
 */
export type Search = {
  test: (fields: readonly string[]) => boolean;
  invalid: readonly string[];
};

const escapeRegExp = (text: string) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export const parseSearch = (query: string): Search => {
  const invalid: string[] = [];
  const terms = query
    .split(/\s+/)
    .filter((term) => term && term !== "!")
    .map((term) => {
      const exclude = term.startsWith("!");
      const pattern = exclude ? term.slice(1) : term;
      try {
        return { exclude, re: new RegExp(pattern, "i") };
      } catch {
        invalid.push(term);
        return { exclude, re: new RegExp(escapeRegExp(pattern), "i") };
      }
    });
  return {
    test: (fields) => terms.every(({ exclude, re }) => fields.some((f) => re.test(f)) !== exclude),
    invalid,
  };
};

/**
 * A search for the rows with a field that is text and nothing else, such as
 * a name to drill into: one term, since separate words could each match
 * another field, or only a part of one.
 */
export const literalSearch = (text: string) =>
  `^${text.trim().split(/\s+/).filter(Boolean).map(escapeRegExp).join("\\s")}$`;
