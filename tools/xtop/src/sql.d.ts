// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

// sql/*.sql, imported as text and embedded by bun build --compile.
declare module "*.sql" {
  const text: string;
  export default text;
}
