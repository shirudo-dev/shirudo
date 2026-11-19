// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

/** How long ago, in the largest unit that keeps it short: 8s, 3m, 5h, 2d. */
export const ago = (d: Date) => {
  const s = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000));
  return s < 60 ? `${s}s` : s < 3600 ? `${Math.round(s / 60)}m` : s < 172800 ? `${Math.round(s / 3600)}h` : `${Math.round(s / 86400)}d`;
};
