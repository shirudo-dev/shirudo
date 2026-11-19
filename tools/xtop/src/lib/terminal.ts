// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

export const APP_TITLE = "xtop";

const ESC = "\x1b";
const pushTitle = `${ESC}[22;0t`;
const popTitle = `${ESC}[23;0t`;
const setTitleSeq = (title: string) => `${ESC}]0;${title}\x07`;

/**
 * Rename the terminal window/tab. The previous title is saved on the
 * terminal's title stack and restored by the returned function.
 */
export function setTerminalTitle(title: string): () => void {
  process.title = title;
  if (!process.stdout.isTTY) return () => {};

  process.stdout.write(pushTitle + setTitleSeq(title));
  let restored = false;
  return () => {
    if (restored) return;
    restored = true;
    process.stdout.write(popTitle);
  };
}
