// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { StringDecoder } from "node:string_decoder";

/** Coordinates are 0-based terminal cells. */
export type MouseEvent =
  | { kind: "press" | "release"; button: "left" | "middle" | "right"; x: number; y: number }
  | { kind: "wheel"; direction: "up" | "down"; x: number; y: number };

// SGR (1006) encoding: ESC [ < button ; x ; y (M = press, m = release)
const SGR_MOUSE = /\x1b\[<(\d+);(\d+);(\d+)([Mm])/g;
const PARTIAL_SGR = /\x1b\[<[\d;]*$/;
const BUTTONS = ["left", "middle", "right"] as const;

const ENABLE = "\x1b[?1000h\x1b[?1006h";
const DISABLE = "\x1b[?1000l\x1b[?1006l";

/**
 * Ink drops mouse reports, so we sit between the terminal and Ink: mouse
 * sequences are parsed and emitted as "mouse" events, everything else is
 * forwarded to the stream Ink reads. Raw mode and ref/unref are proxied to
 * the real stdin so Ink treats the wrapper as a TTY.
 */
export function createMouseInput(source: NodeJS.ReadStream, stdout: NodeJS.WriteStream) {
  const events = new EventEmitter();
  const decoder = new StringDecoder("utf8");
  const input = Object.assign(new PassThrough(), {
    isTTY: source.isTTY,
    setRawMode(mode: boolean) {
      source.setRawMode(mode);
      return input;
    },
    ref() {
      source.ref();
      return input;
    },
    unref() {
      source.unref();
      return input;
    },
  });

  // Raw mode now, not when Ink first asks for it: the terminal answers
  // startup queries (kitty keyboard `ESC[?u`) right away, and in cooked mode
  // the tty echoes the reply onto the screen as `^[[?0u`.
  if (source.isTTY) source.setRawMode(true);

  let pending = "";
  source.on("data", (chunk: Buffer | string) => {
    let text = pending + (typeof chunk === "string" ? chunk : decoder.write(chunk));
    pending = "";
    const partial = text.match(PARTIAL_SGR);
    if (partial) {
      pending = partial[0];
      text = text.slice(0, partial.index);
    }
    text = text.replace(SGR_MOUSE, (_m, b: string, x: string, y: string, t: string) => {
      const code = Number(b);
      const pos = { x: Number(x) - 1, y: Number(y) - 1 };
      if (code & 64) events.emit("mouse", { kind: "wheel", direction: code & 1 ? "down" : "up", ...pos });
      else if (!(code & 32)) {
        const button = BUTTONS[code & 3];
        if (button) events.emit("mouse", { kind: t === "M" ? "press" : "release", button, ...pos });
      }
      return "";
    });
    if (text) input.write(text);
  });

  let enabled = false;
  const disable = () => {
    if (enabled && stdout.isTTY) stdout.write(DISABLE);
    enabled = false;
    if (source.isTTY) source.setRawMode(false);
  };
  if (stdout.isTTY) {
    stdout.write(ENABLE);
    enabled = true;
  }

  return { input, events, disable };
}
