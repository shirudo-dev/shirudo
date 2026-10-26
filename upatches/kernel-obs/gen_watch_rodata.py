#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
"""Generate one kernel-obs watch trie as a raw BTF variable value."""

import argparse
from pathlib import Path
import re
import struct

from gen_watch import build_trie, read_networks


NODE_SIZE = 520
CHILD_OFFSET = 0
TERMINAL_OFFSET = 512


def node_capacity(symbol):
	version = {"obs_watch_v4": "V4", "obs_watch_v6": "V6"}.get(symbol)
	if not version:
		raise ValueError(f"unsupported watch symbol: {symbol}")
	text = Path("watch_generated.h").read_text()
	match = re.search(rf"^#define OBS_WATCH_{version}_NODES (\d+)u$",
			  text, re.MULTILINE)
	if not match:
		raise ValueError(f"missing OBS_WATCH_{version}_NODES in watch_generated.h")
	return int(match.group(1))


def encode(nodes, capacity):
	if len(nodes) > capacity:
		raise ValueError(f"trie needs {len(nodes)} nodes; object holds {capacity}")
	data = bytearray(capacity * NODE_SIZE)
	for index, node in enumerate(nodes):
		base = index * NODE_SIZE
		for octet, child in node["children"].items():
			struct.pack_into("<H", data,
					 base + CHILD_OFFSET + octet * 2, child + 1)
		struct.pack_into("<H", data, base + TERMINAL_OFFSET,
				  int(node["terminal"]))
	return data


def main():
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--input", required=True, type=Path)
	parser.add_argument("--symbol", required=True)
	parser.add_argument("--output", required=True, type=Path)
	args = parser.parse_args()
	version = 4 if args.symbol == "obs_watch_v4" else 6
	try:
		networks = read_networks(args.input)
		data = encode(build_trie(networks, version), node_capacity(args.symbol))
		args.output.write_bytes(data)
	except (OSError, ValueError) as error:
		parser.error(str(error))
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
