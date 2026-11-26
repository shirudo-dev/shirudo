#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
"""Generate sandbox_policy of app-sandbox as a raw BTF variable value.

The rules of each sandbox come from the input, the policy bit of each
from the [[upatches.policy]] table of the Beefile that has its name.
"""

import argparse
import ipaddress
from pathlib import Path
import struct
import tomllib

SANDBOX_MAX = 32
NET_MAX = 128
NET_DENY_MAX = 64
FIM_MAX = 64
GLOB_MAX = 32
FIM_OPS = {"create": 0x1, "rename": 0x2, "write": 0x4, "read": 0x8, "unix": 0x10}
FAMILIES = {
	"unix": 1,
	"inet": 2,
	"inet6": 10,
	"netlink": 16,
	"packet": 17,
	"rds": 21,
	"tipc": 30,
	"bluetooth": 31,
	"alg": 38,
	"nfc": 39,
	"vsock": 40,
	"xdp": 44,
}
PRIV_OPS = {
	"userns": "deny_userns",
	"mount": "deny_mount",
	"ptrace": "deny_ptrace",
	"module": "deny_module",
}
DENY_KEYS = set(FIM_OPS) | {"network", "families", "ops"}
SANDBOX_KEYS = {"exec", "network", "deny"}
MAPPED_V4 = ipaddress.ip_network("::ffff:0:0/96")


def strings(value, where):
	if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
		raise ValueError(f"{where}: expected an array of strings")
	return value


def policy_bits(beefile):
	"""The bit of every policy ID the Beefile declares."""
	with beefile.open("rb") as stream:
		upatches = tomllib.load(stream).get("upatches", [])
	bits = {}
	for upatch in upatches:
		for policy in upatch.get("policy", []):
			name, bit = policy.get("id"), policy.get("bit")
			# shirudo reads a bit as hexadecimal, TOML reads it as
			# decimal without 0x: only a one-hot value is the same bit
			# to both.
			if not isinstance(bit, int) or bit <= 0 or bit & (bit - 1) or bit >> 64:
				raise ValueError(f"{beefile}: policy {name}: write the bit as "
						 "one-hot hexadecimal with 0x")
			if bits.setdefault(name, bit) != bit:
				raise ValueError(f"{beefile}: policy {name} has two bits")
	return bits


def network_object(text, where):
	try:
		network = ipaddress.ip_network(text, strict=False)
	except ValueError as error:
		raise ValueError(f"{where}: {error}") from error
	if network.version == 4:
		address = int(MAPPED_V4.network_address) | int(network.network_address)
		network = ipaddress.ip_network((address, 96 + network.prefixlen))
	return network


def networks(names, sets, where):
	rules = []
	for name in strings(names, where):
		if name.startswith("@"):
			if name[1:] not in sets:
				raise ValueError(f"{where}: no [networks] entry {name[1:]}")
			members = strings(sets[name[1:]], f"networks.{name[1:]}")
		else:
			members = [name]
		rules.extend(network_object(member, where) for member in members)
	return rules


def network_shadowed(allowed, denied):
	remaining = list(allowed)
	for deny in denied:
		next_remaining = []
		for net in remaining:
			if net.subnet_of(deny):
				continue
			if deny.subnet_of(net):
				next_remaining.extend(net.address_exclude(deny))
			else:
				next_remaining.append(net)
		remaining = next_remaining
		if not remaining:
			return True
	return False


def glob_rule(pattern, where):
	raw = pattern.encode()
	if not raw or b"\0" in raw or raw.count(b"/") > 1:
		raise ValueError(f"{where}: {pattern!r} is not a file name or "
				 "parent/name pattern")
	parent = b""
	name = raw
	if b"/" in raw:
		parent, _, name = raw.partition(b"/")
		if (not parent or parent in (b".", b"..") or
		    b"*" in parent or b"?" in parent):
			raise ValueError(f"{where}: {pattern!r} has an invalid parent "
					 "directory name")
		if len(parent) > GLOB_MAX:
			raise ValueError(f"{where}: {pattern!r} parent exceeds "
					 f"{GLOB_MAX} bytes")
	if not name or name.count(b"*") > 1:
		raise ValueError(f"{where}: {pattern!r} is not a file name with at "
				 "most one '*'")
	prefix, star, suffix = name.partition(b"*")
	if len(prefix) > GLOB_MAX or len(suffix) > GLOB_MAX:
		raise ValueError(f"{where}: {pattern!r} has more than {GLOB_MAX} "
				 "bytes on one side of its '*'")
	return parent, prefix, suffix, bool(star)


def read_policy(path, bits):
	with path.open("rb") as stream:
		config = tomllib.load(stream)
	unknown = set(config) - {"networks", "sandbox"}
	if unknown:
		raise ValueError(f"{path}: unknown table {sorted(unknown)[0]}")
	sets = config.get("networks", {})
	policy = {
		"sandboxes": 0,
		"exec_enforced": 0,
		"net_enforced": 0,
		"net_deny_enforced": 0,
		"family_enforced": 0,
		"read_enforced": 0,
		"unix_enforced": 0,
		"deny_userns": 0,
		"deny_mount": 0,
		"deny_ptrace": 0,
		"deny_module": 0,
		"fim_has_parent": 0,
		"exec": [],
		"net": {},
		"net_deny": {},
		"family": [],
		"fim": {},
	}
	for name, sandbox in config.get("sandbox", {}).items():
		where = f"{path}: sandbox.{name}"
		if name not in bits:
			raise ValueError(f"{where}: the Beefile has no policy {name}")
		unknown = set(sandbox) - SANDBOX_KEYS
		if unknown:
			raise ValueError(f"{where}: unknown key {sorted(unknown)[0]}")
		bit = bits[name]
		policy["sandboxes"] |= bit
		if "exec" in sandbox:
			allowed = bit
			for other in strings(sandbox["exec"], f"{where}.exec"):
				if other not in bits:
					raise ValueError(f"{where}.exec: the Beefile has no "
							 f"policy {other}")
				allowed |= bits[other]
			policy["exec_enforced"] |= bit
			policy["exec"].append((bit, allowed))
		allowed_nets = []
		if "network" in sandbox:
			policy["net_enforced"] |= bit
			allowed_nets = networks(sandbox["network"], sets, f"{where}.network")
			for net in allowed_nets:
				key = (net.network_address.packed, net.netmask.packed)
				policy["net"][key] = policy["net"].get(key, 0) | bit
		deny = sandbox.get("deny", {})
		if not isinstance(deny, dict):
			raise ValueError(f"{where}.deny: expected a table")
		unknown = set(deny) - DENY_KEYS
		if unknown:
			raise ValueError(f"{where}.deny: unknown key {sorted(unknown)[0]}")
		if "network" in deny:
			denied_nets = networks(deny["network"], sets, f"{where}.deny.network")
			if denied_nets:
				if allowed_nets and network_shadowed(allowed_nets, denied_nets):
					raise ValueError(f"{where}.deny.network: shadows every "
							 "allowed network; use network = [] to deny all peers")
				policy["net_deny_enforced"] |= bit
				for net in denied_nets:
					key = (net.network_address.packed, net.netmask.packed)
					policy["net_deny"][key] = policy["net_deny"].get(key, 0) | bit
		if "families" in deny:
			family_mask = 0
			for family in strings(deny["families"], f"{where}.deny.families"):
				if family not in FAMILIES:
					raise ValueError(f"{where}.deny.families: unknown socket "
							 f"family {family!r}")
				family_mask |= 1 << FAMILIES[family]
			if family_mask:
				policy["family_enforced"] |= bit
				policy["family"].append((bit, family_mask))
		if "ops" in deny:
			for op in strings(deny["ops"], f"{where}.deny.ops"):
				if op not in PRIV_OPS:
					raise ValueError(f"{where}.deny.ops: unknown operation {op!r}")
				policy[PRIV_OPS[op]] |= bit
		sandbox_fim = {}
		for op in FIM_OPS:
			if op not in deny:
				continue
			patterns = strings(deny[op], f"{where}.deny.{op}")
			if patterns and op == "read":
				policy["read_enforced"] |= bit
			if patterns and op == "unix":
				policy["unix_enforced"] |= bit
			for pattern in patterns:
				rule = glob_rule(pattern, f"{where}.deny.{op}")
				if rule[0]:
					policy["fim_has_parent"] = 1
				sandbox_fim[rule] = sandbox_fim.get(rule, 0) | FIM_OPS[op]
		for rule, ops in sandbox_fim.items():
			key = (rule, ops)
			policy["fim"][key] = policy["fim"].get(key, 0) | bit
	return policy


def table(entries, limit, size, what):
	if len(entries) > limit:
		raise ValueError(f"{len(entries)} {what}; the object holds {limit}")
	return b"".join(entries).ljust(limit * size, b"\0")


def encode(policy):
	"""struct sandbox_policy of app-sandbox.bpf.c, little-endian."""
	execs = [struct.pack("<QQ", bit, allowed) for bit, allowed in policy["exec"]]
	nets = [struct.pack("<Q16s16s", sandboxes, address, mask)
		for (address, mask), sandboxes in sorted(policy["net"].items())]
	net_denies = [struct.pack("<Q16s16s", sandboxes, address, mask)
		      for (address, mask), sandboxes in sorted(policy["net_deny"].items())]
	families = [struct.pack("<QQ", bit, mask) for bit, mask in policy["family"]]
	fims = [struct.pack(f"<QBBBBB3x{GLOB_MAX}s{GLOB_MAX}s{GLOB_MAX}s",
			    sandboxes, ops, len(prefix), len(suffix),
			    wildcard, len(parent), prefix, suffix, parent)
		for ((parent, prefix, suffix, wildcard), ops), sandboxes
		in sorted(policy["fim"].items())]
	header = struct.pack(
		"<QQQQQQQQQQQIIIIII",
		policy["sandboxes"],
		policy["exec_enforced"],
		policy["net_enforced"],
		policy["net_deny_enforced"],
		policy["family_enforced"],
		policy["read_enforced"],
		policy["unix_enforced"],
		policy["deny_userns"],
		policy["deny_mount"],
		policy["deny_ptrace"],
		policy["deny_module"],
		len(execs),
		len(nets),
		len(net_denies),
		len(families),
		len(fims),
		policy["fim_has_parent"],
	)
	return (header +
		table(execs, SANDBOX_MAX, 16, "sandboxes with exec rules") +
		table(nets, NET_MAX, 40, "networks") +
		table(net_denies, NET_DENY_MAX, 40, "denied networks") +
		table(families, SANDBOX_MAX, 16, "sandboxes with family rules") +
		table(fims, FIM_MAX, 112, "file name patterns"))


def main():
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--input", required=True, type=Path)
	parser.add_argument("--symbol", required=True)
	parser.add_argument("--output", required=True, type=Path)
	parser.add_argument("--beefile", type=Path, default=Path("Beefile"))
	args = parser.parse_args()
	try:
		if args.symbol != "sandbox_policy":
			raise ValueError(f"unsupported symbol: {args.symbol}")
		policy = read_policy(args.input, policy_bits(args.beefile))
		args.output.write_bytes(encode(policy))
	except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
		parser.error(str(error))
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
