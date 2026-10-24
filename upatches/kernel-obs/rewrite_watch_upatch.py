#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
"""Replace kernel-obs watch trie values in a signed .upatch."""

import argparse
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

from gen_watch import build_trie, read_networks


UPATCH_HEADER_SIZE = 360
UPATCH_MAX_SIZE = 16 * 1024 * 1024
BTF_MAGIC = 0xEB9F
BTF_KIND_INT = 1
BTF_KIND_ARRAY = 3
BTF_KIND_STRUCT = 4
BTF_KIND_TYPEDEF = 8
BTF_KIND_VOLATILE = 9
BTF_KIND_CONST = 10
BTF_KIND_RESTRICT = 11
BTF_KIND_VAR = 14
BTF_KIND_DATASEC = 15
BTF_KIND_TYPE_TAG = 18
BPF_PSEUDO_MAP_IDX_VALUE = 6
BPF_FUNC_SYS_BPF = 166
BPF_MAP_CREATE = 0
BPF_MAP_UPDATE_ELEM = 2
BPF_LDDW = 0x18
BPF_JMP_CALL = 0x85
BPF_ALU64_MOV_IMM = 0xB7
BPF_LDXW = 0x61
BPF_STXW = 0x63
BPF_STXDW = 0x7B


class RewriteError(Exception):
	pass


def parse_btf_at(data, start):
	if len(data) - start < 24:
		return None
	magic, version, flags, hdr_len, type_off, type_len, str_off, str_len = \
		struct.unpack_from("<HBBIIIII", data, start)
	if magic != BTF_MAGIC or version != 1 or hdr_len < 24:
		return None
	type_start = start + hdr_len + type_off
	type_end = type_start + type_len
	str_start = start + hdr_len + str_off
	str_end = str_start + str_len
	if (type_start < start or type_end < type_start or type_end > len(data) or
	    str_start < start or str_end < str_start or str_end > len(data)):
		return None
	strings = data[str_start:str_end]
	types = [None]
	pos = type_start
	while pos < type_end:
		if type_end - pos < 12:
			return None
		name_off, info, size_type = struct.unpack_from("<III", data, pos)
		kind = (info >> 24) & 0x1f
		vlen = info & 0xffff
		kflag = bool(info & 0x80000000)
		pos += 12
		if kind in (BTF_KIND_INT, BTF_KIND_VAR, 17):
			extra = 4
		elif kind == BTF_KIND_ARRAY:
			extra = 12
		elif kind in (4, 5, BTF_KIND_DATASEC):
			extra = vlen * 12
		elif kind == 6:
			extra = vlen * 8
		elif kind == 13:
			extra = vlen * 8
		elif kind == 19:
			extra = vlen * 12
		else:
			extra = 0
		if extra > type_end - pos:
			return None
		payload = data[pos:pos + extra]
		pos += extra
		if name_off >= len(strings):
			return None
		end = strings.find(b"\0", name_off)
		if end < 0:
			return None
		try:
			name = strings[name_off:end].decode("utf-8")
		except UnicodeDecodeError:
			return None
		types.append({"name": name, "strings": strings,
			      "kind": kind, "vlen": vlen,
			      "size_type": size_type, "kflag": kflag,
			      "payload": payload})
	if pos != type_end:
		return None
	return types


def btf_u32s(typ):
	return struct.unpack("<" + "I" * (len(typ["payload"]) // 4),
			     typ["payload"])


def unwrap_type(types, type_id):
	for _ in range(16):
		if type_id <= 0 or type_id >= len(types):
			raise RewriteError("BTF contains an invalid type reference")
		typ = types[type_id]
		if typ["kind"] in (BTF_KIND_TYPEDEF, BTF_KIND_VOLATILE,
				    BTF_KIND_CONST, BTF_KIND_RESTRICT,
				    BTF_KIND_TYPE_TAG):
			type_id = typ["size_type"]
			continue
		return type_id, typ
	raise RewriteError("BTF type aliases exceed the supported depth")


def read_watch_arrays(data_blob):
	candidates = []
	search = 0
	while True:
		start = data_blob.find(b"\x9f\xeb", search)
		if start < 0:
			break
		search = start + 1
		types = parse_btf_at(data_blob, start)
		if not types:
			continue
		for type_id, typ in enumerate(types):
			if typ["kind"] == BTF_KIND_DATASEC and typ["name"] == ".rodata":
				candidates.append((start, types, type_id, typ))
	if len(candidates) != 1:
		raise RewriteError("expected one BTF .rodata data section in the upatch")
	btf_start, types, datasec_id, datasec = candidates[0]
	vars = {}
	for i in range(datasec["vlen"]):
		var_id, offset, size = struct.unpack_from("<III", datasec["payload"],
							  i * 12)
		if var_id <= 0 or var_id >= len(types):
			raise RewriteError("BTF .rodata contains an invalid variable")
		var = types[var_id]
		if var["kind"] != BTF_KIND_VAR:
			continue
		if var["name"] in ("obs_watch_v4", "obs_watch_v6"):
			vars[var["name"]] = (var["size_type"], offset, size)
	if set(vars) != {"obs_watch_v4", "obs_watch_v6"}:
		raise RewriteError("BTF .rodata is missing obs_watch_v4 or obs_watch_v6")
	return types, vars


def array_layout(types, type_id, var_size):
	type_id, array = unwrap_type(types, type_id)
	if array["kind"] != BTF_KIND_ARRAY:
		raise RewriteError("watch variable is not a BTF array")
	elem_id, index_id, count = btf_u32s(array)
	elem_id, node = unwrap_type(types, elem_id)
	if node["kind"] != BTF_KIND_STRUCT:
		raise RewriteError("watch array element is not a BTF struct")
	node_size = node["size_type"]
	if count == 0 or count * node_size != var_size:
		raise RewriteError("watch array dimensions do not match its .rodata size")
	fields = []
	for i in range(node["vlen"]):
		name_off, field_type, offset_bits = struct.unpack_from(
			"<III", node["payload"], i * 12)
		if node["kflag"]:
			bit_size = offset_bits >> 24
			offset_bits &= 0x00ffffff
		else:
			bit_size = 0
		if bit_size or offset_bits % 8:
			raise RewriteError("watch node has an unsupported bitfield layout")
		# Names are read from BTF's string table by the type parser below.
		fields.append((field_type, offset_bits // 8, name_off))
	child = None
	terminal = None
	reserved = None
	for field_type, offset, name_off in fields:
		if field_type <= 0 or field_type >= len(types):
			continue
		field_name = btf_name(types, name_off)
		if field_name == "child":
			child = (offset, field_type)
		elif field_name == "terminal":
			terminal = (offset, field_type)
		elif field_name == "reserved":
			reserved = (offset, field_type)
	if not child or not terminal or not reserved:
		raise RewriteError("BTF watch node lacks child, terminal, or reserved fields")
	child_offset, child_type_id = child
	_, child_array = unwrap_type(types, child_type_id)
	if child_array["kind"] != BTF_KIND_ARRAY:
		raise RewriteError("BTF child field is not an array")
	child_elem, _, child_count = btf_u32s(child_array)
	child_elem_id, child_elem_type = unwrap_type(types, child_elem)
	if child_count != 256 or child_elem_type["kind"] != BTF_KIND_INT or \
	    child_elem_type["size_type"] != 2:
		raise RewriteError("BTF child field is not 256 unsigned 16-bit entries")
	enc = struct.unpack("<I", child_elem_type["payload"])[0]
	if ((enc >> 24) & 0xf) & 1:
		raise RewriteError("BTF child field uses signed integers")
	term_offset, term_type_id = terminal
	_, term_type = unwrap_type(types, term_type_id)
	if term_type["kind"] != BTF_KIND_INT or term_type["size_type"] != 2:
		raise RewriteError("BTF terminal field is not a 16-bit integer")
	reserved_offset, reserved_type_id = reserved
	_, reserved_type = unwrap_type(types, reserved_type_id)
	if reserved_type["kind"] != BTF_KIND_ARRAY:
		raise RewriteError("BTF reserved field is not an array")
	reserved_elem, _, reserved_count = btf_u32s(reserved_type)
	_, reserved_elem_type = unwrap_type(types, reserved_elem)
	if reserved_count != 3 or reserved_elem_type["kind"] != BTF_KIND_INT or \
	    reserved_elem_type["size_type"] != 2:
		raise RewriteError("BTF reserved field is not three 16-bit integers")
	return {"count": count, "node_size": node_size,
		"child_offset": child_offset, "terminal_offset": term_offset,
		"reserved_offset": reserved_offset}


def btf_name(types, name_off):
	for typ in types[1:]:
		strings = typ.get("strings")
		if strings is not None:
			end = strings.find(b"\0", name_off)
			return strings[name_off:end].decode("utf-8")
	raise RewriteError("BTF string table is unavailable")


def decode_insn(raw, index):
	return struct.unpack_from("<BBhi", raw, index * 8)


def lddw_offset(insns, index, reg):
	if index + 1 >= len(insns):
		return None
	code, regs, off, imm = insns[index]
	next_code, _, next_off, next_imm = insns[index + 1]
	if (code != BPF_LDDW or regs & 0xf != reg or regs >> 4 !=
	    BPF_PSEUDO_MAP_IDX_VALUE or off or imm or next_code or next_off):
		return None
	return next_imm & 0xffffffff


def sys_bpf_call(insns, index):
	if index < 4 or index >= len(insns):
		return None
	if insns[index][0] != BPF_JMP_CALL or insns[index][3] != BPF_FUNC_SYS_BPF:
		return None
	cmd = insns[index - 4]
	attr_size = insns[index - 1]
	if (cmd[0] != BPF_ALU64_MOV_IMM or cmd[1] != 1 or
	    insns[index - 3][0] != BPF_LDDW or
	    attr_size[0] != BPF_ALU64_MOV_IMM or attr_size[1] != 3):
		return None
	attr = lddw_offset(insns, index - 3, 2)
	if attr is None:
		return None
	return cmd[3], attr, attr_size[3]


def next_sys_bpf(insns, start):
	for index in range(start, len(insns)):
		if sys_bpf_call(insns, index):
			return index
	return len(insns)


def map_create_slot(insns, call, end):
	for index in range(call + 1, end - 2):
		offset = lddw_offset(insns, index, 1)
		if offset is None:
			continue
		code, regs, off, imm = insns[index + 2]
		if (code == BPF_STXW and regs & 0xf == 1 and regs >> 4 == 7 and
		    off == 0 and offset % 4 == 0):
			return offset // 4
	return None


def map_update_slot(insns, call, attr):
	start = max(0, call - 48)
	for index in range(start, call - 5):
		fd_array_offset = lddw_offset(insns, index, 2)
		if fd_array_offset is None:
			continue
		code, regs, off, imm = insns[index + 2]
		if (code != BPF_LDXW or regs & 0xf != 0 or regs >> 4 != 2 or off or
		    lddw_offset(insns, index + 3, 1) != attr):
			continue
		code, regs, off, imm = insns[index + 5]
		if (code == BPF_STXW and regs & 0xf == 1 and regs >> 4 == 0 and
		    off == 0 and fd_array_offset % 4 == 0):
			return fd_array_offset // 4
	return None


def map_update_value_offset(insns, call, attr):
	start = max(0, call - 24)
	for index in range(start, call - 4):
		value_offset = lddw_offset(insns, index, 0)
		if value_offset is None:
			continue
		if lddw_offset(insns, index + 2, 1) != attr + 16:
			continue
		code, regs, off, imm = insns[index + 4]
		if (code == BPF_STXDW and regs & 0xf == 1 and regs >> 4 == 0 and
		    off == 0):
			return value_offset
	return None


def locate_rodata_data(loader, data_blob, datasec_size):
	if len(loader) % 8:
		raise RewriteError("loader instruction section has an invalid size")
	insns = [decode_insn(loader, i) for i in range(len(loader) // 8)]
	created = {}
	for index, insn in enumerate(insns):
		call = sys_bpf_call(insns, index)
		if not call:
			continue
		cmd, attr_offset, attr_size = call
		if attr_offset > len(data_blob) or attr_size > len(data_blob) - attr_offset:
			raise RewriteError("loader BPF attribute is outside its data section")
		if cmd == BPF_MAP_CREATE:
			if attr_size < 44:
				continue
			map_name = data_blob[attr_offset + 28:attr_offset + 44]
			map_name = map_name.split(b"\0", 1)[0].decode("ascii", "ignore")
			if not map_name.endswith(".rodata"):
				continue
			slot = map_create_slot(insns, index,
					       next_sys_bpf(insns, index + 1))
			if slot is None:
				raise RewriteError("cannot find the loader slot for .rodata")
			value_size = struct.unpack_from("<I", data_blob,
							attr_offset + 8)[0]
			if value_size != datasec_size:
				raise RewriteError(".rodata map size does not match BTF")
			created[slot] = value_size
		elif cmd == BPF_MAP_UPDATE_ELEM:
			slot = map_update_slot(insns, index, attr_offset)
			if slot not in created or created[slot] != datasec_size:
				continue
			value_offset = map_update_value_offset(insns, index, attr_offset)
			if value_offset is None:
				continue
			if value_offset > len(data_blob) or \
			    datasec_size > len(data_blob) - value_offset:
				raise RewriteError(".rodata initializer is outside loader data")
			return value_offset
		raise RewriteError("loader has no initial .rodata map value")


def encode_nodes(nodes, layout):
	if len(nodes) > layout["count"]:
		raise RewriteError(
			f"new trie needs {len(nodes)} nodes but the existing BTF array "
			f"holds {layout['count']}; rebuild the BPF object to change its layout")
	output = bytearray(layout["count"] * layout["node_size"])
	for index, node in enumerate(nodes):
		base = index * layout["node_size"]
		for octet, child in node["children"].items():
			struct.pack_into("<H", output,
					 base + layout["child_offset"] + octet * 2,
					 child + 1)
		struct.pack_into("<H", output, base + layout["terminal_offset"],
				  int(node["terminal"]))
	return output


def helper_path(explicit):
	if explicit:
		return explicit
	from_env = os.environ.get("SHIRUDO_BUILD")
	if from_env:
		return from_env
	repo = Path(__file__).resolve().parents[2]
	in_tree = repo / "tools" / "shirudo-build" / "shirudo-build"
	if in_tree.is_file() and os.access(in_tree, os.X_OK):
		return str(in_tree)
	return shutil.which("shirudo-build") or "shirudo-build"


def rewrite(args):
	input_path = Path(args.upatch)
	output_path = Path(args.output) if args.output else input_path
	if input_path.stat().st_size > UPATCH_MAX_SIZE:
		raise RewriteError("input is not a bounded .upatch file")
	artifact = bytearray(input_path.read_bytes())
	if len(artifact) > UPATCH_MAX_SIZE or len(artifact) < UPATCH_HEADER_SIZE:
		raise RewriteError("input is not a bounded .upatch file")
	magic, version, flags = struct.unpack_from("<QII", artifact, 0)
	if magic != 0x53485244554e4150 or version != 1 or flags & 1:
		raise RewriteError("input must be a load upatch in version 1 format")
	loader_off, loader_len, sig_off, sig_len, meta_off, meta_len, \
		data_off, data_len = struct.unpack_from("<8I", artifact, 304)
	if (loader_off > len(artifact) or loader_len > len(artifact) - loader_off or
	    data_off > len(artifact) or data_len > len(artifact) - data_off or
	    sig_off > len(artifact) or sig_len > len(artifact) - sig_off or
	    (meta_len and (meta_off > len(artifact) or
			   meta_len > len(artifact) - meta_off))):
		raise RewriteError("upatch section bounds are invalid")
	data_blob = artifact[data_off:data_off + data_len]
	types, variables = read_watch_arrays(data_blob)
	datasec_id = next(i for i, typ in enumerate(types)
			  if typ["kind"] == BTF_KIND_DATASEC and
			  typ["name"] == ".rodata")
	datasec_size = types[datasec_id]["size_type"]
	rodata_offset = locate_rodata_data(
		artifact[loader_off:loader_off + loader_len], data_blob, datasec_size)
	networks = read_networks(Path(args.iplist))
	new_data = bytearray(data_blob)
	counts = {}
	ranges = []
	for version_num, name in ((4, "obs_watch_v4"), (6, "obs_watch_v6")):
		type_id, var_offset, var_size = variables[name]
		layout = array_layout(types, type_id, var_size)
		nodes = build_trie(networks, version_num)
		encoded = encode_nodes(nodes, layout)
		start = rodata_offset + var_offset
		end = start + var_size
		if end > len(new_data) or len(encoded) != var_size:
			raise RewriteError(f"{name} does not fit in the existing .rodata")
		new_data[start:end] = encoded
		counts[version_num] = (len(nodes), layout["count"])
		ranges.append((start, var_size))
	ranges.sort()
	absolute_data = data_off
	artifact[absolute_data:absolute_data + data_len] = new_data
	if args.dry_run:
		print("watch trie fits existing .rodata:")
		print(f"  IPv4: {counts[4][0]} of {counts[4][1]} nodes")
		print(f"  IPv6: {counts[6][0]} of {counts[6][1]} nodes")
		return
	mode = input_path.stat().st_mode & 0o777
	output_path.parent.mkdir(parents=True, exist_ok=True)
	modified_path = None
	signed_path = None
	try:
		with tempfile.NamedTemporaryFile(prefix=".watch-modified-",
						 dir=input_path.parent, delete=False) as f:
			f.write(artifact)
			modified_path = Path(f.name)
		with tempfile.NamedTemporaryFile(prefix=".watch-signed-",
						 dir=output_path.parent, delete=False) as f:
			signed_path = Path(f.name)
		cmd = [helper_path(args.shirudo_build), "upatch", "rewrite-rodata",
		       str(input_path), str(modified_path), "-o", str(signed_path)]
		for offset, length in ranges:
			cmd.extend(("--data-range", f"{offset}:{length}"))
		if args.keys_dir:
			cmd.extend(("--keys-dir", args.keys_dir))
		if args.key:
			cmd.extend(("--key", args.key))
		if args.cert:
			cmd.extend(("--cert", args.cert))
		subprocess.run(cmd, check=True)
		os.chmod(signed_path, mode)
		os.replace(signed_path, output_path)
		signed_path = None
	finally:
		for temp in (modified_path, signed_path):
			if temp is not None:
				try:
					temp.unlink()
				except FileNotFoundError:
					pass
	print(f"rewrote and re-signed {output_path}")
	print(f"  IPv4: {counts[4][0]} of {counts[4][1]} nodes")
	print(f"  IPv6: {counts[6][0]} of {counts[6][1]} nodes")


def main():
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("iplist", help="watch.list with IPv4/IPv6 addresses or CIDRs")
	parser.add_argument("upatch", help="existing signed kernel-obs .upatch")
	parser.add_argument("-o", "--output", help="output path; defaults to in-place update")
	parser.add_argument("--keys-dir", help="shirudo signing key directory")
	parser.add_argument("--key", help="ML-DSA-87 signing_key.pem")
	parser.add_argument("--cert", help="matching cert.der")
	parser.add_argument("--shirudo-build", help="path to the shirudo-build helper")
	parser.add_argument("--dry-run", action="store_true",
			    help="check BTF layout and trie capacity without writing")
	args = parser.parse_args()
	try:
		rewrite(args)
	except (OSError, ValueError, RewriteError, struct.error,
		subprocess.CalledProcessError) as error:
		print(f"rewrite_watch_upatch.py: {error}", file=sys.stderr)
		return 1
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
