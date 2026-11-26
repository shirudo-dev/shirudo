#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3015 -- app-sandbox policy generator: gen_policy.py packs the shipped
# rules and the deny.network, deny.families, deny.ops, deny.read,
# deny.unix and parent/name extensions into struct sandbox_policy,
# refuses malformed or shadowed rules, and satisfies monotonic
# composition across multiple sandboxes.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

REPO=$(cd .. && pwd)
PKG=$REPO/upatches/app-sandbox
GEN=$PKG/gen_policy.py

command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

run_gen() {
	python3 -I "$GEN" --beefile "$1" --input "$2" \
		--symbol sandbox_policy --output "$3"
}

test_expect_success 'the shipped app-sandbox rules pack cleanly' '
	run_gen "$PKG/Beefile" "$PKG/sandbox.toml" "$WORK/shipped.bin" &&
	python3 -I - "$WORK/shipped.bin" <<-\PY
	import struct, sys

	raw = open(sys.argv[1], "rb").read()
	assert len(raw) == 15984, len(raw)
	hdr = struct.unpack_from("<QQQQQQQQQQQIIIIII", raw, 0)
	(sandboxes, exec_enf, net_enf, net_deny_enf, fam_enf, read_enf,
	 unix_enf, d_userns, d_mount, d_ptrace, d_module, nr_exec, nr_net,
	 nr_net_deny, nr_family, nr_fim, fim_has_parent) = hdr
	assert sandboxes == 0x3, hdr
	assert exec_enf == 0x3, hdr
	assert net_enf == 0x3, hdr
	assert net_deny_enf == 0, hdr
	assert fam_enf == 0, hdr
	assert read_enf == 0, hdr
	assert unix_enf == 0, hdr
	assert (d_userns, d_mount, d_ptrace, d_module) == (0, 0, 0, 0), hdr
	assert nr_exec == 2 and nr_net == 8 and nr_net_deny == 0, hdr
	assert nr_family == 0 and nr_fim == 5 and fim_has_parent == 0, hdr
	PY
'

cat >"$WORK/Beefile" <<'EOT'
[package]
name = "app-sandbox"

[[upatches]]
source = "app-sandbox.bpf.c"

[[upatches.policy]]
id = "agent"
bit = 0x1
paths = ["/usr/local/bin/agent"]

[[upatches.policy]]
id = "helper"
bit = 0x2
paths = ["/usr/local/bin/helper"]
EOT

test_expect_success 'deny.network packs IMDS/private CIDRs and refuses shadowed allowlists' '
	cat >"$WORK/net-ok.toml" <<-\EOT &&
	[networks]
	imds = ["169.254.169.254/32", "fd00:ec2::254/128"]
	private = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"]

	[sandbox.agent]
	network = ["0.0.0.0/0", "::/0"]

	[sandbox.agent.deny]
	network = ["@imds", "@private"]
	EOT
	run_gen "$WORK/Beefile" "$WORK/net-ok.toml" "$WORK/net-ok.bin" &&
	python3 -I - "$WORK/net-ok.bin" <<-\PY &&
	import struct, sys

	raw = open(sys.argv[1], "rb").read()
	hdr = struct.unpack_from("<QQQQQQQQQQQIIIIII", raw, 0)
	assert hdr[2] == 0x1 and hdr[3] == 0x1, hdr
	assert hdr[12] == 2 and hdr[13] == 6, hdr
	PY
	cat >"$WORK/net-deny-only.toml" <<-\EOT &&
	[sandbox.agent.deny]
	network = ["169.254.169.254/32"]
	EOT
	run_gen "$WORK/Beefile" "$WORK/net-deny-only.toml" "$WORK/net-deny-only.bin" &&
	python3 -I - "$WORK/net-deny-only.bin" <<-\PY &&
	import struct, sys

	raw = open(sys.argv[1], "rb").read()
	hdr = struct.unpack_from("<QQQQQQQQQQQIIIIII", raw, 0)
	assert hdr[2] == 0 and hdr[3] == 0x1 and hdr[13] == 1, hdr
	PY
	cat >"$WORK/net-shadowed.toml" <<-\EOT &&
	[sandbox.agent]
	network = ["10.0.0.0/24"]

	[sandbox.agent.deny]
	network = ["10.0.0.0/25", "10.0.0.128/25"]
	EOT
	! run_gen "$WORK/Beefile" "$WORK/net-shadowed.toml" "$WORK/bad.bin" \
		2>"$WORK/shadow.err" &&
	grep -qF "shadows every allowed network" "$WORK/shadow.err"
'

test_expect_success 'deny.families and deny.ops pack bitmasks and refuse unknown names' '
	cat >"$WORK/fam-ops.toml" <<-\EOT &&
	[sandbox.agent.deny]
	families = ["vsock", "netlink", "alg", "rds", "tipc", "xdp"]
	ops = ["userns", "mount", "ptrace", "module"]
	EOT
	run_gen "$WORK/Beefile" "$WORK/fam-ops.toml" "$WORK/fam-ops.bin" &&
	python3 -I - "$WORK/fam-ops.bin" <<-\PY &&
	import struct, sys

	raw = open(sys.argv[1], "rb").read()
	hdr = struct.unpack_from("<QQQQQQQQQQQIIIIII", raw, 0)
	assert hdr[4] == 0x1 and hdr[14] == 1, hdr
	assert hdr[7:11] == (1, 1, 1, 1), hdr
	fam_off = 112 + 32 * 16 + 128 * 40 + 64 * 40
	bit, mask = struct.unpack_from("<QQ", raw, fam_off)
	want = (1 << 40) | (1 << 16) | (1 << 38) | (1 << 21) | (1 << 30) | (1 << 44)
	assert bit == 0x1 and mask == want, (hex(bit), hex(mask), hex(want))
	PY
	printf "[sandbox.agent.deny]\nfamilies = [\"bogus\"]\n" >"$WORK/bad-fam.toml" &&
	! run_gen "$WORK/Beefile" "$WORK/bad-fam.toml" "$WORK/bad.bin" \
		2>"$WORK/bad-fam.err" &&
	grep -qF "unknown socket family" "$WORK/bad-fam.err" &&
	printf "[sandbox.agent.deny]\nops = [\"reboot\"]\n" >"$WORK/bad-op.toml" &&
	! run_gen "$WORK/Beefile" "$WORK/bad-op.toml" "$WORK/bad.bin" \
		2>"$WORK/bad-op.err" &&
	grep -qF "unknown operation" "$WORK/bad-op.err"
'

test_expect_success 'deny.read and deny.unix support parent/name patterns and refuse bad paths' '
	cat >"$WORK/fim.toml" <<-\EOT &&
	[sandbox.agent.deny]
	read = [".env", ".ssh/*", ".aws/credentials"]
	unix = ["docker.sock", "run/containerd.sock"]
	EOT
	run_gen "$WORK/Beefile" "$WORK/fim.toml" "$WORK/fim.bin" &&
	python3 -I - "$WORK/fim.bin" <<-\PY &&
	import struct, sys

	raw = open(sys.argv[1], "rb").read()
	hdr = struct.unpack_from("<QQQQQQQQQQQIIIIII", raw, 0)
	assert hdr[5] == 0x1 and hdr[6] == 0x1, hdr
	assert hdr[15] == 5 and hdr[16] == 1, hdr
	PY
	for bad in "a/b/c" "/etc/shadow" "../id_rsa" "a*/id_rsa" ".ssh/"; do
		printf "[sandbox.agent.deny]\nread = [\"%s\"]\n" "$bad" >"$WORK/bad-pat.toml"
		! run_gen "$WORK/Beefile" "$WORK/bad-pat.toml" "$WORK/bad.bin" 2>/dev/null || exit 1
	done
'

test_expect_success 'multi-sandbox composition intersects allows and unions denies monotonically' '
	cat >"$WORK/compose.toml" <<-\EOT &&
	[sandbox.agent]
	exec = ["helper"]
	network = ["0.0.0.0/0", "::/0"]

	[sandbox.agent.deny]
	network = ["169.254.169.254/32", "fd00:ec2::254/128"]
	families = ["vsock"]
	ops = ["userns"]
	read = [".env", ".ssh/*"]
	unix = ["docker.sock"]

	[sandbox.helper]
	exec = []
	network = ["192.0.2.0/24", "169.254.0.0/16"]

	[sandbox.helper.deny]
	families = ["alg"]
	ops = ["ptrace"]
	write = ["*.php", ".env"]
	EOT
	run_gen "$WORK/Beefile" "$WORK/compose.toml" "$WORK/compose.bin" &&
	python3 -I - "$WORK/compose.bin" <<-\PY
	import ipaddress, struct, sys

	raw = open(sys.argv[1], "rb").read()
	hdr = struct.unpack_from("<QQQQQQQQQQQIIIIII", raw, 0)
	(sandboxes, exec_enf, net_enf, net_deny_enf, fam_enf, read_enf,
	 unix_enf, d_userns, d_mount, d_ptrace, d_module, nr_exec, nr_net,
	 nr_net_deny, nr_family, nr_fim, _) = hdr

	off = 112
	exec_rules = [struct.unpack_from("<QQ", raw, off + i * 16) for i in range(nr_exec)]
	off += 32 * 16
	net_rules = [struct.unpack_from("<Q16s16s", raw, off + i * 40) for i in range(nr_net)]
	off += 128 * 40
	deny_rules = [struct.unpack_from("<Q16s16s", raw, off + i * 40) for i in range(nr_net_deny)]
	off += 64 * 40
	fam_rules = [struct.unpack_from("<QQ", raw, off + i * 16) for i in range(nr_family)]
	off += 32 * 16
	fim_rules = [struct.unpack_from("<QBBBBB3x32s32s32s", raw, off + i * 112) for i in range(nr_fim)]

	def to_v6_int(addr):
	    ip = ipaddress.ip_address(addr)
	    if ip.version == 4:
	        return int(ipaddress.IPv6Address("::ffff:" + str(ip)))
	    return int(ip)

	def net_ok(bits, addr):
	    ip = to_v6_int(addr)
	    if bits & net_deny_enf:
	        d_bits = bits & net_deny_enf
	        for sb, a, m in deny_rules:
	            ai = int.from_bytes(a, "big")
	            mi = int.from_bytes(m, "big")
	            if (sb & d_bits) and (ip & mi) == ai:
	                return False
	    if bits & net_enf:
	        a_bits = bits & net_enf
	        allowed = 0
	        for sb, a, m in net_rules:
	            ai = int.from_bytes(a, "big")
	            mi = int.from_bytes(m, "big")
	            if (ip & mi) == ai:
	                allowed |= sb
	        if a_bits & ~allowed:
	            return False
	    return True

	def fam_ok(bits, family):
	    if not (bits & fam_enf):
	        return True
	    bit = 1 << family
	    for sb, denied in fam_rules:
	        if (bits & sb) and (denied & bit):
	            return False
	    return True

	def exec_ok(bits, file_bits):
	    e_bits = bits & exec_enf
	    for sb, allowed in exec_rules:
	        if (e_bits & sb) and not (file_bits & allowed):
	            return False
	    return True

	def fim_denied(bits, op, name_bytes):
	    for sb, ops, plen, slen, wc, parlen, pre, suf, par in fim_rules:
	        if (sb & bits) and (ops & op) and parlen == 0 and not wc:
	            if len(name_bytes) == plen and pre[:plen] == name_bytes:
	                return True
	    return False

	# Composed task (agent | helper = 0x3) must never exceed either alone.
	A, H, BOTH = 0x1, 0x2, 0x3
	for addr in ("192.0.2.5", "198.51.100.1", "169.254.169.254",
	             "::ffff:169.254.169.254", "169.254.1.1", "fd00:ec2::254"):
	    assert net_ok(BOTH, addr) == (net_ok(A, addr) and net_ok(H, addr)), addr
	assert not net_ok(BOTH, "169.254.169.254")
	assert not net_ok(BOTH, "::ffff:169.254.169.254")
	assert not net_ok(BOTH, "fd00:ec2::254")
	assert net_ok(BOTH, "192.0.2.5")
	assert not net_ok(BOTH, "198.51.100.1")

	for fam in (1, 2, 10, 38, 40):
	    assert fam_ok(BOTH, fam) == (fam_ok(A, fam) and fam_ok(H, fam)), fam
	assert not fam_ok(BOTH, 40) and not fam_ok(BOTH, 38) and fam_ok(BOTH, 2)

	for fb in (0, A, H, BOTH):
	    assert exec_ok(BOTH, fb) == (exec_ok(A, fb) and exec_ok(H, fb)), fb
	assert exec_ok(A, H) and not exec_ok(H, A) and not exec_ok(BOTH, A) and exec_ok(BOTH, H)

	# Shared pattern (.env) with distinct ops across sandboxes must not bleed.
	READ, WRITE = 0x8, 0x4
	assert fim_denied(A, READ, b".env") and not fim_denied(A, WRITE, b".env")
	assert fim_denied(H, WRITE, b".env") and not fim_denied(H, READ, b".env")
	assert fim_denied(BOTH, READ, b".env") and fim_denied(BOTH, WRITE, b".env")

	assert (BOTH & d_userns) and (BOTH & d_ptrace) and not (BOTH & d_mount)
	PY
'

test_done
