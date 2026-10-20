-- SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

local RECORD = 128
local FAMILIES = {
	[1] = "unix", [2] = "inet", [10] = "inet6", [16] = "netlink",
	[17] = "packet", [40] = "vsock", [44] = "xdp",
}
local TYPES = {
	[1] = "stream", [2] = "dgram", [3] = "raw", [4] = "rdm",
	[5] = "seqpacket", [6] = "dccp", [10] = "packet",
}
local OPERATIONS = {
	[1] = "create", [2] = "bind", [3] = "connect", [4] = "listen",
	[5] = "accept", [6] = "sendmsg", [7] = "recvmsg",
	[8] = "setsockopt", [9] = "shutdown", [10] = "socketpair",
}

local function header(slot)
	return {
		boot_now_ns = slot:u64(32),
		since_ns = slot:u64(40),
		used = slot:u32(48),
		overflow = slot:u32(52),
		lost = slot:u32(56),
		peek = slot:u32(28) % 2 == 1,
	}
end

local function unix_nano(input, hdr, ts)
	if ts == "0" then
		return nil
	end
	return shirudo.u64_sub(input.timeUnixNano,
		shirudo.u64_sub(hdr.boot_now_ns, ts))
end

local function interval(input, hdr)
	return {
		since_unix_nano = unix_nano(input, hdr, hdr.since_ns),
		used = hdr.used,
		overflow = hdr.overflow,
		lost = hdr.lost,
		peek = hdr.peek,
	}
end

local function record(input, hdr, slot)
	local flags = slot:u32(84)
	local family, type = slot:u16(64), slot:u16(66)
	local operation = slot:u16(68)
	return {
		entry_index = slot:u32(0),
		owner = {
			executable = { dev = slot:u32(8), ino = slot:u64(16) },
			cgroup_id = slot:u64(24),
			pid = slot:u32(56),
			known = flags % 2 == 1,
			inferred = math.floor(flags / 2) % 2 == 1,
		},
		actor = {
			executable = { dev = slot:u32(32), ino = slot:u64(40) },
			cgroup_id = slot:u64(48),
			pid = slot:u32(60),
			known = math.floor(flags / 4) % 2 == 1,
		},
		family = family,
		family_name = FAMILIES[family] or family,
		type = type,
		type_name = TYPES[type] or type,
		operation = OPERATIONS[operation] or operation,
		protocol = slot:u32(72),
		level = slot:u32(76),
		option = slot:u32(80),
		count = slot:u64(96),
		bytes_requested = slot:u64(120),
		first_seen_unix_nano = unix_nano(input, hdr, slot:u64(104)),
		last_seen_unix_nano = unix_nano(input, hdr, slot:u64(112)),
	}
end

function decode(input)
	local records, summary = {}, nil
	for _, page in ipairs(input.data.pages) do
		local slots = shirudo.page_slots(page, RECORD)
		local hdr = slots[1] and header(slots[1])
		if hdr then
			summary = summary or interval(input, hdr)
			for i = 2, #slots do
				if slots[i]:u32(4) % 2 == 1 then
					records[#records + 1] = record(input, hdr, slots[i])
				end
			end
		end
	end
	return {
		schema = 2,
		upatch = input.upatch,
		map = input.map,
		interval = summary,
		records = records,
	}
end
