-- SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

local RECORD = 256
local HEADER = 64
local AGENT = 48
local NAME_LEN = 40
local MORE_AGENTS = 2

local function bit(value, n)
	return math.floor(value / 2 ^ n) % 2 == 1
end

local function unix_nano(input, boot_now, ts)
	if ts == "0" then
		return nil
	end
	return shirudo.u64_sub(input.timeUnixNano, shirudo.u64_sub(boot_now, ts))
end

local function agents(slot)
	local list = {}
	local flags = slot:u32(4)
	for i = 0, slot:u32(56) - 1 do
		local off = HEADER + i * AGENT
		list[#list + 1] = {
			name = slot:cstring(off + 8, NAME_LEN),
			name_truncated = bit(flags, 8 + i),
			ino = slot:u64(off),
		}
	end
	return list
end

local function record(input, boot_now, slot)
	local list = agents(slot)
	return {
		pid = slot:u32(8),
		euid = slot:u32(12),
		started_unix_nano = unix_nano(input, boot_now, slot:u64(16)),
		cgroup_id = slot:u64(24),
		seen_unix_nano = unix_nano(input, boot_now, slot:u64(32)),
		mnt_ns = slot:u32(40),
		libjvm = { dev = slot:u32(44), ino = slot:u64(48) },
		agents = list,
		patched = #list > 0,
		more_agents = bit(slot:u32(4), 1),
	}
end

function decode(input)
	local jvms, overflow = {}, 0
	for _, page in ipairs(input.data.pages) do
		local slots = shirudo.page_slots(page, RECORD)
		local hdr = slots[1]
		if hdr then
			local boot_now = hdr:u64(24)
			overflow = hdr:u32(16)
			for i = 2, #slots do
				if slots[i]:u32(4) % 2 == 1 then
					jvms[#jvms + 1] = record(input, boot_now, slots[i])
				end
			end
		end
	end
	local unpatched = 0
	for _, jvm in ipairs(jvms) do
		if not jvm.patched then
			unpatched = unpatched + 1
		end
	end
	return {
		schema = 1,
		upatch = input.upatch,
		map = input.map,
		overflow = overflow,
		unpatched = unpatched,
		jvms = jvms,
	}
end
