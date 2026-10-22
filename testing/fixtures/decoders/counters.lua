-- SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

function decode(input)
	if not input.data.serialized or input.data.serialized_pages ~= 2 or
	   input.data.serialized_bytes ~= 48 then
		error("unexpected serialized counter payload")
	end
	local records = shirudo.fixed_records(input.data.pages, 24)
	if not records[1] or not records[2] or records[1]:u32(0) ~= 0 or
	   records[2]:u32(0) ~= 1 then
		error("unexpected counter records")
	end
	local packets = tonumber(records[1]:u64(8)) + tonumber(records[2]:u64(8))
	local bytes = tonumber(records[1]:u64(16)) + tonumber(records[2]:u64(16))
	return {
		{name = "shirudo.serialized.packets", unit = "1", sum = {
			aggregationTemporality = 2, isMonotonic = true,
			dataPoints = {{startTimeUnixNano = "1699999990000000000",
				timeUnixNano = "1700000000000000000", asInt = tostring(packets)}}}},
		{name = "shirudo.serialized.bytes", unit = "By", sum = {
			aggregationTemporality = 2, isMonotonic = true,
			dataPoints = {{startTimeUnixNano = "1699999990000000000",
				timeUnixNano = "1700000000000000000", asInt = tostring(bytes)}}}},
	}
end
