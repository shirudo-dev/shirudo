// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>

#include <errno.h>
#include <string.h>

#include "config_measure.h"
#include "crypto.h"

int shirudo_config_measure_pcr_valid(__u32 pcr)
{
	return pcr < 16 && pcr != 9 && pcr != 11 ? 0 : -EINVAL;
}

int shirudo_config_measure_event(enum shirudo_config_event_kind kind,
				 const __u8 root_hash[32], __u8 out[32])
{
	static const char domain[] = "shirudo-config-root-v1";
	__u8 data[sizeof(domain) + 4 + 32];

	if (!root_hash || !out ||
	    (kind != SHIRUDO_CONFIG_EVENT_BOOT &&
	     kind != SHIRUDO_CONFIG_EVENT_UPDATE))
		return -EINVAL;
	memcpy(data, domain, sizeof(domain));
	data[sizeof(domain)] = 0;
	data[sizeof(domain) + 1] = 0;
	data[sizeof(domain) + 2] = 0;
	data[sizeof(domain) + 3] = kind;
	memcpy(data + sizeof(domain) + 4, root_hash, 32);
	return sha256_buffer(data, sizeof(data), out);
}
