// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>
#include <shirudo/tpm.h>

#include <errno.h>
#include <string.h>

#include "config_measure.h"
#include "crypto.h"

/* A config register is a static PCR or the config NvPCR's index. */
int config_measure_pcr_valid(__u32 pcr)
{
	return (pcr < 16 && pcr != 9 && pcr != 11) ||
	       pcr == TPM_CONFIG_NVPCR_INDEX ? 0 : -EINVAL;
}

bool config_measure_nvpcr(__u32 pcr)
{
	return pcr == TPM_CONFIG_NVPCR_INDEX;
}

/* systemd's unlogged initializing write extends a zero digest. */
int config_measure_nvpcr_initial(__u8 out[32])
{
	__u8 zero[64] = {};

	return sha256_buffer(zero, sizeof(zero), out);
}

int config_measure_event(enum config_event_kind kind,
			 const __u8 root_hash[32], __u8 out[32])
{
	static const char domain[] = "shirudo-config-root-v1";
	__u8 data[sizeof(domain) + 4 + 32];

	if (!root_hash || !out ||
	    (kind != CONFIG_EVENT_BOOT &&
	     kind != CONFIG_EVENT_UPDATE))
		return -EINVAL;
	memcpy(data, domain, sizeof(domain));
	data[sizeof(domain)] = 0;
	data[sizeof(domain) + 1] = 0;
	data[sizeof(domain) + 2] = 0;
	data[sizeof(domain) + 3] = kind;
	memcpy(data + sizeof(domain) + 4, root_hash, 32);
	return sha256_buffer(data, sizeof(data), out);
}
