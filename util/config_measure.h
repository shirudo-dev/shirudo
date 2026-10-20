/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_CONFIG_MEASURE_H
#define SHIRUDO_CONFIG_MEASURE_H

#include <shirudo/misc.h>

#include <stdint.h>

#include "config_update.h"

int shirudo_config_measure_pcr_valid(__u32 pcr);
int shirudo_config_measure_event(enum shirudo_config_event_kind kind,
				 const __u8 root_hash[32], __u8 out[32]);

#endif /* SHIRUDO_CONFIG_MEASURE_H */
