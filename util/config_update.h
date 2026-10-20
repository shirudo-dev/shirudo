/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_CONFIG_UPDATE_H
#define SHIRUDO_CONFIG_UPDATE_H

#include <shirudo/misc.h>

#include <stdbool.h>
#include <stdint.h>

#define SHIRUDO_CONFIG_UPDATE_PREFIX_MAX 4096u

enum shirudo_config_event_kind {
	SHIRUDO_CONFIG_EVENT_BOOT = 1,
	SHIRUDO_CONFIG_EVENT_UPDATE = 2,
};

enum shirudo_config_update_checkpoint {
	SHIRUDO_CONFIG_CHECK_PENDING_SYNC = 1,
	SHIRUDO_CONFIG_CHECK_EXTEND,
	SHIRUDO_CONFIG_CHECK_EVENT_SYNC,
	SHIRUDO_CONFIG_CHECK_ACTIVATE,
	SHIRUDO_CONFIG_CHECK_COMPLETE_SYNC,
	SHIRUDO_CONFIG_CHECK_STATE_WRITE,
	SHIRUDO_CONFIG_CHECK_STATE_RENAME,
	SHIRUDO_CONFIG_CHECK_EVENT_WRITE,
};

struct shirudo_config_update_target {
	char prefix[SHIRUDO_CONFIG_UPDATE_PREFIX_MAX];
	__u8 root_hash[32];
};

struct shirudo_config_update_record {
	struct shirudo_config_update_target target;
	__u8 initial_pcr[32];
	__u64 sequence;
	__u32 reset_count;
	__u32 restart_count;
	__u32 pcr;
	enum shirudo_config_event_kind kind;
	bool pending;
};

/* prepare verifies the signed mapping and contents before saving intent. */
struct shirudo_config_update_ops {
	int (*boot_identity)(void *ctx, __u32 *reset, __u32 *restart);
	int (*pcr_read)(void *ctx, __u32 pcr, __u8 out[32]);
	int (*pcr_extend)(void *ctx, __u32 pcr, const __u8 event[32]);
	int (*prepare)(void *ctx,
		       const struct shirudo_config_update_target *target);
	int (*activate)(void *ctx,
			const struct shirudo_config_update_target *target);
	int (*seal)(void *ctx, int fd);
	int (*checkpoint)(void *ctx,
			  enum shirudo_config_update_checkpoint checkpoint);
};

typedef int (*shirudo_config_cb)(const struct shirudo_config_update_record *r,
				void *ctx);

struct shirudo_config_update {
	const struct shirudo_config_update_ops *ops;
	void *ctx;
	int dir_fd;
	int lock_fd;
	bool boot_pending;
};

/* Holds the update lock until close. The directory must already exist. */
int shirudo_config_update_open(const char *directory,
			       const struct shirudo_config_update_ops *ops,
			       void *ctx, struct shirudo_config_update *out);
void shirudo_config_update_close(struct shirudo_config_update *update);
int shirudo_config_update_read(struct shirudo_config_update *update,
			       struct shirudo_config_update_record *out);
int shirudo_config_update_begin(struct shirudo_config_update *update,
				const struct shirudo_config_update_target *t,
				__u32 pcr);
/* Boot leaves intent pending until upatch restoration and NV init succeed. */
int shirudo_config_update_boot(struct shirudo_config_update *update,
			       const struct shirudo_config_update_target *t,
			       __u32 pcr);
int shirudo_config_update_complete_boot(struct shirudo_config_update *update);
/* Refuses pending updates and PCR drift; callers also validate live mounts. */
int shirudo_config_update_check(struct shirudo_config_update *update,
				struct shirudo_config_update_record *out);
/* Events describe selections, not a proof that activation completed. */
int shirudo_config_update_events(struct shirudo_config_update *update,
				 shirudo_config_cb consume, void *ctx);

#endif /* SHIRUDO_CONFIG_UPDATE_H */
