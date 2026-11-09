/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_CONFIG_UPDATE_H
#define SHIRUDO_CONFIG_UPDATE_H

#include <shirudo/misc.h>

#include <stdbool.h>
#include <stdint.h>

#define CONFIG_UPDATE_PREFIX_MAX 4096u

enum config_event_kind {
	CONFIG_EVENT_BOOT = 1,
	CONFIG_EVENT_UPDATE = 2,
};

enum config_update_checkpoint {
	CONFIG_CHECK_PENDING_SYNC = 1,
	CONFIG_CHECK_EXTEND,
	CONFIG_CHECK_EVENT_SYNC,
	CONFIG_CHECK_ACTIVATE,
	CONFIG_CHECK_COMPLETE_SYNC,
	CONFIG_CHECK_STATE_WRITE,
	CONFIG_CHECK_STATE_RENAME,
	CONFIG_CHECK_EVENT_WRITE,
};

struct config_update_target {
	char prefix[CONFIG_UPDATE_PREFIX_MAX];
	__u8 root_hash[32];
};

struct config_update_record {
	struct config_update_target target;
	__u8 initial_pcr[32];
	__u64 sequence;
	__u32 reset_count;
	__u32 restart_count;
	__u32 pcr;
	enum config_event_kind kind;
	bool pending;
};

/* prepare verifies the signed mapping and contents before saving intent. */
struct config_update_ops {
	int (*boot_identity)(void *ctx, __u32 *reset, __u32 *restart);
	int (*pcr_read)(void *ctx, __u32 pcr, __u8 out[32]);
	int (*pcr_extend)(void *ctx, __u32 pcr, const __u8 event[32]);
	int (*prepare)(void *ctx,
		       const struct config_update_target *target);
	int (*activate)(void *ctx,
			const struct config_update_target *target);
	int (*seal)(void *ctx, int fd);
	int (*checkpoint)(void *ctx,
			  enum config_update_checkpoint checkpoint);
	/* How long to wait for another command's operation lock; 0 fails at once. */
	__u32 lock_wait_ms;
};

typedef int (*shirudo_config_cb)(const struct config_update_record *r,
				void *ctx);

struct config_update {
	const struct config_update_ops *ops;
	void *ctx;
	int dir_fd;
	int lock_fd;
	bool boot_pending;
};

/* Holds the update lock until close. The directory must already exist. */
int config_update_open(const char *directory,
		       const struct config_update_ops *ops,
		       void *ctx, struct config_update *out);
void config_update_close(struct config_update *update);
int config_update_read(struct config_update *update,
		       struct config_update_record *out);
/*
 * next-boot uses the selection record format: its target is the candidate,
 * and its sequence and TPM counts identify the selection it was staged from.
 */
int config_update_stage(struct config_update *update,
			const struct config_update_target *target);
int config_update_stage_read(struct config_update *update,
			     struct config_update_record *out);
/* 1 selects an eligible staged target, 0 leaves the current selection. */
int config_update_staged(struct config_update *update,
			 const struct config_update_record *previous,
			 __u32 reset, __u32 restart,
			 struct config_update_target *target);
int config_update_clear_staged(struct config_update *update);
int config_update_begin(struct config_update *update,
			const struct config_update_target *t,
			__u32 pcr);
/* Boot leaves intent pending until upatch restoration and NV init succeed. */
int config_update_boot(struct config_update *update,
		       const struct config_update_target *t,
		       __u32 pcr);
int config_update_complete_boot(struct config_update *update);
/* Refuses pending updates and PCR drift; callers also validate live mounts. */
int config_update_check(struct config_update *update,
			struct config_update_record *out);
/* Events describe selections, not a proof that activation completed. */
int config_update_events(struct config_update *update,
			 shirudo_config_cb consume, void *ctx);

#endif /* SHIRUDO_CONFIG_UPDATE_H */
