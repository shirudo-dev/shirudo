// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Check tree_recover_pending() against the independent recovery model,
 * without also expanding the later tree operations.
 */

#define harness whole_tree_sync_harness
#include "bpm-tree-sync-model.c"
#undef harness

static void recovery_start(struct tree_state *actual, struct mstate *model)
{
	if (have_state) {
		*actual = disk_state;
	} else {
		actual->schema = 1;
		bpm_copy_string(actual->tree_id, sizeof(actual->tree_id),
				fetched.tree_id);
		memset(actual->projection_root, '0', 64);
		actual->projection_root[64] = '\0';
		memset(actual->projection_root_tpm, '0', 64);
		actual->projection_root_tpm[64] = '\0';
	}
	model->tree_id[0] = have_state ? disk_state.tree_id[0] :
					fetched.tree_id[0];
	model->tree_id[1] = '\0';
	model->generation = have_state ? disk_state.generation : 0;
	model->last_seq = have_state ? disk_state.last_seq : 0;
	model->manifest[0] = have_state ? disk_state.manifest_digest[0] : '\0';
	model->manifest[1] = '\0';
	for (int i = 0; i < 32; i++)
		model->root[i] = have_state ?
				 (__u8)disk_state.projection_root[i] : '0';
}

static void recovery_state_matches(const struct tree_state *actual,
				   const struct mstate *model)
{
	bool tpm_root_set = !have_state ||
			    actual->last_seq != disk_state.last_seq;

	__CPROVER_assert(actual->generation == model->generation,
			 "recovery keeps the generation");
	__CPROVER_assert(actual->last_seq == model->last_seq,
			 "recovery advances the expected cursor");
	__CPROVER_assert(actual->tree_id[0] == model->tree_id[0] &&
			 actual->tree_id[1] == model->tree_id[1],
			 "recovery keeps the tree ID");
	__CPROVER_assert(actual->manifest_digest[0] == model->manifest[0] &&
			 actual->manifest_digest[1] == model->manifest[1],
			 "recovery keeps the manifest");
	for (int i = 0; i < 32; i++) {
		__CPROVER_assert((__u8)actual->projection_root[i] ==
				 model->root[i],
				 "recovery records the expected root bytes");
		if (tpm_root_set)
			__CPROVER_assert((__u8)actual->projection_root_tpm[i] ==
					 model->root[i],
					 "recovery records the expected TPM root bytes");
	}
}

void harness(void)
{
	struct tree_state actual = {};
	struct mstate model = {};
	__u32 first_failure;
	bool model_ok;
	int ret;

	fail_at = first_failure;
	any_node();
	any_publication();
	__CPROVER_assume(checked());
	any_replay_root();
	recovery_start(&actual, &model);
	model_ok = recover(&model);
	ret = tree_recover_pending(&fetched, &actual);
	__CPROVER_assert(failed || (ret == 0) == model_ok,
			 "recovery accepts the same pending state as the model");
	__CPROVER_assert(failed || n_got == n_want,
			 "recovery makes every expected write");
	if (!failed && model_ok)
		recovery_state_matches(&actual, &model);
}
