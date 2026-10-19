// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * obs_exec.bpf.c -- executable identity and exec edges.
 *
 * Every exec records the executed file, the image that called exec, the
 * cgroup and the credentials the new image starts with, and stores the
 * executable as the task's identity so that network, file and privilege
 * records can be attributed to it.
 */

#define OBS_EXEC_F_INTERP		(1u << 0)
#define OBS_EXEC_F_CALLER_INFERRED	(1u << 1)
#define OBS_EXEC_F_CALLER_UNKNOWN	(1u << 2)
#define OBS_EXEC_F_PATH_TRUNCATED	(1u << 3)

struct exec_key {
	struct obs_ident ident;
	struct obs_exe caller;
	__u32 euid;
	__u32 flags;
};

struct exec_val {
	__u64 count;
	__u64 first_ns;
	__u64 last_ns;
	__u32 pid;
	__u32 uid;
	__u64 caps;
	__u32 flags;
	__u32 _pad;
	char name[OBS_NAME_LEN];
	char path[OBS_PATH_LEN];
};

#define OBS_T		exec
#define OBS_T_MAP	exec
#define OBS_T_KEY	struct exec_key
#define OBS_T_VAL	struct exec_val
#define OBS_T_CAPACITY	2048
#define OBS_T_BUCKETS	1024
#define OBS_T_STEPS	8
#define OBS_T_MAGIC	0x43455845u	/* "EXEC" little-endian */
#define OBS_T_RECORD	256
#define OBS_T_EMIT	exec_emit_record
#include "obs_table.h"

static int exec_emit_record(struct shirudo_serial_chunk *chunk, __u32 off,
			    const struct exec_entry __arena *e)
{
	*(__u32 *)&chunk->data[off + 8] = e->key.ident.exe.dev;
	*(__u32 *)&chunk->data[off + 12] = 0;
	*(__u64 *)&chunk->data[off + 16] = e->key.ident.exe.ino;
	*(__u64 *)&chunk->data[off + 24] = e->key.ident.cgroup;
	*(__u32 *)&chunk->data[off + 32] = e->key.caller.dev;
	*(__u32 *)&chunk->data[off + 36] = 0;
	*(__u64 *)&chunk->data[off + 40] = e->key.caller.ino;
	*(__u32 *)&chunk->data[off + 48] = e->key.euid;
	*(__u32 *)&chunk->data[off + 52] = e->val.uid;
	*(__u32 *)&chunk->data[off + 56] = e->key.flags | e->val.flags;
	*(__u32 *)&chunk->data[off + 60] = e->val.pid;
	*(__u64 *)&chunk->data[off + 64] = e->val.count;
	*(__u64 *)&chunk->data[off + 72] = e->val.first_ns;
	*(__u64 *)&chunk->data[off + 80] = e->val.last_ns;
	*(__u64 *)&chunk->data[off + 88] = e->val.caps;
	obs_emit_bytes(chunk, off + 96, e->val.name, OBS_NAME_LEN / 8);
	obs_emit_bytes(chunk, off + 128, e->val.path, OBS_PATH_LEN / 8);
	return 0;
}

/*
 * Sleepable so that the path can be resolved; the hook runs once per
 * binfmt pass, so a script yields one record for the script and one,
 * flagged, for its interpreter.  The task's identity is the file named
 * in the exec, not the interpreter that ends up running it.
 */
SEC("lsm.s/bprm_check_security")
int BPF_PROG(obs_exec, struct linux_binprm *bprm)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct obs_task_meta *meta;
	struct exec_entry __arena *e;
	struct exec_key key = {};
	char path[OBS_PATH_LEN] = {};
	char name[OBS_NAME_LEN] = {};
	struct file *file;
	__u64 now = obs_now();
	__u32 euid, uid;
	__u64 caps;
	bool interp;
	int status;
	long len;

	file = bprm->file;
	if (!file || obs_exe_from_file(file, &key.ident.exe))
		return 0;
	key.ident.cgroup = bpf_get_current_cgroup_id();
	interp = bprm->interp != bprm->filename;
	euid = bprm->cred->euid.val;
	uid = bprm->cred->uid.val;
	caps = bprm->cred->cap_effective.val;

	meta = obs_task_meta(task);
	if (meta) {
		obs_cred_check(task, meta, now);
		key.caller = meta->exe;
		if (meta->flags & OBS_TASK_INFERRED)
			key.flags |= OBS_EXEC_F_CALLER_INFERRED;
	} else {
		key.flags |= OBS_EXEC_F_CALLER_UNKNOWN;
	}
	if (interp)
		key.flags |= OBS_EXEC_F_INTERP;
	key.euid = euid;

	e = exec_touch(&key, &status);
	if (e) {
		if (status == OBS_TOUCH_CREATED) {
			obs_name_from_file(file, name);
			obs_copy_in(e->val.name, name, OBS_NAME_LEN / 8);
			len = bpf_d_path(&file->f_path, path, sizeof(path));
			if (len > 0)
				obs_copy_in(e->val.path, path, OBS_PATH_LEN / 8);
			else
				e->val.flags = OBS_EXEC_F_PATH_TRUNCATED;
			e->val.first_ns = now;
			e->val.uid = uid;
			e->val.caps = caps;
		}
		__sync_fetch_and_add(&e->val.count, 1);
		e->val.last_ns = now;
		e->val.pid = obs_tgid();
	}

	if (!meta)
		meta = bpf_task_storage_get(&obs_i_task, task, 0,
					    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (meta) {
		if (!interp) {
			meta->exe = key.ident.exe;
			meta->flags &= ~OBS_TASK_INFERRED;
		}
		meta->euid = euid;
		meta->flags &= ~OBS_TASK_ANOMALY;
	}
	return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(obs_task_alloc, struct task_struct *child, __u64 clone_flags)
{
	struct task_struct *parent = bpf_get_current_task_btf();
	struct obs_task_meta *meta, *inherited;

	(void)clone_flags;
	inherited = obs_task_meta(parent);
	if (!inherited)
		return 0;
	meta = bpf_task_storage_get(&obs_i_task, child, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!meta)
		return 0;
	meta->exe = inherited->exe;
	meta->euid = inherited->euid;
	meta->flags = inherited->flags & OBS_TASK_INFERRED;
	return 0;
}

#ifdef SHIRUDO_TEST_CRED_ANOMALY
SEC("lsm/bprm_committed_creds")
int BPF_PROG(obs_test_cred_anomaly, const struct linux_binprm *bprm)
{
	char name[OBS_NAME_LEN] = {};
	struct obs_task_meta *meta;
	struct task_struct *task;

	if (!bprm->file)
		return 0;
	obs_name_from_file(bprm->file, name);
	if (name[0] != 't' || name[1] != 'r' || name[2] != 'u' ||
	    name[3] != 'e' || name[4])
		return 0;
	task = bpf_get_current_task_btf();
	meta = obs_task_meta(task);
	if (!meta)
		return 0;
	meta->euid = 1;
	obs_cred_check(task, meta, obs_now());
	obs_cred_check(task, meta, obs_now());
	return 0;
}
#endif
