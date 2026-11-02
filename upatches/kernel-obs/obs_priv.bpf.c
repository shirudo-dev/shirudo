// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * obs_priv.bpf.c -- privilege transitions and persistence primitives.
 *
 * Records credential changes to root, root privileges that no exec or
 * setuid explains, ptrace attaches, mounts, executable mappings, kernel
 * file and module loads, user namespace creation and bpf() use, keyed by
 * the executable and cgroup that performed them.
 */

enum obs_priv_kind {
	OBS_PRIV_SETUID_ROOT = 1,
	OBS_PRIV_CRED_ANOMALY = 2,
	OBS_PRIV_PTRACE_ATTACH = 3,
	OBS_PRIV_MOUNT = 4,
	OBS_PRIV_KERNEL_READ_FILE = 5,
	OBS_PRIV_KERNEL_LOAD_DATA = 6,
	OBS_PRIV_MODULE_REQUEST = 7,
	OBS_PRIV_USERNS_CREATE = 8,
	OBS_PRIV_BPF = 9,
	OBS_PRIV_MMAP_EXEC = 10,
	OBS_PRIV_MPROTECT_EXEC = 11,
};

#define OBS_PRIV_DETAIL_LEN	96
#define PTRACE_MODE_ATTACH	0x02
#define OBS_PROT_EXEC		(1UL << 2)
#define OBS_VM_EXEC		(1UL << 2)

struct priv_key {
	struct obs_ident ident;
	__u32 kind;
	__u32 subtype;
	__u32 euid;
	__u32 _pad;
};

struct priv_val {
	__u64 count;
	__u64 first_ns;
	__u64 last_ns;
	__u32 pid;
	__u32 uid;
	__u64 aux;
	char name[OBS_NAME_LEN];
	char detail[OBS_PRIV_DETAIL_LEN];
};

#define OBS_T		priv
#define OBS_T_MAP	priv
#define OBS_T_KEY	struct priv_key
#define OBS_T_VAL	struct priv_val
#define OBS_T_CAPACITY	1024
#define OBS_T_BUCKETS	512
#define OBS_T_STEPS	8
#define OBS_T_MAGIC	0x56495250u	/* "PRIV" little-endian */
#define OBS_T_RECORD	224
#define OBS_T_EMIT	priv_emit_record
#include "obs_table.h"

static int priv_emit_record(struct serial_chunk *chunk, __u32 off,
			    const struct priv_entry __arena *e)
{
	*(__u32 *)&chunk->data[off + 8] = e->key.ident.exe.dev;
	*(__u32 *)&chunk->data[off + 12] = 0;
	*(__u64 *)&chunk->data[off + 16] = e->key.ident.exe.ino;
	*(__u64 *)&chunk->data[off + 24] = e->key.ident.cgroup;
	*(__u32 *)&chunk->data[off + 32] = e->key.kind;
	*(__u32 *)&chunk->data[off + 36] = e->key.subtype;
	*(__u32 *)&chunk->data[off + 40] = e->key.euid;
	*(__u32 *)&chunk->data[off + 44] = e->val.uid;
	*(__u64 *)&chunk->data[off + 48] = e->val.count;
	*(__u64 *)&chunk->data[off + 56] = e->val.first_ns;
	*(__u64 *)&chunk->data[off + 64] = e->val.last_ns;
	*(__u32 *)&chunk->data[off + 72] = e->val.pid;
	*(__u32 *)&chunk->data[off + 76] = 0;
	*(__u64 *)&chunk->data[off + 80] = e->val.aux;
	obs_emit_bytes(chunk, off + 88, e->val.name, OBS_NAME_LEN / 8);
	obs_emit_bytes(chunk, off + 120, e->val.detail,
		       OBS_PRIV_DETAIL_LEN / 8);
	*(__u64 *)&chunk->data[off + 216] = 0;
	return 0;
}

static __always_inline struct priv_entry __arena *
priv_record(const struct obs_ident *ident, __u32 kind, __u32 subtype,
	    __u32 euid, __u64 now, int *status)
{
	struct priv_entry __arena *e;
	struct priv_key key = {};

	key.ident = *ident;
	key.kind = kind;
	key.subtype = subtype;
	key.euid = euid;
	e = priv_touch(&key, status);
	if (!e)
		return 0;
	if (*status == OBS_TOUCH_CREATED) {
		e->val.first_ns = now;
		e->val.uid = (__u32)bpf_get_current_uid_gid();
	}
	__sync_fetch_and_add(&e->val.count, 1);
	e->val.last_ns = now;
	e->val.pid = obs_tgid();
	return e;
}

static __always_inline void priv_set_name(struct priv_entry __arena *e,
					  const char *name)
{
	obs_copy_in(e->val.name, name, OBS_NAME_LEN / 8);
}

static __always_inline void priv_set_detail(struct priv_entry __arena *e,
					    const char *detail)
{
	obs_copy_in(e->val.detail, detail, OBS_PRIV_DETAIL_LEN / 8);
}

static __always_inline void priv_set_mapping_name(struct priv_entry __arena *e,
						  struct file *filp)
{
	char name[OBS_NAME_LEN] = {};

	if (filp)
		obs_name_from_file(filp, name);
	else
		__builtin_memcpy(name, "anonymous", sizeof("anonymous"));
	priv_set_name(e, name);
}

/*
 * A task whose effective uid is zero while its last exec or setuid left
 * it unprivileged gained root some other way, which is what a kernel
 * exploit looks like from the inside.  Report it once per task.
 */
static __always_inline void obs_cred_check(struct task_struct *task,
					   struct obs_task_meta *meta,
					   __u64 now)
{
	struct priv_entry __arena *e;
	struct obs_ident ident = {};
	char comm[OBS_NAME_LEN] = {};
	int status;
	__u32 euid;

	if (!meta || (meta->flags & OBS_TASK_ANOMALY))
		return;
	euid = obs_task_euid(task);
	if (euid != 0 || meta->euid == 0)
		return;
	meta->flags |= OBS_TASK_ANOMALY;
	ident.exe = meta->exe;
	ident.cgroup = bpf_get_current_cgroup_id();
	e = priv_record(&ident, OBS_PRIV_CRED_ANOMALY, meta->euid, euid, now,
			&status);
	if (e && status == OBS_TOUCH_CREATED) {
		bpf_get_current_comm(comm, 16);
		priv_set_name(e, comm);
	}
}

/* Identity of the current task with the credential check applied. */
static __always_inline bool obs_ident_checked(struct obs_ident *ident,
					      __u64 now)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct obs_task_meta *meta = obs_task_meta(task);

	__builtin_memset(ident, 0, sizeof(*ident));
	ident->cgroup = bpf_get_current_cgroup_id();
	if (!meta)
		return false;
	obs_cred_check(task, meta, now);
	ident->exe = meta->exe;
	return true;
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(obs_setuid, struct cred *new, const struct cred *old, int flags)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct obs_task_meta *meta = obs_task_meta(task);
	struct priv_entry __arena *e;
	struct obs_ident ident = {};
	char comm[OBS_NAME_LEN] = {};
	__u64 now = obs_now();
	__u32 new_euid, old_euid;
	int status;

	new_euid = new->euid.val;
	old_euid = old->euid.val;
	if (meta) {
		obs_cred_check(task, meta, now);
		meta->euid = new_euid;
		ident.exe = meta->exe;
	}
	if (new_euid != 0 || old_euid == 0)
		return 0;
	ident.cgroup = bpf_get_current_cgroup_id();
	e = priv_record(&ident, OBS_PRIV_SETUID_ROOT, (__u32)flags, old_euid,
			now, &status);
	if (e && status == OBS_TOUCH_CREATED) {
		e->val.aux = new->uid.val;
		bpf_get_current_comm(comm, 16);
		priv_set_name(e, comm);
	}
	return 0;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(obs_ptrace, struct task_struct *child, unsigned int mode)
{
	struct priv_entry __arena *e;
	struct obs_ident ident;
	char comm[OBS_NAME_LEN] = {};
	__u64 now = obs_now();
	__u32 child_tgid;
	int status;

	if (!(mode & PTRACE_MODE_ATTACH))
		return 0;
	child_tgid = BPF_CORE_READ(child, tgid);
	if (child_tgid == obs_tgid())
		return 0;
	obs_ident_checked(&ident, now);
	e = priv_record(&ident, OBS_PRIV_PTRACE_ATTACH, mode,
			obs_current_euid(), now,
			&status);
	if (!e)
		return 0;
	e->val.aux = child_tgid;
	if (status == OBS_TOUCH_CREATED) {
		bpf_probe_read_kernel_str(comm, 16, child->comm);
		priv_set_name(e, comm);
	}
	return 0;
}

SEC("lsm.s/sb_mount")
int BPF_PROG(obs_mount,
	     const char *dev_name __attribute__((__unused__)),
	     const struct path *path, const char *type, unsigned long flags,
	     void *data __attribute__((__unused__)))
{
	struct priv_entry __arena *e;
	struct obs_ident ident;
	char detail[OBS_PRIV_DETAIL_LEN] = {};
	char name[OBS_NAME_LEN] = {};
	__u64 now = obs_now();
	int status;

	obs_ident_checked(&ident, now);
	e = priv_record(&ident, OBS_PRIV_MOUNT, (__u32)flags,
			obs_current_euid(), now,
			&status);
	if (!e)
		return 0;
	e->val.aux = flags;
	if (status == OBS_TOUCH_CREATED) {
		if (type)
			bpf_probe_read_kernel_str(name, sizeof(name), type);
		priv_set_name(e, name);
		if (path && bpf_d_path((struct path *)path, detail,
				       sizeof(detail)) > 0)
			priv_set_detail(e, detail);
	}
	return 0;
}

SEC("lsm.s/kernel_read_file")
int BPF_PROG(obs_kernel_read_file, struct file *filp,
	     enum kernel_read_file_id id,
	     bool contents __attribute__((__unused__)))
{
	struct priv_entry __arena *e;
	struct obs_ident ident;
	char detail[OBS_PRIV_DETAIL_LEN] = {};
	char name[OBS_NAME_LEN] = {};
	__u64 now = obs_now();
	int status;

	obs_ident_checked(&ident, now);
	e = priv_record(&ident, OBS_PRIV_KERNEL_READ_FILE, (__u32)id,
			obs_current_euid(), now,
			&status);
	if (!e || status != OBS_TOUCH_CREATED)
		return 0;
	obs_name_from_file(filp, name);
	priv_set_name(e, name);
	if (filp && bpf_d_path(&filp->f_path, detail, sizeof(detail)) > 0)
		priv_set_detail(e, detail);
	return 0;
}

SEC("lsm/kernel_load_data")
int BPF_PROG(obs_kernel_load_data, enum kernel_load_data_id id,
	     bool contents __attribute__((__unused__)))
{
	struct obs_ident ident;
	__u64 now = obs_now();
	int status;

	obs_ident_checked(&ident, now);
	priv_record(&ident, OBS_PRIV_KERNEL_LOAD_DATA, (__u32)id,
		    obs_current_euid(), now, &status);
	return 0;
}

SEC("lsm/kernel_module_request")
int BPF_PROG(obs_module_request, char *kmod_name)
{
	struct priv_entry __arena *e;
	struct obs_ident ident;
	char name[OBS_NAME_LEN] = {};
	__u64 now = obs_now();
	int status;

	obs_ident_checked(&ident, now);
	e = priv_record(&ident, OBS_PRIV_MODULE_REQUEST, 0,
			obs_current_euid(), now,
			&status);
	if (!e || status != OBS_TOUCH_CREATED)
		return 0;
	bpf_probe_read_kernel_str(name, sizeof(name), kmod_name);
	priv_set_name(e, name);
	return 0;
}

SEC("lsm/mmap_file")
int BPF_PROG(obs_mmap_file, struct file *filp,
	     unsigned long reqprot __attribute__((__unused__)),
	     unsigned long prot, unsigned long flags)
{
	struct priv_entry __arena *e;
	struct obs_ident ident = {};
	__u64 now = obs_now();
	__u32 euid;
	int status;

	if (!(prot & OBS_PROT_EXEC))
		return 0;
	obs_ident_checked(&ident, now);
	euid = obs_current_euid();
	e = priv_record(&ident, OBS_PRIV_MMAP_EXEC, (__u32)prot, euid, now,
			&status);
	if (!e)
		return 0;
	if (status == OBS_TOUCH_CREATED)
		priv_set_mapping_name(e, filp);
	e->val.aux = flags;
	return 0;
}

SEC("lsm/file_mprotect")
int BPF_PROG(obs_file_mprotect, struct vm_area_struct *vma,
	     unsigned long reqprot __attribute__((__unused__)),
	     unsigned long prot)
{
	struct priv_entry __arena *e;
	struct obs_ident ident = {};
	unsigned long vm_flags;
	__u64 now = obs_now();
	struct file *filp;
	__u32 euid;
	int status;

	if (!(prot & OBS_PROT_EXEC))
		return 0;
	vm_flags = BPF_CORE_READ(vma, vm_flags);
	if (vm_flags & OBS_VM_EXEC)
		return 0;
	filp = BPF_CORE_READ(vma, vm_file);
	obs_ident_checked(&ident, now);
	euid = obs_current_euid();
	e = priv_record(&ident, OBS_PRIV_MPROTECT_EXEC, (__u32)prot, euid,
			now, &status);
	if (!e)
		return 0;
	if (status == OBS_TOUCH_CREATED)
		priv_set_mapping_name(e, filp);
	e->val.aux = BPF_CORE_READ(vma, vm_end) -
		    BPF_CORE_READ(vma, vm_start);
	return 0;
}

SEC("lsm/userns_create")
int BPF_PROG(obs_userns_create, const struct cred *cred)
{
	struct obs_ident ident;
	__u64 now = obs_now();
	int status;

	obs_ident_checked(&ident, now);
	priv_record(&ident, OBS_PRIV_USERNS_CREATE, 0, cred->euid.val, now,
		    &status);
	return 0;
}

/*
 * Reads and enumeration are what shirudo's own exporter and status
 * issue every interval; everything that creates, loads, attaches or
 * changes state is worth a record whether the enforcement LSM admits it
 * or not.
 */
static __always_inline bool obs_bpf_cmd_readonly(int cmd)
{
	switch (cmd) {
	case BPF_MAP_LOOKUP_ELEM:
	case BPF_MAP_GET_NEXT_KEY:
	case BPF_MAP_LOOKUP_BATCH:
	case BPF_OBJ_GET:
	case BPF_OBJ_GET_INFO_BY_FD:
	case BPF_PROG_TEST_RUN:
	case BPF_PROG_GET_NEXT_ID:
	case BPF_MAP_GET_NEXT_ID:
	case BPF_BTF_GET_NEXT_ID:
	case BPF_LINK_GET_NEXT_ID:
	case BPF_PROG_GET_FD_BY_ID:
	case BPF_MAP_GET_FD_BY_ID:
	case BPF_BTF_GET_FD_BY_ID:
	case BPF_LINK_GET_FD_BY_ID:
	case BPF_TASK_FD_QUERY:
	case BPF_PROG_QUERY:
		return true;
	default:
		return false;
	}
}

SEC("lsm/bpf")
int BPF_PROG(obs_bpf, int cmd,
	     union bpf_attr *attr __attribute__((__unused__)),
	     unsigned int size __attribute__((__unused__)), bool kernel)
{
	struct obs_ident ident;
	__u64 now = obs_now();
	int status;

	if (kernel || obs_bpf_cmd_readonly(cmd))
		return 0;
	obs_ident_checked(&ident, now);
	priv_record(&ident, OBS_PRIV_BPF, (__u32)cmd,
		    obs_current_euid(), now, &status);
	return 0;
}
