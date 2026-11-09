// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * cmd_bpm_tree_sync() of builtin-bpm.c, tree_recover_pending() and the loop
 * over the operations included, against the run of the model that
 * testing/proofs/lean4/Shirudo/TreeSync.lean proves never takes a node back.
 * Below sync, the files and the rest of the I/O are stubs that record the
 * write the model names, or fail. For every state, pending record, tree
 * eventlog replay and record of the pending operation this boot, every
 * publication of LEN operations that tree_parse() lets through, every
 * selector answer and every failure, sync makes the model's writes in the
 * model's order, nothing after a failure and all of them when nothing fails.
 * Strings are of one byte, as sync only compares them; hashes, hex and paths
 * are stubs the model does not depend on. The functions after the stubs
 * restate the Lean definitions: checked() is Checked, follows() Follows,
 * recover() recover and run() run, with its loop.
 */

/* As proof.h, before the system headers can include <ctype.h>. */
#define __NO_CTYPE 1

#include <dirent.h>
#include <ftw.h>
#include <sys/file.h>
#include <zlib.h>
#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "proof.h"
/* The model's checks run as the C has them; the digest check is a stub. */
#define tree_operation_validate tree_operation_validate_unused
#include "../../../util/bpm_tree.c"
#undef tree_operation_validate
int tree_operation_validate(const struct tree_operation *op);
#include "../../../builtin-bpm.c"

enum { W_PENDING, W_MEASURE, W_APPEND, W_STATE, W_UNLINK };

/* A write and what it carries: the operation, seq, digest or root, state. */
struct write {
	int		kind;
	int		op;
	__s64		seq;
	__u8		d[32];
	__s64		generation;
	char		manifest[2];
	char		tree_id[2];
};

#define MAX_WRITES	(4 + 5 * LEN)

static struct write want[MAX_WRITES];
static int n_got, n_want;
static __u32 fail_at, fail_call;
static bool failed;

/* What the node holds, what the registry serves and what the checks say. */
static bool have_state, have_pending, measured;
static struct tree_state disk_state;
static struct tree_pending disk_pending;
static int replay_kind;		/* 0 -ENOENT, 1 -EINVAL, 2 a root */
static __u8 replay_root[32];
static struct tree_operation ops[LEN ? LEN : 1];
static struct tree_publication fetched;
static char fetched_manifest[2];
static bool sel_match[LEN ? LEN : 1], sel_fail[LEN ? LEN : 1];
static __s64 measure_seq;
static __u8 measure_d[32];

/* A failed I/O stops sync before another modeled I/O call. */
static bool fail_here(void)
{
	bool fail;

	__CPROVER_assert(fail_call <= fail_at,
			 "no I/O call after a failed I/O");
	fail = fail_call++ == fail_at;
	if (fail)
		failed = true;
	return fail;
}

static void copy_short(char dst[2], const char *src)
{
	dst[0] = src[0];
	dst[1] = '\0';
}

static bool same_write(const struct write *a, int index);

/* A write sync makes, checked against the model's at its place. */
static void record(const struct write *w)
{
	__CPROVER_assert(!failed, "nothing written after a failure");
	__CPROVER_assert(n_got < n_want, "no write the model does not make");
	if (n_got < n_want)
		__CPROVER_assert(same_write(w, n_got),
				 "the model's write at its place");
	n_got++;
}

/* Which operation a pointer is into, without a division by its size. */
static int op_index(const char *digest)
{
	for (int i = 0; i < LEN; i++)
		if (digest == ops[i].operation_digest)
			return i;
	return -1;
}

static int op_of(const struct tree_operation *op)
{
	for (int i = 0; i < LEN; i++)
		if (op == &ops[i])
			return i;
	return -1;
}

/*
 * The projection hash, any function of the root and the digest will do,
 * and an operation digest of one byte as 32: hex_encode() and hex_decode()
 * copy the 32 bytes, which the hex proof covers.
 */
static void model_hash(const __u8 *a, const __u8 *b, __u8 *out)
{
	for (int i = 0; i < 32; i++)
		out[i] = (__u8)((a[i] * 3 + b[i] + 1) & 0xff);
}

static void digest_of(const char *s, __u8 out[32])
{
	memset(out, 0, 32);
	out[0] = (__u8)s[0];
}

/* The stubs. */

/*
 * A path sync formats names a status file or a cached artifact, never
 * pending.json, and no write of the model depends on which.
 */
int strsprintf(char *buf, size_t size, const char *fmt, ...)
{
	buf[0] = 'p';
	buf[1] = '\0';
	return 1;
}

bool image_config_active(void)
{
	return true;
}

int image_open(enum image_path which, int flags)
{
	return 3;
}

static FILE conf_file;

FILE *fdopen(int fd, const char *mode)
{
	return &conf_file;
}

int fclose(FILE *f)
{
	return 0;
}

static char conf_line[2] = "x";

int read_text_line(FILE *f, char **line, size_t *cap, size_t max)
{
	static int calls;

	if (calls++)
		return 0;
	*line = conf_line;
	return 1;
}

void libc_free(void *p)
{
}

void *xcalloc(size_t nmemb, size_t size)
{
	static struct trusted_set trusted;

	__CPROVER_assert(nmemb == 1 && size == sizeof(trusted),
			 "only the active signing set is allocated");
	return fail_here() ? NULL : &trusted;
}

int image_config_root_fd(void)
{
	return 3;
}

int keys_load_image_root(const char *primary, int root_fd,
			 bool with_trusted, struct trusted_set *trusted)
{
	trusted->n = 1;
	return fail_here() ? -EIO : 0;
}

int keys_check_image_set(const struct trusted_set *trusted)
{
	return fail_here() ? -EKEYREJECTED : 0;
}

void xfree(void *p, size_t size)
{
}

int bpm_parse_tree_line(char *line, char *endpoint, size_t endpoint_sz,
			char *reference, size_t reference_sz)
{
	endpoint[0] = 'e';
	endpoint[1] = '\0';
	reference[0] = 'r';
	reference[1] = '\0';
	return 0;
}

int tree_state_read(struct tree_state *out)
{
	*out = disk_state;
	if (!have_state)
		return -ENOENT;
	return fail_here() ? -EIO : 0;
}

int bpm_oci_parse_tree_repo(const char *raw, struct bpm_oci_client *c,
			    char *repository, size_t repository_sz)
{
	repository[0] = '\0';
	return 0;
}

void bpm_oci_client_clear(struct bpm_oci_client *c)
{
}

const char *get_cert_path(void)
{
	return "c";
}

int bpm_tree_fetch_publication(struct bpm_oci_client *c,
			       const char *repository, const char *reference,
			       const char *cert_path,
			       const struct trusted_set *trusted,
			       struct tree_publication *pub,
			       char *manifest_digest, size_t digest_sz)
{
	*pub = fetched;
	copy_short(manifest_digest, fetched_manifest);
	return fail_here() ? -EIO : 0;
}

bool bpm_package_name_ok(const char *s)
{
	bool ok;

	if (!ok)
		failed = true;
	return ok;
}

int tree_operation_validate(const struct tree_operation *op)
{
	return fail_here() ? -EINVAL : 0;
}

int sha256_digest_decode(const char *digest, __u8 out[32])
{
	digest_of(digest, out);
	return fail_here() ? -EINVAL : 0;
}

int hex_decode(const char *hex, __u8 *out, size_t n)
{
	for (size_t i = 0; i < n; i++)
		out[i] = (__u8)hex[i];
	return 0;
}

void hex_encode(const __u8 *in, size_t n, char *out)
{
	for (size_t i = 0; i < n; i++) {
		out[i] = (char)in[i];
		out[n + i] = 'x';
	}
	out[2 * n] = '\0';
}

int sha256_2(const void *a, size_t a_len, const void *b, size_t b_len,
	     __u8 out[CHAIN_DIGEST_LEN])
{
	model_hash(a, b, out);
	return fail_here() ? -EIO : 0;
}

int tree_pending_read(struct tree_pending *out)
{
	*out = disk_pending;
	if (!have_pending)
		return -ENOENT;
	return fail_here() ? -EIO : 0;
}

int tree_event_replay(__u8 out[32])
{
	memcpy(out, replay_root, 32);
	if (replay_kind == 0)
		return -ENOENT;
	if (replay_kind == 1)
		return -EINVAL;
	memcpy(out, replay_root, 32);
	return 0;
}

int eventlog_tree_op_measured(__s64 seq, const char *operation_digest)
{
	__CPROVER_assert(seq == disk_pending.seq &&
			 !strcmp(operation_digest, disk_pending.operation_digest),
			 "the record looked for is the pending operation's");
	if (fail_here())
		return -EIO;
	return measured;
}

int tree_event_append(__s64 seq, const char *operation_digest,
		      const __u8 projection_root[32])
{
	struct write w = { .kind = W_APPEND, .seq = seq };

	if (fail_here())
		return -EIO;
	w.op = op_index(operation_digest);
	memcpy(w.d, projection_root, 32);
	record(&w);
	return 0;
}

int tree_state_write(const struct tree_state *s)
{
	struct write w = { .kind = W_STATE, .seq = s->last_seq,
			   .generation = s->generation };

	if (fail_here())
		return -EIO;
	hex_decode(s->projection_root, w.d, 32);
	copy_short(w.manifest, s->manifest_digest);
	copy_short(w.tree_id, s->tree_id);
	record(&w);
	return 0;
}

int tree_pending_write(const struct tree_operation *op)
{
	struct write w = { .kind = W_PENDING, .op = op_of(op) };

	if (fail_here())
		return -EIO;
	record(&w);
	return 0;
}

/* The C does not look at the unlink of pending.json; the model has it succeed. */
int unlink(const char *path)
{
	struct write w = { .kind = W_UNLINK };

	if (!strcmp(path, BPM_TREE_PENDING_PATH))
		record(&w);
	return 0;
}

int tree_selector_matches(const struct tree_selector *selector)
{
	int i = -1;

	for (int k = 0; k < LEN; k++)
		if (selector == &ops[k].selector)
			i = k;
	__CPROVER_assert(i >= 0, "the selector of an operation");
	if (i < 0)
		return -EIO;
	if (sel_fail[i]) {
		failed = true;
		return -EIO;
	}
	return sel_match[i];
}

bool chain_bound(void)
{
	bool bound;

	return bound;
}

int access(const char *path, int mode)
{
	return 0;
}

/* Every string this harness has is of one byte at most. */
void bpm_copy_string(char *dst, size_t dst_sz, const char *src)
{
	__CPROVER_assert(dst_sz >= 2 && (!src[0] || !src[1]),
			 "a string of one byte into room for it");
	dst[0] = src[0];
	dst[1] = '\0';
}

int upatch_open(const char *path, struct upatch *out)
{
	return fail_here() ? -EIO : 0;
}

void upatch_header_name(const struct upatch *u, char out[UPATCH_NAME_MAX + 1])
{
	char a, b;

	out[0] = a;
	out[1] = a ? b : '\0';
	out[2] = '\0';
}

bool bpm_digest_matches(const char *want, const char *hex)
{
	bool match;

	if (!match)
		failed = true;
	return match;
}

bool upatch_is_unload(const struct upatch *u)
{
	bool unload;

	return unload;
}

void upatch_close(struct upatch *u)
{
}

int upatch_install(const char *path)
{
	int ret;

	__CPROVER_assume(ret == 0 || ret == UPATCH_INSTALL_TARGET_MISSING ||
			 ret == 1 || ret == -EIO);
	if (ret && ret != UPATCH_INSTALL_TARGET_MISSING)
		failed = true;
	return ret;
}

int upatch_remove(const char *path)
{
	int ret;

	__CPROVER_assume(ret == 0 || ret == 1 || ret == -EIO);
	if (ret)
		failed = true;
	return ret;
}

int eventlog_lock(void)
{
	return fail_here() ? -EIO : 3;
}

void eventlog_unlock(int fd)
{
}

int chain_tree_event(__s64 seq, const __u8 operation_digest[32], __u8 event[32])
{
	measure_seq = seq;
	memcpy(measure_d, operation_digest, 32);
	return fail_here() ? -EIO : 0;
}

int chain_extend(const __u8 event[CHAIN_DIGEST_LEN],
		 __u8 out_chain[CHAIN_DIGEST_LEN])
{
	return fail_here() ? -EIO : 0;
}

/* The extend and its eventlog record are one write of the model. */
int eventlog_append(const char *json_line)
{
	struct write w = { .kind = W_MEASURE, .seq = measure_seq };

	if (fail_here())
		return -EIO;
	memcpy(w.d, measure_d, 32);
	record(&w);
	return 0;
}

void eventlog_record_open(struct json_emit *e, const char *type,
			  const __u8 digest[32])
{
}

void json_obj_open(struct json_emit *e)
{
}

void json_obj_open_key(struct json_emit *e, const char *key)
{
}

void json_obj_close(struct json_emit *e)
{
}

void json_kv_string(struct json_emit *e, const char *key, const char *val)
{
}

void json_kv_int(struct json_emit *e, const char *key, __s64 val)
{
}

void json_kv_bool(struct json_emit *e, const char *key, int val)
{
}

void json_kv_null(struct json_emit *e, const char *key)
{
}

bool upatch_name_valid(const char *name)
{
	return true;
}

int seal_mkdir_p(const char *path, mode_t mode)
{
	return fail_here() ? -EIO : 0;
}

int seal_write_file(const char *path, const void *data, size_t len,
		    mode_t mode)
{
	return fail_here() ? -EIO : 0;
}

int printf(const char *fmt, ...)
{
	return 0;
}

/* Every refusal sync reports after its checks passed stops it. */
void pr_err(const char *fmt, ...)
{
	failed = true;
}

void pr_warn(const char *fmt, ...)
{
}

char *strerror(int err)
{
	return "e";
}

/* The model. */

struct mstate {
	char		tree_id[2];
	__s64		generation;
	__s64		last_seq;
	__u8		root[32];
	char		manifest[2];
};

static void want_write(int kind, int op, __s64 seq, const __u8 *d,
		       const struct mstate *st)
{
	int index;

	__CPROVER_assert(n_want < MAX_WRITES, "expected write log fits");
	index = n_want++;
	want[index].kind = kind;
	want[index].op = op;
	want[index].seq = st ? st->last_seq : seq;
	if (d)
		for (int i = 0; i < 32; i++)
			want[index].d[i] = d[i];
	if (st) {
		for (int i = 0; i < 32; i++)
			want[index].d[i] = st->root[i];
		want[index].generation = st->generation;
		want[index].manifest[0] = st->manifest[0];
		want[index].manifest[1] = '\0';
		want[index].tree_id[0] = st->tree_id[0];
		want[index].tree_id[1] = '\0';
	}
}

static bool same_digest(const struct write *actual, int index)
{
	for (int i = 0; i < 32; i++)
		if (actual->d[i] != want[index].d[i])
			return false;
	return true;
}

static bool same_write(const struct write *a, int index)
{
	if (a->kind != want[index].kind)
		return false;
	switch (a->kind) {
	case W_PENDING:
		return a->op == want[index].op;
	case W_MEASURE:
		return a->seq == want[index].seq && same_digest(a, index);
	case W_APPEND:
		return a->op == want[index].op &&
		       a->seq == want[index].seq && same_digest(a, index);
	case W_STATE:
		return a->seq == want[index].seq &&
		       a->generation == want[index].generation &&
		       same_digest(a, index) &&
		       a->manifest[0] == want[index].manifest[0] &&
		       a->manifest[1] == want[index].manifest[1] &&
		       a->tree_id[0] == want[index].tree_id[0] &&
		       a->tree_id[1] == want[index].tree_id[1];
	default:
		return true;
	}
}

static bool checked(void)
{
	if (fetched.generation < 0 || fetched.base_seq != 0 ||
	    fetched.head_seq != fetched.n_operations)
		return false;
	for (int i = 0; i < fetched.n_operations; i++)
		if (ops[i].seq != 1 + i)
			return false;
	return true;
}

static bool follows(const struct mstate *s)
{
	bool same;

	if (!s)
		return fetched.base_seq == 0;
	same = !strcmp(s->manifest, fetched_manifest);
	return !strcmp(s->tree_id, fetched.tree_id) &&
	       (same || s->generation < fetched.generation) &&
	       (same || !(s->generation < fetched.generation &&
			  fetched.generation - 1 == s->generation) ||
		!fetched.parent_manifest_digest[0] ||
		!strcmp(fetched.parent_manifest_digest, s->manifest)) &&
	       fetched.base_seq <= s->last_seq &&
	       s->last_seq <= fetched.head_seq;
}

/* false for a refusal before it writes anything. */
static bool recover(struct mstate *st)
{
	const struct tree_operation *o = NULL;
	__u8 d[32], next[32];

	if (!have_pending)
		return true;
	for (int i = 0; i < fetched.n_operations; i++) {
		if (ops[i].seq == disk_pending.seq &&
		    !strcmp(ops[i].id, disk_pending.id) &&
		    !strcmp(ops[i].operation_digest,
			    disk_pending.operation_digest)) {
			o = &ops[i];
			break;
		}
	}
	if (!o)
		return false;
	if (disk_pending.seq <= st->last_seq) {
		want_write(W_UNLINK, 0, 0, NULL, NULL);
		return true;
	}
	digest_of(disk_pending.operation_digest, d);
	model_hash(st->root, d, next);
	if (replay_kind == 1)
		return false;
	if (replay_kind == 2 && !memcmp(replay_root, next, 32)) {
		memcpy(st->root, next, 32);
		st->last_seq = o->seq;
		want_write(W_STATE, 0, 0, NULL, st);
		want_write(W_UNLINK, 0, 0, NULL, NULL);
		return true;
	}
	if (replay_kind == 2 && memcmp(replay_root, st->root, 32))
		return false;
	if (!measured)
		return true;
	want_write(W_APPEND, op_of(o), o->seq, next, NULL);
	memcpy(st->root, next, 32);
	st->last_seq = o->seq;
	want_write(W_STATE, 0, 0, NULL, st);
	want_write(W_UNLINK, 0, 0, NULL, NULL);
	return true;
}

static void run(void)
{
	struct mstate st;
	__u8 d[32];

	/* The node's state, or the fresh one sync starts from without it. */
	st.tree_id[0] = have_state ? disk_state.tree_id[0] : fetched.tree_id[0];
	st.tree_id[1] = '\0';
	st.generation = have_state ? disk_state.generation : 0;
	st.last_seq = have_state ? disk_state.last_seq : 0;
	for (int i = 0; i < 32; i++)
		st.root[i] = have_state ? (__u8)disk_state.projection_root[i] : '0';
	st.manifest[0] = have_state ? disk_state.manifest_digest[0] : '\0';
	st.manifest[1] = '\0';
	if (!checked() || !follows(have_state ? &st : NULL) || !recover(&st))
		return;
	for (int i = 0; i < fetched.n_operations; i++) {
		if (ops[i].seq <= st.last_seq)
			continue;
		if (!sel_match[i]) {
			st.last_seq = ops[i].seq;
			continue;
		}
		digest_of(ops[i].operation_digest, d);
		want_write(W_PENDING, i, 0, NULL, NULL);
		want_write(W_MEASURE, i, ops[i].seq, d, NULL);
		model_hash(st.root, d, st.root);
		want_write(W_APPEND, i, ops[i].seq, st.root, NULL);
		st.last_seq = ops[i].seq;
		want_write(W_STATE, 0, 0, NULL, &st);
		want_write(W_UNLINK, 0, 0, NULL, NULL);
	}
	st.generation = fetched.generation;
	copy_short(st.manifest, fetched_manifest);
	want_write(W_STATE, 0, 0, NULL, &st);
}

/*
 * A string of one byte, or none when it may be empty: sync compares these
 * strings for equality alone, which one byte tells, and its loops then end
 * at a byte the solver knows.
 */
static void any_name(char *s, bool may_be_empty)
{
	char c;

	__CPROVER_assume(c || may_be_empty);
	s[0] = c;
	s[1] = '\0';
}

/* What tree_parse() lets through, which the fetch stub stands for. */
static void any_publication(void)
{
	struct tree_publication pub;

	pub.operations = ops;
	pub.operations_capacity = 0;
	pub.n_operations = LEN;
	any_name(pub.tree_id, false);
	any_name(pub.parent_manifest_digest, true);
	__CPROVER_assume(pub.generation >= 0 && pub.generation != INT64_MAX &&
			 pub.base_seq >= 0 && pub.head_seq >= pub.base_seq &&
			 pub.head_seq != INT64_MAX);
	fetched = pub;
	for (int i = 0; i < LEN; i++) {
		struct tree_operation *o = &ops[i];
		bool add, match, fail;
		__s64 seq;

		__CPROVER_assume(seq > 0 && (!i || seq - 1 == ops[i - 1].seq));
		o->seq = seq;
		any_name(o->id, false);
		any_name(o->operation_digest, false);
		/* Byte by byte: CBMC's memcpy() misreads one of two literals. */
		for (int k = 0; k < 7; k++)
			o->op[k] = add ? "add\0\0\0"[k] : "delete"[k];
		memcpy(o->artifact.layer_digest, "sha256:a", 9);
		any_name(o->artifact.payload_sha256, false);
		sel_match[i] = match;
		sel_fail[i] = fail;
	}
	any_name(fetched_manifest, false);
}

/*
 * What the node holds, every byte sync compares written on its own, and
 * zero where the node has no such file, as the readers leave it.
 */
static void any_node(void)
{
	bool state_there, pending_there, op_measured;
	__s64 generation, last_seq, seq;
	char tree, manifest, id, digest;
	int replay;

	have_state = state_there;
	have_pending = pending_there;
	measured = op_measured;
	disk_state.tree_id[0] = state_there ? tree : '\0';
	disk_state.manifest_digest[0] = state_there ? manifest : '\0';
	disk_state.generation = state_there ? generation : 0;
	disk_state.last_seq = state_there ? last_seq : 0;
	for (int i = 0; i < 32; i++) {
		__u8 b;

		disk_state.projection_root[i] = state_there ? (char)b : '\0';
	}
	__CPROVER_assume(seq > 0 && id && digest);
	disk_pending.seq = pending_there ? seq : 0;
	disk_pending.id[0] = pending_there ? id : '\0';
	disk_pending.operation_digest[0] = pending_there ? digest : '\0';
	__CPROVER_assume(replay >= 0 && replay <= 2);
	replay_kind = replay;
}

/* Recovery only asks whether replay equals the previous or next root. */
static void any_replay_root(void)
{
	__u8 previous[32], digest[32], next[32], other = 0;
	int relation;

	if (!have_pending || replay_kind != 2)
		return;
	if (have_state)
		memcpy(previous, disk_state.projection_root, sizeof(previous));
	else
		memset(previous, '0', sizeof(previous));
	digest_of(disk_pending.operation_digest, digest);
	model_hash(previous, digest, next);
	__CPROVER_assume(relation >= 0 && relation <= 2);
	if (relation == 1)
		memcpy(replay_root, next, sizeof(replay_root));
	else
		memcpy(replay_root, previous, sizeof(replay_root));
	if (relation != 2)
		return;
	if (other == previous[0] || other == next[0])
		other = 1;
	if (other == previous[0] || other == next[0])
		other = 2;
	__CPROVER_assert(other != previous[0] && other != next[0],
			 "the third replay class differs from both roots");
	replay_root[0] = other;
}

void harness(void)
{
	const char *argv[2];
	__u32 first_failure;

	fail_at = first_failure;
	argv[0] = "tree";
	argv[1] = "sync";
	any_node();
#ifdef TREE_SYNC_APPLICATION_ONLY
	__CPROVER_assume(!have_pending);
#elif defined(TREE_SYNC_PENDING_ONLY)
	__CPROVER_assume(have_pending);
#endif
	any_publication();
	any_replay_root();
	run();
	cmd_bpm_tree_sync(2, argv);
	__CPROVER_assert(failed || n_got == n_want,
			 "all of them when nothing fails");
}
