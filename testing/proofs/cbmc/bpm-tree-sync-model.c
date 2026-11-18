// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * cmd_bpm_tree_sync() of builtin-bpm.c, tree_recover_pending(), the walk
 * back through sealed segments, the base and prefix checks and the loop over
 * the operations included, against the run of the model that
 * testing/proofs/lean4/Shirudo/TreeSync.lean proves never takes a node back.
 * Below sync, the files and the rest of the I/O are stubs that record the
 * write the model names, or fail. For every state, pending record, tree
 * eventlog replay and record of the pending operation this boot, every
 * publication of LEN operations that tree_parse() lets through, at any base,
 * with NSEG 2 a sealed segment of LEN operations the registry serves by its
 * digest too, every selector answer and every failure, sync makes the
 * model's writes in the model's order, nothing after a failure and all of
 * them when nothing fails. Strings are of one byte, as sync only compares
 * them; hashes, hex and paths are stubs the model does not depend on. The
 * functions after the stubs restate the Lean definitions: checked() is
 * Checked, follows() Follows, recover() recover, history_ok() the base and
 * prefix checks and run() run, with its walk and loop. An outcome line
 * carries more here than in the Lean model: its code, 1 or 3 by what the
 * install or the pins say, and the history root, a fold the sync starts
 * from the root its record holds at the cursor.
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
/*
 * The model's checks run as the C has them; the digest check is a stub.
 * The copy of tree_publication_verify() in util/bpm_tree.c would call the
 * real one, so it is given here as the C has it, calling the stub.
 */
#define tree_operation_validate tree_operation_validate_unused
#define tree_publication_verify tree_publication_verify_unused
#include "../../../util/bpm_tree.c"
#undef tree_operation_validate
#undef tree_publication_verify
int tree_operation_validate(const struct tree_operation *op);

int tree_publication_verify(const struct tree_publication *pub, int *bad_op)
{
	int ret;

	if (bad_op)
		*bad_op = -1;
	if (!bpm_package_name_ok(pub->tree_id))
		return -EINVAL;
	ret = tree_publication_check(pub);
	if (ret)
		return ret;
	for (int i = 0; i < pub->n_operations; i++) {
		ret = tree_operation_validate(&pub->operations[i]);
		if (ret) {
			if (bad_op)
				*bad_op = i;
			return ret;
		}
	}
	return 0;
}

#include "../../../builtin-bpm.c"

enum {
	W_PENDING, W_MEASURE, W_APPEND, W_STATE, W_UNLINK, W_OUTCOME,
	W_TRUNCATE, W_KINDS,
};

/*
 * A write and what it carries: the operation, seq, digest or root, state,
 * and for an outcome line its code and the history root.
 */
struct write {
	int		kind;
	int		op;
	__s64		seq;
	__u8		d[32];
	__s64		generation;
	char		manifest[2];
	char		tree_id[2];
	__s64		head_seq;
	__s64		base_seq;
	int		outcome;
	__u8		h[32];
	/* Its place among all the writes the model makes. */
	int		pos;
};

/*
 * NSEG publications: the one the tag names, and with 2 the sealed segment
 * before it. Operation k is the tag's k-th and, from LEN on, the sealed
 * segment's.
 */
#ifndef NSEG
#define NSEG	1
#endif
#define SEG_OPS	(LEN ? LEN : 1)
#define NOPS	(NSEG * SEG_OPS)

/*
 * The model's writes, kept by kind, each with its place among them all:
 * at most a state for each segment, operation, recovery and the end, and
 * of any other kind fewer. A write sync makes is the next of its kind,
 * and it must be the one at the place sync has reached. Looked up in its
 * kind, a write is picked from a few rather than from all of them, as the
 * place sync has reached is any of several once paths have joined.
 */
#define MAX_KIND	(NOPS + NSEG + 2)

static struct write want[W_KINDS][MAX_KIND];
static int n_want_kind[W_KINDS], n_got_kind[W_KINDS];
static int n_got, n_want;
static __u32 fail_at, fail_call;
static bool failed;

/* What the node holds, what the registry serves and what the checks say. */
static bool have_state, have_pending, measured;
static struct tree_state disk_state;
static struct tree_pending disk_pending;
static int replay_kind;		/* 0 -ENOENT, 1 -EINVAL, 2 a root */
static __u8 replay_root[32];
/*
 * Each publication's operations in an object of their own: CBMC reads a
 * pointer that may be into either at the offset it has in each, where in
 * one array the offsets would differ and it would read bytes at an
 * unknown offset from the whole of it, every operation's 13 KB.
 */
static struct tree_operation tag_ops[SEG_OPS];
#if NSEG == 2
static struct tree_operation sealed_ops[SEG_OPS];
#endif
static struct tree_publication fetched, sealed;
static char fetched_manifest[2], sealed_manifest[2];
static int fetches;
static bool sel_match[NOPS], sel_fail[NOPS];
/*
 * The history roots the record holds at the cursor and at any other seq,
 * and what an install finds.
 */
static __u8 disk_history[32], disk_other_history[32];
static bool op_add[NOPS], module_absent[NOPS];
static bool pins_loaded;
static int installing = -1;
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

static bool same_write(const struct write *a, int k, int j);

/* A write sync makes, checked against the model's at its place. */
static void record(const struct write *w)
{
	int k = w->kind, j = n_got_kind[k];

	__CPROVER_assert(!failed, "nothing written after a failure");
	__CPROVER_assert(n_got < n_want, "no write the model does not make");
	if (n_got < n_want)
		__CPROVER_assert(j < n_want_kind[k] && want[k][j].pos == n_got &&
				 same_write(w, k, j),
				 "the model's write at its place");
	n_got_kind[k]++;
	n_got++;
}

static struct tree_operation *op_at(int k)
{
#if NSEG == 2
	if (k >= SEG_OPS)
		return &sealed_ops[k - SEG_OPS];
#endif
	return &tag_ops[k];
}

/* Which operation a pointer is into, without a division by its size. */
static int op_index(const char *digest)
{
	for (int i = 0; i < NOPS; i++)
		if (digest == op_at(i)->operation_digest)
			return i;
	return -1;
}

static int op_of(const struct tree_operation *op)
{
	for (int i = 0; i < NOPS; i++)
		if (op == op_at(i))
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

/* As model_hash(), and another function of the two, as the tag makes it. */
static void model_history(const __u8 *a, const __u8 *b, __u8 *out)
{
	for (int i = 0; i < 32; i++)
		out[i] = (__u8)((a[i] * 5 + b[i] + 7) & 0xff);
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

/*
 * The publication a digest of one byte names, as a registry serves it: 0 the
 * tag's, 1 the sealed segment, -1 none.
 */
static int served(char digest)
{
	if (digest == fetched_manifest[0])
		return 0;
	if (NSEG == 2 && digest == sealed_manifest[0])
		return 1;
	return -1;
}

/*
 * The publication and the name served() gives, the tag's for none, and the
 * tag's alone with one segment: CBMC cannot tell that a 0 or -1 is 0 past
 * the check for -1, and would carry the sealed segment's operations and
 * their count into every read.
 */
static struct tree_publication *served_pub(int s)
{
	return NSEG == 2 && s > 0 ? &sealed : &fetched;
}

static char *served_name(int s)
{
	return NSEG == 2 && s > 0 ? sealed_manifest : fetched_manifest;
}

/*
 * The first fetch is of the tag; the others name a digest, which sync
 * passes as it is or as "sha256:" and the hex of the byte the decode stub
 * takes, the one byte of a NUL-terminated hex_encode() of it. The
 * publication is filled on every path, though sync only frees it after a
 * failure: one left as it was there would make the count of operations
 * and where they are unknown to CBMC where sync reads them.
 */
int bpm_tree_fetch_publication(struct bpm_oci_client *c,
			       const char *repository, const char *reference,
			       const char *cert_path,
			       const struct trusted_set *trusted,
			       struct tree_publication *pub,
			       char *manifest_digest, size_t digest_sz)
{
	bool failure = fail_here();
	int s = 0;

	if (!failure && fetches++)
		s = served(strncmp(reference, "sha256:", 7) ? reference[0] :
			   reference[7]);
	*pub = *served_pub(s);
	if (failure)
		return -EIO;
	if (s < 0)
		return -ENOENT;
	copy_short(manifest_digest, served_name(s));
	return 0;
}

static struct tree_segment walk_store[8];

void *xreallocarray(void *ptr, size_t old_nmemb, size_t new_nmemb,
		    size_t size)
{
	__CPROVER_assert(size == sizeof(struct tree_segment) && new_nmemb <= 8 &&
			 (!ptr || ptr == walk_store),
			 "only the walk's descriptors are reallocated");
	return fail_here() ? NULL : walk_store;
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

/* As util/hex.c has it, over the hex_encode() above. */
void sha256_digest_encode(const __u8 in[32], char out[72])
{
	memcpy(out, "sha256:", 7);
	hex_encode(in, 32, out + 7);
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
	w.head_seq = s->head_seq;
	w.base_seq = s->segment_base_seq;
	record(&w);
	return 0;
}

int tree_outcomes_resume(__s64 last_seq, __u8 history_root[32])
{
	struct write w = { .kind = W_TRUNCATE, .seq = last_seq };

	memset(history_root, 0, 32);
	if (fail_here())
		return -EBADMSG;
	record(&w);
	if (last_seq)
		memcpy(history_root, disk_history, 32);
	return 0;
}

int tree_outcomes_read(__s64 from, __s64 to, __u8 *codes,
		       __u8 projection_root[32], __u8 history_root[32])
{
	__s64 cursor = have_state ? disk_state.last_seq : 0;

	__CPROVER_assert(from == to && !codes,
			 "the roots at one seq are what sync reads");
	if (!from)
		memset(history_root, 0, 32);
	else
		memcpy(history_root, from == cursor ? disk_history :
				     disk_other_history, 32);
	return fail_here() ? -EIO : 0;
}

int chain_history_step(const __u8 prev[32], const __u8 operation_digest[32],
		       __u8 out[32])
{
	model_history(prev, operation_digest, out);
	return fail_here() ? -EIO : 0;
}

int tree_outcome_append(__s64 seq, enum tree_outcome outcome,
			const __u8 projection_root[32],
			const __u8 history_root[32])
{
	struct write w = { .kind = W_OUTCOME, .seq = seq, .outcome = outcome };

	if (fail_here())
		return -EIO;
	memcpy(w.d, projection_root, 32);
	memcpy(w.h, history_root, 32);
	record(&w);
	return 0;
}

bool upatch_loaded_pins(const char *name)
{
	return pins_loaded;
}

/* The model's upatches are BPF ones. */
bool java_agent_loaded(const char *name)
{
	return false;
}

int tree_pending_write(const struct tree_operation *op)
{
	struct write w = { .kind = W_PENDING, .op = op_of(op) };

	if (fail_here())
		return -EIO;
	installing = w.op;
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

	for (int k = 0; k < NOPS; k++)
		if (selector == &op_at(k)->selector)
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

/* The operation pending.json names is the one sync installs. */
int upatch_install(const char *path)
{
	int ret;

	__CPROVER_assert(installing >= 0 && installing < NOPS,
			 "an install follows its pending record");
	if (installing >= 0 && installing < NOPS && module_absent[installing])
		return UPATCH_INSTALL_TARGET_MISSING;
	__CPROVER_assume(ret == 0 || ret == 1 || ret == -EIO);
	if (ret)
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
	__s64		head_seq;
	__s64		base_seq;
	/* Not in state.json: the history root sync holds at last_seq. */
	__u8		hist[32];
};

/*
 * Each write is put together on its own and stored in want[] once: n_want
 * is symbolic past a branch, and CBMC turns a store at a symbolic index
 * into one to every entry, so a store per byte multiplies the program many
 * times over. Each index is stored once, into the zeros want[] starts as.
 */
static void expect(struct write *w)
{
	int k = w->kind;

	__CPROVER_assert(n_want_kind[k] < MAX_KIND, "expected write log fits");
	w->pos = n_want++;
	want[k][n_want_kind[k]++] = *w;
}

static void want_write(int kind, int op, __s64 seq, const __u8 *d,
		       const struct mstate *st)
{
	struct write w = { .kind = kind, .op = op,
			   .seq = st ? st->last_seq : seq };

	if (d)
		for (int i = 0; i < 32; i++)
			w.d[i] = d[i];
	if (st) {
		for (int i = 0; i < 32; i++)
			w.d[i] = st->root[i];
		w.generation = st->generation;
		w.manifest[0] = st->manifest[0];
		w.tree_id[0] = st->tree_id[0];
		w.head_seq = st->head_seq;
		w.base_seq = st->base_seq;
	}
	expect(&w);
}

static void want_outcome(__s64 seq, int outcome, const __u8 *root,
			 const __u8 *hist)
{
	struct write w = { .kind = W_OUTCOME, .seq = seq, .outcome = outcome };

	for (int i = 0; i < 32; i++)
		w.d[i] = root[i];
	for (int i = 0; i < 32; i++)
		w.h[i] = hist[i];
	expect(&w);
}

/*
 * want[k][j] by its indices, not a pointer: CBMC takes a pointer to an
 * entry at an index it does not know for one into any entry of want.
 */
static bool same_history(const struct write *actual, int k, int j)
{
	for (int i = 0; i < 32; i++)
		if (actual->h[i] != want[k][j].h[i])
			return false;
	return true;
}

static bool same_digest(const struct write *actual, int k, int j)
{
	for (int i = 0; i < 32; i++)
		if (actual->d[i] != want[k][j].d[i])
			return false;
	return true;
}

static bool same_write(const struct write *a, int k, int j)
{
	switch (a->kind) {
	case W_PENDING:
		return a->op == want[k][j].op;
	case W_MEASURE:
		return a->seq == want[k][j].seq && same_digest(a, k, j);
	case W_APPEND:
		return a->op == want[k][j].op &&
		       a->seq == want[k][j].seq && same_digest(a, k, j);
	case W_STATE:
		return a->seq == want[k][j].seq &&
		       a->generation == want[k][j].generation &&
		       same_digest(a, k, j) &&
		       a->manifest[0] == want[k][j].manifest[0] &&
		       a->manifest[1] == want[k][j].manifest[1] &&
		       a->tree_id[0] == want[k][j].tree_id[0] &&
		       a->tree_id[1] == want[k][j].tree_id[1] &&
		       a->head_seq == want[k][j].head_seq &&
		       a->base_seq == want[k][j].base_seq;
	case W_OUTCOME:
		return a->seq == want[k][j].seq &&
		       a->outcome == want[k][j].outcome &&
		       same_digest(a, k, j) && same_history(a, k, j);
	case W_TRUNCATE:
		return a->seq == want[k][j].seq;
	default:
		return true;
	}
}

/*
 * Checked: the numbers of tree_publication_check() and the base keys,
 * present past base 0 and absent at it. Their form is the decode stubs',
 * which accept any; the generation tree_parse() keeps from 0.
 */
static bool checked_pub(const struct tree_publication *p)
{
	int n = p->n_operations;

	if (p->generation < 0 || p->base_seq < 0)
		return false;
	if (!p->base_seq && (p->segment_manifest_digest[0] ||
			     p->history_root[0]))
		return false;
	if (p->base_seq && !n)
		return false;
	if (n && (p->operations[0].seq != p->base_seq + 1 ||
		  p->head_seq != p->operations[n - 1].seq))
		return false;
	return n || p->head_seq == p->base_seq;
}

static bool checked(void)
{
	return checked_pub(&fetched);
}

/*
 * tree_publication_follows(): -1 for a refusal, 0 when the publication
 * follows the state, Follows, and 1 for a walk back to its base.
 */
static int follows_pub(const struct tree_publication *p, const char *m,
		       const struct mstate *s)
{
	bool same;

	if (!s)
		return p->base_seq ? 1 : 0;
	same = !strcmp(s->manifest, m);
	if (strcmp(s->tree_id, p->tree_id) ||
	    (!same && p->generation <= s->generation) ||
	    (!same && p->generation - 1 == s->generation &&
	     p->parent_manifest_digest[0] &&
	     strcmp(p->parent_manifest_digest, s->manifest)) ||
	    p->head_seq < s->last_seq)
		return -1;
	return p->base_seq > s->last_seq ? 1 : 0;
}

static bool follows(const struct mstate *s)
{
	return follows_pub(&fetched, fetched_manifest, s) == 0;
}

/* tree_walk_within() with the limits of util/bpm_tree.h. */
static bool within(__s64 base, __s64 last)
{
	return base >= 0 && last >= 0 &&
	       base - last <= (last ? TREE_MAX_WALK_OPS : TREE_MAX_JOIN_OPS);
}

/* tree_segment_precedes() of the publication the walk fetched. */
static bool precedes(const struct tree_publication *pred, const char *m,
		     const struct tree_publication *succ)
{
	return succ->base_seq > 0 &&
	       !strcmp(succ->segment_manifest_digest, m) &&
	       !strcmp(pred->tree_id, succ->tree_id) &&
	       pred->head_seq == succ->base_seq &&
	       pred->generation < succ->generation;
}

/*
 * The base check and the prefix check: the node's history root at the
 * segment's base, the one sync holds when the base is its cursor and the
 * record's otherwise, is the segment's, and the segment's operations up to
 * the cursor fold from it to the one sync holds.
 */
static bool history_ok(const struct tree_publication *p,
		       const struct mstate *st)
{
	__u8 node[32], doc[32], d[32];

	if (p->base_seq == st->last_seq)
		memcpy(node, st->hist, 32);
	else if (!p->base_seq)
		memset(node, 0, 32);
	else
		memcpy(node, p->base_seq == (have_state ? disk_state.last_seq : 0) ?
		       disk_history : disk_other_history, 32);
	memset(doc, 0, 32);
	if (p->base_seq)
		for (int i = 0; i < 32; i++)
			doc[i] = (__u8)p->history_root[i];
	if (memcmp(node, doc, 32))
		return false;
	for (int i = 0; i < p->n_operations; i++) {
		if (p->operations[i].seq > st->last_seq)
			break;
		digest_of(p->operations[i].operation_digest, d);
		model_history(doc, d, doc);
	}
	return !memcmp(doc, st->hist, 32);
}

/*
 * What recovery writes once the pending operation is applied and its line
 * is in the tree eventlog: a line for each operation the stopped sync passed
 * over, the operation's own, the state and the unlink.
 */
static void want_recovered(struct mstate *st, const struct tree_publication *p,
			   const struct tree_operation *o, const __u8 *d,
			   const __u8 *next)
{
	int index = op_of(o);
	__u8 passed[32];

	for (int i = 0; i < p->n_operations; i++) {
		const struct tree_operation *q = &p->operations[i];

		if (q->seq >= o->seq)
			break;
		if (q->seq <= st->last_seq)
			continue;
		digest_of(q->operation_digest, passed);
		model_history(st->hist, passed, st->hist);
		want_outcome(q->seq, TREE_OUTCOME_UNMATCHED, st->root,
			     st->hist);
	}
	model_history(st->hist, d, st->hist);
	want_outcome(o->seq, index >= 0 && op_add[index] && !pins_loaded ?
		     TREE_OUTCOME_MODULE_ABSENT : TREE_OUTCOME_APPLIED,
		     next, st->hist);
	memcpy(st->root, next, 32);
	st->last_seq = o->seq;
	want_write(W_STATE, 0, 0, NULL, st);
	want_write(W_UNLINK, 0, 0, NULL, NULL);
}

/* false for a refusal before it writes anything. */
static bool recover_in(struct mstate *st, const struct tree_publication *p)
{
	const struct tree_operation *o = NULL;
	__u8 d[32], next[32];

	if (!have_pending)
		return true;
	for (int i = 0; i < p->n_operations; i++) {
		const struct tree_operation *q = &p->operations[i];

		if (q->seq == disk_pending.seq &&
		    !strcmp(q->id, disk_pending.id) &&
		    !strcmp(q->operation_digest,
			    disk_pending.operation_digest)) {
			o = q;
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
		want_recovered(st, p, o, d, next);
		return true;
	}
	if (replay_kind == 2 && memcmp(replay_root, st->root, 32))
		return false;
	if (!measured)
		return true;
	want_write(W_APPEND, op_of(o), o->seq, next, NULL);
	want_recovered(st, p, o, d, next);
	return true;
}

static bool recover(struct mstate *st)
{
	return recover_in(st, &fetched);
}

/* The loop over one publication's operations. */
static void loop(struct mstate *st, const struct tree_publication *p)
{
	__u8 d[32];

	for (int i = 0; i < p->n_operations; i++) {
		const struct tree_operation *o = &p->operations[i];
		int k = op_of(o);

		if (o->seq <= st->last_seq)
			continue;
		digest_of(o->operation_digest, d);
		if (!sel_match[k]) {
			model_history(st->hist, d, st->hist);
			want_outcome(o->seq, TREE_OUTCOME_UNMATCHED, st->root,
				     st->hist);
			st->last_seq = o->seq;
			continue;
		}
		want_write(W_PENDING, k, 0, NULL, NULL);
		want_write(W_MEASURE, k, o->seq, d, NULL);
		model_hash(st->root, d, st->root);
		want_write(W_APPEND, k, o->seq, st->root, NULL);
		model_history(st->hist, d, st->hist);
		want_outcome(o->seq, op_add[k] && module_absent[k] ?
			     TREE_OUTCOME_MODULE_ABSENT : TREE_OUTCOME_APPLIED,
			     st->root, st->hist);
		st->last_seq = o->seq;
		want_write(W_STATE, 0, 0, NULL, st);
		want_write(W_UNLINK, 0, 0, NULL, NULL);
	}
}

static void run(void)
{
	const struct tree_publication *walk[NSEG + 1];
	const char *names[NSEG + 1];
	const struct tree_publication *succ = &fetched;
	bool have = have_state;
	struct mstate st;
	__s64 cursor;
	int n = 0;

	/* The node's state, or the fresh one sync starts from without it. */
	st.tree_id[0] = have_state ? disk_state.tree_id[0] : fetched.tree_id[0];
	st.tree_id[1] = '\0';
	st.generation = have_state ? disk_state.generation : 0;
	st.last_seq = have_state ? disk_state.last_seq : 0;
	for (int i = 0; i < 32; i++)
		st.root[i] = have_state ? (__u8)disk_state.projection_root[i] : '0';
	st.manifest[0] = have_state ? disk_state.manifest_digest[0] : '\0';
	st.manifest[1] = '\0';
	st.head_seq = have_state ? disk_state.head_seq : 0;
	st.base_seq = have_state ? disk_state.segment_base_seq : 0;
	if (st.last_seq)
		memcpy(st.hist, disk_history, 32);
	else
		memset(st.hist, 0, 32);
	if (!checked() ||
	    follows_pub(&fetched, fetched_manifest, have ? &st : NULL) < 0)
		return;
	want_write(W_TRUNCATE, 0, st.last_seq, NULL, NULL);
	/* Back to the segment the cursor lies in. */
	cursor = st.last_seq;
	walk[n] = &fetched;
	names[n++] = fetched_manifest;
	while (succ->base_seq > cursor) {
		int s;

		if (!within(succ->base_seq, cursor))
			return;
		s = served(succ->segment_manifest_digest[0]);
		if (s < 0)
			return;
		if (!checked_pub(served_pub(s)) ||
		    !precedes(served_pub(s), served_name(s), succ))
			return;
		__CPROVER_assert(n <= NSEG, "a walk passes each segment once");
		walk[n] = served_pub(s);
		names[n++] = served_name(s);
		succ = walk[n - 1];
	}
	/* Forwards, the oldest first. */
	for (int k = n - 1; k >= 0; k--) {
		const struct tree_publication *p = walk[k];

		if (follows_pub(p, names[k], have ? &st : NULL) ||
		    !history_ok(p, &st))
			return;
		if (k == n - 1 && !recover_in(&st, p))
			return;
		st.generation = p->generation;
		copy_short(st.manifest, names[k]);
		st.head_seq = p->head_seq;
		st.base_seq = p->base_seq;
		have = true;
		want_write(W_STATE, 0, 0, NULL, &st);
		loop(&st, p);
	}
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

/*
 * What tree_parse() lets through, which the fetch stub stands for: the
 * publication of the operations from first on, and its manifest digest.
 */
static void any_one(struct tree_publication *out, int first, char *manifest)
{
	struct tree_publication pub;

	pub.operations = op_at(first);
	pub.operations_capacity = 0;
	pub.n_operations = LEN;
	any_name(pub.tree_id, false);
	any_name(pub.parent_manifest_digest, true);
	any_name(pub.segment_manifest_digest, true);
	any_name(pub.history_root, true);
	__CPROVER_assume(pub.generation >= 0 && pub.generation != INT64_MAX &&
			 pub.base_seq >= 0 && pub.head_seq >= pub.base_seq &&
			 pub.head_seq != INT64_MAX);
	*out = pub;
	for (int i = first; i < first + LEN; i++) {
		struct tree_operation *o = op_at(i);
		bool add, match, fail, absent;
		__s64 seq;

		__CPROVER_assume(seq > 0 && (i == first || seq - 1 == op_at(i - 1)->seq));
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
		op_add[i] = add;
		module_absent[i] = absent;
	}
	any_name(manifest, false);
}

static void any_publication(void)
{
	any_one(&fetched, 0, fetched_manifest);
#if NSEG == 2
	any_one(&sealed, LEN, sealed_manifest);
#endif
}

/*
 * What the node holds, every byte sync compares written on its own, and
 * zero where the node has no such file, as the readers leave it.
 */
static void any_node(void)
{
	bool state_there, pending_there, op_measured, loaded;
	__s64 generation, last_seq, seq, head_seq, base_seq;
	char tree, manifest, id, digest;
	int replay;

	have_state = state_there;
	have_pending = pending_there;
	measured = op_measured;
	pins_loaded = loaded;
	disk_state.tree_id[0] = state_there ? tree : '\0';
	disk_state.manifest_digest[0] = state_there ? manifest : '\0';
	disk_state.generation = state_there ? generation : 0;
	disk_state.last_seq = state_there ? last_seq : 0;
	disk_state.head_seq = state_there ? head_seq : 0;
	disk_state.segment_base_seq = state_there ? base_seq : 0;
	for (int i = 0; i < 32; i++) {
		__u8 b, h, o;

		disk_state.projection_root[i] = state_there ? (char)b : '\0';
		disk_history[i] = h;
		disk_other_history[i] = o;
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
	__u32 first_failure;

	fail_at = first_failure;
	any_node();
#ifdef TREE_SYNC_APPLICATION_ONLY
	__CPROVER_assume(!have_pending);
#elif defined(TREE_SYNC_PENDING_ONLY)
	__CPROVER_assume(have_pending);
#endif
	any_publication();
	any_replay_root();
	run();
	cmd_bpm_tree_sync(false, NULL);
	__CPROVER_assert(failed || n_got == n_want,
			 "all of them when nothing fails");
}
