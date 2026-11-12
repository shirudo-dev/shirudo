#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0006 -- .github/scripts/check-coccinelle.sh: a rule that matches fails the
# check with file, line, rule and message, one that does not passes it,
# a rule that can rewrite does with -D patch, a rule reads the headers
# its #spatch line asks for, on a throwaway repository, each rule taken
# from CERT C, each BPF hazard rule and each scrub rule report a sample of
# what they refuse, and the tree itself.

cd "$(dirname "$0")/.."
. ./test-lib.sh
command -v git >/dev/null 2>&1 || test_skip_all "git not installed"
command -v spatch >/dev/null 2>&1 || test_skip_all "spatch not installed"
ROOT=$(cd .. && pwd)
S=$ROOT/.github/scripts/check-coccinelle.sh
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

R=$W/repo
mkdir -p "$R/testing/coccinelle" "$R/vendor"
git init -q "$R"
cp "$ROOT/testing/coccinelle/zero_init.cocci" \
	"$ROOT/testing/coccinelle/banned.cocci" "$R/testing/coccinelle/"
printf 'int f(void)\n{\n\tint a[4] = {0};\n\n\treturn a[0];\n}\n' >"$R/bad.c"
printf 'int g(void)\n{\n\tint a[4] = {};\n\n\treturn a[0];\n}\n' >"$R/good.c"
printf 'int h(void)\n{\n\treturn rand();\n}\n' >"$R/vendor/skip.c"

check() {
	(cd "$R" && git add -A && sh "$S" "$@") >"$W/out" 2>"$W/err"
}

test_expect_success 'a match fails the check and names file, line and rule' '
	! check &&
	grep -q "^zero_init: bad.c:3:" "$W/err" &&
	grep -q "1 of 2 rules matched" "$W/err"
'

test_expect_success 'the vendored sources are not checked' '
	! grep -q "skip.c" "$W/err"
'

test_expect_success 'a rule is named alone or by path' '
	check banned &&
	grep -q "1 rules, no match" "$W/out" &&
	! check testing/coccinelle/zero_init.cocci
'

test_expect_success 'a rule reads the headers its #spatch line asks for' '
	cp "$ROOT/testing/coccinelle/sizeof_ptr.cocci" "$R/testing/coccinelle/" &&
	mkdir -p "$R/include" &&
	printf "struct foo {\n\tchar *name;\n};\n" >"$R/include/foo.h" &&
	printf "#include \"foo.h\"\n\nvoid f(struct foo *x)\n{\n\tmemset(x->name, 0, sizeof(x->name));\n}\n" >"$R/member.c" &&
	! check sizeof_ptr &&
	grep -q "^sizeof_ptr: member.c:5:" "$W/err" &&
	rm -r "$R/testing/coccinelle/sizeof_ptr.cocci" "$R/include" "$R/member.c"
'

test_expect_success 'a rule rewrites what it finds with -D patch' '
	(cd "$R" && spatch -D patch --very-quiet --in-place \
		--sp-file testing/coccinelle/zero_init.cocci bad.c) &&
	grep -q "= {};" "$R/bad.c" &&
	check
'

# One case of what each rule taken from CERT C and ISO/IEC TS 17961
# refuses. A rule the tree gives no match proves nothing until it matches
# here.
CERT_RULES="errno_clobber positive_errno double_close wrong_test scaled_arith fclose_unchecked"
write_samples() {
	cat >"$1" <<'EOF'
int clobber_stored(const char *path, int other)
{
	int fd = open(path, O_RDONLY);

	close(other);
	if (fd < 0)
		return -errno;
	return fd;
}

int clobber_tested(int fd)
{
	if (fsync(fd)) {
		close(fd);
		return -errno;
	}
	return 0;
}

int positive(int x)
{
	if (x)
		return EINVAL;
	return 0;
}

int reuse(int fd)
{
	close(fd);
	return fsync(fd);
}

int untested(const char *path, int other)
{
	int fd;

	fd = open(path, O_RDONLY);
	if (other < 0)
		return -1;
	return fd;
}

unsigned int scaled(unsigned int *words)
{
	return *(words + sizeof(struct hdr));
}

int unflushed(const char *path)
{
	FILE *f = fopen(path, "w");

	if (!f)
		return -1;
	fputs("x", f);
	fclose(f);
	return 0;
}
EOF
}

test_expect_success 'each rule taken from CERT C reports its sample' '
	R2=$W/samples &&
	mkdir -p "$R2/testing/coccinelle" &&
	git init -q "$R2" &&
	for r in $CERT_RULES; do
		cp "$ROOT/testing/coccinelle/$r.cocci" "$R2/testing/coccinelle/" ||
			exit 1
	done &&
	write_samples "$R2/samples.c" &&
	! (cd "$R2" && git add -A && sh "$S") >"$W/out" 2>"$W/err" &&
	for r in $CERT_RULES; do
		grep -q "^$r: samples.c:" "$W/err" || exit 1
	done &&
	grep -q "6 of 6 rules matched" "$W/err"
'

# One case of each BPF hazard, and beside it the safe form, which no rule
# reports: the count of reports shows the safe forms stay quiet.
BPF_RULES="bpf_map_rmw bpf_cas_unchecked bpf_check_then_insert \
bpf_publish bpf_user_double_fetch bpf_map_use_after_delete"
write_bpf_samples() {
	cat >"$1" <<'EOF'
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} hits SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} cpu_hits SEC(".maps");

struct node {
	int filled;
};

static struct node *head;

void count_plain(void)
{
	__u32 zero = 0;
	__u64 *count;

	count = bpf_map_lookup_elem(&hits, &zero);
	if (count)
		(*count)++;
}

void count_percpu(void)
{
	__u32 zero = 0;
	__u64 *count;

	count = bpf_map_lookup_elem(&cpu_hits, &zero);
	if (count)
		(*count)++;
}

void count_atomic(void)
{
	__u32 zero = 0;
	__u64 *count;

	count = bpf_map_lookup_elem(&hits, &zero);
	if (count)
		__sync_fetch_and_add(count, 1);
}

void cas_ignored(__u32 *slot, __u32 old, __u32 new)
{
	__sync_val_compare_and_swap(slot, old, new);
}

int cas_checked(__u32 *slot, __u32 old, __u32 new)
{
	return __sync_val_compare_and_swap(slot, old, new) == old;
}

void insert_racy(__u32 *k, struct val *v)
{
	if (!bpf_map_lookup_elem(&vals, k)) {
		bpf_map_update_elem(&vals, k, v, BPF_ANY);
	}
}

void insert_exclusive(__u32 *k, struct val *v)
{
	if (!bpf_map_lookup_elem(&vals, k)) {
		bpf_map_update_elem(&vals, k, v, BPF_NOEXIST);
	}
}

void publish_once(struct node *n)
{
	n->filled = 1;
	WRITE_ONCE(head, n);
}

void publish_release(struct node *n)
{
	n->filled = 1;
	__atomic_store_n(&head, n, __ATOMIC_RELEASE);
	WRITE_ONCE(head, NULL);
}

int fetch_twice(const char *uptr)
{
	char a[16], b[16];

	bpf_copy_from_user_str(a, sizeof(a), uptr, 0);
	if (a[0] != 'x')
		return 0;
	bpf_probe_read_user(b, sizeof(b), uptr);
	return b[1];
}

int fetch_once(const char *uptr)
{
	char a[16];

	bpf_probe_read_user(a, sizeof(a), uptr);
	return a[0];
}

void count_decl(void)
{
	__u32 zero = 0;
	__u64 *count = bpf_map_lookup_elem(&hits, &zero);

	if (count)
		(*count)++;
}

void flags_task(struct task_struct *task)
{
	struct meta *m = bpf_task_storage_get(&tasks, task, 0, 0);

	if (m)
		m->flags |= 1;
}

__u64 read_after_delete(__u32 *k)
{
	struct val *v;

	v = bpf_map_lookup_elem(&vals, k);
	if (!v)
		return 0;
	bpf_map_delete_elem(&vals, k);
	return v->count;
}

__u64 read_before_delete(__u32 *k)
{
	struct val *v;
	__u64 n;

	v = bpf_map_lookup_elem(&vals, k);
	if (!v)
		return 0;
	n = v->count;
	bpf_map_delete_elem(&vals, k);
	if (!v)
		return 0;
	return n;
}

struct meta *flags_reassigned(struct sock *sk)
{
	struct meta *m = bpf_sk_storage_get(&socks, sk, 0, 0);

	if (m)
		return m;
	m = meta_create(sk);
	if (m)
		m->flags |= 1;
	return m;
}

void count_add(void)
{
	__u32 zero = 0;
	__u64 *count = bpf_map_lookup_elem(&hits, &zero);

	if (count)
		*count += 1;
}

void count_sum(void)
{
	__u32 zero = 0;
	__u64 *count = bpf_map_lookup_elem(&hits, &zero);

	if (count)
		*count = *count + 2;
}

void count_percpu_add(void)
{
	__u32 zero = 0;
	__u64 *count = bpf_map_lookup_elem(&cpu_hits, &zero);

	if (count)
		*count += 1;
}

void flags_inode(struct inode *inode)
{
	struct meta *m = bpf_inode_storage_get(&inodes, inode, 0, 0);

	if (m)
		m->flags = m->flags + 1;
}
EOF
}

test_expect_success 'each BPF rule reports its sample and spares the safe form' '
	R3=$W/bpf &&
	mkdir -p "$R3/testing/coccinelle" &&
	git init -q "$R3" &&
	cp "$ROOT/testing/coccinelle/bpf.macros" "$R3/testing/coccinelle/" &&
	for r in $BPF_RULES; do
		cp "$ROOT/testing/coccinelle/$r.cocci" "$R3/testing/coccinelle/" ||
			exit 1
	done &&
	write_bpf_samples "$R3/samples.bpf.c" &&
	! (cd "$R3" && git add -A && sh "$S") >"$W/out" 2>"$W/err" &&
	for r in $BPF_RULES; do
		grep -q "^$r: samples.bpf.c:" "$W/err" || exit 1
	done &&
	grep -q "6 of 6 rules matched" "$W/err" &&
	[ "$(grep -c "^bpf_[a-z_]*: samples.bpf.c:" "$W/err")" = 10 ]
'

# A secret left on the stack, and beside it the scrubbed form and a local
# that holds nothing secret, which no rule reports: one report for each
# return of the two that leave the secret.
write_scrub_samples() {
	cat >"$1" <<'EOF'
int kdf_left(const __u8 *seed)
{
	__u8 key[16];

	if (tpm_kdfa(seed, 32, "STORAGE", NULL, 0, NULL, 0, key, sizeof(key)))
		return -EIO;
	return use(key);
}

int kdf_scrubbed(const __u8 *seed)
{
	__u8 key[16];
	int ret = -EIO;

	if (tpm_kdfa(seed, 32, "STORAGE", NULL, 0, NULL, 0, key, sizeof(key)))
		goto out;
	ret = use(key);
out:
	memzero_explicit(key, sizeof(key));
	return ret;
}

int credential_left(const char *hex)
{
	__u8 cred[16];

	if (hex_decode(hex, cred, sizeof(cred)))
		return -EINVAL;
	return use(cred);
}

int digest_public(const char *hex)
{
	__u8 digest[32];

	if (hex_decode(hex, digest, sizeof(digest)))
		return -EINVAL;
	return use(digest);
}

int address_output(const char *hex)
{
	__u8 credential[16];

	if (getrandom(&credential, sizeof(credential), 0) < 0)
		return -EIO;
	return use(credential);
}

int partial_scrub(const char *hex)
{
	__u8 credential[16];

	if (hex_decode(hex, credential, sizeof(credential))) {
		memzero_explicit(credential, 1);
		return -EINVAL;
	}
	memzero_explicit(credential, 1);
	return 0;
}

void credential_fallthrough(void)
{
	__u8 credential[16];

	getrandom(credential, sizeof(credential), 0);
	use(credential);
}
EOF
}

# The same for a struct a header marks: the two returns after its use,
# the compound literal and the scrub of one field alone are reported, the
# return before its use, the scrubbed form and the __cleanup() one not.
write_sensitive_samples() {
	mkdir -p "$1/include" &&
	printf 'struct client {\n\tchar name[32];\n\tchar password[64] __sensitive;\n\tchar token[32] __sensitive;\n};\n' \
		>"$1/include/client.h" &&
	cat >"$1/sensitive.c" <<'EOF'
int client_left(const char *url)
{
	struct client c = {};

	if (early())
		return -EINVAL;
	if (client_parse(url, &c))
		return -EINVAL;
	return use(&c);
}

int client_scrubbed(const char *url)
{
	struct client c = {};
	int ret = -EINVAL;

	if (early())
		goto out;
	ret = client_parse(url, &c);
	if (!ret)
		ret = use(&c);
out:
	memzero_explicit(&c, sizeof(c));
	return ret;
}

int client_cleanup(const char *url)
{
	struct client c __cleanup(client_clear) = {};

	if (client_parse(url, &c))
		return -EINVAL;
	return use(&c);
}

int client_literal(const char *url)
{
	return client_parse(url, &(struct client){});
}

int client_field(const char *url)
{
	struct client c = {};

	c.name[0] = url[0];
	memzero_explicit(c.password, sizeof(c.password));
	return 0;
}

int client_partial_scrub(const char *url)
{
	struct client c = {};

	if (client_parse(url, &c))
		return -EINVAL;
	memzero_explicit(&c, 1);
	return use(&c);
}

EOF
}

test_expect_success 'each scrub rule reports its samples and spares the scrubbed forms' '
	R4=$W/scrub &&
	mkdir -p "$R4/testing/coccinelle" &&
	git init -q "$R4" &&
	cp "$ROOT/testing/coccinelle/scrub_missing.cocci" \
		"$ROOT/testing/coccinelle/sensitive_scrub.cocci" \
		"$R4/testing/coccinelle/" &&
	write_scrub_samples "$R4/samples.c" &&
	write_sensitive_samples "$R4" &&
	! (cd "$R4" && git add -A && sh "$S") >"$W/out" 2>"$W/err" &&
	grep -q "2 of 2 rules matched" "$W/err" &&
	[ "$(grep -c "^scrub_missing: samples.c:" "$W/err")" = 9 ] &&
	[ "$(grep -c "^sensitive_scrub: sensitive.c:" "$W/err")" = 6 ] &&
	[ "$(grep -c "^[a-z_]*: " "$W/err")" = 15 ]
'

test_expect_success 'curl_slist_free reports lists freed without scrubbing' '
	R5=$W/curl-slist &&
	mkdir -p "$R5/testing/coccinelle" &&
	git init -q "$R5" &&
	cp "$ROOT/testing/coccinelle/curl_slist_free.cocci" \
		"$R5/testing/coccinelle/" &&
	printf "void headers_free(struct curl_slist *headers)\n{\n\tcurl_slist_free_all(headers);\n}\n" \
		>"$R5/samples.c" &&
	! (cd "$R5" && git add -A && sh "$S") >"$W/out" 2>"$W/err" &&
	[ "$(grep -c "^curl_slist_free: samples.c:" "$W/err")" = 1 ]
'

test_expect_success 'the tree passes' '
	(cd "$ROOT" && sh "$S") >"$W/out" 2>"$W/err" &&
	grep -q "rules, no match" "$W/out"
'

test_done
