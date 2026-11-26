#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0006 -- .github/scripts/check-coccinelle.sh: a rule that matches fails the
# check with file, line, rule and message, one that does not passes it,
# a rule that can rewrite does with -D patch, a rule reads the headers
# its #spatch line asks for, on a throwaway repository, each rule taken
# from CERT C, each BPF hazard rule, each scrub rule, dead_store and the
# two rules for bytes taken for a string report a sample of what they
# refuse, the rules of SAMPLE_RULES each at its line, array_size a count
# by hand in a macro and an ARRAY_SIZE() outside <shirudo/misc.h>,
# local_escape a local's address, or that of its member or element,
# left in the caller's object at any depth or in *out, and a block's
# local left in a pointer read after the block,
# literal_count a literal compared under a length written out,
# literal_strscpy a literal copied into an array with strscpy(),
# digest_concat two strings hashed with nothing between them, a file a
# rule gives up on at its time limit is named rather than failed, every
# rule declares SEC an attribute, and the tree itself.

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
# refuses, and for positive_errno a second, the branch of a conditional.
# A rule the tree gives no match proves nothing until it matches here.
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

int positive_chosen(long key)
{
	int ret;

	ret = key < 0 ? errno : 0;
	return ret;
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
	[ "$(grep -c "^positive_errno: samples.c:" "$W/err")" = 2 ] &&
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

# One case of each rule below at the line given with it, and beside it
# the forms the rule leaves alone: the count of reports shows they stay
# quiet.
SAMPLE_RULES="stale_success break_error sum_overwrite fd_leak getenv_null
strerror_negative double_test name_after_fd"
SAMPLE_LINES="stale_success:9 break_error:53 sum_overwrite:110 fd_leak:148
getenv_null:170 getenv_null:177 strerror_negative:196 strerror_negative:202
double_test:215 double_test:222 double_test:231 double_test:243 double_test:254
name_after_fd:276 name_after_fd:285 name_after_fd:296 name_after_fd:307"
write_line_samples() {
	cat >"$1" <<'EOF'
int search_left(int fd, int key)
{
	int ret = -EACCES;

	ret = check(fd);
	if (ret)
		goto out;
	if (lookup(fd, key))
		goto out;
	ret = 0;
out:
	close(fd);
	return ret;
}

int search_reset(int fd, int key)
{
	int ret = -EACCES;

	ret = check(fd);
	if (ret)
		goto out;
	ret = -EACCES;
	if (lookup(fd, key))
		goto out;
	ret = 0;
out:
	close(fd);
	return ret;
}

int holds_exactly(int fd, int n)
{
	int ret = -ENOMEM;

	ret = read_links(fd);
	if (ret)
		goto out;
	if (links(fd) != n)
		goto out;
	ret = 1;
out:
	return ret;
}

int upgrade_left(DIR *d, int n)
{
	struct dirent *de;
	int ret = 0;

	while ((de = readdir(d))) {
		if (pair(de)) {
			ret = -ENAMETOOLONG;
			break;
		}
		n++;
	}
	closedir(d);
	sort_pairs(n);
	if (unload(n))
		ret = -EIO;
	return ret;
}

int upgrade_tested(DIR *d, int n)
{
	struct dirent *de;
	int ret = 0;

	while ((de = readdir(d))) {
		if (pair(de)) {
			ret = -ENAMETOOLONG;
			break;
		}
		n++;
	}
	closedir(d);
	if (ret)
		return ret;
	sort_pairs(n);
	if (unload(n))
		ret = -EIO;
	return ret;
}

int scan_fallback(DIR *d, char *root)
{
	struct dirent *de;
	int ret = 0;

	while ((de = readdir(d))) {
		if (bad(de)) {
			ret = -EINVAL;
			break;
		}
		take(root, de);
	}
	if (!root[0])
		ret = -EINVAL;
	closedir(d);
	return ret;
}

size_t status_cap(int rows, int events, int lines)
{
	size_t cap;

	cap = 16384 + (size_t)rows * 256;
	if (events)
		cap = 65536 + 3 * (size_t)events;
	if (lines)
		cap += (size_t)lines * 1024;
	return cap;
}

size_t status_cap_added(int rows, int events, int lines)
{
	size_t cap;

	cap = 16384 + (size_t)rows * 256;
	if (events)
		cap += 65536 + 3 * (size_t)events;
	if (lines)
		cap += (size_t)lines * 1024;
	return cap;
}

size_t header_size(size_t fixed, size_t chosen, int custom)
{
	size_t n;

	n = fixed;
	if (custom)
		n = chosen;
	n += 64;
	return n;
}

int measure_left(const struct op *op)
{
	int lock, ret;

	lock = eventlog_lock();
	if (lock < 0)
		return lock;
	ret = measure_locked(op);
	if (ret)
		return ret;
	eventlog_unlock(lock);
	return 0;
}

int measure_unlocked(const struct op *op)
{
	int lock, ret;

	lock = eventlog_lock();
	if (lock < 0)
		return lock;
	ret = measure_locked(op);
	eventlog_unlock(lock);
	return ret;
}

int env_stored(void)
{
	const char *scheme;

	scheme = getenv("BPM_OCI_SCHEME");
	return !strcmp(scheme, "http");
}

size_t env_declared(void)
{
	const char *home = getenv("HOME");

	return strlen(home);
}

int env_tested(void)
{
	const char *region, *endpoint;

	region = getenv("AWS_REGION");
	endpoint = getenv("AWS_ENDPOINT_URL_S3");
	if (!region || !region[0] || !endpoint)
		return -EINVAL;
	return endpoint[0] && strlen(endpoint) < 256;
}

void report_stored(const char *path)
{
	int ret;

	ret = -errno;
	pr_err("open %s: %s", path, strerror(ret));
}

void report_tested(int ret)
{
	if (ret < 0)
		pr_err("load: %s", strerror(ret));
}

void report_negated(int ret, int err)
{
	if (ret < 0)
		pr_err("load: %s", strerror(-ret));
	err = errno;
	pr_err("read: %s", strerror(err));
}

const char *direction_alike(int egress)
{
	return egress ? "ingress" : "ingress";
}

int kind_two(int kind)
{
	if (kind == 3)
		return 1;
	else if (kind == 3)
		return 2;
	return 0;
}

int kind_named_twice(const char *kind)
{
	if (!strcmp(kind, "xdp"))
		return 1;
	else if (!strcmp(kind, "xdp"))
		return 2;
	else
		return 0;
}

int kind_repeated(int kind)
{
	if (kind == 3)
		return 1;
	else if (kind == 4)
		return 2;
	else if (kind == 3)
		return 3;
	return 0;
}

int kind_repeated_else(int kind)
{
	if (kind == 3)
		return 1;
	else if (kind == 4)
		return 2;
	else if (kind == 3)
		return 3;
	else
		return 0;
}

int counted_twice(struct lexer *l)
{
	if (l->pos++ == 0)
		return 1;
	else if (l->pos++ == 0)
		return 2;
	return 0;
}

int checked(int fd, const char *path)
{
	char real[PATH_MAX];
	struct stat st;

	if (fstat(fd, &st))
		return -errno;
	if (!realpath(path, real))
		return -errno;
	return walk(real);
}

static ssize_t target_of(const char *path, int dirfd, char *buf, size_t cap)
{
	if (owned(dirfd))
		return -EPERM;
	return readlink(path, buf, cap);
}

int opened(const char *path)
{
	char real[PATH_MAX];
	int fd, ret;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	ret = realpath(path, real) ? walk(real) : -errno;
	close(fd);
	return ret;
}

int opened_at(int dir, const char *link, char *buf, size_t cap)
{
	int fd = openat(dir, link, O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		return -errno;
	if (readlink(link, buf, cap) < 0) {
		close(fd);
		return -errno;
	}
	return fd;
}

int resolved_first(const char *path)
{
	char real[PATH_MAX];

	if (!realpath(path, real))
		return -errno;
	return open(real, O_RDONLY | O_CLOEXEC);
}

int named_again(const char *path, const char *other, char *real)
{
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	path = other;
	if (!realpath(path, real)) {
		close(fd);
		return -errno;
	}
	return fd;
}

int stated(int fd, const char *path)
{
	struct stat st;

	return stat(path, &st) ? -errno : 0;
}

int by_descriptor(int fd, char *buf, size_t cap)
{
	char proc[64];

	if (strsprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd) < 0)
		return -E2BIG;
	return readlink(proc, buf, cap) < 0 ? -errno : 0;
}

int no_descriptor(int flags, const char *path, char *real)
{
	return realpath(path, real) ? flags : -errno;
}

int committed(int dirfd, const char *name, const char *tmp, const void *data)
{
	int fd = openat(dirfd, tmp, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);

	if (fd < 0)
		return -errno;
	return commit_file(dirfd, name, tmp, fd, data);
}
EOF
}

test_expect_success 'each rule reports its sample at its line and spares the safe forms' '
	R9=$W/lines &&
	mkdir -p "$R9/testing/coccinelle" &&
	git init -q "$R9" &&
	for r in $SAMPLE_RULES; do
		cp "$ROOT/testing/coccinelle/$r.cocci" "$R9/testing/coccinelle/" ||
			exit 1
	done &&
	write_line_samples "$R9/samples.c" &&
	! (cd "$R9" && git add -A && sh "$S") >"$W/out" 2>"$W/err" &&
	for l in $SAMPLE_LINES; do
		grep -q "^${l%%:*}: samples.c:${l#*:}:" "$W/err" || exit 1
	done &&
	[ "$(grep -c "^[a-z_]*: samples.c:" "$W/err")" = \
		"$(echo $SAMPLE_LINES | wc -w)" ]
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

# The error of the first call is stored over before anything reads it;
# a value read on an error path, one read through its address and one
# the next store reads are all read first.
write_dead_store_samples() {
	cat >"$1" <<'EOF'
int lost(const char *buf)
{
	int ret;

	ret = parse_header(buf);
	ret = parse_body(buf);
	return ret;
}

int on_error_path(const char *buf)
{
	int ret;

	ret = -EBADMSG;
	if (!buf)
		goto out;
	ret = parse_body(buf);
out:
	return ret;
}

int through_address(int fd)
{
	int value;

	value = 0;
	read_into(fd, &value);
	value = 1;
	return value;
}

int accumulated(int n)
{
	int sum;

	sum = n;
	sum = sum + 1;
	return sum;
}
EOF
}

test_expect_success 'dead_store reports a store stored over and spares the reads' '
	R6=$W/dead-store &&
	mkdir -p "$R6/testing/coccinelle" &&
	git init -q "$R6" &&
	cp "$ROOT/testing/coccinelle/dead_store.cocci" "$R6/testing/coccinelle/" &&
	write_dead_store_samples "$R6/samples.c" &&
	! (cd "$R6" && git add -A && sh "$S") >"$W/out" 2>"$W/err" &&
	grep -q "^dead_store: samples.c:5:" "$W/err" &&
	[ "$(grep -c "^dead_store: samples.c:" "$W/err")" = 1 ]
'

# An option compared by hand, which option_by_hand reports, beside the
# standard output path "-", which is no option, and the parser itself,
# whose file the rule leaves alone.
write_option_samples() {
	cat >"$1/samples.c" <<'EOF'
int by_hand(int argc, const char **argv)
{
	return argc > 1 && !strcmp(argv[1], "--json");
}

int to_stdout(const char *path)
{
	return !strcmp(path, "-");
}
EOF
	mkdir -p "$1/util" &&
	cat >"$1/util/options.c" <<'EOF'
int is_end(const char *arg)
{
	return !strcmp(arg, "--");
}
EOF
}

test_expect_success 'option_by_hand reports an option compared outside the parser' '
	R7=$W/option &&
	mkdir -p "$R7/testing/coccinelle" &&
	git init -q "$R7" &&
	cp "$ROOT/testing/coccinelle/option_by_hand.cocci" \
		"$R7/testing/coccinelle/" &&
	write_option_samples "$R7" &&
	! (cd "$R7" && git add -A && sh "$S") >"$W/out" 2>"$W/err" &&
	grep -q "^option_by_hand: samples.c:3:" "$W/err" &&
	[ "$(grep -c "^option_by_hand:" "$W/err")" = 1 ]
'

# Bytes taken for a string: a buffer a read filled that nothing
# terminated, and a file read whole that nothing saw with its length,
# each beside the forms that terminate or check first, which no rule
# reports.
write_string_samples() {
	cat >"$1" <<'EOF'
int id_unterminated(int fd, const char *want)
{
	char id[64];

	if (read(fd, id, sizeof(id) - 1) <= 0)
		return -EIO;
	return strcmp(id, want);
}

int id_terminated(int fd, const char *want)
{
	char id[64];
	ssize_t n;

	n = read(fd, id, sizeof(id) - 1);
	if (n <= 0)
		return -EIO;
	id[n] = '\0';
	return strcmp(id, want);
}

int id_zeroed(int fd, const char *want)
{
	char id[64] = {};

	if (read(fd, id, sizeof(id) - 1) <= 0)
		return -EIO;
	return strcmp(id, want);
}

int id_checked(int fd, const char *want)
{
	char id[64];
	ssize_t n;

	n = read(fd, id, sizeof(id) - 1);
	if (n <= 0 || span_to_str(id, sizeof(id), id, (size_t)n))
		return -EIO;
	return strcmp(id, want);
}

size_t label_unterminated(const char *path)
{
	char label[65];

	if (getxattr(path, "user.label", label, sizeof(label)) < 0)
		return 0;
	return strlen(label);
}

int file_searched(const char *path, const char *needle)
{
	size_t len;
	char *text;
	int found;

	if (read_file(path, 4096, &text, &len))
		return -EIO;
	found = strstr(text, needle) != NULL;
	xfree(text, len + 1);
	return found;
}

int file_checked(const char *path, const char *needle)
{
	size_t len;
	char *text;
	int found;

	if (read_file(path, 4096, &text, &len))
		return -EIO;
	if (span_to_str(text, len + 1, text, len)) {
		xfree(text, len + 1);
		return -EINVAL;
	}
	found = strstr(text, needle) != NULL;
	xfree(text, len + 1);
	return found;
}

int file_parsed(const char *path, struct json_field *f, size_t n)
{
	size_t len;
	char *text;
	int ret;

	if (read_file(path, 4096, &text, &len))
		return -EIO;
	ret = json_parse(text, len, f, n);
	xfree(text, len + 1);
	return ret;
}

int member_walked(int fd)
{
	char *save, *line;
	size_t len;
	__u8 *body;
	int n = 0;

	if (bpm_pkg_read_member_fd(fd, "list", NULL, NULL, 0, &body, &len,
				   4096))
		return -EIO;
	for (line = strtok_r((char *)body, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save))
		n++;
	xfree(body, len + 1);
	return n;
}

int id_searched(int fd)
{
	char id[64];

	if (read(fd, id, sizeof(id) - 1) <= 0)
		return -EIO;
	return str_contains(id, "x");
}
EOF
}

test_expect_success 'the string rules report bytes taken for a string unchecked' '
	R9=$W/string &&
	mkdir -p "$R9/testing/coccinelle" &&
	git init -q "$R9" &&
	cp "$ROOT/testing/coccinelle/read_unterminated.cocci" \
		"$ROOT/testing/coccinelle/file_as_string.cocci" \
		"$R9/testing/coccinelle/" &&
	write_string_samples "$R9/samples.c" &&
	! (cd "$R9" && git add -A && sh "$S") >"$W/out" 2>"$W/err" &&
	grep -q "2 of 2 rules matched" "$W/err" &&
	grep -q "^read_unterminated: samples.c:7:" "$W/err" &&
	grep -q "^read_unterminated: samples.c:48:" "$W/err" &&
	grep -q "^read_unterminated: samples.c:117:" "$W/err" &&
	[ "$(grep -c "^read_unterminated: samples.c:" "$W/err")" = 3 ] &&
	grep -q "^file_as_string: samples.c:59:" "$W/err" &&
	grep -q "^file_as_string: samples.c:104:" "$W/err" &&
	[ "$(grep -c "^file_as_string: samples.c:" "$W/err")" = 2 ]
'

# A count by hand in a macro, which writes its argument in parentheses,
# and an ARRAY_SIZE() of a file's own, while the one of <shirudo/misc.h>
# is spared.
write_array_size_samples() {
	mkdir -p "$1/include/shirudo" &&
	cat >"$1/include/shirudo/misc.h" <<'EOF'
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]) + __must_be_array(a))
EOF
	cat >"$1/samples.c" <<'EOF'
#define COUNT(a) (sizeof(a) / sizeof((a)[0]) + __must_be_array(a))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

int counted(void)
{
	int x[4];

	return sizeof(x) / sizeof(*(x)) + ARRAY_SIZE(x);
}
EOF
}

test_expect_success 'array_size reports counts by hand and a second ARRAY_SIZE()' '
	R8=$W/array &&
	mkdir -p "$R8/testing/coccinelle" &&
	git init -q "$R8" &&
	cp "$ROOT/testing/coccinelle/array_size.cocci" \
		"$R8/testing/coccinelle/" &&
	write_array_size_samples "$R8" &&
	! (cd "$R8" && git add -A && sh "$S") >"$W/out" 2>"$W/err" &&
	grep -q "^array_size: samples.c:1:" "$W/err" &&
	grep -q "^array_size: samples.c:2:" "$W/err" &&
	grep -q "^array_size: samples.c:8:" "$W/err" &&
	[ "$(grep -c "^array_size:" "$W/err")" = 3 ]
'

test_expect_success 'array_size rewrites the counts but not a definition' '
	R8=$W/array &&
	(cd "$R8" && spatch -D patch --very-quiet --in-place --no-includes \
		--sp-file testing/coccinelle/array_size.cocci samples.c) &&
	grep -qxF "#define COUNT(a) (ARRAY_SIZE(a))" "$R8/samples.c" &&
	grep -qxF "#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))" \
		"$R8/samples.c" &&
	grep -qF "return ARRAY_SIZE(x) + ARRAY_SIZE(x);" "$R8/samples.c"
'

# The address of a local left in an object the caller passed in: an
# array, a variable and an element, through a parameter or a pointer
# taken from one, in a member at any depth, an element and *out, and the
# address of a local's member or element, cast or offset, and a pointer
# from outside a loop's or a branch's block left at a local of the block
# and read after it. Beside them what keeps nothing: a member or *out
# cleared before the return, a static local, a pointer's value, the
# address of what a member points to, an object of the function's own,
# and a pointer cleared in its block or set again before it is read.
write_escape_samples() {
	cat >"$1" <<'EOF'
struct ctx {
	const int *entry;
	const char *name;
	int *count;
};

int kept_array(struct ctx *u, int n)
{
	int entry[2] = { n, n };

	u->entry = entry;
	return n;
}

int kept_variable(struct ctx *u)
{
	int count = 0;

	u->count = &count;
	return 0;
}

int kept_through_alias(void *arg)
{
	struct ctx *u = arg;
	int entry[2] = {};

	u->entry = entry;
	return 0;
}

void kept_element(struct ctx *u)
{
	int entry[2] = {};

	if (entry[0])
		u->entry = &entry[1];
}

int cleared(struct ctx *u)
{
	int entry[2] = {};

	u->entry = entry;
	use(u);
	u->entry = NULL;
	return 0;
}

int static_local(struct ctx *u)
{
	static const int
		entry[2] = { 1, 2 };

	u->entry = entry;
	return 0;
}

int pointer_value(struct ctx *u, const char *name)
{
	const char *local = name;

	u->name = local;
	return 0;
}

int own_object(struct ctx *other)
{
	struct ctx c, *u = &c;
	int entry[2] = {};

	u->entry = entry;
	return use(u) + use(other);
}

struct nest {
	struct ctx in;
	const int *slot[2];
	struct ctx *next;
	struct {
		int n;
	} pair;
};

int kept_nested(struct nest *n)
{
	int entry[2] = {};

	n->in.entry = entry + 1;
	return 0;
}

int kept_slot(struct nest *n, int i)
{
	int v = i;

	n->slot[i] = &v;
	return 0;
}

int kept_out(const int **out)
{
	struct {
		int n;
	} vals[2] = {};

	*out = &vals[1].n;
	return 0;
}

int kept_through(struct nest *n)
{
	int v = 0;

	(*n).next->count = &v;
	return 0;
}

int kept_member(struct ctx *u)
{
	struct nest local = {};

	u->entry = &local.pair.n;
	u->name = (const char *)&local.in;
	return 0;
}

int cleared_out(const int **out)
{
	int v = 0;

	*out = &v;
	use(*out);
	*out = NULL;
	return 0;
}

int pointee(const int **out, struct ctx *u)
{
	struct ctx local = *u;

	*out = local.entry;
	*out = &local.entry[1];
	return 0;
}

int own_nested(struct nest *other)
{
	struct nest n = {};
	int entry[2] = {};

	n.in.entry = entry;
	n.slot[0] = entry;
	return use(&n) + use(other);
}

int kept_past_loop(int n)
{
	const char *name = "none";
	int i;

	for (i = 0; i < n; i++) {
		char buf[16];

		buf[0] = 'a';
		name = buf;
	}
	return use(name);
}

int kept_past_branch(int n)
{
	const int *p = NULL;
	const char *argv[2] = {};

	if (n) {
		int v = n;
		char arg[4] = "-v";

		p = &v;
		argv[0] = arg;
	}
	return p ? *p + use(argv[0]) : 0;
}

int kept_past_while(int n)
{
	const int *slots[2] = {};
	const char *name = "none";

	while (n--) {
		int v = n;
		char buf[8] = "ab";

		slots[0] = &v;
		name = &buf[1];
	}
	return use(name) + *slots[0];
}

int used_in_block(int n)
{
	const char *name = "none";

	if (n) {
		char buf[16] = "x";

		name = buf;
		use(name);
		name = "none";
	}
	return use(name);
}

int reassigned_past_block(int n)
{
	const char *name = "none";

	if (n) {
		char buf[16] = "x";

		name = buf;
		use(name);
	}
	name = "none";
	return use(name);
}

int static_in_block(int n)
{
	const char *name = "none";

	if (n) {
		static char buf[16];

		name = buf;
	}
	return use(name);
}
EOF
}

test_expect_success 'local_escape reports a local left in the caller'"'"'s object' '
	R9=$W/escape &&
	mkdir -p "$R9/testing/coccinelle" &&
	git init -q "$R9" &&
	cp "$ROOT/testing/coccinelle/local_escape.cocci" \
		"$R9/testing/coccinelle/" &&
	write_escape_samples "$R9/samples.c" &&
	! (cd "$R9" && git add -A && sh "$S") >"$W/out" 2>"$W/err" &&
	for line in 11 19 28 37 89 97 107 115 123 124 166 180 181 195 196; do
		grep -q "^local_escape: samples.c:$line:" "$W/err" || exit 1
	done &&
	grep -q "samples.c:11:.*u->entry keeps the address of the local entry past the return" "$W/err" &&
	grep -q "samples.c:107:.*\*out keeps the address of the local vals past the return" "$W/err" &&
	grep -q "samples.c:166:.*name keeps the address of the local buf past its block" "$W/err" &&
	[ "$(grep -c "^local_escape:" "$W/err")" = 15 ]
'

# A literal compared or searched under a length written out as a number,
# on either side of the call, beside the lengths taken from the literal
# and a named one, which the rule leaves alone.
write_count_samples() {
	cat >"$1" <<'EOF'
#define TAG_LEN	7

int counted(const char *s, const void *p, int c)
{
	return !memcmp(s, "sha256:", 7) || !memcmp("GNU", p, 4) ||
	       memchr("nrt", c, 3) || !strncasecmp(s, "az", 3) ||
	       memmem(p, 64, "ustar", 5);
}

int derived(const char *s, const void *p, int c)
{
	static const char escapes[] = "nrt";

	return !memcmp(s, "sha256:", sizeof("sha256:") - 1) ||
	       !memcmp(p, "GNU", sizeof("GNU")) ||
	       !memcmp(s, "sha256:", TAG_LEN) ||
	       memchr(escapes, c, sizeof(escapes) - 1) ||
	       !memcmp(s, p, 7) || str_has_prefix(s, "sha256:");
}
EOF
}

test_expect_success 'literal_count reports a literal compared under a number' '
	R10=$W/count &&
	mkdir -p "$R10/testing/coccinelle" &&
	git init -q "$R10" &&
	cp "$ROOT/testing/coccinelle/literal_count.cocci" \
		"$R10/testing/coccinelle/" &&
	write_count_samples "$R10/samples.c" &&
	! (cd "$R10" && git add -A && sh "$S") >"$W/out" 2>"$W/err" &&
	grep -q "^literal_count: samples.c:5:.*memcmp() of a literal with the length 7 written out" "$W/err" &&
	grep -q "^literal_count: samples.c:5:.*memcmp() of a literal with the length 4 written out" "$W/err" &&
	grep -q "^literal_count: samples.c:6:.*memchr() of a literal with the length 3" "$W/err" &&
	grep -q "^literal_count: samples.c:6:.*strncasecmp() of a literal with the length 3" "$W/err" &&
	grep -q "^literal_count: samples.c:7:.*memmem() of a literal with the length 5" "$W/err" &&
	[ "$(grep -c "^literal_count:" "$W/err")" = 5 ]
'

# A literal copied into an array with strscpy(), with the size of the
# array or without parentheses, beside a copy into a pointer and a size,
# a copy of a variable and strscpy_literal(), which the rule leaves alone.
write_strscpy_samples() {
	cat >"$1" <<'EOF'
struct s { char name[16]; };

int copied(struct s *o, char *buf, size_t cap, const char *v)
{
	char local[8];

	if (strscpy(o->name, "fixed", sizeof(o->name)) < 0)
		return -E2BIG;
	if (strscpy(local, "x", sizeof local) < 0)
		return -E2BIG;
	if (strscpy(buf, "?", cap) < 0 ||
	    strscpy(o->name, v, sizeof(o->name)) < 0)
		return -E2BIG;
	strscpy_literal(o->name, "fixed");
	return 0;
}
EOF
}

test_expect_success 'literal_strscpy reports a literal strscpy() into an array' '
	R12=$W/strscpy &&
	mkdir -p "$R12/testing/coccinelle" &&
	git init -q "$R12" &&
	cp "$ROOT/testing/coccinelle/literal_strscpy.cocci" \
		"$R12/testing/coccinelle/" &&
	write_strscpy_samples "$R12/samples.c" &&
	! (cd "$R12" && git add -A && sh "$S") >"$W/out" 2>"$W/err" &&
	grep -q "^literal_strscpy: samples.c:7:.*not strscpy_literal()" "$W/err" &&
	grep -q "^literal_strscpy: samples.c:9:.*not strscpy_literal()" "$W/err" &&
	[ "$(grep -c "^literal_strscpy:" "$W/err")" = 2 ]
'

# Two strings fed to a digest in a row, each by its strlen() alone: as
# statements, through a return code, in one condition and through
# sha256_2(). Beside them what tells the two apart: the first string's
# terminator, a delimiter, a fixed size, and two digests.
write_digest_samples() {
	cat >"$1" <<'EOF'
int plain(struct sha256_ctx *ctx, const char *host, const char *port)
{
	sha256_update(ctx, host, strlen(host));
	sha256_update(ctx, port, strlen(port));
	return 0;
}

int chained(struct sha256_ctx *ctx, const char *host, const char *port)
{
	int ret;

	ret = sha256_update(ctx, host, strlen(host));
	if (!ret)
		ret = sha256_update(ctx, port, strlen(port));
	return ret;
}

int in_one_condition(struct sha256_ctx *ctx, const char *host,
		     const char *port)
{
	if (sha256_update(ctx, host, strlen(host)) != 0 ||
	    sha256_update(ctx, port, strlen(port)) != 0)
		return -EIO;
	return 0;
}

int both_at_once(const char *host, const char *port, __u8 out[32])
{
	return sha256_2(host, strlen(host), port, strlen(port), out);
}

int terminated(struct sha256_ctx *ctx, const char *host, const char *port)
{
	sha256_update(ctx, host, strlen(host) + 1);
	sha256_update(ctx, port, strlen(port));
	return 0;
}

int delimited(struct sha256_ctx *ctx, const char *host, const char *port)
{
	if (sha256_update(ctx, host, strlen(host)) != 0 ||
	    sha256_update(ctx, ":", 1) != 0 ||
	    sha256_update(ctx, port, strlen(port)) != 0)
		return -EIO;
	return 0;
}

int fixed_size(struct sha256_ctx *ctx, const char *host, const __u8 key[32])
{
	sha256_update(ctx, host, strlen(host));
	sha256_update(ctx, key, 32);
	return 0;
}

int two_digests(struct sha256_ctx *a, struct sha256_ctx *b, const char *host,
		const char *port)
{
	sha256_update(a, host, strlen(host));
	sha256_update(b, port, strlen(port));
	return 0;
}

int tagged(const char *tag, const __u8 cert[32], __u8 out[32])
{
	return sha256_2(tag, strlen(tag) + 1, cert, 32, out);
}
EOF
}

test_expect_success 'digest_concat reports two strings hashed with nothing between' '
	R11=$W/digest &&
	mkdir -p "$R11/testing/coccinelle" &&
	git init -q "$R11" &&
	cp "$ROOT/testing/coccinelle/digest_concat.cocci" \
		"$R11/testing/coccinelle/" &&
	write_digest_samples "$R11/samples.c" &&
	! (cd "$R11" && git add -A && sh "$S") >"$W/out" 2>"$W/err" &&
	for line in 4 14 21 29; do
		grep -q "^digest_concat: samples.c:$line:.*port is hashed right after host, each by its strlen() alone" "$W/err" ||
			exit 1
	done &&
	[ "$(grep -c "^digest_concat:" "$W/err")" = 4 ]
'

# A spatch that gives up, as a rule with --timeout makes it: the file it
# gave up on is named and the check passes, while another failure fails.
write_fake_spatch() {
	cat >"$1" <<'EOF'
#!/bin/sh
for arg; do
	file=$arg
done
if [ -n "${FAKE_SPATCH_FAIL:-}" ]; then
	echo "parse error" >&2
else
	echo "timeout (we abort): $file" >&2
	echo "Fatal error: exception Coccinelle_modules.Common.Timeout" >&2
fi
exit 2
EOF
	chmod +x "$1"
}

test_expect_success 'a file a rule gives up on is named, not failed' '
	R7=$W/timeout &&
	mkdir -p "$R7/testing/coccinelle" "$W/bin" &&
	git init -q "$R7" &&
	cp "$ROOT/testing/coccinelle/dead_store.cocci" "$R7/testing/coccinelle/" &&
	printf "int x;\n" >"$R7/slow.c" &&
	write_fake_spatch "$W/bin/spatch" &&
	(cd "$R7" && git add -A && PATH="$W/bin:$PATH" sh "$S") \
		>"$W/out" 2>"$W/err" &&
	grep -q "dead_store: gave up on slow.c at its time limit" "$W/err" &&
	! (cd "$R7" && FAKE_SPATCH_FAIL=1 PATH="$W/bin:$PATH" sh "$S") \
		>"$W/out" 2>"$W/err" &&
	grep -q "dead_store: spatch failed" "$W/err"
'

test_expect_success 'every rule declares SEC an attribute' '
	for r in "$ROOT"/testing/coccinelle/*.cocci; do
		grep -q "^attribute name SEC;$" "$r" || exit 1
	done
'

if [ "${SHIRUDO_SKIP_TREE_CHECKS:-0}" != 1 ]; then
	test_expect_success 'the tree passes' '
		(cd "$ROOT" && sh "$S") >"$W/out" 2>"$W/err" &&
		grep -q "rules, no match" "$W/out"
	'
fi

test_done
