// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The attach metadata build_prog_metadata() of package.c writes for the
 * programs LEN picks from a table, with libbpf's object and the ELF
 * resolver modelled: it has the length the format gives, prog_specs_parse()
 * of util/upatch.c takes it and reads back what each section spells, and
 * what the reader refuses is refused with nothing written.
 */

/* As proof.h, before the system headers can include <ctype.h>. */
#define __NO_CTYPE 1

#include <openssl/evp.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#if defined(KPROBE_OBJECTS) && LEN == 14
static void *metadata_malloc(size_t size);
static void *metadata_calloc(size_t nmemb, size_t size);
static char *metadata_strndup(const char *s, size_t len);
static void *metadata_realloc(void *ptr, size_t old_nmemb, size_t new_nmemb,
			      size_t size);
#define xmalloc metadata_malloc
#define xcalloc metadata_calloc
#define xstrndup metadata_strndup
#endif
#include "../../../util/upatch.c"
#if defined(KPROBE_OBJECTS) && LEN == 14
#undef xmalloc
#undef xcalloc
#undef xstrndup
#define xreallocarray metadata_realloc
#endif
#include "../../../tools/shirudo-build/package.c"
#if defined(KPROBE_OBJECTS) && LEN == 14
#undef xreallocarray
#endif

#define TAIL		3
#define TEXT_MAX	160
#define NR_PROGS_MAX	2
#define NR_OFFSETS	2
#define UPROBE_PATH	"/x"
#define A15		"aaaaaaaaaaaaaaa"
#define A127		A15 "a" A15 "a" A15 "a" A15 "a" A15 "a" A15 "a" \
			A15 "a" A15

enum { TAIL_NONE, TAIL_SEC, TAIL_NAME };
enum { TAKEN, EITHER, REFUSED };

/*
 * A program: its section and name, any TAIL bytes behind the one or the
 * other where tail says so, whether the writer takes it, and what the
 * reader then gives. A uprobe's binary has a build ID of build_id_len
 * bytes, and the resolver finds it unless no_binary is set. A kprobe multi
 * program reads back syms, its names sorted and joined by ','.
 */
struct shape {
	const char	*sec;
	const char	*name;
	__u32		tail;
	__u32		verdict;
	__u32		role;
	__u32		kind;
	const char	*target;
	__u64		offset;
	__u32		build_id_len;
	bool		no_binary;
	const char	*syms;
};

#define PROG(sec, verdict, kind, ...) \
	{ sec, "p", TAIL_NONE, verdict, UPATCH_PROG_ROLE_ATTACH, \
	  UPATCH_ATTACH_##kind, __VA_ARGS__ }
#define PLAIN(sec, kind) \
	PROG(sec, TAKEN, kind, "")
#define PROBE(sec, kind, target, offset) \
	PROG(sec, TAKEN, kind, target, offset)
#define REFUSE(sec) \
	{ sec, "p", TAIL_NONE, REFUSED }
#define XDP(digit, verdict) \
	{ "xdp/" digit, "p", TAIL_SEC, verdict, UPATCH_PROG_ROLE_ATTACH, \
	  UPATCH_ATTACH_XDP }
#define SERIALIZER(map, tail, verdict) \
	{ "syscall", SERIALIZER_PREFIX map, tail, verdict, \
	  UPATCH_PROG_ROLE_SERIALIZER }
#define TEST_RUN(id, verdict) \
	{ "syscall", TEST_RUN_PREFIX id, TAIL_NONE, verdict, \
	  UPATCH_PROG_ROLE_TEST_RUN, 0, "" }
#define AT(sec, at) \
	sec "/" UPROBE_PATH ":" at
/* The writer refuses a function the resolver finds beyond 4 GiB. */
#define UPROBE(sec, kind, target, offset, build_id_len) \
	PROG(sec, EITHER, kind, target, offset, build_id_len)
#define GLOB(sec, kind, target, build_id_len) \
	PROG(sec, TAKEN, kind, target, 0, build_id_len)
#define NO_BINARY(sec, kind) \
	PROG(sec, REFUSED, kind, "f", 0, 20, true)
#define KMULTI(sec, kind, syms) \
	PROG(sec, TAKEN, kind, "", 0, 0, false, syms)

static const struct {
	__u32		nr_progs;
	struct shape	progs[NR_PROGS_MAX];
} objects[] = {
#if defined(KPROBE_OBJECTS)
	{ 1, { PROBE("kprobe/f", KPROBE, "f", 0) } },
	{ 1, { PROBE("kprobe/fn+7", KPROBE, "fn", 7) } },
	{ 1, { PROBE("kprobe/a+b+0x1122334455667788", KPROBE, "a+b",
		     0x1122334455667788) } },
	{ 1, { PROBE("kprobe/" A127, KPROBE, A127, 0) } },
	{ 1, { PROBE("kretprobe/f", KRETPROBE, "f", 0) } },
	{ 2, { PROBE("kretprobe/g+0", KRETPROBE, "g", 0),
	       PROBE("kprobe/f+18446744073709551615", KPROBE, "f",
		     UINT64_MAX) } },
	{ 1, { REFUSE("kprobe/" A127 "a") } },
	{ 1, { REFUSE("kretprobe/f+1") } },
	{ 1, { REFUSE("kprobe/+1") } },
	{ 1, { REFUSE("kprobe/f+") } },
	{ 1, { REFUSE("kprobe/f+07") } },
	{ 1, { KMULTI("kprobe.multi/f", KPROBE_MULTI, "f") } },
	{ 1, { KMULTI("kretprobe.multi/g,f", KRETPROBE_MULTI, "f,g") } },
	{ 2, { KMULTI("kprobe.multi/f", KPROBE_MULTI, "f"),
	       KMULTI("kretprobe.multi/g", KRETPROBE_MULTI, "g") } },
	{ 2, { UPROBE(AT("uprobe", "f"), UPROBE, "f", 0, 20),
	       KMULTI("kprobe.multi/g", KPROBE_MULTI, "g") } },
	{ 1, { REFUSE("kprobe.multi/f*") } },
	{ 1, { REFUSE("kprobe.multi/f,f") } },
	{ 1, { REFUSE("kprobe.multi/f,") } },
	{ 1, { REFUSE("kprobe.multi/") } },
	{ 1, { REFUSE("kprobe") } },
	{ 1, { REFUSE("kprobe/") } },
	{ 1, { REFUSE("kretprobe") } },
	{ 1, { REFUSE("kretprobe/") } },
#elif defined(XDP_OBJECTS)
	{ 1, { XDP("0", EITHER) } },
	{ 1, { XDP("1", EITHER) } },
	{ 1, { XDP("2", EITHER) } },
	{ 1, { XDP("3", EITHER) } },
	{ 1, { XDP("4", REFUSED) } },
	{ 1, { XDP("8", EITHER) } },
	{ 1, { XDP("9", EITHER) } },
	{ 2, { XDP("1", EITHER), XDP("2", EITHER) } },
	{ 2, { XDP("1", EITHER), XDP("1", EITHER) } },
#elif defined(UPROBE_OBJECTS)
	{ 1, { UPROBE(AT("uprobe", "f"), UPROBE, "f", 0, 20) } },
	{ 1, { UPROBE(AT("uprobe.s", "fn+0x1f"), UPROBE, "fn", 31, 1) } },
	{ 1, { UPROBE(AT("uprobe", "0x1f"), UPROBE, "0x1f", 0,
		      UPATCH_BUILD_ID_MAX) } },
	{ 1, { UPROBE(AT("uretprobe.s", "f"), URETPROBE, "f", 0, 20) } },
	{ 1, { UPROBE(AT("uretprobe", "0X2"), URETPROBE, "0X2", 0, 20) } },
	{ 1, { GLOB(AT("uprobe.multi.s", "f*"), UPROBE_MULTI, "f*",
		    UPATCH_BUILD_ID_MAX) } },
	{ 1, { GLOB(AT("uretprobe.multi", "?"), URETPROBE_MULTI, "?", 1) } },
	{ 1, { GLOB(AT("uprobe.multi", A127), UPROBE_MULTI, A127, 20) } },
	{ 2, { GLOB(AT("uprobe.multi", "f*"), UPROBE_MULTI, "f*", 20),
	       UPROBE(AT("uprobe", "g+9"), UPROBE, "g", 9, 3) } },
	{ 2, { PLAIN("fentry/f", RAW_TRACEPOINT),
	       UPROBE(AT("uretprobe", "g"), URETPROBE, "g", 0, 20) } },
	{ 2, { UPROBE(AT("uprobe.s", "0x8"), UPROBE, "0x8", 0, 2),
	       PLAIN("tp_btf/f", RAW_TRACEPOINT) } },
	{ 1, { REFUSE(AT("uretprobe", "f+1")) } },
	{ 1, { REFUSE(AT("uprobe", "0xg")) } },
	{ 1, { REFUSE(AT("uprobe.multi", "f,g")) } },
	{ 1, { REFUSE(AT("uretprobe.multi.s", "f|g")) } },
	{ 1, { REFUSE(AT("uprobe.multi", A127 "a")) } },
	{ 1, { REFUSE(AT("uprobe.multi", "")) } },
	{ 1, { REFUSE("uprobe/x:f") } },
	{ 1, { REFUSE("uretprobe/" UPROBE_PATH) } },
	{ 1, { REFUSE("uprobe") } },
	{ 1, { NO_BINARY(AT("uprobe.multi", "f"), UPROBE_MULTI) } },
	{ 1, { NO_BINARY(AT("uprobe", "f"), UPROBE) } },
#else
	{ 0 },
	{ 1, { PLAIN("fentry/f", RAW_TRACEPOINT) } },
	{ 1, { PLAIN("?lsm.s/f", RAW_TRACEPOINT) } },
	{ 1, { PLAIN("fmod_ret/f", FMOD_RET) } },
	{ 1, { PLAIN("fmod_ret.s/f", FMOD_RET) } },
	{ 1, { PLAIN("netfilter", NETFILTER_IPV6_PRE_ROUTING) } },
	{ 2, { PLAIN("cgroup_skb/ingress", CGROUP_SKB_INGRESS),
	       PLAIN("cgroup_skb/egress", CGROUP_SKB_EGRESS) } },
	{ 1, { TEST_RUN("t", TAKEN) } },
	{ 2, { TEST_RUN("t", TAKEN), TEST_RUN("u", REFUSED) } },
	{ 1, { { "syscall", "p", TAIL_NONE, REFUSED } } },
	{ 1, { SERIALIZER("m", TAIL_NAME, EITHER) } },
	{ 1, { SERIALIZER(A15, TAIL_NONE, EITHER) } },
	{ 2, { SERIALIZER("a", TAIL_NONE, EITHER),
	       SERIALIZER("b", TAIL_NONE, EITHER) } },
	{ 2, { SERIALIZER("a", TAIL_NONE, EITHER),
	       SERIALIZER("a", TAIL_NONE, REFUSED) } },
	{ 1, { SERIALIZER(A15 "a", TAIL_NONE, REFUSED) } },
	{ 1, { SERIALIZER(SERIAL_MAP_NAME, TAIL_NONE, REFUSED) } },
	{ 1, { { "fentry/f", SERIALIZER_PREFIX "m", TAIL_NONE, REFUSED } } },
	{ 1, { REFUSE("fmod_ret") } },
	{ 1, { REFUSE("cgroup/skb") } },
	{ 1, { REFUSE("sk_skb") } },
	{ 1, { REFUSE("socket") } },
	{ 1, { REFUSE("tracepoint/f") } },
#endif
};

#define NR_PROGS	(objects[LEN].nr_progs)

struct bpf_program {
	__u32	idx;
	char	name[TEXT_MAX];
	char	sec[TEXT_MAX];
};

struct bpf_map {
	__u32	idx;
	char	name[TEXT_MAX];
	__u32	type;
	__u32	key_size;
	__u32	value_size;
	__u32	max_entries;
};

/* The programs, two maps of any name and the serializers' output map. */
struct bpf_object {
	struct bpf_program	progs[NR_PROGS_MAX];
	struct bpf_map		maps[3];
};

/* What the ELF resolver found for each uprobe, in the order it was asked. */
static struct elf_target resolved[NR_PROGS_MAX];
static __u64 resolved_offsets[NR_PROGS_MAX][NR_OFFSETS];
static __u32 nr_resolved;

struct bpf_program *bpf_object__next_program(const struct bpf_object *obj,
					     struct bpf_program *prev)
{
	__u32 idx = prev ? prev->idx + 1 : 0;

	return idx < NR_PROGS ? (struct bpf_program *)&obj->progs[idx] : NULL;
}

const char *bpf_program__name(const struct bpf_program *prog)
{
	return prog->name;
}

const char *bpf_program__section_name(const struct bpf_program *prog)
{
	return prog->sec;
}

struct bpf_map *bpf_object__next_map(const struct bpf_object *obj,
				     const struct bpf_map *prev)
{
	__u32 idx = prev ? prev->idx + 1 : 0;

	return idx < ARRAY_SIZE(obj->maps) ?
	       (struct bpf_map *)&obj->maps[idx] : NULL;
}

const char *bpf_map__name(const struct bpf_map *map)
{
	return map->name;
}

enum bpf_map_type bpf_map__type(const struct bpf_map *map)
{
	return map->type;
}

__u32 bpf_map__key_size(const struct bpf_map *map)
{
	return map->key_size;
}

__u32 bpf_map__value_size(const struct bpf_map *map)
{
	return map->value_size;
}

__u32 bpf_map__max_entries(const struct bpf_map *map)
{
	return map->max_entries;
}

void pr_err(const char *fmt, ...)
{
}

/* CBMC models no qsort(); the writer sorts at most two names here. */
void qsort(void *base, size_t nmemb, size_t size,
	   int (*compare)(const void *, const void *))
{
	char **names = base;
	char *first;

	__CPROVER_assert(nmemb <= 2 && size == sizeof(*names),
			 "at most two names to sort");
	if (nmemb == 2 && compare(&names[0], &names[1]) > 0) {
		first = names[0];
		names[0] = names[1];
		names[1] = first;
	}
}

char *strerror(int err)
{
	return "error";
}

static const struct shape *uprobe_shape(__u32 nth)
{
	__u32 i;

	for (i = 0; i < NR_PROGS; i++)
		if (kind_has_uprobe_target(objects[LEN].progs[i].kind) &&
		    !nth--)
			return &objects[LEN].progs[i];
	return NULL;
}

/*
 * What util/elf_target.c gives: an errno, or a build ID of 1 to 64 bytes,
 * here of the length the shape names, with one file offset for a function
 * and strictly rising ones for a glob, here NR_OFFSETS of them.
 */
static int resolve(struct elf_target *out, __u32 nr_offsets)
{
	const struct shape *shape = uprobe_shape(nr_resolved);
	__u8 build_id[UPATCH_BUILD_ID_MAX];
	__u64 offsets[NR_OFFSETS];
	__u32 i;
	int err;

	__CPROVER_assert(shape, "resolved for a uprobe only");
	memset(out, 0, sizeof(*out));
	if (shape->no_binary) {
		__CPROVER_assume(err < 0 && err >= -4095);
		return err;
	}
	out->offsets = xcalloc(nr_offsets, sizeof(*out->offsets));
	if (!out->offsets)
		return -ENOMEM;
	for (i = 0; i < nr_offsets; i++) {
		__CPROVER_assume(!i || offsets[i - 1] < offsets[i]);
		out->offsets[i] = offsets[i];
		resolved_offsets[nr_resolved][i] = offsets[i];
	}
	out->offsets_cap = nr_offsets;
	out->nr_offsets = nr_offsets;
	for (i = 0; i < shape->build_id_len; i++)
		out->build_id[i] = build_id[i];
	out->build_id_len = shape->build_id_len;
	resolved[nr_resolved++] = *out;
	return 0;
}

int elf_target_resolve(const char *path, const char *pattern,
		       struct elf_target *out)
{
	if (!path || path[0] != '/' || !pattern || !pattern[0] || !out)
		return -EINVAL;
	return resolve(out, NR_OFFSETS);
}

int elf_target_resolve_func(const char *path, const char *func, __u64 offset,
			    struct elf_target *out)
{
	if (!path || path[0] != '/' || (func && !func[0]) || !out)
		return -EINVAL;
	return resolve(out, 1);
}

void elf_target_free(struct elf_target *target)
{
	xfree(target->offsets,
	      (size_t)target->offsets_cap * sizeof(*target->offsets));
	memset(target, 0, sizeof(*target));
}

/* prefix and then, where it goes there, any TAIL bytes and a NUL. */
static void text(char *dst, const char *prefix, bool tail)
{
	size_t n = strlen(prefix), i;
	char behind[TAIL];

	for (i = 0; i < n; i++)
		dst[i] = prefix[i];
	for (i = 0; tail && i < TAIL; i++)
		dst[n++] = behind[i];
	dst[n] = '\0';
}

/*
 * The table of the format: a header, the entries, the uprobe targets and
 * the kprobe multi targets.
 */
static __u32 table_len(void)
{
	__u32 len = 16 + 160 * NR_PROGS, nr_uprobes = 0, nr_kprobes = 0, i;

	for (i = 0; i < NR_PROGS; i++) {
		const struct shape *shape = &objects[LEN].progs[i];

		if (kind_is_kprobe_multi(shape->kind)) {
			len += 12 + strlen(shape->syms) + 1;
			nr_kprobes++;
			continue;
		}
		if (!kind_has_uprobe_target(shape->kind))
			continue;
		len += 16 + strlen(UPROBE_PATH) + shape->build_id_len +
		       8 * (kind_is_uprobe_multi(shape->kind) ? NR_OFFSETS : 1);
		nr_uprobes++;
	}
	return len + (nr_uprobes ? 16 : 0) + (nr_kprobes ? 16 : 0);
}

#if defined(KPROBE_OBJECTS) && LEN == 14
static void *metadata_malloc(size_t size)
{
	__CPROVER_assert(size == 2, "the mixed table's symbol buffer has two bytes");
	return xmalloc(2);
}

static void *metadata_calloc(size_t nmemb, size_t size)
{
	if (nmemb == 2 && size == sizeof(struct prog_spec))
		return xcalloc(2, sizeof(struct prog_spec));
	if (nmemb == 1 && size == sizeof(__u64))
		return xcalloc(1, sizeof(__u64));
	__CPROVER_assert(false, "the mixed table's program and target array extents");
	return NULL;
}

static char *metadata_strndup(const char *s, size_t len)
{
	char *copy;

	__CPROVER_assert(len == 2 && strnlen(s, len) == 2,
			 "the mixed table's path has two non-NUL bytes");
	copy = xmalloc(3);
	if (!copy)
		return NULL;
	copy[0] = s[0];
	copy[1] = s[1];
	copy[2] = '\0';
	return copy;
}

/* A symbolic heap extent makes the mixed table exceed CI's memory cap. */
static void *metadata_realloc(void *ptr, size_t old_nmemb, size_t new_nmemb,
			      size_t size)
{
	const size_t base_len = sizeof(struct upatch_prog_metadata) +
		NR_PROGS * sizeof(struct upatch_prog_entry);
	const size_t grown_len = table_len();

	__CPROVER_assert(old_nmemb == base_len && new_nmemb == grown_len && size == 1,
			 "the mixed table grows to its exact extent");
	return xreallocarray(ptr, base_len, grown_len, 1);
}
#endif

#if (defined(KPROBE_OBJECTS) && LEN == 14) || defined(XDP_OBJECTS)
/*
 * Re-store only a value proved equal, so the reader's attach branches and
 * allocation sizes depend on constants rather than reads of heap bytes.
 */
static void constant_u32(void *field, __u32 value)
{
	__le32 encoded = cpu_to_le32(value);

	__CPROVER_assert(get_le32(field) == value, "the writer's structural field");
	memcpy(field, &encoded, sizeof(encoded));
}

static __u8 *constant_uprobe_block(__u8 *cursor, __u32 nr_targets)
{
	struct upatch_uprobe_targets header;
	__u32 i;

	memcpy(&header, cursor, sizeof(header));
	constant_u32(&header.magic, UPATCH_UPROBE_TARGET_MAGIC);
	constant_u32(&header.version, UPATCH_UPROBE_TARGET_VERSION);
	constant_u32(&header.nr_targets, nr_targets);
	constant_u32(&header.reserved, 0);
	memcpy(cursor, &header, sizeof(header));
	cursor += sizeof(header);
	for (i = 0; i < NR_PROGS; i++) {
		const struct shape *shape = &objects[LEN].progs[i];
		struct upatch_uprobe_target record;
		__u32 nr_offsets;

		if (!kind_has_uprobe_target(shape->kind))
			continue;
		nr_offsets = kind_is_uprobe_multi(shape->kind) ? NR_OFFSETS : 1;
		memcpy(&record, cursor, sizeof(record));
		constant_u32(&record.prog_idx, i);
		constant_u32(&record.path_len, strlen(UPROBE_PATH));
		constant_u32(&record.build_id_len, shape->build_id_len);
		constant_u32(&record.nr_offsets, nr_offsets);
		memcpy(cursor, &record, sizeof(record));
		cursor += sizeof(record) + strlen(UPROBE_PATH) +
			  shape->build_id_len + nr_offsets * sizeof(__le64);
	}
	return cursor;
}

static __u8 *constant_kprobe_block(__u8 *cursor, __u32 nr_targets)
{
	struct upatch_kprobe_targets header;
	__u32 i;

	memcpy(&header, cursor, sizeof(header));
	constant_u32(&header.magic, UPATCH_KPROBE_TARGET_MAGIC);
	constant_u32(&header.version, UPATCH_KPROBE_TARGET_VERSION);
	constant_u32(&header.nr_targets, nr_targets);
	constant_u32(&header.reserved, 0);
	memcpy(cursor, &header, sizeof(header));
	cursor += sizeof(header);
	for (i = 0; i < NR_PROGS; i++) {
		const struct shape *shape = &objects[LEN].progs[i];
		struct upatch_kprobe_target record;
		__u32 syms_len;

		if (!kind_is_kprobe_multi(shape->kind))
			continue;
		syms_len = strlen(shape->syms) + 1;
		memcpy(&record, cursor, sizeof(record));
		constant_u32(&record.prog_idx, i);
		constant_u32(&record.nr_syms, strchr(shape->syms, ',') ? 2 : 1);
		constant_u32(&record.syms_len, syms_len);
		memcpy(cursor, &record, sizeof(record));
		cursor += sizeof(record) + syms_len;
	}
	return cursor;
}

static void constant_metadata(void *metadata, __u32 nr_maps, __u32 len)
{
	struct upatch_prog_metadata *md = metadata;
	__u8 *cursor = (__u8 *)metadata + sizeof(*md) +
		NR_PROGS * sizeof(struct upatch_prog_entry);
	__u32 nr_uprobes = 0, nr_kprobes = 0, i;

	constant_u32(&md->magic, UPATCH_PROG_MAGIC);
	constant_u32(&md->version, UPATCH_PROG_VERSION);
	constant_u32(&md->nr_progs, NR_PROGS);
	constant_u32(&md->nr_maps, nr_maps);
	for (i = 0; i < NR_PROGS; i++) {
		const struct shape *shape = &objects[LEN].progs[i];

		constant_u32(&md->progs[i].role, shape->role);
		constant_u32(&md->progs[i].kind, shape->kind);
		nr_uprobes += kind_has_uprobe_target(shape->kind);
		nr_kprobes += kind_is_kprobe_multi(shape->kind);
	}
	if (nr_uprobes)
		cursor = constant_uprobe_block(cursor, nr_uprobes);
	if (nr_kprobes)
		cursor = constant_kprobe_block(cursor, nr_kprobes);
	__CPROVER_assert(cursor == (__u8 *)metadata + len, "the blocks fill the metadata");
}

#endif

static void uprobe_target(const struct prog_spec *s,
			  const struct shape *shape, __u32 nth)
{
	__u32 i;

	__CPROVER_assert(!strcmp(s->uprobe_path, UPROBE_PATH),
			 "the path the section names");
	__CPROVER_assert(s->build_id_len == shape->build_id_len &&
			 !memcmp(s->build_id, resolved[nth].build_id,
				 UPATCH_BUILD_ID_MAX),
			 "the build ID of the binary");
	__CPROVER_assert(s->nr_uprobe_offsets == resolved[nth].nr_offsets,
			 "as many offsets as resolved");
	for (i = 0; i < s->nr_uprobe_offsets; i++)
		__CPROVER_assert(s->uprobe_offsets[i] ==
				 resolved_offsets[nth][i],
				 "the offsets resolved");
	__CPROVER_assert(kind_is_uprobe_multi(s->kind) ||
			 s->uprobe_offsets[0] <= UINT32_MAX,
			 "a function below 4 GiB");
}

/* The names of syms, in its order, each NUL-terminated in the record. */
static void kprobe_syms(const struct prog_spec *s, const char *syms)
{
	const char *want = syms, *rest;
	__u32 i;

	for (i = 0; i < s->nr_kprobe_syms; i++) {
		rest = str_after_prefix(want, s->kprobe_syms[i]);
		__CPROVER_assert(*want && rest && (*rest == ',' || !*rest),
				 "the names the section lists, sorted");
		want = rest + (*rest == ',');
	}
	__CPROVER_assert(s->nr_kprobe_syms && !*want, "every name the section lists");
}

static __u32 decimal(const char *digits)
{
	__u32 value = 0;

	for (; *digits; digits++)
		value = value * 10 + (__u32)(*digits - '0');
	return value;
}

static void read_back(const struct prog_spec *s, const char *sec,
		      const char *name, const struct shape *shape,
		      __u32 nth_uprobe)
{
	__CPROVER_assert(s->role == shape->role && s->kind == shape->kind,
			 "the role and kind of the section");
	if (s->role == UPATCH_PROG_ROLE_SERIALIZER)
		__CPROVER_assert(!strcmp(s->map, name +
					 strlen(SERIALIZER_PREFIX)),
				 "the map the serializer names");
	else if (s->kind == UPATCH_ATTACH_XDP)
		__CPROVER_assert(s->device_classes ==
				 decimal(sec + strlen("xdp/")),
				 "the device classes the section names");
	else
		__CPROVER_assert(!strcmp(s->target, shape->target) &&
				 s->offset == shape->offset,
				 "the target and offset the section names");
	if (kind_has_uprobe_target(s->kind))
		uprobe_target(s, shape, nth_uprobe);
	if (kind_is_kprobe_multi(s->kind))
		kprobe_syms(s, shape->syms);
}

void harness(void)
{
	__u32 nr_maps, len = 0xdeadbeef, classes = 0, nr_uprobes = 0, i;
	const struct shape *shape = objects[LEN].progs;
	struct prog_spec *specs;
	__u32 verdict = TAKEN;
	struct bpf_object obj;
	void *md = (void *)1;
	bool has_output;
	int ret;

	for (i = 0; i < NR_PROGS; i++) {
		obj.progs[i].idx = i;
		text(obj.progs[i].sec, shape[i].sec,
		     shape[i].tail == TAIL_SEC);
		text(obj.progs[i].name, shape[i].name,
		     shape[i].tail == TAIL_NAME);
		verdict = max(verdict, shape[i].verdict);
	}
	for (i = 0; i < ARRAY_SIZE(obj.maps); i++) {
		obj.maps[i].idx = i;
		__CPROVER_assume(!obj.maps[i].name[UPATCH_PROG_MAP_MAX]);
	}
	text(obj.maps[2].name, SERIAL_MAP_NAME, false);
	if (!has_output)
		obj.maps[2].name[0] = '\0';
	ret = build_prog_metadata(&obj, nr_maps, NR_PROGS, &md, &len);
	__CPROVER_assert(verdict != TAKEN || !ret, "taken");
	__CPROVER_assert(verdict != REFUSED || ret, "refused");
	if (ret) {
		__CPROVER_assert(ret < 0 && !md && !len,
				 "an error and no metadata");
		return;
	}
	__CPROVER_assert(md && len == table_len(),
			 "a table of the length the format gives");
	/* As just shown, so that CBMC takes both for the constants they are. */
	__CPROVER_assume(md && len == table_len());
#if (defined(KPROBE_OBJECTS) && LEN == 14) || defined(XDP_OBJECTS)
	constant_metadata(md, nr_maps, len);
#endif
	ret = prog_specs_parse(md, len, nr_maps, NR_PROGS, &specs);
	__CPROVER_assert(!ret, "the reader takes what the writer wrote");
	if (ret)
		return;
	for (i = 0; i < NR_PROGS; i++) {
		read_back(&specs[i], obj.progs[i].sec, obj.progs[i].name,
			  &shape[i], nr_uprobes);
		nr_uprobes += kind_has_uprobe_target(shape[i].kind);
		__CPROVER_assert(!(classes & specs[i].device_classes),
				 "no device class for two programs");
		classes |= specs[i].device_classes;
	}
	prog_specs_free(specs, NR_PROGS);
	xfree(md, len);
}
