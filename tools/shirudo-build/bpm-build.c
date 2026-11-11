// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * `bpm build`: a Beefile describes ordinary files and upatches, each
 * upatch is compiled and signed in-process, and the result is a
 * deterministic gzip-compressed ustar archive. Also the `bpm` entry.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include "bpm.h"
#include "bpm_oci.h"
#include "bpm_package.h"
#include "compile.h"
#include "crypto.h"
#include "io.h"
#include "json.h"
#include "log.h"
#include "hex.h"
#include "malloc.h"
#include "timefmt.h"
#include "package.h"
#include "paths.h"
#include "upatch.h"
#include "version.h"
#include "vmlinux.h"

#ifndef VMLINUX_PATH
#define VMLINUX_PATH "/usr/local/share/shirudo/vmlinux.h"
#endif

#define BPM_BUILD_MAX_FILE (256u * 1024u * 1024u)
#define BPM_BUILD_MAX_JSON (256u * 1024u)
#define BPM_BUILD_MAX_VALUE 1024

static char *build_trim(char *s)
{
	char *end;

	while (isspace((__u8)*s))
		s++;
	end = s + strlen(s);
	while (end > s && isspace((__u8)end[-1]))
		*--end = '\0';
	return s;
}

static void build_strip_comment(char *s)
{
	bool basic = false, literal = false, escaped = false;

	for (; *s; s++) {
		if (escaped) {
			escaped = false;
			continue;
		}
		if (basic && *s == '\\') {
			escaped = true;
			continue;
		}
		if (!literal && *s == '"') {
			basic = !basic;
			continue;
		}
		if (!basic && *s == '\'') {
			literal = !literal;
			continue;
		}
		if (!basic && !literal && *s == '#') {
			*s = '\0';
			return;
		}
	}
}

static int build_read_file(const char *path, __u8 **out, size_t *len,
			   size_t max)
{
	struct stat st;
	__u8 *body;
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) || st.st_size < 0 || (uintmax_t)st.st_size > max) {
		int ret = errno ? -errno : -E2BIG;

		close(fd);
		return ret;
	}
	body = xmalloc((size_t)st.st_size + 1);
	if (!body) {
		close(fd);
		return -ENOMEM;
	}
	n = 0;
	while ((size_t)n < (size_t)st.st_size) {
		ssize_t got = read(fd, body + n, (size_t)st.st_size - (size_t)n);

		if (got <= 0) {
			int ret = got < 0 ? -errno : -EIO;

			close(fd);
			xfree(body, (size_t)st.st_size + 1);
			return ret;
		}
		n += got;
	}
	close(fd);
	body[n] = '\0';
	*out = body;
	*len = (size_t)n;
	return 0;
}

static int build_parse_string(const char *value, char *out, size_t cap)
{
	const char *p = value;
	char quote;
	size_t n = 0;

	while (isspace((__u8)*p))
		p++;
	if (*p != '"' && *p != '\'')
		return -EINVAL;
	quote = *p++;
	while (*p && *p != quote) {
		__u8 c = (__u8)*p++;

		if (c == '\\' && quote == '"') {
			c = (__u8)*p++;
			switch (c) {
			case 'n':
				c = '\n';
				break;
			case 'r':
				c = '\r';
				break;
			case 't':
				c = '\t';
				break;
			case '\\':
			case '"':
				break;
			default:
				return -EINVAL;
			}
		}
		if (n + 1 >= cap)
			return -ENAMETOOLONG;
		out[n++] = (char)c;
	}
	if (*p != quote)
		return -EINVAL;
	p++;
	while (isspace((__u8)*p))
		p++;
	if (*p)
		return -EINVAL;
	out[n] = '\0';
	return 0;
}

static int build_parse_value(const char *value, char *out, size_t cap,
			     bool array_ok)
{
	const char *p = value;

	while (isspace((__u8)*p))
		p++;
	if (array_ok && *p == '[') {
		const char *end = strrchr(p, ']');

		if (!end)
			return -EINVAL;
		while (isspace((__u8)end[1]))
			end++;
		return end[1] ? -EINVAL : 0;
	}
	return build_parse_string(value, out, cap);
}

/*
 * A TOML array of strings: ["a", 'b']. Elements land in out[], at most max
 * of them; an empty array is rejected since every selector list is a
 * non-empty set.
 */
static int build_parse_string_array(const char *value,
				    char out[][TREE_STRING_MAX],
				    int max, int *n)
{
	char item[BPM_BUILD_MAX_VALUE];
	const char *p = value;
	int count = 0;

	while (isspace((__u8)*p))
		p++;
	if (*p++ != '[')
		return -EINVAL;
	for (;;) {
		const char *start, *end;
		char quote;

		while (isspace((__u8)*p))
			p++;
		if (*p == ']')
			break;
		if (*p != '"' && *p != '\'')
			return -EINVAL;
		quote = *p;
		start = p++;
		while (*p && *p != quote) {
			if (quote == '"' && *p == '\\' && p[1])
				p++;
			p++;
		}
		if (*p != quote)
			return -EINVAL;
		end = ++p;
		if ((size_t)(end - start) >= sizeof(item))
			return -ENAMETOOLONG;
		memcpy(item, start, (size_t)(end - start));
		item[end - start] = '\0';
		if (count >= max)
			return -E2BIG;
		if (build_parse_string(item, out[count], TREE_STRING_MAX))
			return -EINVAL;
		count++;
		while (isspace((__u8)*p))
			p++;
		if (*p == ',') {
			p++;
			continue;
		}
		if (*p != ']')
			return -EINVAL;
	}
	p++;
	while (isspace((__u8)*p))
		p++;
	if (*p || !count)
		return -EINVAL;
	*n = count;
	return 0;
}

static int build_parse_selector_kv(const char *key, const char *value,
				   struct tree_selector_kv **kvs,
				   int max, int *n)
{
	struct tree_selector_kv *kv;
	size_t key_len = strlen(key);
	int ret;

	if (key_len >= 2 && (key[0] == '"' || key[0] == '\'') &&
	    key[key_len - 1] == key[0]) {
		key++;
		key_len -= 2;
	}
	if (!key_len || key_len >= TREE_STRING_MAX)
		return -EINVAL;
	for (int i = 0; i < *n; i++) {
		if (strlen((*kvs)[i].key) == key_len &&
		    !strncmp((*kvs)[i].key, key, key_len))
			return -EEXIST;
	}
	ret = tree_selector_kv_add(kvs, n, max, &kv);
	if (ret)
		return ret;
	memcpy(kv->key, key, key_len);
	kv->key[key_len] = '\0';
	if (build_parse_string_array(value, kv->values,
				     TREE_MAX_SELECTOR_VALUES,
				     &kv->n_values))
		return -EINVAL;
	return 0;
}

static bool build_name_ok(const char *s)
{
	const __u8 *p = (const __u8 *)s;

	if (!s || !*s || !isalnum((__u8)s[0]) || strlen(s) >= 128)
		return false;
	for (; *p; p++) {
		if (!(isalnum(*p) || *p == '.' || *p == '_' || *p == '-'))
			return false;
	}
	return true;
}

/* A version the target orders as the operator means it. */
static bool build_version_ok(const char *s)
{
	return s && strlen(s) < 128 && bpm_semver_valid(s);
}

static int build_default_targets(struct bpm_build_upatch *u)
{
	char base[PATH_MAX];
	char *slash;

	strscpy(base, u->source, sizeof(base));
	slash = strrchr(base, '/');
	if (slash)
		memmove(base, slash + 1, strlen(slash + 1) + 1);
	if (strlen(base) > 6 && !strcmp(base + strlen(base) - 6, ".bpf.c")) {
		base[strlen(base) - 6] = '\0';
	} else if (strlen(base) > 6 &&
		   !strcmp(base + strlen(base) - 6, ".bpf.o")) {
		base[strlen(base) - 6] = '\0';
	} else {
		slash = strrchr(base, '.');
		if (slash)
			*slash = '\0';
	}
	if (!*base)
		return -EINVAL;
	if (!u->load_target[0] &&
	    strsprintf(u->load_target, sizeof(u->load_target),
		       "upatches/%s.upatch", base) < 0)
		return -ENAMETOOLONG;
	if (!u->unload_target[0] && strsprintf(u->unload_target,
					       sizeof(u->unload_target), "upatches/%s.unload.upatch",
					       base) < 0)
		return -ENAMETOOLONG;
	return 0;
}

static int build_target_ok(const char *target);

/* A TOML bare key, or with dots a dotted one of bare keys alone. */
static bool build_bare_key(const char *key, bool dots)
{
	bool part = false;

	for (; *key; key++) {
		if (isalnum((__u8)*key) || *key == '_' || *key == '-')
			part = true;
		else if (dots && *key == '.' && part)
			part = false;
		else
			return false;
	}
	return part;
}

static int build_parse_spec(struct bpm_build_spec *spec, char *body)
{
	struct bpm_build_upatch *upatch = NULL, *tree_owner = NULL;
	struct bpm_build_policy *policy = NULL;
	struct bpm_build_rodata *rodata = NULL;
	struct bpm_build_file *file = NULL;
	struct tree_selector *sel = NULL;
	bool tree_section = false;
	char *save = NULL, *line;
	char section[48] = {};

	for (line = strtok_r(body, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char *s, *eq, *key, *value;

		build_strip_comment(line);
		s = build_trim(line);
		if (!*s)
			continue;
		if (s[0] == '[') {
			bool array = s[1] == '[';
			const char *start = s + (array ? 2 : 1);
			const char *close = array ? "]]" : "]";
			const char *end = strstr(start, close);

			if (!end || end[strlen(close)])
				return -EINVAL;
			if ((size_t)(end - start) >= sizeof(section))
				return -ENAMETOOLONG;
			memcpy(section, start, (size_t)(end - start));
			section[end - start] = '\0';
			s = build_trim(section);
			if (s != section)
				memmove(section, s, strlen(s) + 1);
			/*
			 * TOML spells [upatches.tree] with blanks or quotes
			 * around its parts too: such a header could name a
			 * tree table this reader would pass over.
			 */
			if (!build_bare_key(section, true))
				return -EINVAL;
			file = NULL;
			upatch = NULL;
			rodata = NULL;
			policy = NULL;
			tree_section = !array &&
				(!strcmp(section, "upatches.tree") ||
				 !strcmp(section, "upatches.tree.selector") ||
				 !strcmp(section, "upatches.tree.selector.kconfig") ||
				 !strcmp(section, "upatches.tree.selector.labels"));
			if (array && !strcmp(section, "files")) {
				if (spec->n_files >= BPM_BUILD_MAX_ENTRIES)
					return -E2BIG;
				file = &spec->files[spec->n_files++];
				tree_owner = NULL;
			} else if (array && !strcmp(section, "upatches")) {
				if (spec->n_upatches >= BPM_BUILD_MAX_ENTRIES)
					return -E2BIG;
				upatch = &spec->upatches[spec->n_upatches++];
				tree_owner = upatch;
			} else if (array && !strcmp(section, "upatches.rodata")) {
				if (!tree_owner ||
				    tree_owner->n_rodata >= BPM_BUILD_MAX_RODATA)
					return -E2BIG;
				if (!tree_owner->rodata) {
					tree_owner->rodata = xcalloc(BPM_BUILD_MAX_RODATA,
								     sizeof(*tree_owner->rodata));
					if (!tree_owner->rodata)
						return -ENOMEM;
				}
				rodata = &tree_owner->rodata[tree_owner->n_rodata++];
			} else if (array && !strcmp(section, "upatches.policy")) {
				if (!tree_owner ||
				    tree_owner->n_policies >= BPM_BUILD_MAX_POLICIES)
					return -E2BIG;
				if (!tree_owner->policies) {
					tree_owner->policies =
						xcalloc(BPM_BUILD_MAX_POLICIES,
							sizeof(*tree_owner->policies));
					if (!tree_owner->policies)
						return -ENOMEM;
				}
				policy = &tree_owner->policies[tree_owner->n_policies++];
			} else if (array) {
				return -EINVAL;
			} else if (tree_section) {
				/* The tree tables qualify the preceding [[upatches]]. */
				if (!tree_owner)
					return -EINVAL;
				tree_owner->tree.present = true;
				if (!tree_owner->tree.selector) {
					tree_owner->tree.selector =
						xmalloc(sizeof(*tree_owner->tree.selector));
					if (!tree_owner->tree.selector)
						return -ENOMEM;
				}
				sel = tree_owner->tree.selector;
			} else if (!strncmp(section, "upatches.tree",
					    strlen("upatches.tree"))) {
				/*
				 * A selector the builder cannot read would
				 * widen the rollout.
				 */
				return -EINVAL;
			} else {
				tree_owner = NULL;
			}
			continue;
		}
		eq = strchr(s, '=');
		if (!eq)
			return -EINVAL;
		*eq = '\0';
		key = build_trim(s);
		value = build_trim(eq + 1);
		if (!strcmp(section, "package")) {
			char ignored[BPM_BUILD_MAX_VALUE];

			if (!strcmp(key, "name")) {
				if (build_parse_value(value, spec->name, sizeof(spec->name), false))
					return -EINVAL;
			} else if (!strcmp(key, "description") || !strcmp(key, "license")) {
				if (build_parse_value(value, ignored, sizeof(ignored), false))
					return -EINVAL;
			} else if (!strcmp(key, "authors")) {
				if (build_parse_value(value, ignored, sizeof(ignored), true))
					return -EINVAL;
			} else {
				return -EINVAL;
			}
		} else if (file) {
			if (!strcmp(key, "source")) {
				if (build_parse_string(value, file->source, sizeof(file->source)))
					return -EINVAL;
			} else if (!strcmp(key, "target")) {
				if (build_parse_string(value, file->target, sizeof(file->target)))
					return -EINVAL;
			} else {
				return -EINVAL;
			}
		} else if (upatch) {
			char *dst = NULL;
			size_t cap = 0;

			if (!strcmp(key, "source")) {
				dst = upatch->source;
				cap = sizeof(upatch->source);
			} else if (!strcmp(key, "type")) {
				dst = upatch->type;
				cap = sizeof(upatch->type);
			} else if (!strcmp(key, "load_target")) {
				dst = upatch->load_target;
				cap = sizeof(upatch->load_target);
			} else if (!strcmp(key, "unload_target")) {
				dst = upatch->unload_target;
				cap = sizeof(upatch->unload_target);
			} else {
				return -EINVAL;
			}
			if (build_parse_string(value, dst, cap))
				return -EINVAL;
		} else if (policy) {
			if (!strcmp(key, "id")) {
				if (build_parse_string(value, policy->id,
						       sizeof(policy->id)))
					return -EINVAL;
			} else if (!strcmp(key, "bit")) {
				const char *number = value;
				size_t len = strlen(value);

				if (len > 2 && value[0] == '0' &&
				    (value[1] == 'x' || value[1] == 'X')) {
					number += 2;
					len -= 2;
				}
				if (!len || parse_x64(number, len, UINT64_MAX, &policy->bit) ||
				    !policy->bit ||
				    (policy->bit & (policy->bit - 1)))
					return -EINVAL;
			} else if (!strcmp(key, "paths")) {
				if (policy->n_paths ||
				    build_parse_string_array(value, policy->paths,
							     ARRAY_SIZE(policy->paths),
							     &policy->n_paths))
					return -EINVAL;
			} else {
				return -EINVAL;
			}
		} else if (rodata) {
			if (!strcmp(key, "symbol")) {
				if (build_parse_string(value, rodata->symbol,
						       sizeof(rodata->symbol)))
					return -EINVAL;
			} else if (!strcmp(key, "input")) {
				if (build_parse_string(value, rodata->input,
						       sizeof(rodata->input)))
					return -EINVAL;
			} else if (!strcmp(key, "generator")) {
				if (rodata->n_generator ||
				    build_parse_string_array(value, rodata->generator,
							     BPM_BUILD_MAX_COMMAND_ARGS,
							     &rodata->n_generator))
					return -EINVAL;
			} else if (!strcmp(key, "update")) {
				if (rodata->n_update ||
				    build_parse_string_array(value, rodata->update,
							     BPM_BUILD_MAX_COMMAND_ARGS,
							     &rodata->n_update))
					return -EINVAL;
			} else {
				return -EINVAL;
			}
		} else if (tree_section && !strcmp(section, "upatches.tree")) {
			struct bpm_build_tree *t = &tree_owner->tree;
			char *dst = NULL;
			size_t cap = 0;

			/*
			 * Unknown tree keys are additive metadata for newer
			 * publishers, but a dotted key or an inline table
			 * would be the selector spelled another way.
			 */
			if (!build_bare_key(key, false) || !strcmp(key, "selector"))
				return -EINVAL;
			if (!strcmp(key, "id")) {
				dst = t->id;
				cap = sizeof(t->id);
			} else if (!strcmp(key, "load_artifact")) {
				dst = t->load_artifact;
				cap = sizeof(t->load_artifact);
			} else if (!strcmp(key, "unload_artifact")) {
				dst = t->unload_artifact;
				cap = sizeof(t->unload_artifact);
			} else {
				continue;
			}
			if (build_parse_string(value, dst, cap))
				return -EINVAL;
		} else if (tree_section && !strcmp(section, "upatches.tree.selector")) {
			char (*dst)[TREE_STRING_MAX];
			int *n;

			if (!strcmp(key, "kernel_release_prefix")) {
				dst = sel->kernel_release_prefix;
				n = &sel->n_kernel_release_prefix;
			} else if (!strcmp(key, "kernel_build_id")) {
				dst = sel->kernel_build_id;
				n = &sel->n_kernel_build_id;
			} else if (!strcmp(key, "architecture")) {
				dst = sel->architecture;
				n = &sel->n_architecture;
			} else {
				return -EINVAL;
			}
			if (*n || build_parse_string_array(value, dst,
							   TREE_MAX_SELECTOR_VALUES, n))
				return -EINVAL;
		} else if (tree_section && !strcmp(section, "upatches.tree.selector.kconfig")) {
			if (build_parse_selector_kv(key, value, &sel->kconfig,
						    TREE_MAX_KCONFIG,
						    &sel->n_kconfig))
				return -EINVAL;
		} else if (tree_section) {
			if (build_parse_selector_kv(key, value, &sel->labels,
						    TREE_MAX_LABELS,
						    &sel->n_labels))
				return -EINVAL;
		}
	}
	if (!build_name_ok(spec->name))
		return -EINVAL;
	for (size_t i = 0; i < spec->n_files; i++) {
		if (!spec->files[i].source[0])
			return -EINVAL;
		if (!spec->files[i].target[0])
			strscpy(spec->files[i].target, spec->files[i].source,
				sizeof(spec->files[i].target));
	}
	for (size_t i = 0; i < spec->n_upatches; i++) {
		struct bpm_build_upatch *u = &spec->upatches[i];
		char *p;

		if (!u->source[0])
			return -EINVAL;
		if (!u->type[0])
			strscpy(u->type, "bpf", sizeof(u->type));
		for (p = u->type; *p; p++)
			*p = (char)tolower((__u8)*p);
		if (strcmp(u->type, "bpf") || build_default_targets(u))
			return -EINVAL;
		for (size_t j = 0; j < u->n_rodata; j++) {
			struct bpm_build_rodata *r = &u->rodata[j];

			if (!r->symbol[0] || !r->input[0] ||
			    !r->n_generator || !r->n_update ||
			    r->input[0] == '/' || strstr(r->input, "../") ||
			    !strcmp(r->input, ".."))
				return -EINVAL;
		}
		if (!u->tree.present)
			continue;
		if (!u->tree.id[0] || !upatch_name_valid(u->tree.id))
			return -EINVAL;
		if (!u->tree.load_artifact[0])
			strscpy(u->tree.load_artifact, u->load_target,
				sizeof(u->tree.load_artifact));
		if (!u->tree.unload_artifact[0])
			strscpy(u->tree.unload_artifact, u->unload_target,
				sizeof(u->tree.unload_artifact));
		if (build_target_ok(u->tree.load_artifact) ||
		    build_target_ok(u->tree.unload_artifact))
			return -EINVAL;
	}
	return 0;
}

int bpm_build_parse_beefile(const __u8 *body, size_t len,
			    struct bpm_build_spec *spec)
{
	__u8 *scratch;
	int ret;

	if (!body || !spec || memchr(body, '\0', len))
		return -EINVAL;
	spec->build_file = xmalloc(len + 1);
	scratch = xmalloc(len + 1);
	if (!spec->build_file || !scratch) {
		xfree(scratch, len + 1);
		xfree(spec->build_file, len + 1);
		spec->build_file = NULL;
		return -ENOMEM;
	}
	memcpy(spec->build_file, body, len);
	spec->build_file[len] = '\0';
	spec->build_file_len = len;
	memcpy(scratch, body, len);
	scratch[len] = '\0';
	ret = build_parse_spec(spec, (char *)scratch);
	xfree(scratch, len + 1);
	return ret;
}

void bpm_build_spec_free(struct bpm_build_spec *spec)
{
	if (!spec)
		return;
	for (size_t i = 0; i < spec->n_upatches; i++) {
		tree_selector_free(spec->upatches[i].tree.selector);
		xfree(spec->upatches[i].tree.selector,
		      sizeof(*spec->upatches[i].tree.selector));
		xfree(spec->upatches[i].rodata,
		      BPM_BUILD_MAX_RODATA *
		      sizeof(*spec->upatches[i].rodata));
		xfree(spec->upatches[i].policies,
		      BPM_BUILD_MAX_POLICIES *
		      sizeof(*spec->upatches[i].policies));
	}
	xfree(spec->build_file, spec->build_file_len + 1);
	xfree(spec, sizeof(*spec));
}

static bool build_within(const char *dir, const char *path)
{
	char resolved[PATH_MAX];
	size_t n;

	if (!realpath(path, resolved))
		return false;
	n = strlen(dir);
	return !strncmp(dir, resolved, n) && (resolved[n] == '\0' || resolved[n] == '/');
}

static int build_resolve_source(const struct bpm_build_spec *spec,
				const char *source, char *out, size_t cap,
				struct stat *st)
{
	char path[PATH_MAX];

	if (!source[0] || source[0] == '/' || strstr(source, "../") ||
	    !strcmp(source, ".."))
		return -EINVAL;
	if (strsprintf(path, sizeof(path), "%s/%s", spec->scope, source) < 0)
		return -ENAMETOOLONG;
	if (stat(path, st))
		return -errno;
	if (!S_ISREG(st->st_mode) || !build_within(spec->scope, path))
		return -EINVAL;
	if (!realpath(path, out))
		return -errno;
	if (strlen(out) >= cap)
		return -ENAMETOOLONG;
	return 0;
}

static int build_rodata_input_name(const char *path, char *name, size_t cap)
{
	const char *base = strrchr(path, '/');
	const char *dot;
	size_t len;

	base = base ? base + 1 : path;
	dot = strchr(base, '.');
	len = dot ? (size_t)(dot - base) : strlen(base);
	if (!len || len >= cap)
		return -EINVAL;
	memcpy(name, base, len);
	name[len] = '\0';
	return 0;
}

static const char *build_rodata_input(const struct bpm_build_rodata *rodata,
				      const struct bpm_build_input_override *overrides,
				      size_t n_overrides)
{
	char name[128];

	if (build_rodata_input_name(rodata->input, name, sizeof(name)))
		return NULL;
	for (size_t i = 0; i < n_overrides; i++)
		if (!strcmp(overrides[i].name, name))
			return overrides[i].path;
	return rodata->input;
}

/*
 * One --rodata-input <name>=<path> into overrides[*n]: 1 when it is a
 * usage error, -errno when the path is no regular file.
 */
static int parse_rodata_input(const char *value,
			      struct bpm_build_input_override *overrides,
			      size_t *n, size_t max)
{
	struct bpm_build_input_override *o = &overrides[*n];
	const char *eq = strchr(value, '=');
	char path[PATH_MAX];
	struct stat st;
	size_t name_len;

	if (*n == max || !eq || eq == value || !eq[1])
		return 1;
	name_len = (size_t)(eq - value);
	if (name_len >= sizeof(o->name))
		return 1;
	memcpy(o->name, value, name_len);
	o->name[name_len] = '\0';
	for (size_t j = 0; j < *n; j++)
		if (!strcmp(overrides[j].name, o->name))
			return 1;
	if (!realpath(eq + 1, path))
		return -errno;
	if (stat(path, &st) || !S_ISREG(st.st_mode))
		return -EINVAL;
	if (strscpy(o->path, path, sizeof(o->path)) < 0)
		return -ENAMETOOLONG;
	(*n)++;
	return 0;
}

static int build_run_rodata_command(const struct bpm_build_spec *spec,
				    const struct bpm_build_rodata *rodata,
				    bool update, const char *input,
				    const char *output)
{
	const char *argv[BPM_BUILD_MAX_COMMAND_ARGS + 7] = {};
	const char (*command)[TREE_STRING_MAX] = update ?
		rodata->update : rodata->generator;
	int n_command = update ? rodata->n_update : rodata->n_generator;
	int status;
	pid_t pid;

	for (int i = 0; i < n_command; i++)
		argv[i] = command[i];
	argv[n_command++] = "--input";
	argv[n_command++] = input;
	argv[n_command++] = "--symbol";
	argv[n_command++] = rodata->symbol;
	argv[n_command++] = "--output";
	argv[n_command++] = output;
	pid = fork();
	if (pid < 0)
		return -errno;
	if (!pid) {
		if (chdir(spec->scope))
			_exit(126);
		execvp(argv[0], (char *const *)argv);
		_exit(127);
	}
	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR)
			return -errno;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return 0;
	return -EIO;
}

static int build_rodata_apply(const struct bpm_build_spec *spec,
			      const struct bpm_build_upatch *upatch,
			      const char *load, const char *pkey,
			      const char *cert,
			      const struct bpm_build_input_override *overrides,
			      size_t n_overrides, bool update)
{
	for (size_t i = 0; i < upatch->n_rodata; i++) {
		const struct bpm_build_rodata *rodata = &upatch->rodata[i];
		const char *selected = build_rodata_input(rodata, overrides,
							 n_overrides);
		char input[PATH_MAX], generated[PATH_MAX], patched[PATH_MAX];
		__u8 *value = NULL;
		size_t value_len = 0;
		int ret;

		if (!selected)
			return -EINVAL;
		if (selected == rodata->input) {
			ret = build_resolve_source(spec, selected, input,
						   sizeof(input), &(struct stat){});
			if (ret)
				return ret;
		} else if (strscpy(input, selected, sizeof(input)) < 0) {
			return -ENAMETOOLONG;
		}
		if (strsprintf(generated, sizeof(generated), "%s/rodata-%zu-%zu.bin",
			       spec->stage, (size_t)(upatch - spec->upatches), i) < 0 ||
		    strsprintf(patched, sizeof(patched), "%s/rodata-%zu-%zu.upatch",
			       spec->stage, (size_t)(upatch - spec->upatches), i) < 0)
			return -ENAMETOOLONG;
		unlink(generated);
		unlink(patched);
		ret = build_run_rodata_command(spec, rodata, update, input,
					       generated);
		if (ret) {
			pr_err("bpm %s: converter failed for .rodata symbol %s",
			       update ? "config update" : "build", rodata->symbol);
			goto out;
		}
		ret = build_read_file(generated, &value, &value_len,
				      UPATCH_FILE_MAX);
		if (ret)
			goto out;
		ret = build_package_patch_rodata(load, patched,
						 rodata->symbol, value,
						 value_len, pkey, cert);
		if (!ret && rename(patched, load))
			ret = -errno;
out:
		xfree(value, value_len + 1);
		unlink(generated);
		if (ret) {
			unlink(patched);
			return ret;
		}
	}
	return 0;
}

static int build_rodata_overrides_known(const struct bpm_build_spec *spec,
					const struct bpm_build_input_override *overrides,
					size_t count)
{
	for (size_t i = 0; i < count; i++) {
		bool found = false;

		for (size_t j = 0; j < spec->n_upatches; j++) {
			const struct bpm_build_upatch *upatch = &spec->upatches[j];

			for (size_t k = 0; k < upatch->n_rodata; k++) {
				char name[128];

				if (!build_rodata_input_name(upatch->rodata[k].input,
							     name, sizeof(name)) &&
				    !strcmp(name, overrides[i].name))
					found = true;
			}
		}
		if (!found)
			return -ENOENT;
	}
	return 0;
}

static int build_target_ok(const char *target)
{
	const char *p = target;

	if (!target[0] || target[0] == '/')
		return -EINVAL;
	/*
	 * As the target's archive reader takes a path, or the package
	 * would build and never install, or read one way and install
	 * another: ./Beefile is the reserved Beefile, and a/./b is a/b.
	 */
	while (*p) {
		const char *q = strchr(p, '/');
		size_t n = q ? (size_t)(q - p) : strlen(p);

		if (!n || (n == 1 && *p == '.') ||
		    (n == 2 && !strncmp(p, "..", 2)) || (q && !q[1]))
			return -EINVAL;
		p = q ? q + 1 : p + n;
	}
	return 0;
}

static int build_add_target(char seen[][PATH_MAX], size_t *n, const char *target)
{
	if (build_target_ok(target))
		return -EINVAL;
	if (!strcmp(target, "Beefile") || !strcmp(target, "README.md") ||
	    !strcmp(target, "cert.der") || !strcmp(target, "build-environment.json"))
		return -EEXIST;
	for (size_t i = 0; i < *n; i++) {
		if (!strcmp(seen[i], target))
			return -EEXIST;
	}
	if (*n >= BPM_BUILD_MAX_ENTRIES * 3)
		return -E2BIG;
	strscpy(seen[(*n)++], target, PATH_MAX);
	return 0;
}

static const char *
build_rodata_command_source(const struct bpm_build_rodata *rodata, bool update)
{
	const char (*command)[TREE_STRING_MAX] = update ?
		rodata->update : rodata->generator;
	int n = update ? rodata->n_update : rodata->n_generator;

	if (!n)
		return NULL;
	if (strchr(command[0], '/'))
		return command[0];
	return n > 1 ? command[1] : NULL;
}

static int __build_validate(struct bpm_build_spec *spec,
			    bool allow_missing_upatch_source,
			    char seen[][PATH_MAX])
{
	char resolved[PATH_MAX];
	struct stat st;
	size_t n = 0;

	for (size_t i = 0; i < spec->n_files; i++) {
		if (build_add_target(seen, &n, spec->files[i].target) ||
		    build_resolve_source(spec, spec->files[i].source, resolved,
					 sizeof(resolved), &st))
			return -EINVAL;
	}
	for (size_t i = 0; i < spec->n_upatches; i++) {
		struct bpm_build_upatch *u = &spec->upatches[i];

		if (build_add_target(seen, &n, u->load_target) ||
		    build_add_target(seen, &n, u->unload_target) ||
		    (allow_missing_upatch_source ? build_target_ok(u->source) :
		     build_resolve_source(spec, u->source, resolved, sizeof(resolved),
					  &st)))
			return -EINVAL;
		for (size_t j = 0; j < u->n_rodata; j++) {
			struct bpm_build_rodata *r = &u->rodata[j];
			char input_name[128], other_name[128];

			if (build_resolve_source(spec, r->input, resolved,
						 sizeof(resolved), &st) ||
			    build_rodata_input_name(r->input, input_name,
						    sizeof(input_name)))
				return -EINVAL;
			for (size_t k = 0; k < i; k++) {
				for (size_t m = 0; m < spec->upatches[k].n_rodata; m++) {
					struct bpm_build_rodata *prev =
						&spec->upatches[k].rodata[m];

					if (build_rodata_input_name(prev->input,
								    other_name,
								    sizeof(other_name)))
						return -EINVAL;
					if (!strcmp(input_name, other_name) &&
					    strcmp(r->input, prev->input))
						return -EEXIST;
				}
			}
			for (size_t k = 0; k < j; k++) {
				struct bpm_build_rodata *prev = &u->rodata[k];

				if (build_rodata_input_name(prev->input, other_name,
							    sizeof(other_name)))
					return -EINVAL;
				if (!strcmp(input_name, other_name) &&
				    strcmp(r->input, prev->input))
					return -EEXIST;
			}
			for (int k = 0; k < 2; k++) {
				const char *cmd_source = build_rodata_command_source(r,
									  k != 0);

				if (!cmd_source ||
				    build_resolve_source(spec, cmd_source, resolved,
							 sizeof(resolved), &st))
					return -EINVAL;
			}
		}
		for (size_t j = 0; j < u->n_policies; j++) {
			struct bpm_build_policy *p = &u->policies[j];

			if (!p->id[0] || !p->bit || !p->n_paths ||
			    (p->bit & (p->bit - 1)))
				return -EINVAL;
			for (int path = 0; path < p->n_paths; path++)
				if (p->paths[path][0] != '/')
					return -EINVAL;
			for (size_t x = 0; x <= i; x++) {
				struct bpm_build_upatch *other = &spec->upatches[x];
				size_t limit = x == i ? j : other->n_policies;

				for (size_t y = 0; y < limit; y++) {
					struct bpm_build_policy *q = &other->policies[y];

					if ((!strcmp(p->id, q->id) && p->bit != q->bit) ||
					    (strcmp(p->id, q->id) && p->bit == q->bit))
						return -EEXIST;
				}
			}
		}
	}
	return 0;
}

/* The targets seen take 1.5 MiB, which a stack frame should not carry. */
static int build_validate(struct bpm_build_spec *spec,
			  bool allow_missing_upatch_source)
{
	const size_t cap = BPM_BUILD_MAX_ENTRIES * 3;
	char (*seen)[PATH_MAX];
	int ret;

	seen = xcalloc(cap, PATH_MAX);
	if (!seen)
		return -ENOMEM;
	ret = __build_validate(spec, allow_missing_upatch_source, seen);
	xfree(seen, cap * PATH_MAX);
	return ret;
}

static int build_entry_name(char *out, size_t cap, const char *top,
			    const char *entry)
{
	size_t top_len = strlen(top);
	size_t entry_len = strlen(entry);

	if (size_add(size_add(top_len, entry_len), 2) > cap)
		return -ENAMETOOLONG;
	memcpy(out, top, top_len);
	out[top_len] = '/';
	memcpy(out + top_len + 1, entry, entry_len + 1);
	return 0;
}

int build_upatch_name(const char *source, char *out, size_t cap)
{
	const char *base = strrchr(source, '/');
	ssize_t n;

	n = strscpy(out, base ? base + 1 : source, cap);
	if (n < 0)
		return n;
	if (name_has_suffix(out, n, ".bpf.c") ||
	    name_has_suffix(out, n, ".bpf.o"))
		out[n - 6] = '\0';
	else if (name_has_suffix(out, n, ".o"))
		out[n - 2] = '\0';
	return 0;
}

/*
 * The artifacts are signed into a directory of their own under names of
 * their own, so no target name can reach a file of the operator's and the
 * build leaves nothing behind.
 */
static int build_stage_open(struct bpm_build_spec *spec)
{
	const char *tmpdir = getenv("TMPDIR");
	char resolved[PATH_MAX];

	if (!tmpdir || !tmpdir[0])
		tmpdir = "/tmp";
	if (strsprintf(spec->stage, sizeof(spec->stage),
		       "%s/shirudo-bpm-build.XXXXXX", tmpdir) < 0)
		return -ENAMETOOLONG;
	if (!mkdtemp(spec->stage))
		return -errno;
	if (!realpath(spec->stage, resolved)) {
		int ret = -errno;

		rmdir(spec->stage);
		return ret;
	}
	if (strscpy(spec->stage, resolved, sizeof(spec->stage)) < 0) {
		rmdir(resolved);
		return -ENAMETOOLONG;
	}
	return 0;
}

static const char *build_vmlinux_from_cwd(char *out, size_t cap)
{
	static const char *const paths[] = {
		"./vmlinux.h", "./vendor/linux/vmlinux.h",
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(paths); i++)
		if (realpath(paths[i], out))
			return out;
	return NULL;
}

static const char *build_shirudo_bpf_include(char *out)
{
	char header[PATH_MAX];

	if (!realpath("bpf/lib", out))
		return NULL;
	if (strsprintf(header, sizeof(header), "%s/serializer.h",
		       out) < 0 || access(header, R_OK))
		return NULL;
	return out;
}

static int build_remove_tree(const char *path)
{
	struct dirent *entry;
	struct stat st;
	DIR *dir;
	int ret = 0;

	if (lstat(path, &st))
		return errno == ENOENT ? 0 : -errno;
	if (!S_ISDIR(st.st_mode))
		return unlink(path) ? -errno : 0;
	dir = opendir(path);
	if (!dir)
		return -errno;
	while ((entry = readdir(dir))) {
		char child[PATH_MAX];

		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;
		if (strsprintf(child, sizeof(child), "%s/%s", path,
			       entry->d_name) < 0) {
			ret = -ENAMETOOLONG;
			break;
		}
		ret = build_remove_tree(child);
		if (ret)
			break;
	}
	closedir(dir);
	if (!ret && rmdir(path))
		ret = -errno;
	return ret;
}

static void build_stage_close(struct bpm_build_spec *spec)
{
	char object[PATH_MAX + 8];

	for (size_t i = 0; i < spec->n_upatches; i++) {
		struct bpm_build_upatch *u = &spec->upatches[i];

		if (!u->load_path[0])
			continue;
		if (strsprintf(object, sizeof(object), "%s.bpf.o",
			       u->load_path) >= 0)
			unlink(object);
		unlink(u->load_path);
		unlink(u->unload_path);
	}
	build_remove_tree(spec->stage);
}

/*
 * The unload directive is bound to the payload digest the load artifact
 * ended up with.
 */
static int build_upatches(struct bpm_build_spec *spec, const char *pkey,
			  const char *cert, const char *vmlinux_override,
			  const char *shirudo_bpf_incdir,
			  const struct bpm_build_input_override *overrides,
			  size_t n_overrides, bool update)
{
	const char *vmlinux_h = vmlinux_override;

	for (size_t i = 0; i < spec->n_upatches; i++) {
		char source[PATH_MAX], load[PATH_MAX], unload[PATH_MAX];
		char object[PATH_MAX], name[UPATCH_NAME_MAX];
		struct upatch_policy_label_entry *labels = NULL;
		struct bpm_build_upatch *u = &spec->upatches[i];
		const char *bpf_o = source, *src_path = NULL;
		__u8 payload[CRYPTO_SHA256_LEN];
		struct upatch parsed = {};
		__u32 nr_labels = 0;
		int ret;

		if (build_resolve_source(spec, u->source, source, sizeof(source),
					 &(struct stat){}))
			return -EINVAL;
		if (strsprintf(load, sizeof(load), "%s/%zu.upatch", spec->stage,
			       i) < 0 ||
		    strsprintf(unload, sizeof(unload), "%s/%zu.unload.upatch",
			       spec->stage, i) < 0)
			return -ENAMETOOLONG;
		strscpy(u->load_path, load, sizeof(u->load_path));
		strscpy(u->unload_path, unload, sizeof(u->unload_path));
		if (name_has_suffix(source, strlen(source), ".bpf.c")) {
			if (!vmlinux_h) {
				vmlinux_h = build_locate_vmlinux(NULL);
				if (!vmlinux_h) {
					pr_err("bpm build: vmlinux.h not found (tried "
					       "./vmlinux.h, ./vendor/linux/vmlinux.h, %s)",
					       VMLINUX_PATH);
					return -ENOENT;
				}
			}
			if (strsprintf(object, sizeof(object), "%s.bpf.o", load) < 0)
				return -ENAMETOOLONG;
			ret = build_compile(source, object, vmlinux_h, NULL,
					    shirudo_bpf_incdir);
			if (ret) {
				pr_err("bpm build: compile %s failed", u->source);
				return ret < 0 ? ret : -EIO;
			}
			bpf_o = object;
			src_path = source;
		} else if (!name_has_suffix(source, strlen(source), ".o")) {
			pr_err("bpm build: %s is neither .bpf.c nor .bpf.o", u->source);
			return -EINVAL;
		}
		if (build_upatch_name(source, name, sizeof(name)))
			return -ENAMETOOLONG;
		for (size_t j = 0; j < u->n_policies; j++)
			nr_labels += u->policies[j].n_paths;
		if (nr_labels) {
			labels = xcalloc(nr_labels, sizeof(*labels));
			if (!labels)
				return -ENOMEM;
			nr_labels = 0;
			for (size_t j = 0; j < u->n_policies; j++) {
				struct bpm_build_policy *p = &u->policies[j];

				for (int k = 0; k < p->n_paths; k++) {
					struct upatch_policy_label_entry *e =
						&labels[nr_labels++];

					e->bit = cpu_to_le64(p->bit);
					strscpy(e->policy, p->id, sizeof(e->policy));
					strscpy(e->path, p->paths[k], sizeof(e->path));
				}
			}
		}
		ret = build_package_load(bpf_o, src_path, load, name,
					 labels, nr_labels, pkey, cert);
		xfree(labels, size_mul(nr_labels, sizeof(*labels)));
		if (bpf_o == object)
			unlink(object);
		if (ret)
			return ret < 0 ? ret : -EIO;
		ret = build_rodata_apply(spec, u, load, pkey, cert, overrides,
					 n_overrides, update);
		if (ret)
			return ret;
		if (upatch_open(load, &parsed))
			return -EINVAL;
		if (upatch_is_unload(&parsed) || !parsed.hdr.name[0]) {
			upatch_close(&parsed);
			return -EINVAL;
		}
		upatch_header_name(&parsed, u->name);
		hex_encode(parsed.hdr.payload_sha256,
			   CRYPTO_SHA256_LEN,
			   u->payload_sha256);
		memcpy(payload, parsed.hdr.payload_sha256, sizeof(payload));
		strscpy(u->type, upatch_type_str(&parsed), sizeof(u->type));
		upatch_close(&parsed);
		ret = build_package_unload(u->name, payload, unload, pkey,
					   cert);
		if (ret)
			return ret < 0 ? ret : -EIO;
	}
	return 0;
}

static int build_environment(const struct bpm_build_spec *spec,
			     const char *version, const char *fingerprint,
			     __u8 **out, size_t *out_len)
{
	char *body = xmalloc(BPM_BUILD_MAX_JSON);
	struct json_emit e = { .buf = body, .cap = BPM_BUILD_MAX_JSON };
	struct utsname un = {};
	char self[PATH_MAX] = "shirudo";
	char timestamp[32] = {};
	time_t now = time(NULL);
	ssize_t self_len;

	if (!body || uname(&un) ||
	    iso8601(now, timestamp, sizeof(timestamp))) {
		xfree(body, BPM_BUILD_MAX_JSON);
		return -EIO;
	}
	self_len = readlink("/proc/self/exe", self, sizeof(self) - 1);
	if (self_len > 0)
		self[self_len] = '\0';
	json_obj_open(&e);
	json_kv_int(&e, "format_version", 1);
	json_kv_string(&e, "builder", "bpm build");
	json_kv_string(&e, "created_at", timestamp);
	json_obj_open_key(&e, "package");
	json_kv_string(&e, "name", spec->name);
	json_kv_string(&e, "version", version);
	json_obj_close(&e);
	json_kv_string(&e, "os", un.sysname);
	json_kv_string(&e, "arch", un.machine);
	json_kv_string(&e, "bpm_version", shirudo_version);
	json_obj_open_key(&e, "shirudo");
	json_kv_string(&e, "path", self);
	json_kv_string(&e, "version", shirudo_version);
	json_kv_string(&e, "spki_sha256_fingerprint", fingerprint);
	json_obj_close(&e);
	json_arr_open(&e, "upatches");
	for (size_t i = 0; i < spec->n_upatches; i++) {
		const struct bpm_build_upatch *u = &spec->upatches[i];

		json_obj_open(&e);
		json_kv_string(&e, "source", u->source);
		json_kv_string(&e, "type", u->type);
		json_kv_string(&e, "load_target", u->load_target);
		json_kv_string(&e, "load_output", strrchr(u->load_target, '/') ?
			       strrchr(u->load_target, '/') + 1 : u->load_target);
		json_kv_string(&e, "unload_target", u->unload_target);
		json_kv_string(&e, "unload_output", strrchr(u->unload_target, '/') ?
			       strrchr(u->unload_target, '/') + 1 : u->unload_target);
		json_kv_string(&e, "upatch_name", u->name);
		json_kv_string(&e, "payload_sha256", u->payload_sha256);
		json_obj_close(&e);
	}
	json_arr_close(&e);
	json_obj_close(&e);
	if (e.err) {
		xfree(body, BPM_BUILD_MAX_JSON);
		return e.err;
	}
	*out = (__u8 *)body;
	*out_len = e.len;
	return 0;
}

struct bpm_tar {
	gzFile gz;
};

static int tar_write(struct bpm_tar *tar, const void *data, size_t len)
{
	if (!len)
		return 0;
	if (len > INT_MAX)
		return -EFBIG;
	return gzwrite(tar->gz, data, (__u32)len) == (int)len ? 0 : -EIO;
}

static int tar_octal(__u8 *h, size_t off, size_t size, __u64 value)
{
	return strsprintf((char *)h + off, size, "%0*llo", (int)(size - 1),
			  value) < 0 ? -E2BIG : 0;
}

static int tar_entry(struct bpm_tar *tar, const char *name, const void *data,
		     size_t len, mode_t mode, char type)
{
	__u8 h[512] = {};
	__u32 sum = 0;
	__u8 zeros[512] = {};

	if (strlen(name) >= 100 || (type == '0' && len > 077777777777ULL))
		return -ENAMETOOLONG;
	memcpy(h, name, strlen(name));
	if (tar_octal(h, 100, 8, mode & 07777) || tar_octal(h, 108, 8, 0) ||
	    tar_octal(h, 116, 8, 0) || tar_octal(h, 124, 12, len) ||
	    tar_octal(h, 136, 12, 0))
		return -E2BIG;
	memset(h + 148, ' ', 8);
	h[156] = (__u8)type;
	memcpy(h + 257, "ustar\0", 6);
	memcpy(h + 263, "00", 2);
	for (size_t i = 0; i < sizeof(h); i++)
		sum += h[i];
	if (strsprintf((char *)h + 148, 8, "%06o ", sum) < 0)
		return -E2BIG;
	if (tar_write(tar, h, sizeof(h)) || tar_write(tar, data, len))
		return -EIO;
	if (type == '0' && (len & 511))
		return tar_write(tar, zeros, 512 - (len & 511));
	return 0;
}

static int tar_path(struct bpm_tar *tar, const char *name, const char *path)
{
	__u8 *body;
	size_t len;
	struct stat st;
	int ret;

	if (stat(path, &st))
		return -errno;
	if (!S_ISREG(st.st_mode))
		return -EINVAL;
	ret = build_read_file(path, &body, &len, BPM_BUILD_MAX_FILE);
	if (!ret) {
		ret = tar_entry(tar, name, body, len, st.st_mode, '0');
		xfree(body, len + 1);
	}
	return ret;
}

static int build_archive(const struct bpm_build_spec *spec, const char *version,
			 const char *cert_path, const char *fingerprint,
			 const char *out_dir)
{
	char output[PATH_MAX], top[PATH_MAX], name[PATH_MAX];
	size_t environment_len = 0, cert_len = 0;
	__u8 *environment = NULL, *cert = NULL;
	struct bpm_tar tar;
	int ret;

	if (strsprintf(top, sizeof(top), "%s-%s", spec->name, version) < 0 ||
	    strsprintf(output, sizeof(output), "%s/%s.bee", out_dir, top) < 0)
		return -ENAMETOOLONG;
	if (build_environment(spec, version, fingerprint, &environment,
			      &environment_len))
		return -EIO;
	if (build_read_file(cert_path, &cert, &cert_len, BPM_BUILD_MAX_FILE)) {
		xfree(environment, BPM_BUILD_MAX_JSON);
		return -ENOENT;
	}
	tar.gz = gzopen(output, "wb9");
	if (!tar.gz) {
		xfree(environment, BPM_BUILD_MAX_JSON);
		xfree(cert, cert_len + 1);
		return -errno;
	}
	ret = build_entry_name(name, sizeof(name), top, "");
	if (!ret)
		ret = tar_entry(&tar, name, NULL, 0, 0755, '5');
	if (!ret) {
		ret = build_entry_name(name, sizeof(name), top, "Beefile");
		if (!ret)
			ret = tar_entry(&tar, name, spec->build_file,
					spec->build_file_len, 0644, '0');
	}
	for (size_t i = 0; !ret && i < spec->n_files; i++) {
		char resolved[PATH_MAX];
		struct stat st;

		ret = build_resolve_source(spec, spec->files[i].source, resolved,
					   sizeof(resolved), &st);
		if (!ret)
			ret = build_entry_name(name, sizeof(name), top,
					       spec->files[i].target);
		if (!ret)
			ret = tar_path(&tar, name, resolved);
	}
	for (size_t i = 0; !ret && i < spec->n_upatches; i++) {
		const struct bpm_build_upatch *u = &spec->upatches[i];

		ret = build_entry_name(name, sizeof(name), top, u->load_target);
		if (!ret)
			ret = tar_path(&tar, name, u->load_path);
		if (!ret)
			ret = build_entry_name(name, sizeof(name), top, u->unload_target);
		if (!ret)
			ret = tar_path(&tar, name, u->unload_path);
	}
	if (!ret) {
		char readme[PATH_MAX];
		struct stat st;

		ret = path_join(readme, sizeof(readme), spec->scope,
				"README.md");
		if (!ret) {
			if (!stat(readme, &st)) {
				if (!build_within(spec->scope, readme))
					ret = -EINVAL;
			} else if (errno != ENOENT) {
				ret = -errno;
			}
		}
		if (!ret && !access(readme, R_OK)) {
			ret = build_entry_name(name, sizeof(name), top, "README.md");
			if (!ret)
				ret = tar_path(&tar, name, readme);
		}
	}
	if (!ret) {
		ret = build_entry_name(name, sizeof(name), top, "cert.der");
		if (!ret)
			ret = tar_entry(&tar, name, cert, cert_len, 0644, '0');
	}
	if (!ret) {
		ret = build_entry_name(name, sizeof(name), top,
				       "build-environment.json");
		if (!ret)
			ret = tar_entry(&tar, name, environment, environment_len, 0644, '0');
	}
	if (!ret) {
		__u8 end[1024] = {};

		ret = tar_write(&tar, end, sizeof(end));
	}
	if (gzclose(tar.gz) != Z_OK)
		ret = ret ? ret : -EIO;
	xfree(environment, BPM_BUILD_MAX_JSON);
	xfree(cert, cert_len + 1);
	if (ret)
		unlink(output);
	else
		printf("%s\n", output);
	return ret;
}

static const char *build_resolve_keys_dir(const char *arg, char *out, size_t cap)
{
	const char *home = getenv("HOME");

	if (cap)
		out[0] = '\0';
	if (!arg || !*arg)
		arg = keys_dir_resolve(NULL);
	if (arg[0] == '~' && (!arg[1] || arg[1] == '/')) {
		if (!home || strsprintf(out, cap, "%s%s", home, arg + 1) < 0)
			return NULL;
		return out;
	}
	if (strscpy(out, arg, cap) < 0)
		return NULL;
	return out;
}

static void build_usage(void)
{
	fprintf(stderr,
		"usage: shirudo bpm build [context] --version <version>\n"
		"       shirudo bpm build [context] --file <name>.bee --version <version>\n"
		"                              [--keys-dir <dir>]\n"
		"                              [--vmlinux <vmlinux.h>]\n"
		"                              [--rodata-input <name>=<path>]...\n\n"
		"Builds a signed .bee package from a Beefile. The build command\n"
		"is available only in shirudo-operator and requires signing keys.\n");
}

static int __build_bpm_build(int argc, char **argv,
			     struct bpm_build_input_override *overrides)
{
	const char *context = ".", *file_arg = NULL, *version = NULL;
	const char *keys_arg = NULL, *vmlinux_arg = NULL;
	size_t n_overrides = 0;
	const char *vmlinux_override = NULL;
	const char *shirudo_bpf_incdir = NULL;
	char build_file[PATH_MAX], resolved_file[PATH_MAX];
	char keys_dir[PATH_MAX], vmlinux_abs[PATH_MAX];
	char shirudo_bpf_incdir_buf[PATH_MAX];
	char keys_abs[PATH_MAX], pkey[PATH_MAX], cert_path[PATH_MAX];
	char fingerprint[CRYPTO_SHA256_LEN * 2 + 1];
	__u8 digest[CRYPTO_SHA256_LEN];
	struct cert cert = {};
	struct bpm_build_spec *spec;
	int positional = 0, ret;
	char out_dir[PATH_MAX];
	size_t body_len = 0;
	__u8 *body = NULL;

	for (int i = 1; i < argc; i++) {
		if (build_is_help(argv[i])) {
			build_usage();
			return 0;
		} else if (!strcmp(argv[i], "--file")) {
			if (++i >= argc)
				goto usage;
			file_arg = argv[i];
		} else if (!strncmp(argv[i], "--file=", 7)) {
			file_arg = argv[i] + 7;
		} else if (!strcmp(argv[i], "--version")) {
			if (++i >= argc)
				goto usage;
			version = argv[i];
		} else if (!strncmp(argv[i], "--version=", 10)) {
			version = argv[i] + 10;
		} else if (!strcmp(argv[i], "--keys-dir")) {
			if (++i >= argc)
				goto usage;
			keys_arg = argv[i];
		} else if (!strncmp(argv[i], "--keys-dir=", 11)) {
			keys_arg = argv[i] + 11;
		} else if (!strcmp(argv[i], "--vmlinux")) {
			if (++i >= argc)
				goto usage;
			vmlinux_arg = argv[i];
		} else if (!strncmp(argv[i], "--vmlinux=", 10)) {
			vmlinux_arg = argv[i] + 10;
		} else if (!strcmp(argv[i], "--rodata-input")) {
			if (++i >= argc)
				goto usage;
			ret = parse_rodata_input(argv[i], overrides,
						 &n_overrides,
						 BPM_BUILD_MAX_ENTRIES);
			if (ret > 0)
				goto usage;
			if (ret)
				return ret;
		} else if (argv[i][0] == '-') {
			goto usage;
		} else if (++positional == 1) {
			context = argv[i];
		} else {
			goto usage;
		}
	}
	if (!version) {
		pr_err("bpm build: --version <version> is required");
		goto usage;
	}
	if (!build_version_ok(version)) {
		pr_err("bpm build: --version %s is not a SemVer 2.0.0 version such as 1.2.0, 1.2.0-rc.1 or 1.2.0+build.5",
		       version);
		return -EINVAL;
	}
	if (!build_resolve_keys_dir(keys_arg, keys_dir, sizeof(keys_dir)) ||
	    !realpath(keys_dir, keys_abs)) {
		pr_err("bpm build: keys directory %s is not usable", keys_dir);
		return -ENOENT;
	}
	ret = key_paths(keys_abs, pkey, sizeof(pkey), cert_path,
			sizeof(cert_path));
	if (ret)
		return ret;
	if (build_check_keys(pkey, cert_path))
		return -EACCES;
	if (vmlinux_arg && !realpath(vmlinux_arg, vmlinux_abs)) {
		pr_err("bpm build: cannot resolve vmlinux.h %s: %s",
		       vmlinux_arg, strerror(errno));
		return -errno;
	}
	if (vmlinux_arg)
		vmlinux_override = vmlinux_abs;
	else
		vmlinux_override = build_vmlinux_from_cwd(vmlinux_abs,
							  sizeof(vmlinux_abs));
	if (!getcwd(out_dir, sizeof(out_dir)))
		return -errno;
	shirudo_bpf_incdir = build_shirudo_bpf_include(shirudo_bpf_incdir_buf);
	if (file_arg) {
		if (strscpy(build_file, file_arg, sizeof(build_file)) < 0)
			return -ENAMETOOLONG;
	} else if (path_join(build_file, sizeof(build_file), context,
			     "Beefile")) {
		return -ENAMETOOLONG;
	}
	if (!realpath(build_file, resolved_file))
		return -errno;
	spec = xmalloc(sizeof(*spec));
	if (!spec)
		return -ENOMEM;
	strscpy(spec->scope, resolved_file, sizeof(spec->scope));
	{
		char *slash = strrchr(spec->scope, '/');

		if (!slash) {
			ret = -EINVAL;
			goto out;
		}
		*slash = '\0';
	}
	ret = build_read_file(resolved_file, &body, &body_len, BPM_BUILD_MAX_FILE);
	if (ret)
		goto out;
	ret = bpm_build_parse_beefile(body, body_len, spec);
	if (!ret)
		ret = build_validate(spec, false);
	if (ret) {
		pr_err("bpm build: %s is not a valid Beefile", resolved_file);
		goto out;
	}
	ret = build_rodata_overrides_known(spec, overrides, n_overrides);
	if (ret)
		goto out;
	if (cert_read_file(cert_path, &cert)) {
		ret = -ENOENT;
		goto out;
	}
	ret = cert_pubkey_digest(&cert, digest);
	if (ret)
		goto out_cert;
	hex_encode(digest, sizeof(digest), fingerprint);
	/*
	 * Compile in the package directory so ./vmlinux.h and the vendored
	 * headers resolve the way they do for `shirudo build` run there.
	 */
	if (chdir(spec->scope)) {
		ret = -errno;
		goto out_cert;
	}
	ret = build_stage_open(spec);
	if (ret)
		goto out_cert;
	ret = build_upatches(spec, pkey, cert_path, vmlinux_override,
			     shirudo_bpf_incdir, overrides, n_overrides, false);
	if (!ret)
		ret = build_archive(spec, version, cert_path, fingerprint, out_dir);
	build_stage_close(spec);
out_cert:
	cert_free(&cert);
out:
	xfree(body, body_len + 1);
	bpm_build_spec_free(spec);
	return ret;
usage:
	build_usage();
	return -EINVAL;
}

/* The overrides take half a MiB, which a stack frame should not carry. */
static int build_bpm_build(int argc, char **argv)
{
	struct bpm_build_input_override *overrides;
	int ret;

	overrides = xcalloc(BPM_BUILD_MAX_ENTRIES, sizeof(*overrides));
	if (!overrides)
		return -ENOMEM;
	ret = __build_bpm_build(argc, argv, overrides);
	xfree(overrides, BPM_BUILD_MAX_ENTRIES * sizeof(*overrides));
	return ret;
}

static int build_copy_package_member(const char *package, const char *member,
				     const char *output)
{
	__u8 *body = NULL;
	char parent[PATH_MAX];
	size_t len = 0;
	char *slash;
	int fd = -1;
	int ret;

	ret = bpm_pkg_read_member(package, member, &body, &len,
				  BPM_BUILD_MAX_FILE);
	if (ret)
		return ret;
	if (strscpy(parent, output, sizeof(parent)) < 0) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	slash = strrchr(parent, '/');
	if (slash) {
		char *p;
		struct stat st;

		*slash = '\0';
		for (p = parent + (parent[0] == '/'); ; p++) {
			if (*p != '/' && *p != '\0')
				continue;
			{
				char saved = *p;

				*p = '\0';
				if (mkdir(parent, 0700) && errno != EEXIST) {
					ret = -errno;
					goto out;
				}
				if (lstat(parent, &st)) {
					ret = -errno;
					goto out;
				}
				if (!S_ISDIR(st.st_mode)) {
					ret = -ENOTDIR;
					goto out;
				}
				*p = saved;
			}
			if (!*p)
				break;
		}
	}
	fd = open(output, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0) {
		ret = -errno;
		goto out;
	}
	ret = write_complete(fd, body, len);
	if (!ret && fsync(fd))
		ret = -errno;
out:
	if (fd >= 0)
		close(fd);
	xfree(body, len + 1);
	return ret;
}

static int build_download_package(const char *reference, char *path)
{
	struct bpm_oci_client client __cleanup(bpm_oci_client_clear) = {};
	struct bpm_descriptor layers[8] = {};
	struct bpm_buffer manifest = {};
	char repository[BPM_MAX_ENDPOINT], tag[BPM_MAX_NAME];
	char url[PATH_MAX], digest[BPM_MAX_DIGEST];
	__u8 *body = NULL;
	size_t body_len = 0;
	int n_layers = 0, fd = -1, ret;

	ret = bpm_oci_parse_pull_ref(reference, &client, repository,
				     sizeof(repository), tag, sizeof(tag));
	if (ret)
		return ret;
	ret = bpm_oci_url(&client, repository, "manifests", tag, url,
			  sizeof(url));
	if (ret)
		return ret;
	ret = bpm_oci_get_memory(&client, url, BPM_MANIFEST_MEDIA, &manifest);
	if (ret)
		goto out;
	ret = bpm_oci_parse_manifest(manifest.data, manifest.len, layers,
				     ARRAY_SIZE(layers), &n_layers, NULL, 0);
	if (ret)
		goto out;
	for (int i = 0; i < n_layers; i++) {
		if (strcmp(layers[i].media, BPM_PACKAGE_MEDIA))
			continue;
		ret = bpm_oci_url(&client, repository, "blobs", layers[i].digest,
				  url, sizeof(url));
		if (ret)
			goto out;
		fd = mkstemp(path);
		if (fd < 0) {
			ret = -errno;
			goto out;
		}
		ret = bpm_oci_get_file(&client, url, BPM_PACKAGE_MEDIA, fd,
				       layers[i].size);
		if (close(fd) && !ret)
			ret = -errno;
		fd = -1;
		if (ret)
			goto out;
		ret = build_read_file(path, &body, &body_len, BPM_BUILD_MAX_FILE);
		if (ret)
			goto out;
		ret = bpm_sha256_hex(body, body_len, digest, sizeof(digest));
		if (!ret && !bpm_digest_matches(layers[i].digest, digest))
			ret = -EKEYREJECTED;
		goto out;
	}
	if (!ret)
		ret = -ENOENT;
out:
	if (fd >= 0)
		close(fd);
	if (ret)
		unlink(path);
	xfree(body, body_len + 1);
	bpm_buffer_free(&manifest);
	return ret;
}

static int __build_bpm_config_update(int argc, char **argv,
				     struct bpm_build_input_override *overrides)
{
	const char *file_arg = NULL, *base_arg = NULL;
	const char *version = NULL, *keys_arg = NULL;
	size_t n_overrides = 0;
	char build_file[PATH_MAX], resolved_file[PATH_MAX], source_dir[PATH_MAX];
	char base_package[PATH_MAX], base_package_tmp[] =
		"/tmp/shirudo-bpm-base-XXXXXX";
	char keys_dir[PATH_MAX], keys_abs[PATH_MAX];
	char out_dir[PATH_MAX], pkey[PATH_MAX], cert_path[PATH_MAX];
	char fingerprint[CRYPTO_SHA256_LEN * 2 + 1];
	__u8 digest[CRYPTO_SHA256_LEN], *body = NULL;
	struct cert cert = {};
	struct bpm_package_info base_info = {};
	struct bpm_build_spec *spec;
	size_t body_len = 0;
	int ret;
	bool has_rodata = false, package_source, stage_open = false;
	bool downloaded_package = false;

	for (int i = 1; i < argc; i++) {
		if (build_is_help(argv[i])) {
			fprintf(stdout,
				"usage: shirudo bpm config update "
				"--base-package <package.bee|oci://host/repo:tag> "
				"--version <version> "
				"[--file <name>.bee] [--keys-dir <dir>] "
				"[--rodata-input <name>=<path>]...\n"
				"Without --file, the Beefile and updater inputs come from "
				"--base-package and are trusted as operator-side code.\n");
			return 0;
		} else if (!strcmp(argv[i], "--file")) {
			if (++i >= argc)
				goto usage;
			file_arg = argv[i];
		} else if (!strcmp(argv[i], "--base-package")) {
			if (++i >= argc)
				goto usage;
			base_arg = argv[i];
		} else if (!strcmp(argv[i], "--version")) {
			if (++i >= argc)
				goto usage;
			version = argv[i];
		} else if (!strcmp(argv[i], "--keys-dir")) {
			if (++i >= argc)
				goto usage;
			keys_arg = argv[i];
		} else if (!strcmp(argv[i], "--rodata-input")) {
			if (++i >= argc)
				goto usage;
			ret = parse_rodata_input(argv[i], overrides,
						 &n_overrides,
						 BPM_BUILD_MAX_ENTRIES);
			if (ret > 0)
				goto usage;
			if (ret)
				return ret;
		} else {
			goto usage;
		}
	}
	if (!base_arg || !version)
		goto usage;
	if (!build_version_ok(version)) {
		pr_err("bpm config update: --version %s is not a SemVer 2.0.0 version such as 1.2.0, 1.2.0-rc.1 or 1.2.0+build.5",
		       version);
		return -EINVAL;
	}
	if (!strncmp(base_arg, "oci://", 6)) {
		ret = build_download_package(base_arg, base_package_tmp);
		if (ret)
			return ret;
		if (strscpy(base_package, base_package_tmp,
			    sizeof(base_package)) < 0) {
			unlink(base_package_tmp);
			return -ENAMETOOLONG;
		}
		downloaded_package = true;
	} else if (!realpath(base_arg, base_package)) {
		goto usage;
	}
	ret = bpm_pkg_load_info(base_package, &base_info);
	if (ret)
		goto out_base;
	if (bpm_semver_compare(version, base_info.version) <= 0) {
		ret = -EINVAL;
		goto out_base;
	}
	if (!getcwd(out_dir, sizeof(out_dir))) {
		ret = -errno;
		goto out_base;
	}
	if (!build_resolve_keys_dir(keys_arg, keys_dir, sizeof(keys_dir)) ||
	    !realpath(keys_dir, keys_abs)) {
		ret = -ENOENT;
		goto out_base;
	}
	ret = key_paths(keys_abs, pkey, sizeof(pkey), cert_path,
			sizeof(cert_path));
	if (ret)
		goto out_base;
	if (build_check_keys(pkey, cert_path))
		goto key_error;
	package_source = !file_arg;
	spec = xmalloc(sizeof(*spec));
	if (!spec)
		goto alloc_error;
	if (package_source) {
		ret = build_stage_open(spec);
		if (ret)
			goto out;
		stage_open = true;
		if (strsprintf(source_dir, sizeof(source_dir), "%s/source",
			       spec->stage) < 0) {
			ret = -ENAMETOOLONG;
			goto out;
		}
		if (mkdir(source_dir, 0700)) {
			ret = -errno;
			goto out;
		}
		if (strsprintf(build_file, sizeof(build_file), "%s/Beefile",
			       source_dir) < 0) {
			ret = -ENAMETOOLONG;
			goto out;
		}
		ret = build_copy_package_member(base_package, "Beefile", build_file);
		if (ret == -ENOENT) {
			pr_err("bpm config update: base package %s has no Beefile; "
			       "rebuild it with a Beefile or pass --file <name>.bee",
			       base_package);
			ret = -EINVAL;
		}
		if (ret)
			goto out;
	} else if (strscpy(build_file, file_arg, sizeof(build_file)) < 0) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	if (!realpath(build_file, resolved_file)) {
		ret = -errno;
		goto out;
	}
	strscpy(spec->scope, resolved_file, sizeof(spec->scope));
	{
		char *slash = strrchr(spec->scope, '/');

		if (!slash) {
			ret = -EINVAL;
			goto out;
		}
		*slash = '\0';
	}
	ret = build_read_file(resolved_file, &body, &body_len,
			      BPM_BUILD_MAX_FILE);
	if (ret)
		goto out;
	ret = bpm_build_parse_beefile(body, body_len, spec);
	if (!ret && package_source) {
		for (size_t i = 0; i < spec->n_files && !ret; i++) {
			char output[PATH_MAX];

			if (build_target_ok(spec->files[i].source) ||
			    build_target_ok(spec->files[i].target)) {
				ret = -EINVAL;
				break;
			}
			if (path_join(output, sizeof(output), spec->scope,
				      spec->files[i].source)) {
				ret = -ENAMETOOLONG;
				break;
			}
			ret = build_copy_package_member(base_package,
							spec->files[i].target,
							output);
		}
		if (!ret) {
			char readme[PATH_MAX];

			if (path_join(readme, sizeof(readme), spec->scope,
				      "README.md")) {
				ret = -ENAMETOOLONG;
			} else {
				ret = build_copy_package_member(base_package,
								"README.md", readme);
				if (ret == -ENOENT)
					ret = 0;
			}
		}
	}
	if (!ret)
		ret = build_validate(spec, package_source);
	if (!ret)
		ret = build_rodata_overrides_known(spec, overrides, n_overrides);
	if (!ret && strcmp(spec->name, base_info.name))
		ret = -EINVAL;
	for (size_t i = 0; !ret && i < spec->n_upatches; i++)
		if (spec->upatches[i].n_rodata)
			has_rodata = true;
	if (!ret && !has_rodata)
		ret = -EINVAL;
	if (ret)
		goto out;
	if (cert_read_file(cert_path, &cert)) {
		ret = -ENOENT;
		goto out_cert;
	}
	ret = cert_pubkey_digest(&cert, digest);
	if (ret)
		goto out_cert;
	hex_encode(digest, sizeof(digest), fingerprint);
	if (strcmp(fingerprint, base_info.signer)) {
		ret = -EKEYREJECTED;
		goto out_cert;
	}
	if (chdir(spec->scope)) {
		ret = -errno;
		goto out_cert;
	}
	if (!stage_open) {
		ret = build_stage_open(spec);
		if (ret)
			goto out_cert;
		stage_open = true;
	}
	for (size_t i = 0; i < spec->n_upatches && !ret; i++) {
		struct bpm_build_upatch *upatch = &spec->upatches[i];
		char load[PATH_MAX], unload[PATH_MAX];
		char expected_name[UPATCH_NAME_MAX];
		struct upatch parsed = {};
		__u8 payload[CRYPTO_SHA256_LEN];

		if (strsprintf(load, sizeof(load), "%s/update-%zu.upatch",
			       spec->stage, i) < 0 ||
		    strsprintf(unload, sizeof(unload), "%s/update-%zu.unload.upatch",
			       spec->stage, i) < 0) {
			ret = -ENAMETOOLONG;
			break;
		}
		ret = build_copy_package_member(base_package, upatch->load_target,
						load);
		if (ret)
			break;
		ret = build_package_verify(load, cert_path);
		if (ret)
			break;
		ret = build_upatch_name(upatch->source, expected_name,
					sizeof(expected_name));
		if (ret)
			break;
		ret = upatch_open(load, &parsed);
		if (ret)
			break;
		if (upatch_is_unload(&parsed) ||
		    strncmp(parsed.hdr.name, expected_name,
			    sizeof(parsed.hdr.name))) {
			ret = -EINVAL;
			upatch_close(&parsed);
			break;
		}
		upatch_close(&parsed);
		ret = build_rodata_apply(spec, upatch, load, pkey, cert_path,
					 overrides, n_overrides, true);
		if (ret)
			break;
		ret = upatch_open(load, &parsed);
		if (ret)
			break;
		if (upatch_is_unload(&parsed)) {
			ret = -EINVAL;
			upatch_close(&parsed);
			break;
		}
		upatch_header_name(&parsed, upatch->name);
		memcpy(payload, parsed.hdr.payload_sha256, sizeof(payload));
		hex_encode(payload, sizeof(payload), upatch->payload_sha256);
		strscpy(upatch->type, upatch_type_str(&parsed),
			sizeof(upatch->type));
		upatch_close(&parsed);
		strscpy(upatch->load_path, load, sizeof(upatch->load_path));
		strscpy(upatch->unload_path, unload, sizeof(upatch->unload_path));
		ret = build_package_unload(upatch->name, payload, unload,
					   pkey, cert_path);
	}
	if (!ret)
		ret = build_archive(spec, version, cert_path, fingerprint, out_dir);
out_cert:
	cert_free(&cert);
out:
	if (stage_open) {
		if (chdir(out_dir) && !ret)
			ret = -errno;
		build_stage_close(spec);
	}
	xfree(body, body_len + 1);
	bpm_build_spec_free(spec);
	goto out_base;
key_error:
	ret = -EACCES;
	goto out_base;
alloc_error:
	ret = -ENOMEM;
out_base:
	xfree(base_info.cert, base_info.cert_len + 1);
	if (downloaded_package)
		unlink(base_package);
	return ret;
usage:
	fprintf(stderr,
		"usage: shirudo bpm config update --base-package "
		"<package.bee|oci://host/repo:tag> --version <version> "
		"[--file <name>.bee] "
		"[--rodata-input <name>=<path>]... [--keys-dir <dir>]\n");
	return -EINVAL;
}

/* The overrides take half a MiB, which a stack frame should not carry. */
static int build_bpm_config_update(int argc, char **argv)
{
	struct bpm_build_input_override *overrides;
	int ret;

	overrides = xcalloc(BPM_BUILD_MAX_ENTRIES, sizeof(*overrides));
	if (!overrides)
		return -ENOMEM;
	ret = __build_bpm_config_update(argc, argv, overrides);
	xfree(overrides, BPM_BUILD_MAX_ENTRIES * sizeof(*overrides));
	return ret;
}

static void bpm_usage(FILE *fp)
{
	fprintf(fp,
		"usage: shirudo bpm build [context] --version <version> [--file <name>.bee]\n"
		"                         [--keys-dir <dir>] [--vmlinux <vmlinux.h>]\n"
		"                         [--rodata-input <name>=<path>]...\n"
		"       shirudo bpm config update --base-package <package.bee|oci://...>\n"
		"                         --version <version> [--file <name>.bee]\n"
		"                         [--rodata-input <name>=<path>]...\n"
		"       shirudo bpm push <package-file> <repository> [--keys-dir <dir> |\n"
		"                        --index-cert <cert.der> --index-key <key.pem>]\n"
		"       shirudo bpm tree append <package-file> <repository> [options]\n\n"
		"Operator-only BPM commands, implemented in shirudo-build and reached\n"
		"through `shirudo bpm`. Each accepts --help.\n");
}

bool build_is_help(const char *arg)
{
	return arg && (!strcmp(arg, "--help") || !strcmp(arg, "-h") ||
		       !strcmp(arg, "help"));
}

int build_bpm(int argc, char **argv)
{
	int ret;

	if (argc < 2 || build_is_help(argv[1])) {
		bpm_usage(argc < 2 ? stderr : stdout);
		return argc < 2 ? 2 : 0;
	}
	if (!strcmp(argv[1], "build")) {
		ret = build_bpm_build(argc - 1, argv + 1);
		if (ret < 0 && ret != -EINVAL)
			pr_err("bpm build: %s", strerror(-ret));
		return ret ? 1 : 0;
	}
	if (!strcmp(argv[1], "config") && argc >= 3 &&
	    !strcmp(argv[2], "update")) {
		ret = build_bpm_config_update(argc - 2, argv + 2);
		if (ret < 0 && ret != -EINVAL)
			pr_err("bpm config update: %s", strerror(-ret));
		return ret ? 1 : 0;
	}
	if (!strcmp(argv[1], "push"))
		return build_bpm_push(argc - 1, argv + 1);
	if (!strcmp(argv[1], "tree"))
		return build_bpm_tree(argc - 1, argv + 1);
	pr_err("shirudo-build bpm: '%s' is not an operator bpm command", argv[1]);
	bpm_usage(stderr);
	return 2;
}
