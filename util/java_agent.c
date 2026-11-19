// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The Java agents a target runs: the sealed jars of the loaded Java
 * upatches and the JAVA_TOOL_OPTIONS file that names them.
 */

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "io.h"
#include "java_agent.h"
#include "malloc.h"
#include "paths.h"
#include "seal.h"
#include "upatch.h"

#define JAVA_OPTIONS_MAX	(64u * 1024u)

/*
 * A jar a JVM takes as an agent that does nothing, left in place of an
 * agent taken out: a user manager started before keeps naming the jar in
 * JAVA_TOOL_OPTIONS, and a JVM given a missing jar, or one without a
 * premain, does not start. It stores the manifest and the class of
 *
 *	package shirudo;
 *
 *	public final class Unloaded {
 *		public static void premain(String args) { }
 *	}
 *
 * built for Java 8 without debug information.
 */
static const __u8 java_placeholder[] = {
	0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x21, 0x00, 0x6d, 0x6f, 0x09, 0xd7, 0x3a, 0x00, 0x00, 0x00, 0x3a, 0x00,
	0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x4d, 0x45, 0x54, 0x41, 0x2d, 0x49,
	0x4e, 0x46, 0x2f, 0x4d, 0x41, 0x4e, 0x49, 0x46, 0x45, 0x53, 0x54, 0x2e,
	0x4d, 0x46, 0x4d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x2d, 0x56,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x31, 0x2e, 0x30, 0x0d,
	0x0a, 0x50, 0x72, 0x65, 0x6d, 0x61, 0x69, 0x6e, 0x2d, 0x43, 0x6c, 0x61,
	0x73, 0x73, 0x3a, 0x20, 0x73, 0x68, 0x69, 0x72, 0x75, 0x64, 0x6f, 0x2e,
	0x55, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x65, 0x64, 0x0d, 0x0a, 0x0d, 0x0a,
	0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x21, 0x00, 0xbc, 0xe2, 0x68, 0x5c, 0xc0, 0x00, 0x00, 0x00, 0xc0, 0x00,
	0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x73, 0x68, 0x69, 0x72, 0x75, 0x64,
	0x6f, 0x2f, 0x55, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x65, 0x64, 0x2e, 0x63,
	0x6c, 0x61, 0x73, 0x73, 0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34,
	0x00, 0x0c, 0x0a, 0x00, 0x02, 0x00, 0x03, 0x07, 0x00, 0x04, 0x0c, 0x00,
	0x05, 0x00, 0x06, 0x01, 0x00, 0x10, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c,
	0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x01, 0x00,
	0x06, 0x3c, 0x69, 0x6e, 0x69, 0x74, 0x3e, 0x01, 0x00, 0x03, 0x28, 0x29,
	0x56, 0x07, 0x00, 0x08, 0x01, 0x00, 0x10, 0x73, 0x68, 0x69, 0x72, 0x75,
	0x64, 0x6f, 0x2f, 0x55, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x65, 0x64, 0x01,
	0x00, 0x04, 0x43, 0x6f, 0x64, 0x65, 0x01, 0x00, 0x07, 0x70, 0x72, 0x65,
	0x6d, 0x61, 0x69, 0x6e, 0x01, 0x00, 0x15, 0x28, 0x4c, 0x6a, 0x61, 0x76,
	0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x53, 0x74, 0x72, 0x69, 0x6e,
	0x67, 0x3b, 0x29, 0x56, 0x00, 0x31, 0x00, 0x07, 0x00, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x05, 0x00, 0x06, 0x00, 0x01,
	0x00, 0x09, 0x00, 0x00, 0x00, 0x11, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x05, 0x2a, 0xb7, 0x00, 0x01, 0xb1, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x09, 0x00, 0x0a, 0x00, 0x0b, 0x00, 0x01, 0x00, 0x09, 0x00, 0x00, 0x00,
	0x0d, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xb1, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x50, 0x4b, 0x01, 0x02, 0x14, 0x03, 0x14, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x6d, 0x6f, 0x09, 0xd7,
	0x3a, 0x00, 0x00, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa4, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x4d, 0x45, 0x54, 0x41, 0x2d, 0x49, 0x4e, 0x46, 0x2f, 0x4d,
	0x41, 0x4e, 0x49, 0x46, 0x45, 0x53, 0x54, 0x2e, 0x4d, 0x46, 0x50, 0x4b,
	0x01, 0x02, 0x14, 0x03, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x21, 0x00, 0xbc, 0xe2, 0x68, 0x5c, 0xc0, 0x00, 0x00, 0x00, 0xc0, 0x00,
	0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xa4, 0x01, 0x6c, 0x00, 0x00, 0x00, 0x73, 0x68, 0x69, 0x72,
	0x75, 0x64, 0x6f, 0x2f, 0x55, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x65, 0x64,
	0x2e, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x50, 0x4b, 0x05, 0x06, 0x00, 0x00,
	0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x86, 0x00, 0x00, 0x00, 0x60, 0x01,
	0x00, 0x00, 0x00, 0x00,
};

int java_agent_path(const char *name, char *buf, size_t cap)
{
	if (strsprintf(buf, cap, "%s/%s.jar", JAVA_DIR, name) < 0)
		return -ENAMETOOLONG;
	return 0;
}

/*
 * The label is what the seal protects: an unlabelled directory here is
 * one root made, whose jars root could swap.
 */
static int java_dir_check(void)
{
	struct stat st;

	if (lstat(JAVA_DIR, &st))
		return -errno;
	if (!S_ISDIR(st.st_mode) || st.st_uid || (st.st_mode & 0022) ||
	    !seal_parent_labeled(JAVA_DIR "/."))
		return -EPERM;
	return 0;
}

int java_agent_dir_prepare(void)
{
	int ret;

	if (mkdir(JAVA_DIR, 0755)) {
		if (errno != EEXIST)
			return -errno;
		return java_dir_check();
	}
	ret = chmod(JAVA_DIR, 0755) ? -errno : seal_label(JAVA_DIR);
	if (ret) {
		rmdir(JAVA_DIR);
		return ret;
	}
	return 0;
}

int java_agent_install(const char *name, const void *jar, size_t len)
{
	char path[PATH_MAX];
	int ret;

	ret = java_agent_path(name, path, sizeof(path));
	if (!ret)
		ret = java_agent_dir_prepare();
	if (!ret)
		ret = seal_write_file_mode(path, jar, len, 0644);
	return ret;
}

/* Whether the jar installed under name is the len bytes at jar. */
static int jar_installed(const char *name, const void *jar, size_t len)
{
	char path[PATH_MAX];
	size_t have_len = 0;
	__u8 *have;
	int fd, ret;

	ret = java_agent_path(name, path, sizeof(path));
	if (ret)
		return ret;
	fd = seal_open_read(path);
	if (fd == -ENOENT)
		return 0;
	if (fd < 0)
		return fd;
	ret = read_fd(fd, path, UPATCH_FILE_MAX, &have, &have_len);
	close(fd);
	if (ret)
		return ret;
	ret = have_len == len && !memcmp(have, jar, len);
	xfree(have, have_len + 1);
	return ret;
}

int java_agent_retire(const char *name)
{
	char path[PATH_MAX];
	int ret;

	ret = java_agent_path(name, path, sizeof(path));
	if (ret)
		return ret;
	if (access(path, F_OK))
		return errno == ENOENT ? 0 : -errno;
	ret = jar_installed(name, java_placeholder, sizeof(java_placeholder));
	if (ret)
		return min(ret, 0);
	return seal_write_file_mode(path, java_placeholder,
				    sizeof(java_placeholder), 0644);
}

/* The sealed archive of name, opened: 0, or -ENOENT for none. */
static int archive_open(const char *name, struct upatch *u)
{
	char path[PATH_MAX];
	int fd, ret;

	if (strsprintf(path, sizeof(path), "%s/%s.upatch", UPATCHES_DIR,
		       name) < 0)
		return -ENAMETOOLONG;
	fd = seal_open_read(path);
	if (fd < 0)
		return fd;
	ret = upatch_open_fd(fd, u);
	close(fd);
	return ret;
}

static bool java_load(const struct upatch *u)
{
	return u->hdr.type == UPATCH_TYPE_JAVA && !upatch_is_unload(u);
}

/*
 * 1 with *u open when the archive of name is a Java load; 0 when there is
 * none, or one that is foreign, malformed or of another kind, which boot
 * restore ignores too; -errno when that cannot be told.
 */
static int archived_java(const char *name, struct upatch *u)
{
	int ret = archive_open(name, u);

	if (ret == -ENOENT || ret == -EPERM || ret == -EINVAL ||
	    ret == -EFBIG)
		return 0;
	if (ret)
		return ret;
	if (java_load(u))
		return 1;
	upatch_close(u);
	return 0;
}

int java_agent_payload(const char *name,
		       __u8 payload[UPATCH_PAYLOAD_HASH_LEN])
{
	struct upatch u;
	const void *jar;
	__u32 len;
	int ret;

	ret = archived_java(name, &u);
	if (ret <= 0)
		return ret ? ret : -ENOENT;
	jar = upatch_signed_jar(&u, &len);
	if (!jar) {
		upatch_close(&u);
		return -ENOENT;
	}
	ret = jar_installed(name, jar, len);
	if (ret == 1) {
		memcpy(payload, u.hdr.payload_sha256, UPATCH_PAYLOAD_HASH_LEN);
		ret = 0;
	} else if (!ret) {
		ret = -ESTALE;
	}
	upatch_close(&u);
	return ret;
}

int java_tool_options(const char *const *names, size_t n, char *out,
		      size_t cap)
{
	size_t off = 0, i;
	int w;

	/* Appended, so that another environment.d file's options stay. */
	w = strsprintf(out, cap,
		       "JAVA_TOOL_OPTIONS=\"${JAVA_TOOL_OPTIONS:+$JAVA_TOOL_OPTIONS }");
	if (w < 0)
		return w;
	off = (size_t)w;
	for (i = 0; i < n; i++) {
		w = strsprintf(out + off, cap - off, "%s-javaagent:%s/%s.jar",
			       i ? " " : "", JAVA_DIR, names[i]);
		if (w < 0)
			return w;
		off += (size_t)w;
	}
	w = strsprintf(out + off, cap - off, "\"\n");
	if (w < 0)
		return w;
	return (int)(off + (size_t)w);
}

bool java_agent_loaded(const char *name)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN];

	return !java_agent_payload(name, payload);
}

static int jar_select(const struct dirent *e)
{
	return name_has_suffix(e->d_name, strlen(e->d_name), ".jar");
}

/* cb for each jar under JAVA_DIR whose name is a upatch's, in name order. */
static int jars_each(int (*cb)(const char *name, void *ctx), void *ctx)
{
	struct dirent **ents = NULL;
	int n, i, ret = 0;

	n = scandir(JAVA_DIR, &ents, jar_select, alphasort);
	if (n < 0)
		return errno == ENOENT ? 0 : -errno;
	for (i = 0; i < n; i++) {
		size_t len = strlen(ents[i]->d_name) - strlen(".jar");
		char name[UPATCH_NAME_MAX + 1];

		if (!ret && len < sizeof(name)) {
			memcpy(name, ents[i]->d_name, len);
			name[len] = '\0';
			if (upatch_name_valid(name))
				ret = cb(name, ctx);
		}
		libc_free(ents[i]);
	}
	libc_free(ents);
	return ret;
}

struct loaded_walk {
	int	(*cb)(const char *name,
		      const __u8 payload[UPATCH_PAYLOAD_HASH_LEN], void *ctx);
	void	*ctx;
};

static int loaded_one(const char *name, void *ctx)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN];
	struct loaded_walk *w = ctx;

	if (java_agent_payload(name, payload))
		return 0;
	return w->cb(name, payload, w->ctx);
}

int java_agents_each_loaded(int (*cb)(const char *name,
				      const __u8 payload[UPATCH_PAYLOAD_HASH_LEN],
				      void *ctx),
			    void *ctx)
{
	struct loaded_walk w = { .cb = cb, .ctx = ctx };

	return jars_each(loaded_one, &w);
}

struct unbacked_walk {
	int	(*cb)(const char *name, void *ctx);
	void	*ctx;
	int	n;
};

static int unbacked_one(const char *name, void *ctx)
{
	struct unbacked_walk *w = ctx;
	int ret;

	ret = jar_installed(name, java_placeholder, sizeof(java_placeholder));
	if (ret)
		return min(ret, 0);
	if (java_agent_loaded(name))
		return 0;
	w->n++;
	return w->cb ? w->cb(name, w->ctx) : 0;
}

int java_agents_unbacked(int (*cb)(const char *name, void *ctx), void *ctx)
{
	struct unbacked_walk w = { .cb = cb, .ctx = ctx };
	int ret = jars_each(unbacked_one, &w);

	return ret ? ret : w.n;
}

struct java_agents {
	char	**names;
	size_t	n;
	size_t	cap;
};

static void agents_free(struct java_agents *a)
{
	size_t i;

	for (i = 0; i < a->n; i++)
		xstrfree(a->names[i]);
	xfree(a->names, a->cap * sizeof(*a->names));
	a->names = NULL;
	a->n = 0;
}

/*
 * The jar file kept and named in a while its archive is a Java load, or
 * while that cannot be told: a jar retired on a passing error would leave
 * a measured agent missing with nothing measuring its removal.
 */
static int agent_sync_one(struct java_agents *a, const char *file)
{
	size_t len = strlen(file) - strlen(".jar");
	struct upatch u;
	char *name;
	int ret;

	name = xstrndup(file, len);
	if (!name)
		return -ENOMEM;
	ret = upatch_name_valid(name) ? archived_java(name, &u) : 0;
	if (ret == 1)
		upatch_close(&u);
	if (ret) {
		a->names[a->n++] = name;
		return min(ret, 0);
	}
	ret = java_agent_retire(name);
	xstrfree(name);
	return ret;
}

/*
 * The jars under JAVA_DIR brought in line with the archive and named in a,
 * in name order. 0, or the -errno when the directory cannot be read; the
 * first error of a jar goes to *jar_err, the rest still done.
 */
static int agents_installed(struct java_agents *a, int *jar_err)
{
	struct dirent **ents = NULL;
	int n, i, err;

	a->names = NULL;
	a->cap = 0;
	a->n = 0;
	*jar_err = 0;
	n = scandir(JAVA_DIR, &ents, jar_select, alphasort);
	if (n < 0)
		return errno == ENOENT ? 0 : -errno;
	a->cap = (size_t)n + 1;
	a->names = xcalloc(a->cap, sizeof(*a->names));
	for (i = 0; i < n; i++) {
		err = a->names ? agent_sync_one(a, ents[i]->d_name) : -ENOMEM;
		if (err && !*jar_err)
			*jar_err = err;
		libc_free(ents[i]);
	}
	libc_free(ents);
	return a->names ? 0 : -ENOMEM;
}

static bool options_current(const char *want, size_t len)
{
	size_t have_len = 0;
	char *have;
	bool same;

	if (read_file(JAVA_ENV_PATH, JAVA_OPTIONS_MAX, &have, &have_len))
		return false;
	same = have_len == len && !memcmp(have, want, len);
	xfree(have, have_len + 1);
	return same;
}

/* User managers read the directory as their user, whoever made it. */
static int env_dir_prepare(void)
{
	if (mkdir(JAVA_ENV_DIR, 0755) && errno != EEXIST)
		return -errno;
	return chmod(JAVA_ENV_DIR, 0755) ? -errno : 0;
}

static int write_options(const struct java_agents *a)
{
	char *buf;
	int len, ret;

	if (!a->n) {
		if (unlink(JAVA_ENV_PATH) && errno != ENOENT)
			return -errno;
		return 0;
	}
	buf = xmalloc(JAVA_OPTIONS_MAX);
	if (!buf)
		return -ENOMEM;
	len = java_tool_options((const char *const *)a->names, a->n, buf,
				JAVA_OPTIONS_MAX);
	ret = min(len, 0);
	if (!ret && !options_current(buf, (size_t)len)) {
		ret = env_dir_prepare();
		if (!ret)
			ret = seal_write_file_mode(JAVA_ENV_PATH, buf,
						   (size_t)len, 0644);
	}
	xfree(buf, JAVA_OPTIONS_MAX);
	return ret;
}

int java_agents_sync(void)
{
	struct java_agents a;
	int ret, jar_err;

	ret = agents_installed(&a, &jar_err);
	if (ret)
		return ret;
	ret = write_options(&a);
	agents_free(&a);
	return jar_err ? jar_err : ret;
}
