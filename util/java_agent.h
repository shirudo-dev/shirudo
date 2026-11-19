/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The Java agents a target runs: each loaded Java upatch's jar, sealed
 * under JAVA_DIR, and the JAVA_TOOL_OPTIONS that names them.
 */

#ifndef SHIRUDO_UTIL_JAVA_AGENT_H
#define SHIRUDO_UTIL_JAVA_AGENT_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/misc.h>
#include <shirudo/upatch.h>

struct upatch;

/* JAVA_DIR/<name>.jar into buf, or -ENAMETOOLONG. */
int java_agent_path(const char *name, char *buf, size_t cap) __must_check;

/*
 * JAVA_DIR made 0755 and labelled, or, when it is there, checked to be
 * root's, not writable by others, and labelled. 0, -EPERM for one of
 * someone else's making, or -errno.
 */
int __must_check java_agent_dir_prepare(void);

/*
 * The jar of name written sealed, readable by every JVM: JAVA_DIR as
 * java_agent_dir_prepare() leaves it and the jar 0644. 0 or -errno.
 */
int java_agent_install(const char *name, const void *jar,
		       size_t len) __must_check;

/*
 * The jar of name replaced by one a JVM loads as an agent that does
 * nothing: the options a user manager read before still name the jar, and
 * a JVM does not start without it. 0, also when there was no jar.
 */
int java_agent_retire(const char *name) __must_check;

/*
 * The payload digest of the Java upatch loaded under name: its sealed
 * archive is a Java load and its installed jar is the archived one, byte
 * for byte. -ENOENT without such an archive, as when it is foreign,
 * malformed or another kind of upatch, -ESTALE when the jar is missing or
 * another, or another negative errno when that cannot be told.
 */
int java_agent_payload(const char *name,
		       __u8 payload[UPATCH_PAYLOAD_HASH_LEN]) __must_check;

/*
 * Whether java_agent_payload() finds name loaded. A check that cannot run
 * counts as not loaded.
 */
bool java_agent_loaded(const char *name);

/*
 * cb for each Java upatch java_agent_payload() finds loaded, in name
 * order, with its payload digest; a non-zero return of cb ends the walk
 * with that value. 0, or -errno when the jar directory cannot be read.
 */
int java_agents_each_loaded(int (*cb)(const char *name,
				      const __u8 payload[UPATCH_PAYLOAD_HASH_LEN],
				      void *ctx),
			    void *ctx);

/*
 * cb for each jar that is an agent no archive backs: neither the
 * placeholder nor the jar of the Java load archived under its name, as a
 * load stopped before its archive leaves one. Their number, or the first
 * non-zero return of cb, or -errno.
 */
int java_agents_unbacked(int (*cb)(const char *name, void *ctx), void *ctx);

/*
 * The JAVA_TOOL_OPTIONS line of an environment.d file for the n agents,
 * each a -javaagent of its jar, in the order given, NUL-terminated in
 * out. The length, or -E2BIG when it does not fit.
 */
int java_tool_options(const char *const *names, size_t n, char *out,
		      size_t cap) __must_check;

/*
 * The jars and the options brought in line with the archive: a jar whose
 * archive is not a Java load is replaced with the placeholder, and the
 * options name every other jar, the file rewritten only when that changes
 * it and removed when no jar is named. A jar whose archive cannot be read
 * is kept and named. 0, or the first -errno, the rest still done; the
 * options are left alone when the jar directory cannot be read.
 */
int __must_check java_agents_sync(void);

#endif /* SHIRUDO_UTIL_JAVA_AGENT_H */
