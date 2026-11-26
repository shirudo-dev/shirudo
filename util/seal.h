/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Inode labelling for the bpf/seal.c filesystem-sealing LSM.
 */

#ifndef SHIRUDO_SEAL_H
#define SHIRUDO_SEAL_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

/*
 * The label value: SHA-256 of the xattr name, 64 hex characters, the
 * same for every build. bpf/seal.c takes the label, whatever its value,
 * as marking a protected inode. A runtime task mark authorizes the caller;
 * copying this public label never grants authority.
 */
#define SEAL_LABEL \
	"94442b45cfcdc59aabc2a91364ed2ae129418e05a5c1985231b9c032e673f469"

/* A symlink's own inode, not its target's. Idempotent. */
int seal_label(const char *path);

/*
 * Label writable state before attaching the seal: everything on the
 * first init, nothing afterwards, when an entry without the label or of
 * a kind shirudo never makes is someone else's and is ignored. Stop on
 * the first failed label; partial sealing is an init failure.
 */
int seal_label_tree(bool allow_first);

/*
 * Mark the directories above the state root at root, up to the root of
 * its file system, so that the seal refuses to rename them.
 */
int seal_mark_ancestors(const char *root);

/*
 * Creating under a sealed directory. The directory decides: an inode
 * created under a labelled directory carries that directory's label,
 * which the seal writes inside the transaction that creates it, on the
 * strength of the mark the directory's open leaves. So these helpers
 * open the directory first and hold it open across the creation, which
 * also keeps its inode and the mark on it in memory, and put the label
 * on afterwards where the kernel did not: no seal attached, a file
 * system that takes no xattrs at creation. All return -errno on
 * failure, a sealed inode that could not be labelled included.
 */

int seal_open(const char *path, int flags, mode_t mode);

/* mkdir -p, every directory created labelled as its parent is. */
int seal_mkdir_p(const char *path, mode_t mode);

/*
 * Open an entry of sealed state for reading, as shirudo's own: not
 * through a symbolic link, and under a labelled directory only when it
 * carries that label. -EPERM for a foreign entry.
 */
int seal_open_read(const char *path);

/* Open VAR_LIB itself and require its seal on the opened directory. */
int seal_open_state_root(void);
/* One child of parent, on its mount and carrying its label. */
int seal_open_child(int parent, const char *name, int flags);
/*
 * The same for what an operation makes below a directory it holds open,
 * so that a mount root places there meanwhile is refused, not followed.
 * seal_mkdir_child() makes the directory name, or with exclusive unset
 * takes the one there, and opens it. seal_create_child() opens the
 * regular file name as seal_open() opens a path: made with O_CREAT when
 * it is not there, -EEXIST with O_EXCL when it is, truncated with
 * O_TRUNC once it is known to be shirudo's own.
 */
int seal_mkdir_child(int parent, const char *name, mode_t mode, bool exclusive);
int seal_create_child(int parent, const char *name, int flags, mode_t mode);

/*
 * seal_open_read() of an entry whose directory must carry the label:
 * one of root's making, which no task without authority can label,
 * holds nothing shirudo takes for its own. -EPERM when it does not.
 */
int seal_open_sealed(const char *path);

/* Whether seal_open_read() would succeed. */
bool seal_owns(const char *path);

/* Whether the directory path names an entry of carries the seal label. */
bool seal_parent_labeled(const char *path);

/* Under the caller's lock, stage a new file beside a single child name. */
int seal_replace_locked_at(int parent, const char *name, const void *data, size_t len,
			   mode_t mode);

int seal_write_file(const char *path, const void *data, size_t len,
		    mode_t mode);
/* The same, with exactly that mode whatever the umask, before the rename. */
int seal_write_file_mode(const char *path, const void *data, size_t len,
			 mode_t mode);

/*
 * The lock file at path, created sealed when it is not there, held
 * exclusively until the returned descriptor is closed; or -errno.
 */
int seal_lock(const char *path);

/*
 * line appended as one record to the sealed log at path, created when it
 * is not there, under the lock that keeps its appenders apart; see
 * append_line(). 0 or -errno.
 */
int seal_append_line(const char *path, const char *line, size_t len);

/*
 * Open a file the caller names for shirudo to write: a report, a
 * download, an export. Root may run shirudo with any path, and the seal
 * lets shirudo write what it denies everyone else, so the file must be
 * a regular one that carries no label, not be created under a labelled
 * directory, and not be reached through a symbolic link. The truncation
 * waits until the inode has been checked. -EPERM for a sealed target.
 */
int seal_output_open(const char *path, int flags, mode_t mode);

/*
 * A document and its newline written to such a file, truncated first. A
 * file the write does not complete is removed, but through the directory
 * it was opened in and only while its name still holds the inode that
 * was written: root, who picks the path and can make the write fail,
 * could otherwise point it at sealed state for shirudo to remove.
 * seal_output_create() is 0 or what seal_output_open() refused with;
 * seal_output_commit() closes the file and is 0 or -errno.
 */
struct seal_output {
	int		fd;
	int		dfd;
	const char	*name;
};

int seal_output_create(struct seal_output *out, const char *path,
		       mode_t mode);
int seal_output_commit(struct seal_output *out, const void *buf, size_t len);

/* Give the inode behind fd the label of its directory, open as dfd. */
int seal_inherit(int dfd, int fd);

/* The same by path, without following a symlink. */
int seal_inherit_path(const char *path);

#endif /* SHIRUDO_SEAL_H */
