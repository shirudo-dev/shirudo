/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_BPM_INSTALL_H
#define SHIRUDO_BPM_INSTALL_H

#include <stdbool.h>

#include "bpm_oci.h"

/*
 * One install of a package version. What it reads and writes it reaches
 * from directories it opens once, below the state root the caller
 * checked: the package's directory in the store, the version it
 * extracts and the archive it stages. A mount or a foreign entry placed
 * under the state root meanwhile fails the install; it is not followed.
 */
struct bpm_install {
	const char	*name;
	const char	*version;
	int		staging;
	int		package;
	int		dir;		/* of the version, once extracted */
	int		archive;
	bool		extracted;	/* the version directory is this install's */
	char		archive_name[2 * BPM_MAX_NAME + 8];
};

/*
 * Open the package's directory and a new, empty archive for an install
 * of name at version, below the state root open as root. 0 or -errno;
 * bpm_install_close() ends the install either way.
 */
int bpm_install_open(struct bpm_install *in, int root, const char *name,
		     const char *version);
/*
 * Unpack the archive, which the caller has written and checked through
 * in->archive, into the version's directory. -EEXIST, with that
 * directory left as it is, when the version is there already.
 */
int bpm_install_extract(struct bpm_install *in);
/* A file at the top of the extracted version, open for reading. */
int bpm_install_member(const struct bpm_install *in, const char *name);
/*
 * Unload what old_version of the package loaded, when it is set, by its
 * directives in reverse name order, then load the members of the new
 * version in name order. A failure undoes the loads made and loads the
 * old version again.
 */
int bpm_install_load(const struct bpm_install *in, const char *old_version);
/*
 * End the install with err: 0 keeps the archive beside the versions,
 * anything else removes it and the version this install extracted.
 * Closes what the install holds and returns err.
 */
int bpm_install_close(struct bpm_install *in, int err);

#endif /* SHIRUDO_BPM_INSTALL_H */
