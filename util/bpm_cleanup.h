/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_BPM_CLEANUP_H
#define SHIRUDO_BPM_CLEANUP_H

struct bpm_state_entry;

/* Remove one directory below parent without crossing a mount. */
int bpm_pkg_remove_at(int parent, const char *name);
/* Unload the active version, then retire the complete package directory. */
int bpm_uninstall_at(int store, const struct bpm_state_entry *st);

#endif /* SHIRUDO_BPM_CLEANUP_H */
