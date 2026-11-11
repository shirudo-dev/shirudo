/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What a publisher can tell about the nodes two operations of an upatch
 * tree reach, from their selectors alone.
 */

#ifndef SHIRUDO_BPM_TREE_OVERLAP_H
#define SHIRUDO_BPM_TREE_OVERLAP_H

#include <stdbool.h>

struct tree_publication;
struct tree_selector;

/*
 * Whether no node matches both selectors: they name different
 * architectures, kernel builds or releases, or different values for one
 * label or kernel option. False is no proof of a shared node.
 */
bool tree_selectors_disjoint(const struct tree_selector *a,
			     const struct tree_selector *b);

/*
 * Whether the add at index may still be loaded somewhere: no later
 * delete of its upatch reaches every node the add reaches.
 */
bool tree_add_live(const struct tree_publication *pub, int index);

#endif /* SHIRUDO_BPM_TREE_OVERLAP_H */
