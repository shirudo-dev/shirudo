// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Which operations of an upatch tree can meet on one node, for the
 * checks `bpm tree append` makes before it signs a publication.
 */

#include <stdbool.h>
#include <string.h>

#include "bpm_tree.h"
#include "bpm_tree_overlap.h"
#include "kernel_release.h"

static bool list_holds(const char (*list)[TREE_STRING_MAX], int n,
		       const char *value)
{
	for (int i = 0; i < n; i++)
		if (!strcmp(list[i], value))
			return true;
	return false;
}

static bool lists_share(const char (*a)[TREE_STRING_MAX], int na,
			const char (*b)[TREE_STRING_MAX], int nb)
{
	for (int i = 0; i < na; i++)
		if (list_holds(b, nb, a[i]))
			return true;
	return false;
}

static bool list_within(const char (*inner)[TREE_STRING_MAX], int n_inner,
			const char (*outer)[TREE_STRING_MAX], int n_outer)
{
	for (int i = 0; i < n_inner; i++)
		if (!list_holds(outer, n_outer, inner[i]))
			return false;
	return true;
}

/*
 * Two prefixes take a common release exactly when one takes the other
 * read as a release: every release the longer takes continues it.
 */
static bool prefixes_share(const char (*a)[TREE_STRING_MAX], int na,
			   const char (*b)[TREE_STRING_MAX], int nb)
{
	for (int i = 0; i < na; i++)
		for (int j = 0; j < nb; j++)
			if (kernel_release_prefix_matches(a[i], b[j]) ||
			    kernel_release_prefix_matches(b[j], a[i]))
				return true;
	return false;
}

static bool prefixes_within(const char (*inner)[TREE_STRING_MAX], int n_inner,
			    const char (*outer)[TREE_STRING_MAX], int n_outer)
{
	for (int i = 0; i < n_inner; i++) {
		bool taken = false;

		for (int j = 0; j < n_outer && !taken; j++)
			taken = kernel_release_prefix_matches(inner[i],
							      outer[j]);
		if (!taken)
			return false;
	}
	return true;
}

/* A node has one value for a key. */
static bool kvs_exclude(const struct tree_selector_kv *a, int na,
			const struct tree_selector_kv *b, int nb)
{
	for (int i = 0; i < na; i++)
		for (int j = 0; j < nb; j++)
			if (!strcmp(a[i].key, b[j].key) &&
			    !lists_share(a[i].values, a[i].n_values,
					 b[j].values, b[j].n_values))
				return true;
	return false;
}

static bool kvs_within(const struct tree_selector_kv *inner, int n_inner,
		       const struct tree_selector_kv *outer, int n_outer)
{
	for (int j = 0; j < n_outer; j++) {
		bool held = false;

		for (int i = 0; i < n_inner && !held; i++)
			held = !strcmp(inner[i].key, outer[j].key) &&
			       list_within(inner[i].values, inner[i].n_values,
					   outer[j].values, outer[j].n_values);
		if (!held)
			return false;
	}
	return true;
}

bool tree_selectors_disjoint(const struct tree_selector *a,
			     const struct tree_selector *b)
{
	if (a->n_architecture && b->n_architecture &&
	    !lists_share(a->architecture, a->n_architecture,
			 b->architecture, b->n_architecture))
		return true;
	if (a->n_kernel_build_id && b->n_kernel_build_id &&
	    !lists_share(a->kernel_build_id, a->n_kernel_build_id,
			 b->kernel_build_id, b->n_kernel_build_id))
		return true;
	if (a->n_kernel_release_prefix && b->n_kernel_release_prefix &&
	    !prefixes_share(a->kernel_release_prefix,
			    a->n_kernel_release_prefix,
			    b->kernel_release_prefix,
			    b->n_kernel_release_prefix))
		return true;
	return kvs_exclude(a->kconfig, a->n_kconfig, b->kconfig, b->n_kconfig) ||
	       kvs_exclude(a->labels, a->n_labels, b->labels, b->n_labels);
}

/* An empty list of outer constrains nothing, one of inner everything. */
static bool selector_covers(const struct tree_selector *outer,
			    const struct tree_selector *inner)
{
	if (outer->n_architecture &&
	    (!inner->n_architecture ||
	     !list_within(inner->architecture, inner->n_architecture,
			  outer->architecture, outer->n_architecture)))
		return false;
	if (outer->n_kernel_build_id &&
	    (!inner->n_kernel_build_id ||
	     !list_within(inner->kernel_build_id, inner->n_kernel_build_id,
			  outer->kernel_build_id, outer->n_kernel_build_id)))
		return false;
	if (outer->n_kernel_release_prefix &&
	    (!inner->n_kernel_release_prefix ||
	     !prefixes_within(inner->kernel_release_prefix,
			      inner->n_kernel_release_prefix,
			      outer->kernel_release_prefix,
			      outer->n_kernel_release_prefix)))
		return false;
	return kvs_within(inner->kconfig, inner->n_kconfig,
			  outer->kconfig, outer->n_kconfig) &&
	       kvs_within(inner->labels, inner->n_labels,
			  outer->labels, outer->n_labels);
}

bool tree_add_live(const struct tree_publication *pub, int index)
{
	const struct tree_operation *add = &pub->operations[index];

	for (int i = index + 1; i < pub->n_operations; i++) {
		const struct tree_operation *later = &pub->operations[i];

		if (!strcmp(later->op, "delete") &&
		    !strcmp(later->id, add->id) &&
		    selector_covers(&later->selector, &add->selector))
			return false;
	}
	return true;
}
