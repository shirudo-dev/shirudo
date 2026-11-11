// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/string.h>

#include "bpm_tree.h"
#include "bpm_tree_overlap.h"
#include "unit.h"

static void set(char *dst, size_t cap, const char *src)
{
	ASSERT_TRUE(strscpy(dst, src, cap) >= 0);
}

static void pair(struct tree_selector_kv **kvs, int *n, const char *key,
		 const char *first, const char *second)
{
	struct tree_selector_kv *kv;

	ASSERT_EQ(tree_selector_kv_add(kvs, n, TREE_MAX_LABELS, &kv), 0);
	set(kv->key, sizeof(kv->key), key);
	set(kv->values[kv->n_values++], TREE_STRING_MAX, first);
	if (second)
		set(kv->values[kv->n_values++], TREE_STRING_MAX, second);
}

static void label(struct tree_selector *s, const char *key, const char *first,
		  const char *second)
{
	pair(&s->labels, &s->n_labels, key, first, second);
}

static void an_unconstrained_selector_shares_every_node(void)
{
	static struct tree_selector any, some;

	set(some.architecture[some.n_architecture++], TREE_STRING_MAX, "x86_64");
	label(&some, "site", "a", NULL);
	EXPECT_FALSE(tree_selectors_disjoint(&any, &any));
	EXPECT_FALSE(tree_selectors_disjoint(&any, &some));
	EXPECT_FALSE(tree_selectors_disjoint(&some, &any));
	tree_selector_free(&some);
}

static void lists_without_a_common_value_are_disjoint(void)
{
	static struct tree_selector a, b;

	set(a.architecture[a.n_architecture++], TREE_STRING_MAX, "x86_64");
	set(b.architecture[b.n_architecture++], TREE_STRING_MAX, "aarch64");
	EXPECT_TRUE(tree_selectors_disjoint(&a, &b));
	set(b.architecture[b.n_architecture++], TREE_STRING_MAX, "x86_64");
	EXPECT_FALSE(tree_selectors_disjoint(&a, &b));
	set(a.kernel_build_id[a.n_kernel_build_id++], TREE_STRING_MAX, "aa");
	EXPECT_FALSE(tree_selectors_disjoint(&a, &b));
	set(b.kernel_build_id[b.n_kernel_build_id++], TREE_STRING_MAX, "bb");
	EXPECT_TRUE(tree_selectors_disjoint(&a, &b));
}

/* 7.1 takes 7.1.3 and not 7.10.0, as the node reads a prefix. */
static void release_prefixes_meet_where_one_continues_the_other(void)
{
	static struct tree_selector a, b;

	set(a.kernel_release_prefix[a.n_kernel_release_prefix++],
	    TREE_STRING_MAX, "7.1");
	set(b.kernel_release_prefix[b.n_kernel_release_prefix++],
	    TREE_STRING_MAX, "7.10");
	EXPECT_TRUE(tree_selectors_disjoint(&a, &b));
	EXPECT_TRUE(tree_selectors_disjoint(&b, &a));
	set(b.kernel_release_prefix[0], TREE_STRING_MAX, "7.1.3");
	EXPECT_FALSE(tree_selectors_disjoint(&a, &b));
	EXPECT_FALSE(tree_selectors_disjoint(&b, &a));
	set(b.kernel_release_prefix[0], TREE_STRING_MAX, "7");
	EXPECT_FALSE(tree_selectors_disjoint(&a, &b));
}

static void a_key_with_other_values_is_disjoint(void)
{
	static struct tree_selector a, b, other_key, both;

	label(&a, "site", "a", NULL);
	label(&b, "site", "b", NULL);
	label(&other_key, "env", "b", NULL);
	label(&both, "site", "b", "a");
	EXPECT_TRUE(tree_selectors_disjoint(&a, &b));
	EXPECT_FALSE(tree_selectors_disjoint(&a, &other_key));
	EXPECT_FALSE(tree_selectors_disjoint(&a, &both));
	pair(&a.kconfig, &a.n_kconfig, "CONFIG_PREEMPT", "y", NULL);
	pair(&both.kconfig, &both.n_kconfig, "CONFIG_PREEMPT", "n", NULL);
	EXPECT_TRUE(tree_selectors_disjoint(&a, &both));
	tree_selector_free(&a);
	tree_selector_free(&b);
	tree_selector_free(&other_key);
	tree_selector_free(&both);
}

static struct tree_operation *operation(struct tree_publication *pub,
					const char *op, const char *id)
{
	static struct tree_operation blank;

	set(blank.op, sizeof(blank.op), op);
	set(blank.id, sizeof(blank.id), id);
	ASSERT_EQ(tree_publication_append(pub, &blank), 0);
	return &pub->operations[pub->n_operations - 1];
}

/* A delete that leaves the upatch on some node the add reached keeps it. */
static void an_add_lives_until_a_delete_reaches_all_its_nodes(void)
{
	struct tree_publication pub = {};
	struct tree_operation *op;

	operation(&pub, "delete", "x");
	op = operation(&pub, "add", "x");
	label(&op->selector, "site", "a", "b");
	EXPECT_TRUE(tree_add_live(&pub, 1));

	operation(&pub, "delete", "y");
	EXPECT_TRUE(tree_add_live(&pub, 1));
	operation(&pub, "add", "x");
	EXPECT_TRUE(tree_add_live(&pub, 1));

	op = operation(&pub, "delete", "x");
	label(&op->selector, "site", "a", NULL);
	EXPECT_TRUE(tree_add_live(&pub, 1));

	op = operation(&pub, "delete", "x");
	label(&op->selector, "site", "a", "b");
	set(op->selector.architecture[op->selector.n_architecture++],
	    TREE_STRING_MAX, "x86_64");
	EXPECT_TRUE(tree_add_live(&pub, 1));

	op = operation(&pub, "delete", "x");
	label(&op->selector, "site", "b", "a");
	EXPECT_FALSE(tree_add_live(&pub, 1));
	EXPECT_TRUE(tree_add_live(&pub, 3));
	pub.n_operations--;
	EXPECT_TRUE(tree_add_live(&pub, 1));

	operation(&pub, "delete", "x");
	EXPECT_FALSE(tree_add_live(&pub, 1));
	EXPECT_FALSE(tree_add_live(&pub, 3));
	tree_publication_free(&pub);
}

static const struct unit_case cases[] = {
	UNIT_CASE(an_unconstrained_selector_shares_every_node),
	UNIT_CASE(lists_without_a_common_value_are_disjoint),
	UNIT_CASE(release_prefixes_meet_where_one_continues_the_other),
	UNIT_CASE(a_key_with_other_values_is_disjoint),
	UNIT_CASE(an_add_lives_until_a_delete_reaches_all_its_nodes),
	{}
};

UNIT_SUITE(bpm_tree_overlap, cases);
