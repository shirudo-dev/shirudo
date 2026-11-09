// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Prove that tree_fetch_publication() checks the active image's signing set
 * before fetching a tree, and releases the set on every path that allocates it.
 */

#define __NO_CTYPE 1

#include <dirent.h>
#include <ftw.h>
#include <sys/file.h>
#include <zlib.h>
#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "proof.h"
#include "../../../builtin-bpm.c"

static struct trusted_set signing_set;
static bool active, parse_fail, alloc_fail, load_fail, check_fail, fetch_fail;
static bool allocated, loaded, checked, fetched, freed;
static __u32 n_signers, n_unvouched;

int bpm_oci_parse_tree_repo(const char *raw, struct bpm_oci_client *c,
			    char *repository, size_t repository_sz)
{
	__CPROVER_assert(raw[0] == 'e' && repository_sz >= 2,
			 "the configured tree endpoint is parsed");
	if (parse_fail)
		return -EINVAL;
	repository[0] = 'r';
	repository[1] = '\0';
	return 0;
}

void bpm_oci_client_clear(struct bpm_oci_client *c)
{
}

bool image_config_active(void)
{
	return active;
}

void *xcalloc(size_t nmemb, size_t size)
{
	__CPROVER_assert(nmemb == 1 && size == sizeof(signing_set),
			 "the active signing set is allocated");
	if (alloc_fail)
		return NULL;
	allocated = true;
	return &signing_set;
}

const char *get_cert_path(void)
{
	return "cert";
}

int image_config_root_fd(void)
{
	return 7;
}

int keys_load_image_root(const char *primary, int root_fd,
			 bool with_trusted, struct trusted_set *set)
{
	__CPROVER_assert(active && allocated && set == &signing_set &&
			 !strcmp(primary, "cert") && root_fd == 7 &&
			 with_trusted, "the image root supplies the complete set");
	loaded = true;
	set->n = n_signers;
	set->n_unvouched = n_unvouched;
	return load_fail ? -EIO : 0;
}

int keys_check_image_set(const struct trusted_set *set)
{
	__CPROVER_assert(loaded && !load_fail && set == &signing_set &&
			 set->n && !set->n_unvouched,
			 "only a nonempty vouched set is checked");
	checked = true;
	return check_fail ? -EKEYREJECTED : 0;
}

int bpm_tree_fetch_publication(struct bpm_oci_client *c,
			       const char *repository, const char *reference,
			       const char *cert_path,
			       const struct trusted_set *set,
			       struct tree_publication *pub,
			       char *manifest_digest, size_t digest_sz)
{
	__CPROVER_assert(!parse_fail && repository[0] == 'r' &&
			 reference[0] == 'f' && !strcmp(cert_path, "cert") &&
			 digest_sz == BPM_MAX_DIGEST,
			 "fetch uses the configured tree and certificate");
	__CPROVER_assert(!active ||
			 (allocated && loaded && checked && !load_fail &&
			  !check_fail && n_signers && !n_unvouched),
			 "an active image is checked before fetch");
	__CPROVER_assert(set == (active ? &signing_set : NULL),
			 "fetch receives the checked signing set");
	fetched = true;
	return fetch_fail ? -EIO : 0;
}

void xfree(void *p, size_t size)
{
	__CPROVER_assert(!freed && size == sizeof(signing_set) &&
			 p == (allocated ? &signing_set : NULL),
			 "the owned signing set is released once");
	freed = true;
}

void harness(void)
{
	struct bpm_tree_config cfg = {};
	struct tree_publication pub = {};
	struct {
		__u32 signers, unvouched;
		bool active, parse_fail, alloc_fail;
		bool load_fail, check_fail, fetch_fail;
	} input;
	char manifest[BPM_MAX_DIGEST] = {};
	bool should_fetch, should_check, should_free;
	int ret;

	active = input.active;
	parse_fail = input.parse_fail;
	alloc_fail = input.alloc_fail;
	load_fail = input.load_fail;
	check_fail = input.check_fail;
	fetch_fail = input.fetch_fail;
	n_signers = input.signers;
	n_unvouched = input.unvouched;
	__CPROVER_assume(n_signers <= KEYS_MAX && n_unvouched <= n_signers);
	cfg.endpoint[0] = 'e';
	cfg.reference[0] = 'f';
	ret = tree_fetch_publication(&cfg, &pub, manifest, sizeof(manifest));

	should_check = !parse_fail && active && !alloc_fail &&
		       !load_fail && n_signers && !n_unvouched;
	should_fetch = !parse_fail &&
		       (!active || (should_check && !check_fail));
	__CPROVER_assert(loaded == (!parse_fail && active && !alloc_fail),
			 "image keys load only after allocation");
	__CPROVER_assert(checked == should_check,
			 "a valid loaded set is always checked");
	__CPROVER_assert(fetched == should_fetch,
			 "fetch occurs exactly after successful preflight");
	should_free = !parse_fail && (!active || !alloc_fail);
	__CPROVER_assert(freed == should_free,
			 "every allocated set is released");
	if (!should_fetch)
		__CPROVER_assert(ret < 0, "preflight failures refuse the tree");
	else
		__CPROVER_assert(ret == (fetch_fail ? -EIO : 0),
				 "fetch result is returned");
	if (!parse_fail && active && !alloc_fail && !load_fail &&
	    (!n_signers || n_unvouched))
		__CPROVER_assert(ret == -EKEYREJECTED,
				 "empty or unvouched signing sets are refused");
}
