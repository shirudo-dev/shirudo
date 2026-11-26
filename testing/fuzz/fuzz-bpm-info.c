// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm info on a .bee, which it reads unverified: the README, the list of
 * upatches, and the .rodata of each upatch as text and as JSON.
 */

#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "fuzz.h"

#include "../../builtin-bpm.c"

/* The upatches of a package whose .rodata one run prints, at most. */
#define DATA_MEMBERS_MAX	4
/* The size up to which bpm info reads a Beefile. */
#define BEEFILE_MAX		(4u * 1024u * 1024u)

struct data_members {
	char	name[DATA_MEMBERS_MAX][PATH_MAX];
	size_t	n;
};

/* bpm info installs, removes, revokes and forwards nothing. */
int upatch_install(const char *path)
{
	abort();
}

int upatch_remove(const char *path)
{
	abort();
}

int keys_revoke_image(const __u8 *der, size_t size, bool boot)
{
	abort();
}

int keys_revoke_check(void)
{
	abort();
}

bool build_available(void)
{
	abort();
}

int build_forward(const char *label, const char *const words[], int argc,
		  const char **argv)
{
	abort();
}

/* Held for the run, so that bpm info's own init and cleanup only count. */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		abort();
	fuzz_output_capture();
	return 0;
}

/* The upatches by the names the archive has, as a script passes them. */
static int add_data_member(void *ctx, const char *member, char type)
{
	struct data_members *m = ctx;

	if (m->n < DATA_MEMBERS_MAX && type == '0' &&
	    str_has_prefix(member, "upatches/") &&
	    strscpy(m->name[m->n], member, sizeof(m->name[0])) > 0)
		m->n++;
	return 0;
}

static void find_data_members(const char *path, struct data_members *m)
{
	size_t beefile_len = 0;
	__u8 *beefile = NULL;
	char package_dir[101];
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	if (!bpm_pkg_read_member_fd(fd, "Beefile", NULL, package_dir,
				    sizeof(package_dir), &beefile,
				    &beefile_len, BEEFILE_MAX))
		bpm_pkg_visit_members_fd(fd, package_dir, add_data_member, m);
	xfree(beefile, beefile_len + 1);
	close(fd);
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	static struct data_members members;
	const char *member;
	char path[64];
	int fd;

	fd = fuzz_gzip_file(data, size, path, sizeof(path));
	if (fd < 0)
		return 0;
	fuzz_run(bpm_info_cmd, "bpm", "info", path, NULL);
	fuzz_run(bpm_info_cmd, "bpm", "info", "upatches", path, "--all", NULL);
	members.n = 0;
	find_data_members(path, &members);
	for (size_t i = 0; i < members.n; i++) {
		member = members.name[i];
		fuzz_run(bpm_info_cmd, "bpm", "info", "data", path, member, NULL);
		fuzz_run(bpm_info_cmd, "bpm", "info", "data", path, member,
			 "--json", NULL);
	}
	close(fd);
	return 0;
}
