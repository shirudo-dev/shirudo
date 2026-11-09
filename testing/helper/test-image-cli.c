// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include "../../builtin-bpm.c"
#include "util/config.h"

#include "image-cli.h"

int __wrap_bpm_tree_fetch_publication(struct bpm_oci_client *client,
				      const char *repository,
				      const char *reference,
				      const char *certificate,
				      const struct trusted_set *trusted,
				      struct tree_publication *pub,
				      char *digest, size_t capacity)
{
	puts(certificate);
	return 0;
}

int __wrap_keys_load_image_root(const char *primary, int root_fd,
				bool with_trusted, struct trusted_set *set)
{
	set->n = 1;
	return 0;
}

int __wrap_keys_check_image_set(const struct trusted_set *set)
{
	return set->n == 1 ? 0 : -EINVAL;
}

int main(int argc, const char **argv)
{
	struct config bootstrap;
	int fd, ret;

	if (argc < 3)
		return 2;
	fd = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return 1;
	ret = config_load_path(&bootstrap, "/dev/null");
	if (!ret) {
		memcpy(bootstrap.tpm_owner_auth, "bootstrap-owner", 15);
		bootstrap.tpm_owner_auth_len = 15;
		strscpy(bootstrap.tpm_tcti, "bootstrap-tcti", sizeof(bootstrap.tpm_tcti));
		ret = image_config_set(&bootstrap, fd);
	}
	close(fd);
	if (ret)
		return 1;
	if (!strcmp(argv[2], "bpm")) {
		ret = cmd_bpm(argc - 2, argv + 2);
	} else if (!strcmp(argv[2], "keys")) {
		ret = cmd_keys(argc - 2, argv + 2);
	} else if (!strcmp(argv[2], "config")) {
		ret = cmd_config(argc - 2, argv + 2);
	} else if (!strcmp(argv[2], "source") && argc == 4) {
		struct bpm_source source;

		ret = load_source(argv[3], &source);
		if (!ret) {
			char content[64];
			int kfd = image_open_relative(source.key_file,
						      O_RDONLY);
			FILE *file = kfd < 0 ? NULL : fdopen(kfd, "r");

			if (!file) {
				ret = kfd < 0 ? kfd : -errno;
				if (kfd >= 0)
					close(kfd);
			} else {
				if (!fgets(content, sizeof(content), file))
					ret = -EIO;
				else
					fputs(content, stdout);
				fclose(file);
			}
		}
	} else if (!strcmp(argv[2], "tree")) {
		struct tree_publication publication = {};
		struct bpm_tree_config config = {};
		char digest[BPM_MAX_DIGEST];

		strscpy(config.endpoint, "oci://example.invalid/tree", sizeof(config.endpoint));
		strscpy(config.reference, "latest", sizeof(config.reference));
		ret = tree_fetch_publication(&config, &publication, digest,
					     sizeof(digest));
	} else {
		ret = 2;
	}
	image_config_clear();
	return ret ? 1 : 0;
}
