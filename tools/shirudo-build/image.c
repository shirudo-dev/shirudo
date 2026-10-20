// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "bpm.h"
#include "config_image.h"
#include "crypto.h"
#include "hex.h"
#include "image.h"
#include "io.h"
#include "log.h"
#include "malloc.h"
#include "paths.h"
#include "sign.h"

static void image_usage(FILE *fp)
{
	fprintf(fp, "usage: shirudo-build image build <filesystem.img> -o "
		    "<prefix>\n"
		    "       [--kind config|runtime] [--keys-dir <dir>]\n"
		    "       [--key <private.pem>] [--cert <cert.der>] [--salt "
		    "<64-hex>]\n"
		    "Writes <prefix>.img/.verity/.roothash/.p7s; existing files "
		    "are refused.\n"
		    "Input is a 4096-byte-aligned ext4 filesystem image.\n"
		    "       shirudo-build image verify <prefix> --cert <cert.der>\n"
		    "Build and offline verification require veritysetup.\n");
}

static int build_image(int argc, char **argv)
{
	char executable[PATH_MAX], script[PATH_MAX], directory[PATH_MAX];
	char **command;
	ssize_t size;
	char *slash;
	int i, n;

	size = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
	if (size < 0 || (size_t)size >= sizeof(executable) - 1)
		return 1;
	executable[size] = '\0';
	memcpy(directory, executable, size + 1);
	slash = strrchr(directory, '/');
	if (!slash)
		return 1;
	*slash = '\0';
	n = snprintf(script, sizeof(script),
		     "%s/../gen-image/shirudo-gen-verity", directory);
	if (n < 0 || (size_t)n >= sizeof(script))
		return 1;
	if (access(script, X_OK)) {
		n = snprintf(script, sizeof(script),
			     "%s/gen-image/shirudo-gen-verity", directory);
		if (n < 0 || (size_t)n >= sizeof(script))
			return 1;
	}
	command = xcalloc((size_t)argc + 2, sizeof(*command));
	if (!command)
		return 1;
	command[0] = script;
	command[1] = "--builder";
	command[2] = executable;
	for (i = 2; i < argc; i++)
		command[i + 1] = argv[i];
	execv(script, command);
	pr_err("image build: cannot run %s: %s", script, strerror(errno));
	xfree(command, ((size_t)argc + 2) * sizeof(*command));
	return 1;
}

/* Inherited descriptors keep verification on the files we authenticated. */
static int verify_verity(int data_fd, int hash_fd, const char *root)
{
	char data_path[40], hash_path[40];
	pid_t pid;
	int status;

	snprintf(data_path, sizeof(data_path), "/proc/self/fd/%d", data_fd);
	snprintf(hash_path, sizeof(hash_path), "/proc/self/fd/%d", hash_fd);
	pid = fork();
	if (pid < 0)
		return -errno;
	if (!pid) {
		if (fcntl(data_fd, F_SETFD, 0) || fcntl(hash_fd, F_SETFD, 0))
			_exit(126);
		execlp("veritysetup", "veritysetup", "verify", "--hash-offset=0",
		       data_path, hash_path, root, NULL);
		pr_err("veritysetup: %s; install the operator veritysetup tool",
		       strerror(errno));
		_exit(127);
	}
	while (waitpid(pid, &status, 0) < 0)
		if (errno != EINTR)
			return -errno;
	if (!WIFEXITED(status))
		return -EIO;
	if (WEXITSTATUS(status) == 127)
		return -ENOENT;
	return WEXITSTATUS(status) ? -EIO : 0;
}

static int verify_root_signature(const char root[65], const __u8 *signature,
				 size_t size, const char *path)
{
	struct shirudo_cert cert = {};
	char algorithm[32];
	int rc;

	rc = cert_read_file(path, &cert);
	if (!rc)
		rc = cert_key_algorithm(&cert, algorithm,
					sizeof(algorithm));
	if (!rc && strcmp(algorithm, "ML-DSA-87"))
		rc = -EKEYREJECTED;
	if (!rc && cms_signed_by(signature, size, &cert) != 1)
		rc = -EKEYREJECTED;
	if (!rc)
		rc = verify_detached((const __u8 *)root, 64,
				     signature, size, &cert);
	cert_free(&cert);
	return rc;
}

static int verify_image(const char *prefix, const char *cert)
{
	struct shirudo_config_image_open image = {
		.data_fd = -1, .hash_fd = -1, .signature_fd = -1,
	};
	__u8 signature[SHIRUDO_CONFIG_IMAGE_SIG_MAX + 1];
	size_t size = 0;
	char root[65];
	ssize_t n;
	int rc;

	rc = shirudo_config_image_open(prefix, &image);
	if (rc)
		return rc;
	while (size < sizeof(signature)) {
		n = pread(image.signature_fd, signature + size,
			  sizeof(signature) - size, size);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			rc = -errno;
			goto out;
		}
		if (!n)
			break;
		size += n;
	}
	if (!size || size > SHIRUDO_CONFIG_IMAGE_SIG_MAX) {
		rc = -EINVAL;
		goto out;
	}
	hex_encode(image.image.root_hash, sizeof(image.image.root_hash),
		   root);
	rc = verify_root_signature(root, signature, size, cert);
	if (!rc)
		rc = verify_verity(image.data_fd, image.hash_fd, root);
	if (!rc)
		puts(root);
out:
	shirudo_config_image_close(&image);
	return rc;
}

static int sign_root(const char *input, const char *output, const char *pkey,
		     const char *cert)
{
	__u8 signature[SHIRUDO_CONFIG_IMAGE_SIG_MAX];
	struct shirudo_sign_io sign = {};
	char root[65] = {};
	size_t done = 0;
	struct stat st;
	ssize_t size;
	int fd, rc;

	if (shirudo_build_check_keys(pkey, cert))
		return -EKEYREJECTED;
	fd = open(input, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0)
		return -errno;
	rc = fstat(fd, &st) ? -errno : 0;
	if (!rc && (!S_ISREG(st.st_mode) || st.st_size != 64))
		rc = -EINVAL;
	while (!rc && done < 64) {
		size = read(fd, root + done, 64 - done);
		if (size < 0) {
			if (errno != EINTR)
				rc = -errno;
		} else if (!size) {
			rc = -EIO;
		} else {
			done += size;
		}
	}
	close(fd);
	if (rc)
		return rc;
	for (done = 0; done < 64; done++)
		if (!((root[done] >= '0' && root[done] <= '9') ||
		      (root[done] >= 'a' && root[done] <= 'f')))
			return -EINVAL;
	sign.insns = root;
	sign.insns_sz = 64;
	sign.signature = signature;
	sign.signature_sz = sizeof(signature);
	rc = cms_sign(&sign, pkey, cert);
	if (!rc)
		rc = verify_root_signature(root, signature, sign.signature_sz,
					   cert);
	if (rc)
		return rc;
	fd = open(output, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
	if (fd < 0)
		return -errno;
	rc = write_complete(fd, signature, sign.signature_sz);
	if (!rc && fsync(fd))
		rc = -errno;
	close(fd);
	if (rc)
		unlink(output);
	return rc;
}

int shirudo_build_image(int argc, char **argv)
{
	bool explicit_key = false, explicit_cert = false;
	char pkey_path[PATH_MAX], cert_path[PATH_MAX];
	const char *pkey = SHIRUDO_SIGNING_KEY_PATH;
	const char *input = NULL, *prefix = NULL;
	const char *cert = SHIRUDO_CERT_PATH;
	const char *keys_dir = NULL;
	int i, rc;

	if (argc >= 2 && !strcmp(argv[1], "build"))
		return build_image(argc, argv);
	if (argc == 2 && !strcmp(argv[1], "--help")) {
		image_usage(stdout);
		return 0;
	}
	if (argc == 5 && !strcmp(argv[1], "verify") &&
	    !strcmp(argv[3], "--cert")) {
		rc = verify_image(argv[2], argv[4]);
		if (rc)
			pr_err("image verify: %s", strerror(-rc));
		return rc ? 1 : 0;
	}
	if (argc < 2 || strcmp(argv[1], "sign-root")) {
		image_usage(stderr);
		return 2;
	}
	for (i = 2; i < argc; i++) {
		const char *arg = argv[i];

		if (!strcmp(arg, "--help")) {
			image_usage(stdout);
			return 0;
		}
		if (!strcmp(arg, "-o") && i + 1 < argc) {
			prefix = argv[++i];
		} else if (!strcmp(arg, "--keys-dir") && i + 1 < argc) {
			keys_dir = argv[++i];
		} else if (!strcmp(arg, "--key") && i + 1 < argc) {
			pkey = argv[++i];
			explicit_key = true;
		} else if (!strcmp(arg, "--cert") && i + 1 < argc) {
			cert = argv[++i];
			explicit_cert = true;
		} else if (arg[0] != '-' && !input) {
			input = arg;
		} else {
			image_usage(stderr);
			return 2;
		}
	}
	if (!input || !prefix || !*prefix)
		return 2;
	keys_dir = keys_dir_resolve(keys_dir);
	if (keys_dir) {
		rc = key_paths(keys_dir, pkey_path, sizeof(pkey_path),
			       cert_path, sizeof(cert_path));
		if (rc)
			return 2;
		if (!explicit_key)
			pkey = pkey_path;
		if (!explicit_cert)
			cert = cert_path;
	}
	rc = sign_root(input, prefix, pkey, cert);
	if (rc)
		pr_err("image sign-root: %s", strerror(-rc));
	return rc ? 1 : 0;
}
