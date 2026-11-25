// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>
#include <shirudo/string.h>

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
#include "help.h"
#include "log.h"
#include "options.h"
#include "malloc.h"
#include "paths.h"
#include "sign.h"

enum image_verify_opt {
	IMAGE_VERIFY_CERT,
};

static const struct opt_spec image_verify_opts[] = {
	[IMAGE_VERIFY_CERT] = { "--cert", 0, 0, "<cert.der>",
		"the certificate the image's root hash is signed for" },
};

enum image_sign_opt {
	IMAGE_SIGN_OUTPUT,
	IMAGE_SIGN_KEYS_DIR,
	IMAGE_SIGN_KEY,
	IMAGE_SIGN_CERT,
};

static const struct opt_spec image_sign_opts[] = {
	[IMAGE_SIGN_OUTPUT] = { "--output", 'o', 0, "<signature>",
		"where to write the signature" },
	[IMAGE_SIGN_KEYS_DIR] = { "--keys-dir", 0, 0, "<dir>",
		"read signing_key.pem and cert.der from <dir>" },
	[IMAGE_SIGN_KEY] = { "--key", 0, 0, "<private.pem>",
		"the signing key, over --keys-dir" },
	[IMAGE_SIGN_CERT] = { "--cert", 0, 0, "<cert.der>",
		"the certificate, over --keys-dir" },
};

static const struct help_section image_sections[] = {
	HELP_OPTIONS("verify options:", image_verify_opts),
};

static const struct help image_help = {
	.usage	    = "shirudo image build <filesystem.img> -o <prefix> "
		      "[--kind config|runtime]\n"
		      "                     [--keys-dir <dir>] "
		      "[--key <private.pem>] [--cert <cert.der>]\n"
		      "                     [--salt <64-hex>]\n"
		      "       shirudo image verify <prefix> --cert <cert.der>",
	.summary    = "build writes <prefix>.img, .verity, .roothash and .p7s "
		      "from a 4096-byte\naligned ext4 file system image and "
		      "refuses files that exist. Build and\noffline "
		      "verification require veritysetup.",
	.sections   = image_sections,
	.n_sections = ARRAY_SIZE(image_sections),
};

static int __build_image(int argc, const char **argv)
{
	char executable[PATH_MAX], script[PATH_MAX], directory[PATH_MAX];
	const char **command;
	ssize_t size;
	char *slash;
	int i;

	size = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
	if (size < 0 || (size_t)size >= sizeof(executable) - 1)
		return 1;
	executable[size] = '\0';
	memcpy(directory, executable, size + 1);
	slash = strrchr(directory, '/');
	if (!slash)
		return 1;
	*slash = '\0';
	if (strsprintf(script, sizeof(script),
		       "%s/../gen-image/shirudo-gen-verity", directory) < 0)
		return 1;
	if (access(script, X_OK) &&
	    strsprintf(script, sizeof(script),
		       "%s/gen-image/shirudo-gen-verity", directory) < 0)
		return 1;
	command = xcalloc((size_t)argc + 2, sizeof(*command));
	if (!command)
		return 1;
	command[0] = script;
	command[1] = "--builder";
	command[2] = executable;
	for (i = 2; i < argc; i++)
		command[i + 1] = argv[i];
	execv(script, (char *const *)command);
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

	if (strsprintf(data_path, sizeof(data_path), "/proc/self/fd/%d",
		       data_fd) < 0 ||
	    strsprintf(hash_path, sizeof(hash_path), "/proc/self/fd/%d",
		       hash_fd) < 0)
		return -ENAMETOOLONG;
	pid = fork();
	if (pid < 0)
		return -errno;
	if (!pid) {
		if (fcntl(data_fd, F_SETFD, 0) || fcntl(hash_fd, F_SETFD, 0))
			_exit(126);
		execlp("veritysetup", "veritysetup", "verify", "--hash-offset=0",
		       data_path, hash_path, root, (char *)NULL);
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
	struct cert cert = {};
	int ret;

	ret = cert_read_file(path, &cert);
	if (!ret)
		ret = cert_require_mldsa87(&cert, NULL, 0);
	if (!ret && cms_signed_by(signature, size, &cert) != 1)
		ret = -EKEYREJECTED;
	if (!ret)
		ret = verify_detached((const __u8 *)root, 64,
				      signature, size, &cert);
	cert_free(&cert);
	return ret;
}

static int verify_image(const char *prefix, const char *cert)
{
	struct config_image_open image = {
		.data_fd = -1, .hash_fd = -1, .signature_fd = -1,
	};
	__u8 signature[CONFIG_IMAGE_SIG_MAX + 1];
	size_t size = 0;
	char root[65];
	ssize_t n;
	int ret;

	ret = config_image_open(prefix, &image);
	if (ret)
		return ret;
	while (size < sizeof(signature)) {
		n = pread(image.signature_fd, signature + size,
			  sizeof(signature) - size, size);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			ret = -errno;
			goto out;
		}
		if (!n)
			break;
		size += n;
	}
	if (!size || size > CONFIG_IMAGE_SIG_MAX) {
		ret = -EINVAL;
		goto out;
	}
	hex_encode(image.image.root_hash, sizeof(image.image.root_hash),
		   root);
	ret = verify_root_signature(root, signature, size, cert);
	if (!ret)
		ret = verify_verity(image.data_fd, image.hash_fd, root);
	if (!ret)
		puts(root);
out:
	config_image_close(&image);
	return ret;
}

static int sign_root(const char *input, const char *output, const char *pkey,
		     const char *cert)
{
	__u8 signature[CONFIG_IMAGE_SIG_MAX];
	struct sign_io sign = {};
	char root[65] = {};
	size_t done = 0;
	struct stat st;
	ssize_t size;
	int fd, ret;

	if (build_check_keys(pkey, cert))
		return -EKEYREJECTED;
	fd = open(input, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0)
		return -errno;
	ret = fstat(fd, &st) ? -errno : 0;
	if (!ret && (!S_ISREG(st.st_mode) || st.st_size != 64))
		ret = -EINVAL;
	while (!ret && done < 64) {
		size = read(fd, root + done, 64 - done);
		if (size < 0) {
			if (errno != EINTR)
				ret = -errno;
		} else if (!size) {
			ret = -EIO;
		} else {
			done += size;
		}
	}
	close(fd);
	if (ret)
		return ret;
	if (!hex_is_lower(root, 64))
		return -EINVAL;
	sign.insns = root;
	sign.insns_sz = 64;
	sign.signature = signature;
	sign.signature_sz = sizeof(signature);
	ret = cms_sign(&sign, pkey, cert);
	if (!ret)
		ret = verify_root_signature(root, signature, sign.signature_sz,
					    cert);
	if (ret)
		return ret;
	fd = open(output, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
	if (fd < 0)
		return -errno;
	ret = write_complete(fd, signature, sign.signature_sz);
	if (!ret && fsync(fd))
		ret = -errno;
	close(fd);
	if (ret)
		unlink(output);
	return ret;
}

static int image_verify_cmd(int argc, const char **argv)
{
	const char *prefix = NULL, *cert = NULL;
	struct opt_parser p;
	int opt, ret;

	OPT_INIT(&p, "image verify", image_verify_opts, &image_help, argc,
		 argv, 2);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case IMAGE_VERIFY_CERT:
			cert = p.value;
			break;
		case OPT_ARG:
			if (prefix) {
				opt_usage(&p, "unexpected argument '%s'",
					  p.value);
				return EXIT_USAGE;
			}
			prefix = p.value;
			break;
		case OPT_DONE:
			return 0;
		default:
			return EXIT_USAGE;
		}
	}
	if (!prefix || !cert) {
		opt_usage(&p, "takes <prefix> and --cert <cert.der>");
		return EXIT_USAGE;
	}
	ret = verify_image(prefix, cert);
	if (ret)
		pr_err("image verify: %s", strerror(-ret));
	return ret ? 1 : 0;
}

/* What shirudo-gen-verity calls back with for the root hash it made. */
static int image_sign_root_cmd(int argc, const char **argv)
{
	char pkey_path[PATH_MAX], cert_path[PATH_MAX];
	const char *input = NULL, *signature = NULL;
	const char *pkey = SIGNING_KEY_PATH;
	const char *cert = CERT_PATH;
	const char *keys_dir = NULL;
	struct opt_parser p;
	int opt, ret;

	OPT_INIT(&p, "image sign-root", image_sign_opts, NULL, argc, argv, 2);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case IMAGE_SIGN_OUTPUT:
			signature = p.value;
			break;
		case IMAGE_SIGN_KEYS_DIR:
			keys_dir = p.value;
			break;
		case IMAGE_SIGN_KEY:
			pkey = p.value;
			break;
		case IMAGE_SIGN_CERT:
			cert = p.value;
			break;
		case OPT_ARG:
			if (input) {
				opt_usage(&p, "unexpected argument '%s'",
					  p.value);
				return EXIT_USAGE;
			}
			input = p.value;
			break;
		case OPT_DONE:
			return 0;
		default:
			return EXIT_USAGE;
		}
	}
	if (!input || !signature) {
		opt_usage(&p, "takes <root-hash-file> and -o <signature>");
		return EXIT_USAGE;
	}
	keys_dir = keys_dir_resolve(keys_dir);
	if (keys_dir) {
		ret = key_paths(keys_dir, pkey_path, sizeof(pkey_path),
				cert_path, sizeof(cert_path));
		if (ret)
			return EXIT_USAGE;
		if (!opt_given(&p, IMAGE_SIGN_KEY))
			pkey = pkey_path;
		if (!opt_given(&p, IMAGE_SIGN_CERT))
			cert = cert_path;
	}
	ret = sign_root(input, signature, pkey, cert);
	if (ret)
		pr_err("image sign-root: %s", strerror(-ret));
	return ret ? 1 : 0;
}

int build_image(int argc, const char **argv)
{
	if (argc >= 2 && !strcmp(argv[1], "build"))
		return __build_image(argc, argv);
	if (argc < 2 || is_help(argv[1])) {
		print_help(&image_help);
		return argc < 2 ? EXIT_USAGE : 0;
	}
	if (!strcmp(argv[1], "verify"))
		return image_verify_cmd(argc, argv);
	if (!strcmp(argv[1], "sign-root"))
		return image_sign_root_cmd(argc, argv);
	pr_err("image: '%s' is not a subcommand", argv[1]);
	return EXIT_USAGE;
}
