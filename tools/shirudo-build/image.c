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
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/rand.h>

#include "bpm.h"
#include "config_image.h"
#include "crypto.h"
#include "hex.h"
#include "image.h"
#include "io.h"
#include "log.h"
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

static int image_output_path(char *path, size_t cap, const char *prefix,
			     const char *suffix)
{
	int n = snprintf(path, cap, "%s%s", prefix, suffix);

	return n < 0 || (size_t)n >= cap ? -ENAMETOOLONG : 0;
}

static int copy_image(int input_fd, int output_fd, __u64 size)
{
	__u8 buf[65536];
	__u64 done = 0;
	size_t want;
	ssize_t n;
	int rc;

	while (done < size) {
		want = size - done < sizeof(buf) ? size - done : sizeof(buf);
		n = read(input_fd, buf, want);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (!n)
			return -EIO;
		rc = write_complete(output_fd, buf, n);
		if (rc)
			return rc;
		done += n;
	}
	do {
		n = read(input_fd, buf, 1);
	} while (n < 0 && errno == EINTR);
	return n < 0 ? -errno : n ? -EFBIG : 0;
}

/* Only the operator invokes veritysetup; inherited FDs pin its inputs. */
static int run_veritysetup(int data_fd, int hash_fd, int root_fd,
			   const struct shirudo_config_image *image)
{
	char root_path[80], data_path[40], hash_path[40], blocks[48];
	char salt[72], root[65];
	pid_t pid;
	int status;

	snprintf(data_path, sizeof(data_path), "/proc/self/fd/%d", data_fd);
	snprintf(hash_path, sizeof(hash_path), "/proc/self/fd/%d", hash_fd);
	snprintf(root_path, sizeof(root_path),
		 "--root-hash-file=/proc/self/fd/%d", root_fd);
	snprintf(blocks, sizeof(blocks), "--data-blocks=%llu",
		 (__u64)image->data_blocks);
	memcpy(salt, "--salt=", 7);
	hex_encode(image->salt, sizeof(image->salt), salt + 7);
	hex_encode(image->root_hash, sizeof(image->root_hash), root);
	pid = fork();
	if (pid < 0)
		return -errno;
	if (!pid) {
		const char *const format_args[] = {
			"veritysetup", "format", "--format=1", "--hash=sha256",
			"--data-block-size=4096", "--hash-block-size=4096",
			"--hash-offset=0", blocks, salt,
			data_path, hash_path, root_path, NULL,
		};
		const char *const verify_args[] = {
			"veritysetup", "verify", "--hash-offset=0",
			data_path, hash_path, root, NULL,
		};
		int null_fd;

		if (fcntl(data_fd, F_SETFD, 0) || fcntl(hash_fd, F_SETFD, 0) ||
		    (root_fd >= 0 && fcntl(root_fd, F_SETFD, 0)))
			_exit(126);
		null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
		if (null_fd < 0 || dup2(null_fd, STDOUT_FILENO) < 0)
			_exit(126);
		close(null_fd);
		execvp("veritysetup", (char *const *)(root_fd >= 0 ?
			format_args : verify_args));
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

static int format_image(int data_fd, int hash_fd, __u64 size,
			const __u8 salt[32],
			struct shirudo_config_image *image)
{
	char root[66];
	ssize_t n;
	int fd, rc;

	*image = (struct shirudo_config_image) {
		.data_blocks = size / SHIRUDO_CONFIG_IMAGE_BLOCK_SIZE,
	};
	memcpy(image->salt, salt, sizeof(image->salt));
	fd = memfd_create("shirudo-verity-root", MFD_CLOEXEC);
	if (fd < 0)
		return -errno;
	rc = run_veritysetup(data_fd, hash_fd, fd, image);
	if (rc)
		goto out;
	do {
		n = pread(fd, root, sizeof(root), 0);
	} while (n < 0 && errno == EINTR);
	if (n != 64 && (n != 65 || root[64] != '\n')) {
		rc = n < 0 ? -errno : -EINVAL;
		goto out;
	}
	rc = shirudo_config_image_read_header(hash_fd, image);
	if (rc)
		goto out;
	root[64] = 0;
	rc = hex_decode(root, image->root_hash,
			sizeof(image->root_hash));
	if (rc)
		goto out;
	rc = shirudo_config_image_check_files(data_fd, hash_fd, image);
out:
	close(fd);
	return rc;
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
		rc = run_veritysetup(image.data_fd, image.hash_fd, -1,
				     &image.image);
	if (!rc)
		puts(root);
out:
	shirudo_config_image_close(&image);
	return rc;
}

static int build_image(const char *input, const char *prefix, const char *pkey,
		       const char *cert, const __u8 salt[32])
{
	static const char *const suffix[] = {".img", ".verity", ".roothash",
					     ".p7s"};
	__u8 signature[SHIRUDO_CONFIG_IMAGE_SIG_MAX];
	struct shirudo_config_image image;
	struct shirudo_sign_io sign = {};
	char paths[4][PATH_MAX], root[65];
	int fds[4] = {-1, -1, -1, -1};
	struct stat st;
	int in = -1, rc;
	__u32 i;

	if (shirudo_build_check_keys(pkey, cert))
		return -EKEYREJECTED;
	for (i = 0; i < 4; i++) {
		rc = image_output_path(paths[i], sizeof(paths[i]), prefix,
				       suffix[i]);
		if (rc)
			return rc;
	}
	in = open(input, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
	if (in < 0)
		return -errno;
	if (fstat(in, &st)) {
		rc = -errno;
		goto out;
	}
	if (!S_ISREG(st.st_mode) || st.st_size <= 0 ||
	    (__u64)st.st_size > SHIRUDO_CONFIG_IMAGE_MAX_BYTES ||
	    st.st_size % SHIRUDO_CONFIG_IMAGE_BLOCK_SIZE) {
		rc = -EINVAL;
		goto out;
	}
	for (i = 0; i < 4; i++) {
		fds[i] = open(paths[i], O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
			      0644);
		if (fds[i] < 0) {
			rc = -errno;
			goto out;
		}
	}
	rc = copy_image(in, fds[0], st.st_size);
	if (!rc)
		rc = format_image(fds[0], fds[1], st.st_size, salt,
				  &image);
	if (rc)
		goto out;
	hex_encode(image.root_hash, sizeof(image.root_hash), root);
	sign.insns = root;
	sign.insns_sz = 64;
	sign.signature = signature;
	sign.signature_sz = sizeof(signature);
	rc = cms_sign(&sign, pkey, cert);
	if (!rc)
		rc = verify_root_signature(root, signature, sign.signature_sz,
					   cert);
	if (!rc)
		rc = write_complete(fds[2], root, 64);
	if (!rc)
		rc = write_complete(fds[3], signature, sign.signature_sz);
	for (i = 0; !rc && i < 4; i++)
		if (fsync(fds[i]))
			rc = -errno;
	if (!rc)
		puts(root);
out:
	if (in >= 0)
		close(in);
	for (i = 0; i < 4; i++) {
		if (fds[i] < 0)
			continue;
		close(fds[i]);
		if (rc)
			unlink(paths[i]);
	}
	return rc;
}

int shirudo_build_image(int argc, char **argv)
{
	const char *pkey = SHIRUDO_SIGNING_KEY_PATH;
	const char *cert = SHIRUDO_CERT_PATH;
	const char *keys_dir = NULL, *salt_hex = NULL;
	const char *input = NULL, *prefix = NULL;
	bool explicit_key = false, explicit_cert = false;
	char pkey_path[PATH_MAX], cert_path[PATH_MAX];
	__u8 salt[SHIRUDO_CONFIG_IMAGE_SALT_SIZE];
	int i, rc;

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
	if (argc < 2 || strcmp(argv[1], "build")) {
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
		} else if (!strcmp(arg, "--salt") && i + 1 < argc) {
			salt_hex = argv[++i];
		} else if (!strcmp(arg, "--kind") && i + 1 < argc) {
			arg = argv[++i];
			if (strcmp(arg, "config") && strcmp(arg, "runtime"))
				return 2;
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
	if (salt_hex) {
		if (strlen(salt_hex) != 64 ||
		    hex_decode(salt_hex, salt, sizeof(salt)))
			return 2;
	} else if (RAND_bytes(salt, sizeof(salt)) != 1) {
		return 1;
	}
	rc = build_image(input, prefix, pkey, cert, salt);
	if (rc)
		pr_err("image build: %s", strerror(-rc));
	return rc ? 1 : 0;
}
