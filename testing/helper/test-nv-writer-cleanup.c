// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <linux/keyctl.h>

#include "../../builtin-init.c"
#include "../fixtures/nv-writer-fault.h"

const __u8 *__wrap_shirudo_image_runtime_root(void);

/* The injected failure precedes runtime mounting and guard attachment. */
const __u8 *__wrap_shirudo_image_runtime_root(void)
{
	static const __u8 root[32] = { 1 };

	return root;
}

struct ring_snapshot {
	key_serial_t keys[256];
	long bytes;
};

static int serial_order(const void *a, const void *b)
{
	key_serial_t right = *(const key_serial_t *)b;
	key_serial_t left = *(const key_serial_t *)a;

	return (left > right) - (left < right);
}

static int snapshot(key_serial_t ring, struct ring_snapshot *out)
{
	out->bytes = syscall(__NR_keyctl, KEYCTL_READ, ring, out->keys,
			     sizeof(out->keys), 0);
	if (out->bytes < 0)
		return -errno;
	if ((size_t)out->bytes > sizeof(out->keys) ||
	    out->bytes % sizeof(out->keys[0]))
		return -EOVERFLOW;
	qsort(out->keys, out->bytes / sizeof(out->keys[0]),
	      sizeof(out->keys[0]), serial_order);
	return 0;
}

static int unchanged(key_serial_t ring, const struct ring_snapshot *before)
{
	struct ring_snapshot after = {};
	int rc;

	rc = snapshot(ring, &after);
	if (rc)
		return rc;
	if (before->bytes != after.bytes ||
	    memcmp(before->keys, after.keys, before->bytes)) {
		fprintf(stderr, "keyring %d changed: before %ld bytes, after %ld bytes\n",
			ring, before->bytes, after.bytes);
		return -EUCLEAN;
	}
	return 0;
}

static int contains(key_serial_t parent, key_serial_t ring)
{
	struct ring_snapshot state = {};
	size_t i;
	int rc;

	rc = snapshot(parent, &state);
	if (rc)
		return rc;
	for (i = 0; i < (size_t)state.bytes / sizeof(state.keys[0]); i++)
		if (state.keys[i] == ring)
			return 0;
	return -ENOKEY;
}

static int enroll(const char *path)
{
	__u8 *der = NULL;
	size_t len = 0;
	int rc;

	rc = read_der(path, &der, &len);
	if (rc)
		return rc;
	rc = keyring_bpf_add_cert(der, len);
	xfree(der, len);
	return rc < 0 ? rc : keyring_bpf_seal();
}

static int exercise(const char *mode, const char *object)
{
	struct bpf_link *import_link = NULL, *map_link = NULL;
	struct ring_snapshot user = {}, session = {};
	__u8 public[SHIRUDO_TPM_NV_RSA_BYTES] = {};
	__u8 signature[SHIRUDO_TPM_NV_RSA_BYTES];
	key_serial_t ring = -1, writer = -1;
	struct nv_writer_fault state = {};
	struct bpf_object *obj = NULL;
	struct bpf_program *program;
	int rc, result, fd = -1;
	__u8 digest[32] = {};
	__u32 zero = 0;

	rc = snapshot(KEY_SPEC_USER_KEYRING, &user);
	if (!rc)
		rc = snapshot(KEY_SPEC_SESSION_KEYRING, &session);
	if (rc)
		return rc;
	if (object) {
		state.pid = getpid();
		state.fail_import = !strcmp(mode, "import");
		if (!strcmp(mode, "update"))
			state.command = BPF_MAP_UPDATE_ELEM;
		else if (!strcmp(mode, "freeze"))
			state.command = BPF_MAP_FREEZE;
		obj = bpf_object__open_file(object, NULL);
		rc = libbpf_get_error(obj);
		if (rc)
			return rc;
		rc = bpf_object__load(obj);
		if (rc)
			goto out;
		fd = bpf_object__find_map_fd_by_name(obj, "fault");
		if (fd < 0 || bpf_map_update_elem(fd, &zero, &state, BPF_ANY)) {
			rc = fd < 0 ? fd : -errno;
			goto out;
		}
		program = bpf_object__find_program_by_name(obj, "fail_writer_import");
		if (!program) {
			rc = -ENOENT;
			goto out;
		}
		import_link = bpf_program__attach_lsm(program);
		rc = libbpf_get_error(import_link);
		if (rc)
			goto out;
		program = bpf_object__find_program_by_name(obj, "fail_writer_map");
		if (!program) {
			rc = -ENOENT;
			goto out;
		}
		map_link = bpf_program__attach_lsm(program);
		rc = libbpf_get_error(map_link);
		if (rc)
			goto out;
	}
	if (state.command) {
		result = init_lsm();
		rc = result == -EIO ? 0 : -EPROTO;
		if (rc)
			fprintf(stderr, "init_lsm returned %d, expected -EIO\n", result);
	} else {
		result = nv_writer_create(&ring, &writer, public);
		if (!strcmp(mode, "success")) {
			rc = result;
			if (!rc)
				rc = contains(KEY_SPEC_USER_KEYRING, ring);
			if (!rc)
				rc = contains(KEY_SPEC_SESSION_KEYRING, ring);
			if (!rc)
				rc = nv_writer_sign_key(writer, digest, signature);
			nv_writer_destroy(ring);
		} else {
			rc = result == -EBADMSG && !ring && !writer ? 0 : -EPROTO;
			if (rc)
				fprintf(stderr, "import returned %d, ring %d, writer %d\n",
					result, ring, writer);
		}
	}
	if (fd >= 0) {
		if (bpf_map_lookup_elem(fd, &zero, &state)) {
			rc = -errno;
			goto out;
		}
		if (state.imports != 1 || state.failures != 1) {
			fprintf(stderr, "fault did not fire exactly once: imports %u, failures %u\n",
				state.imports, state.failures);
			rc = -EPROTO;
		}
	}
	result = unchanged(KEY_SPEC_USER_KEYRING, &user);
	if (result)
		rc = result;
	result = unchanged(KEY_SPEC_SESSION_KEYRING, &session);
	if (result)
		rc = result;
	if (state.command && (!access(SHIRUDO_IDENTITY_PIN, F_OK) ||
			      !access(SHIRUDO_LSM_LINK_PIN, F_OK)))
		rc = -EUCLEAN;
out:
	bpf_link__destroy(map_link);
	bpf_link__destroy(import_link);
	bpf_object__close(obj);
	return rc;
}

int main(int argc, char **argv)
{
	const char *vm = getenv("SHIRUDO_TEST_REGISTER_VM");
	key_serial_t sentinel;
	int rc, cleanup;
	long ret;

	log_init();
	if (!vm || strcmp(vm, "1") || getuid() || argc < 2 ||
	    !access(SHIRUDO_LSM_LINK_PIN, F_OK)) {
		fprintf(stderr, "requires an opted-in, uninitialized disposable VM\n");
		return 2;
	}
	if (argc == 3 && !strcmp(argv[1], "enroll")) {
		rc = enroll(argv[2]);
		goto done;
	}
	if (!((argc == 2 && (!strcmp(argv[1], "no-pkcs8") ||
			     !strcmp(argv[1], "success"))) ||
	      (argc == 3 && (!strcmp(argv[1], "import") ||
			     !strcmp(argv[1], "update") ||
			     !strcmp(argv[1], "freeze"))))) {
		fprintf(stderr, "usage: %s enroll CERT | success | no-pkcs8 | {import,update,freeze} BPF_OBJECT\n",
			argv[0]);
		return 2;
	}
	ret = syscall(__NR_keyctl, KEYCTL_JOIN_SESSION_KEYRING, NULL, 0, 0, 0);
	if (ret < 0) {
		rc = -errno;
		goto done;
	}
	ret = syscall(__NR_add_key, "keyring", "shirudo.nv-test.keep", NULL, 0,
		      KEY_SPEC_SESSION_KEYRING);
	if (ret < 0) {
		rc = -errno;
		goto done;
	}
	sentinel = (key_serial_t)ret;
	ret = syscall(__NR_keyctl, KEYCTL_LINK, sentinel, KEY_SPEC_USER_KEYRING, 0, 0);
	if (ret < 0) {
		rc = -errno;
		goto done;
	}
	rc = exercise(argv[1], argc == 3 ? argv[2] : NULL);
	cleanup = keyring_unlink_key(KEY_SPEC_USER_KEYRING, sentinel);
	if (cleanup)
		rc = cleanup;
done:
	if (rc)
		fprintf(stderr, "NV writer cleanup test: %s\n", strerror(-rc));
	return rc ? 1 : 0;
}
