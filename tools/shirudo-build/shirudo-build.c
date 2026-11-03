// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Operator-only artifact pipeline: compile, sign, package.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "bpm.h"
#include "compile.h"
#include "harden.h"
#include "log.h"
#include "hex.h"
#include "image.h"
#include "malloc.h"
#include "package.h"
#include "paths.h"
#include "sign.h"
#include "upatch.h"
#include "vmlinux.h"

#ifndef VMLINUX_PATH
#define VMLINUX_PATH "/usr/local/share/shirudo/vmlinux.h"
#endif

static void usage(FILE *fp)
{
	fprintf(fp,
		"usage:\n"
		"  shirudo-build <input> [-o <output.upatch>]\n"
		"                [--name <upatch-name>]\n"
		"                [--keys-dir <dir>]\n"
		"                [--key <signing_key.pem>] [--cert <cert.der>]\n"
		"                [--vmlinux <vmlinux.h>] [--extra-cflags '<flags>']\n"
		"                [--emit-artifacts]\n"
		"                [--attach-upatch <target.upatch> --attach-object <target.bpf.o>]\n"
		"\n"
		"  shirudo-build --unload <upatch-name> [-o <output.upatch>]\n"
		"                [--payload-sha256 <64-hex>]\n"
		"                [--keys-dir <dir>]\n"
		"                [--key <signing_key.pem>] [--cert <cert.der>]\n"
		"\n"
		"  shirudo-build image build <filesystem.img> -o <prefix> ...\n"
		"  shirudo-build bpm <build|push|tree append> ...\n"
		"  shirudo-build keys vouch <cert.der> [-o <file>] ...\n"
		"\n"
		"<input> is .bpf.c (compiled via clang) or .bpf.o.\n"
		"-o defaults to <input> with a trailing .c/.o replaced by\n"
		"   .upatch (foo/bar.bpf.c -> foo/bar.bpf.upatch), written\n"
		"   next to the input; for --unload it defaults to\n"
		"   <name>.unload.upatch in the current directory. Pass -o\n"
		"   only to write somewhere else.\n"
		"--keys-dir defaults key/cert to <dir>/signing_key.pem and\n"
		"           <dir>/cert.der. If omitted, %s is used when set.\n"
		"           Explicit --keys-dir overrides the environment;\n"
		"           explicit --key/--cert override both.\n"
		"--key default without --keys-dir/%s: %s\n"
		"--cert default without --keys-dir/%s: %s\n"
		"--vmlinux: explicit; else ./vmlinux.h, ./vendor/linux/vmlinux.h,\n"
		"           then %s.\n"
		"--payload-sha256: 64 hex chars; if omitted, read from the local\n"
		"                  archive /var/lib/shirudo/upatches/<name>.upatch,\n"
		"                  else all-zero (target skips the payload check).\n"
		"--attach-upatch, --attach-object: attach fentry, fexit and freplace\n"
		"                  programs to the programs of the target upatch,\n"
		"                  built from the target object; the result loads\n"
		"                  only on top of exactly this build of the target.\n"
		"--emit-artifacts: for a .bpf.c input, also keep the compiled\n"
		"                  .bpf.o next to the .upatch (instead of a temp\n"
		"                  file that is removed). Reports every emitted\n"
		"                  path on stdout. A debugging aid.\n"
		"bpm: the operator-only package commands (`shirudo bpm build`,\n"
		"     `push`, `tree append`); see `shirudo-build bpm --help`.\n",
		KEYS_DIR_ENV, KEYS_DIR_ENV,
		SIGNING_KEY_PATH, KEYS_DIR_ENV,
		CERT_PATH, VMLINUX_PATH);
}

static const char *derive_name(const char *input, char *buf, size_t buf_sz)
{
	const char *base = strrchr(input, '/');
	size_t n;

	strscpy(buf, base ? base + 1 : input, buf_sz);

	n = strlen(buf);
	if (n > 6 && strcmp(buf + n - 6, ".bpf.c") == 0)
		buf[n - 6] = '\0';
	else if (n > 6 && strcmp(buf + n - 6, ".bpf.o") == 0)
		buf[n - 6] = '\0';
	else if (n > 2 && strcmp(buf + n - 2, ".o") == 0)
		buf[n - 2] = '\0';
	return buf;
}

static int ends_with(const char *s, const char *suf)
{
	size_t ns = strlen(s);
	size_t nf = strlen(suf);

	return ns >= nf && strcmp(s + ns - nf, suf) == 0;
}

/* foo/bar.bpf.c lands at foo/bar.bpf.upatch beside its input. */
static int derive_output(const char *input, char *buf, size_t buf_sz)
{
	size_t stem = strlen(input);

	if (stem > 2 && (strcmp(input + stem - 2, ".c") == 0 ||
			 strcmp(input + stem - 2, ".o") == 0))
		stem -= 2;

	if (strsprintf(buf, buf_sz, "%.*s.upatch", (int)stem, input) < 0)
		return -ENAMETOOLONG;
	return 0;
}

/* The .bpf.o sits beside the .upatch. */
static int derive_artifact_o(const char *output, char *buf, size_t buf_sz)
{
	size_t stem = strlen(output);

	if (stem > 7 && strcmp(output + stem - 7, ".upatch") == 0)
		stem -= 7;

	if (strsprintf(buf, buf_sz, "%.*s.o", (int)stem, output) < 0)
		return -ENAMETOOLONG;
	return 0;
}

static int compile_to_temp(const char *source, const char *vmlinux_h,
			   const char *extra_cflags, char **out_path)
{
	char tmpl[] = "/tmp/shirudo-build-XXXXXX.bpf.o";
	int fd;
	int ret;

	fd = mkstemps(tmpl, strlen(".bpf.o"));
	if (fd < 0)
		return -errno;
	close(fd);

	ret = build_compile(source, tmpl, vmlinux_h, extra_cflags, NULL);
	if (ret) {
		unlink(tmpl);
		return ret;
	}
	*out_path = xstrdup(tmpl);
	if (!*out_path) {
		unlink(tmpl);
		return -ENOMEM;
	}
	return 0;
}

int build_check_keys(const char *pkey, const char *cert)
{
	int fd = open_signing_key(pkey);

	if (fd < 0) {
		if (fd != -EPERM)
			pr_err("run `shirudo genkey` on the operator (or pass --key).");
		return 1;
	}
	close(fd);
	if (access(cert, R_OK) != 0) {
		pr_err("cert not readable: %s: %s",
		       cert, strerror(errno));
		pr_err("run `shirudo genkey` on the operator (or pass --cert).");
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	const char *pkey = SIGNING_KEY_PATH;
	const char *payload_sha256_hex = NULL;
	const char *cert = CERT_PATH;
	const char *keys_dir_arg = NULL;
	const char *keys_dir;
	struct build_attach_upatch attach = {};
	const char *attach_upatch = NULL;
	const char *vmlinux_override = NULL;
	const char *extra_cflags = NULL;
	__u8 payload_sha256[32] = {};
	const char *unload_name = NULL;
	const char *output = NULL;
	const char *input = NULL;
	const char *name = NULL;
	const char *emitted_o = NULL;
	char *temp_bpf_o = NULL;
	const char *src_path = NULL;
	char artifact_buf[PATH_MAX];
	char pkey_path[PATH_MAX];
	char cert_path[PATH_MAX];
	char output_buf[PATH_MAX];
	char name_buf[256];
	const char *bpf_o;
	int emit_artifacts = 0;
	int pkey_explicit = 0;
	int cert_explicit = 0;
	int ret;
	int i;

	harden_stdio();
	log_init();
	if (harden_self())
		return 1;

	if (argc >= 2 && strcmp(argv[1], "image") == 0)
		return build_image(argc - 1, argv + 1);
	if (argc >= 2 && strcmp(argv[1], "upatch") == 0)
		return build_upatch_cli(argc - 1, argv + 1);
	if (argc >= 2 && strcmp(argv[1], "bpm") == 0)
		return build_bpm(argc - 1, argv + 1);
	if (argc >= 3 && strcmp(argv[1], "keys") == 0 &&
	    strcmp(argv[2], "vouch") == 0)
		return build_keys_vouch(argc - 2, argv + 2);

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (strcmp(a, "-o") == 0 && i + 1 < argc) {
			output = argv[++i];
		} else if (strcmp(a, "--name") == 0 && i + 1 < argc) {
			name = argv[++i];
		} else if (strcmp(a, "--keys-dir") == 0 && i + 1 < argc) {
			keys_dir_arg = argv[++i];
		} else if (strncmp(a, "--keys-dir=", 11) == 0) {
			keys_dir_arg = a + 11;
		} else if (strcmp(a, "--key") == 0 && i + 1 < argc) {
			pkey = argv[++i];
			pkey_explicit = 1;
		} else if (strcmp(a, "--cert") == 0 && i + 1 < argc) {
			cert = argv[++i];
			cert_explicit = 1;
		} else if (strcmp(a, "--vmlinux") == 0 && i + 1 < argc) {
			vmlinux_override = argv[++i];
		} else if (strcmp(a, "--extra-cflags") == 0 && i + 1 < argc) {
			extra_cflags = argv[++i];
		} else if (strcmp(a, "--unload") == 0 && i + 1 < argc) {
			unload_name = argv[++i];
		} else if (strcmp(a, "--payload-sha256") == 0 && i + 1 < argc) {
			payload_sha256_hex = argv[++i];
		} else if (strcmp(a, "--emit-artifacts") == 0) {
			emit_artifacts = 1;
		} else if (strcmp(a, "--attach-upatch") == 0 && i + 1 < argc) {
			attach_upatch = argv[++i];
		} else if (strcmp(a, "--attach-object") == 0 && i + 1 < argc) {
			attach.obj_path = argv[++i];
		} else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
			usage(stdout);
			return 0;
		} else if (a[0] == '-') {
			pr_err("unknown option '%s'", a);
			usage(stderr);
			return 2;
		} else if (!input) {
			input = a;
		} else {
			pr_err("unexpected positional arg '%s'", a);
			return 2;
		}
	}

	keys_dir = keys_dir_resolve(keys_dir_arg);

	if (keys_dir) {
		if (!pkey_explicit) {
			ret = format_key_path(pkey_path, sizeof(pkey_path),
					      keys_dir,
					      SIGNING_KEY_FILE);
			if (ret) {
				pr_err("invalid keys dir %s: %s",
				       keys_dir, strerror(-ret));
				return 2;
			}
			pkey = pkey_path;
		}
		if (!cert_explicit) {
			ret = format_key_path(cert_path, sizeof(cert_path),
					      keys_dir, CERT_FILE);
			if (ret) {
				pr_err("invalid keys dir %s: %s",
				       keys_dir, strerror(-ret));
				return 2;
			}
			cert = cert_path;
		}
	}

	if (build_check_keys(pkey, cert))
		return 1;

	if (unload_name) {
		if (input) {
			pr_err("--unload takes no positional input");
			return 2;
		}
		if (payload_sha256_hex) {
			if (hex_decode(payload_sha256_hex,
				       payload_sha256, 32)) {
				pr_err("--payload-sha256 must be 64 hex chars");
				return 2;
			}
		} else {
			/*
			 * No explicit digest: consult the operator's local
			 * archive so the unload still binds payload_mismatch.
			 * Absent there too, fall through with the all-zero
			 * payload, which the target reads as "no expected
			 * payload" and skips the check (the documented, less
			 * safe escape hatch).
			 */
			char archive[PATH_MAX];
			struct upatch u;

			if (strsprintf(archive, sizeof(archive), "%s/%s.upatch",
				       UPATCHES_DIR, unload_name) < 0) {
				pr_err("archive path too long for '%s'",
				       unload_name);
				return 1;
			}
			if (upatch_open(archive, &u) == 0) {
				memcpy(payload_sha256, u.hdr.payload_sha256,
				       sizeof(payload_sha256));
				upatch_close(&u);
				pr_info("--payload-sha256 derived from archive %s",
					archive);
			} else {
				pr_warn("--payload-sha256 omitted and no archive "
					"entry at %s; the directive will carry no "
					"expected payload and the target will skip "
					"the payload_mismatch check. Pass "
					"--payload-sha256 to bind it.", archive);
			}
		}

		if (!output) {
			if (strsprintf(output_buf, sizeof(output_buf),
				       "%s.unload.upatch", unload_name) < 0) {
				pr_err("derived output path too long for '%s'",
				       unload_name);
				return 1;
			}
			output = output_buf;
			pr_info("writing %s (no -o given)", output);
		}

		ret = build_package_unload(unload_name, payload_sha256,
					   output, pkey, cert);
		if (ret == 0 && emit_artifacts) {
			printf("emitted:\n");
			printf("  upatch: %s\n", output);
			printf("  bpf.o:  (none; --unload embeds the prebuilt "
			       "unload program)\n");
		}
		return ret ? 1 : 0;
	}

	if (!input) {
		usage(stderr);
		return 2;
	}

	/*
	 * Resolve the output path before compiling: --emit-artifacts
	 * derives the .bpf.o location from it so the object lands in the
	 * same directory as the .upatch.
	 */
	if (!output) {
		ret = derive_output(input, output_buf, sizeof(output_buf));
		if (ret) {
			pr_err("cannot derive output path from %s: %s",
			       input, strerror(-ret));
			return 1;
		}
		output = output_buf;
		pr_info("writing %s (no -o given)", output);
	}

	if (ends_with(input, ".bpf.c")) {
		const char *vmlinux_h =
			build_locate_vmlinux(vmlinux_override);
		if (!vmlinux_h) {
			pr_err("vmlinux.h not found (tried %s, ./vmlinux.h, "
			       "./vendor/linux/vmlinux.h, %s)",
			       vmlinux_override ? vmlinux_override
						 : "(none)", VMLINUX_PATH);
			return 1;
		}
		if (emit_artifacts) {
			ret = derive_artifact_o(output, artifact_buf,
						sizeof(artifact_buf));
			if (ret) {
				pr_err("cannot derive .bpf.o path from %s: %s",
				       output, strerror(-ret));
				return 1;
			}
			ret = build_compile(input, artifact_buf,
					    vmlinux_h, extra_cflags, NULL);
			if (ret) {
				pr_err("compile %s: %d", input, ret);
				return 1;
			}
			bpf_o = artifact_buf;
			emitted_o = artifact_buf;
		} else {
			ret = compile_to_temp(input, vmlinux_h, extra_cflags,
					      &temp_bpf_o);
			if (ret) {
				pr_err("compile %s: %d", input, ret);
				return 1;
			}
			bpf_o = temp_bpf_o;
		}
		src_path = input;	/* anchors relative decoder paths */
	} else if (ends_with(input, ".bpf.o") || ends_with(input, ".o")) {
		bpf_o = input;		/* decoder paths resolve from the cwd */
	} else {
		pr_err("input must be .bpf.c or .bpf.o");
		return 2;
	}

	if (!name)
		name = derive_name(input, name_buf, sizeof(name_buf));

	if (!attach_upatch != !attach.obj_path) {
		pr_err("--attach-upatch and --attach-object go together");
		ret = -EINVAL;
	} else if (attach_upatch) {
		const char *target_name;
		struct upatch target;

		ret = upatch_open(attach_upatch, &target);
		if (ret) {
			pr_err("open %s: %s", attach_upatch, strerror(-ret));
		} else {
			target_name = upatch_signed_name(&target);
			if (!target_name || upatch_is_unload(&target) ||
			    strscpy(attach.name, target_name,
				    sizeof(attach.name)) < 0) {
				pr_err("%s is not a signed load upatch",
				       attach_upatch);
				ret = -EINVAL;
			}
			memcpy(attach.payload_sha256, target.hdr.payload_sha256,
			       sizeof(attach.payload_sha256));
			upatch_close(&target);
		}
		if (!ret)
			ret = build_package_load_attach(bpf_o, src_path, output,
							name, NULL, 0, &attach,
							pkey, cert);
	} else {
		ret = build_package_load(bpf_o, src_path, output, name,
					 NULL, 0, pkey, cert);
	}

	if (temp_bpf_o) {
		unlink(temp_bpf_o);
		xstrfree(temp_bpf_o);
	}

	if (ret == 0 && emit_artifacts) {
		printf("emitted:\n");
		printf("  upatch: %s\n", output);
		if (emitted_o)
			printf("  bpf.o:  %s\n", emitted_o);
		else
			printf("  bpf.o:  (none; input was a pre-compiled "
			       "object, not recompiled)\n");
	}
	return ret ? 1 : 0;
}
