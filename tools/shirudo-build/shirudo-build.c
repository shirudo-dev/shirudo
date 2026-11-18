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
#include "help.h"
#include "log.h"
#include "options.h"
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

enum build_opt {
	BUILD_OUTPUT,
	BUILD_NAME,
	BUILD_KEYS_DIR,
	BUILD_KEY,
	BUILD_CERT,
	BUILD_VMLINUX,
	BUILD_EXTRA_CFLAGS,
	BUILD_UNLOAD,
	BUILD_PAYLOAD_SHA256,
	BUILD_JAVA,
	BUILD_EMIT_ARTIFACTS,
};

static const struct opt_spec build_opts[] = {
	[BUILD_OUTPUT] = { "--output", 'o', 0, "<output.upatch>",
		"where to write the upatch instead of beside the input, or of "
		"<name>.unload.upatch in the current directory" },
	[BUILD_NAME] = { "--name", 0, 0, "<upatch-name>",
		"the upatch's name instead of the one the input gives" },
	[BUILD_KEYS_DIR] = { "--keys-dir", 0, 0, "<dir>",
		"read signing_key.pem and cert.der from <dir>, where "
		KEYS_DIR_ENV " points otherwise" },
	[BUILD_KEY] = { "--key", 0, 0, "<signing_key.pem>",
		"the signing key, over --keys-dir (default "
		SIGNING_KEY_PATH ")" },
	[BUILD_CERT] = { "--cert", 0, 0, "<cert.der>",
		"the certificate, over --keys-dir (default " CERT_PATH ")" },
	[BUILD_VMLINUX] = { "--vmlinux", 0, 0, "<vmlinux.h>",
		"compile against it instead of ./vmlinux.h, "
		"./vendor/linux/vmlinux.h or " VMLINUX_PATH },
	[BUILD_EXTRA_CFLAGS] = { "--extra-cflags", 0, 0, "'<flags>'",
		"more flags for clang" },
	[BUILD_UNLOAD] = { "--unload", 0, 0, "<upatch-name>",
		"sign the UNLOAD directive of the named upatch" },
	[BUILD_PAYLOAD_SHA256] = { "--payload-sha256", 0, 0, "<64-hex>",
		"with --unload, the payload digest, which the archive "
		"/var/lib/shirudo/upatches/<name>.upatch gives otherwise" },
	[BUILD_JAVA] = { "--java", 0, 0, NULL,
		"with --unload and --payload-sha256, sign the directive of a "
		"Java upatch, which the archive tells otherwise" },
	[BUILD_EMIT_ARTIFACTS] = { "--emit-artifacts", 0, 0, NULL,
		"keep the compiled .bpf.o beside the .upatch and print each "
		"path written" },
};

static const struct help_section build_sections[] = {
	HELP_OPTIONS("options:", build_opts),
};

static const struct help build_help = {
	.usage	    = "shirudo build <input.bpf.c|.bpf.o|.jar> "
		      "[-o <output.upatch>] [options]\n"
		      "       shirudo build --unload <upatch-name> "
		      "[-o <output.upatch>] [options]",
	.summary    = "Compile a .bpf.c, or take a .bpf.o or a Java agent "
		      ".jar, and sign it into a\n.upatch, or sign the UNLOAD "
		      "directive of a loaded upatch.\nfoo/bar.bpf.c becomes "
		      "foo/bar.bpf.upatch, foo/agent.jar foo/agent.upatch.",
	.sections   = build_sections,
	.n_sections = ARRAY_SIZE(build_sections),
	.footer	    = "The helper also serves shirudo image build and verify, "
		      "the operator\nbpm commands and keys vouch; each takes "
		      "--help.",
};

/* foo/bar.bpf.c lands at foo/bar.bpf.upatch beside its input. */
static int derive_output(const char *input, char *buf, size_t buf_sz)
{
	size_t stem = strlen(input);

	if (name_has_suffix(input, stem, ".c") ||
	    name_has_suffix(input, stem, ".o"))
		stem -= 2;
	else if (name_has_suffix(input, stem, ".jar"))
		stem -= 4;

	if (strsprintf(buf, buf_sz, "%.*s.upatch", (int)stem, input) < 0)
		return -ENAMETOOLONG;
	return 0;
}

/* The .bpf.o sits beside the .upatch. */
static int derive_artifact_o(const char *output, char *buf, size_t buf_sz)
{
	size_t stem = strlen(output);

	if (name_has_suffix(output, stem, ".upatch"))
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
	/* Nothing writes the arguments; the parsers take them as const. */
	const char **args = (const char **)argv;
	const char *pkey = SIGNING_KEY_PATH;
	const char *payload_sha256_hex = NULL;
	const char *cert = CERT_PATH;
	const char *keys_dir_arg = NULL;
	const char *keys_dir;
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
	bool java = false;
	int pkey_explicit = 0;
	int cert_explicit = 0;
	struct opt_parser p;
	int ret, opt;

	harden_stdio();
	log_init();
	if (harden_self())
		return 1;

	if (argc >= 2 && strcmp(args[1], "image") == 0)
		return build_image(argc - 1, args + 1);
	if (argc >= 2 && strcmp(args[1], "upatch") == 0)
		return build_upatch_cli(argc - 1, args + 1);
	if (argc >= 2 && strcmp(args[1], "bpm") == 0)
		return build_bpm(argc - 1, args + 1);
	if (argc >= 3 && strcmp(args[1], "keys") == 0 &&
	    strcmp(args[2], "vouch") == 0)
		return build_keys_vouch(argc - 2, args + 2);

	OPT_INIT(&p, "build", build_opts, &build_help, argc, args, 1);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case BUILD_OUTPUT:
			output = p.value;
			break;
		case BUILD_NAME:
			name = p.value;
			break;
		case BUILD_KEYS_DIR:
			keys_dir_arg = p.value;
			break;
		case BUILD_KEY:
			pkey = p.value;
			pkey_explicit = 1;
			break;
		case BUILD_CERT:
			cert = p.value;
			cert_explicit = 1;
			break;
		case BUILD_VMLINUX:
			vmlinux_override = p.value;
			break;
		case BUILD_EXTRA_CFLAGS:
			extra_cflags = p.value;
			break;
		case BUILD_UNLOAD:
			unload_name = p.value;
			break;
		case BUILD_PAYLOAD_SHA256:
			payload_sha256_hex = p.value;
			break;
		case BUILD_JAVA:
			java = true;
			break;
		case BUILD_EMIT_ARTIFACTS:
			emit_artifacts = 1;
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
	if (unload_name && input) {
		opt_usage(&p, "--unload takes no input");
		return EXIT_USAGE;
	}
	if (!unload_name && !input) {
		opt_usage(&p, "takes <input.bpf.c|.bpf.o|.jar> or --unload <upatch-name>");
		return EXIT_USAGE;
	}
	if (java && (!unload_name || !payload_sha256_hex)) {
		opt_usage(&p, "--java takes --unload and --payload-sha256");
		return EXIT_USAGE;
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
		if (payload_sha256_hex) {
			if (hex_decode(payload_sha256_hex,
				       payload_sha256, 32)) {
				opt_usage(&p, "--payload-sha256 must be 64 hex characters");
				return EXIT_USAGE;
			}
		} else {
			/*
			 * No explicit digest: take it from the operator's local
			 * archive, since the target refuses a directive whose
			 * digest is not the loaded payload's.
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
				java = u.hdr.type == UPATCH_TYPE_JAVA;
				upatch_close(&u);
				pr_info("--payload-sha256 derived from archive %s",
					archive);
			} else {
				pr_err("--payload-sha256 omitted and no archive at %s; pass the digest upatch info shows",
				       archive);
				return 2;
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

		if (java)
			ret = build_package_java_unload(unload_name,
							payload_sha256, output,
							pkey, cert);
		else
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

	if (!name) {
		if (build_upatch_name(input, name_buf, sizeof(name_buf))) {
			pr_err("upatch name from %s too long", input);
			return 2;
		}
		name = name_buf;
	}

	if (name_has_suffix(input, strlen(input), ".jar")) {
		ret = build_package_java_load(input, output, name, pkey, cert);
		if (ret == 0 && emit_artifacts)
			printf("emitted:\n  upatch: %s\n", output);
		return ret ? 1 : 0;
	}

	if (name_has_suffix(input, strlen(input), ".bpf.c")) {
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
	} else if (name_has_suffix(input, strlen(input), ".o")) {
		bpf_o = input;		/* decoder paths resolve from the cwd */
	} else {
		pr_err("input must be .bpf.c, .bpf.o or .jar");
		return 2;
	}

	ret = build_package_load(bpf_o, src_path, output, name,
				 NULL, 0, pkey, cert);

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
