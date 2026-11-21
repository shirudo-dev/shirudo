// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <shirudo/misc.h>

#define SHIRUDO_TPM_COPY(out, in, size) (memcpy(out, in, size), 0)
#include <shirudo/tpm_command.h>

static void put32(__u8 *out, __u32 value)
{
	out[0] = value >> 24;
	out[1] = value >> 16;
	out[2] = value >> 8;
	out[3] = value;
}

static void packet(__u8 command[64], __u32 code, __u32 length)
{
	memset(command, 0, 64);
	command[0] = 0x80;
	command[1] = 1;
	put32(command + 2, length);
	put32(command + 6, code);
}

static int check(enum shirudo_tpm_access observed,
		 enum shirudo_tpm_access expected, const char *name)
{
	if (observed == expected)
		return 0;
	fprintf(stderr, "%s: access %d, expected %d\n", name, observed, expected);
	return 1;
}

/* Only the Shirudo runtime may use a RUNTIME command; anyone a PUBLIC one. */
static int check_runtime_only(enum shirudo_tpm_access access, const char *name)
{
	if (shirudo_tpm_allowed(access, false) || !shirudo_tpm_allowed(access, true)) {
		fprintf(stderr, "%s: needs exactly the Shirudo runtime\n", name);
		return 1;
	}
	return 0;
}

int main(void)
{
	static const __u32 nv_commands[] = {
		0x122, 0x134, 0x135, 0x136, 0x137, 0x138, 0x14f,
	};
	static const __u32 pcr_commands[] = { 0x13c, 0x13d, 0x182, 0x183, 0x185 };
	enum shirudo_tpm_access expected, access;
	__u8 command[64];
	__u32 pcr;
	size_t i;
	int failures = 0;

	for (i = 0; i < ARRAY_SIZE(nv_commands); i++) {
		packet(command, nv_commands[i], 18);
		put32(command + 10, 0x40000001);
		/* Shirudo's measurement register: every mutation. */
		put32(command + 14, 0x01818e00);
		access = shirudo_tpm_access(command, 18, 13);
		failures += check(access, SHIRUDO_TPM_RUNTIME, "register NV mutation");
		failures += check_runtime_only(access, "register NV mutation");
		/* The config NvPCR: every mutation, extension included. */
		put32(command + 14, 0x01818e04);
		access = shirudo_tpm_access(command, 18, 0x01818e04);
		failures += check(access, SHIRUDO_TPM_RUNTIME, "config NvPCR mutation");
		failures += check_runtime_only(access, "config NvPCR mutation");
		failures += check(shirudo_tpm_access(command, 18, 13),
				  SHIRUDO_TPM_RUNTIME,
				  "config NvPCR stays reserved with a config PCR");
		put32(command + 14, 0x01818e05);
		failures += check(shirudo_tpm_access(command, 18, 0x01818e04),
				  SHIRUDO_TPM_PUBLIC, "NV mutation past the reserved block");
		put32(command + 14, 0x01500000);
		failures += check(shirudo_tpm_access(command, 18, 13),
				  SHIRUDO_TPM_PUBLIC, "unrelated NV mutation");
		/* systemd's NvPCRs: extensions stay public, nothing else does. */
		expected = nv_commands[i] == 0x136 ? SHIRUDO_TPM_PUBLIC :
						     SHIRUDO_TPM_RUNTIME;
		put32(command + 14, 0x01d10202);
		access = shirudo_tpm_access(command, 18, 13);
		failures += check(access, expected, "systemd NvPCR mutation");
		if (nv_commands[i] != 0x136)
			failures += check_runtime_only(access, "systemd NvPCR mutation");
		put32(command + 14, 0x01d10200);
		failures += check(shirudo_tpm_access(command, 18, 13), expected,
				  "first systemd NvPCR mutation");
		put32(command + 14, 0x01d105ff);
		failures += check(shirudo_tpm_access(command, 18, 13), expected,
				  "last UAPI.19 Linux NV mutation");
		put32(command + 14, 0x01d10600);
		failures += check(shirudo_tpm_access(command, 18, 13),
				  SHIRUDO_TPM_PUBLIC, "NV mutation past the Linux range");
		put32(command + 14, 0x01d101ff);
		failures += check(shirudo_tpm_access(command, 18, 13),
				  SHIRUDO_TPM_PUBLIC, "NV mutation before the Linux range");
	}
	for (i = 0; i < ARRAY_SIZE(pcr_commands); i++) {
		packet(command, pcr_commands[i], 14);
		put32(command + 10, 13);
		access = shirudo_tpm_access(command, 14, 13);
		failures += check(access, SHIRUDO_TPM_RUNTIME, "config PCR mutation");
		failures += check_runtime_only(access, "config PCR mutation");
		put32(command + 10, 15);
		access = shirudo_tpm_access(command, 14, 13);
		failures += check(access, SHIRUDO_TPM_PUBLIC,
				  "systemd machine and file system measurement");
		if (!shirudo_tpm_allowed(access, false)) {
			fprintf(stderr, "root without a role must extend PCR 15\n");
			failures++;
		}
		for (pcr = 0; pcr < 24; pcr++) {
			put32(command + 10, pcr);
			expected = pcr == 13 ? SHIRUDO_TPM_RUNTIME : SHIRUDO_TPM_PUBLIC;
			failures += check(shirudo_tpm_access(command, 14, 13),
					  expected, "PCR allocation");
		}
		put32(command + 10, 13);
		failures += check(shirudo_tpm_access(command, 14, 16),
				  SHIRUDO_TPM_PUBLIC, "PCR 13 with another config PCR");
		/* With the config NvPCR, PCR 13 is systemd-stub's again. */
		failures += check(shirudo_tpm_access(command, 14, 0x01818e04),
				  SHIRUDO_TPM_PUBLIC, "PCR 13 with the config NvPCR");
	}
	packet(command, 0x11f, 18);
	put32(command + 10, 0x01818e00);
	put32(command + 14, 0x4000000c);
	failures += check(shirudo_tpm_access(command, 18, 13),
			  SHIRUDO_TPM_RUNTIME, "policy deletion names NV before platform");
	put32(command + 10, 0x01d10202);
	failures += check(shirudo_tpm_access(command, 18, 13),
			  SHIRUDO_TPM_RUNTIME, "systemd NvPCR deletion by policy");
	packet(command, 0x13b, 14);
	put32(command + 10, 0x01d10202);
	failures += check(shirudo_tpm_access(command, 14, 13),
			  SHIRUDO_TPM_RUNTIME, "systemd NvPCR authorization change");
	packet(command, 0x12a, 32);
	put32(command + 10, 0x4000000c);
	command[17] = 14;
	put32(command + 18, 0x01818e00);
	failures += check(shirudo_tpm_access(command, 32, 13),
			  SHIRUDO_TPM_RUNTIME, "NV definition without auth session");
	put32(command + 18, 0x01d10202);
	failures += check(shirudo_tpm_access(command, 32, 13),
			  SHIRUDO_TPM_RUNTIME, "systemd NvPCR redefinition");
	put32(command + 18, 0x01818e04);
	failures += check(shirudo_tpm_access(command, 32, 0x01818e04),
			  SHIRUDO_TPM_RUNTIME, "config NvPCR redefinition");
	packet(command, 0x12a, 45);
	command[1] = 2;
	put32(command + 10, 0x4000000c);
	put32(command + 14, 9);
	command[30] = 14;
	put32(command + 31, 0x01818e00);
	failures += check(shirudo_tpm_access(command, 45, 13),
			  SHIRUDO_TPM_RUNTIME, "NV definition with password session");
	put32(command + 14, 4096);
	failures += check(shirudo_tpm_access(command, 45, 13),
			  SHIRUDO_TPM_MALFORMED, "oversized authorization area");
	packet(command, 0x126, 14);
	failures += check(shirudo_tpm_access(command, 14, 13),
			  SHIRUDO_TPM_RUNTIME, "root cannot clear protected measurements");
	packet(command, 0x198, 14);
	failures += check(shirudo_tpm_access(command, 14, 13),
			  SHIRUDO_TPM_RUNTIME, "ACT timeout requires runtime authority");
	packet(command, 0x17e, 10);
	failures += check(shirudo_tpm_access(command, 10, 13),
			  SHIRUDO_TPM_PUBLIC, "PCR_Read remains public");
	packet(command, 0x144, 12);
	failures += check(shirudo_tpm_access(command, 12, 13),
			  SHIRUDO_TPM_PUBLIC, "systemd may probe an already initialized TPM");
	failures += check(shirudo_tpm_access(command, 9, 13),
			  SHIRUDO_TPM_MALFORMED, "truncated header");
	packet(command, 0x20000000, 10);
	failures += check(shirudo_tpm_access(command, 10, 13),
			  SHIRUDO_TPM_RUNTIME, "unknown vendor command");
	if (shirudo_tpm_allowed(SHIRUDO_TPM_MALFORMED, true) ||
	    shirudo_tpm_allowed(SHIRUDO_TPM_RUNTIME, false) ||
	    !shirudo_tpm_allowed(SHIRUDO_TPM_RUNTIME, true) ||
	    !shirudo_tpm_allowed(SHIRUDO_TPM_PUBLIC, false)) {
		fprintf(stderr, "access classes were conflated\n");
		failures++;
	}
	return failures ? 1 : 0;
}
