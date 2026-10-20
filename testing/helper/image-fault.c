// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "image-fault.h"

int __wrap_main(int argc, const char **argv)
{
	if (argc != 4 || strcmp(argv[1], "image") ||
	    strcmp(argv[2], "update")) {
		fprintf(stderr, "usage: shirudo-image-fault "
			"image update <prefix>\n");
		return 2;
	}
	return __real_main(argc, argv);
}

TSS2_RC __wrap_Esys_PCR_Extend(ESYS_CONTEXT *context, ESYS_TR pcr,
			       ESYS_TR first, ESYS_TR second, ESYS_TR third,
			       const TPML_DIGEST_VALUES *digests)
{
	TSS2_RC rc;

	rc = __real_Esys_PCR_Extend(context, pcr, first, second, third,
				    digests);
	if (!rc)
		_exit(99);
	return rc;
}
