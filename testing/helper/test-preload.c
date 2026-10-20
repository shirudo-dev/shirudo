// SPDX-License-Identifier: BSD-2-Clause

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

static void __attribute__((constructor)) mark_preload(void)
{
	const char *path = getenv("SHIRUDO_PRELOAD_MARKER");
	int descriptor;

	if (!path)
		return;
	descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (descriptor >= 0)
		close(descriptor);
}
