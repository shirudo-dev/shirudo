/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Where init runs: the initrd, with the root file system at /sysroot.
 */

#ifndef SHIRUDO_UTIL_INITRD_H
#define SHIRUDO_UTIL_INITRD_H

#include <stdbool.h>

/*
 * The initrd marks itself with /etc/initrd-release; tests point
 * SHIRUDO_INITRD_RELEASE elsewhere.
 */
bool in_initrd(void);

const char *sysroot(void);

/*
 * Where the state tree is on the root file system, which the initrd
 * binds at /var/lib/shirudo: <sysroot>/var/lib/shirudo while the initrd
 * runs, /var/lib/shirudo otherwise. 0 or -ENAMETOOLONG.
 */
int state_source(char *buf, size_t cap);

/*
 * The keys init enrols: the initrd's own, measured copies while the
 * initrd runs, the state tree's otherwise. cert.der is the primary
 * certificate in that directory.
 */
const char *get_keys_dir(void);
const char *get_cert_path(void);

#endif /* SHIRUDO_UTIL_INITRD_H */
