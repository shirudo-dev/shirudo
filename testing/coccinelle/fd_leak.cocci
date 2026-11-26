// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A descriptor that was opened is closed, returned, stored or handed to
// what closes it (fdopen(), fdopendir(), gzdopen(), a BIO with
// BIO_CLOSE, commit_file()) on every path out of the function once the
// open succeeded.
// A leak on an error path goes unnoticed in a one-shot command until a
// loop or a retry runs out of descriptors, and keeps open what it should
// not. The locks of eventlog_lock() and seal_lock() are descriptors too,
// and eventlog_unlock() closes one: a lock left held makes the next
// eventlog_lock() of the same command wait for itself, as flock() takes
// each open of the file apart.

virtual report

@initialize:python@
@@
def leak(p1, p2):
    coccilib.report.print_report(p2[0], "returns without closing the descriptor opened on line %s" % p1[0].line)

@r exists@
attribute name SEC;
local idexpression int fd;
expression E, E1, E2;
statement S, S1;
identifier opener = {open, openat, socket, accept4, dup, memfd_create,
		     eventfd, epoll_create1, inotify_init1, timerfd_create,
		     pidfd_open, bpf_obj_get, eventlog_lock,
		     seal_lock};
position p1, p2;
@@
(
  fd = opener@p1(...);
|
  fd = fcntl@p1(E2, \(F_DUPFD\|F_DUPFD_CLOEXEC\), ...);
)
... when != fd = E1
if (\(fd < 0\|fd == -1\)) S
... when != close(fd)
    when != eventlog_unlock(fd)
    when != fd = E1
    when != E = fd
    when != if (fd >= 0) S1
    when != fdopen(fd, ...)
    when != fdopendir(fd)
    when != gzdopen(fd, ...)
    when != BIO_new_fd(fd, BIO_CLOSE)
    when != commit_file(..., fd, ...)
    when != \(_exit\|exit\|abort\)(...)
(
  return fd;
|
  return <+... close(fd) ...+>;
|
  return commit_file(..., fd, ...);
|
  return@p2 ...;
)

@d exists@
identifier fd;
expression E, E1, E2;
statement S, S1;
identifier opener = {open, openat, socket, accept4, dup, memfd_create,
		     eventfd, epoll_create1, inotify_init1, timerfd_create,
		     pidfd_open, bpf_obj_get, eventlog_lock,
		     seal_lock};
position p1, p2;
@@
(
  int fd = opener@p1(...);
|
  int fd = fcntl@p1(E2, \(F_DUPFD\|F_DUPFD_CLOEXEC\), ...);
)
... when != fd = E1
if (\(fd < 0\|fd == -1\)) S
... when != close(fd)
    when != eventlog_unlock(fd)
    when != fd = E1
    when != E = fd
    when != if (fd >= 0) S1
    when != fdopen(fd, ...)
    when != fdopendir(fd)
    when != gzdopen(fd, ...)
    when != BIO_new_fd(fd, BIO_CLOSE)
    when != commit_file(..., fd, ...)
    when != \(_exit\|exit\|abort\)(...)
(
  return fd;
|
  return <+... close(fd) ...+>;
|
  return commit_file(..., fd, ...);
|
  return@p2 ...;
)

@script:python depends on report@
p1 << r.p1;
p2 << r.p2;
@@
leak(p1, p2)

@script:python depends on report@
p1 << d.p1;
p2 << d.p2;
@@
leak(p1, p2)
