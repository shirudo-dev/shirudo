..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Tutorial
:audience: upatch authors

Your first upatch
=================

In this tutorial you write a small upatch of your own: a BPF program that
counts the calls of a kernel function in a map. You build and sign it,
load it on the test target, read the count and unload it again.

Before you begin
----------------

- The test VM from the :doc:`/start/quickstart`, running as
  ``quickstart``
- The operator shell from the quickstart: in the root of your checkout,
  with ``shirudo`` and ``shirudo-build`` on ``PATH`` and ``KEYS`` naming
  the test VM's key directory
- A root shell on the target (``make -C testing vm-ssh
  VM_NAME=quickstart``) in which ``shirudo`` runs the runtime binary:

  .. code-block:: console

     target# alias shirudo=shirudo-runtime

Write the program
-----------------

1. Make a directory for your work in the checkout:

   .. code-block:: console

      operator$ mkdir -p build/tutorial

   Git ignores ``build/``, and the guest sees the directory as
   ``/workspace/shirudo/build/tutorial``.

2. Write ``build/tutorial/sleep-count.bpf.c``:

   .. code-block:: c

      // SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
      #include "vmlinux.h"
      #include <bpf/bpf_helpers.h>
      #include <bpf/bpf_tracing.h>

      char _license[] SEC("license") = "Dual BSD/GPL";

      struct {
              __uint(type, BPF_MAP_TYPE_ARRAY);
              __uint(max_entries, 1);
              __type(key, __u32);
              __type(value, __u64);
      } calls SEC(".maps");

      SEC("fentry/do_nanosleep")
      int BPF_PROG(count_nanosleep)
      {
              __u32 key = 0;
              __u64 *n;

              n = bpf_map_lookup_elem(&calls, &key);
              if (n)
                      __sync_fetch_and_add(n, 1);
              return 0;
      }

   The ``fentry`` program runs on every entry to the kernel function
   ``do_nanosleep()``, which ``nanosleep(2)`` and ``clock_nanosleep(2)``
   reach, and adds one to the single entry of the array map ``calls``.
   ``vmlinux.h`` declares the kernel's types, so the program compiles once
   and the loader relocates it to the target kernel's layout. Keep the
   license string GPL-compatible: the kernel refuses LSM programs without
   one, and kernel functions and kernel structures to any program without
   one.

Build and sign it
-----------------

1. Build the upatch:

   .. code-block:: console

      operator$ shirudo build build/tutorial/sleep-count.bpf.c --keys-dir "$KEYS" -o build/tutorial/sleep-count.upatch
      wrote build/tutorial/sleep-count.upatch (insns=1184 sig=4853 data=3024 sections=2 maps=1 progs=1 decoders=0 name=sleep-count)

   Run from the checkout root, the helper finds the libbpf headers in
   :src:`vendor/libbpf` and the kernel types in ``vendor/linux/vmlinux.h``.
   The upatch takes its name, ``sleep-count``, from the file name, and it
   carries one map and one program. The sizes and digests on this page
   depend on your toolchain and paths.

2. Inspect it:

   .. code-block:: console

      operator$ shirudo upatch info build/tutorial/sleep-count.upatch
      File:                  build/tutorial/sleep-count.upatch
      Name:                  sleep-count
      Type:                  LOAD
      Payload type:          bpf
      Version:               1
      Payload sha256:        d7eaea457b679a8e9a6d4a8708ded501c6a3f604c8756388d9e5e4d6f2922c6f
      ...

   Check that ``Name`` is ``sleep-count`` and ``Type`` is ``LOAD``.

3. Keep its payload digest:

   .. code-block:: console

      operator$ COUNT_PAYLOAD=$(shirudo upatch info --json build/tutorial/sleep-count.upatch | jq -r .payload_sha256)

4. Build the unload directive for this payload:

   .. code-block:: console

      operator$ shirudo build --unload sleep-count --payload-sha256 "$COUNT_PAYLOAD" --keys-dir "$KEYS" -o build/tutorial/sleep-count.unload.upatch
      wrote build/tutorial/sleep-count.unload.upatch (insns=1320 sig=4853 data=2808 sections=2 maps=1 progs=1 decoders=0 name=sleep-count UNLOAD)

Load it and read the map
------------------------

1. Load the upatch on the target:

   .. code-block:: console

      target# shirudo upatch load /workspace/shirudo/build/tutorial/sleep-count.upatch
      upatch load: signed loader accepted, keyring 272801410, 148 instructions
      upatch load: loader ran, 1 maps and 1 programs
      upatch load: program 0 (raw_tracepoint) pinned at /run/shirudo/bpffs/upatches/sleep-count/link
      upatch load: map 0 (calls) pinned at /run/shirudo/bpffs/upatches/sleep-count/maps/calls
      upatch load: sleep-count loaded, 1 programs, keyring 272801410
      upatch load: sleep-count measured, register 88e45b0c80b0ffe83d471b6372402082a5dcf82173adc5c4bdd631039fe4609c

   The loader created the map and the program in the kernel. shirudo
   pinned both in its private bpffs and measured the load.

2. Sleep a few times:

   .. code-block:: console

      target# sleep 1; sleep 1; sleep 1

3. List the maps of the loaded upatches:

   .. code-block:: console

      target# shirudo upatch map
      Pinned maps (1):
        UPATCH                 MAP              TYPE               ENTRIES
        sleep-count            calls            array              max=1

4. Read the map:

   .. code-block:: console

      target# shirudo upatch map sleep-count calls
      Name:                  sleep-count
      Map:                   calls
      Type:                  array
      Max entries:           1
      Entries:               1 of 1
      Key type:              unsigned int (4 B)
      Value type:            unsigned long long (8 B)

      Contents:
        key = 0
           -> 3

   The value is the number of calls so far. It counts every caller on
   the guest, not only your ``sleep`` commands, so yours can be higher.
   Only shirudo's runtime binary can read the map: the LSM refuses the map
   to every other task, root included.

Unload it
---------

1. Unload the upatch:

   .. code-block:: console

      target# shirudo upatch unload /workspace/shirudo/build/tutorial/sleep-count.unload.upatch
      upatch unload: signed loader accepted, keyring 272801410, 165 instructions
      upatch unload: sleep-count carries the directive's payload
      upatch unload: sleep-count measured, register 52764aa4e68b762c7e5bbacf1261bd3242b44a0b66876f34c89c5b8d57da7177
      upatch unload: sleep-count detached and unpinned

2. Check that the map is gone:

   .. code-block:: console

      target# shirudo upatch map
      Pinned maps (0):
        none

The count was lost with the unload: the map lived only as long as the
upatch. A single counter fits an array map. A upatch that accumulates
records keeps them in a BPF arena, with a serializer program that exports
them in one consistent snapshot.

Next steps
----------

- :doc:`/upatches/learn/kernel-fix-tutorial` takes a real kernel fix to a
  shipped upatch.
- :doc:`/upatches/write/attach-kinds` lists the attachment kinds besides
  ``fentry``.
- :doc:`/upatches/write/maps-arenas-serializers` explains arenas and
  serializers.
- :doc:`publish-package` ships a upatch through an OCI registry.
- :doc:`/reference/cli/upatch-map` describes every option of
  ``shirudo upatch map``.
