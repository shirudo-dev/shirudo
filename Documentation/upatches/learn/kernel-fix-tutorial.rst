..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Tutorial
:audience: upatch authors

From a kernel fix to a upatch
==============================

This tutorial takes one kernel fix to a signed upatch, loads it on a test
target, unloads it again, and packages it for a registry. The example is
CVE-2026-63984, an overflow in the IPv6 RPL routing header code, whose
detector ships in :src:`upatches/kernel-cve/sources/`. You read the fix,
decide where the upatch attaches, write the program, then build, inspect,
test, unload, package and publish it.

Before you begin
----------------

- A shirudo checkout built with ``make`` and ``make shirudo-build``, and
  clang 23 installed as ``/usr/bin/clang``, the path the build helper
  runs.
- A test VM running from that checkout, as :doc:`/upatches/test/testing`
  describes. The
  steps below use the default ``bpf-next`` VM and the signing key its
  bundle enrolled.
- A Linux kernel git tree, to read the fix.
- For the last step only, an OCI registry you can push to.

Run the operator commands as root, the user who built the test VM and
owns the key it enrolled, from the checkout's root at first, with the
binary and the helper on your path:

.. code-block:: console

   operator$ export PATH="$PWD:$PWD/tools/shirudo-build:$PATH"

Read the fix
------------

Start from the commit that fixes the bug, not from the CVE text. The fix
says exactly which inputs are dangerous, and that condition becomes the
upatch's predicate. In a kernel tree:

.. code-block:: console

   $ git show 9d5e7a46a9f6

The commit is ``ipv6: rpl: fix hdrlen overflow in
ipv6_rpl_srh_decompress()``. ``ipv6_rpl_srh_rcv()`` derives ``n`` from a
received RPL routing header, which carries ``n + 1`` addresses, and calls
``ipv6_rpl_srh_decompress()``. That function stores
``((n + 1) * 16) >> 3`` in the 8-bit ``hdrlen`` of the header it builds.
From ``n = 127`` on, the value no longer fits, the recompressed header
lands inside the decompressed addresses, and the recompression corrupts
the routing header of the forwarded packet. The fix
changes one bound in ``ipv6_rpl_srh_rcv()`` from ``(n + 1) > 255`` to
``(n + 1) > 127``.

Two facts from the source shape the upatch. The dangerous call is a call
of ``ipv6_rpl_srh_decompress()`` with ``n + 1 > 127``. And the kernel only
reaches it when ``net.ipv6.conf.all.rpl_seg_enabled`` and the receiving
interface's ``rpl_seg_enabled`` are both set.

Choose the attach point
-----------------------

A upatch can refuse the dangerous input or record it. Refusing needs a
hook that can change the outcome:

- ``fmod_ret`` would return early from ``ipv6_rpl_srh_rcv()`` or its
  caller ``ipv6_rthdr_rcv()``. The kernel admits ``fmod_ret`` only on
  ``security_*`` hooks, system call entry points, functions marked for
  error injection or return modification, and functions its build
  tagged because they return errors
  (:doc:`/concepts/background/fmod-ret`). Neither function is marked,
  and the build tags neither: both return -1 on every failure, which
  the build does not take for an error code.
- A ``netfilter`` program at IPv6 pre-routing could drop such packets
  before the routing header code sees them, by parsing the routing header
  itself. That parser is a larger piece of work than this tutorial.

So this upatch records. ``ipv6_rpl_srh_decompress()`` is a global function
that is present in the kernel's BTF, and ``n`` is its fourth argument. The
shipped detector, ``cve-2026-63984-rpl-detector.bpf.c``, attaches a
``kprobe`` there. This tutorial uses ``fentry`` instead, for three
reasons: the program receives the arguments with their BTF types instead
of raw registers, the verifier checks the program's prototype against the
kernel's, and the test VM's kernel is built without kprobes.
:doc:`/upatches/write/attach-kinds` compares the kinds.

Write the program
-----------------

Work in a directory under ``build/``, which git ignores and the test VM
sees. Create it and change into it:

.. code-block:: console

   operator$ mkdir -p build/rpl-shield && cd build/rpl-shield

Generate a ``vmlinux.h`` from the BTF of the kernel the upatch is for,
here the test VM's:

.. code-block:: console

   operator$ ../../tools/gen-vmlinux-h/gen-vmlinux-h \
       ../../artifacts/bpf-next-kernel-debs/vmlinux.btf > vmlinux.h

The compiler looks for libbpf's headers under ``./vendor/libbpf``, so link
the checkout's vendored copy into the directory:

.. code-block:: console

   operator$ ln -s ../../vendor vendor

Write ``cve-2026-63984-rpl.bpf.c``:

.. code-block:: c

   // SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
   /*
    * CVE-2026-63984: count ipv6_rpl_srh_decompress() calls whose segment
    * count overflows the 8-bit hdrlen the function computes.
    */

   #include "vmlinux.h"
   #include <bpf/bpf_helpers.h>
   #include <bpf/bpf_tracing.h>

   char _license[] SEC("license") = "Dual BSD/GPL";

   struct {
           __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
           __uint(max_entries, 1);
           __type(key, __u32);
           __type(value, __u64);
   } hits SEC(".maps");

   struct {
           __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
           __uint(max_entries, 1);
           __type(key, __u32);
           __type(value, __u64);
   } activity SEC(".maps");

   static __always_inline void count_event(void *map)
   {
           __u32 zero = 0;
           __u64 *count = bpf_map_lookup_elem(map, &zero);

           if (count)
                   (*count)++;
   }

   SEC("fentry/ipv6_rpl_srh_decompress")
   int BPF_PROG(cve_2026_63984_rpl, struct ipv6_rpl_sr_hdr *outhdr,
                const struct ipv6_rpl_sr_hdr *inhdr,
                const struct in6_addr *daddr, unsigned char n)
   {
           count_event(&activity);
           if ((__u32)n + 1 > 127)
                   count_event(&hits);
           return 0;
   }

The maps and the predicate are the shipped detector's. ``activity`` counts
every call, which shows that the upatch is attached and the path is in
use. ``hits`` counts the calls the fix rejects. Per-CPU counters need no
locking. The section name and the ``BPF_PROG`` prototype are what changed
from the ``kprobe`` version, which also needs a ``__TARGET_ARCH_*`` define
to read arguments from registers.

Build and sign it
-----------------

The test VM enrolled the certificate of the key in
``/tmp/shirudo-test-vm-private-<uid>/operator-keys/keys``, where
``<uid>`` is your user ID. Sign with that key:

.. code-block:: console

   operator$ shirudo build cve-2026-63984-rpl.bpf.c --vmlinux vmlinux.h \
       --keys-dir <keys-dir> -o cve-2026-63984-rpl.upatch
   wrote cve-2026-63984-rpl.upatch (insns=1376 sig=4853 data=3480 sections=2 maps=2 progs=1 decoders=0 name=cve-2026-63984-rpl)

``<keys-dir>`` is that directory. ``shirudo build`` compiled the source, generated the
signed loader around the object, signed it with ML-DSA-87 and named the
upatch after the file, ``cve-2026-63984-rpl``. The sizes and digests on
this page depend on your headers and paths.

Inspect it
----------

Read the artifact back before it leaves the operator host:

.. code-block:: console

   operator$ shirudo upatch info cve-2026-63984-rpl.upatch
   File:                  cve-2026-63984-rpl.upatch
   Name:                  cve-2026-63984-rpl
   Type:                  LOAD
   Payload type:          bpf
   Version:               1
   Payload sha256:        f3e2894d7c20d90e759b9d716849fc2acf01ff5de2ad8565b1e0f0320ef9e711
   File size:             10069 bytes

   Loader:
     Instructions:          off=360 len=1376
     Log buffer size:       1048576
     Data:                  off=6589 len=3480

   Signature:
     Offset:                1736
     Length:                4853 bytes

   Signed sections:
     Name:                  cve-2026-63984-rpl
     Attach metadata:       176 bytes
     Unload payload:        (none)

   Decoders:
     (none)

``Payload sha256`` is the SHA-256 of the signed loader and its data. The
signed sections hold the name and the attach metadata, one program entry
for the fentry program. The file carries no decoders, because the source
declares none.

Build the unload directive next, bound to that digest:

.. code-block:: console

   operator$ shirudo build --unload cve-2026-63984-rpl \
       --payload-sha256 "$(shirudo upatch info --json cve-2026-63984-rpl.upatch | jq -r .payload_sha256)" \
       --keys-dir <keys-dir> -o cve-2026-63984-rpl.unload.upatch
   wrote cve-2026-63984-rpl.unload.upatch (insns=1320 sig=4853 data=2808 sections=2 maps=1 progs=1 decoders=0 name=cve-2026-63984-rpl UNLOAD)

The directive removes only a loaded upatch with exactly this payload.

Test it on the target
---------------------

In a second terminal, at the checkout's root, open a shell on the test VM:

.. code-block:: console

   # make -C testing vm-ssh

The VM sees the checkout read-only at ``/mnt/shirudo-src``. Run shirudo
there as ``shirudo-runtime``, which executes the binary from the verified
runtime image. Load the upatch and print the report:

.. code-block:: console

   target# shirudo-runtime upatch load --report=- \
       /mnt/shirudo-src/build/rpl-shield/cve-2026-63984-rpl.upatch
   upatch load: signed loader accepted, keyring 531121468, 172 instructions
   upatch load: loader ran, 2 maps and 1 programs
   upatch load: program 0 (fentry) pinned at /run/shirudo/bpffs/upatches/cve-2026-63984-rpl/link
   upatch load: map 0 (hits) pinned at /run/shirudo/bpffs/upatches/cve-2026-63984-rpl/maps/hits
   upatch load: map 1 (activity) pinned at /run/shirudo/bpffs/upatches/cve-2026-63984-rpl/maps/activity
   upatch load: cve-2026-63984-rpl loaded, 1 programs, keyring 531121468
   upatch load: cve-2026-63984-rpl measured, register 3380b0e2d22c066ecba561c182869b1366e5706f73fc3a657b907394953cfbfc
   {"schema":1,"result":"ok","op":"upatch_load","phase":"done","errno":null,"errno_name":null,"category":"ok","message":"","verifier_log":"","loader_return":0,"upatch":{"path":"/mnt/shirudo-src/build/rpl-shield/cve-2026-63984-rpl.upatch","name":"cve-2026-63984-rpl","payload_sha256":"f3e2894d7c20d90e759b9d716849fc2acf01ff5de2ad8565b1e0f0320ef9e711"},"kernel":{"release":"7.3.0-bpf-next+"},"tpm":{"nv_index":"0x01818E00","chain_after":"3380b0e2d22c066ecba561c182869b1366e5706f73fc3a657b907394953cfbfc"}}

The log lines go to standard error and the JSON report to standard
output. The report has ``"result":"ok"``, phase ``done`` and category
``ok``, and its ``tpm.chain_after`` is the measurement register after the
load. ``program 0 (fentry) pinned at ...`` means that shirudo attached
the fentry program at the function the verifier bound, and pinned the
link.
:doc:`/upatches/test/debugging` explains the report when a load fails.

Check where the kernel attached it and read the counters:

.. code-block:: console

   target# shirudo-runtime upatch get cve-2026-63984-rpl
   Name:                  cve-2026-63984-rpl
   Location:              fentry/ipv6_rpl_srh_decompress
   Program ID:            77
   Loaded at:             <time>  (12s ago)
   Payload sha256:        f3e2894d7c20d90e759b9d716849fc2acf01ff5de2ad8565b1e0f0320ef9e711  (signature-bound)
   Maps:                  activity, hits

   Source (kernel BTF line_info):

     <checkout>/build/rpl-shield/cve-2026-63984-rpl.bpf.c:
          29: __u32 zero = 0;
          30: __u64 *count = bpf_map_lookup_elem(map, &zero);
          32: if (count)
          33: (*count)++;
          37: int BPF_PROG(cve_2026_63984_rpl, struct ipv6_rpl_sr_hdr *outhdr,
          42: if ((__u32)n + 1 > 127)

   == Map: activity ==
   ...

``<time>`` is the time of the load and ``<checkout>`` the path of your
checkout on the host, where the compiler saw the source. ``upatch get``
shows the attach site, ``fentry/ipv6_rpl_srh_decompress``, the source
lines the kernel holds for the program, and the maps with their contents.
Read one map:

.. code-block:: console

   target# shirudo-runtime upatch map cve-2026-63984-rpl hits
   Name:                  cve-2026-63984-rpl
   Map:                   hits
   Type:                  percpu_array (64 CPUs)
   Max entries:           1
   Entries:               1 of 1
   Key type:              unsigned int (4 B)
   Value type:            unsigned long long (8 B)

   Contents:
     key=0: sum=0
       cpu0=0        cpu1=0        cpu2=0        cpu3=0
   ...

Both counters stay at zero until the kernel processes an RPL routing
header, which needs ``rpl_seg_enabled`` set and a crafted packet. On a
kernel that carries the fix, ``ipv6_rpl_srh_rcv()`` drops a header with
too many addresses before the call, so ``hits`` stays at zero there even
under attack.

Unload it
---------

Apply the unload directive:

.. code-block:: console

   target# shirudo-runtime upatch unload --report=- \
       /mnt/shirudo-src/build/rpl-shield/cve-2026-63984-rpl.unload.upatch
   upatch unload: signed loader accepted, keyring 531121468, 165 instructions
   upatch unload: cve-2026-63984-rpl carries the directive's payload
   upatch unload: cve-2026-63984-rpl measured, register 3b96bfbac667807c99332a8d2ba9d2a7b5eb74db42aba18eea452bef9a7d0c6b
   upatch unload: cve-2026-63984-rpl detached and unpinned
   {"schema":1,"result":"ok","op":"upatch_unload","phase":"done","errno":null,"errno_name":null,"category":"ok","message":"","verifier_log":"","loader_return":0,"upatch":{"path":"/mnt/shirudo-src/build/rpl-shield/cve-2026-63984-rpl.unload.upatch","name":"cve-2026-63984-rpl","payload_sha256":"f3e2894d7c20d90e759b9d716849fc2acf01ff5de2ad8565b1e0f0320ef9e711"},"kernel":{"release":"7.3.0-bpf-next+"},"tpm":{"nv_index":"0x01818E00","chain_after":"3b96bfbac667807c99332a8d2ba9d2a7b5eb74db42aba18eea452bef9a7d0c6b"}}

The report again shows category ``ok``. The kernel verified the
directive's signature, shirudo matched its digest against the pinned
upatch, measured the unload, and removed the pins and the archive copy.
``shirudo-runtime upatch list`` no longer shows the upatch. Leave the VM
shell.

Package it
----------

A package carries the upatch, its unload directive and an optional entry
for the upatch tree. In ``build/rpl-shield`` on the operator host, write
``Beefile``:

.. code-block:: toml

   [package]
   name = "rpl-shield"
   description = "Detector for CVE-2026-63984 in ipv6_rpl_srh_decompress()"
   license = "GPL-2.0 OR BSD-2-Clause"
   authors = ["Example Org"]

   [[upatches]]
   source = "cve-2026-63984-rpl.bpf.c"

   [upatches.tree]
   id = "cve-2026-63984-rpl"

   [upatches.tree.selector.kconfig]
   CONFIG_IPV6 = ["y", "m"]

The upatch name in a package is always the source's base name, and the
tree ``id`` must equal it. The selector limits the tree entry to kernels
built with IPv6. A target evaluates it against ``/proc/config.gz`` or
``/boot/config-<release>``. A target that has neither does not match, and
a target that does not match an entry passes over it for good.
:doc:`/reference/formats/beefile` lists every key.

Build the package:

.. code-block:: console

   operator$ shirudo bpm build --version 1.0.0 --vmlinux vmlinux.h \
       --keys-dir <keys-dir>
   wrote /tmp/shirudo-bpm-build.<random>/0.upatch (insns=1376 sig=4853 data=3480 sections=2 maps=2 progs=1 decoders=0 name=cve-2026-63984-rpl)
   wrote /tmp/shirudo-bpm-build.<random>/0.unload.upatch (insns=1320 sig=4853 data=2808 sections=2 maps=1 progs=1 decoders=0 name=cve-2026-63984-rpl UNLOAD)
   <checkout>/build/rpl-shield/rpl-shield-1.0.0.bee

``<random>`` is the suffix of a temporary directory and ``<checkout>`` the
path of your checkout. ``bpm build`` compiled and signed the upatch again,
generated its unload directive from the new payload digest, and wrote
``rpl-shield-1.0.0.bee``. Built from the same source, headers and
directory, the packaged upatch has the same payload digest as the one you
tested. List what the package will load:

.. code-block:: console

   operator$ shirudo bpm info upatches rpl-shield-1.0.0.bee --all
   upatches/cve-2026-63984-rpl.upatch
   upatches/cve-2026-63984-rpl.unload.upatch

Publish it
----------

Push the package to a repository and add it to the registry's signed
index:

.. code-block:: console

   operator$ shirudo bpm push rpl-shield-1.0.0.bee \
       oci://<registry>/<namespace>/rpl-shield --keys-dir <keys-dir>

Append its tree entry to a tree that targets follow:

.. code-block:: console

   operator$ shirudo bpm tree append rpl-shield-1.0.0.bee \
       oci://<registry>/<namespace>/<tree> --tree-id <tree-id> \
       --keys-dir <keys-dir>

``<registry>`` and ``<namespace>`` name your registry and repository path,
``<tree>`` the repository of the tree and ``<tree-id>`` its id, which an
append to an existing tree must name. ``bpm push`` prints the pushed
reference, ``bpm tree append`` the tree's reference and manifest digest.
A package signed with the test bundle's key is for test targets only.
Sign what a fleet runs with your own key.

Next steps
----------

- :doc:`/upatches/publish/publishing` for the index, the tree and withdrawing an
  entry
- :doc:`/operate/run/deliver-packages` for what a target does with them
- :doc:`/upatches/write/maps-arenas-serializers` and
  :doc:`/upatches/write/decoders` to export what the upatch records
- :doc:`/upatches/write/attach-kinds` for the other places a upatch can attach
