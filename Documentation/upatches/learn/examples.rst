..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: upatch authors

Example packages
================

The tree ships packages under :src:`upatches/`: ``kernel-obs``, a
complete observability package with arena tables, serializers, decoders
and generated ``.rodata``, and in ``kernel-cve`` three small CVE
detectors exported from a mitigation campaign and one CVE mitigation,
each a package of its own.

kernel-obs
----------

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Item
     - Content
   * - Package
     - ``kernel-obs``, from :src:`upatches/kernel-obs/Beefile`
   * - upatch
     - ``kernel-obs``, built from ``kernel-obs.bpf.c``, which includes
       ``obs_exec.bpf.c``, ``obs_net.bpf.c``, ``obs_dns.bpf.c``,
       ``obs_priv.bpf.c`` and ``obs_file.bpf.c``
   * - Attach kinds
     - ``lsm`` and ``lsm.s`` hooks for processes, files, sockets,
       credentials, mounts, modules and ``bpf()``; ``cgroup_skb/ingress``
       and ``cgroup_skb/egress`` for packets and DNS
   * - Tables
     - ``exec``, ``net``, ``socket``, ``listen``, ``watch``, ``dns``,
       ``priv`` and ``file``: one ``obs_table.h`` instance each, all in the
       arena ``obs_i_arena``, each with a serializer and a log decoder
   * - Counters
     - ``watch_stat``, a per-CPU array with a metric decoder
   * - Test-run program
     - ``shirudo_test__kernel_obs`` allocates every table in the arena at
       load
   * - Generated ``.rodata``
     - ``obs_watch_v4`` and ``obs_watch_v6``, generated from
       ``watch.list`` by ``gen_watch_rodata.py``
   * - Enforces
     - nothing, every hook observes

``kernel-obs`` is the reference for the conventions in
:doc:`/upatches/write/maps-arenas-serializers` and
:doc:`/upatches/write/decoders`: the double-buffered
tables, the one-entry maps that name the tables, the arena association,
the page header and the timestamp conversion in the decoders.

Its ``README.md`` is what ``shirudo bpm info`` prints for the package.
It follows here as it ships. Where it tells a target to add a key with
``bpm key add``, note that a production target takes its keys and
repositories from its signed config image and refuses local key changes.
:doc:`/operate/run/deliver-packages` describes that setup.

.. include:: ../../../upatches/kernel-obs/README.md
   :parser: myst_parser.sphinx_

kernel-cve
----------

:src:`upatches/kernel-cve/` holds three detectors, each in
``sources/<slug>/observability/``, a ``vmlinux.h``, ``manifest.json``
with one record per detector, and one Beefile per detector,
``<detector>.bee``. The manifest names the kernel the detectors were
loaded on, ``7.2.0-shirudo-7.2``.

Each Beefile builds a package named after its detector with one upatch
and one ``[upatches.tree]`` entry of the same name. The entry's
``fixes`` names the detector's CVE, and its selector the kernel of the
manifest: release prefix ``7.2``, its build ID, ``x86_64`` and the
Kconfig option of the driver or protocol the detector watches. They are
the shields :src:`tools/put-shields` publishes, as
:doc:`/upatches/publish/publishing` shows.

.. list-table::
   :header-rows: 1
   :widths: 34 26 40

   * - Source
     - Hook
     - ``hits`` counts calls where
   * - ``cve-2025-71093-e1000-tbi-detector.bpf.c``
     - ``kprobe/e1000_tbi_should_accept``
     - the frame length is 0
   * - ``cve-2026-31675-netem-detector.bpf.c``
     - ``kprobe/netem_enqueue``
     - the packet's linear head is empty
   * - ``cve-2026-63984-rpl-detector.bpf.c``
     - ``kprobe/ipv6_rpl_srh_decompress``
     - ``n + 1`` exceeds 127, the bound the fix introduces

Each detector counts every call in a per-CPU ``activity`` counter and the
calls that match its predicate in ``hits``. None of them refuses
anything. They are ``kprobe`` programs and define
``__TARGET_ARCH_x86``, so they need a target with ``CONFIG_KPROBES`` and
``CONFIG_KPROBE_EVENTS`` on x86-64. ``manifest.json`` marks every
predicate as ``source_derived_unvalidated``: derived from the fix, not
checked against an exploit.

:doc:`/upatches/learn/kernel-fix-tutorial` takes the third detector from its fix
to a package, as an ``fentry`` program.

The directory also holds a mitigation, which the manifest does not
list: ``cve-2026-31431-af-alg-block.bee`` builds
``sources/cve-2026-31431-crypto-algif-aead-copy-fail/mitigation/cve-2026-31431-af-alg-block.bpf.c``
into a package of the same shape, with ``fixes`` naming CVE-2026-31431.
Its one program, at ``lsm/socket_create``, refuses every ``AF_ALG``
socket with ``EPERM``. That keeps the ``algif_aead`` code the CVE is in
out of reach, and with it every other use of the kernel's crypto
algorithms through sockets, so a target that needs those cannot take
it. The program reads only the hook's arguments, keeps no state and
loads on every architecture; its selector is the Kconfig option
``CONFIG_CRYPTO_USER_API_AEAD`` alone. :src:`tools/put-shields`
publishes it with the detectors. Beside the source a reproducer,
``reproducer/cve-2026-31431-repro.py``, splices a file's page cache
through a pipe into an ``AF_ALG`` aead socket and reports whether the
bug corrupted it; ``t3115-af-alg-block`` drives it to check the
mitigation refuses the socket.

Related
-------

- :doc:`/upatches/learn/kernel-fix-tutorial` to write a detector of your own
- :doc:`/reference/formats/beefile` for the keys both Beefiles use
