..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

Overhead
========

What shirudo uses on a target: files, memory, CPU time, TPM commands,
network traffic and disk writes. The base platform is what every target
pays with no upatch loaded. Each upatch adds a fixed cost on top of it,
and the cost of its own programs and maps, which depends on how the
upatch is written.

Sizes and limits come from the code and the build. Times and memory peaks
come from one test VM, described under `Measurement setup`_. They show
orders of magnitude for that system. Other CPUs, kernels, disks and TPMs
give other numbers, and every command that talks to the TPM takes as long
as the TPM takes to answer.

Measurement setup
-----------------

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Item
     - Value
   * - shirudo
     - Commit ``ba550c6ab2b3ff1123569fe4eace7b128401400a``, the bundle
       that ``make -C testing test-vm-bundle`` builds at that commit, with
       its runtime image built at the default 15 MiB around the target
       binary alone, and config images of the default 1 MiB.
   * - Host
     - AMD Ryzen 9 3950X, Ubuntu 24.04, QEMU 8.2.2 with KVM.
   * - Guest
     - A test VM: ``q35`` machine, 4 vCPUs (``-cpu host``), 4 GiB of
       memory, Ubuntu 26.04 with systemd 259.
   * - Kernel
     - bpf-next, built by ``make -C testing kernel``.
   * - TPM
     - swtpm 0.7.3, a software TPM, through ``/dev/tpmrm0``.
   * - Method
     - Peak RSS and wall time per command from ``wait4()``, the median of
       three to ten runs. Loads and unloads are single runs. CPU time per
       timer run from systemd's accounting of the service, averaged over
       24 runs of each 5 s timer and 3 of each 60 s timer. Hook times from
       the kernel's own BPF program statistics with
       ``kernel.bpf_stats_enabled=1``, read from userspace, with no BPF
       program of the measurement's own. They count the run of each
       program, not the trampoline around it, and the statistics add two
       clock reads to every run.

Base platform
-------------

Files and images
~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 24 26 50

   * - Item
     - Size
     - Notes
   * - Target binary
     - 17.0 MiB as built, 12.7 MiB without symbols, 3.8 MiB compressed
       with ``xz -9``
     - Static PIE. It contains OpenSSL, libcurl, tpm2-tss, libelf, zlib,
       zstd, LuaJIT, libbpf and the guard BPF objects. ``make
       install-target``, the tarballs and the Debian package install it as
       built. ``shirudo-gen-runtime`` strips it for the runtime image.
   * - Binary in the initrd
     - 14.0 MiB before compression
     - dracut removes the debug sections. The ``90shirudo`` module adds
       the certificates, 7.3 KiB each, and ``shirudo-initrd.service``.
   * - Runtime image
     - 15 MiB by default, plus a 128 KiB hash tree
     - ``shirudo-gen-runtime --size``. It holds the stripped binary, its
       certificates and its settings, and leaves 1.3 MiB free with the
       x86-64 binary.
   * - Config image
     - 1 MiB by default, plus a 16 KiB hash tree
     - ``shirudo-gen-image --size``. The test VM's boot config leaves
       912 KiB of it free. ``image update`` keeps every config
       image it fetches under ``/var/lib/shirudo/images``. shirudo removes
       none of them.
   * - ``/var/lib/shirudo`` without images
     - 22 KiB after the first boot
     - Certificates, a 1.9 KiB eventlog and the config activation state.
   * - ``/run/shirudo``
     - ``tmpfs`` limited to 16 MiB
     - Holds the mount points of the images and the private bpffs. It
       held no file data in the test VM.
   * - Eventlog growth
     - 1.9 KiB per boot, 350 B per upatch load or unload
     - shirudo never shortens the eventlog. See the size limits in
       :doc:`/reference/eventlog`.

.. figure:: /images/operate-runtime-image.svg
   :alt: Of the 15 MiB runtime image, the stripped target binary takes
         12.7 MiB, file system structures, certificates and settings
         1.0 MiB, and 1.3 MiB stay free.

   Figure 1. The default runtime image of 15 MiB around the stripped
   x86-64 target binary.

Boot
~~~~

``shirudo-initrd.service`` ran for 1.17 s in the test VM, nearly all of
it in the three steps of Figure 2: mapping, reading and verifying the
runtime and config images and sealing the keyrings, loading and
attaching the guards, and defining and binding the measurement register
with its extension of PCR 9.

.. figure:: /images/operate-initrd-init.svg
   :alt: Images and keyrings take 0.12 s, the guards 0.46 s and the
         measurement register 0.56 s.

   Figure 2. Steps of ``init`` in the initrd.

``init`` reads every image completely through its dm-verity mapping
before it uses it, so each boot reads the whole runtime image and the
active config image from disk. The second ``init``, from the root file
system, took 120 ms and sends no register extension.

Memory
~~~~~~

No shirudo process runs between commands. Every command calls
``mlockall(MCL_CURRENT | MCL_FUTURE)`` first, so all of its memory,
including the pages of the binary it maps, stays resident and locked
until it exits. The units set ``LimitMEMLOCK=infinity`` for this, see
:doc:`/reference/systemd-units`.

.. list-table::
   :header-rows: 1
   :widths: 56 22 22

   * - Command
     - Peak RSS
     - Wall time
   * - ``shirudo version``
     - 12.9 MiB
     - 1.3 ms
   * - ``shirudo status``
     - 20.5 MiB
     - 72 ms
   * - ``shirudo status --otel --include-system``, the keepalive timer
       before it quoted its body
     - 20.5 MiB
     - 72 ms
   * - ``shirudo upatch map --all``, the map export timer, no upatch
       loaded
     - 20.5 MiB
     - 48 ms
   * - ``shirudo bpm repo update``, ``bpm upgrade`` and ``bpm tree sync``
       with no repository or tree configured
     - 20.5 MiB
     - 48 to 62 ms
   * - ``shirudo init``, second run in a boot
     - 21.1 MiB
     - 120 ms
   * - ``shirudo upatch load`` and ``upatch unload`` of an 8.4 KiB upatch
     - 29.7 MiB
     - 0.50 to 0.51 s
   * - ``shirudo attest``
     - 20.5 MiB
     - 0.46 s

Larger inputs raise the peak. These limits bound it:

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Input
     - Limit
   * - upatch file
     - 16 MiB. ``upatch load`` holds the file twice and allocates a
       16 MiB verifier log.
   * - Registry responses read into memory
     - 16 MiB: manifests, the repository index and its signature, tree
       publications and the upatch artifacts they name.
   * - Package archive
     - 256 MiB, written to disk, and 256 MiB unpacked.
   * - JSON documents, the repository index and the eventlog among them
     - 8 MiB, read whole.
   * - Lua decoder
     - 32 MiB of heap, which holds the copy of the map it decodes, and
       1,000,000 instructions per run.
   * - OTLP request
     - ``map_export.otlp_max_bytes``, 4 MiB by default and 8 MiB at most.
       One decoded record: ``map_export.log_record_max_bytes``, 1 MiB by
       default.
   * - Map reads
     - No limit. An export reads every map of every loaded upatch whole,
       one map at a time, so its memory follows the size of the largest
       map.

In the kernel, the guards stay loaded until shutdown:

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Object
     - Size
   * - Programs
     - 48 BPF LSM programs on 39 hooks: 50,952 B of translated
       instructions, 28,281 B JIT-compiled, 196 KiB charged as locked
       memory. The kernel adds a BPF trampoline for each hook.
   * - Maps
     - Nine: small arrays for the identity record, the tamper counters and
       internal records, a hash map for 128 dm-verity devices that the
       kernel allocates in full when it creates it, three task-storage
       maps and one inode-storage map.
   * - Task storage
     - About 0.5 KiB for each task that has executed a program or written
       a file, computed from the kernel's local-storage layout: two
       storage elements and the per-task storage header. The kernel frees
       it when the task exits.
   * - Inode storage
     - One element for each directory under shirudo's seal label while
       its inode is cached.

Guard hooks
~~~~~~~~~~~

The kernel runs the guards on every operation their hooks cover,
whether or not the operation touches shirudo's state.
:doc:`/internals/enforcement` describes what each hook checks. The BPF
time one operation cost in the test VM, summed over every guard program
it ran. The BPF trampoline's own work on each call, RCU and recursion
handling among it, comes on top and is not counted here:

.. list-table::
   :header-rows: 1
   :widths: 30 50 20

   * - Operation
     - Hooks
     - BPF time
   * - ``fork()`` and ``execve()`` of ``/bin/true`` from a shell
     - ``task_alloc``, ``bprm_check_security``, ``bprm_committed_creds``,
       and ``file_open``, ``mmap_file`` and ``file_mprotect`` for the
       files the new program maps
     - 3.2 µs
   * - Open, read and close an existing file
     - ``file_open``
     - 0.15 µs
   * - Create, write, rename and unlink a file
     - ``file_open``, ``inode_create``, ``inode_init_security``,
       ``inode_rename``, ``inode_unlink``
     - 0.65 µs
   * - ``mmap()``
     - ``mmap_file``
     - 37 ns
   * - ``mprotect()``
     - ``file_mprotect``
     - 0.15 µs
   * - ``ioctl()``
     - ``file_ioctl``
     - 0.28 µs

In the loops behind these numbers, the guards took 6.4 ms of 845 ms for
2,000 forks and execs, 6.5 ms of 133 ms for 10,000 file cycles on
``ext4`` and ``tmpfs``, and 2.9 ms of 37 ms for 20,000 opens. Other hooks
with guards run on frequent operations as well: ``inode_setattr``,
``inode_setxattr``, ``inode_removexattr``, ``ptrace_access_check``,
``task_prctl`` and ``key_permission``. On an otherwise idle target the
guards ran 56,452 times per minute for a total of 2.8 ms, mostly for
shirudo's own timer runs.

Timers
~~~~~~

The four timers start a new ``shirudo`` process each time. Every run of
a target command other than ``init`` and ``version`` checks that all 48
guards are attached, loading the kernel's BTF to do so, and creates the
TPM attestation key, see `TPM commands`_.

.. list-table::
   :header-rows: 1
   :widths: 36 30 16 18

   * - Unit
     - Interval
     - CPU per run
     - Runs per minute
   * - ``shirudo-keepalive.service``
     - 60 s after the previous run ends
     - 17.9 ms before it quoted its body
     - 1
   * - ``shirudo-map-export.service``
     - 5 s after the previous run ends
     - 14.5 ms with no upatch loaded
     - 11.9
   * - ``shirudo-bpm-repo-update.service``, two processes per run
     - 60 s after the previous run ends
     - 32.3 ms
     - 1
   * - ``shirudo-bpm-tree-sync.service``
     - 60 s after the previous run starts
     - 9.8 ms
     - 1

Together they used 0.43 s of CPU time per minute in the test VM, 0.71 %
of one vCPU, in about 27 process starts, when the keepalive ran every
5 seconds and sent no quote. Figure 3 shows that measurement, with the
keepalive and map export timers taking most of it. The keepalive now
runs once a minute, which leaves it one run of the 11.8 the figure
counts, plus the quote below, which the measurement does not include.

.. figure:: /images/operate-timer-cpu.svg
   :alt: Per minute, keepalive uses 212 ms of CPU time, map export 172 ms,
         package update and upgrade 32 ms and tree sync 10 ms.

   Figure 3. CPU time of the four timers per minute, with no upatch
   loaded.

To read the CPU time of a timer's last run on your own target:

.. code-block:: console

   target# systemctl show shirudo-keepalive.service -p CPUUsageNSec
   CPUUsageNSec=19073000

TPM commands
~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Operation
     - TPM work
   * - Every target command except ``init`` and ``version``
     - Creates the ECC P-256 attestation key, reads the clock and the
       config PCR.
   * - ``status``
     - Adds reads of the measurement register's NV index.
   * - ``status --otel``
     - Adds a second attestation key, created with
       ``TPM2_CreatePrimary`` for the quote and flushed after it, and
       ``TPM2_Quote`` of the keepalive body.
   * - ``upatch load``, ``upatch unload``
     - One register extension: about 20 commands, among them a new
       RSA-3072 primary key (the NV writer key), a new attestation key, a
       signature, a policy session and ``TPM2_NV_Extend``.
   * - ``init`` in the initrd
     - Two RSA-3072 primary keys and two attestation keys,
       ``TPM2_NV_UndefineSpace`` and ``TPM2_NV_DefineSpace`` of the
       register, the first extension, and extensions of PCR 9 and the
       config PCR.
   * - ``init`` again in the same boot
     - Reads only.
   * - ``attest``
     - A quote over 14 PCRs by default, ``TPM2_NV_Certify`` of the
       register and the endorsement key.

With the default timers an idle target creates its attestation key about
17 times per minute, twice in each keepalive. The register is an orderly NV index, so an
extension updates it in TPM RAM rather than writing NV memory each time.
``init`` defines the index again at every boot. In the test VM, with
swtpm, the extension took 0.44 s of a 0.50 s load, binding the register
at boot 0.56 s and ``attest`` 0.46 s.
:doc:`/concepts/background/tpm` explains the objects involved.

The keepalive's ``TPM2_CreatePrimary`` derives the P-256 key from the
endorsement seed at every run. A firmware or discrete TPM can take
hundreds of milliseconds for it, which the keepalive spends once a
minute. Keeping the key under a persistent handle would avoid it, at the
price of TPM state shirudo does not keep today;
:doc:`/internals/design-decisions` records the choice.

Network
~~~~~~~

With no repository, tree or export endpoint configured, shirudo sends
nothing.

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Source
     - Traffic
   * - Keepalive
     - One OTLP/HTTP request per run when ``map_export.otel_endpoint`` or
       ``OTEL_EXPORTER_OTLP_ENDPOINT`` names a collector.
   * - Map export
     - One OTLP/HTTP request per map of every loaded upatch per run when
       ``map_export.otel_endpoint`` is set. Without it and without
       ``map_export.json_path``, the export prints the maps to standard
       output, and the journal stores them.
   * - ``bpm repo update``
     - Every minute, for every configured repository: the index manifest,
       the whole index and its signature, with no conditional request. A
       registry that wants a token adds a refused request and a token
       request before each of them.
   * - ``bpm upgrade``
     - Nothing unless the cached index lists a newer version of an
       installed package.
   * - ``bpm tree sync``
     - Every minute with a tree configured: its manifest, payload and
       signature.

Each request opens a new connection with its own TLS 1.3 handshake.
:doc:`/operate/run/telemetry` and :doc:`/operate/run/deliver-packages` describe
the settings.

Disk writes
~~~~~~~~~~~

- ``bpm upgrade`` rewrites ``bpm/state.json`` with ``fsync()`` every
  minute, also when nothing changed. ``bpm repo update`` rewrites the
  cached index of every repository.
- ``bpm tree sync`` rewrites ``bpm/upatch-tree/state.json`` with
  ``fsync()`` twice every minute with a tree configured, also when
  nothing changed, and appends a line of about 220 bytes to
  ``bpm/upatch-tree/outcomes`` with ``fsync()`` for every new tree
  operation. It reads that file once at the start of a sync.
- shirudo appends every eventlog record with ``fsync()``.
- Map export creates an empty lock file for every map it exports in
  ``/var/lib/shirudo/locks``, named by the kernel's map ID. Map IDs change
  at every load and every boot, and the files stay.
- systemd logs about 5 KiB per minute for the starts and stops of the
  four timers' services.

upatches
--------

An upatch costs the target in two ways: a fixed cost that shirudo adds
for every upatch, whatever it does, and the cost of its own programs and
maps. shirudo limits neither how many programs and maps an upatch brings
nor how often the kernel runs them. The verifier bounds a single program
run, not the work an upatch does on a hook that fires for every open or
exec, nor the size of its maps. A badly written upatch can slow the
target down or use much of its memory.

Per-upatch baseline
~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Item
     - Cost
   * - Signed file
     - 8.4 KiB for an upatch with one small program, 4,627 B of it the
       ML-DSA-87 signature. An unload directive is 9.1 KiB.
   * - Copies on disk
     - One in ``/var/lib/shirudo/upatches``. An upatch from a package also
       stays in the package archive and its unpacked directory, and an
       upgrade keeps those of the previous version until
       ``bpm uninstall``.
   * - Eventlog
     - About 330 B plus the length of its name per load and per unload,
       and about 100 B plus the name in the init record of every boot
       that restores it.
   * - TPM
     - One register extension per load and per unload. Restoring loaded
       upatches at boot adds no extension.
   * - Load
     - 29.7 MiB peak RSS in the loading process. The signed loader runs
       once and is freed.
   * - Kernel
     - A pin for every link and map in the private bpffs.
   * - Timers
     - Map export reads every map of the upatch every 5 s and, with an
       endpoint configured, sends one request per map. ``status`` reports
       the upatch.

Programs and maps of an upatch
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Its programs run on every event of their hooks. Their time adds to the
  guards' time on the same operation.
- Array maps and hash maps created without ``BPF_F_NO_PREALLOC`` take
  their full size when the loader creates them. An arena takes pages as
  the programs write them. Local storage grows with the tasks, sockets or
  inodes it is attached to.
- The verifier's time at load grows with the size and branches of the
  programs. It runs in the kernel, in the loading process.
- Serializer programs and Lua decoders run at every export, every 5 s.
  The Lua limits above bound a decoder.

:doc:`/upatches/write/maps-arenas-serializers` explains how an upatch keeps
records in an arena.

kernel-obs example
~~~~~~~~~~~~~~~~~~

The observability package in :src:`upatches/kernel-obs` is one example,
measured in the same test VM:

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Item
     - Value
   * - Signed file
     - 819 KiB.
   * - Programs
     - 35: 24 on LSM hooks, 2 on cgroup socket buffers, 8 serializers and
       1 test program. 348,248 B of translated instructions, 184,460 B
       JIT-compiled.
   * - Maps
     - 18. Its records live in one arena of up to 4,096 pages, 16 MiB with
       4 KiB pages, which it fills as it records.
   * - Load
     - 1.97 to 2.19 s, 1.42 to 1.47 s of it CPU time in the kernel.
       31.0 MiB peak RSS.
   * - Unload
     - 0.50 s.
   * - Added hook time
     - 4.1 µs per ``fork()`` and ``execve()``, 0.14 µs per open.
   * - Export
     - 72 ms and 20.4 MiB per ``upatch map --all`` run. With no export
       destination configured, its map output put about 550 KiB per
       minute into the journal. The amount follows what its maps hold.

Figure 4 sets the hook time kernel-obs adds beside that of the guards.
On ``fork()`` and ``execve()`` it more than doubles the BPF time: it runs
a program of its own on each hook they pass, ``task_alloc``,
``bprm_check_security``, ``file_open``, ``mmap_file`` and
``file_mprotect``.

.. figure:: /images/operate-hook-time.svg
   :alt: BPF time per operation for the guards and for kernel-obs:
         fork and exec 3.2 and 4.1 µs; create, write, rename and unlink
         0.65 and 0.14 µs; open, read and close 0.15 and 0.14 µs; ioctl
         0.28 µs and none; mprotect 0.15 and 0.12 µs; mmap 0.04 and
         0.08 µs.

   Figure 4. BPF time per operation, the guards and kernel-obs on top of
   them.

Related
-------

- :doc:`/operate/plan/system-requirements`
- :doc:`/operate/plan/scalability`
- :doc:`/reference/systemd-units`
- :doc:`/reference/files`
- :doc:`/reference/eventlog`
- :doc:`/internals/enforcement`
- :doc:`/concepts/background/tpm`
