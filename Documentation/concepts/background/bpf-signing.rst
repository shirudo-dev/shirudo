..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

BPF program signing
===================

The kernel can check a signature over BPF code when it is loaded. The
check establishes who produced the code and that it was not tampered with
on the way. It does not stop an unsigned load by itself: the kernel records a
verdict, and a security module decides what to do with it. This page
explains the mechanism, then how shirudo builds on it and where it stops.

Why a program cannot be signed directly
---------------------------------------

The obvious scheme signs a program's instructions at build time and
checks the signature at ``BPF_PROG_LOAD``. It fails because the bytes the
kernel finally loads are not the bytes that were built. Between the two,
libbpf and the kernel rewrite the program:

- map file descriptors are patched into instructions, and a descriptor
  number differs on every run;
- CO-RE relocations rewrite field offsets for the running kernel (see
  :doc:`co-re-btf`);
- references to kfuncs and kernel symbols are resolved to the running
  kernel;
- global data is created and filled as maps at load time.

No fixed byte string is both signable at build time and what the kernel
loads.

Signed loader
-------------

The kernel's answer is to move that rewriting into a small BPF program,
the loader, and to sign the loader instead of the programs. libbpf's
gen_loader emits the loader as a ``BPF_PROG_TYPE_SYSCALL`` program (see
:doc:`bpf`). Its data, everything it installs, lives in a separate array
map, the metadata map. The signature covers both::

    Sig(I_loader || D_meta)

``I_loader`` is the loader's instruction stream and ``D_meta`` the
content of the metadata map. Both are the same on every kernel: the
loader's instructions carry no relocations and refer to the metadata map
by its index in the load's ``fd_array``, not by a descriptor number. The
host-specific rewriting still happens, inside the loader at run time, on
data the kernel has already verified.

Two map properties keep the metadata map trustworthy between the check
and the run:

Exclusive maps
    A map created with ``excl_prog_hash`` may only be used by a program
    whose SHA-256 digest matches that hash. The metadata map is bound to
    exactly one loader.

Frozen maps
    The metadata map is frozen with ``BPF_MAP_FREEZE`` before the loader
    is loaded, so userspace cannot change the signed bytes afterwards.

Verification inside the verifier
--------------------------------

The loader is loaded with ``signature``, ``signature_size`` and
``keyring_id`` set, the metadata map in ``fd_array``, and
``fd_array_cnt`` set so that the kernel resolves every entry up front.
The checks then run in this order:

#. ``security_bpf()`` (``lsm/bpf``) runs at the entry of the ``bpf()``
   system call, before any of what follows.
#. Inside ``bpf_check()``, the kernel resolves ``fd_array`` into the maps
   the program uses.
#. ``bpf_prog_verify_signature()`` refuses a signed program that carries
   CO-RE relocations, checks that each bound map is an exclusive, frozen
   array map without active writers, appends each map's contents to the
   instructions in order and verifies the PKCS#7 signature over the
   result.
#. ``security_bpf_prog_load()`` (``lsm/bpf_prog_load``) runs with the
   verdict already recorded.
#. The verifier analyzes the program. Any map the signature does not
   cover, and any BTF, is refused when the verifier tries to bind it.

Because the maps folded into the signature are the ones the program
binds, from a single resolution of ``fd_array``, nothing can swap the
verified bytes for others after the check. Figure 1 of
:doc:`/internals/signed-loader` places these checks among the calls of
an upatch load.

Verdict
-------

The kernel records the outcome in ``prog->aux->sig``. The verdict is
``BPF_SIG_UNSIGNED`` or ``BPF_SIG_VERIFIED``; there is no partial state.
A signature that fails verification aborts the load. Beside the verdict
the kernel records which kind of keyring verified the signature and, for
a keyring the caller supplied, its serial:

.. list-table::
   :header-rows: 1
   :widths: 40 35 25

   * - ``keyring_id``
     - ``keyring_type``
     - ``keyring_serial``
   * - ``0``
     - ``BPF_SIG_KEYRING_BUILTIN``
     - ``0``
   * - ``VERIFY_USE_SECONDARY_KEYRING`` (``1``)
     - ``BPF_SIG_KEYRING_SECONDARY``
     - ``0``
   * - ``VERIFY_USE_PLATFORM_KEYRING`` (``2``)
     - ``BPF_SIG_KEYRING_PLATFORM``
     - ``0``
   * - ``KEY_SPEC_BPF_KEYRING`` (``-9``)
     - ``BPF_SIG_KEYRING_BPF``
     - ``0``
   * - any other key or keyring
     - ``BPF_SIG_KEYRING_USER``
     - its serial

The system keyrings and the ``.bpf`` keyring are trusted as a whole and
expose no serial, so a policy tells them apart by ``keyring_type``. See
:doc:`keyrings` for what each keyring holds.

BPF keyring
-----------

A key in a system keyring is trusted for more than BPF, for kernel
modules for example. A keyring the caller supplies is filled by the same
process that loads the program, so it carries no trust of its own. The
``.bpf`` keyring fills the gap: a keyring scoped to BPF program loading,
provisioned at boot.

The kernel creates ``.bpf`` sealed and empty: it carries a restriction
that rejects every key, and a load that names it fails with ``-ENOKEY``.
Booting with ``bpf.keyring_unsealed=1`` leaves it open so that the initrd
can add keys and then restrict it. The kernel consults ``.bpf`` only once
it is both non-empty and restricted, so a half-provisioned keyring is
inert rather than weak.

``bpf.keyring_unsealed=1`` also makes ``.bpf`` the only non-system
keyring a loader may name for the rest of the boot. From the first load
on, a caller-supplied keyring is refused with ``-EPERM``, whether or not
provisioning completed. The builtin, secondary and platform keyrings
stay selectable.

Kernel records, LSM decides
---------------------------

Signing does not change the permission model. A signed load still needs
the usual privileges, and an unsigned load proceeds as before unless a
security module refuses it. A policy that requires signatures acts at
``lsm/bpf_prog_load``: deny unless the verdict is ``BPF_SIG_VERIFIED``
and the keyring is the one the policy trusts. The kernel then refuses on
its own any loader that uses a map its signature does not cover, so the
admission hook needs no second enforcement point. See :doc:`bpf-lsm` for
how such a policy is attached.

How shirudo uses it
-------------------

``shirudo build`` runs gen_loader with ``gen_hash`` set. In that mode
the loader takes map sizes and initial values only from its signed data,
never from the context the caller passes at run time. The build appends
the upatch's name, attach metadata and decoders to the loader's data as
signed sections and signs ``loader_insns || data`` with the operator's
ML-DSA-87 key. Everything the target later trusts about the upatch is
inside that signature. Figure 1 shows the bytes it covers and how the
target hands them to the kernel's check.

.. figure:: /images/background-signed-loader.svg
   :alt: One ML-DSA-87 CMS signature spans loader_insns followed by
         data. data holds the loader data gen_loader emits, the BTF, the
         maps and initial values, the payload programs and CO-RE
         records, and then the signed sections shirudo appends, NAME,
         UPGM, DCDB, SHPL or UNLD, a directory and a trailer. On the
         target, all of data goes into __loader.map, a one-entry array
         exclusive to the SHA-256 of loader_insns and frozen before the
         load. BPF_PROG_LOAD passes loader_insns, the signature,
         keyring_id .bpf and the map in fd_array, and
         bpf_prog_verify_signature() checks loader_insns followed by the
         frozen value against .bpf and records the verdict that
         lsm/bpf_prog_load reads.

   Figure 1. What the loader signature covers, and how a load presents
   it to the kernel.

``shirudo upatch load`` on the target:

#. creates the metadata map ``__loader.map`` as a single-entry array whose
   ``excl_prog_hash`` is the SHA-256 of the loader's instructions;
#. writes the signed data into it and freezes it;
#. loads the loader as a sleepable ``BPF_PROG_TYPE_SYSCALL`` program with
   the signature, ``keyring_id`` set to ``KEY_SPEC_BPF_KEYRING``, the map
   in ``fd_array`` and ``fd_array_cnt`` set to ``1``;
#. runs the loader with ``BPF_PROG_TEST_RUN``. The loader creates the
   payload's maps and loads its programs from inside the kernel.

shirudo's ``lsm/bpf`` program admits a ``BPF_PROG_LOAD`` from userspace
only for a ``BPF_PROG_TYPE_SYSCALL`` program with a non-zero signature
size. Its ``lsm/bpf_prog_load`` program admits a userspace load only with
verdict ``BPF_SIG_VERIFIED`` and keyring type ``BPF_SIG_KEYRING_BPF``.
Both allow calls with ``kernel`` set, which is how the loader's own calls
pass. ``shirudo init`` enrolls the operator's certificates in ``.bpf``
and seals it from the initrd (see :doc:`keyrings`).

A failed signature check maps to a failure category: ``-EKEYREJECTED`` to
``signature_rejected``, ``-ENOKEY`` to ``keyring_missing``, ``-ENOPKG``
(a kernel without the ML-DSA verifier) to ``signature_unsupported``. See
:doc:`/internals/signed-loader` for the full load path and
:doc:`/internals/enforcement` for the admission hooks.

Limits
------

A valid signature establishes origin and integrity, not safety, and not
time. Any artifact ever signed by an enrolled key passes the kernel's
check, so root, which can run shirudo's runtime binary, can choose which
signed upatches run and when. The measurement register records every
such choice; see :doc:`/concepts/measurement-register`.

The ``kernel`` argument is also set for BPF that kernel code loads
itself, such as the in-kernel light skeleton of the ``bpf_preload``
module. shirudo's admission programs allow those loads as they allow a
signed loader's own calls.

shirudo's two enforcement objects are not signed. ``shirudo init`` loads
them before their admission programs attach; production targets
authenticate them as part of the initrd. See
:doc:`/internals/boot-flow`.

Signing covers BPF programs loaded through ``bpf()``. Classic BPF
filters, such as seccomp filters and socket filters attached with
``SO_ATTACH_FILTER``, do not pass through it. The kernel verifies the
instructions and folded metadata as one buffer of at most about 16 MiB.
The threat model lists the residual risks: :doc:`/security/threat-model`.
