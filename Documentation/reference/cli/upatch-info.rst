..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: All readers

shirudo upatch info
===================

Describe a ``.upatch`` file offline: header, signature, payload digest,
signed sections and decoders.

Runs on: any host, and on a target with the runtime binary. Requires: read
access to the file. Changes measured state: no.

Usage
-----

.. code-block:: none

   shirudo upatch info [--json] <file>

Description
-----------

``info`` parses the file and prints what it carries. It reads no kernel
state and checks no signature. The target checks the signature when it
loads the artifact. For a loaded upatch as the kernel holds it, use
:doc:`upatch-get`.

The human output has these parts:

- the file, name, type (``LOAD`` or ``UNLOAD-directive``), payload type,
  format version, payload digest and size
- the loader: offset and length of its instructions, the log buffer
  size, its metadata and its data
- the signature: offset and length
- the signed sections: the name, the length of the attach metadata, for
  a Java load the length of its agent jar and, for a directive, the
  expected payload digest
- the decoders: target upatch and map, language and API version, input
  format, export signal (``log`` or ``metric``) and source

As no signature is checked, the file, the names and the decoder fields
are printed with each control character, and each byte that starts no
UTF-8 character, shown as ``?``. ``--json`` writes them as JSON
strings, with such a byte as U+FFFD.

:doc:`/reference/formats/upatch-format` describes each field.

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 14 12 12 62

   * - Option
     - Argument
     - Default
     - Description
   * - ``--json``
     - none
     - off
     - Print one JSON object: ``schema``, ``path``, ``name``, ``type``,
       ``payload_type``, ``version``, ``payload_sha256``,
       ``loader_insns_len``, ``signature_len``, ``data_len``,
       ``log_buf_sz``, ``file_size``, ``signed_name``,
       ``attach_metadata_len``, ``jar_len`` (0 but for a Java load),
       ``unload_payload_sha256`` and ``decoders``.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - The file was described.
   * - 1
     - The file cannot be opened or is not a valid ``.upatch``.
   * - 2
     - A usage error: no file, a second file, an unknown option or
       ``--json`` given twice.

Examples
--------

Describe an artifact:

.. code-block:: console

   operator$ shirudo upatch info basic.upatch
   File:                  basic.upatch
   Name:                  basic
   Type:                  LOAD
   Payload type:          bpf
   Version:               1
   Payload sha256:        46f3d9f5f6568bddb7692cad28e99a86a3104192d8a2251f9ef9ec6d593c2035
   File size:             8661 bytes

   Loader:
     Instructions:          off=360 len=992
     Log buffer size:       1048576
     Data:                  off=6205 len=2456

   Signature:
     Offset:                1352
     Length:                4853 bytes

   Signed sections:
     Name:                  basic
     Attach metadata:       176 bytes
     Unload payload:        (none)

   Decoders:
     (none)

Read the payload digest for ``build --unload --payload-sha256``:

.. code-block:: console

   operator$ shirudo upatch info --json basic.upatch | jq -r .payload_sha256
   46f3d9f5f6568bddb7692cad28e99a86a3104192d8a2251f9ef9ec6d593c2035

The JSON form of another artifact:

.. code-block:: console

   target# shirudo upatch info --json shirudo-test-basic.upatch
   {"schema":1,"path":"shirudo-test-basic.upatch","name":"shirudo-test-basic","type":"load","payload_type":"bpf","version":1,"payload_sha256":"8aee7072a1a15e4dddc93ad6b253a0e2e70ad6cdf767442aa8a1c1997bc3069f","loader_insns_len":992,"signature_len":4853,"data_len":2400,"log_buf_sz":1048576,"file_size":8605,"signed_name":"shirudo-test-basic","attach_metadata_len":176,"jar_len":0,"unload_payload_sha256":null,"decoders":[]}

Related
-------

- :doc:`build`
- :doc:`upatch-get`
- :doc:`/reference/formats/upatch-format`
