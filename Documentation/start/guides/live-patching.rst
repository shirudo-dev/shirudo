..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Tutorial
:audience: Operators, upatch authors

Live patch a kernel and a JVM
=============================

In this tutorial we walk through the end-to-end workflow to close two
vulnerabilities on a running target without a reboot and without a
restart of the kernel or the JDK. For example purposes we picked two
vulnerabilities that were both well documented and fixes have been
published and available for some time. First for a kernel based example
we pick Copy Fail (CVE-2026-31431) a vulnerability in the kernel's ``AF_ALG``
sockets. A BPF upatch will block and record when processes try to open
potentially exploitable socket types. The second is java2shell (CVE-2026-114938)
an exploit in the Base64 decoder of the JDK, which a Java agent guards.
To protect against this vulnerability we sanitize input arguments which
should only block inputs that match the input structure described in the
bug fix.

We publish both as packages, append them to the upatch tree the target
follows, and watch the target pull them. We then pop the upatch off the
tree which is the final stage used once the kernel and JVM source updates
have been rolled out.

Both examples are shipped in the source code and tested as part of the
end-to-end CI and can be found in :src:`upatches/`. We call these upatch
fixes "shields".

Before you begin
----------------

- A shell that may lock memory, which ``shirudo`` does as it starts:

  .. code-block:: console

     operator$ sudo prlimit --pid $$ --memlock=unlimited:unlimited

  ``ulimit -l`` then prints ``unlimited``. Under a lower limit
  ``shirudo`` stops with ``hardening: cannot lock process memory``, and
  ``make vm`` with ``cannot fingerprint the bundle's own certificate``
  or ``cannot read the version_id of the bundle's shirudo``. The limit
  belongs to the shell: set it in each terminal you run the commands of
  this guide in.
- The local stack and the test VM, started from the root of your
  checkout, the settings of the stack in your operator shell and the
  target enrolled in the backend:

  .. code-block:: console

     operator$ make stack-up && make vm VM_NAME=quickstart
     operator$ . build/test-vm/stack/env
     operator$ make vm-enroll VM_NAME=quickstart

  :doc:`backend` explains these lines. A shell you open later needs the
  second line again.

- ``jq`` on the operator host
- A root shell on the target, in which ``shirudo`` runs the runtime
  binary:

  .. code-block:: console

     operator$ make vm-ssh VM_NAME=quickstart

- An x86-64 host, for the second part: the Base64 flaw is in the
  decoder's AVX-512 code, and the package selects that architecture
- A JDK of release 24 or later on the operator host, for ``javac`` and
  ``jar``

Reproduce both flaws
--------------------

1. Run the probe for CVE-2026-31431 on the target:

   .. code-block:: console

      target# python3 /workspace/shirudo/upatches/kernel-cve/sources/cve-2026-31431-crypto-algif-aead-copy-fail/reproducer/cve-2026-31431-splice-probe.py
      SPLICE_OK

   The probe splices a page of a file into an ``AF_ALG`` socket without a
   copy, the step the exploit of the CVE builds on. ``SPLICE_OK`` says
   the kernel took it. The target mounts your checkout read-only at
   ``/workspace/shirudo``.

2. Build a program that feeds the Base64 decoder the crafted input:

   .. code-block:: console

      operator$ upatches/test/build.sh

   It writes ``upatches/test/badDecoder.jar`` from
   :src:`upatches/test/BadDecoder.java`.

3. Run it on the target in a JVM that a user manager starts:

   .. code-block:: console

      target# sh /workspace/shirudo/testing/end2end/guarded-jvm.sh /workspace/shirudo/upatches/test/badDecoder.jar
      badDecoder: no guard, the JDK refused: Last unit does not have enough valid bits
      status 1

   The input reaches the decoder of the JDK. This JDK is not vulnerable
   and refuses the input itself; a vulnerable one writes past the
   destination array. :src:`testing/end2end/guarded-jvm.sh` creates a
   user, starts a user manager for it and runs the jar in a service of
   that manager, which is how a JVM comes to load the Java agents of a
   target: :doc:`/upatches/write/java-agents` explains why.

Publish the shields
-------------------

1. Build both packages and push them to one namespace of the registry:

   .. code-block:: console

      operator$ mkdir -p build/tutorial
      operator$ tools/put-shields --version 1.0.0 --keys-dir "$KEYS" --catalog build/tutorial/shields.json --new-index oci://127.0.0.1:15444/live-patching upatches/kernel-cve/cve-2026-31431-alg-splice-block.bee upatches/java-base64
      wrote /tmp/shirudo-bpm-build.qTghwI/0.upatch (insns=992 sig=4853 data=39256 sections=2 maps=0 progs=1 decoders=0 name=cve-2026-31431-alg-splice-block)
      wrote /tmp/shirudo-bpm-build.qTghwI/0.unload.upatch (insns=1320 sig=4853 data=2832 sections=2 maps=1 progs=1 decoders=0 name=cve-2026-31431-alg-splice-block UNLOAD)
      put-shields: pushed oci://127.0.0.1:15444/live-patching/cve-2026-31431-alg-splice-block:1.0.0 sha256:907fd7f79f14e3d2d869ba5d7bb140cd16dee131ec3b3b1d68aca686a049994f
      shirudo bpm tree append oci://127.0.0.1:15444/live-patching/cve-2026-31431-alg-splice-block:1.0.0 --package-digest sha256:907fd7f79f14e3d2d869ba5d7bb140cd16dee131ec3b3b1d68aca686a049994f oci://<registry>/<tree> --tree-id <tree-id>
      wrote /tmp/shirudo-bpm-build.oQlqSq/0.upatch (java sig=4853 data=7904 name=java-base64)
      wrote /tmp/shirudo-bpm-build.oQlqSq/0.unload.upatch (java sig=4853 data=360 name=java-base64 UNLOAD)
      put-shields: pushed oci://127.0.0.1:15444/live-patching/java-base64:1.0.0 sha256:d37ad3d8a345f3a1e5e19a9d85ebe66e076b9a0540f8f17952d3709030aebbb4
      shirudo bpm tree append oci://127.0.0.1:15444/live-patching/java-base64:1.0.0 --package-digest sha256:d37ad3d8a345f3a1e5e19a9d85ebe66e076b9a0540f8f17952d3709030aebbb4 oci://<registry>/<tree> --tree-id <tree-id>

   :src:`tools/put-shields` runs ``shirudo bpm build`` and ``shirudo bpm
   push`` for each package, which sign the upatches and the namespace's
   index with the key in ``KEYS``. For each package it prints the
   ``shirudo bpm tree append`` command that takes it into a tree, by its
   reference and the digest of its manifest. Your digests differ.

2. Keep the two digests for the commands below:

   .. code-block:: console

      operator$ CVE_DIGEST=$(jq -r 'first(.shields[] | select(.package == "cve-2026-31431-alg-splice-block")).manifest_digest' build/tutorial/shields.json)
      operator$ JAVA_DIGEST=$(jq -r 'first(.shields[] | select(.package == "java-base64")).manifest_digest' build/tutorial/shields.json)

   The catalog ``put-shields`` wrote holds, for each package, the
   ``sha256:`` value its command printed after ``--package-digest``.

3. Tell the backend that the shields are available:

   .. code-block:: console

      operator$ tools/backend/jobs/shields-put build/tutorial/shields.json
      shields-put: oci://127.0.0.1:15444/live-patching/cve-2026-31431-alg-splice-block:1.0.0 cve-2026-31431-alg-splice-block (CVE-2026-31431)
      shields-put: oci://127.0.0.1:15444/live-patching/java-base64:1.0.0 java-base64 (CVE-2026-114938)
      shields-put: loaded shields: 2

   ``--catalog`` had ``put-shields`` write what it pushed, with the
   advisories each shield mitigates, and
   :doc:`/operate/backend/shields-put` loads that file. xtop lists the
   two in its shields view. Nothing runs on the target yet: a published
   package reaches a target only through the tree.

Block the kernel flaw
---------------------

1. Append the kernel shield to the tree:

   .. code-block:: console

      operator$ shirudo bpm tree append oci://127.0.0.1:15444/live-patching/cve-2026-31431-alg-splice-block:1.0.0 --package-digest "$CVE_DIGEST" "$TREE" --tree-id local-tree --keys-dir "$KEYS"
      oci://127.0.0.1:15444/shirudo/local-tree:stable sha256:b13473fa4bdff594dd39f948e5d19fc4276fd3363ace67ab80b5ba0849efbebe

   The tree is a signed list of operations. This one says ``add`` with
   the upatch's payload digest and its selector, which reads the kernel
   configuration: only a target built with
   ``CONFIG_CRYPTO_USER_API_AEAD`` loads it.

2. Wait for the target's next sync, at most 10 seconds on the test VM,
   and list its upatches:

   .. code-block:: console

      target# shirudo upatch list
      Archived upatches (/var/lib/shirudo/upatches):
        NAME                             LOADED  TYPE    KIND  PAYLOAD
        cve-2026-31431-alg-splice-block  yes     load    bpf   42dc3be289a0f3d7..

   ``shirudo-bpm-tree-sync.timer`` ran ``shirudo bpm tree sync``, which
   fetched the tree, verified its signature against the sealed keyring,
   pulled the package and loaded the upatch through the signed loader,
   with the load extended into the TPM register. You ran nothing on the
   target.

3. Run the probe again:

   .. code-block:: console

      target# python3 /workspace/shirudo/upatches/kernel-cve/sources/cve-2026-31431-crypto-algif-aead-copy-fail/reproducer/cve-2026-31431-splice-probe.py
      SPLICE_BLOCKED

   The upatch refuses the splice in an LSM hook, and every other use of
   the socket goes on as before. The kernel is the one that booted.

4. Load the tree into the backend and read the target's checks:

   .. code-block:: console

      operator$ tools/backend/jobs/tree-ingest --shirudo "$PWD/shirudo" --cert "$KEYS/cert.der" "$TREE"
      tree-ingest: loaded local-tree generation 1 (operations: 1, fixes: 1)
      operator$ docker exec -i shirudo-dev-clickhouse clickhouse-client --query "SYSTEM REFRESH VIEW shirudo.node_status_mv; SYSTEM WAIT VIEW shirudo.node_status_mv"
      operator$ docker exec -i shirudo-dev-clickhouse clickhouse-client --query "SELECT arrayJoin(log) FROM shirudo.node_status"
      1 signed: pass, enrolled, 0 rejected in the last hour
      2 fresh: pass, last record 1 s ago
      3 reported: FAIL, verdict ok, cond 0x1555, flags 0, tamper +22, build 59400f7e
      4 chain: pass, root 4de4d83c
      5 head: pass, seq 1 of 1, generation 1
      6 set: pass, 1 loaded
      7 peers: no peers, 1 in group

   :doc:`/operate/backend/tree-ingest` reads the tree as a target does.
   Checks 4 to 6 then hold the target's keepalive against it: the target
   is at operation 1 of 1 and runs the one upatch that operation leaves
   loaded. Check 3 fails here because the target's tamper counters rose
   after its first record; :doc:`/operate/backend/status` says how each
   check reads a record.

Guard the JVM
-------------

1. Append the Java shield:

   .. code-block:: console

      operator$ shirudo bpm tree append oci://127.0.0.1:15444/live-patching/java-base64:1.0.0 --package-digest "$JAVA_DIGEST" "$TREE" --tree-id local-tree --keys-dir "$KEYS"
      oci://127.0.0.1:15444/shirudo/local-tree:stable sha256:02c6eb7391955e4c95e12883400f8def7c96f5fd79c5e2334c6704c5aafef566

2. After the next sync, list the target's upatches:

   .. code-block:: console

      target# shirudo upatch list
      Archived upatches (/var/lib/shirudo/upatches):
        NAME                             LOADED  TYPE    KIND  PAYLOAD
        cve-2026-31431-alg-splice-block  yes     load    bpf   42dc3be289a0f3d7..
        java-base64                      yes     load    java  fea9e483dd384ec7..

   A Java upatch is a signed agent jar. The target verified it as it
   verifies a BPF upatch, sealed the jar and named it in
   ``JAVA_TOOL_OPTIONS`` for the JVMs that start from here on.

3. Run the crafted input again:

   .. code-block:: console

      target# sh /workspace/shirudo/testing/end2end/guarded-jvm.sh /workspace/shirudo/upatches/test/badDecoder.jar
      Picked up JAVA_TOOL_OPTIONS: -javaagent:/run/shirudo-java/java-base64.jar
      OpenJDK 64-Bit Server VM warning: Sharing is only supported for boot loader classes because bootstrap classpath has been appended
      Base64 guard installed on java.util.Base64$Decoder.decode0
      Base64 guard rejected candidate: length=66, padding=1, remainder=2, alphabet=standard
      badDecoder: refused by the guard
      status 0

   The agent refuses the input before the decoder of the JDK sees it. The
   JDK and the application's jar are unchanged.

Take the shields back
---------------------

1. Append a delete for each shield:

   .. code-block:: console

      operator$ shirudo bpm tree append oci://127.0.0.1:15444/live-patching/java-base64:1.0.0 --package-digest "$JAVA_DIGEST" "$TREE" --tree-id local-tree --keys-dir "$KEYS" --op delete
      oci://127.0.0.1:15444/shirudo/local-tree:stable sha256:21a2aaa16532bb25d310014ec3c32d0cf282b7ead233bb0df911cf05d4942a65
      operator$ shirudo bpm tree append oci://127.0.0.1:15444/live-patching/cve-2026-31431-alg-splice-block:1.0.0 --package-digest "$CVE_DIGEST" "$TREE" --tree-id local-tree --keys-dir "$KEYS" --op delete
      oci://127.0.0.1:15444/shirudo/local-tree:stable sha256:4817283178193d0ef0c858b701db7e585efbcad153abee015caba0efc67c6f19

   The tree only grows: a delete is one more signed operation, and the
   adds stay on record before it.

2. After the next sync, check that the target unloaded both:

   .. code-block:: console

      target# shirudo upatch list
      Archived upatches (/var/lib/shirudo/upatches):
        none
      target# sh /workspace/shirudo/testing/end2end/guarded-jvm.sh /workspace/shirudo/upatches/test/badDecoder.jar
      badDecoder: no guard, the JDK refused: Last unit does not have enough valid bits
      status 1
      target# python3 /workspace/shirudo/upatches/kernel-cve/sources/cve-2026-31431-crypto-algif-aead-copy-fail/reproducer/cve-2026-31431-splice-probe.py
      SPLICE_OK

   Each unload ran the signed unload directive of its package and is in
   the TPM register like the load.

3. Load the tree into the backend again and read the checks:

   .. code-block:: console

      operator$ tools/backend/jobs/tree-ingest --shirudo "$PWD/shirudo" --cert "$KEYS/cert.der" "$TREE"
      tree-ingest: loaded local-tree generation 4 (operations: 4, fixes: 2)
      operator$ docker exec -i shirudo-dev-clickhouse clickhouse-client --query "SYSTEM REFRESH VIEW shirudo.node_status_mv; SYSTEM WAIT VIEW shirudo.node_status_mv"
      operator$ docker exec -i shirudo-dev-clickhouse clickhouse-client --query "SELECT arrayJoin(log) FROM shirudo.node_status"
      1 signed: pass, enrolled, 0 rejected in the last hour
      2 fresh: pass, last record 10 s ago
      3 reported: FAIL, verdict ok, cond 0x1555, flags 0, tamper +50, build 59400f7e
      4 chain: pass, root 75c9c1c3
      5 head: pass, seq 4 of 4, generation 4
      6 set: pass, 0 loaded
      7 peers: no peers, 1 in group

   The target is at operation 4 of 4 with nothing loaded, which is what
   two adds and two deletes leave.

Tear down
---------

The guides share the stack, the VM and the tree: skip this section to
go on to another one.

1. Remove the VM, the stack and the files of this guide:

   .. code-block:: console

      operator$ make vm-stop VM_NAME=quickstart
      operator$ make vm-clean VM_NAME=quickstart
      operator$ make stack-down
      operator$ rm build/tutorial/shields.json

   Stopping the VM ends the target shell. The VM's disk and TPM state,
   the registry with the tree in it, the backend's tables and the CA
   are gone. The first lines of this guide start again from nothing.

Next steps
----------

- :doc:`/upatches/learn/kernel-fix-tutorial` writes a upatch for a
  kernel CVE, from the fix to the published package.
- :doc:`/upatches/write/java-agents` explains Java upatches and which
  JVMs load them.
- :doc:`/upatches/publish/publishing` describes the tree, its selectors
  and its segments.
- :doc:`/operate/backend/exposure` shows which nodes run a vulnerable
  package or kernel and which shield covers them.
- :doc:`system-hardening` and :doc:`runtime-observability` use the same
  tree for a sandbox and for observability.
