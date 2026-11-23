..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Tutorial
:audience: Operators, upatch authors

Sandbox Vulnerable Apache
=========================

In this tutorial we put Apache in an application sandbox to reduce lateral
movement and privilege escalations inside the network and host if the
php2shell or other vulnerabilities were leveraged to gain control of the
process. To sandbox the application the example scopes two
operations: first executes only the programs listed in the policy, second
connects only to the networks specified in the policy. This is the example
case the policy engine can also be further leveraged to scope privileged
operations, such as user namespaces, mounts, and file access. We then
simulate an attacker attempting to upload a php script and connect to a
remote server, in this case 1.1.1.1:80.

The sandbox is the ``app-sandbox`` upatch of :src:`upatches/app-sandbox/`,
built with rules you write, published as a package and delivered through the
upatch tree. The application is not changed, restarted with other options or
wrapped: the rules apply to every task that executes its file.

The package ships example rules for Apache httpd and PHP-FPM that are used
in this example workflow. The policy can be further scoped or relaxed as
needed in individual environments.

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
- Docker on the operator host, also for the image of the web server

Install the web server
----------------------

1. Build the image of the web server and write its file system to an
   archive:

   .. code-block:: console

      operator$ mkdir -p build/tutorial
      operator$ upatches/app-sandbox/demo/build.sh build/tutorial/apache-php.tar
      shirudo-app-sandbox-demo -> build/tutorial/apache-php.tar

   :src:`upatches/app-sandbox/demo/` holds the image: Apache httpd with
   PHP, as the official ``php:8.4-apache`` image builds it, a TLS site on
   port 8443 and two scripts. The first build pulls that image. PHP runs
   inside the Apache processes here, so the ``apache`` sandbox of the
   package is the one that applies; where PHP-FPM runs the scripts, its
   processes are in the ``php-fpm`` sandbox.

2. Unpack the archive on the target:

   .. code-block:: console

      target# sh /workspace/shirudo/upatches/app-sandbox/demo/apache.sh install /workspace/shirudo/build/tutorial/apache-php.tar

   :src:`upatches/app-sandbox/demo/apache.sh` unpacks the image under
   ``/var/lib/app-sandbox-demo``, to run Apache from there in a chroot,
   since the target has no Docker. It also makes ``/usr/sbin/apache2`` a
   hard link to the server's binary: that is the path the package names,
   and a hard link is the same file. The target mounts your checkout
   read-only at ``/workspace/shirudo``. Apache does not run yet.

Publish and deliver the sandbox
-------------------------------

1. Build the package as it ships and push it to a namespace of the
   registry:

   .. code-block:: console

      operator$ tools/put-shields --version 1.0.0 --keys-dir "$KEYS" --catalog build/tutorial/sandbox.json --new-index oci://127.0.0.1:15444/hardening upatches/app-sandbox
      wrote /tmp/shirudo-bpm-build.Fr0mUH/0.upatch (insns=9408 sig=4853 data=145888 sections=3 maps=5 progs=12 decoders=0 name=app-sandbox)
      wrote /tmp/shirudo-bpm-build.Fr0mUH/0.unload.upatch (insns=1320 sig=4853 data=2832 sections=2 maps=1 progs=1 decoders=0 name=app-sandbox UNLOAD)
      put-shields: pushed oci://127.0.0.1:15444/hardening/app-sandbox:1.0.0 sha256:af1e98233268d1862b6835ed4dcf2d1f3c168198440733d478404d5588841bf7
      shirudo bpm tree append oci://127.0.0.1:15444/hardening/app-sandbox:1.0.0 --package-digest sha256:af1e98233268d1862b6835ed4dcf2d1f3c168198440733d478404d5588841bf7 oci://<registry>/<tree> --tree-id <tree-id>

   The package has two parts. :src:`upatches/app-sandbox/Beefile` names
   the files of each sandbox by path, ``/usr/sbin/apache2`` among those
   of ``apache``, and :src:`upatches/app-sandbox/sandbox.toml` gives each
   sandbox its rules. The tasks of ``apache`` execute no file but their
   own, connect and send only to loopback and private networks, and
   create, rename and open for writing no file whose name ends in
   ``.php``. The build compiles the rules into the signed upatch, so
   nobody on the target can change them. :src:`tools/put-shields` prints
   the command that appends the package to a tree. Your digest differs.

2. Keep the digest and tell the backend that the package is available:

   .. code-block:: console

      operator$ SANDBOX_DIGEST=$(jq -r '.shields[0].manifest_digest' build/tutorial/sandbox.json)
      operator$ tools/backend/jobs/shields-put build/tutorial/sandbox.json
      shields-put: oci://127.0.0.1:15444/hardening/app-sandbox:1.0.0 app-sandbox (CVE-2026-109618, CVE-2026-109619)
      shields-put: loaded shields: 1

   The catalog ``put-shields`` wrote holds the ``sha256:`` value its
   command printed after ``--package-digest``. The backend lists the
   package with the two advisories its ``Beefile`` names as the ones it
   mitigates.

3. Append the package to the tree:

   .. code-block:: console

      operator$ shirudo bpm tree append oci://127.0.0.1:15444/hardening/app-sandbox:1.0.0 --package-digest "$SANDBOX_DIGEST" "$TREE" --tree-id local-tree --keys-dir "$KEYS"
      oci://127.0.0.1:15444/shirudo/local-tree:stable sha256:cbf0590ad56459e675282d8ed34ea37dd8debd631cac338d6068912cf011505e

   The tree is a signed list of operations, and this one says ``add``
   with the upatch's payload digest. The package has no selector, so
   every target that follows the tree loads it.

4. Wait for the target's next sync, at most 10 seconds on the test VM,
   and list its upatches:

   .. code-block:: console

      target# shirudo upatch list
      Archived upatches (/var/lib/shirudo/upatches):
        NAME                      LOADED  TYPE    KIND  PAYLOAD
        app-sandbox               yes     load    bpf   c6d5d7e6214b1f23..

5. Read the label the load put on the server's binary:

   .. code-block:: console

      target# python3 -c 'import os; print(os.getxattr("/usr/sbin/apache2", "security.bpf.shirudo.policy").hex())'
      0100000000000000

   When the target loads the upatch, shirudo labels the files the
   ``Beefile`` names with the bit of their policy, ``0x1`` for
   ``apache``. A task that executes a labeled file carries the bit from
   then on, as do the tasks it starts. Only shirudo sets or removes the
   label; :doc:`/internals/seal` describes it.

Run the server in its sandbox
-----------------------------

1. Start Apache:

   .. code-block:: console

      target# sh /workspace/shirudo/upatches/app-sandbox/demo/apache.sh start

   Apache executes the labeled binary and is in the ``apache`` sandbox
   from its first instruction, with every worker it starts.

2. Request a page of the site:

   .. code-block:: console

      target# curl --silent --insecure https://127.0.0.1:8443/index.php
      GET get=0 post=0

   The site answers as it does without a sandbox.

3. Request the script that does what an attacker does next:

   .. code-block:: console

      target# curl --silent --insecure https://127.0.0.1:8443/attack.php
      write note.txt: ok
      write shell.php: refused
      rename note.txt note.php: refused
      mkdir d.php: refused
      run a command: did not run
      connect 127.0.0.1 port 8443: ok
      connect 1.1.1.1 port 80: errno 13
      target# ls /var/lib/app-sandbox-demo/var/www/html/uploads
      data.txt
      note.txt

   :src:`upatches/app-sandbox/demo/htdocs/attack.php` stands for a
   vulnerability that lets a request run PHP of the attacker's choice. In
   the site's upload directory it writes a text file, as the site does,
   and then a script the server would run on the next request, renames
   the text file to a script, runs a command and connects to a host on
   the internet. The site's own write and its connection to the target
   go through. The script cannot be planted, the command does not run
   and the connection to the internet ends in ``EACCES``, errno 13,
   although Apache started as root. Neither Apache nor PHP was changed
   or configured for it.

4. Load the tree into the backend and read the target's checks:

   .. code-block:: console

      operator$ tools/backend/jobs/tree-ingest --shirudo "$PWD/shirudo" --cert "$KEYS/cert.der" "$TREE"
      tree-ingest: loaded local-tree generation 1 (operations: 1, fixes: 2)
      operator$ docker exec -i shirudo-dev-clickhouse clickhouse-client --query "SYSTEM REFRESH VIEW shirudo.node_status_mv; SYSTEM WAIT VIEW shirudo.node_status_mv"
      operator$ docker exec -i shirudo-dev-clickhouse clickhouse-client --query "SELECT arrayJoin(log) FROM shirudo.node_status"
      1 signed: pass, enrolled, 0 rejected in the last hour
      2 fresh: pass, last record 7 s ago
      3 reported: FAIL, verdict ok, cond 0x1555, flags 0, tamper +16, build 59400f7e
      4 chain: pass, root 2beddd58
      5 head: pass, seq 1 of 1, generation 1
      6 set: pass, 1 loaded
      7 peers: no peers, 1 in group

   Checks 4 to 6 say that the target is at the head of the tree and runs
   the one upatch it leaves loaded. Check 3 fails here because the
   target's tamper counters rose after its first record;
   :doc:`/operate/backend/status` says how each check reads a record.

Release the server
------------------

1. Append a delete for the package:

   .. code-block:: console

      operator$ shirudo bpm tree append oci://127.0.0.1:15444/hardening/app-sandbox:1.0.0 --package-digest "$SANDBOX_DIGEST" "$TREE" --tree-id local-tree --keys-dir "$KEYS" --op delete
      oci://127.0.0.1:15444/shirudo/local-tree:stable sha256:c852a788e10affb3405a5def41e481eada639eb2785fb86846a01e5bfc384d7a

2. After the next sync, request the attacker's script again:

   .. code-block:: console

      target# shirudo upatch list
      Archived upatches (/var/lib/shirudo/upatches):
        none
      target# curl --silent --insecure https://127.0.0.1:8443/attack.php
      write note.txt: ok
      write shell.php: ok
      rename note.txt note.php: ok
      mkdir d.php: ok
      run a command: ran
      connect 127.0.0.1 port 8443: ok
      connect 1.1.1.1 port 80: ok

   The rules went with the upatch. This is what the sandbox held back:
   the same server, with nothing around it, plants the script, runs the
   command and reaches the internet.

3. Stop Apache and remove it from the target:

   .. code-block:: console

      target# sh /workspace/shirudo/upatches/app-sandbox/demo/apache.sh remove

Tear down
---------

The guides share the stack, the VM and the tree: skip this section to
go on to another one.

1. Remove the VM, the stack and the files of this guide:

   .. code-block:: console

      operator$ make vm-stop VM_NAME=quickstart
      operator$ make vm-clean VM_NAME=quickstart
      operator$ make stack-down
      operator$ rm build/tutorial/sandbox.json build/tutorial/apache-php.tar

   Stopping the VM ends the target shell. The VM's disk and TPM state,
   the registry with the tree in it, the backend's tables and the CA
   are gone. The first lines of this guide start again from nothing.

Next steps
----------

- :doc:`/upatches/learn/examples` describes the ``app-sandbox`` package,
  every key of its rules and how to write a sandbox for another
  application.
- :doc:`/reference/formats/beefile` describes ``[[upatches.policy]]``
  and every other key of a ``Beefile``.
- :doc:`/internals/seal` explains the labels and the marks a task
  carries.
- :doc:`/operate/plan/hardening` hardens the target itself: kernel
  configuration, boot chain and TPM.
- :doc:`live-patching` and :doc:`runtime-observability` use the same
  tree for shields and for observability.
