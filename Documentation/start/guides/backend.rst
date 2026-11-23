..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Tutorial
:audience: Operators, upatch authors

Set up the backend
==================

In this tutorial you start what a target pulls from and reports to, on
your own host: an OCI registry, an OpenTelemetry Collector and the
example backend of :src:`tools/backend/`, a ClickHouse that checks every
keepalive a target sends. You enroll the test target in the backend and
read its status there. The use-case guides,
:doc:`live-patching`, :doc:`system-hardening` and
:doc:`runtime-observability`, start from the state this page leaves.

The test VM is configured for these services from its first boot. Its
signed config names ``oci://10.0.2.2:15444/shirudo/local-tree`` as the
upatch tree to follow and ``https://10.0.2.2:14319`` as the collector,
and its timers look for a tree operation and send a keepalive every 10
seconds, where a target's wait a minute. Until the services run, the
timers retry.

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
- A host that meets the requirements of the :doc:`/start/quickstart`,
  with the test kernel staged and shirudo built as its first three
  sections do: in the root of your checkout, with ``shirudo`` and
  ``shirudo-build`` on ``PATH``
- Docker on the operator host

Start the services and the target
---------------------------------

1. Start the registry, the collector, the backend and the test VM, and
   load the settings of the stack into your operator shell:

   .. code-block:: console

      operator$ make stack-up && make vm VM_NAME=quickstart
      operator$ . build/test-vm/stack/env

   The first line prints:

   .. code-block:: console

      ...
      OCI: oci://127.0.0.1:15444 (CA: /home/user/shirudo/build/test-vm/stack/ca.pem)
      OTLP: https://127.0.0.1:14319; ClickHouse with the backend: http://127.0.0.1:18124
      Shell: . /home/user/shirudo/build/test-vm/stack/env
      ...
      [test-vm] booting bzImage with 4 CPUs and 4G memory
      [test-vm] VM ready: name=quickstart state=.../build/test-vm/vms/quickstart qemu_pid=... swtpm_pid=...
      ...
      [test-vm] console: make -C testing vm-console VM_NAME=quickstart
      [test-vm] ssh: make -C testing vm-ssh

   ``make stack-up`` builds ``tools/quote-check/shirudo-quote-check``,
   the checker the backend verifies keepalives with, which
   :doc:`/reference/cli/quote-check` describes. It then runs three
   containers on the host's loopback interface: the registry, the
   collector and a ClickHouse with the schema of
   :src:`tools/backend/sql/` and the checker installed as its
   ``tpm_quote_check`` function. ``make vm`` boots the test VM of the
   quickstart, which reaches the services at ``10.0.2.2`` and trusts the
   CA the ``OCI:`` line names. A VM that the quickstart booted before works
   as well: run ``make stack-up`` alone. :ref:`local-dev-stack`
   describes each ``make`` target of this stack, and
   :doc:`/operate/backend/set-up` sets the backend up on a host of your
   own.

2. Open a root shell on the target, in which ``shirudo`` runs the
   runtime binary:

   .. code-block:: console

      operator$ make -C testing vm-ssh VM_NAME=quickstart

   Commands with the ``target#`` prompt run in this shell.

3. Look at the settings the ``Shell:`` line names, which your shell
   read in the first step:

   .. code-block:: console

      operator$ cat build/test-vm/stack/env
      export PATH='/home/user/shirudo:/home/user/shirudo/tools/shirudo-build':"$PATH"
      KEYS='/tmp/shirudo-test-vm-private-1000/operator-keys/keys'
      export BPM_OCI_CA_FILE='/home/user/shirudo/build/test-vm/stack/ca.pem'
      TREE=oci://127.0.0.1:15444/shirudo/local-tree
      export CLICKHOUSE_CLIENT='docker exec -i shirudo-dev-clickhouse clickhouse-client'

   ``make stack-up`` writes the file, as a ``make`` target cannot set a
   variable in the shell that ran it. It puts ``shirudo`` and
   ``shirudo-build`` of your checkout on ``PATH`` and names the key
   directory, the registry's CA and the tree for the commands of the
   guides. ``shirudo bpm`` reads ``BPM_OCI_CA_FILE`` to verify the
   registry, and the jobs of :src:`tools/backend/jobs/` run the
   ClickHouse client ``CLICKHOUSE_CLIENT`` names. A shell you open later
   has none of them until it reads the file too. The tree does not
   exist yet: the first operation you append creates it.

Enroll the target
-----------------

1. Load the names of the target's TPM keys into the backend:

   .. code-block:: console

      operator$ make vm-enroll VM_NAME=quickstart
      $ cat build/test-vm/vms/quickstart/enroll.json
      {"source": "test-vm", "nodes": [{"ak_name": "000b384a13035ce74a05397c2df1837c26832060a048f199cebf270b40c6d1a29b35", "ek_name": "000b2bcc6ad1b9d260ae30ffb0a3f75dd65bf20d0870c7346aeab39abd295ddda2d0", "node_id": "quickstart"}]}
      $ CLICKHOUSE_CLIENT='docker exec -i shirudo-dev-clickhouse clickhouse-client' tools/backend/jobs/enroll-put build/test-vm/vms/quickstart/enroll.json
      enroll-put: 000b384a13035ce74a05397c2df1837c26832060a048f199cebf270b40c6d1a29b35 (ek_name 000b2bcc6ad1b9d260ae30ffb0a3f75dd65bf20d0870c7346aeab39abd295ddda2d0, node_id quickstart): enrolled
      enroll-put: loaded bindings: 1
      $ CLICKHOUSE_CLIENT='docker exec -i shirudo-dev-clickhouse clickhouse-client' tools/put-shirudo-build --note 'test-vm build' 59400f7e494aaa7d25dd4e6205689571ceda217bb77d07ceba6708ed0a372441
      put-shirudo-build: 59400f7e494aaa7d25dd4e6205689571ceda217bb77d07ceba6708ed0a372441: allowed

   The backend trusts a keepalive only when the attestation key that
   signed its quote is enrolled. ``make vm`` recorded the names of the
   attestation and endorsement keys when it created the VM's TPM, as the
   builder of a real target does, and ``make vm-enroll`` loads that
   record with :doc:`/operate/backend/enroll-put`. It also tells the
   backend which build of shirudo to expect. Your names and build
   differ. :doc:`attest-target` enrolls a key from the target itself,
   through credential activation.

2. Read the target's status in the backend:

   .. code-block:: console

      operator$ docker exec -i shirudo-dev-clickhouse clickhouse-client --query "SYSTEM REFRESH VIEW shirudo.node_status_mv; SYSTEM WAIT VIEW shirudo.node_status_mv"
      operator$ docker exec -i shirudo-dev-clickhouse clickhouse-client --query "SELECT node_id, status, trust, loaded FROM shirudo.node_status FORMAT PrettyCompactMonoBlock"
         ┌─node_id────┬─status──┬─trust────┬─loaded─┐
      1. │ quickstart │ healthy │ enrolled │      0 │
         └────────────┴─────────┴──────────┴────────┘

   The backend works ``node_status`` out once a minute; the first command
   has it do so at once. The row comes from the keepalives the target
   sends: each is the target's status with a TPM quote over it, and
   ``enrolled`` says that the quote verified against the key you loaded.

3. Read the checks behind that status:

   .. code-block:: console

      operator$ docker exec -i shirudo-dev-clickhouse clickhouse-client --query "SELECT arrayJoin(log) FROM shirudo.node_status"
      1 signed: pass, enrolled, 0 rejected in the last hour
      2 fresh: pass, last record 2 s ago
      3 reported: pass, verdict ok, cond 0x1555, flags 0, tamper +0, build 59400f7e
      4 chain: no tree
      5 head: no tree
      6 set: no tree
      7 peers: no tree

   Checks 4 to 7 compare what the target applied with the upatch tree,
   and the backend knows no tree yet. The guides append to the tree and
   read these lines again. :doc:`/operate/backend/status` describes each
   check.

Watch the target
----------------

1. Start :doc:`xtop </operate/backend/xtop>` in a second terminal:

   .. code-block:: console

      operator$ make xtop

   xtop is a terminal view of the same tables: the nodes with their
   status, the shields the backend knows as available and the ones each
   node runs. It needs ``bun`` on the host. Leave it running while you
   follow a guide.

Stop the services
-----------------

1. Remove the VM, and the containers with their data, when you are
   done with the guides:

   .. code-block:: console

      operator$ make vm-stop VM_NAME=quickstart
      operator$ make vm-clean VM_NAME=quickstart
      operator$ make stack-down

   Stopping the VM ends the target shell. The VM's disk and TPM state,
   the registry, the tree in it, the backend's tables and the CA are
   gone. A VM that is left running trusts the removed CA, so a stack
   you start later needs a fresh one.

Next steps
----------

- :doc:`live-patching` blocks a kernel vulnerability and guards a JVM
  with upatches the target pulls from the tree.
- :doc:`system-hardening` puts an application in a sandbox.
- :doc:`runtime-observability` collects what runs, connects and reads
  on the target.
- :doc:`/operate/backend/index` explains the backend and its tables.
