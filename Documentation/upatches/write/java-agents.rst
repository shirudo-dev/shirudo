..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: upatch authors, operators, security reviewers

Java agent upatches
===================

A Java agent upatch ships a ``java.lang.instrument`` agent, a ``.jar``
with a ``Premain-Class`` in its manifest, the way a BPF upatch ships a
program: signed by the operator, loaded and unloaded by signed
artifacts, measured into the register and restored at boot. What it
patches is the JVMs that load the agent, not the kernel.

Build and ship
--------------

``shirudo build agent.jar`` signs the jar into ``agent.upatch``, and
``shirudo build --unload agent`` signs its directive (see
:doc:`/reference/cli/build`). In a package, a Beefile upatch with
``type = "java"`` and a ``.jar`` source does the same (see
:doc:`/reference/formats/beefile`), and its ``[upatches.tree]`` entry
publishes it through a tree as it does a BPF upatch. The container
carries no loader: its signed data holds the name, the payload type and
the jar (:doc:`/reference/formats/upatch-format`).

The jar must name a ``Premain-Class`` in its manifest, and with its
signature fit the 16 MiB a ``.upatch`` may have; ``build`` refuses one
that does not.

On the target
-------------

``shirudo upatch load agent.upatch``, a ``bpm install`` of the
package, or a ``bpm tree sync`` that takes its ``add``:

#. checks the signature over the signed data against the certificates
   of the authenticated runtime that the ``.bpf`` keyring holds, as the
   kernel does for a BPF loader, and the signed name, payload type and
   payload digest;
#. writes the jar, sealed, to ``/run/shirudo-java/agent.jar``, mode
   ``0644``, archives the upatch and measures a ``java_load`` event;
#. writes ``/run/environment.d/shirudo.conf`` with one
   ``-javaagent:/run/shirudo-java/<name>.jar`` for each loaded Java
   upatch, in name order, appended to the ``JAVA_TOOL_OPTIONS`` that
   ``environment.d`` files sorting before it set.

``shirudo upatch unload agent.unload.upatch``, or a tree ``delete``,
measures a ``java_unload`` event, replaces the jar with one whose agent
does nothing, removes the archive, and rewrites the options without the
agent. At boot ``init`` verifies each archived Java upatch the eventlog
records as loaded and writes its jar and the options, which ``/run``
carries to the root file system. A later run of ``init`` in the same
boot leaves a jar that is the archived one in place, and refuses one
that is missing or another as tampered, as it refuses a BPF upatch
without its pins. ``upatch list`` and ``status`` show a Java
upatch loaded while its installed jar is the archived one; ``status``
reports one whose jar is missing or another under ``UpatchesMeasured``,
and a jar no archive backs, which a load stopped before its archive
leaves until the next upatch command replaces it.

A BPF and a Java upatch share one name space: a load is refused as
``already_loaded`` when a upatch of either kind is loaded under its name.

What reaches a JVM
------------------

The seal keeps the jar as signed: no task without runtime authority can
write, rename or remove it. The options file is not sealed, and what
reads it is outside shirudo:

- systemd's user managers read ``environment.d`` and pass the options
  to the JVMs they start. A system service, a container or a login that
  no user manager starts does not see them; such a JVM needs the same
  ``-javaagent`` in its own unit or command line.
- A JVM reads ``JAVA_TOOL_OPTIONS`` when it starts. One already running
  keeps the agents it started with until it restarts.
- A user manager reads ``environment.d`` when it starts. One started
  before a load does not name the agent in the JVMs it starts, and one
  started before an unload still names it. A JVM does not start when a
  ``-javaagent`` jar is missing, so an unload leaves a jar in place whose
  agent does nothing, until the next boot.
- An ``environment.d`` file that sorts after ``shirudo.conf`` and sets
  ``JAVA_TOOL_OPTIONS`` without ``${JAVA_TOOL_OPTIONS}`` in its value
  drops the agents.
- Root, or the user who starts the JVM, can set ``JAVA_TOOL_OPTIONS`` or
  edit the file, and so start a JVM without the agent.
- A Java 8 JVM reads at most 1024 bytes and 64 options from
  ``JAVA_TOOL_OPTIONS`` and drops options past that without an error
  (JDK-8288483). Each agent adds ``-javaagent:/run/shirudo-java/<name>.jar``
  to what other ``environment.d`` files set, so keep the agents few and
  their names short where Java 8 runs.

The ``java-watch`` package of :src:`upatches/java-watch` lists the
JVMs that run on a node and, for each, the jars of ``/run/shirudo-java``
it opened, so that the JVMs these options did not reach show up in the
map export (see :doc:`/upatches/learn/examples`).

An agent does what Java code in the JVM can do: it is a mitigation
inside the application, not a boundary the kernel enforces. A BPF upatch
is the tool for a policy that root must not be able to step around.

A Java agent cannot report to a BPF upatch: the BPF LSM refuses
``BPF_OBJ_GET`` and ``BPF_PROG_TEST_RUN`` to every task but shirudo, so
an agent's telemetry goes through the JVM's own logging.
