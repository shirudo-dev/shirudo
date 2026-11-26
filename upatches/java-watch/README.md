# java-watch

The `java-watch` package installs the `java-watch` upatch, which lists
the JVMs running on the host and, for each, the agents of Java upatches
it opened. A Java upatch reaches only the JVMs that start with its
`-javaagent` option (`Documentation/upatches/write/java-agents.rst`).
This list shows the ones it did not reach: a JVM started before the
load, one a user manager did not start, one in a container, one whose
`JAVA_TOOL_OPTIONS` another file replaced. Nothing in this package
enforces or changes a JVM.

## What counts

- A JVM is a process that maps a file named `libjvm.so` executable. Its
  record is made when the mapping is requested and is removed when the
  last thread of the process exits or the process executes another
  program.
- An agent is a file `<name>.jar` in a directory named `shirudo-java`
  that carries shirudo's seal label, opened by a thread of that JVM.
  Only shirudo can set the label, so a copy of the jar elsewhere, or a
  jar root puts into a directory of that name, does not count. Java
  upatches install their jars in `/run/shirudo-java`.
- A JVM with at least one such agent is `patched`. The JVM opens a
  `-javaagent` jar before `main()` runs and stops if the agent's
  `premain` fails, so a patched JVM that keeps running ran the agent.

## Install the package

```sh
PACKAGE=oci://registry.example.com/shirudo/java-watch:0.1.0
sudo shirudo bpm install "$PACKAGE"
```

The Beefile has a tree entry for `java-watch`, without a selector, so a
signed upatch tree can take it to every node that syncs the tree, beside
the Java upatches it watches.

## Read the list

```sh
sudo shirudo upatch map java-watch jvms --json
```

The table is the set of JVMs running now, not an interval of events: a
read takes nothing away, with or without `--peek`, and the map-export
timer sends the whole list every time it runs. The decoder returns:

| Field | Content |
| --- | --- |
| `jvms[].pid` | the process ID in the initial PID namespace |
| `jvms[].euid` | the effective user ID of the thread that mapped `libjvm.so` |
| `jvms[].started_unix_nano` | when the process started |
| `jvms[].seen_unix_nano` | when it mapped `libjvm.so` |
| `jvms[].cgroup_id` | its cgroup, which names the service or container |
| `jvms[].mnt_ns` | the inode number of its mount namespace |
| `jvms[].libjvm` | `{dev, ino}` of the `libjvm.so` it mapped, which names the JDK |
| `jvms[].agents` | up to four agents, each `{name, name_truncated, ino}`, the jar's file name cut to 39 bytes |
| `jvms[].patched` | whether `agents` names one |
| `jvms[].more_agents` | whether it opened agents past the fourth |
| `unpatched` | the number of JVMs without an agent |
| `overflow` | JVMs that found no free slot and are not listed |

The table holds 512 JVMs. A JVM that finds none of the 16 slots its
process ID selects free is not listed and is counted in `overflow`.

## Limits

- JVMs that started before the upatch loaded are not listed. After a
  reboot `init` restores the upatch before any JVM starts, so this is
  a gap of the first load only.
- A JVM is found by the file name of its `libjvm.so`. A renamed copy
  runs without a record, and a process that maps any file of that name
  has one. A statically linked native image has no `libjvm.so` and no
  agents.
- An opened agent jar says the agent ran at startup, not that it still
  guards what it patched: the application can undo what Java code in it
  did. A Java upatch is a mitigation, not a boundary against root.

## Cost

The programs run on every executable mapping, every open, every exec
and every process exit on the host. For a process that is not a JVM a
mapping costs a name comparison, an open a task storage lookup, an exec
a probe of 16 slots and an exit a task storage lookup. Only a JVM's
opens of jars named `*.jar` in a `shirudo-java` directory read an
extended attribute. The arena takes about 150 KiB at load.

## Preemption model

`java-watch` is written for preemptible RCU, the weakest guarantee, and
is correct on every preemption model. It uses no per-CPU memory: the
extended attribute is read into the task's own storage. Runs on
different CPUs share the slots on every kernel. A JVM takes a slot by
compare-and-swap of its sequence word and publishes it with a release
store; its threads add agents by compare-and-swap of the agent's inode
and publish each name with a release store; an exit or an exec frees the
slot by compare-and-swap into the next generation. The serializer reads
a slot as a seqlock reader, and drops a record whose sequence word
changed while it read.
