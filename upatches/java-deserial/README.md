# java-deserial

The `java-deserial` package installs the `java-deserial` Java upatch: an
agent that installs a JVM-wide deserialization filter refusing the
classes that known gadget chains are built from. A service that passes
untrusted bytes to `ObjectInputStream.readObject`, in a request body, a
cookie, an RMI or JMX call or a cache entry, lets the sender pick the
classes it instantiates, and a chain of library classes whose
`readObject`, `compare` or `invoke` calls one another ends in running
the sender's code. The filter stops such a stream at the first class on
its deny list, before that class is instantiated. A refused class makes
`readObject` throw `java.io.InvalidClassException`, which the callers of
`readObject` already handle, and logs the class name alone, never the
stream.

The guard rewrites no bytecode. It uses the JDK's own filter API, JEP
290 and JEP 415, and nothing outside the JDK:

- On release 17 and newer it replaces the filter factory with one that
  puts the guard in front of the filter the JVM's factory picks. A
  filter that `jdk.serialFilter` sets, or that the application sets on a
  stream with `setObjectInputFilter`, still applies beside the guard: a
  class the guard refuses is refused, and every other class gets that
  filter's answer.
- On release 9 to 16, which have no factory, it sets the JVM-wide
  filter. A stream that sets its own filter replaces it, and so is not
  guarded.

## What it refuses

| Entry | Chains it breaks |
|---|---|
| `org.apache.commons.collections.functors.*` | CommonsCollections1, 3, 5, 6 and 7, through `InvokerTransformer`, `InstantiateTransformer` and `ChainedTransformer` |
| `org.apache.commons.collections4.functors.*` | CommonsCollections2 and 4, the same transformers in Commons Collections 4 |
| `org.apache.commons.beanutils.BeanComparator` | CommonsBeanutils1 |
| `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` | Every chain that ends in loading the sender's bytecode through the JDK's XSLTC: Jdk7u21, CommonsBeanutils1, CommonsCollections2, 3 and 4, Spring1 and 2, ROME, Hibernate1 and others |
| `org.apache.xalan.xsltc.trax.TemplatesImpl` | The same, through a standalone Xalan |
| `org.codehaus.groovy.runtime.ConvertedClosure`, `org.codehaus.groovy.runtime.MethodClosure` | Groovy1 |
| `bsh.XThis*` | BeanShell1, through `bsh.XThis` and its `Handler` |
| `com.sun.syndication.feed.impl.ObjectBean`, `com.rometools.rome.feed.impl.ObjectBean` | ROME, under its old and its new package |
| `com.mchange.v2.naming.ReferenceIndirector$ReferenceSerialized` | C3P0, which loads a class from a remote JNDI reference |
| `org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider` | Spring1 |
| `org.springframework.transaction.jta.JtaTransactionManager` | The Spring JtaTransactionManager chain, which looks up a JNDI name the stream gives |

These are classes that a service has no reason to deserialize from
untrusted input, so the list is meant not to break applications. It
sets no `maxdepth`, `maxrefs`, `maxbytes` or `maxarray` limits: those
stop a deserialization that exhausts memory or time, but a limit that
fits one application breaks another's legitimate large graphs, so they
belong in that application's own `jdk.serialFilter`.

## What it does not refuse

- A chain made only of classes the list does not name. A deny list
  refuses the chains known when it was written. Not deserializing
  untrusted input, or a `jdk.serialFilter` that allows only the
  application's own classes, is the durable fix; this is a mitigation in
  front of it.
- Classes that are also written to streams legitimately, such as
  `DiskFileItem` of Commons FileUpload and Wicket, JSF view state and
  Vaadin session classes, even though some chains use them.
- On release 9 to 16, a stream with its own filter, as said above.
- Deserialization outside `ObjectInputStream`: XML, JSON and YAML
  libraries with their own type handling, and `java.beans.XMLDecoder`.

## Which JVMs it reaches

The guard needs a JVM of release 9 or newer. Its premain is built for
release 8, so a Java 8 JVM that the shirudo `JAVA_TOOL_OPTIONS` reach
still starts: it prints
`Deserialization guard not installed: it needs a JVM of release 9 or newer, this one is 8`
and runs without the guard.

When a filter factory is already set, by `jdk.serialFilterFactory` or
by the application, or on release 9 to 16 a JVM-wide filter is already
set, the JDK lets nobody replace it. The guard then prints one
`Deserialization guard not installed: ...` line and the JVM runs without
it, rather than not starting. The same holds for an attach to a JVM that
has already created an `ObjectInputStream`.

The agent reaches a JVM two ways:

- As a shirudo Java upatch it is applied with `-javaagent` at JVM start,
  through the `JAVA_TOOL_OPTIONS` that
  `/run/environment.d/shirudo.conf` sets (see
  `Documentation/upatches/write/java-agents.rst`). It reaches only JVMs
  that a systemd user manager starts after the upatch is loaded; root
  can start a JVM without it. It is a mitigation inside the application,
  not a boundary against root.
- For a JVM that shirudo does not start, such as one in a container,
  the same jar attaches to a running process:
  `java -jar java-deserial.jar <pid>`.

## Build

The build needs a JDK of release 9 or newer, with `javac` and `jar` on
`PATH`:

```sh
upatches/java-deserial/build.sh 0.1.0 --keys-dir <keys>
```

It writes `java-deserial-0.1.0.bee` into the current directory.

## Check that the guard is in a JVM

`upatches/test/build.sh` builds `upatches/test/deserialRead.jar`, which
serializes a stub named like Commons Collections' `InvokerTransformer`,
alone and inside a list, and an ordinary `HashMap` of lists, and reads
each back. The stub holds nothing, so a JVM without the guard reads it
back and nothing runs. On release 17 and newer it also reads them
through a stream with its own filter, which refuses `java.util.Date`,
and checks that both filters apply. It exits with 0 when the guard
refused the stub and passed the rest, and with 1 in a JVM without it:

```sh
upatches/test/build.sh
java -jar upatches/test/deserialRead.jar
```
