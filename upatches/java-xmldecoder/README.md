# java-xmldecoder

The `java-xmldecoder` package installs the `java-xmldecoder` Java
upatch: an agent that has `java.beans.XMLDecoder` refuse some of the
operations a document asks it to make. While a thread decodes, the
method calls, constructions and public-field access that the decoder
makes on JDK classes are refused unless the class is on a short list.
`XMLDecoder` calls the methods and constructors that a document names,
so a document can start a process:
`<void class="java.lang.ProcessBuilder">...<void method="start"/>`.
This is the class of CVE-2017-3506 and CVE-2017-10271; it was not
replayed on WebLogic.

A thread decodes from the start of `DocumentHandler.parse`, or of a SAX
callback of a handler from `XMLDecoder.createHandler`, to its end. The
agent checks method calls at `MethodUtil.invoke`, constructions at
`ConstructorFinder.findConstructor` and `Class.newInstance`, and field
access at `FieldElementHandler`. A refusal throws
`com.shirudo.xmldecoderguard.RefusedException`, a `SecurityException`,
out of `readObject` or of `close`, which parses when `readObject` has
not, and logs the class and the member, not the document. The check
class rides in a nested jar that the agent appends to the bootstrap
loader, so the mitigation is one signed jar.

## What it refuses and what it does not

- A class is the JDK's when the bootstrap or the platform loader
  defined it (the extension loader on release 8), or its name starts
  with `jdk.`, `sun.`, `com.sun.tools.`, `com.sun.jdi.` or
  `com.sun.source.`. Every JDK class is refused unless it is one of:
  - `Object`, `String`, `Boolean`, `Character`, `StringBuilder`,
    `StringBuffer`, a `Number`, an `Enum`;
  - a `Collection` or a `Map` in package `java.util` itself, a `Date`, a
    `Calendar`, a `TimeZone`, `Locale`, `UUID`, `Currency`, `BitSet`,
    `Optional`, `Collections`, `Arrays`, `Objects`;
  - a class of `java.math`, `java.time` or `java.awt.geom`, or
    `java.awt.Color`, `Point`, `Dimension`, `Rectangle`, `Insets`;
  - `File` and `URI`, to construct only.
- Of `Class` only `newInstance` and `getField` pass, and of `Field`
  only `set` on a field that is not static: that is how `XMLEncoder`
  writes a public field. A field that a `<field>` element or a `field`
  attribute names is the one the decoder resolves: its class and its
  declaring class must pass, and a static field is not written.
- A method that a refused JDK class declares is refused on an
  application class too, and a static field is not written in any class.
  So "classes of the application are not restricted" means their own
  methods, constructors and instance fields, and a document can still
  use a gadget class among them.
- An allowed class is allowed with all its public methods, so what it
  does with its arguments is not checked: a map calls `hashCode` and
  `equals` of what it is given. A document can still take time and
  memory, and resolving a class by name, which the decoder does without
  a check, can initialise it.
- An archive of AWT or Swing components, fonts, `URL` objects or event
  listeners is refused.
- An attach does not cut over at a document boundary: a decode in
  progress is partly guarded. Attach while no decode runs.
- The agent keeps its transformer, so a class that another agent
  retransforms later gets the guard again. If that fails, the line
  `XMLDecoder guard: cannot transform <class>` on the standard error
  says so, and the guard is off for that class until the JVM restarts.

## Which JVMs it reaches

The agent is built for release 8 and was exercised on Temurin 8, 11, 17,
21 and 25. A JVM older than 8 cannot load it and does not start once the
upatch is loaded, so publish it only to hosts that run none. A failure
that the agent catches in `premain`, such as a JVM without `java.desktop`,
prints `XMLDecoder guard not installed: <reason>` and the JVM starts.

The agent reaches a JVM two ways:

- As a shirudo Java upatch it is applied with `-javaagent` at JVM start,
  through the `JAVA_TOOL_OPTIONS` that
  `/run/environment.d/shirudo.conf` sets (see
  `Documentation/upatches/write/java-agents.rst`). It reaches only JVMs
  that a systemd user manager starts after the upatch is loaded and has
  read the updated environment; root can start a JVM without it.
  Unloading the upatch affects the JVMs started afterwards: a running
  one keeps the guard. It is a mitigation inside the application, not a
  boundary against root.
- For a JVM that shirudo does not start, such as one in a container,
  the same jar attaches to a running process:
  `java -jar java-xmldecoder.jar <pid>`. The launcher's user must be
  allowed to attach, and the jar path must be one the target can open.
  Use a launcher JDK of the target's release: a newer one against
  release 8 loads the agent and reports an error. A failed install makes
  the launcher exit non-zero and leaves the guard off; the line on the
  target's standard error says what happened.

A second load does nothing. The agent writes its nested jar to the
temporary directory and removes it at exit, not after a crash. Where
class data sharing is on, a JVM prints `Sharing is only supported for
boot loader classes` once, and, unless `-XX:+EnableDynamicAgentLoading`
is set, one of release 21 or newer a warning about a dynamically loaded
agent when the agent attaches.

## Build

The build needs Maven 3.6.3 or newer and a JDK of release 9 or newer on
`PATH`, and fetches Byte Buddy on first use:

```sh
upatches/java-xmldecoder/build.sh 0.1.0 --keys-dir <keys>
```

It writes `java-xmldecoder-0.1.0.bee` into the current directory.

## Check that the guard is in a JVM

`upatches/test/build.sh` builds `upatches/test/xmlDecode.jar`, which
decodes synthetic documents that make a marker file, write a field of
the program's own or read `System.out`, also through a SAX parser, then
what `XMLEncoder` writes for a list, a map and a bean. It exits with 0
when the guard refused every attack, no effect happened and the ordinary
documents decoded. Without the agent each attack prints `no guard, it
ran` and the exit status is 1. Run it both ways:

```sh
upatches/test/build.sh
java -jar upatches/test/xmlDecode.jar
java -javaagent:upatches/java-xmldecoder/java-xmldecoder.jar -jar upatches/test/xmlDecode.jar
```

Started with `wait`, it decodes one document, prints `xmlDecode: ready`
and waits for a byte on standard input, so that the guard can attach to
a JVM that has decoded already.
