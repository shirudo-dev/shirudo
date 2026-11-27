# java-xxe

The `java-xxe` package installs the `java-xxe` Java upatch: an agent
that has the XML parsers of the JDK refuse to fetch an external DTD or
an external entity. That fetch is the step of an XML external entity
injection (XXE) where a document names a local file or a URL, as in
`<!ENTITY e SYSTEM "file:///etc/passwd">`, and the parser reads it
into the document. A parser that would fetch one fails with the JDK's
own error:

```
External Entity: Failed to read external document 'passwd', because
'file' access is not allowed due to restriction set by the
accessExternalDTD property.
```

The agent rewrites no class and has no dependency. It sets the system
property `javax.xml.accessExternalDTD`, which the JDK has had since
JAXP 1.5, to the empty list of protocols, unless something has set it
already.

## What it refuses and what it does not

- The DOM, SAX and StAX parsers of the JDK, and what parses with them,
  such as `javax.xml.transform` and `javax.xml.xpath`, refuse to fetch
  an external general entity, an external parameter entity and an
  external DTD subset, over every protocol. An entity a document
  defines itself parses as before.
- A DTD the application resolves is not refused: the JDK does not apply
  the property to what an `EntityResolver` or an `XMLResolver` returns.
  Frameworks that resolve their DTDs from the class path keep working.
- For the same reason a library whose resolver answers every system
  identifier is not covered. `SAXReader` of dom4j 2.1.1 is one, so
  CVE-2020-10683 is not stopped.
- A document whose `DOCTYPE` names a DTD that the parser fetched itself
  until now, by path or by URL, no longer parses, also when it is read
  through XInclude or the `document()` function of XSLT. Do not load
  the upatch on a host that runs an application relying on that.
- Code that sets the property on its own factory or parser decides for
  that one. A parser that is not the JDK's need not honour it.
- Schemas and stylesheets have properties of their own, which the agent
  does not set.
- Hardening the parser in the application is the durable fix; this is a
  mitigation in front of it.

## Which JVMs it reaches

The agent is built for release 8 and does the same on every later
release. An older JVM cannot load it and does not start once the upatch
is loaded: publish it only to hosts that run none.

The agent reaches a JVM two ways:

- As a shirudo Java upatch it is applied with `-javaagent` at JVM start,
  through the `JAVA_TOOL_OPTIONS` that
  `/run/environment.d/shirudo.conf` sets (see
  `Documentation/upatches/write/java-agents.rst`). It reaches only JVMs
  that a systemd user manager starts after the upatch is loaded; root
  can start a JVM without it. It is a mitigation inside the application,
  not a boundary against root. A JVM that started with the agent keeps
  the property after an unload, until it restarts.
- For a JVM that shirudo does not start, such as one in a container,
  the same jar attaches to a running process:
  `java -jar java-xxe.jar <pid>`. It restricts what reads the property
  from then on; restart the JVM to be sure of every parser. The
  launcher needs a JDK of release 9 or newer. Against a release 8 JVM
  it loads the agent and then reports an `AgentLoadException`, because
  release 8 answers in an older form: the line `XXE guard installed` on
  the standard error of the target is what tells.

## Build

The build needs a JDK of release 9 or newer, with `javac` and `jar` on
`PATH`:

```sh
upatches/java-xxe/build.sh 0.1.0 --keys-dir <keys>
```

It writes `java-xxe-0.1.0.bee` into the current directory.

## Check what the property does in a JVM

`upatches/test/build.sh` builds `upatches/test/xxeRead.jar`, which
parses a document whose external entity names a file it wrote, with
the DOM, SAX and StAX parsers. It exits with 0 when the property kept
every parser from the file and with 1 when one read it. That shows what
the property does, not who set it, so run it without the agent and with
it:

```sh
upatches/test/build.sh
java -jar upatches/test/xxeRead.jar
java -javaagent:upatches/java-xxe/java-xxe.jar -jar upatches/test/xxeRead.jar
```
