# java-jndi

The `java-jndi` package installs the `java-jndi` Java upatch: an agent
that refuses a JNDI name with a remote URL scheme, `ldap:`, `ldaps:`,
`rmi:`, `dns:`, `iiop:`, `iiopname:`, `corbaname:` or `nis:`, before
`javax.naming.InitialContext` creates a context for it. That is the
step of a JNDI injection, CVE-2021-44228 (Log4Shell) and CVE-2021-45046
among them, where text an attacker controls makes the JVM connect to a
server the attacker runs and load an object from it. A refused name
throws `javax.naming.NoPermissionException`, a `NamingException` that
the callers of `lookup` already handle, and logs only its scheme, since
the rest of the name is the attacker's text.

The guard is a check prepended to both
`InitialContext.getURLOrDefaultInitCtx` methods, which every operation
of an `InitialContext` or `InitialDirContext` on a name goes through.
It is written with the JDK Class-File API alone, with no third-party
dependency, and `JndiCheck`, which the instrumented `java.naming` code
calls, rides in a nested `jndi-check.jar` that the agent appends to the
bootstrap loader.

## What it refuses and what it does not

- A name without a URL scheme, such as `java:comp/env/jdbc/app` or
  `jdbc/app`, goes to the default context as before. An application
  that reaches a directory through `Context.PROVIDER_URL` in its
  environment and looks up plain names keeps working.
- An application that looks up a remote URL on purpose, for example
  `ldap://directory.example.com/...` passed to `lookup`, is refused as
  well. Do not load the upatch on a host that runs one.
- Code that creates a URL context itself, through
  `NamingManager.getURLContext` or a provider class, does not pass the
  guard. It closes the path injected text takes, not every way to
  reach a directory.
- Upgrading the library that passes the text to JNDI, Log4j 2.17.1 or
  later for CVE-2021-44228, is the durable fix; this is a mitigation in
  front of it.

## Which JVMs it reaches

The guard needs a JVM of release 24 or newer for the Class-File API.
Its premain is built for release 8, so an older JVM that the shirudo
`JAVA_TOOL_OPTIONS` reach still starts: it prints
`JNDI guard not installed: it needs a JVM of release 24 or newer` and
runs without the guard.

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
  `java -jar java-jndi.jar <pid>`.

## Build

The build needs a JDK of release 24 or newer, with `javac` and `jar` on
`PATH`:

```sh
upatches/java-jndi/build.sh 0.1.0 --keys-dir <keys>
```

It writes `java-jndi-0.1.0.bee` into the current directory.

## Check that the guard is in a JVM

`upatches/test/build.sh` builds `upatches/test/jndiLookup.jar`, which
looks up remote names of each refused scheme on a closed port of the
loopback, and a plain name the guard must pass. It exits with 0 when the
guard refused every remote name and passed the plain one, and with 1 in
a JVM without it, where the JDK answers with a connection error:

```sh
upatches/test/build.sh
java -jar upatches/test/jndiLookup.jar
```
