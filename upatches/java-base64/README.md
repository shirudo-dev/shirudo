# java-base64

The `java-base64` package installs the `java-base64` Java upatch: an
agent that guards `java.util.Base64$Decoder.decode0` against the x64
AVX-512 tail-underflow of CVE-2026-114938. A crafted input whose length
leaves a one-to-three byte tail with padding can drive the decoder's
native AVX-512 stub to write past the destination array. The agent
rejects that input shape before `decode0` writes, throwing
`IllegalArgumentException` and logging a diagnostic that omits the input
bytes, so a patched JVM is the durable fix and this is a mitigation in
front of it.

The guard is written with the JDK Class-File API alone, with no
third-party dependency. `GuardCheck`, which the instrumented
`java.base` code calls, rides in a nested `guard-check.jar` that the
agent appends to the bootstrap loader when it installs, so the whole
mitigation is one signed jar.

The agent reaches a JVM two ways:

- As a shirudo Java upatch it is applied with `-javaagent` at JVM start,
  through the `JAVA_TOOL_OPTIONS` that
  `/run/environment.d/shirudo.conf` sets (see
  `Documentation/upatches/write/java-agents.rst`). It reaches only JVMs
  that a systemd user manager starts after the upatch is loaded; root
  can start a JVM without it. It is a mitigation inside the application,
  not a boundary against root.
- For a JVM that shirudo does not start, such as the Elasticsearch lab
  below, the same jar attaches to a running process:
  `java -jar java-base64.jar <pid>`.

## Build

The build needs a JDK of release 24 or newer (for the Class-File API),
with `javac` and `jar` on `PATH`:

```sh
upatches/java-base64/build.sh 0.1.0 --keys-dir <keys>
```

It writes `java-base64-0.1.0.bee`. A short version keeps the package's
member paths within the 99 bytes a `.bee` archive allows.

## Publish and view in xtop

`make shields` builds and pushes every shield of `upatches/`, including
this one, to the local stack's registry and loads the catalog, so the
Shields view of `tools/xtop` lists `java-base64` as available, its
`TARGET` the jar it guards and its `FIXES` CVE-2026-114938. Appending it
to a tree with `shirudo bpm tree append` moves it to the "in trees" tab.

## Try it against the Elasticsearch lab

The Elasticsearch compose lab is a JVM that shirudo does not manage, so
xtop shows `java-base64` as a published shield while the lab shows it
applied: copy the signed jar into the container and attach it to the
Elasticsearch JVM. Before, a crafted Base64 request drives the decoder
path; after, the same request gets the guard's rejection. Because the
lab is a container and not a shirudo target, it never reads shirudo's
`environment.d`; the agent is applied by dynamic attach, not by
`-javaagent`.
