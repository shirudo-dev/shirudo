# java-sql-inj

The `java-sql-inj` package installs the `java-sql-inj` Java upatch: a
Byte Buddy agent that instruments every JDBC `Statement` and blocks an
`execute`, `executeQuery` or `executeUpdate` whose SQL carries a
structural SQL injection, a quote that ends a literal before a comment
or a tautology such as `OR 1=1`. A blocked statement throws a
`SecurityException` in the application before it reaches the database.

The package also ships `vulnerable-app.jar`, a small application that
concatenates its argument into a query against an in-memory H2
database, and `sql_inj_vuln`, which runs it with the options the
loaded Java upatches set.

The agent reaches only JVMs that start with
`JAVA_TOOL_OPTIONS` from `/run/environment.d/shirudo.conf`, which
systemd's user managers read, and only after it is loaded. Root can
start a JVM without it. It is a mitigation inside the application, not
a boundary against root; see `Documentation/upatches/write/java-agents.rst`.

## Build

The build needs Maven and a JDK of release 11 or newer, and fetches
Byte Buddy and H2 on first use:

```sh
upatches/java-sql-inj/build.sh 0.1.0 --keys-dir <keys>
```

It writes `java-sql-inj-0.1.0.bee` into the current directory.

## Try it on a target

Install the package, then run the application from the package
directory, once with the default request, which is blocked, and once
with a benign one, which runs:

```sh
sudo shirudo bpm install <repository>/java-sql-inj
sql_inj_vuln
sql_inj_vuln admin
```

The blocked run prints:

```text
[RASP ALERT] SQL Injection Attempt Detected: SELECT * FROM users WHERE username = 'admin' OR 1=1'
[App] RASP safely aborted execution: Request blocked by RASP: Malicious SQL patterns detected.
```

`sudo shirudo bpm uninstall java-sql-inj` removes the agent; JVMs
started afterwards run without it.
