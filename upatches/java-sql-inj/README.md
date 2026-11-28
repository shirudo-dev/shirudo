# java-sql-inj

The `java-sql-inj` package installs the `java-sql-inj` Java upatch: a
Byte Buddy agent that instruments every JDBC `Statement` and
`Connection`. It blocks the SQL text of `execute*`, `addBatch`,
`prepareStatement` and `prepareCall` when it carries a structural SQL
injection. A blocked statement throws a `SecurityException` in the
application before it reaches the database.

The check, in `SqlGuard`, is a small SQL lexer that knows string
literals, quoted identifiers (`"..."`, `` `...` ``, `[...]`) and comments,
and looks only outside literals. It blocks:

- a comment: `--`, `#`, or a `/* ... */` anywhere but first or last in the
  statement, which is where tracing agents and ORMs put theirs;
- a second statement after a `;`;
- an `OR` whose operands are literals that compare true, such as
  `OR 1=1`, `OR 'a'='a'`, `OR 2>1`, `OR(1=1)` or `OR TRUE`;
- a comparison of two string literals that is true, wherever it stands,
  since no application compares two string constants.

An `AND` tautology passes, since query builders emit `AND 1=1`, and so
does a pattern inside a literal, such as `'A OR 1=1 sale'`. A statement
with bind parameters carries none of this. It is an example, not a
parser of any dialect, and it does not see an injection that uses
neither, such as a `UNION SELECT` appended to a numeric condition with
no tautology. A query that holds a comment on purpose inside the
statement, such as an optimizer hint `/*+ hint */` after `SELECT`, is
blocked.

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

## Test

`SqlGuard` needs only a JDK. The test is a table of statements and
whether each is blocked; it needs no database and no Maven:

```sh
cd upatches/java-sql-inj
javac -d /tmp/sqlguard agent/src/main/java/com/security/rasp/SqlGuard.java \
    agent/src/test/java/com/security/rasp/SqlGuardTest.java
java -cp /tmp/sqlguard com.security.rasp.SqlGuardTest
```

It prints how many rows pass and exits 1 when one differs.

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
[RASP ALERT] SQL Injection Attempt Detected (OR with a condition that is always true): SELECT * FROM users WHERE username = 'admin' OR 1=1'
[App] RASP safely aborted execution: Request blocked by RASP: Malicious SQL patterns detected.
```

`sudo shirudo bpm uninstall java-sql-inj` removes the agent; JVMs
started afterwards run without it.
