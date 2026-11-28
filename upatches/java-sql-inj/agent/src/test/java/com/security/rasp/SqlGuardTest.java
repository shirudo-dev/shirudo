// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

package com.security.rasp;

/**
 * A table of statements and whether SqlGuard blocks them. It needs no
 * database and no test framework:
 *
 * <pre>
 * javac -d /tmp/sqlguard agent/src/main/java/com/security/rasp/SqlGuard.java \
 *     agent/src/test/java/com/security/rasp/SqlGuardTest.java
 * java -cp /tmp/sqlguard com.security.rasp.SqlGuardTest
 * </pre>
 *
 * It exits 1 when a row differs.
 */
public class SqlGuardTest {

    private static final String T = "SELECT * FROM users WHERE name = ";

    private static final Object[][] ROWS = {
        // Injections: the payload ends the literal, then does one of these.
        {true, T + "'admin' OR 1=1'"},
        {true, T + "'x' OR 'a'='a'"},
        {true, T + "'x' OR 2>1 --'"},
        {true, T + "'x'/**/OR/**/1=1/**/--'"},
        {true, "SELECT * FROM users WHERE id = 1 OR(1=1)"},
        {true, "SELECT * FROM users WHERE id = 1 or ((1 = 1))"},
        {true, "SELECT * FROM users WHERE id = 1 OR '1'=1"},
        {true, "SELECT * FROM users WHERE id = 1 OR 3 >= 3"},
        {true, "SELECT * FROM users WHERE id = 1 OR 1 <> 2"},
        {true, T + "'x'; DROP TABLE users; SELECT 'a'"},
        {true, T + "'admin'#'"},
        {true, T + "'admin' -- '"},
        {true, T + "'a''b' OR 1=1 OR ''='"},
        {true, "SELECT * FROM users WHERE id = 1 OR TRUE"},
        {true, "SELECT * FROM users WHERE id = 1 or (true)"},
        {true, T + "'x' UNION SELECT password, null FROM admins WHERE 'a'='a'"},
        {true, "SELECT * FROM users WHERE id = 1 AND 'x' = 'x'"},
        {true, "SELECT * FROM t /* c */ WHERE a = ?"},
        {true, "SELECT * FROM t WHERE a = ? /* never ends"},
        // Benign: bind parameters, query builders, data that looks like SQL.
        {false, "SELECT * FROM t WHERE a = ? AND 1 = 1"},
        {false, "SELECT * FROM t WHERE 1=1 AND a = ?"},
        {false, "INSERT INTO notes(body) VALUES ('use -- for comments')"},
        {false, "SELECT * FROM t WHERE label = 'A OR 1=1 sale'"},
        {false, "SELECT * FROM t WHERE label = 'x; DROP TABLE t'"},
        {false, "SELECT * FROM t WHERE label = 'a /* b */ c'"},
        {false, "SELECT * FROM t WHERE label = 'it''s -- fine'"},
        {false, "SELECT \"a--b\", `c#d`, [e;f] FROM t"},
        {false, "SELECT * FROM t WHERE a = 1 OR 1 = 0"},
        {false, "SELECT * FROM t WHERE a = 1 OR 'a' = 'b'"},
        {false, "SELECT * FROM t WHERE a = 1 OR b = 1"},
        {false, "SELECT * FROM t WHERE a = 1 OR x = x"},
        {false, "SELECT * FROM t WHERE a = 1 OR 2 < 1"},
        {false, "SELECT * FROM t WHERE color = 'blue' OR color = 'red'"},
        {false, "SELECT * FROM t WHERE a = 1;"},
        {false, "SELECT * FROM t WHERE a = 1 ; ;"},
        // A block comment first or last is how tracing tools tag a statement.
        {false, "/* app=shop */ SELECT * FROM t WHERE a = ?"},
        {false, "SELECT * FROM t WHERE a = ? /*traceparent='00-abc-01'*/"},
        {false, "/* a */ SELECT * FROM t WHERE a = ? /* b */"},
        {false, "SELECT * FROM t WHERE a = 1 OR TRUE = b"},
        {false, "SELECT * FROM t WHERE a IN ('a', 'b')"},
        {false, "SELECT * FROM t WHERE 'a' = 'b'"},
        {false, "SELECT 1"},
        {false, ""},
        // A literal that never ends is data to its end, not a way out.
        {false, T + "'abc"},
        {false, T + "'abc -- OR 1=1"},
    };

    public static void main(String[] args) {
        int bad = 0;

        for (Object[] row : ROWS) {
            boolean want = (Boolean) row[0];
            String sql = (String) row[1];
            String reason = SqlGuard.check(sql);
            boolean got = reason != null;

            if (got != want) {
                bad++;
                System.out.println("FAIL: want " + (want ? "block" : "pass")
                        + ", got " + (got ? "block (" + reason + ")" : "pass")
                        + ": " + sql);
            }
        }
        if (SqlGuard.check(null) != null) {
            bad++;
            System.out.println("FAIL: null must pass");
        }
        System.out.println((ROWS.length + 1 - bad) + "/" + (ROWS.length + 1) + " rows ok");
        System.exit(bad == 0 ? 0 : 1);
    }
}
