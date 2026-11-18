// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

package com.security.rasp;

import net.bytebuddy.asm.Advice;
import java.util.regex.Pattern;

public class SqlInjectionAdvisor {

    // A structural pattern of typical SQL injection: a quote ending a
    // literal before a comment, or a tautology such as OR 1=1.
    private static final Pattern SQLI_PATTERN = Pattern.compile(
            "(['\"]\\s*--)|(\\b(OR|AND)\\b\\s+\\d+\\s*=\\s*\\d+)",
            Pattern.CASE_INSENSITIVE
    );

    @Advice.OnMethodEnter(inline = false)
    public static void onEnter(@Advice.Argument(0) String sql) {
        if (sql != null && SQLI_PATTERN.matcher(sql).find()) {
            System.err.println("[RASP ALERT] SQL Injection Attempt Detected: " + sql);
            // Block the statement before it reaches the database.
            throw new SecurityException("Request blocked by RASP: Malicious SQL patterns detected.");
        }
    }
}
