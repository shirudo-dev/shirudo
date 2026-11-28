// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

package com.security.rasp;

import net.bytebuddy.asm.Advice;

public class SqlInjectionAdvisor {

    @Advice.OnMethodEnter(inline = false)
    public static void onEnter(@Advice.Argument(0) String sql) {
        String reason = SqlGuard.check(sql);

        if (reason != null) {
            System.err.println("[RASP ALERT] SQL Injection Attempt Detected (" + reason + "): " + sql);
            // Block the statement before it reaches the database.
            throw new SecurityException("Request blocked by RASP: Malicious SQL patterns detected.");
        }
    }
}
