// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
package com.shirudo.jndiguard;

import java.lang.instrument.Instrumentation;

/**
 * The agent's entry point, built for release 8 so that every JVM the
 * JAVA_TOOL_OPTIONS of shirudo reach can load it. A JVM fails to start when
 * the premain of a -javaagent throws, and the guard itself needs the
 * Class-File API of release 24: on an older JVM this class says so and
 * returns, and the JVM runs without the guard instead of not at all.
 */
public final class JndiGuardAgent {
    static final int RELEASE = 24;

    private JndiGuardAgent() {}

    /** -javaagent entry: applies the guard as the JVM starts. */
    public static void premain(String args, Instrumentation instrumentation) throws Exception {
        install(instrumentation);
    }

    /** Dynamic-attach entry: applies the guard to a running JVM. */
    public static void agentmain(String args, Instrumentation instrumentation) throws Exception {
        install(instrumentation);
    }

    /** The feature release of this JVM: 8 for "1.8", 24 for "24". */
    static int release() {
        String spec = System.getProperty("java.specification.version", "0");
        if (spec.startsWith("1.")) spec = spec.substring(2);
        try {
            return Integer.parseInt(spec);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static void install(Instrumentation instrumentation) throws Exception {
        int release = release();
        if (release < RELEASE) {
            System.err.println("JNDI guard not installed: it needs a JVM of release "
                    + RELEASE + " or newer, this one is " + release);
            return;
        }
        try {
            Class.forName("com.shirudo.jndiguard.JndiGuardInstaller")
                    .getMethod("install", Instrumentation.class)
                    .invoke(null, instrumentation);
        } catch (java.lang.reflect.InvocationTargetException e) {
            // What install threw, not the reflection wrapper around it.
            Throwable cause = e.getCause();
            if (cause instanceof Exception) throw (Exception) cause;
            throw (Error) cause;
        }
    }
}
