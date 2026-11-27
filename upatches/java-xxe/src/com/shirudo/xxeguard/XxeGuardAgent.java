// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
package com.shirudo.xxeguard;

/**
 * Sets javax.xml.accessExternalDTD to the empty list of protocols when
 * nothing has set it. The property (JAXP 1.5) is the default that the XML
 * processors of the JDK take for the protocols over which they may fetch
 * an external DTD or an external entity themselves. With none allowed they
 * refuse the fetch that an XML external entity injection relies on, where
 * a document names a local file or a URL. Rewrites no class. Applies at
 * JVM start through -javaagent (premain) and by dynamic attach
 * (agentmain). Built for release 8: an older JVM cannot load it.
 */
public final class XxeGuardAgent {
    static final String PROPERTY = "javax.xml.accessExternalDTD";

    private XxeGuardAgent() {}

    /** -javaagent entry: applies the guard as the JVM starts. */
    public static void premain(String args) {
        install();
    }

    /** Dynamic-attach entry: applies the guard to what reads the property from now on. */
    public static void agentmain(String args) {
        install();
    }

    private static void install() {
        Object set;
        try {
            // In one step, so that a value the application sets meanwhile stays.
            set = System.getProperties().putIfAbsent(PROPERTY, "");
        } catch (SecurityException e) {
            // A JVM does not start when premain throws: one whose security
            // manager denies the properties runs without the guard instead.
            System.err.println("XXE guard not installed: a security manager denies the system properties");
            return;
        }
        if (set == null) {
            System.err.println("XXE guard installed: " + PROPERTY + " allows no protocol");
        } else if ("".equals(set)) {
            System.err.println("XXE guard in place: " + PROPERTY + " already allows no protocol");
        } else {
            // Set on the command line or by the application: theirs to decide.
            System.err.println("XXE guard not installed: " + PROPERTY + " is already set");
        }
    }
}
