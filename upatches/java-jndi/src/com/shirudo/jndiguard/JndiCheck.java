// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
package com.shirudo.jndiguard;

import java.util.Locale;
import javax.naming.Name;
import javax.naming.NoPermissionException;

/**
 * Loaded by the bootstrap loader so java.naming can call it from
 * InitialContext.getURLOrDefaultInitCtx, the method every InitialContext
 * operation on a name goes through to pick the context for the name's URL
 * scheme.
 */
public final class JndiCheck {
    static final String MESSAGE = "Rejected JNDI name with a remote URL scheme";

    private JndiCheck() {}

    public static void check(String name) throws NoPermissionException {
        if (name != null) reject(scheme(name));
    }

    public static void check(Name name) throws NoPermissionException {
        // InitialContext takes the scheme of a composite name from its
        // first component.
        if (name != null && name.size() > 0) reject(scheme(name.get(0)));
    }

    /** The URL scheme as InitialContext reads it: before the first ':', no '/' before it. */
    static String scheme(String name) {
        int colon = name.indexOf(':');
        int slash = name.indexOf('/');
        if (colon <= 0 || (slash >= 0 && slash < colon)) return null;
        return name.substring(0, colon).trim().toLowerCase(Locale.ROOT);
    }

    static boolean remote(String scheme) {
        if (scheme == null) return false;
        switch (scheme) {
        case "ldap":
        case "ldaps":
        case "rmi":
        case "dns":
        case "iiop":
        case "iiopname":
        case "corbaname":
        case "nis":
            return true;
        default:
            return false;
        }
    }

    private static void reject(String scheme) throws NoPermissionException {
        if (!remote(scheme)) return;
        // The scheme alone: the rest of the name is the attacker's text,
        // and a log line is where it would be looked up again.
        System.err.println("JNDI guard rejected a lookup: scheme=" + scheme);
        throw new NoPermissionException(MESSAGE);
    }
}
