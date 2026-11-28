// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Looks up the JNDI names the java-jndi guard refuses, as a Log4Shell
// payload would have the JVM do, and a local name it lets through, and
// says who answered: exit status 0 when the guard refused every remote
// name and passed the local one, 1 otherwise. The remote names point at
// a closed port of the loopback, so a JVM without the guard fails them
// with a connection error and never reaches a server.

import java.util.Hashtable;
import javax.naming.CompositeName;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.NoInitialContextException;
import javax.naming.NoPermissionException;
import javax.naming.directory.InitialDirContext;

public class JndiLookup {
    private static final String GUARD = "Rejected JNDI name with a remote URL scheme";
    private static final String[] REMOTE = {
        "ldap://127.0.0.1:1/Exploit",
        "LDAPS://127.0.0.1:1/Exploit",
        "rmi://127.0.0.1:1/Exploit",
        "dns://127.0.0.1:1/example.com",
        "iiop://127.0.0.1:1/Exploit",
    };

    private interface Lookup {
        void run() throws NamingException;
    }

    private static boolean refused(String what, Lookup lookup) {
        try {
            lookup.run();
            System.out.println("jndiLookup: " + what + ": looked up, no guard");
        } catch (NoPermissionException e) {
            if (GUARD.equals(e.getMessage())) {
                System.out.println("jndiLookup: " + what + ": refused by the guard");
                return true;
            }
            System.out.println("jndiLookup: " + what + ": no guard: " + e);
        } catch (NamingException e) {
            System.out.println("jndiLookup: " + what + ": no guard, the JDK answered: " + e);
        }
        return false;
    }

    public static void main(String[] args) throws Exception {
        boolean ok = true;
        InitialContext ctx = new InitialContext();
        InitialDirContext dir = new InitialDirContext();
        for (String name : REMOTE) {
            ok &= refused("lookup " + name, () -> ctx.lookup(name));
            ok &= refused("lookup(Name) " + name, () -> ctx.lookup(new CompositeName().add(name)));
            ok &= refused("getAttributes " + name, () -> dir.getAttributes(name));
        }
        // A name without a URL scheme goes to the default context, which
        // is not configured here: the guard must leave it alone.
        try {
            ctx.lookup("jdbc/app");
            System.out.println("jndiLookup: local name: looked up");
        } catch (NoInitialContextException | NameNotFoundException e) {
            System.out.println("jndiLookup: local name: passed to the default context");
        } catch (NamingException e) {
            System.out.println("jndiLookup: local name: refused: " + e);
            ok = false;
        }
        System.exit(ok ? 0 : 1);
    }
}
