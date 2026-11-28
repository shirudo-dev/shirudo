// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
package com.shirudo.deserialguard;

import com.sun.tools.attach.VirtualMachine;
import java.io.File;
import java.io.ObjectInputFilter;
import java.lang.reflect.InvocationTargetException;
import java.util.function.BinaryOperator;

/**
 * Installs a JVM-wide deserialization filter that refuses the classes known
 * gadget chains are built from, through the JDK's own filter API (JEP 290,
 * JEP 415). It rewrites no bytecode. On release 17 and newer it wraps the
 * filter factory, so the filter a stream or the application sets still
 * applies beside the guard; on release 9 to 16 it sets the JVM-wide filter
 * when none is set yet. DeserialGuardAgent, the entry point, calls it only on
 * release 9 or newer.
 */
public final class DeserialGuardInstaller {
    /**
     * The refused classes, in the pattern syntax of
     * ObjectInputFilter.Config.createFilter. README.md names the chain each
     * entry breaks.
     */
    static final String DENY = String.join(";",
            "!org.apache.commons.collections.functors.*",
            "!org.apache.commons.collections4.functors.*",
            "!org.apache.commons.beanutils.BeanComparator",
            "!com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
            "!org.apache.xalan.xsltc.trax.TemplatesImpl",
            "!org.codehaus.groovy.runtime.ConvertedClosure",
            "!org.codehaus.groovy.runtime.MethodClosure",
            "!bsh.XThis*",
            "!com.sun.syndication.feed.impl.ObjectBean",
            "!com.rometools.rome.feed.impl.ObjectBean",
            "!com.mchange.v2.naming.ReferenceIndirector$ReferenceSerialized",
            "!org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider",
            "!org.springframework.transaction.jta.JtaTransactionManager");

    private static ObjectInputFilter denyFilter;

    private static boolean installed;

    private DeserialGuardInstaller() {}

    /** Dynamic-attach launcher: java -jar java-deserial.jar <pid>. */
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Usage: java -jar java-deserial.jar <pid>");
        VirtualMachine vm = VirtualMachine.attach(args[0]);
        try {
            vm.loadAgent(new File(DeserialGuardInstaller.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI()).getAbsolutePath());
        } finally {
            vm.detach();
        }
    }

    /**
     * The guard in front of next, the filter that would apply without it, or
     * of no filter when next is null: a class on the deny list is refused,
     * and every other check gets the answer of next.
     */
    static ObjectInputFilter guard(ObjectInputFilter next) {
        return info -> {
            if (denyFilter.checkInput(info) == ObjectInputFilter.Status.REJECTED) {
                // The name comes from the stream: print only the characters
                // of a Java binary name.
                String name = info.serialClass().getName().replaceAll("[^A-Za-z0-9_$.\\[;]", "?");
                System.err.println("Deserialization guard refused class " + name);
                return ObjectInputFilter.Status.REJECTED;
            }
            return next == null ? ObjectInputFilter.Status.UNDECIDED : next.checkInput(info);
        };
    }

    /** Applies the guard; DeserialGuardAgent calls it from premain and agentmain. */
    public static synchronized void install(int release) throws Exception {
        if (installed) return;
        try {
            denyFilter = ObjectInputFilter.Config.createFilter(DENY);
            if (release >= 17) {
                installFactory();
            } else if (ObjectInputFilter.Config.getSerialFilter() != null) {
                System.err.println("Deserialization guard not installed: a JVM-wide filter is already set");
                return;
            } else {
                ObjectInputFilter.Config.setSerialFilter(guard(null));
            }
        } catch (IllegalStateException | LinkageError e) {
            // jdk.serialFilterFactory, the application, or a stream created
            // before an attach, set the filter first, or a jdk.serialFilter
            // or jdk.serialFilterFactory the JDK could not read left
            // ObjectInputFilter.Config unusable. The JVM keeps running.
            System.err.println("Deserialization guard not installed: " + e);
            return;
        }
        installed = true;
        System.err.println("Deserialization guard installed on java.io.ObjectInputStream");
    }

    /**
     * Release 17's filter factory, reached by reflection since this class is
     * built for release 9. The factory the JVM had, which applies
     * jdk.serialFilter and the filter a stream sets, picks the filter as
     * before, and the guard goes in front of what it picks.
     */
    @SuppressWarnings("unchecked")
    private static void installFactory() throws Exception {
        Class<?> config = ObjectInputFilter.Config.class;
        try {
            BinaryOperator<ObjectInputFilter> previous = (BinaryOperator<ObjectInputFilter>)
                    config.getMethod("getSerialFilterFactory").invoke(null);
            BinaryOperator<ObjectInputFilter> factory = (current, requested) ->
                    guard(previous.apply(current, requested));
            config.getMethod("setSerialFilterFactory", BinaryOperator.class).invoke(null, factory);
        } catch (InvocationTargetException e) {
            // What the JDK threw, IllegalStateException among them.
            Throwable cause = e.getCause();
            if (cause instanceof Exception) throw (Exception) cause;
            throw (Error) cause;
        }
    }
}
