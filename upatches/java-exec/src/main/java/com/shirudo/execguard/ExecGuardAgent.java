// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
package com.shirudo.execguard;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import net.bytebuddy.agent.ByteBuddyAgent;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.utility.JavaModule;

/**
 * Has java.lang.ProcessBuilder refuse a shell command string that chains or
 * substitutes commands, the shape of an OS command injection, before the
 * process starts. ExecAdvice is the check. It goes at the start of the
 * private start(Redirect[]) of release 9 and newer, which start(),
 * startPipeline and every Runtime.exec reach, or of start() on release 8,
 * which has no other. Applies at JVM start through -javaagent (premain) and
 * by dynamic attach (agentmain).
 */
public final class ExecGuardAgent {
    private static boolean installed;

    private ExecGuardAgent() {}

    /** Dynamic-attach launcher: java -jar java-exec.jar <pid>. */
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Usage: java -jar java-exec.jar <pid>");
        ByteBuddyAgent.attach(new File(ExecGuardAgent.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI()), args[0]);
    }

    /** -javaagent entry: applies the guard as the JVM starts, and never stops the JVM. */
    public static void premain(String args, Instrumentation instrumentation) {
        try {
            install(instrumentation);
        } catch (Throwable t) {
            System.err.println("java-exec guard not installed: " + t);
        }
    }

    /** Dynamic-attach entry: applies the guard to a running JVM, or fails the attach. */
    public static void agentmain(String args, Instrumentation instrumentation) throws Exception {
        try {
            install(instrumentation);
        } catch (Exception e) {
            System.err.println("java-exec guard not installed: " + e);
            throw e;
        }
    }

    private static synchronized void install(Instrumentation instrumentation) throws Exception {
        if (installed) return;
        if (!instrumentation.isRetransformClassesSupported()
                || !instrumentation.isModifiableClass(ProcessBuilder.class))
            throw new IllegalStateException("ProcessBuilder cannot be retransformed");
        ElementMatcher<MethodDescription> start = startMethod();
        AtomicBoolean transformed = new AtomicBoolean();
        AtomicReference<Throwable> failed = new AtomicReference<>();
        AgentBuilder.Listener listener = new AgentBuilder.Listener.Adapter() {
            @Override
            public void onTransformation(TypeDescription type, ClassLoader loader, JavaModule module,
                                         boolean loaded, DynamicType dynamicType) {
                transformed.set(true);
            }

            @Override
            public void onError(String name, ClassLoader loader, JavaModule module, boolean loaded,
                                Throwable error) {
                failed.compareAndSet(null, error);
            }
        };
        // ProcessBuilder is a bootstrap class the JVM has loaded already, so
        // it is retransformed in place: no new members, no type initializer.
        new AgentBuilder.Default()
                .disableClassFormatChanges()
                .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
                .with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE)
                .with(AgentBuilder.TypeStrategy.Default.REDEFINE)
                .with(listener)
                .ignore(ElementMatchers.none())
                .type(ElementMatchers.is(ProcessBuilder.class))
                .transform((builder, type, loader, module, domain) ->
                        builder.visit(Advice.to(ExecAdvice.class).on(start)))
                .installOn(instrumentation);
        if (failed.get() != null) throw new IllegalStateException("ProcessBuilder was not transformed", failed.get());
        if (!transformed.get()) throw new IllegalStateException("ProcessBuilder was not transformed");
        installed = true;
        System.err.println("java-exec guard installed on java.lang.ProcessBuilder.start");
    }

    /** start(Redirect[]) where the JDK has it, release 9 and newer, else start(). */
    private static ElementMatcher<MethodDescription> startMethod() {
        try {
            ProcessBuilder.class.getDeclaredMethod("start", ProcessBuilder.Redirect[].class);
            return ElementMatchers.named("start").and(ElementMatchers.takesArguments(ProcessBuilder.Redirect[].class));
        } catch (NoSuchMethodException e) {
            return ElementMatchers.named("start").and(ElementMatchers.takesArguments(0));
        }
    }
}
