// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
package com.shirudo.xmldecoderguard;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.ProtectionDomain;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.JarFile;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.agent.ByteBuddyAgent;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.pool.TypePool;
import net.bytebuddy.utility.OpenedClassReader;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;

/**
 * Has java.beans.XMLDecoder construct and call only the JDK classes that GuardCheck
 * allows, and ends the decode on the first refusal. Applies at JVM start through
 * -javaagent (premain) and by dynamic attach (agentmain).
 */
public final class XmlDecoderGuardAgent {
    private static final String HANDLER = "com.sun.beans.decoder.DocumentHandler";
    private static final String FIELDS = "com.sun.beans.decoder.FieldElementHandler";
    private static final String METHOD_UTIL = "sun.reflect.misc.MethodUtil";
    private static final String FINDER = "com.sun.beans.finder.ConstructorFinder";
    private static final String CHECK = "com.shirudo.xmldecoderguard.GuardCheck";
    private static final String REFUSED = "com.shirudo.xmldecoderguard.RefusedException";
    // The calls to GuardCheck that the advice puts into each method of a target:
    // "method:call". A class is woven when it has exactly these and no others.
    private static final Map<String, Set<String>> WOVEN = new HashMap<>();
    static {
        WOVEN.put(internal(HANDLER), new HashSet<>(Arrays.asList(
                "parse:enter", "parse:exit", "startElement:enter", "startElement:exit",
                "endElement:enter", "endElement:exit", "characters:enter", "characters:exit",
                "handleException:rethrow")));
        WOVEN.put(internal(FIELDS), new HashSet<>(Arrays.asList("getFieldValue:field", "setFieldValue:field")));
        WOVEN.put(internal(METHOD_UTIL), new HashSet<>(Arrays.asList("invoke:invoke")));
        WOVEN.put(internal(FINDER), new HashSet<>(Arrays.asList("findConstructor:construct")));
    }
    private static boolean installed;
    private static boolean appended;

    private XmlDecoderGuardAgent() {}

    /** Dynamic-attach launcher: java -jar java-xmldecoder.jar <pid>. */
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Usage: java -jar java-xmldecoder.jar <pid>");
        ByteBuddyAgent.attach(new File(XmlDecoderGuardAgent.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI()), args[0]);
    }

    /** -javaagent entry: applies the guard as the JVM starts, and never stops the JVM. */
    public static void premain(String args, Instrumentation instrumentation) {
        try {
            install(instrumentation);
        } catch (Throwable t) {
            report(t);
        }
    }

    /** Dynamic-attach entry: applies the guard to a running JVM, or fails the attach. */
    public static void agentmain(String args, Instrumentation instrumentation) throws Exception {
        try {
            install(instrumentation);
        } catch (Throwable t) {
            report(t);
            throw t;
        }
    }

    private static void report(Throwable t) {
        StringBuilder line = new StringBuilder("XMLDecoder guard not installed: ").append(t);
        for (Throwable suppressed : t.getSuppressed()) line.append("; also ").append(suppressed);
        say(line.toString());
    }

    // A line that cannot be printed must not change what an install came to.
    private static void say(String line) {
        try {
            System.err.println(line);
        } catch (Throwable ignored) {
            // Nothing else to do.
        }
    }

    private static synchronized void install(Instrumentation instrumentation) throws Exception {
        if (installed) return;
        Class<?> handler = load(HANDLER);
        Class<?> fields = load(FIELDS);
        Class<?> methodUtil = load(METHOD_UTIL);
        Class<?> finder = load(FINDER);
        Class<?>[] targets = {handler, fields, methodUtil, finder};
        for (Class<?> target : targets) {
            if (!instrumentation.isModifiableClass(target)) throw new IllegalStateException(target + " is not modifiable");
        }
        if (!instrumentation.isRetransformClassesSupported()) {
            throw new IllegalStateException("the JVM cannot retransform classes");
        }
        Map<String, AsmVisitorWrapper> advice = new HashMap<>();
        advice.put(internal(HANDLER), new AsmVisitorWrapper.Compound(
                Advice.to(XmlDecoderAdvice.Scope.class).on(
                        method(handler, "parse", InputSource.class)
                        .or(method(handler, "startElement", String.class, String.class, String.class, Attributes.class))
                        .or(method(handler, "endElement", String.class, String.class, String.class))
                        .or(method(handler, "characters", char[].class, int.class, int.class))),
                Advice.to(XmlDecoderAdvice.HandleException.class).on(method(handler, "handleException", Exception.class))));
        advice.put(internal(FIELDS), new AsmVisitorWrapper.Compound(
                Advice.to(XmlDecoderAdvice.ReadField.class).on(method(fields, "getFieldValue", Object.class, String.class)),
                Advice.to(XmlDecoderAdvice.WriteField.class)
                        .on(method(fields, "setFieldValue", Object.class, String.class, Object.class))));
        advice.put(internal(METHOD_UTIL), Advice.to(XmlDecoderAdvice.Invoke.class)
                .on(method(methodUtil, "invoke", Method.class, Object.class, Object[].class)));
        advice.put(internal(FINDER), Advice.to(XmlDecoderAdvice.Construct.class)
                .on(method(finder, "findConstructor", Class.class, Class[].class)));

        // The classes belong to the JDK, so GuardCheck must be visible to the
        // bootstrap loader for the injected calls to resolve. It rides as a
        // nested jar that holds it and RefusedException alone, so appending it
        // does not also put the agent's own classes on the bootstrap loader.
        if (!appended) appendGuardCheck(instrumentation);
        // The helper must run from the bootstrap loader before a hook can call it.
        Class.forName(CHECK, true, null);
        Class.forName(REFUSED, true, null);
        GuardCheck.setPlatformLoader(platformLoader());

        // The checks stay inert until every target has been transformed: a
        // thread that decodes meanwhile meets the hooks that are in already,
        // and they let everything pass.
        Hooks hooks = new Hooks(advice);
        Set<String> transformed = ConcurrentHashMap.newKeySet();
        hooks.attempt = transformed;
        instrumentation.addTransformer(hooks, true);
        try {
            instrumentation.retransformClasses(targets);
        } catch (Throwable t) {
            // The JVM applies a batch whole or not at all.
            instrumentation.removeTransformer(hooks);
            throw t;
        } finally {
            hooks.attempt = null;
        }
        if (transformed.size() != targets.length) {
            IllegalStateException failure = new IllegalStateException("not every target was transformed");
            instrumentation.removeTransformer(hooks);
            try {
                instrumentation.retransformClasses(targets);
            } catch (Throwable restore) {
                failure.addSuppressed(restore);
            }
            throw failure;
        }
        installed = true;
        GuardCheck.setActive(true);
        say("XMLDecoder guard installed on " + HANDLER + ", " + FIELDS + ", " + METHOD_UTIL + " and " + FINDER);
    }

    /**
     * Gives each target the advice for it. It stays registered, so that a class
     * that another agent retransforms gets the advice again from its original bytes.
     */
    private static final class Hooks implements ClassFileTransformer {
        private final Map<String, AsmVisitorWrapper> advice;
        // The targets that this attempt to install has transformed.
        volatile Set<String> attempt;

        Hooks(Map<String, AsmVisitorWrapper> advice) {
            this.advice = advice;
        }

        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> redefining,
                                ProtectionDomain domain, byte[] bytes) {
            if (loader != null || !advice.containsKey(className)) return null;
            try {
                String name = className.replace('/', '.');
                ClassFileLocator locator = new ClassFileLocator.Compound(
                        ClassFileLocator.Simple.of(name, bytes), ClassFileLocator.ForClassLoader.ofBootLoader());
                TypePool pool = TypePool.Default.of(locator);
                TypeDescription type = pool.describe(name).resolve();
                byte[] result = new ByteBuddy().redefine(type, locator).visit(advice.get(className))
                        .make(pool).getBytes();
                if (!WOVEN.get(className).equals(calls(result))) throw new IllegalStateException("advice not woven");
                Set<String> transformed = attempt;
                if (transformed != null) transformed.add(className);
                return result;
            } catch (Throwable t) {
                // The JVM would drop the exception and keep the class as it is.
                say("XMLDecoder guard: cannot transform " + className + ": " + t
                        + "; the guard may be off for that class: restart the JVM");
                return null;
            }
        }
    }

    private static Class<?> load(String className) {
        try {
            return Class.forName(className, false, null);
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException(className + " is not in this JVM");
        }
    }

    // The calls to GuardCheck in the methods of a class, as "method:call".
    private static Set<String> calls(byte[] bytes) {
        Set<String> calls = new HashSet<>();
        String check = internal(CHECK);
        OpenedClassReader.of(bytes).accept(new ClassVisitor(OpenedClassReader.ASM_API) {
            @Override
            public MethodVisitor visitMethod(int access, String method, String descriptor, String signature,
                                             String[] exceptions) {
                return new MethodVisitor(OpenedClassReader.ASM_API) {
                    @Override
                    public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
                        if (owner.equals(check)) calls.add(method + ":" + name);
                    }
                };
            }
        }, 0);
        return calls;
    }

    // The platform loader on release 9 and later, found by reflection since this
    // class is built for release 8. Only release 8 has none: there it is the
    // extension loader, the top of the chain above the system class loader.
    private static ClassLoader platformLoader() throws ReflectiveOperationException {
        ClassLoader loader;
        try {
            loader = (ClassLoader) ClassLoader.class.getMethod("getPlatformClassLoader").invoke(null);
        } catch (NoSuchMethodException e) {
            loader = ClassLoader.getSystemClassLoader();
            while (loader != null && loader.getParent() != null) loader = loader.getParent();
        }
        if (loader == null) throw new IllegalStateException("the platform class loader is not known");
        return loader;
    }

    private static String internal(String className) {
        return className.replace('.', '/');
    }

    // Advice that matches no method does nothing, so look for the method first.
    private static ElementMatcher.Junction<MethodDescription> method(Class<?> type, String name,
            Class<?>... parameters) throws NoSuchMethodException {
        type.getDeclaredMethod(name, parameters);
        return ElementMatchers.named(name).and(ElementMatchers.takesArguments(parameters));
    }

    private static void appendGuardCheck(Instrumentation instrumentation) throws IOException {
        Path jar = Files.createTempFile("shirudo-xmldecoder-guard-check", ".jar");
        JarFile file;
        try {
            try (InputStream in = XmlDecoderGuardAgent.class.getResourceAsStream(
                    "/com/shirudo/xmldecoderguard/guard-check.jar");
                 OutputStream out = Files.newOutputStream(jar)) {
                if (in == null) throw new IllegalStateException("guard-check.jar missing from the agent jar");
                byte[] buffer = new byte[8192];
                for (int n = in.read(buffer); n >= 0; n = in.read(buffer)) out.write(buffer, 0, n);
            }
            file = new JarFile(jar.toFile());
            instrumentation.appendToBootstrapClassLoaderSearch(file);
        } catch (Throwable t) {
            Files.deleteIfExists(jar);
            throw t;
        }
        appended = true;
        // The JVM opens the jar by its name, so the Java handle can go. What
        // fails from here on leaves the jar where it is.
        try {
            file.close();
            jar.toFile().deleteOnExit();
        } catch (Throwable t) {
            say("XMLDecoder guard: cannot tidy up " + jar + ": " + t);
        }
    }
}
