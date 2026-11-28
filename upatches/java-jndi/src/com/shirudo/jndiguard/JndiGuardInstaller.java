// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
package com.shirudo.jndiguard;

import com.sun.tools.attach.VirtualMachine;
import java.io.File;
import java.io.InputStream;
import java.lang.classfile.ClassFile;
import java.lang.classfile.ClassModel;
import java.lang.classfile.CodeBuilder;
import java.lang.classfile.CodeElement;
import java.lang.classfile.CodeTransform;
import java.lang.classfile.MethodModel;
import java.lang.classfile.MethodTransform;
import java.lang.constant.ClassDesc;
import java.lang.constant.MethodTypeDesc;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.ProtectionDomain;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarFile;
import javax.naming.InitialContext;
import javax.naming.Name;

/**
 * Prepends a check to both javax.naming.InitialContext.getURLOrDefaultInitCtx
 * methods that refuses a name with a remote URL scheme (ldap, rmi, dns, iiop,
 * corba, nis) before a URL context is created for it. This closes the JNDI
 * injection path of CVE-2021-44228 (Log4Shell) and of the libraries that pass
 * a name from a request to InitialContext.lookup. Uses only the public
 * Class-File API (no third-party deps), so it runs on a JVM of release 24 or
 * newer; JndiGuardAgent, the entry point, calls it only on one.
 */
public final class JndiGuardInstaller {
    private static final String TARGET = "javax/naming/InitialContext";
    private static final String METHOD = "getURLOrDefaultInitCtx";
    private static final String BY_STRING = "(Ljava/lang/String;)Ljavax/naming/Context;";
    private static final String BY_NAME = "(Ljavax/naming/Name;)Ljavax/naming/Context;";
    private static final ClassDesc CHECK = ClassDesc.of("com.shirudo.jndiguard.JndiCheck");

    private static boolean installed;

    private JndiGuardInstaller() {}

    private static CodeTransform prependCheck(String descriptor) {
        String arg = descriptor.substring(1, descriptor.indexOf(')'));
        MethodTypeDesc check = MethodTypeDesc.ofDescriptor("(" + arg + ")V");
        return new CodeTransform() {
            @Override
            public void atStart(CodeBuilder builder) {
                builder.aload(1).invokestatic(CHECK, "check", check);
            }

            @Override
            public void accept(CodeBuilder builder, CodeElement element) {
                builder.with(element);
            }
        };
    }

    private static boolean guarded(MethodModel m) {
        return m.methodName().equalsString(METHOD)
                && (m.methodType().equalsString(BY_STRING) || m.methodType().equalsString(BY_NAME));
    }

    /** Dynamic-attach launcher: java -jar java-jndi.jar <pid>. */
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Usage: java -jar java-jndi.jar <pid>");
        VirtualMachine vm = VirtualMachine.attach(args[0]);
        try {
            vm.loadAgent(selfJarPath());
        } finally {
            vm.detach();
        }
    }

    /** Applies the guard; JndiGuardAgent calls it from premain and agentmain. */
    public static synchronized void install(Instrumentation instrumentation) throws Exception {
        if (installed) return;
        // InitialContext is a java.naming class of the bootstrap loader, so
        // JndiCheck must be visible to that loader for the injected call to
        // resolve. It rides as a nested jar holding JndiCheck alone, so
        // appending it does not also put the agent's own classes there.
        appendJndiCheck(instrumentation);
        Class<?> context = InitialContext.class;
        for (Class<?> arg : new Class<?>[] { String.class, Name.class }) {
            Method method = context.getDeclaredMethod(METHOD, arg);
            if (!Modifier.isProtected(method.getModifiers())
                    || method.getReturnType() != javax.naming.Context.class)
                throw new IllegalStateException("InitialContext does not match this guard");
        }
        if (!instrumentation.isRetransformClassesSupported() || !instrumentation.isModifiableClass(context))
            throw new IllegalStateException("InitialContext cannot be retransformed");
        // java.naming must read the bootstrap loader's unnamed module, where
        // JndiCheck is, for the call from InitialContext to link.
        Class<?> check = Class.forName("com.shirudo.jndiguard.JndiCheck", true, null);
        instrumentation.redefineModule(context.getModule(), Set.of(check.getModule()),
                Map.of(), Map.of(), Set.of(), Map.of());

        AtomicInteger transformed = new AtomicInteger();
        ClassFileTransformer transformer = new ClassFileTransformer() {
            @Override
            public byte[] transform(ClassLoader loader, String className, Class<?> redefining,
                                    ProtectionDomain domain, byte[] bytes) {
                if (!TARGET.equals(className)) return null;
                ClassFile cf = ClassFile.of();
                ClassModel model = cf.parse(bytes);
                long matches = model.methods().stream().filter(JndiGuardInstaller::guarded).count();
                if (matches != 2) throw new IllegalStateException(METHOD + " signatures changed");
                byte[] result = cf.transformClass(model, (builder, element) -> {
                    if (element instanceof MethodModel m && guarded(m)) {
                        CodeTransform check = prependCheck(m.methodType().stringValue());
                        builder.transformMethod(m, MethodTransform.transformingCode(check));
                    } else {
                        builder.with(element);
                    }
                });
                transformed.set((int) matches);
                return result;
            }
        };
        instrumentation.addTransformer(transformer, true);
        try {
            instrumentation.retransformClasses(context);
            if (transformed.get() != 2) throw new IllegalStateException(METHOD + " was not transformed");
            installed = true;
            System.err.println("JNDI guard installed on javax.naming.InitialContext." + METHOD);
        } finally {
            instrumentation.removeTransformer(transformer);
        }
    }

    private static void appendJndiCheck(Instrumentation instrumentation) throws Exception {
        Path jar = Files.createTempFile("shirudo-jndi-check", ".jar");
        jar.toFile().deleteOnExit();
        try (InputStream in = JndiGuardInstaller.class.getResourceAsStream(
                "/com/shirudo/jndiguard/jndi-check.jar")) {
            if (in == null) throw new IllegalStateException("jndi-check.jar missing from the agent jar");
            Files.copy(in, jar, StandardCopyOption.REPLACE_EXISTING);
        }
        instrumentation.appendToBootstrapClassLoaderSearch(new JarFile(jar.toFile()));
    }

    private static String selfJarPath() throws Exception {
        return new File(JndiGuardInstaller.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI()).getAbsolutePath();
    }
}
