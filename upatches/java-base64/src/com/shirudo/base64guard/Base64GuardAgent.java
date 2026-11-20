// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
package com.shirudo.base64guard;

import com.sun.tools.attach.VirtualMachine;
import java.io.File;
import java.lang.classfile.ClassFile;
import java.lang.classfile.ClassModel;
import java.lang.classfile.ClassTransform;
import java.lang.classfile.CodeBuilder;
import java.lang.classfile.CodeElement;
import java.lang.classfile.CodeTransform;
import java.lang.constant.ClassDesc;
import java.lang.constant.MethodTypeDesc;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.ProtectionDomain;
import java.util.concurrent.atomic.AtomicBoolean;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.jar.JarFile;

/**
 * Prepends a guard to java.util.Base64$Decoder.decode0 that rejects the x64
 * AVX-512 tail-underflow input shape before the vulnerable stub writes out of
 * bounds. Uses only the public Class-File API (no third-party deps). Applies at
 * JVM start through -javaagent (premain) and by dynamic attach (agentmain).
 */
public final class Base64GuardAgent {
    private static final String TARGET = "java/util/Base64$Decoder";
    private static final ClassDesc DECODER = ClassDesc.of("java.util.Base64$Decoder");
    private static final ClassDesc CHECK = ClassDesc.of("com.shirudo.base64guard.GuardCheck");
    private static final CodeTransform PREPEND_GUARD = new CodeTransform() {
        @Override
        public void atStart(CodeBuilder builder) {
            builder.aload(1).iload(2).iload(3)
                    .aload(0).getfield(DECODER, "isURL", ClassDesc.ofDescriptor("Z"))
                    .aload(0).getfield(DECODER, "isMIME", ClassDesc.ofDescriptor("Z"))
                    .invokestatic(CHECK, "check", MethodTypeDesc.ofDescriptor("([BIIZZ)V"));
        }

        @Override
        public void accept(CodeBuilder builder, CodeElement element) {
            builder.with(element);
        }
    };
    private static boolean installed;

    private Base64GuardAgent() {}

    /** Dynamic-attach launcher: java -jar java-base64.jar <pid>. */
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Usage: java -jar java-base64.jar <pid>");
        VirtualMachine vm = VirtualMachine.attach(args[0]);
        try {
            vm.loadAgent(selfJarPath());
        } finally {
            vm.detach();
        }
    }

    /** -javaagent entry: applies the guard as the JVM starts. */
    public static void premain(String args, Instrumentation instrumentation) throws Exception {
        install(instrumentation);
    }

    /** Dynamic-attach entry: applies the guard to a running JVM. */
    public static void agentmain(String args, Instrumentation instrumentation) throws Exception {
        install(instrumentation);
    }

    private static synchronized void install(Instrumentation instrumentation) throws Exception {
        if (installed) return;
        // java.util.Base64$Decoder is a java.base class, so GuardCheck must be
        // visible to the bootstrap loader for the injected call to resolve.
        // It rides as a nested jar holding GuardCheck alone, so appending it
        // does not also put the agent's own classes on the bootstrap loader.
        appendGuardCheck(instrumentation);
        Class<?> decoder = Class.forName("java.util.Base64$Decoder", false, null);
        Method method = decoder.getDeclaredMethod("decode0", byte[].class, int.class, int.class, byte[].class);
        if (method.getReturnType() != int.class || !Modifier.isPrivate(method.getModifiers())
                || decoder.getDeclaredField("isURL").getType() != boolean.class
                || decoder.getDeclaredField("isMIME").getType() != boolean.class
                || !instrumentation.isRetransformClassesSupported()
                || !instrumentation.isModifiableClass(decoder)) {
            throw new IllegalStateException("Base64.Decoder does not match this guard");
        }
        AtomicBoolean transformed = new AtomicBoolean();
        ClassFileTransformer transformer = new ClassFileTransformer() {
            @Override
            public byte[] transform(ClassLoader loader, String className, Class<?> redefining,
                                    ProtectionDomain domain, byte[] bytes) {
                if (!TARGET.equals(className)) return null;
                ClassFile cf = ClassFile.of();
                ClassModel model = cf.parse(bytes);
                long matches = model.methods().stream().filter(m -> m.methodName().equalsString("decode0")
                        && m.methodType().equalsString("([BII[B)I")).count();
                if (matches != 1) throw new IllegalStateException("decode0 signature changed");
                byte[] result = cf.transformClass(model, ClassTransform.transformingMethodBodies(
                        m -> m.methodName().equalsString("decode0") && m.methodType().equalsString("([BII[B)I"),
                        PREPEND_GUARD));
                transformed.set(true);
                return result;
            }
        };
        instrumentation.addTransformer(transformer, true);
        try {
            instrumentation.retransformClasses(decoder);
            if (!transformed.get()) throw new IllegalStateException("decode0 was not transformed");
            installed = true;
            System.err.println("Base64 guard installed on java.util.Base64$Decoder.decode0");
        } finally {
            instrumentation.removeTransformer(transformer);
        }
    }

    private static void appendGuardCheck(Instrumentation instrumentation) throws Exception {
        Path jar = Files.createTempFile("shirudo-base64-guard-check", ".jar");
        jar.toFile().deleteOnExit();
        try (InputStream in = Base64GuardAgent.class.getResourceAsStream(
                "/com/shirudo/base64guard/guard-check.jar")) {
            if (in == null) throw new IllegalStateException("guard-check.jar missing from the agent jar");
            Files.copy(in, jar, StandardCopyOption.REPLACE_EXISTING);
        }
        instrumentation.appendToBootstrapClassLoaderSearch(new JarFile(jar.toFile()));
    }

    private static String selfJarPath() throws Exception {
        return new File(Base64GuardAgent.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI()).getAbsolutePath();
    }
}
