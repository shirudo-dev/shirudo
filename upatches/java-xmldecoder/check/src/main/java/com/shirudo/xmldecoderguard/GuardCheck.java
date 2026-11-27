// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
package com.shirudo.xmldecoderguard;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Loaded by the bootstrap loader so the JDK's bean decoder can call it.
 * While a thread decodes, a class that the JDK defines may be constructed
 * or called only when it is on a short list. Classes of the application
 * are not restricted.
 */
public final class GuardCheck {
    // The depth of the decode of each thread that decodes, and the number of
    // threads that do: a check returns at once while that is zero, without
    // reading the thread-local of a thread that never decodes.
    private static final ThreadLocal<int[]> DEPTH = new ThreadLocal<>();
    private static final AtomicInteger DECODING = new AtomicInteger();
    // Set by the agent once every hook is in, so that a half-installed guard
    // lets everything pass.
    private static volatile boolean active;
    // The platform loader on release 9 and later, the extension loader on 8,
    // which the agent finds and hands over before it turns the checks on.
    private static volatile ClassLoader platform;

    // The JDK's tool modules are defined by the application loader on
    // release 9 and later, and tools.jar, when it is on the class path, holds them on release 8.
    private static final String[] JDK_PACKAGES = {
        "jdk.", "sun.", "com.sun.tools.", "com.sun.jdi.", "com.sun.source.",
    };

    // A JDK class that may be constructed and called.
    private static final Class<?>[] FAMILIES = {
        Number.class, Enum.class, Date.class, Calendar.class, TimeZone.class,
    };
    // A collection or a map of java.util itself: elsewhere one does more than
    // hold values, as a blocking queue waits and java.beans.beancontext
    // creates an object by its name.
    private static final Class<?>[] CONTAINERS = {Collection.class, Map.class};
    private static final Set<String> EXACT = new HashSet<>(Arrays.asList(
            "java.lang.Object", "java.lang.String", "java.lang.Boolean", "java.lang.Character",
            "java.lang.StringBuilder", "java.lang.StringBuffer",
            "java.util.Locale", "java.util.UUID", "java.util.Currency", "java.util.BitSet",
            "java.util.Optional", "java.util.Collections", "java.util.Arrays", "java.util.Objects",
            "java.awt.Color", "java.awt.Point", "java.awt.Dimension", "java.awt.Rectangle",
            "java.awt.Insets"));
    private static final String[] PACKAGES = {"java.math.", "java.time.", "java.awt.geom."};
    // A JDK class that may be constructed, and none of its methods called: a
    // document names these as values.
    private static final Set<String> CONSTRUCT_ONLY = new HashSet<>(Arrays.asList(
            "java.io.File", "java.net.URI"));

    private GuardCheck() {}

    /** Names the loader of the JDK's platform classes, which the checks tell from the application's. */
    public static void setPlatformLoader(ClassLoader loader) {
        platform = loader;
    }

    /** Turns the checks on, once every hook is in, or off. */
    public static void setActive(boolean on) {
        active = on;
    }

    /** Marks the calling thread as inside a decode. */
    public static void enter() {
        int[] depth = DEPTH.get();
        if (depth == null) {
            depth = new int[1];
            DEPTH.set(depth);
        }
        if (depth[0]++ == 0) DECODING.incrementAndGet();
    }

    /** Marks the calling thread as out of the decode that it entered last. */
    public static void exit() {
        int[] depth = DEPTH.get();
        if (depth != null && --depth[0] == 0) {
            DEPTH.remove();
            DECODING.decrementAndGet();
        }
    }

    /** Refuses a call of method on target while the thread decodes. */
    public static void invoke(Method method, Object target) {
        if (!decoding()) return;
        Class<?> declaring = method.getDeclaringClass();
        String name = method.getName();
        Class<?> type = target instanceof Class ? (Class<?>) target : target == null ? null : target.getClass();
        if (declaring == Class.class) {
            // newInstance is how the decoder runs a constructor without
            // arguments. XMLEncoder writes a public field, of a Point for
            // one, as Class.getField(name) and Field.set(object, value).
            if (name.equals("newInstance")) {
                if (type != null) construct(type);
                return;
            }
            if (!name.equals("getField")) throw refuse(declaring, name);
        } else if (declaring == Field.class) {
            if (!name.equals("set")) throw refuse(declaring, name);
            if (target instanceof Field) {
                Field field = (Field) target;
                if (Modifier.isStatic(field.getModifiers()) || refusedToCall(field.getDeclaringClass())) {
                    throw refuse(field.getDeclaringClass(), field.getName());
                }
            }
            return;
        } else if (refusedToCall(declaring)) {
            throw refuse(declaring, name);
        }
        if (type != null && refusedToCall(type)) throw refuse(type, name);
    }

    /**
     * Refuses a read or a write of the public field name of bean, or of the
     * class bean for a static field, while the thread decodes. The field is
     * the one the decoder resolves: it may be inherited, or static.
     */
    public static void field(Object bean, String name, boolean write) {
        if (!decoding() || bean == null) return;
        Class<?> type = bean instanceof Class ? (Class<?>) bean : bean.getClass();
        Field field;
        try {
            field = type.getField(name);
        } catch (NoSuchFieldException e) {
            return; // The decoder fails on its own account.
        } catch (SecurityException e) {
            throw refuse(type, name);
        }
        Class<?> declaring = field.getDeclaringClass();
        if (refusedToCall(type) || refusedToCall(declaring) || (write && Modifier.isStatic(field.getModifiers()))) {
            throw refuse(declaring, field.getName());
        }
    }

    /** Refuses the construction of type while the thread decodes. */
    public static void construct(Class<?> type) {
        if (!decoding()) return;
        Class<?> element = element(type);
        if (definedByJdk(element) && !listed(element) && !CONSTRUCT_ONLY.contains(element.getName())) {
            throw refuse(type, "<init>");
        }
    }

    /** Throws the refusal that exception or one of its causes is, so that the decode ends. */
    public static void rethrow(Throwable exception) {
        if (!decoding()) return;
        Throwable t = exception;
        for (int hops = 0; t != null && hops < 16; hops++, t = t.getCause()) {
            if (t instanceof RefusedException) throw (RefusedException) t;
        }
    }

    private static boolean decoding() {
        if (!active || DECODING.get() == 0) return false;
        int[] depth = DEPTH.get();
        return depth != null && depth[0] > 0;
    }

    private static boolean refusedToCall(Class<?> type) {
        Class<?> element = element(type);
        return definedByJdk(element) && !listed(element);
    }

    // For an array, the type of its elements decides.
    private static Class<?> element(Class<?> type) {
        while (type.isArray()) type = type.getComponentType();
        return type;
    }

    private static boolean definedByJdk(Class<?> type) {
        if (type.isPrimitive()) return false;
        try {
            ClassLoader loader = type.getClassLoader();
            if (loader == null || loader == platform) return true;
        } catch (SecurityException e) {
            // A class whose origin cannot be told is refused.
            return true;
        }
        String name = type.getName();
        for (String prefix : JDK_PACKAGES) {
            if (name.startsWith(prefix)) return true;
        }
        return false;
    }

    private static boolean listed(Class<?> type) {
        String name = type.getName();
        if (!name.startsWith("java.")) return false;
        if (EXACT.contains(name)) return true;
        for (String prefix : PACKAGES) {
            if (name.startsWith(prefix)) return true;
        }
        for (Class<?> family : FAMILIES) {
            if (family.isAssignableFrom(type)) return true;
        }
        if (name.lastIndexOf('.') != "java.util".length() || !name.startsWith("java.util.")) return false;
        for (Class<?> container : CONTAINERS) {
            if (container.isAssignableFrom(type)) return true;
        }
        return false;
    }

    private static RefusedException refuse(Class<?> type, String member) {
        String message = "XMLDecoder guard refused " + type.getName() + "." + member;
        System.err.println(message);
        return new RefusedException(message);
    }
}
