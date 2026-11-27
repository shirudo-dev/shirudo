// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
package com.shirudo.xmldecoderguard;

import java.lang.reflect.Method;
import net.bytebuddy.asm.Advice;

/**
 * The checks that Byte Buddy inlines into the JDK's bean decoder. Each calls
 * GuardCheck, which the bootstrap loader serves to the instrumented code.
 */
final class XmlDecoderAdvice {
    private XmlDecoderAdvice() {}

    /**
     * The entry points of DocumentHandler that evaluate a document: parse, and
     * the SAX callbacks that a handler from XMLDecoder.createHandler gets from
     * a parser of the application's own.
     */
    static final class Scope {
        @Advice.OnMethodEnter
        static void enter() {
            GuardCheck.enter();
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        static void exit() {
            GuardCheck.exit();
        }
    }

    /** MethodUtil.invoke(Method, Object, Object[]): the methods that elements call. */
    static final class Invoke {
        @Advice.OnMethodEnter
        static void enter(@Advice.Argument(0) Method method, @Advice.Argument(1) Object target) {
            GuardCheck.invoke(method, target);
        }
    }

    /** ConstructorFinder.findConstructor(Class, Class[]): the constructors that elements run. */
    static final class Construct {
        @Advice.OnMethodEnter
        static void enter(@Advice.Argument(0) Class<?> type) {
            GuardCheck.construct(type);
        }
    }

    /** FieldElementHandler.getFieldValue(Object, String): a field that an element reads. */
    static final class ReadField {
        @Advice.OnMethodEnter
        static void enter(@Advice.Argument(0) Object bean, @Advice.Argument(1) String name) {
            GuardCheck.field(bean, name, false);
        }
    }

    /** FieldElementHandler.setFieldValue(Object, String, Object): a field that an element writes. */
    static final class WriteField {
        @Advice.OnMethodEnter
        static void enter(@Advice.Argument(0) Object bean, @Advice.Argument(1) String name) {
            GuardCheck.field(bean, name, true);
        }
    }

    /** DocumentHandler.handleException(Exception): where the decoder would skip a refusal. */
    static final class HandleException {
        @Advice.OnMethodEnter
        static void enter(@Advice.Argument(0) Exception exception) {
            GuardCheck.rethrow(exception);
        }
    }
}
