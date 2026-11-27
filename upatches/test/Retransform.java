// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// An agent that has the JVM retransform the class its argument names and
// changes nothing, as a second agent in a JVM does while it applies a
// change of its own. A guard has to be in the class afterwards as before:
//   java -javaagent:<guard>.jar -javaagent:retransform.jar=<class> ...

import java.lang.instrument.Instrumentation;

public class Retransform {
    public static void premain(String className, Instrumentation instrumentation) throws Exception {
        instrumentation.retransformClasses(
                Class.forName(className, false, Retransform.class.getClassLoader()));
        System.err.println("retransform: retransformed " + className);
    }
}
