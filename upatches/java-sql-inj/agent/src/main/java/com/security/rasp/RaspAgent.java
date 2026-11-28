// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

package com.security.rasp;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.matcher.ElementMatchers;
import java.lang.instrument.Instrumentation;
import java.sql.Connection;
import java.sql.Statement;

public class RaspAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        System.out.println("[RASP Agent] Initializing SQL Injection Shield...");

        new AgentBuilder.Default()
            // Every class that implements JDBC Statement, not the interfaces.
            .type(ElementMatchers.isSubTypeOf(Statement.class)
                    .and(ElementMatchers.not(ElementMatchers.isInterface())))
            .transform((builder, typeDescription, classLoader, module, protectionDomain) ->
                builder.method(
                    // execute(), executeQuery(), executeUpdate() and
                    // addBatch() of a String.
                    ElementMatchers.nameStartsWith("execute").or(ElementMatchers.named("addBatch"))
                        .and(ElementMatchers.takesArgument(0, String.class))
                )
                .intercept(Advice.to(SqlInjectionAdvisor.class))
            )
            // The same for the SQL a connection prepares: concatenation
            // into prepareStatement() is as common an injection site.
            .type(ElementMatchers.isSubTypeOf(Connection.class)
                    .and(ElementMatchers.not(ElementMatchers.isInterface())))
            .transform((builder, typeDescription, classLoader, module, protectionDomain) ->
                builder.method(
                    ElementMatchers.namedOneOf("prepareStatement", "prepareCall")
                        .and(ElementMatchers.takesArgument(0, String.class))
                )
                .intercept(Advice.to(SqlInjectionAdvisor.class))
            )
            .installOn(inst);
    }
}
