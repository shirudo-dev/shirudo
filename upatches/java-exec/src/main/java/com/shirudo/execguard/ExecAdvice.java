// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
package com.shirudo.execguard;

import java.io.IOException;
import java.util.List;
import net.bytebuddy.asm.Advice;

/**
 * The check Byte Buddy inlines at the start of the method of
 * java.lang.ProcessBuilder that starts every process. The inlined code uses
 * java.base classes alone, so nothing has to be added to the bootstrap
 * loader for ProcessBuilder to run it; that is also why it is one method.
 */
public final class ExecAdvice {
    /** The start of the message of the IOException a refused start throws. */
    public static final String REFUSED = "java-exec guard refused a shell command that ";

    private ExecAdvice() {}

    /**
     * Throws IOException when the program is a shell given a command string
     * with -c, and that string chains or substitutes commands. Every other
     * start goes on: a program that is not a shell has no shell to inject
     * into, and the operands after the command string are the shell's
     * positional parameters, the safe way to pass it data.
     */
    @Advice.OnMethodEnter
    static void enter(@Advice.This ProcessBuilder builder) throws IOException {
        List<String> command = builder.command();
        if (command.isEmpty()) return;
        String program = command.get(0);
        if (program == null) return;
        String shell = program.substring(program.lastIndexOf('/') + 1);
        if (!(shell.equals("sh") || shell.equals("bash") || shell.equals("dash")
                || shell.equals("zsh") || shell.equals("ksh") || shell.equals("ash"))) return;
        // The options before the first operand: -c in a cluster such as -lc
        // makes that operand the command string; -o, -O, --rcfile and
        // --init-file take the next argument as their value.
        boolean commandString = false;
        String script = null;
        int i = 1;
        while (i < command.size()) {
            String arg = command.get(i);
            i++;
            if (arg == null) return;
            if (arg.equals("--")) {
                if (i < command.size()) script = command.get(i);
                break;
            }
            if (arg.startsWith("--")) {
                if (arg.equals("--rcfile") || arg.equals("--init-file")) i++;
                continue;
            }
            if ((arg.startsWith("-") || arg.startsWith("+")) && arg.length() > 1) {
                if (arg.charAt(0) == '-' && arg.indexOf('c') > 0) commandString = true;
                if (arg.indexOf('o') > 0 || arg.indexOf('O') > 0) i++;
                continue;
            }
            script = arg;
            break;
        }
        if (!commandString || script == null) return;
        String what = null;
        if (script.indexOf('`') >= 0 || script.contains("$(")) {
            what = "substitutes commands";
        } else if (script.indexOf(';') >= 0 || script.indexOf('\n') >= 0) {
            what = "chains commands";
        } else if (script.indexOf('|') >= 0) {
            what = "pipes or backgrounds commands";
        } else {
            // An & of a redirection, as in 2>&1, <&3 or &>file, starts no
            // command.
            for (int j = script.indexOf('&'); j >= 0; j = script.indexOf('&', j + 1)) {
                char before = j > 0 ? script.charAt(j - 1) : ' ';
                char after = j + 1 < script.length() ? script.charAt(j + 1) : ' ';
                if (before != '>' && before != '<' && after != '>') {
                    what = "pipes or backgrounds commands";
                    break;
                }
            }
        }
        if (what == null) return;
        // The shell is one of the names above and what one of three phrases:
        // nothing of the command, which is the attacker's text, is printed.
        System.err.println(REFUSED + what + ": " + shell + " -c");
        throw new IOException(REFUSED + what + ": " + shell + " -c");
    }
}
