// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Starts the shell commands the java-exec guard refuses, as code that pastes
// a request parameter into "sh -c" would, through Runtime.exec(String),
// Runtime.exec(String[]), ProcessBuilder.start and startPipeline, and the
// commands it lets through, and says who answered: exit status 0 when the
// guard refused every injected shape and passed the others, 1 otherwise. The
// refused commands only echo, so a JVM without the guard runs them and
// nothing else happens.

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

public class ExecShell {
    private static final String GUARD = "java-exec guard refused a shell command that ";

    private interface Start {
        Process run() throws IOException;
    }

    /** True when the guard refused the start, false when it let it through. */
    private static boolean refused(String what, Start start) throws InterruptedException {
        try {
            Process process = start.run();
            process.waitFor();
            System.out.println("execShell: " + what + ": started");
        } catch (IOException e) {
            if (e.getMessage() != null && e.getMessage().startsWith(GUARD)) {
                System.out.println("execShell: " + what + ": refused by the guard");
                return true;
            }
            // No such program: the guard let the start through.
            System.out.println("execShell: " + what + ": not refused: " + e.getMessage());
        }
        return false;
    }

    private static Start builder(String... command) {
        return () -> new ProcessBuilder(command).start();
    }

    public static void main(String[] args) throws Exception {
        Runtime runtime = Runtime.getRuntime();
        boolean ok = true;
        // Runtime.exec(String) splits at white space, so the injected
        // command string is a single word.
        ok &= refused("exec(String) sh -c with ;", () -> runtime.exec("sh -c echo;true"));
        ok &= refused("exec(String[]) sh -c with ;",
                () -> runtime.exec(new String[] { "sh", "-c", "echo ok; true" }));
        ok &= refused("start /bin/bash -lc with $(", builder("/bin/bash", "-lc", "echo $(id)"));
        ok &= refused("start dash -c with a backquote", builder("dash", "-c", "echo `id`"));
        ok &= refused("start sh -c with |", builder("sh", "-c", "echo a | tr a b"));
        ok &= refused("start sh -e -c with &&", builder("sh", "-e", "-c", "echo a && echo b"));
        ok &= refused("start sh -c with &", builder("sh", "-c", "echo a 2>&1 & echo b"));
        ok &= refused("start sh -c with a newline", builder("sh", "-c", "echo a\necho b"));
        ok &= refused("startPipeline sh -c with ;", () -> ProcessBuilder.startPipeline(
                Collections.singletonList(new ProcessBuilder("sh", "-c", "echo a; echo b"))).get(0));

        ok &= !refused("sh -c without a metacharacter", builder("sh", "-c", "echo ok"));
        ok &= !refused("sh -c with a redirection", builder("sh", "-c", "echo ok 2>&1 >/dev/null"));
        ok &= !refused("echo without a shell", builder("echo", "ok; true"));
        ok &= !refused("sh with a script file", builder("sh", "script;name.sh"));
        ok &= !refused("sh -c with data as a positional parameter",
                builder("sh", "-c", "echo \"$1\"", "sh", "a; b"));
        ok &= !refused("sh -o with a value before -c",
                builder("bash", "-o", "pipefail", "-c", "echo ok"));
        ok &= !refused("a program named like a shell's argument", builder("shx", "-c", "a; b"));
        System.out.println(ok ? "execShell: refused by the guard" : "execShell: no guard");
        System.exit(ok ? 0 : 1);
    }
}
