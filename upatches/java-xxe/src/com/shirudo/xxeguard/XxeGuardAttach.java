// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
package com.shirudo.xxeguard;

import com.sun.tools.attach.VirtualMachine;
import java.io.File;

/**
 * Dynamic-attach launcher: java -jar java-xxe.jar <pid>. Apart from the
 * agent because the attach API is in the jdk.attach module, which release
 * 8 does not have: this class is built for release 9.
 */
public final class XxeGuardAttach {
    private XxeGuardAttach() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Usage: java -jar java-xxe.jar <pid>");
        // This jar, which the target JVM opens by the same path.
        String jar = new File(XxeGuardAttach.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI()).getAbsolutePath();
        VirtualMachine vm = VirtualMachine.attach(args[0]);
        try {
            vm.loadAgent(jar);
        } finally {
            vm.detach();
        }
    }
}
