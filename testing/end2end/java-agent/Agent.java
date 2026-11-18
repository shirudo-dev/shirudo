// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

package shirudo.e2e;

/*
 * The Java agent of the end-to-end test: its premain names the jar the
 * JVM loaded it from, which t9105 compares against the sealed one.
 */
public final class Agent {
	private Agent() {
	}

	public static void premain(String args) {
		System.err.println("shirudo-e2e-agent: premain from "
				   + Agent.class.getProtectionDomain()
					   .getCodeSource().getLocation().getPath());
	}
}
