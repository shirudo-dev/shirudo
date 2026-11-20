// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Decodes a Base64 input of the shape the java-base64 guard refuses, and
// says who refused it: exit status 0 when the guard did, 1 when the JVM
// runs without it.

import java.util.Base64;

public class BadDecoder {
    // 66 bytes: a tail of two past a 64-byte block, one of them padding.
    private static final String CANDIDATE = "A".repeat(64) + "A=";
    private static final String GUARD = "Rejected Base64 x64 tail-underflow candidate";

    public static void main(String[] args) {
        try {
            Base64.getDecoder().decode(CANDIDATE);
            System.out.println("badDecoder: decoded, no guard");
        } catch (IllegalArgumentException e) {
            if (GUARD.equals(e.getMessage())) {
                System.out.println("badDecoder: refused by the guard");
                return;
            }
            System.out.println("badDecoder: no guard, the JDK refused: " + e.getMessage());
        }
        System.exit(1);
    }
}
