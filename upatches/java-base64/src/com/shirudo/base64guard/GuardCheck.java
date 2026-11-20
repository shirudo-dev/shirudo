// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
package com.shirudo.base64guard;

/** Loaded by the bootstrap loader so java.base can call it from decode0. */
public final class GuardCheck {
    private GuardCheck() {}

    public static void check(byte[] src, int sp, int sl, boolean isURL, boolean isMIME) {
        int length = sl - sp;
        if (isMIME || length < 65) return;
        int remainder = length & 63;
        if (remainder < 1 || remainder > 3) return;
        int padding = 0;
        while (padding < 3 && src[sl - 1 - padding] == '=') padding++;
        if (padding < 1 || padding > 2 || padding > remainder) return;
        for (int i = sp; i < sl - padding; i++) {
            int c = src[i] & 0xff;
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || (isURL ? c == '-' || c == '_' : c == '+' || c == '/'))) return;
        }
        System.err.println("Base64 guard rejected candidate: length=" + length
                + ", padding=" + padding + ", remainder=" + remainder
                + ", alphabet=" + (isURL ? "URL-safe" : "standard"));
        throw new IllegalArgumentException("Rejected Base64 x64 tail-underflow candidate");
    }
}
