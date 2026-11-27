// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
package com.shirudo.xmldecoderguard;

/** Thrown when a document being decoded asks for a call or a construction the guard refuses. */
public final class RefusedException extends SecurityException {
    private static final long serialVersionUID = 1L;

    RefusedException(String message) {
        super(message);
    }
}
