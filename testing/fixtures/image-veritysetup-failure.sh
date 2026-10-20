#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

case "$IMAGE_BUILD_FAILURE:$1" in
format:format|verify:verify) exit 42 ;;
publish:verify) printf sentinel >"$IMAGE_OUTPUT.roothash" ;;
esac
exec "$REAL_VERITY" "$@"
