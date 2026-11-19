# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# xtop is a Bun program; these targets need bun on PATH.

BUN ?= bun

all: dist/xtop

node_modules: package.json bun.lock
	$(BUN) install --frozen-lockfile
	touch $@

dist/xtop: node_modules build.ts $(shell find src sql -type f)
	$(BUN) run build.ts

tests: node_modules
	$(BUN) x tsc --noEmit
	$(BUN) test

clean:
	rm -rf dist node_modules

.PHONY: all tests clean
