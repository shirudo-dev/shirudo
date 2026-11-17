# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# The backend has nothing to build; this runs its SQL tests. Its
# documentation is Documentation/operate/integrations/backend.

.DEFAULT_GOAL := help

.PHONY: help tests

help:
	@printf '%s\n' \
	  'make tests       run the SQL tests (test/run.sh)'

tests:
	test/run.sh
