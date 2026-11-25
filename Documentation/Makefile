# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Documentation: Sphinx in a container, or on the host with DOCS_CONTAINER=0.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
DOCS := $(ROOT)/Documentation
MAKEFLAGS += -rR --no-print-directory

ifeq ($(V),1)
  Q =
else
  Q = @
endif
export Q V

.DEFAULT_GOAL := help

DOCS_OUT ?= $(DOCS)/output
DOCS_PORT ?= 8000
DOCS_BIND ?= 127.0.0.1
DOCS_CONTAINER ?= 1
CONTAINER ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null)
SPHINXBUILD ?= sphinx-build
SPHINXOPTS ?= -W --keep-going -n -q

OUT := $(abspath $(DOCS_OUT))
IMAGE := shirudo-docs:$(shell cat $(DOCS)/Containerfile $(DOCS)/requirements.txt | \
	sha256sum | cut -c1-16)

# The build writes the output as the invoking user. Rootless podman maps
# that user to root in the container and --user to a subordinate uid
# that cannot write the output, so it keeps the user's id instead.
RUN_AS_USER = $(if $(filter true,$(if $(findstring podman,$(notdir $(CONTAINER))),$(shell $(CONTAINER) info --format '{{.Host.Security.Rootless}}' 2>/dev/null))),--userns=keep-id,--user "$$(id -u):$$(id -g)")

# The build sees the tree read-only and no network; the server sees only
# the rendered pages, read-only, as nobody, published on DOCS_BIND alone.
RUN_BUILD = $(CONTAINER) run --rm --network=none --read-only --tmpfs /tmp \
	$(RUN_AS_USER) -e DOCS_LASTCHANGE=/out/lastchange.txt \
	-v "$(ROOT):/src:ro" -v "$(OUT):/out" $(IMAGE)
RUN_SERVE = $(CONTAINER) run --rm --read-only --cap-drop=ALL \
	--security-opt=no-new-privileges --user 65534:65534 \
	-p "$(DOCS_BIND):$(DOCS_PORT):8000" -v "$(OUT)/html:/srv:ro" $(IMAGE)

.PHONY: help container-check image lastchange html html-docs serve check \
	linkcheck figures clean

help:
	@printf '%s\n' \
	  'make -C Documentation html       render the HTML into $(DOCS_OUT)/html' \
	  'make -C Documentation serve      render, serve on $(DOCS_BIND):$(DOCS_PORT), watch with fswatch or inotifywait' \
	  'make -C Documentation check      render, then check the docs against the code' \
	  'make -C Documentation linkcheck  check external links (needs the network)' \
	  'make -C Documentation figures    draw the SVGs of images/ from figures/ (needs TeX)' \
	  'DOCS_CONTAINER=0 renders with the host sphinx-build from requirements.txt.'

container-check:
	$(Q)[ -n "$(CONTAINER)" ] || { \
	    printf 'shirudo: no podman or docker; use DOCS_CONTAINER=0 with %s\n' \
		'the packages in Documentation/requirements.txt' >&2; \
	    exit 1; }

# Built from a context holding only what the Containerfile copies, and
# tagged by the hash of both files so a change rebuilds it.
image: container-check
	$(Q)$(CONTAINER) image inspect $(IMAGE) >/dev/null 2>&1 || { \
	    ctx="$(OUT)/.image" && rm -rf "$$ctx" && mkdir -p "$$ctx" && \
	    cp $(DOCS)/Containerfile $(DOCS)/requirements.txt "$$ctx" && \
	    printf '  IMAGE   %s\n' '$(IMAGE)' && \
	    $(CONTAINER) build -q -t $(IMAGE) -f "$$ctx/Containerfile" "$$ctx" \
		>/dev/null && rm -rf "$$ctx"; }

# The commit that last changed each document and when, in UTC, for the
# page footers.
lastchange:
	$(Q)mkdir -p "$(OUT)"
	$(Q)if git -C $(ROOT) rev-parse --git-dir >/dev/null 2>&1; then \
	    TZ=UTC git -C $(ROOT) log --date=format-local:'%Y-%m-%d %H:%M' \
		--format='@%h%x09%cd' --name-only -- Documentation | \
	    awk '/^@/ { c = substr($$0, 2); next } \
		NF && !($$0 in s) { s[$$0] = c; print $$0 "\t" c }' \
		>"$(OUT)/lastchange.txt"; \
	else \
	    : >"$(OUT)/lastchange.txt"; \
	fi

# The plain-text pages under _text/ are what llms.txt points to, for
# readers that are agents.
ifeq ($(DOCS_CONTAINER),1)
html: image lastchange
	$(Q)printf '  HTML    %s\n' '$(DOCS_OUT)/html'
	$(Q)$(RUN_BUILD) sphinx-build $(SPHINXOPTS) -b html -d /out/doctrees \
		/src/Documentation /out/html
	$(Q)$(RUN_BUILD) sphinx-build $(SPHINXOPTS) -b text -d /out/doctrees \
		/src/Documentation /out/html/_text
else
html: lastchange
	$(Q)printf '  HTML    %s\n' '$(DOCS_OUT)/html'
	$(Q)DOCS_LASTCHANGE="$(OUT)/lastchange.txt" $(SPHINXBUILD) $(SPHINXOPTS) \
		-b html -d "$(OUT)/doctrees" $(DOCS) "$(OUT)/html"
	$(Q)$(SPHINXBUILD) $(SPHINXOPTS) -b text -d "$(OUT)/doctrees" $(DOCS) \
		"$(OUT)/html/_text"
endif

html-docs: html

serve: html
	@printf 'shirudo: serving http://%s:%s/ (Ctrl-C stops it)\n' \
		'$(DOCS_BIND)' '$(DOCS_PORT)'
	+$(Q)bash "$(DOCS)/serve.sh" "$(MAKE)" "$(OUT)" $(RUN_SERVE) \
		python3 -m http.server --directory /srv --bind 0.0.0.0 8000

check: html
	$(Q)$(ROOT)/.github/scripts/check-docs.sh

linkcheck: image
	$(Q)$(CONTAINER) run --rm --read-only --tmpfs /tmp $(RUN_AS_USER) \
		-v "$(ROOT):/src:ro" -v "$(OUT):/out" $(IMAGE) \
		sphinx-build -q -b linkcheck -d /out/doctrees /src/Documentation \
		/out/linkcheck

# On the host, as the container has no TeX: LaTeX with TikZ and the IBM
# Plex fonts, and dvisvgm. Only figures whose source changed are drawn.
figures:
	$(Q)python3 $(DOCS)/figures/build.py

clean:
	$(Q)rm -rf "$(OUT)"
