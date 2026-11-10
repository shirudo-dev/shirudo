# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# shirudo shared build Makefile.
#
# Run shared build and install targets from the repo root. Feature probes
# write config.mk; Makefile.shirudo contains the actual build graph.

EXTRAVERSION = -rc0
NAME = Social BPF Coding

export EXTRAVERSION NAME

MAKEFLAGS += -rR --no-print-directory

include Makefile.version

# Output verbosity. `make V=1` shows full command lines.
ifeq ($(V),1)
  Q =
else
  Q = @
endif
export Q V

# Install paths (override at make-invocation time for packagers).
prefix      ?= /usr/local
exec_prefix ?= $(prefix)
bindir      ?= $(exec_prefix)/bin
libexecdir  ?= $(exec_prefix)/libexec
sharedir    ?= $(prefix)/share
libdir      ?= $(exec_prefix)/lib
mandir      ?= $(sharedir)/man
completionsdir ?= $(sharedir)/bash-completion/completions
# Absolute by default (systemd does not scan /usr/local); packagers override.
systemdunitdir ?= /usr/lib/systemd/system
udevrulesdir ?= /usr/lib/udev/rules.d
dracutmodulesdir ?= /usr/lib/dracut/modules.d

# Local target dependency build defaults. make target-deps builds a static
# OpenSSL (3.5+), an OpenSSL-backed static libcurl and TPM2-TSS under
# TARGET_DEPS_DIR; these are overridable for a prebuilt dependency prefix.
TARGET_MULTIARCH ?= $(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || gcc -print-multiarch)
TARGET_DEPS_DIR ?= $(CURDIR)/build/target-deps
TARGET_DEPS_OPENSSL_PREFIX ?= $(TARGET_DEPS_DIR)/openssl
TARGET_DEPS_CURL_PREFIX ?= $(TARGET_DEPS_DIR)/curl
SHIRUDO_TARGET_STATIC_LIBDIR ?= $(TARGET_DEPS_DIR)/lib
SHIRUDO_TARGET_PKG_CONFIG_PATH ?= $(TARGET_DEPS_CURL_PREFIX)/lib/pkgconfig:$(TARGET_DEPS_OPENSSL_PREFIX)/lib/pkgconfig:$(SHIRUDO_TARGET_STATIC_LIBDIR)/pkgconfig

export prefix exec_prefix bindir libexecdir sharedir libdir mandir completionsdir \
       systemdunitdir udevrulesdir dracutmodulesdir SHIRUDO_TARGET_PKG_CONFIG_PATH \
       SHIRUDO_TARGET_STATIC_LIBDIR

.PHONY: all help target target-deps target-deps-clean shirudo-target target-config shirudo-build quote-check quote-check-deps docs bpf-deps install install-target install-operator clean distclean config tests proofs proofs-cbmc proofs-lean4 sparse tags cscope

all: config
	+$(Q)$(MAKE) -f Makefile.shirudo PROFILE=operator CONFIG_MK=config.mk all

target-deps:
ifeq ($(TARGET_DEPS_PREBUILT),1)
	@printf 'shirudo: using prebuilt target dependencies\n'
else
	+$(Q)$(MAKE) -f Makefile.target-deps \
		TARGET_DEPS_DIR="$(TARGET_DEPS_DIR)" \
		TARGET_STATIC_LIBDIR="$(SHIRUDO_TARGET_STATIC_LIBDIR)" \
		TARGET_OPENSSL_PREFIX="$(TARGET_DEPS_OPENSSL_PREFIX)" \
		TARGET_CURL_PREFIX="$(TARGET_DEPS_CURL_PREFIX)"
endif

target-deps-clean:
	+$(Q)$(MAKE) -f Makefile.target-deps \
		TARGET_DEPS_DIR="$(TARGET_DEPS_DIR)" clean

target: shirudo-target

shirudo-target:
	+$(Q)$(MAKE) target-deps
	+$(Q)$(MAKE) target-config
	+$(Q)$(MAKE) -f Makefile.shirudo PROFILE=target CONFIG_MK=config-target.mk shirudo-target

target-config:
	+$(Q)$(MAKE) -f Makefile.config -B SHIRUDO_PROFILE=target \
		CONFIG_OUT=config-target.mk \
		SHIRUDO_TARGET_PKG_CONFIG_PATH="$(SHIRUDO_TARGET_PKG_CONFIG_PATH)" \
		SHIRUDO_TARGET_STATIC_LIBDIR="$(SHIRUDO_TARGET_STATIC_LIBDIR)" config.mk

help:
	@printf '%s\n' \
	  'shirudo make targets:' \
	  '  Build: make, make target, make target-deps, make bpf-deps, make install' \
	  '  Operator tools: make shirudo-build, make quote-check' \
	  '  Local stack: make stack-up, make oci, make telemetry, make vm, make stack-down' \
	  '  Checks: make sparse' \
	  '  Source index: make tags (ctags), make cscope' \
	  '  Install roles: make install-target, make install-operator' \
	  '  Package: make -C packaging help' \
	  '  Tests: make tests (all of them), make -C testing help' \
	  '  Proofs: make proofs (CBMC and Lean 4), make proofs-cbmc [PROOFS=<proof>...], make proofs-lean4' \
	  '  Documentation: make docs (render and serve), make -C Documentation help' \
	  '  Watch lists: make -C upatches/kernel-obs lists'

shirudo-build:
	+$(Q)$(MAKE) -C tools/shirudo-build

# The helper's sub-make builds files the binary's builds too, such as
# vendor/linux/vmlinux.h, and would write one while the other's clang reads
# it. Given with all, as packaging does, the helper waits for all.
shirudo-build: | $(filter all,$(MAKECMDGOALS))

# shirudo-quote-check is a static PIE. Where the distribution ships no
# libcrypto.a, as Fedora does not, it links a static OpenSSL built once
# into QUOTE_CHECK_OPENSSL_PREFIX instead.
QUOTE_CHECK_OPENSSL_PREFIX ?= $(CURDIR)/build/quote-check-openssl
QUOTE_CHECK_SYSTEM_LIBCRYPTO_A := $(wildcard $(shell pkg-config \
	--variable=libdir libcrypto 2>/dev/null)/libcrypto.a)
QUOTE_CHECK_OPENSSL ?= $(if $(SANITIZE)$(QUOTE_CHECK_SYSTEM_LIBCRYPTO_A),, \
	$(QUOTE_CHECK_OPENSSL_PREFIX))

quote-check-deps:
ifneq ($(strip $(QUOTE_CHECK_OPENSSL)),)
	+$(Q)$(MAKE) -f Makefile.target-deps \
		TARGET_DEPS_DIR="$(CURDIR)/build/quote-check-deps" \
		TARGET_OPENSSL_PREFIX="$(strip $(QUOTE_CHECK_OPENSSL))" openssl
endif

quote-check: quote-check-deps
	+$(Q)$(MAKE) -C tools/quote-check \
		QUOTE_CHECK_OPENSSL="$(strip $(QUOTE_CHECK_OPENSSL))"

sparse: config
	+$(Q)$(MAKE) -f Makefile.shirudo PROFILE=operator CONFIG_MK=config.mk sparse

docs:
	+$(Q)$(MAKE) -C Documentation serve

tests:
	+$(Q)$(MAKE) -C testing

# The C sources of the tree, untracked ones included, and the generated
# vmlinux.h that the BPF code reads its kernel types from.
TAGS_FILES = { git ls-files --cached --others --exclude-standard -- '*.[ch]' 2>/dev/null || \
	       find . -path ./build -prune -o -name '*.[ch]' -print; } | sort -u; \
	     [ ! -f vendor/linux/vmlinux.h ] || echo vendor/linux/vmlinux.h

tags:
	@printf '  GEN     tags\n'
	$(Q)rm -f tags
	$(Q)($(TAGS_FILES)) | ctags -L - -f tags

cscope:
	@printf '  GEN     cscope\n'
	$(Q)rm -f cscope.files cscope.out cscope.in.out cscope.po.out
	$(Q)($(TAGS_FILES)) > cscope.files
	$(Q)cscope -b -q -k -i cscope.files

proofs: proofs-cbmc proofs-lean4

proofs-cbmc:
	$(Q)testing/proofs/cbmc/run.sh $(if $(CHANGED),-c '$(CHANGED)') $(PROOFS)

proofs-lean4:
	$(Q)testing/proofs/lean4/run.sh

# config.mk is regenerated by Makefile.config from the host's pkg-config
# state. Caches results until `make distclean`.
bpf-deps:
	$(Q)KERNEL_SRC="$(KERNEL_SRC)" tools/bpf-deps/bpf-deps.sh

config: config.mk

config.mk: Makefile.config
	$(Q)$(MAKE) -f Makefile.config config.mk

install: all
	+$(Q)$(MAKE) -f Makefile.shirudo install

install-target: all
	+$(Q)$(MAKE) target-deps
	+$(Q)$(MAKE) target-config
	+$(Q)$(MAKE) -f Makefile.shirudo PROFILE=target CONFIG_MK=config-target.mk install-target

install-operator: all quote-check-deps
	+$(Q)$(MAKE) -f Makefile.shirudo install-operator \
		QUOTE_CHECK_OPENSSL="$(strip $(QUOTE_CHECK_OPENSSL))"

clean:
	+$(Q)$(MAKE) -C Documentation clean
	+$(Q)$(MAKE) -C testing clean
	+$(Q)$(MAKE) -C packaging clean
	+$(Q)$(MAKE) -f Makefile.shirudo clean

distclean: clean
	$(Q)rm -f config.mk
	$(Q)rm -f tags cscope.files cscope.out cscope.in.out cscope.po.out
	+$(Q)$(MAKE) -f Makefile.target-deps TARGET_DEPS_DIR="$(TARGET_DEPS_DIR)" clean
	$(Q)rm -rf build/quote-check-deps "$(QUOTE_CHECK_OPENSSL_PREFIX)"
	$(Q)$(MAKE) -f Makefile.shirudo distclean

.PHONY: vm vm-console vm-ssh vm-stop vm-clean oci telemetry stack-up stack-down
vm vm-console vm-ssh vm-stop vm-clean oci telemetry stack-up stack-down:
	+$(Q)$(MAKE) -C testing $@
