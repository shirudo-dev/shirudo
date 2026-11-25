# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Package build targets. Run with make -C packaging <target>.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
MAKEFLAGS += -rR --no-print-directory

ifeq ($(V),1)
  Q =
else
  Q = @
endif
export Q V

root-path = $(if $(filter /%,$(1)),$(1),$(ROOT)/$(1))
include $(ROOT)/Makefile.version
.DEFAULT_GOAL := help

prefix      ?= /usr/local
exec_prefix ?= $(prefix)
bindir      ?= $(exec_prefix)/bin
libexecdir  ?= $(exec_prefix)/libexec
sharedir    ?= $(prefix)/share
libdir      ?= $(exec_prefix)/lib
mandir      ?= $(sharedir)/man
completionsdir ?= $(sharedir)/bash-completion/completions
systemdunitdir ?= /usr/lib/systemd/system
dracutmodulesdir ?= /usr/lib/dracut/modules.d

.PHONY: help clean config bintar-pkg bindeb-pkg binrpm-pkg

INSTALLER_TARBALL    ?= shirudo.tar.gz
INSTALLER_STAGE      ?= build/shirudo-installer
INSTALLER_ROOT       := $(INSTALLER_STAGE)/root

INSTALL_PATHS := prefix=$(prefix) exec_prefix=$(exec_prefix) \
                 bindir=$(bindir) libexecdir=$(libexecdir) \
                 sharedir=$(sharedir) libdir=$(libdir) mandir=$(mandir) \
                 completionsdir=$(completionsdir) \
                 systemdunitdir=$(systemdunitdir) \
                 dracutmodulesdir=$(dracutmodulesdir)

STATIC_IMAGE_TARBALL ?= shirudo-static.tar.gz
STATIC_IMAGE_STAGE   ?= build/shirudo-static-image
STATIC_IMAGE_ROOT    := $(STATIC_IMAGE_STAGE)/root

# Distribution packaging (make -C packaging bindeb-pkg, make -C packaging binrpm-pkg). Distro
# packages live under /usr, not /usr/local, and that prefix is baked into
# the binary (it is how the core `shirudo` finds shirudo-build), so both
# rebuild with this prefix.
PKG_PREFIX      ?= /usr
PKG_RAW_VERSION ?= $(shell cd $(ROOT) && ($(SHIRUDO_GIT_DESCRIBE) 2>/dev/null || cat $(ROOT)/VERSION))
# Which roles to package. The target package is fully static
# and portable across distributions; the operator package links the
# build host's shared libraries and belongs on the distribution it is
# built on, so PKG_ROLES=operator builds just that one there.
PKG_ROLES       ?= target operator
PKG_MAINTAINER  ?= $(shell git config user.name 2>/dev/null || echo shirudo) <$(shell git config user.email 2>/dev/null || echo shirudo@localhost)>

DEB_STAGE      ?= build/deb
DEB_RAW_VERSION ?= $(PKG_RAW_VERSION)
DEB_VERSION    ?= $(shell printf '%s' "$(DEB_RAW_VERSION)" | sed 's/^v//; s/[^A-Za-z0-9.+:~-]/./g; /^[0-9]/!s/^/0~/')
DEB_ARCH       ?= $(shell dpkg --print-architecture 2>/dev/null || echo amd64)
DEB_TARGET_PKG   ?= shirudo-target_$(DEB_VERSION)_$(DEB_ARCH).deb
DEB_OPERATOR_PKG ?= shirudo-operator_$(DEB_VERSION)_$(DEB_ARCH).deb

# An RPM Version may not contain '-', so the describe output is split at
# the first dash: a plain tag is Release 1; commits past the tag
# ("-<n>-g<hash>", "-dirty") become Release 1.<n>.g<hash>, sorting after
# the tag; a pre-release tag suffix ("-rc1") becomes Release 0.rc1,
# sorting before the final 1. A describe without any tag is version
# 0.<hash>.
RPM_STAGE       ?= build/rpm
RPM_RAW_VERSION ?= $(PKG_RAW_VERSION)
RPM_VERSION     ?= $(shell printf '%s\n' "$(RPM_RAW_VERSION)" | sed 's/^v//; s/-.*//; s/[^A-Za-z0-9.+~^]/./g; /^[0-9]/!s/^/0./')
RPM_RELEASE     ?= $(shell printf '%s\n' "$(RPM_RAW_VERSION)" | sed 's/^v//; s/^[^-]*//; s/^-//; s/[^A-Za-z0-9.+~^]/./g' | sed -e 's/^$$/1/;t' -e 's/^[0-9]/1.&/;t' -e 's/^dirty/1.&/;t' -e 's/^/0./')
RPM_ARCH        ?= $(shell rpm --eval '%{_arch}' 2>/dev/null || uname -m)
RPM_TARGET_PKG   ?= shirudo-target-$(RPM_VERSION)-$(RPM_RELEASE).$(RPM_ARCH).rpm
RPM_OPERATOR_PKG ?= shirudo-operator-$(RPM_VERSION)-$(RPM_RELEASE).$(RPM_ARCH).rpm

# The outer make exports bindir/libexecdir/... derived from the default
# prefix, and a sub-make's `?=` will not recompute an already-set (env)
# value -- so we must hand the whole path set to the packaging sub-makes
# as command-line overrides (which beat the environment and propagate).
INSTALLER_TARBALL_PATH := $(call root-path,$(INSTALLER_TARBALL))
INSTALLER_STAGE_PATH := $(call root-path,$(INSTALLER_STAGE))
INSTALLER_ROOT_PATH := $(INSTALLER_STAGE_PATH)/root
STATIC_IMAGE_TARBALL_PATH := $(call root-path,$(STATIC_IMAGE_TARBALL))
STATIC_IMAGE_STAGE_PATH := $(call root-path,$(STATIC_IMAGE_STAGE))
STATIC_IMAGE_ROOT_PATH := $(STATIC_IMAGE_STAGE_PATH)/root
DEB_STAGE_PATH := $(call root-path,$(DEB_STAGE))
DEB_TARGET_PKG_PATH := $(call root-path,$(DEB_TARGET_PKG))
DEB_OPERATOR_PKG_PATH := $(call root-path,$(DEB_OPERATOR_PKG))
RPM_STAGE_PATH := $(call root-path,$(RPM_STAGE))
RPM_TARGET_PKG_PATH := $(call root-path,$(RPM_TARGET_PKG))
RPM_OPERATOR_PKG_PATH := $(call root-path,$(RPM_OPERATOR_PKG))

# Debian's clang-23, which the operator package depends on, installs clang
# under /usr/lib/llvm-23 and leaves /usr/bin/clang to the distribution's
# default release, so the helper of that package runs it from there.
DEB_CLANG := SHIRUDO_CLANG_PATH=/usr/lib/llvm-23/bin/clang

PKG_PATHS := prefix=$(PKG_PREFIX) exec_prefix=$(PKG_PREFIX) \
             bindir=$(PKG_PREFIX)/bin libexecdir=$(PKG_PREFIX)/libexec \
             sharedir=$(PKG_PREFIX)/share libdir=$(PKG_PREFIX)/lib \
             mandir=$(PKG_PREFIX)/share/man \
             completionsdir=$(PKG_PREFIX)/share/bash-completion/completions \
             systemdunitdir=/usr/lib/systemd/system

# Build two target-installer tarballs (kernel-style `bin*-pkg`). Both target
# binaries are fully static PIE, including their C and compiler runtimes.
# Each tarball contains a staged install-target tree under root/ plus an
# install.sh wrapper. Keep both archive names for existing consumers.
bintar-pkg: config $(ROOT)/packaging/tar/install.sh
	@printf '  STAGE   $(INSTALLER_STAGE_PATH)  (static PIE)\n'
	$(Q)rm -rf $(INSTALLER_STAGE_PATH) $(INSTALLER_TARBALL_PATH)
	$(Q)rm -f $(ROOT)/shirudo $(ROOT)/shirudo-target $(ROOT)/shirudo-runtime
	$(Q)install -d $(INSTALLER_STAGE_PATH) $(dir $(INSTALLER_TARBALL_PATH))
	+$(Q)$(MAKE) -C $(ROOT) target-deps
	+$(Q)$(MAKE) -C $(ROOT) target-config
	+$(Q)$(MAKE) -C $(ROOT) -f Makefile.shirudo PROFILE=target CONFIG_MK=config-target.mk \
	    $(INSTALL_PATHS) \
	    LDFLAGS='$(LDFLAGS)' \
	    DESTDIR=$(INSTALLER_ROOT_PATH) \
	    install-target
	$(Q)install -m 0755 $(ROOT)/packaging/tar/install.sh $(INSTALLER_STAGE_PATH)/install.sh
	$(Q)install -m 0644 $(ROOT)/LICENSE $(ROOT)/README.md $(ROOT)/VERSION $(INSTALLER_STAGE_PATH)/
	@printf '  TAR     $(INSTALLER_TARBALL_PATH)\n'
	$(Q)tar -C $(dir $(INSTALLER_STAGE_PATH)) -czf $(INSTALLER_TARBALL_PATH) \
	    $(notdir $(INSTALLER_STAGE_PATH))
	@printf '  STAGE   $(STATIC_IMAGE_STAGE_PATH)  (static PIE)\n'
	$(Q)rm -rf $(STATIC_IMAGE_STAGE_PATH) $(STATIC_IMAGE_TARBALL_PATH)
	$(Q)install -d $(STATIC_IMAGE_STAGE_PATH) $(dir $(STATIC_IMAGE_TARBALL_PATH))
	$(Q)cp -a $(INSTALLER_ROOT_PATH) $(STATIC_IMAGE_ROOT_PATH)
	$(Q)install -m 0755 $(ROOT)/packaging/tar/install.sh \
	    $(STATIC_IMAGE_STAGE_PATH)/install.sh
	$(Q)install -m 0644 $(ROOT)/LICENSE $(ROOT)/README.md $(ROOT)/VERSION $(STATIC_IMAGE_STAGE_PATH)/
	@printf '  TAR     $(STATIC_IMAGE_TARBALL_PATH)\n'
	$(Q)tar -C $(dir $(STATIC_IMAGE_STAGE_PATH)) -czf $(STATIC_IMAGE_TARBALL_PATH) \
	    $(notdir $(STATIC_IMAGE_STAGE_PATH))
	@printf 'shirudo: wrote $(INSTALLER_TARBALL_PATH) and $(STATIC_IMAGE_TARBALL_PATH)\n'

# Build two .deb packages (run with `make -C packaging bindeb-pkg`):
#   shirudo-target_<version>_<arch>.deb
#       shirudo + the systemd reboot, map-export, and keepalive units
#       (target node)
#   shirudo-operator_<version>_<arch>.deb
#       shirudo + shirudo-build + shirudo-quote-check + BPF headers,
#       no unit
# Rebuilds from clean with prefix=$(PKG_PREFIX) because the libexec path is
# compiled into the binary and make cannot see the changed -D otherwise.
bindeb-pkg:
	$(Q)command -v dpkg-deb >/dev/null 2>&1 || { \
	    printf 'shirudo: dpkg-deb not found; install the dpkg-dev package\n' >&2; \
	    exit 1; }
	@printf '  CLEAN   (rebuild with prefix=$(PKG_PREFIX) for packaging)\n'
	+$(Q)$(MAKE) -C $(ROOT) clean
	+$(Q)$(MAKE) -C $(ROOT) $(PKG_PATHS) $(DEB_CLANG) all $(if $(filter operator,$(PKG_ROLES)),shirudo-build)
	$(Q)rm -rf $(DEB_STAGE_PATH) \
	    $(if $(filter target,$(PKG_ROLES)),$(DEB_TARGET_PKG_PATH)) \
	    $(if $(filter operator,$(PKG_ROLES)),$(DEB_OPERATOR_PKG_PATH))
	$(if $(filter target,$(PKG_ROLES)),@printf '  STAGE   $(DEB_STAGE_PATH)/target\n')
	$(if $(filter target,$(PKG_ROLES)),+$(Q)$(MAKE) -C $(ROOT) $(PKG_PATHS) DESTDIR=$(DEB_STAGE_PATH)/target install-target)
	$(if $(filter operator,$(PKG_ROLES)),@printf '  STAGE   $(DEB_STAGE_PATH)/operator\n')
	$(if $(filter operator,$(PKG_ROLES)),+$(Q)$(MAKE) -C $(ROOT) $(PKG_PATHS) $(DEB_CLANG) DESTDIR=$(DEB_STAGE_PATH)/operator install-operator)
	$(if $(filter target,$(PKG_ROLES)),$(Q)$(ROOT)/packaging/deb/builddeb.sh target $(DEB_STAGE_PATH)/target \
	    '$(DEB_VERSION)' '$(DEB_ARCH)' '$(PKG_MAINTAINER)' $(DEB_TARGET_PKG_PATH))
	$(if $(filter operator,$(PKG_ROLES)),$(Q)$(ROOT)/packaging/deb/builddeb.sh operator $(DEB_STAGE_PATH)/operator \
	    '$(DEB_VERSION)' '$(DEB_ARCH)' '$(PKG_MAINTAINER)' $(DEB_OPERATOR_PKG_PATH))
	@printf 'shirudo: wrote %s\n' "$(strip $(if $(filter target,$(PKG_ROLES)),$(DEB_TARGET_PKG_PATH)) $(if $(filter operator,$(PKG_ROLES)),$(DEB_OPERATOR_PKG_PATH)))"

# Build the same two packages as binary RPMs. The staged trees are identical
# to the deb ones; only the
# metadata and scriptlets differ. Library dependencies are rpm's
# automatic soname requires, so the output installs on any RPM
# distribution shipping those libraries.
binrpm-pkg:
	$(Q)command -v rpmbuild >/dev/null 2>&1 || { \
	    printf 'shirudo: rpmbuild not found; install rpm (Debian/Ubuntu) or rpm-build (Fedora)\n' >&2; \
	    exit 1; }
	@printf '  CLEAN   (rebuild with prefix=$(PKG_PREFIX) for packaging)\n'
	+$(Q)$(MAKE) -C $(ROOT) clean
	+$(Q)$(MAKE) -C $(ROOT) $(PKG_PATHS) all $(if $(filter operator,$(PKG_ROLES)),shirudo-build)
	$(Q)rm -rf $(RPM_STAGE_PATH) \
	    $(if $(filter target,$(PKG_ROLES)),$(RPM_TARGET_PKG_PATH)) \
	    $(if $(filter operator,$(PKG_ROLES)),$(RPM_OPERATOR_PKG_PATH))
	$(if $(filter target,$(PKG_ROLES)),@printf '  STAGE   $(RPM_STAGE_PATH)/target\n')
	$(if $(filter target,$(PKG_ROLES)),+$(Q)$(MAKE) -C $(ROOT) $(PKG_PATHS) DESTDIR=$(RPM_STAGE_PATH)/target install-target)
	$(if $(filter operator,$(PKG_ROLES)),@printf '  STAGE   $(RPM_STAGE_PATH)/operator\n')
	$(if $(filter operator,$(PKG_ROLES)),+$(Q)$(MAKE) -C $(ROOT) $(PKG_PATHS) DESTDIR=$(RPM_STAGE_PATH)/operator install-operator)
	$(if $(filter target,$(PKG_ROLES)),$(Q)$(ROOT)/packaging/rpm/buildrpm.sh target $(RPM_STAGE_PATH)/target \
	    '$(RPM_VERSION)' '$(RPM_RELEASE)' '$(RPM_ARCH)' '$(PKG_MAINTAINER)' $(RPM_TARGET_PKG_PATH))
	$(if $(filter operator,$(PKG_ROLES)),$(Q)$(ROOT)/packaging/rpm/buildrpm.sh operator $(RPM_STAGE_PATH)/operator \
	    '$(RPM_VERSION)' '$(RPM_RELEASE)' '$(RPM_ARCH)' '$(PKG_MAINTAINER)' $(RPM_OPERATOR_PKG_PATH))
	@printf 'shirudo: wrote %s\n' "$(strip $(if $(filter target,$(PKG_ROLES)),$(RPM_TARGET_PKG_PATH)) $(if $(filter operator,$(PKG_ROLES)),$(RPM_OPERATOR_PKG_PATH)))"

config:
	+$(Q)$(MAKE) -C $(ROOT) config

help:
	@printf '%s\n' \
	  'Package targets:' \
	  '  make -C packaging bintar-pkg' \
	  '  make -C packaging bindeb-pkg [PKG_ROLES=target|operator]' \
	  '  make -C packaging binrpm-pkg [PKG_ROLES=target|operator]' \
	  '  make -C packaging clean'

clean:
	$(Q)rm -rf "$(INSTALLER_STAGE_PATH)" "$(STATIC_IMAGE_STAGE_PATH)" \
		"$(DEB_STAGE_PATH)" "$(DEB_TARGET_PKG_PATH)" "$(DEB_OPERATOR_PKG_PATH)" \
		"$(RPM_STAGE_PATH)" "$(RPM_TARGET_PKG_PATH)" "$(RPM_OPERATOR_PKG_PATH)" \
		"$(INSTALLER_TARBALL_PATH)" "$(STATIC_IMAGE_TARBALL_PATH)"
