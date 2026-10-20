# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Host, VM, and kernel test targets. Run with make -C testing <target>.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
MAKEFLAGS += -rR --no-print-directory

ifeq ($(V),1)
  Q =
else
  Q = @
endif
export Q V

root-path = $(if $(filter /%,$(1)),$(1),$(ROOT)/$(1))
# $(call test-vm-arch,NAME): the value contrib/test-vm-arch.sh gives NAME.
test-vm-arch = $(shell TEST_VM_ARCH='$(TEST_VM_ARCH)'; \
	. $(ROOT)/contrib/test-vm-arch.sh && printf '%s' "$$$(1)")

.DEFAULT_GOAL := help
.PHONY: help clean test-helpers test-op fuzz test test-installer bundle test-vm-bundle kernel \
	bpf-next vm vm-console vm-ssh vm-stop vm-clean test-tgt test-tgt-obs \
	test-vm test-vm-clean

KERNEL_PATCHES ?= $(if $(wildcard $(ROOT)/kernel/*.patch),$(ROOT)/kernel/,)
override KERNEL_PATCHES := $(if $(strip $(KERNEL_PATCHES)),$(call root-path,$(KERNEL_PATCHES)),)
PACKAGE_FORMAT ?= $(call test-vm-arch,TEST_VM_HOST_PKG_FORMAT)

TEST_VM_WORK_DIR ?= build/test-vm
override TEST_VM_WORK_DIR := $(call root-path,$(TEST_VM_WORK_DIR))
TEST_VM_BUNDLE_DIR ?= $(TEST_VM_WORK_DIR)/host-bundle-$(VM_KERNEL_TAG)$(KERNEL_COMMIT_SUFFIX)
TEST_VM_RUNTIME_CACHE_DIR ?= $(TEST_VM_WORK_DIR)/cache/runtime
override TEST_VM_RUNTIME_CACHE_DIR := $(call root-path,$(TEST_VM_RUNTIME_CACHE_DIR))
TEST_VM_MAP_EXPORT_CA ?=
override TEST_VM_MAP_EXPORT_CA := $(if $(strip $(TEST_VM_MAP_EXPORT_CA)),$(call root-path,$(TEST_VM_MAP_EXPORT_CA)),)
TEST_VM_OCI_CA ?=
override TEST_VM_OCI_CA := $(if $(strip $(TEST_VM_OCI_CA)),$(call root-path,$(TEST_VM_OCI_CA)),)
TEST_VM_BPM_TREE_CONFIG ?=
override TEST_VM_BPM_TREE_CONFIG := $(if $(strip $(TEST_VM_BPM_TREE_CONFIG)),$(call root-path,$(TEST_VM_BPM_TREE_CONFIG)),)
TEST_VM_PACKAGE_CERT ?=
override TEST_VM_PACKAGE_CERT := $(if $(strip $(TEST_VM_PACKAGE_CERT)),$(call root-path,$(TEST_VM_PACKAGE_CERT)),)
TEST_VM_BPM_OCI_INDEX_CERT ?=
override TEST_VM_BPM_OCI_INDEX_CERT := $(if $(strip $(TEST_VM_BPM_OCI_INDEX_CERT)),$(call root-path,$(TEST_VM_BPM_OCI_INDEX_CERT)),)
TEST_VM_CPUS ?= 4
TEST_VM_MEMORY ?= 4G
TEST_VM_DISK_SIZE ?= 30G
TEST_VM_UBUNTU_CODENAME ?= resolute
TEST_VM_VERBOSE ?= 0
# `make -C testing vm` keeps bpf-next as its default, but can boot a kernel
# built from an upstream release tag, Linux v7.4 or newer being what a
# target runs.
VM_KERNEL ?= $(if $(strip $(KERNEL)),$(KERNEL),bpf-next)
VM_KERNEL_VERSION := $(patsubst v%,%,$(VM_KERNEL))
VM_KERNEL_MIN := 7.4
VM_KERNEL_IS_RELEASE := $(shell printf '%s\n' '$(VM_KERNEL_VERSION)' | \
                          grep -Ec '^[0-9]+\.[0-9]+(\.[0-9]+)?$$')
VM_KERNEL_OLDEST := $(firstword $(shell printf '%s\n' '$(VM_KERNEL_MIN)' \
                                '$(VM_KERNEL_VERSION)' | sort -V))
KERNEL_COMMIT ?=
KERNEL_COMMIT_SUFFIX := $(if $(strip $(KERNEL_COMMIT)),-$(KERNEL_COMMIT),)
ifeq ($(VM_KERNEL),bpf-next)
ifneq ($(strip $(KERNEL_COMMIT)),)
  $(error KERNEL_COMMIT is supported only for release VM kernels)
endif
  VM_KERNEL_TAG := bpf-next
  VM_KERNEL_ARTIFACT_DIR := $(ROOT)/artifacts/bpf-next-kernel-debs
else ifeq ($(VM_KERNEL_IS_RELEASE),1)
ifneq ($(VM_KERNEL_OLDEST),$(VM_KERNEL_MIN))
  $(error shirudo requires Linux v$(VM_KERNEL_MIN) or newer; KERNEL '$(VM_KERNEL)' is older)
endif
  VM_KERNEL_TAG := v$(VM_KERNEL_VERSION)
  VM_KERNEL_ARTIFACT_DIR := $(ROOT)/artifacts/linux-$(VM_KERNEL_TAG)$(KERNEL_COMMIT_SUFFIX)-kernel-debs
else
  $(error unsupported VM KERNEL '$(VM_KERNEL)'; choose bpf-next or a release such as $(VM_KERNEL_MIN))
endif
override TEST_VM_BUNDLE_DIR := $(call root-path,$(TEST_VM_BUNDLE_DIR))
VM_KERNEL_IMAGE_NAME := $(call test-vm-arch,TEST_VM_ARCH_KIMAGE)
VM_KERNEL_IMAGE := $(VM_KERNEL_ARTIFACT_DIR)/$(VM_KERNEL_IMAGE_NAME)
VM_KERNEL_STAMP := $(VM_KERNEL_ARTIFACT_DIR)/$(VM_KERNEL_IMAGE_NAME).sha256sum
VM_KERNEL_DEP := $(VM_KERNEL_STAMP)

KERNEL_TAG ?= $(if $(strip $(TAG)),$(TAG),bpf-next)
KERNEL_TAG_VERSION := $(patsubst v%,%,$(KERNEL_TAG))
KERNEL_REPOSITORY ?= https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
KERNEL_SOURCE_DIR ?=
override KERNEL_SOURCE_DIR := $(if $(strip $(KERNEL_SOURCE_DIR)),$(call root-path,$(KERNEL_SOURCE_DIR)),)
KERNEL_CONFIG ?=
override KERNEL_CONFIG := $(if $(strip $(KERNEL_CONFIG)),$(call root-path,$(KERNEL_CONFIG)),)
KERNEL_BUILD_JOBS ?= $(shell nproc)
ifeq ($(KERNEL_TAG),bpf-next)
ifneq ($(filter kernel bpf-next,$(MAKECMDGOALS)),)
ifneq ($(strip $(KERNEL_COMMIT)),)
  $(error KERNEL_COMMIT is supported only for release kernel tags)
endif
endif
  KERNEL_TAG_NORMALIZED := bpf-next
  KERNEL_BUILD_ARTIFACT_DIR := $(ROOT)/artifacts/bpf-next-kernel-debs
else
  KERNEL_TAG_NORMALIZED := v$(KERNEL_TAG_VERSION)
  KERNEL_BUILD_ARTIFACT_DIR := $(ROOT)/artifacts/linux-$(KERNEL_TAG_NORMALIZED)$(KERNEL_COMMIT_SUFFIX)-kernel-debs
endif
KERNEL_BUILD_STAMP := $(KERNEL_BUILD_ARTIFACT_DIR)/$(VM_KERNEL_IMAGE_NAME).sha256sum

TEST_VM_BUNDLE_STAMP := $(TEST_VM_BUNDLE_DIR)/.stamp
TEST_VM_BUNDLE_SOURCES := $(sort $(wildcard \
	$(ROOT)/*.c $(ROOT)/*.h $(ROOT)/include/*.h $(ROOT)/util/*.c $(ROOT)/util/*.h \
	$(ROOT)/bpf/*.c $(ROOT)/bpf/lib/*.h \
	$(ROOT)/tools/shirudo-build/*.c $(ROOT)/tools/shirudo-build/*.h \
	$(ROOT)/vendor/libbpf/bpf/*.c $(ROOT)/vendor/libbpf/bpf/*.h \
	$(ROOT)/vendor/libbpf/include/linux/*.h \
	$(ROOT)/vendor/libbpf/include/uapi/linux/*.h \
	$(ROOT)/vendor/libbpf/include/asm/*.h \
	$(ROOT)/testing/helper/*.c $(ROOT)/testing/helper/*.py \
	$(ROOT)/testing/upatch/kernel-obs/exec/*.c $(ROOT)/completion/* $(ROOT)/systemd/*.in \
	$(ROOT)/systemd/*.timer $(ROOT)/testing/fixtures/*.c $(ROOT)/testing/fixtures/*.lua \
	$(ROOT)/testing/fixtures/decoders/* \
	$(ROOT)/upatches/kernel-obs/*.c $(ROOT)/upatches/kernel-obs/*.h $(ROOT)/upatches/kernel-obs/*.list \
		$(ROOT)/upatches/kernel-obs/*.py $(ROOT)/upatches/kernel-obs/Beefile \
	$(ROOT)/upatches/kernel-obs/decoders/*))
# The kernel build replaces versioned package files; depend on its stable stamp.
TEST_VM_BUNDLE_ARTIFACTS := $(VM_KERNEL_STAMP)
TEST_VM_BUNDLE_INPUTS := $(sort \
	$(ROOT)/Makefile $(ROOT)/Makefile.config $(ROOT)/Makefile.shirudo $(ROOT)/Makefile.version $(ROOT)/config.mk \
	$(ROOT)/Makefile.target-deps \
	$(ROOT)/testing/Makefile $(ROOT)/packaging/Makefile \
	$(ROOT)/vendor/libbpf/Makefile $(ROOT)/vendor/libbpf/COMMIT \
	$(ROOT)/Documentation/Makefile $(ROOT)/upatches/kernel-obs/Makefile \
	$(ROOT)/contrib/build-test-vm-bundle.sh $(ROOT)/contrib/test-vm-guest.sh \
	$(ROOT)/contrib/test-vm-arch.sh \
	$(ROOT)/contrib/prepare-test-vm-runtime.sh $(ROOT)/contrib/test-vm-runtime-packages \
	$(TEST_VM_BUNDLE_SOURCES) $(TEST_VM_BUNDLE_ARTIFACTS) \
	$(if $(strip $(TEST_VM_PACKAGE_CERT)),$(TEST_VM_PACKAGE_CERT)))

$(ROOT)/config.mk: $(ROOT)/Makefile.config
	+$(Q)$(MAKE) -C $(ROOT) config

test-vm-bundle: $(VM_KERNEL_DEP) $(TEST_VM_BUNDLE_STAMP)

$(TEST_VM_BUNDLE_STAMP): $(TEST_VM_BUNDLE_INPUTS)
	$(Q)TEST_VM_HOST_BUNDLE="$(abspath $(TEST_VM_BUNDLE_DIR))" \
		TEST_VM_WORK_DIR="$(abspath $(TEST_VM_WORK_DIR))" \
		TEST_VM_RUNTIME_CACHE_DIR="$(abspath $(TEST_VM_RUNTIME_CACHE_DIR))" \
		TEST_VM_UBUNTU_CODENAME="$(TEST_VM_UBUNTU_CODENAME)" \
		TEST_VM_ROOTFS_URL="$(TEST_VM_ROOTFS_URL)" \
		TEST_VM_ROOTFS_SHA256="$(TEST_VM_ROOTFS_SHA256)" \
		TEST_VM_PACKAGE_CERT="$(TEST_VM_PACKAGE_CERT)" \
		TEST_VM_BUNDLE_STAMP="$(abspath $(TEST_VM_BUNDLE_STAMP))" \
		TEST_VM_BUNDLE_INPUTS="$(abspath $(TEST_VM_BUNDLE_INPUTS))" \
		BPF_VMLINUX_BTF="$(abspath $(VM_KERNEL_ARTIFACT_DIR)/vmlinux.btf)" \
		$(ROOT)/contrib/build-test-vm-bundle.sh

kernel: $(KERNEL_BUILD_STAMP)

bpf-next:
	$(Q)PACKAGE_FORMAT='$(PACKAGE_FORMAT)' \
		KERNEL_PATCHES='$(KERNEL_PATCHES)' \
		KERNEL_CONFIG='$(KERNEL_CONFIG)' \
		KERNEL_BUILD_JOBS='$(KERNEL_BUILD_JOBS)' \
		$(ROOT)/contrib/build-kernel-package.sh

$(KERNEL_BUILD_STAMP): $(ROOT)/contrib/build-kernel-package.sh
	$(Q)KERNEL_TAG='$(KERNEL_TAG_NORMALIZED)' \
		KERNEL_COMMIT='$(KERNEL_COMMIT)' \
		KERNEL_PATCHES='$(KERNEL_PATCHES)' \
		KERNEL_REPOSITORY='$(KERNEL_REPOSITORY)' \
		KERNEL_SOURCE_DIR='$(KERNEL_SOURCE_DIR)' \
		KERNEL_CONFIG='$(KERNEL_CONFIG)' \
		PACKAGE_FORMAT='$(PACKAGE_FORMAT)' \
		KERNEL_BUILD_JOBS='$(KERNEL_BUILD_JOBS)' \
		OUTPUT_DIR="$(abspath $(KERNEL_BUILD_ARTIFACT_DIR))" \
		$(ROOT)/contrib/build-kernel-package.sh

# A VM selection owns its kernel artifact independently of the generic
# KERNEL_TAG selection used by `make -C testing kernel`.
ifneq ($(VM_KERNEL_DEP),)
ifneq ($(VM_KERNEL_TAG),$(KERNEL_TAG_NORMALIZED))
$(VM_KERNEL_STAMP):
	+$(Q)$(MAKE) -C $(ROOT) -f testing/Makefile kernel KERNEL_TAG='$(VM_KERNEL_TAG)' KERNEL_COMMIT='$(KERNEL_COMMIT)' KERNEL_CONFIG='$(KERNEL_CONFIG)'
endif
endif

vm: $(VM_KERNEL_DEP) test-vm-bundle
	$(Q)VM_MODE=interactive VM_NAME="$(VM_NAME)" VM_TENANT="$(VM_TENANT)" \
		TEST_VM_KERNEL="$(abspath $(VM_KERNEL_IMAGE))" \
		TEST_VM_KERNEL_ARTIFACT_DIR="$(abspath $(VM_KERNEL_ARTIFACT_DIR))" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" \
		TEST_VM_RUNTIME_CACHE_DIR="$(TEST_VM_RUNTIME_CACHE_DIR)" \
		TEST_VM_CPUS="$(TEST_VM_CPUS)" \
		TEST_VM_MEMORY="$(TEST_VM_MEMORY)" \
		TEST_VM_DISK_SIZE="$(TEST_VM_DISK_SIZE)" \
		TEST_VM_SSH_PORT="$(TEST_VM_SSH_PORT)" \
		TEST_VM_MAP_EXPORT_ENDPOINT="$(TEST_VM_MAP_EXPORT_ENDPOINT)" \
		TEST_VM_MAP_EXPORT_TENANT_ID="$(TEST_VM_MAP_EXPORT_TENANT_ID)" \
		TEST_VM_MAP_EXPORT_INSECURE="$(TEST_VM_MAP_EXPORT_INSECURE)" \
		TEST_VM_MAP_EXPORT_CA="$(TEST_VM_MAP_EXPORT_CA)" \
		TEST_VM_OCI_CA="$(TEST_VM_OCI_CA)" \
		TEST_VM_BPM_TREE_CONFIG="$(TEST_VM_BPM_TREE_CONFIG)" \
		TEST_VM_PACKAGE_CERT="$(TEST_VM_PACKAGE_CERT)" \
		TEST_VM_BPM_OCI_REPOSITORY="$(TEST_VM_BPM_OCI_REPOSITORY)" \
		TEST_VM_BPM_OCI_INDEX_CERT="$(TEST_VM_BPM_OCI_INDEX_CERT)" \
		TEST_VM_HOST_BUNDLE="$(abspath $(TEST_VM_BUNDLE_DIR))" \
		$(ROOT)/contrib/test-vm.sh
vm-console:
	$(Q)VM_NAME="$(VM_NAME)" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" $(ROOT)/contrib/test-vm.sh --console

vm-ssh:
	$(Q)VM_NAME="$(VM_NAME)" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" $(ROOT)/contrib/test-vm.sh --ssh

test-tgt: $(VM_KERNEL_DEP) test-vm-bundle
	$(Q)VM_MODE=test TEST_VM_SUITE="$(TEST_VM_SUITE)" VM_VERBOSE="$(TEST_VM_VERBOSE)" VM_NAME="$(VM_NAME)" VM_TENANT="$(VM_TENANT)" \
		TEST_VM_KERNEL="$(abspath $(VM_KERNEL_IMAGE))" \
		TEST_VM_KERNEL_ARTIFACT_DIR="$(abspath $(VM_KERNEL_ARTIFACT_DIR))" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" \
		TEST_VM_RUNTIME_CACHE_DIR="$(TEST_VM_RUNTIME_CACHE_DIR)" \
		TEST_VM_MAP_EXPORT_ENDPOINT="$(TEST_VM_MAP_EXPORT_ENDPOINT)" \
		TEST_VM_MAP_EXPORT_TENANT_ID="$(TEST_VM_MAP_EXPORT_TENANT_ID)" \
		TEST_VM_MAP_EXPORT_INSECURE="$(TEST_VM_MAP_EXPORT_INSECURE)" \
		TEST_VM_MAP_EXPORT_CA="$(TEST_VM_MAP_EXPORT_CA)" \
		TEST_VM_OCI_CA="$(TEST_VM_OCI_CA)" \
		TEST_VM_BPM_OCI_REPOSITORY="$(TEST_VM_BPM_OCI_REPOSITORY)" \
		TEST_VM_BPM_OCI_INDEX_CERT="$(TEST_VM_BPM_OCI_INDEX_CERT)" \
		TEST_VM_HOST_BUNDLE="$(abspath $(TEST_VM_BUNDLE_DIR))" \
		$(ROOT)/contrib/test-vm.sh

test-tgt-obs: $(VM_KERNEL_DEP) test-vm-bundle
	$(Q)VM_MODE=test TEST_VM_SUITE=obs VM_VERBOSE="$(TEST_VM_VERBOSE)" VM_NAME="$(VM_NAME)" VM_TENANT="$(VM_TENANT)" \
		TEST_VM_KERNEL="$(abspath $(VM_KERNEL_IMAGE))" \
		TEST_VM_KERNEL_ARTIFACT_DIR="$(abspath $(VM_KERNEL_ARTIFACT_DIR))" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" \
		TEST_VM_RUNTIME_CACHE_DIR="$(TEST_VM_RUNTIME_CACHE_DIR)" \
		TEST_VM_MAP_EXPORT_ENDPOINT="$(TEST_VM_MAP_EXPORT_ENDPOINT)" \
		TEST_VM_MAP_EXPORT_TENANT_ID="$(TEST_VM_MAP_EXPORT_TENANT_ID)" \
		TEST_VM_MAP_EXPORT_INSECURE="$(TEST_VM_MAP_EXPORT_INSECURE)" \
		TEST_VM_MAP_EXPORT_CA="$(TEST_VM_MAP_EXPORT_CA)" \
		TEST_VM_OCI_CA="$(TEST_VM_OCI_CA)" \
		TEST_VM_BPM_OCI_REPOSITORY="$(TEST_VM_BPM_OCI_REPOSITORY)" \
		TEST_VM_BPM_OCI_INDEX_CERT="$(TEST_VM_BPM_OCI_INDEX_CERT)" \
		TEST_VM_HOST_BUNDLE="$(abspath $(TEST_VM_BUNDLE_DIR))" \
		$(ROOT)/contrib/test-vm.sh

vm-stop:
	$(Q)VM_NAME="$(VM_NAME)" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" $(ROOT)/contrib/test-vm.sh --stop

vm-clean:
	$(Q)VM_NAME="$(VM_NAME)" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" $(ROOT)/contrib/test-vm.sh --clean

test-vm-clean: vm-clean

test-op:
	+$(Q)$(MAKE) -C $(ROOT) all
	+$(Q)$(MAKE) -C $(ROOT) shirudo-build
	+$(Q)$(MAKE) -C $(ROOT) -f testing/Makefile test-helpers
	+$(Q)$(MAKE) -C $(ROOT) -f Makefile.shirudo check

test-helpers:
	+$(Q)$(MAKE) -C $(ROOT) config
	+$(Q)$(MAKE) -C $(ROOT) -f Makefile.shirudo test-helpers

# The parsers of input from outside the host under libFuzzer, each target
# for FUZZ_SECONDS on its seed corpus; needs clang with its fuzzer runtime.
FUZZ_SECONDS ?= 60

fuzz:
	+$(Q)$(MAKE) -C $(ROOT) config
	+$(Q)$(MAKE) -C $(ROOT) -f Makefile.shirudo fuzz-targets
	$(Q)sh $(ROOT)/testing/fuzz/run.sh $(FUZZ_SECONDS)

# The installer end to end: a stock cloud image in QEMU with a vTPM, the
# bpf-next kernel packages, tools/gen-initrd/install.sh with a local
# target package, two reboots and the production configuration.
test-installer:
	$(Q)cd $(ROOT) && bash testing/t1300-installer-e2e.sh

bundle: test-vm-bundle

test-vm: test-tgt

test:
	+$(Q)$(MAKE) -C $(ROOT) -f testing/Makefile bundle
	+$(Q)$(MAKE) -C $(ROOT) -f testing/Makefile test-op
	+$(Q)$(MAKE) -C $(ROOT) -f testing/Makefile test-tgt

help:
	@printf '%s\n' \
	  'Testing targets:' \
	  '  make -C testing test' \
	  '  make -C testing test-op' \
	  '  make -C testing test-helpers' \
	  '  make -C testing fuzz [FUZZ_SECONDS=60]' \
	  '  make -C testing test-tgt [TEST_VM_INITRD=1]' \
	  '  make -C testing test-tgt-obs' \
	  '  make -C testing test-installer' \
	  '  make -C testing vm, vm-console, vm-ssh, vm-stop, or vm-clean' \
	  '  make -C testing vm KERNEL=7.4' \
	  '  make -C testing kernel KERNEL_TAG=v7.4' \
	  '  make -C testing bpf-next or test-vm-bundle' \
	  '  make -C testing clean'

clean:
	+$(Q)set -eu; \
		bundle_dir="$(abspath $(TEST_VM_BUNDLE_DIR))"; \
		mkdir -p "$$(dirname "$$bundle_dir")"; \
		exec 9>"$$bundle_dir.lock"; \
		flock 9; \
		rm -rf "$$bundle_dir"
