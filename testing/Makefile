# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Test, VM and kernel targets. make -C testing runs every test, make -C
# testing <tier>[/<name>] one tier or part of it; make -C testing help
# lists the rest.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
MAKEFLAGS += -rR --no-print-directory

ifeq ($(V),1)
  Q =
else
  Q = @
endif
export Q V
export TEST_FILTER

# make tests at the top exports the install paths, and dracut takes the
# prefix it finds in the environment for the initrd a test VM boots.
unexport prefix exec_prefix bindir libexecdir sharedir libdir mandir \
	completionsdir systemdunitdir dracutmodulesdir

root-path = $(if $(filter /%,$(1)),$(1),$(ROOT)/$(1))
# $(call test-vm-arch,NAME): the value testing/vm/arch.sh gives NAME.
test-vm-arch = $(shell TEST_VM_ARCH='$(TEST_VM_ARCH)'; \
	. $(ROOT)/testing/vm/arch.sh && printf '%s' "$$$(1)")

.DEFAULT_GOAL := all
.PHONY: all help clean unit ci-checks functional end2end build-operator build-unit \
	test-helpers \
	fuzz bundle test-vm-bundle kernel bpf-next vm vm-console vm-ssh vm-stop vm-clean \
	vm-operator-end2end

KERNEL_PATCHES ?= $(if $(wildcard $(ROOT)/kernel/*.patch),$(ROOT)/kernel/,)
override KERNEL_PATCHES := $(if $(strip $(KERNEL_PATCHES)),$(call root-path,$(KERNEL_PATCHES)),)
KERNEL_PATCH_FILES := $(foreach patch,$(KERNEL_PATCHES),$(if $(wildcard $(patch)/*.patch),$(wildcard $(patch)/*.patch),$(wildcard $(patch))))
PACKAGE_FORMAT ?= $(call test-vm-arch,TEST_VM_HOST_PKG_FORMAT)

TEST_VM_MODE ?= verity
ifneq ($(TEST_VM_MODE),verity)
  $(error TEST_VM_MODE must be verity)
endif
TEST_VM_INITRD ?= 1
TEST_VM_WORK_DIR ?= build/test-vm
override TEST_VM_WORK_DIR := $(call root-path,$(TEST_VM_WORK_DIR))
TEST_VM_HOST_PRIVATE_DIR ?= /tmp/shirudo-test-vm-private-$(shell id -u)
override TEST_VM_HOST_PRIVATE_DIR := $(call root-path,$(TEST_VM_HOST_PRIVATE_DIR))
TEST_VM_BUNDLE_DIR ?= $(TEST_VM_WORK_DIR)/host-bundle-$(VM_KERNEL_TAG)$(KERNEL_COMMIT_SUFFIX)-$(TEST_VM_MODE)
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
TEST_VM_BPM_OCI_REPOSITORY ?=
TEST_VM_BPM_OCI_INDEX_REPOSITORY ?=
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
	$(ROOT)/*.c $(ROOT)/*.h $(ROOT)/include/shirudo/*.h \
	$(ROOT)/util/*.c $(ROOT)/util/*.h \
	$(ROOT)/bpf/*.c $(ROOT)/bpf/lib/*.h \
	$(ROOT)/tools/shirudo-build/*.c $(ROOT)/tools/shirudo-build/*.h \
	$(ROOT)/vendor/libbpf/bpf/*.c $(ROOT)/vendor/libbpf/bpf/*.h \
	$(ROOT)/vendor/libbpf/include/linux/*.h \
	$(ROOT)/vendor/libbpf/include/uapi/linux/*.h \
	$(ROOT)/vendor/libbpf/include/asm/*.h \
	$(ROOT)/testing/helper/*.c $(ROOT)/testing/helper/*.h $(ROOT)/testing/helper/*.py \
	$(ROOT)/testing/vm/bundle-images.sh $(ROOT)/testing/vm/image-fixtures.sh \
	$(ROOT)/tools/gen-image/shirudo-gen-* $(ROOT)/tools/gen-image/*.sh \
	$(ROOT)/tools/gen-image/*.in \
	$(ROOT)/testing/vm/files/* \
	$(ROOT)/testing/end2end/*.c $(ROOT)/completion/* $(ROOT)/systemd/*.in \
	$(ROOT)/systemd/*.timer $(ROOT)/testing/fixtures/*.c $(ROOT)/testing/fixtures/*.lua \
	$(ROOT)/testing/fixtures/*.conf $(ROOT)/testing/fixtures/*.sh \
	$(ROOT)/testing/fixtures/*.h \
	$(ROOT)/testing/fixtures/policy-labels/* \
	$(ROOT)/testing/fixtures/policy-exec-graph/* \
	$(ROOT)/testing/fixtures/segments/*/* \
	$(ROOT)/testing/fixtures/decoders/* \
	$(ROOT)/upatches/kernel-obs/*.c $(ROOT)/upatches/kernel-obs/*.h $(ROOT)/upatches/kernel-obs/*.list \
		$(ROOT)/upatches/kernel-obs/*.py $(ROOT)/upatches/kernel-obs/Beefile \
	$(ROOT)/upatches/kernel-obs/decoders/*))
# The host's util/version_id.c is no input: every build of the host's
# writes it, and the bundle's build writes its own.
TEST_VM_BUNDLE_SOURCES := $(filter-out $(ROOT)/util/version_id.c,$(TEST_VM_BUNDLE_SOURCES))
# The kernel build replaces versioned package files; depend on its stable stamp.
TEST_VM_BUNDLE_ARTIFACTS := $(VM_KERNEL_STAMP)
# The bundle builds in the build container unless BUILD_CONTAINER=0, so it
# depends on the image's inputs rather than on the host's configuration.
BUILD_CONTAINER ?= 1
TEST_VM_BUILD_ENV := $(if $(filter 0,$(BUILD_CONTAINER)),$(ROOT)/config.mk, \
	$(ROOT)/testing/container/Containerfile $(ROOT)/testing/container/packages \
	$(ROOT)/testing/container/run.sh $(ROOT)/.github/scripts/install-clang.sh \
	$(ROOT)/.github/scripts/install-static-libcrypto-deps.sh \
	$(ROOT)/testing/vm/list-source.sh)
TEST_VM_BUNDLE_INPUTS := $(sort \
	$(ROOT)/Makefile $(ROOT)/Makefile.config $(ROOT)/Makefile.shirudo $(ROOT)/Makefile.version \
	$(TEST_VM_BUILD_ENV) \
	$(ROOT)/Makefile.target-deps \
	$(ROOT)/testing/Makefile $(ROOT)/packaging/Makefile \
	$(ROOT)/vendor/libbpf/Makefile $(ROOT)/vendor/libbpf/COMMIT \
	$(ROOT)/Documentation/Makefile $(ROOT)/upatches/kernel-obs/Makefile \
	$(ROOT)/testing/vm/build-bundle.sh $(ROOT)/testing/vm/build-bundle-payload.sh \
	$(ROOT)/testing/vm/guest.sh \
	$(ROOT)/testing/vm/arch.sh \
	$(ROOT)/testing/vm/prepare-runtime.sh $(ROOT)/testing/vm/runtime-packages \
	$(TEST_VM_BUNDLE_SOURCES) $(TEST_VM_BUNDLE_ARTIFACTS) \
	$(if $(strip $(TEST_VM_PACKAGE_CERT)),$(TEST_VM_PACKAGE_CERT)))

$(ROOT)/config.mk: $(ROOT)/Makefile.config
	+$(Q)$(MAKE) -C $(ROOT) config

test-vm-bundle: $(VM_KERNEL_DEP) $(TEST_VM_BUNDLE_STAMP)

$(TEST_VM_BUNDLE_STAMP): $(TEST_VM_BUNDLE_INPUTS)
	$(Q)mkdir -p $(dir $(BUILD_LOCK))
	$(Q)TEST_VM_MODE="$(TEST_VM_MODE)" TEST_VM_INITRD="$(TEST_VM_INITRD)" \
		BUILD_CONTAINER="$(BUILD_CONTAINER)" \
		TEST_VM_HOST_BUNDLE="$(abspath $(TEST_VM_BUNDLE_DIR))" \
		TEST_VM_WORK_DIR="$(abspath $(TEST_VM_WORK_DIR))" \
		TEST_VM_HOST_PRIVATE_DIR="$(abspath $(TEST_VM_HOST_PRIVATE_DIR))" \
		TEST_VM_RUNTIME_CACHE_DIR="$(abspath $(TEST_VM_RUNTIME_CACHE_DIR))" \
		TEST_VM_UBUNTU_CODENAME="$(TEST_VM_UBUNTU_CODENAME)" \
		TEST_VM_ROOTFS_URL="$(TEST_VM_ROOTFS_URL)" \
		TEST_VM_ROOTFS_SHA256="$(TEST_VM_ROOTFS_SHA256)" \
		TEST_VM_PACKAGE_CERT="$(TEST_VM_PACKAGE_CERT)" \
		TEST_VM_BUNDLE_STAMP="$(abspath $(TEST_VM_BUNDLE_STAMP))" \
		TEST_VM_BUNDLE_INPUTS="$(abspath $(TEST_VM_BUNDLE_INPUTS))" \
		BPF_VMLINUX_BTF="$(abspath $(VM_KERNEL_ARTIFACT_DIR)/vmlinux.btf)" \
		flock $(BUILD_LOCK) $(ROOT)/testing/vm/build-bundle.sh

kernel: $(KERNEL_BUILD_STAMP)

bpf-next:
	$(Q)PACKAGE_FORMAT='$(PACKAGE_FORMAT)' \
		KERNEL_PATCHES='$(KERNEL_PATCHES)' \
		KERNEL_CONFIG='$(KERNEL_CONFIG)' \
		KERNEL_BUILD_JOBS='$(KERNEL_BUILD_JOBS)' \
		$(ROOT)/testing/vm/build-kernel.sh

$(KERNEL_BUILD_STAMP): $(ROOT)/testing/vm/build-kernel.sh $(KERNEL_PATCH_FILES)
	$(Q)KERNEL_TAG='$(KERNEL_TAG_NORMALIZED)' \
		KERNEL_COMMIT='$(KERNEL_COMMIT)' \
		KERNEL_PATCHES='$(KERNEL_PATCHES)' \
		KERNEL_REPOSITORY='$(KERNEL_REPOSITORY)' \
		KERNEL_SOURCE_DIR='$(KERNEL_SOURCE_DIR)' \
		KERNEL_CONFIG='$(KERNEL_CONFIG)' \
		PACKAGE_FORMAT='$(PACKAGE_FORMAT)' \
		KERNEL_BUILD_JOBS='$(KERNEL_BUILD_JOBS)' \
		OUTPUT_DIR="$(abspath $(KERNEL_BUILD_ARTIFACT_DIR))" \
		$(ROOT)/testing/vm/build-kernel.sh

# A VM selection owns its kernel artifact independently of the generic
# KERNEL_TAG selection used by `make -C testing kernel`.
ifneq ($(VM_KERNEL_DEP),)
ifneq ($(VM_KERNEL_TAG),$(KERNEL_TAG_NORMALIZED))
$(VM_KERNEL_STAMP):
	+$(Q)$(MAKE) -C $(ROOT) -f testing/Makefile kernel KERNEL_TAG='$(VM_KERNEL_TAG)' KERNEL_COMMIT='$(KERNEL_COMMIT)' KERNEL_CONFIG='$(KERNEL_CONFIG)'
endif
endif

LOCAL_STACK ?= 1

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
		TEST_VM_BPM_OCI_INDEX_REPOSITORY="$(TEST_VM_BPM_OCI_INDEX_REPOSITORY)" \
		TEST_VM_BPM_OCI_INDEX_CERT="$(TEST_VM_BPM_OCI_INDEX_CERT)" \
		TEST_VM_MODE="$(TEST_VM_MODE)" TEST_VM_INITRD="$(TEST_VM_INITRD)" \
		TEST_VM_HOST_BUNDLE="$(abspath $(TEST_VM_BUNDLE_DIR))" \
		$(if $(filter 0,$(LOCAL_STACK)),,$(ROOT)/testing/vm/stack.sh vm) $(ROOT)/testing/vm/run.sh
vm-console:
	$(Q)VM_NAME="$(VM_NAME)" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" $(ROOT)/testing/vm/run.sh --console

vm-ssh:
	$(Q)VM_NAME="$(VM_NAME)" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" $(ROOT)/testing/vm/run.sh --ssh

define run-target-vm
VM_MODE=$(or $(4),$(if $(filter $(1),$(VM_SERVE_SUITES)),serve,test)) \
		TEST_VM_SUITE="$(1)" VM_VERBOSE="$(TEST_VM_VERBOSE)" VM_NAME="$(2)" VM_TENANT="$(VM_TENANT)" \
		TEST_VM_INITRD="$(3)" \
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
		TEST_VM_BPM_OCI_INDEX_REPOSITORY="$(TEST_VM_BPM_OCI_INDEX_REPOSITORY)" \
		TEST_VM_BPM_OCI_INDEX_CERT="$(TEST_VM_BPM_OCI_INDEX_CERT)" \
		TEST_VM_MODE="$(TEST_VM_MODE)" \
		TEST_VM_HOST_BUNDLE="$(abspath $(TEST_VM_BUNDLE_DIR))" \
		$(ROOT)/testing/vm/run.sh
endef

# The tiers: the unit tests, the tests of the scripts CI runs, the families
# of functional tests in number order, and the end-to-end tests. A test with
# a target number (t?1??) runs in a VM its family boots from the bundle, so
# no test finds what another family left behind; tpm boots a second VM
# before init, without the initrd, for the TPM register tests. VM=0 leaves
# out every test that boots a VM.
VM ?= 1
UNIT_SUITES := $(sort $(basename $(notdir $(filter-out %/unit.c, \
	$(wildcard $(ROOT)/testing/unit/*.c)))))
family-list = $(shell cd $(ROOT)/testing/functional && \
	ls */t[0-9]$(1)[0-9][0-9]-*.sh | \
	awk -F/ '{ print substr($$2, 2, 1), $$1 }' | sort -u | cut -d' ' -f2)
FAMILIES := $(call family-list,[0-9])
VM_SUITES := $(call family-list,1) end2end
# The host runs the end-to-end VM's target tests over SSH, where it can act
# between them; the families' VMs run theirs themselves.
VM_SERVE_SUITES := end2end
vm-tests = $(if $(filter 0,$(VM)),:,$(MAKE) $(addprefix vm-test-,$(1)))
.PHONY: $(addprefix unit/,$(UNIT_SUITES)) $(addprefix functional/,$(FAMILIES)) \
	$(addprefix vm-test-,register $(VM_SUITES)) vm-node-end2end

all:
	+$(Q)$(MAKE) unit
	+$(Q)$(MAKE) ci-checks
	+$(Q)$(MAKE) functional
	+$(Q)$(MAKE) end2end

unit: build-unit
	$(Q)$(ROOT)/testing/run-tests.sh unit

$(addprefix unit/,$(UNIT_SUITES)): unit/%: build-unit
	$(Q)$(ROOT)/testing/run-tests.sh unit/$*

# The tests of the scripts under .github/scripts, which need no build.
ci-checks:
	$(Q)$(ROOT)/testing/run-tests.sh ci-checks

functional: build-operator
	$(Q)$(ROOT)/testing/run-tests.sh functional
	+$(Q)$(call vm-tests,$(filter-out end2end,$(VM_SUITES)))

$(addprefix functional/,$(FAMILIES)): functional/%: build-operator
	$(Q)$(ROOT)/testing/run-tests.sh functional/$*
	+$(Q)$(call vm-tests,$(filter $*,$(VM_SUITES)))

# The end-to-end test boots the operator VM, which builds the operator
# package and alone gets the signing key on its own disk; while it serves,
# host.sh has it publish kernel-obs, runs node A and has it verify what
# node A attests. The host's own build plays the operator for the keepalive
# backend and for the tests host.sh runs against the other nodes. The goals
# host.sh boots the VMs with build nothing: all VMs boot this bundle, and a
# rebuild between them, for an input changed meanwhile, would replace the
# key the operator signs with and the targets trust.
end2end: build-operator
	$(Q)$(ROOT)/testing/run-tests.sh end2end
	+$(Q)$(if $(filter 0,$(VM)),:,$(MAKE) test-vm-bundle && \
		TEST_VM_HOST_BUNDLE="$(abspath $(TEST_VM_BUNDLE_DIR))" \
		TEST_VM_HOST_PRIVATE_DIR="$(abspath $(TEST_VM_HOST_PRIVATE_DIR))" \
		MAKE="$(MAKE)" $(ROOT)/testing/end2end/host.sh)

vm-operator-end2end:
	$(Q)VM_MODE=serve TEST_VM_ROLE=operator TEST_VM_INITRD=0 \
		VM_VERBOSE="$(TEST_VM_VERBOSE)" VM_NAME="$(VM_NAME)" \
		TEST_VM_SERVE_COMMAND="$(TEST_VM_SERVE_COMMAND)" \
		TEST_VM_PRIVATE_DIR="$(TEST_VM_PRIVATE_DIR)" \
		TEST_VM_OPERATOR_KEYS="$(abspath $(TEST_VM_HOST_PRIVATE_DIR))/operator-keys/keys" \
		TEST_VM_KERNEL="$(abspath $(VM_KERNEL_IMAGE))" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" \
		TEST_VM_RUNTIME_CACHE_DIR="$(TEST_VM_RUNTIME_CACHE_DIR)" \
		TEST_VM_MODE="$(TEST_VM_MODE)" \
		TEST_VM_HOST_BUNDLE="$(abspath $(TEST_VM_BUNDLE_DIR))" \
		$(ROOT)/testing/vm/run.sh

vm-test-end2end:
	$(Q)$(call run-target-vm,end2end,$(if $(VM_NAME),$(VM_NAME)-end2end),1)

# A node of the end-to-end run that end2end/host.sh boots and stops,
# prepared like the suite's VM, but it runs no tests and stays up until it
# is stopped. END2END_NODE=b is node B, with the core role, beside the
# suite's VM; edge is a fresh node with the edge role, after it.
END2END_NODE ?= b
vm-node-end2end:
	$(Q)$(if $(filter-out b edge,$(END2END_NODE)),$(error END2END_NODE must be b or edge))
	$(Q)TEST_VM_NODE_ROLE=$(if $(filter edge,$(END2END_NODE)),edge,core) \
		$(call run-target-vm,end2end,$(if $(VM_NAME),$(VM_NAME)-end2end-$(END2END_NODE)),1,node)

vm-test-tpm: vm-test-register

$(addprefix vm-test-,register $(filter-out end2end,$(VM_SUITES))): \
		vm-test-%: $(VM_KERNEL_DEP) test-vm-bundle
	$(Q)$(call run-target-vm,$*,$(if $(VM_NAME),$(VM_NAME)-$*),$(if $(filter register,$*),0,1))

vm-stop:
	$(Q)VM_NAME="$(VM_NAME)" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" $(ROOT)/testing/vm/run.sh --stop

vm-clean:
	$(Q)VM_NAME="$(VM_NAME)" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" $(ROOT)/testing/vm/run.sh --clean

# The operator build and the bundle build compile in the same tree, one at
# a time.
BUILD_LOCK := $(ROOT)/build/.testing-build.lock

build-operator: build-unit
	+$(Q)flock $(BUILD_LOCK) $(MAKE) -C $(ROOT) shirudo-build
	+$(Q)flock $(BUILD_LOCK) $(MAKE) -C $(ROOT) quote-check
	+$(Q)flock $(BUILD_LOCK) $(MAKE) -C $(ROOT) -f Makefile.shirudo test-helpers

build-unit:
	$(Q)mkdir -p $(dir $(BUILD_LOCK))
	+$(Q)flock $(BUILD_LOCK) $(MAKE) -C $(ROOT) all
	+$(Q)flock $(BUILD_LOCK) $(MAKE) -C $(ROOT) -f Makefile.shirudo unit-tests

test-helpers:
	+$(Q)$(MAKE) -C $(ROOT) config
	+$(Q)$(MAKE) -C $(ROOT) -f Makefile.shirudo test-helpers

# The parsers of input from outside the host under libFuzzer, each target
# for FUZZ_SECONDS on its seed corpus and, with FUZZ_CORPUS=<dir>, on what
# earlier runs kept there; needs clang with its fuzzer runtime.
FUZZ_SECONDS ?= 60

fuzz:
	+$(Q)$(MAKE) -C $(ROOT) config
	+$(Q)$(MAKE) -C $(ROOT) -f Makefile.shirudo fuzz-targets
	$(Q)sh $(ROOT)/testing/fuzz/run.sh $(FUZZ_SECONDS)

bundle: test-vm-bundle

help:
	@printf '%s\n' \
	  'Testing targets (make tests at the top runs the first):' \
	  '  make -C testing                         every test' \
	  '  make -C testing unit[/<suite>]          suites: $(UNIT_SUITES)' \
	  '  make -C testing ci-checks               the scripts CI runs' \
	  '  make -C testing functional[/<family>]   families: $(FAMILIES)' \
	  '  make -C testing end2end' \
	  '  TEST_FILTER=<regex> selects test filenames (empty runs everything).' \
	  '  VM=0 leaves out the tests that boot a VM, which need root;' \
	  '  make -j boots several at once.' \
	  '  make -C testing fuzz [FUZZ_SECONDS=60] [FUZZ_CORPUS=<dir>]' \
	  '  make -C testing vm, vm-console, vm-ssh, vm-stop, or vm-clean' \
	  '  make -C testing vm KERNEL=7.4' \
	  '  make -C testing kernel KERNEL_TAG=v7.4' \
	  '  make -C testing bpf-next, bundle or test-helpers' \
	  '  make -C testing stack-up, oci, telemetry or stack-down' \
	  '  make -C testing clean'

clean:
	+$(Q)set -eu; \
		bundle_dir="$(abspath $(TEST_VM_BUNDLE_DIR))"; \
		mkdir -p "$$(dirname "$$bundle_dir")"; \
		exec 9>"$$bundle_dir.lock"; \
		flock 9; \
		rm -rf "$$bundle_dir" "$$bundle_dir.operator" \
			"$(abspath $(TEST_VM_HOST_PRIVATE_DIR))/operator-keys" \
			$(ROOT)/build/test-vm/end2end

.PHONY: oci telemetry stack-up stack-down
stack-up: oci telemetry

oci telemetry:
	$(Q)TEST_VM_HOST_PRIVATE_DIR="$(TEST_VM_HOST_PRIVATE_DIR)" $(ROOT)/testing/vm/stack.sh $@
stack-down:
	$(Q)TEST_VM_HOST_PRIVATE_DIR="$(TEST_VM_HOST_PRIVATE_DIR)" $(ROOT)/testing/vm/stack.sh down
