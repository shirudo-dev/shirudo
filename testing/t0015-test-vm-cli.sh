#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./test-lib.sh

RUNNER=../contrib/test-vm.sh
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

test_expect_success 'test-vm rejects a missing local kernel before boot' '
	! TEST_VM_WORK_DIR="$WORK/missing" \
		TEST_VM_KERNEL="$WORK/no-bzImage" "$RUNNER" \
		>"$WORK/missing.out" 2>&1 &&
	grep -q "kernel image not found" "$WORK/missing.out"
'

test_expect_success 'test-vm requires a SHA-256 for a remote kernel' '
	! TEST_VM_WORK_DIR="$WORK/no-sha" \
		TEST_VM_KERNEL_URL=https://example.invalid/bzImage "$RUNNER" \
		>"$WORK/no-sha.out" 2>&1 &&
	grep -q "requires a 64-character TEST_VM_KERNEL_SHA256" \
		"$WORK/no-sha.out"
'

test_expect_success 'test-vm rejects conflicting kernel selectors' '
	! TEST_VM_WORK_DIR="$WORK/conflict" \
		TEST_VM_KERNEL="$WORK/bzImage" \
		TEST_VM_KERNEL_URL=https://example.invalid/bzImage \
		TEST_VM_KERNEL_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
		"$RUNNER" >"$WORK/conflict.out" 2>&1 &&
	grep -q "TEST_VM_KERNEL and TEST_VM_KERNEL_URL are mutually exclusive" \
		"$WORK/conflict.out"
'

test_expect_success 'test-vm prints an install command for missing dependencies' '
	mkdir "$WORK/fake-bin" &&
	ln -s /bin/bash "$WORK/fake-bin/bash" &&
	ln -s /usr/bin/dirname "$WORK/fake-bin/dirname" &&
	for command_name in curl sha256sum awk qemu-system-x86_64 qemu-img \
		swtpm timeout tee
	do
		ln -s /bin/true "$WORK/fake-bin/$command_name" || return 1
	done &&
	printf kernel >"$WORK/bzImage" &&
	! PATH="$WORK/fake-bin" \
		TEST_VM_WORK_DIR="$WORK/missing-dependency" \
		TEST_VM_KERNEL="$WORK/bzImage" "$RUNNER" \
		>"$WORK/missing-dependency.out" 2>&1 &&
	grep -q "missing host commands: cloud-localds" \
		"$WORK/missing-dependency.out" &&
	grep -q "sudo apt-get install -y --no-install-recommends cloud-image-utils" \
		"$WORK/missing-dependency.out"
'

test_expect_success 'test-vm selects the root partition without an initramfs' '
	grep -q "root=/dev/vda1 rootwait rw" "$RUNNER" &&
	! grep -q "root=LABEL=cloudimg-rootfs" "$RUNNER"
'

test_expect_success 'test-vm guest uses prebuilt target fixtures' '
	grep -q "SHIRUDO_TEST_FIXTURES_DIR" ../contrib/test-vm-guest.sh &&
	grep -q "run-target-tests.sh" ../contrib/test-vm-guest.sh &&
	! grep -q "SHIRUDO_BUILD_BIN=" ../contrib/test-vm-guest.sh &&
	grep -q "prepared Ubuntu runtime image" ../contrib/test-vm-guest.sh &&
	! grep -q "apt-get install" ../contrib/test-vm-guest.sh &&
	test -x run-target-tests.sh &&
	test -x t1200-target-fixtures.sh &&
	! grep -q "libluajit-5.1-dev" ../contrib/test-vm-guest.sh
'

test_expect_success 'test-vm imports the host-built payload' '
	grep -q "TEST_VM_BUNDLE_DIR" ../testing/Makefile &&
	grep -q "test-vm-bundle" ../testing/Makefile &&
	grep -q "build-test-vm-bundle.sh" ../testing/Makefile &&
	grep -q "prepare-test-vm-runtime.sh" ../testing/Makefile &&
	grep -q "virt-customize" ../contrib/build-test-vm-bundle.sh &&
	grep -q "mount_tag=shirudo-bundle" ../contrib/test-vm.sh &&
	grep -q "importing host-built Shirudo payload" \
		../contrib/test-vm-guest.sh &&
	grep -q "package_cert=\"\${TEST_VM_PACKAGE_CERT:-\$BUNDLE/fixtures/cert.der}\"" \
		../contrib/test-vm-guest.sh &&
	! grep -q "vmlinux.h" ../contrib/test-vm-guest.sh &&
	! grep -q "shirudo-build" ../contrib/test-vm-guest.sh &&
	! grep -Fq "make \"\${BPF_MAKE_ARGS[@]}\" check" \
		../contrib/test-vm-guest.sh &&
	grep -Fq "LIBBPF_VENDOR    := vendor/libbpf" ../Makefile.shirudo &&
	grep -Fq "\$(LIBBPF_A)" ../Makefile.shirudo &&
	grep -Fq "VMLINUX_GEN      := tools/gen-vmlinux-h/gen-vmlinux-h" \
		../Makefile.shirudo &&
	! grep -q "shirudo-bpf-deps" ../contrib/build-kernel-package.sh
'
	test_expect_success 'test-vm bundle stamp controls incremental rebuilds' '
	grep -q "TEST_VM_BUNDLE_STAMP" ../testing/Makefile &&
	grep -q "TEST_VM_BUNDLE_INPUTS" ../testing/Makefile &&
	grep -q "bundle_is_current" ../contrib/build-test-vm-bundle.sh &&
	grep -q "flock 9" ../testing/Makefile &&
	grep -q "bundle_dir.lock" ../testing/Makefile &&
	! grep -Fq "rm -rf \"\$\$bundle_dir.lock\"" ../testing/Makefile &&
	grep -Fq "\$\$bundle_dir" ../testing/Makefile
'

	test_expect_success 'test-vm summary records failed test names' '
	grep -q "print_test_summary" ../contrib/test-vm.sh &&
	grep -q "exit \"\$FINAL_STATUS\"" ../contrib/test-vm.sh &&
	grep -q "failed tests:" ../contrib/test-vm.sh &&
	grep -q "VM_VERBOSE" ../testing/Makefile &&
	grep -q "summary_log" ../contrib/test-vm.sh &&
	grep -q "print_quiet_progress" ../contrib/test-vm.sh &&
	grep -q "stream_verbose_console" ../contrib/test-vm.sh &&
	grep -q "qemu.log\\\" 2>&1 &" ../contrib/test-vm.sh &&
	grep -q "SHIRUDO_TEST_FAILURES_FILE" ../contrib/test-vm-guest.sh &&
	grep -q "SHIRUDO_TEST_SUITE_FAILURES_FILE" ../contrib/test-vm-guest.sh &&
	grep -q "SHIRUDO_TEST_FAILURES_FILE" ../testing/test-lib.sh &&
	grep -q "SHIRUDO_TEST_SUITE_FAILURES_FILE" ../testing/run-tests.sh
'

test_expect_success 'test harness records a failed test title' '
	printf "%s\n" \
		"#!/bin/sh" \
		". \"\$PWD/test-lib.sh\"" \
		"test_expect_success \"synthetic failure\" \"false\"" \
		"test_done" >"$WORK/failing-suite.sh" &&
	! SHIRUDO_TEST_FAILURES_FILE="$WORK/failed-tests" \
		sh "$WORK/failing-suite.sh" >"$WORK/failing-suite.out" 2>&1 &&
	grep -Fq "test	$WORK/failing-suite.sh	synthetic failure" \
		"$WORK/failed-tests"
'

test_expect_success 'make -C testing vm and test-vm share named mode support' '
	grep -q "^[[:space:]]*vm:" ../testing/Makefile &&
	grep -q "VM_MODE=interactive" ../testing/Makefile &&
	grep -q "VM_MODE=test" ../testing/Makefile &&
	grep -Fq "VMS_DIR=\"\${VM_ROOT}/vms\"" ../contrib/test-vm.sh &&
	grep -Fq "mktemp -d \"\${VMS_DIR}/\${VM_MODE}-XXXXXX\"" \
		../contrib/test-vm.sh &&
	grep -q "VM_TENANT" ../contrib/test-vm.sh &&
	grep -q "while :; do sleep 3600; done" ../contrib/test-vm.sh
'
test_expect_success 'make -C testing vm selects supported stable kernel artifacts' '
	grep -q "VM_KERNEL_STABLE_VERSIONS := 7.2 6.18 6.12 6.6 6.1" ../testing/Makefile &&
	grep -q "make -C testing vm KERNEL=6.18" ../testing/Makefile &&
	grep -Fq "VM_KERNEL_ARTIFACT_DIR := \$(ROOT)/artifacts/linux-\$(VM_KERNEL_TAG)\$(KERNEL_COMMIT_SUFFIX)-kernel-debs" ../testing/Makefile &&
	grep -q "TEST_VM_KERNEL=\"\$(abspath \$(VM_KERNEL_IMAGE))\"" ../testing/Makefile &&
	make -n -C .. -f testing/Makefile vm KERNEL=6.18 TEST_VM_ARCH=x86_64 \
		TEST_VM_WORK_DIR="$WORK/stable-vm" \
		>"$WORK/stable-vm-make.out" 2>&1 &&
	grep -q "artifacts/linux-v6.18-kernel-debs/bzImage" \
		"$WORK/stable-vm-make.out"
'

test_expect_success 'the VM kernel image is named for the host architecture' '
	for spec in x86_64:bzImage amd64:bzImage aarch64:Image arm64:Image \
		riscv64:bzImage
	do
		arch=${spec%%:*} image=${spec#*:} &&
		make -n -C .. -f testing/Makefile vm KERNEL=6.18 \
			TEST_VM_ARCH=$arch TEST_VM_WORK_DIR="$WORK/arch-$arch" \
			>"$WORK/arch-$arch.out" 2>&1 &&
		grep -q "artifacts/linux-v6.18-kernel-debs/$image" \
			"$WORK/arch-$arch.out" || return 1
	done
'

test_expect_success 'the VM kernel is not built on an unsupported architecture' '
	! TEST_VM_ARCH=riscv64 ../contrib/build-kernel-package.sh \
		>"$WORK/riscv64-kernel.out" 2>&1 &&
	grep -q "x86_64 and aarch64 hosts only, not riscv64" \
		"$WORK/riscv64-kernel.out"
'

test_expect_success 'all kernel and VM builds use the slim profile' '
	! grep -Eq "^(kernel-small|vm-small|test-vm-small-bundle):" ../testing/Makefile &&
	! grep -q "KERNEL_PROFILE" ../testing/Makefile ../contrib/build-kernel-package.sh &&
	! test -e ../contrib/kernel-small.config &&
	! test -e ../contrib/kernel-observability-configs.txt &&
	grep -q "kernel-slim.config" ../contrib/build-kernel-package.sh &&
	grep -q "config_profile=slim" ../contrib/build-kernel-package.sh &&
	grep -q "CONFIG_CC_OPTIMIZE_FOR_SIZE=y" ../contrib/build-kernel-package.sh &&
	grep -q "make -C testing vm KERNEL=6.18" ../testing/Makefile &&
	make -n -C .. -f testing/Makefile vm VM_NAME=slim-cli-vm \
		TEST_VM_ARCH=x86_64 TEST_VM_WORK_DIR="$WORK/slim-vm" \
		>"$WORK/slim-vm-make.out" 2>&1 &&
	grep -q "artifacts/bpf-next-kernel-debs/bzImage" \
		"$WORK/slim-vm-make.out" &&
	grep -q "BPF_VMLINUX_BTF=.*artifacts/bpf-next-kernel-debs/vmlinux.btf" \
		"$WORK/slim-vm-make.out"
'

test_expect_success 'VM reports guest and host memory usage' '
	grep -q "report_boot_memory" ../contrib/test-vm-guest.sh &&
	grep -q "guest_mem_total_kb" ../contrib/test-vm-guest.sh &&
	grep -q "guest_mem_available_kb" ../contrib/test-vm-guest.sh &&
	grep -q "guest_mem_used_percent" ../contrib/test-vm-guest.sh &&
	grep -q "capture_host_memory_report" ../contrib/test-vm.sh &&
	grep -q "qemu_vmrss_kb" ../contrib/test-vm.sh &&
	grep -q "qemu_pss_kb" ../contrib/test-vm.sh &&
	grep -q "print_memory_summary" ../contrib/test-vm.sh
'

test_expect_success 'make -C testing kernel builds a tagged third-party Linux source' '
	grep -q "^kernel: \$(KERNEL_BUILD_STAMP)" ../testing/Makefile &&
	grep -q "KERNEL_TAG=\"\${KERNEL_TAG:-bpf-next}\"" \
		../contrib/build-kernel-package.sh &&
	grep -q "KERNEL_REPOSITORY=\"\${KERNEL_REPOSITORY:-https://git.kernel.org" \
		../contrib/build-kernel-package.sh &&
	grep -q "git clone --depth 1 --branch" ../contrib/build-kernel-package.sh &&
	grep -q "make -C testing kernel KERNEL_TAG=v6.18" ../testing/Makefile &&
	! KERNEL_TAG=not-a-kernel-tag ../contrib/build-kernel-package.sh \
		>"$WORK/invalid-kernel-tag.out" 2>&1 &&
	grep -q "KERNEL_TAG must be bpf-next or a Linux release tag" \
		"$WORK/invalid-kernel-tag.out"
'
test_expect_success 'make -C testing vm and kernel select an exact stable commit' '
	make -n -C .. -f testing/Makefile vm KERNEL=6.18 KERNEL_COMMIT=abcdef1234567 \
		TEST_VM_ARCH=x86_64 TEST_VM_WORK_DIR="$WORK/commit-vm" \
		>"$WORK/commit-vm-make.out" 2>&1 &&
	grep -q "artifacts/linux-v6.18-abcdef1234567-kernel-debs/bzImage" \
		"$WORK/commit-vm-make.out" &&
	grep -q "KERNEL_COMMIT=" "$WORK/commit-vm-make.out" &&
	grep -q "KERNEL_COMMIT is supported only for stable/LTS VM kernels" ../testing/Makefile &&
	! make -n -C .. -f testing/Makefile vm KERNEL=bpf-next KERNEL_COMMIT=abcdef1234567 \
		>"$WORK/commit-bpf-next.out" 2>&1 &&
	grep -q "KERNEL_COMMIT is supported only for stable/LTS VM kernels" \
		"$WORK/commit-bpf-next.out" &&
	! KERNEL_TAG=v6.18 KERNEL_COMMIT=not-a-sha \
		../contrib/build-kernel-package.sh >"$WORK/invalid-kernel-commit.out" 2>&1 &&
	grep -q "KERNEL_COMMIT must contain 7 to 40 hexadecimal characters" \
		"$WORK/invalid-kernel-commit.out"
'
test_expect_success 'kernel VM artifacts provide networking modules' '
	grep -q "CONFIG_VETH=m" ../contrib/build-kernel-package.sh &&
	grep -q "CONFIG_BRIDGE=m" ../contrib/build-kernel-package.sh &&
	grep -q "CONFIG_VLAN_8021Q=m" ../contrib/build-kernel-package.sh &&
	grep -q "CONFIG_NF_FLOW_TABLE=m" ../contrib/build-kernel-package.sh &&
	grep -q "CONFIG_NF_FLOW_TABLE_INET=m" ../contrib/build-kernel-package.sh &&
	grep -q "CONFIG_NF_FLOW_TABLE_PROCFS=y" ../contrib/build-kernel-package.sh &&
	grep -q "CONFIG_PROC_FS=y" ../contrib/build-kernel-package.sh &&
	grep -q "require_config CONFIG_VETH m" ../contrib/build-kernel-package.sh &&
	grep -q "dpkg-deb -x" ../contrib/build-kernel-package.sh &&
	grep -q "depmod -b" ../contrib/build-kernel-package.sh &&
	grep -q "TEST_VM_KERNEL_ARTIFACT_DIR" ../testing/Makefile &&
	grep -q "mount_tag=shirudo-kernel" ../contrib/test-vm.sh &&
	grep -q "TEST_VM_KERNEL_MODULES" ../contrib/test-vm.sh &&
	grep -q "install_kernel_modules" ../contrib/test-vm-guest.sh &&
	grep -q "modprobe \"\$module\"" ../contrib/test-vm-guest.sh &&
	grep -q "nf_flow_table_procfs" ../contrib/test-vm-guest.sh
'
test_expect_success 'prepared VM runtime includes ripgrep' '
	grep -qx "ripgrep" ../contrib/test-vm-runtime-packages &&
	grep -q "package_digest" ../contrib/build-test-vm-bundle.sh
'

test_expect_success 'named VM console and SSH access helpers are wired up' '
	grep -q "^vm-console:" ../testing/Makefile &&
	grep -q "^vm-ssh:" ../testing/Makefile &&
	grep -q "contrib/test-vm.sh --console" ../testing/Makefile &&
	grep -q "contrib/test-vm.sh --ssh" ../testing/Makefile &&
	grep -q "VM_SSH_COMMAND" ../contrib/test-vm.sh &&
	grep -q "TEST_VM_SSH_PORT" ../contrib/test-vm.sh &&
	grep -q "hostfwd=tcp:127.0.0.1" ../contrib/test-vm.sh &&
	grep -q "socket,id=console" ../contrib/test-vm.sh &&
	grep -q "logfile=.*console.log" ../contrib/test-vm.sh &&
	grep -q "TEST_VM_SSH_PUBLIC_KEY" ../contrib/test-vm.sh &&
	grep -q "serial-getty@ttyS0.service" ../contrib/test-vm-guest.sh &&
	grep -q "TEST_VM_SSH_PUBLIC_KEY" ../contrib/test-vm-guest.sh
'

test_expect_success 'VM console requires a named VM and SSH reports empty state' '
	! TEST_VM_WORK_DIR="$WORK/access-console" "$RUNNER" --console \
		>"$WORK/access-console.out" 2>&1 &&
	grep -q "VM_NAME is required for VM console/SSH access" \
		"$WORK/access-console.out" &&
	! TEST_VM_WORK_DIR="$WORK/access-ssh" "$RUNNER" --ssh \
		>"$WORK/access-ssh.out" 2>&1 &&
	grep -q "no saved VM states found" \
		"$WORK/access-ssh.out"
'

test_expect_success 'unnamed vm-ssh selects the newest saved VM state' '
	root="$WORK/latest-ssh" &&
	mkdir -p "$root/vms/older" "$root/vms/newer" &&
	printf "1000000000000000000\n" >"$root/vms/older/created-at" &&
	printf "2000000000000000000\n" >"$root/vms/newer/created-at" &&
	touch -t 203001010000 "$root/vms/older" &&
	! TEST_VM_WORK_DIR="$root" "$RUNNER" --ssh \
		>"$WORK/latest-ssh.out" 2>&1 &&
	grep -q "VM '\''newer'\'' is not running" "$WORK/latest-ssh.out"
'

test_expect_success 'explicit VM_NAME overrides unnamed vm-ssh selection' '
	root="$WORK/named-ssh" &&
	mkdir -p "$root/vms/older" "$root/vms/newer" &&
	printf "1000000000000000000\n" >"$root/vms/older/created-at" &&
	printf "2000000000000000000\n" >"$root/vms/newer/created-at" &&
	! VM_NAME=older TEST_VM_WORK_DIR="$root" "$RUNNER" --ssh \
		>"$WORK/named-ssh.out" 2>&1 &&
	grep -q "VM '\''older'\'' is not running" "$WORK/named-ssh.out"
'

test_expect_success 'VM bundle installs target units and interactive mode activates timers' '
	grep -q "DESTDIR=\"\$TMP_DIR/root\" install-target" \
		../contrib/build-test-vm-bundle.sh &&
	grep -q "systemd/\\*.timer" ../testing/Makefile &&
	grep -q "shirudo-map-export.timer" ../contrib/test-vm-guest.sh &&
	grep -q "shirudo-keepalive.timer" ../contrib/test-vm-guest.sh &&
	grep -q "shirudo-bpm-repo-update.service" ../contrib/test-vm-guest.sh &&
	grep -q "shirudo-bpm-repo-update.timer" ../contrib/test-vm-guest.sh &&
	grep -q "shirudo-bpm-tree-sync.service" ../contrib/test-vm-guest.sh &&
	grep -q "shirudo-bpm-tree-sync.timer" ../contrib/test-vm-guest.sh &&
	grep -q "OnUnitActiveSec=60s" ../systemd/shirudo-bpm-tree-sync.timer &&
	grep -q "Persistent=true" ../systemd/shirudo-bpm-tree-sync.timer &&
	grep -q "systemctl enable shirudo.service" ../contrib/test-vm-guest.sh &&
	grep -q "systemctl enable --now shirudo-map-export.timer" \
		../contrib/test-vm-guest.sh &&
	grep -q "systemctl enable --now shirudo-keepalive.timer" \
		../contrib/test-vm-guest.sh &&
	grep -q "systemctl enable --now shirudo-bpm-repo-update.timer" \
		../contrib/test-vm-guest.sh &&
	grep -q "systemctl enable --now shirudo-bpm-tree-sync.timer" \
		../contrib/test-vm-guest.sh &&
	grep -Fq "if [[ \"\$VM_MODE\" == interactive ]]" \
		../contrib/test-vm-guest.sh
'

test_expect_success 'VM stop and cleanup use the VM runner paths' '
	grep -q "^vm-stop:" ../testing/Makefile &&
	grep -q "contrib/test-vm.sh --stop" ../testing/Makefile &&
	grep -q "^vm-clean:" ../testing/Makefile &&
	grep -q "contrib/test-vm.sh --clean" ../testing/Makefile &&
	grep -q "^test-vm-clean: vm-clean" ../testing/Makefile &&
	grep -q "VM_NAME=\"\$(VM_NAME)\"" ../testing/Makefile &&
	grep -q "stop_pid_file" ../contrib/test-vm.sh &&
	grep -q "removed VM state and logs" ../contrib/test-vm.sh
'

test_expect_success 'named vm-stop preserves the selected VM state' '
	root="$WORK/named-stop" &&
	mkdir -p "$root/vms/one" "$root/logs/one" &&
	printf state >"$root/vms/one/sentinel" &&
	printf log >"$root/logs/one/sentinel" &&
	VM_NAME=one TEST_VM_WORK_DIR="$root" "$RUNNER" --stop &&
	test -e "$root/vms/one/sentinel" &&
	test -e "$root/logs/one/sentinel"
'

test_expect_success 'unnamed vm-stop stops all VMs and preserves state' '
	root="$WORK/all-stop" &&
	mkdir -p "$root/vms/one" "$root/vms/two" "$root/logs/one" \
		"$root/logs/two" &&
	printf state >"$root/vms/one/sentinel" &&
	printf state >"$root/vms/two/sentinel" &&
	printf log >"$root/logs/one/sentinel" &&
	printf log >"$root/logs/two/sentinel" &&
	TEST_VM_WORK_DIR="$root" "$RUNNER" --stop &&
	test -e "$root/vms/one/sentinel" &&
	test -e "$root/vms/two/sentinel" &&
	test -e "$root/logs/one/sentinel" &&
	test -e "$root/logs/two/sentinel"
'

test_expect_success 'named test-vm-clean removes only the selected VM' '
	root="$WORK/named-clean" &&
	mkdir -p "$root/vms/one" "$root/vms/two" "$root/logs/one" \
		"$root/logs/two" "$root/cache" &&
	printf state >"$root/vms/one/sentinel" &&
	printf state >"$root/vms/two/sentinel" &&
	printf log >"$root/logs/one/sentinel" &&
	printf log >"$root/logs/two/sentinel" &&
	VM_NAME=one TEST_VM_WORK_DIR="$root" "$RUNNER" --clean &&
	! test -e "$root/vms/one" &&
	! test -e "$root/logs/one" &&
	test -e "$root/vms/two/sentinel" &&
	test -e "$root/logs/two/sentinel" &&
	test -d "$root/cache"
'

test_expect_success 'test-vm supports secure and explicit insecure map-export modes' '
	grep -q "MAP_EXPORT_CA=\"\${TEST_VM_MAP_EXPORT_CA:-}\"" "$RUNNER" &&
	grep -q "MAP_EXPORT_INSECURE=false" "$RUNNER" &&
	grep -q "HTTPS map-export endpoints require TEST_VM_MAP_EXPORT_INSECURE=false" "$RUNNER" &&
	grep -q "HTTP map-export endpoints require TEST_VM_MAP_EXPORT_INSECURE=true" "$RUNNER" &&
	grep -q "TEST_VM_MAP_EXPORT_CA=\"\$(TEST_VM_MAP_EXPORT_CA)\"" ../testing/Makefile &&
	grep -q "export TEST_VM_MAP_EXPORT_ENDPOINT" "$RUNNER" &&
	grep -q "export TEST_VM_MAP_EXPORT_CA=/mnt/shirudo-otel/ca.pem" "$RUNNER" &&
	grep -q "mount_tag=shirudo-otel" "$RUNNER" &&
	grep -q "10.0.2.2 otel.test" ../contrib/test-vm-guest.sh &&
	grep -q "map_export.otel_endpoint = \$endpoint" ../contrib/test-vm-guest.sh &&
	grep -q "map_export.otel_insecure = \$insecure" ../contrib/test-vm-guest.sh &&
	grep -q "OTEL_EXPORTER_OTLP_CERTIFICATE=/etc/shirudo/otel/ca.pem" \
		../contrib/test-vm-guest.sh &&
	grep -q "map_export.tenant_id = \$tenant_id" ../contrib/test-vm-guest.sh
'

test_expect_success 'test-vm rejects incomplete map-export bridge settings' '
	printf kernel >"$WORK/map-export-kernel" &&
	! TEST_VM_WORK_DIR="$WORK/incomplete-map-export" \
		TEST_VM_KERNEL="$WORK/map-export-kernel" \
		TEST_VM_MAP_EXPORT_ENDPOINT=http://otel.test:4318 \
		TEST_VM_MAP_EXPORT_INSECURE=true "$RUNNER" \
		>"$WORK/incomplete-map-export.out" 2>&1 &&
	grep -q "must be set together" "$WORK/incomplete-map-export.out"
'

test_expect_success 'test-vm accepts secure HTTPS export without insecure setting' '
	! TEST_VM_WORK_DIR="$WORK/secure-map-export" \
		TEST_VM_KERNEL="$WORK/map-export-kernel" \
		TEST_VM_MAP_EXPORT_ENDPOINT=https://otel.test:4318 \
		TEST_VM_MAP_EXPORT_TENANT_ID=tenant-test "$RUNNER" \
		>"$WORK/secure-map-export.out" 2>&1 &&
	! grep -q "must be exactly true" "$WORK/secure-map-export.out" &&
	! grep -q "must be true or false" "$WORK/secure-map-export.out"
'

test_expect_success 'test-vm rejects cleartext export without explicit insecure setting' '
	! TEST_VM_WORK_DIR="$WORK/cleartext-map-export" \
		TEST_VM_KERNEL="$WORK/map-export-kernel" \
		TEST_VM_MAP_EXPORT_ENDPOINT=http://otel.test:4318 \
		TEST_VM_MAP_EXPORT_TENANT_ID=tenant-test "$RUNNER" \
		>"$WORK/cleartext-map-export.out" 2>&1 &&
	grep -q "HTTP map-export endpoints require TEST_VM_MAP_EXPORT_INSECURE=true" \
		"$WORK/cleartext-map-export.out"
'

test_expect_success 'test-vm validates a custom OTEL CA file before boot' '
	! TEST_VM_WORK_DIR="$WORK/missing-map-export-ca" \
		TEST_VM_KERNEL="$WORK/map-export-kernel" \
		TEST_VM_MAP_EXPORT_ENDPOINT=https://otel.test:4318 \
		TEST_VM_MAP_EXPORT_TENANT_ID=tenant-test \
		TEST_VM_MAP_EXPORT_CA="$WORK/no-ca.pem" "$RUNNER" \
		>"$WORK/missing-map-export-ca.out" 2>&1 &&
	grep -q "TEST_VM_MAP_EXPORT_CA is not a readable regular file" \
		"$WORK/missing-map-export-ca.out"
'

test_expect_success 'test-vm passes an OCI CA into the guest trust store' '
	grep -q "TEST_VM_OCI_CA" ../testing/Makefile &&
	grep -q "OCI_CA=\"\${TEST_VM_OCI_CA:-}\"" "$RUNNER" &&
	grep -q "shirudo-oci" "$RUNNER" &&
	grep -q "export TEST_VM_OCI_CA=/mnt/shirudo-oci/ca.crt" "$RUNNER" &&
	grep -q "shirudo-oci-ca.crt" ../contrib/test-vm-guest.sh &&
	grep -q "update-ca-certificates" ../contrib/test-vm-guest.sh
'

test_expect_success 'test-vm validates a custom OCI CA file before boot' '
	! TEST_VM_WORK_DIR="$WORK/missing-oci-ca" \
		TEST_VM_KERNEL="$WORK/map-export-kernel" \
		TEST_VM_OCI_CA="$WORK/no-oci-ca.pem" "$RUNNER" \
		>"$WORK/missing-oci-ca.out" 2>&1 &&
	grep -q "TEST_VM_OCI_CA is not a readable, non-empty regular file" \
		"$WORK/missing-oci-ca.out"
'

test_expect_success 'test-vm hands off an interactive BPM tree configuration' '
	grep -q "TEST_VM_BPM_TREE_CONFIG" ../testing/Makefile &&
	grep -q "TEST_VM_BPM_TREE_CONFIG=\"\$(TEST_VM_BPM_TREE_CONFIG)\"" ../testing/Makefile &&
	grep -q "BPM_TREE_CONFIG=\"\${TEST_VM_BPM_TREE_CONFIG:-}\"" "$RUNNER" &&
	grep -q "validate_bpm_tree_config" "$RUNNER" &&
	grep -q "BPM_TREE_DIR=\"\${RUN_DIR}/bpm-tree\"" "$RUNNER" &&
	grep -q "install -m 0644 \"\$BPM_TREE_CONFIG\" \"\$BPM_TREE_DIR/upatch-tree.conf\"" "$RUNNER" &&
	grep -q "mount_tag=shirudo-bpm-tree" "$RUNNER" &&
	grep -q "export TEST_VM_BPM_TREE_INPUT=/mnt/shirudo-bpm-tree" "$RUNNER" &&
	grep -q "mount.*shirudo-bpm-tree /mnt/shirudo-bpm-tree" "$RUNNER" &&
	grep -q "credentials and private signing" "$RUNNER" &&
	grep -q "configure_bpm_tree" ../contrib/test-vm-guest.sh &&
	grep -Fq "[[ -z \"\$tree_input\" ]] && return 0" ../contrib/test-vm-guest.sh &&
	grep -q "local config_file=\"\${tree_input}/upatch-tree.conf\"" ../contrib/test-vm-guest.sh &&
	grep -q "temporary=\"\${target}.tmp.\$\$\"" ../contrib/test-vm-guest.sh &&
	grep -q "mv -f \"\$temporary\" \"\$target\"" ../contrib/test-vm-guest.sh &&
	grep -q "systemctl start shirudo-bpm-tree-sync.service" ../contrib/test-vm-guest.sh &&
	grep -q "systemctl enable --now shirudo-bpm-tree-sync.timer" ../contrib/test-vm-guest.sh &&
	test "$(grep -n "/usr/local/bin/shirudo init" ../contrib/test-vm-guest.sh | cut -d: -f1)" -lt \
		"$(grep -n "systemctl start shirudo-bpm-tree-sync.service" ../contrib/test-vm-guest.sh | cut -d: -f1)" &&
	test "$(grep -n "systemctl start shirudo-bpm-tree-sync.service" ../contrib/test-vm-guest.sh | cut -d: -f1)" -lt \
		"$(grep -n "systemctl enable --now shirudo-bpm-tree-sync.timer" ../contrib/test-vm-guest.sh | cut -d: -f1)"
'

test_expect_success 'test-vm validates BPM tree configuration mode and contents' '
	printf kernel >"$WORK/bpm-tree-kernel" &&
	! TEST_VM_WORK_DIR="$WORK/missing-bpm-tree" \
		VM_MODE=interactive TEST_VM_KERNEL="$WORK/bpm-tree-kernel" \
		TEST_VM_BPM_TREE_CONFIG="$WORK/no-bpm-tree.conf" "$RUNNER" \
		>"$WORK/missing-bpm-tree.out" 2>&1 &&
	grep -q "TEST_VM_BPM_TREE_CONFIG is not a readable, non-empty regular file" \
		"$WORK/missing-bpm-tree.out" &&
	: >"$WORK/empty-bpm-tree.conf" &&
	! TEST_VM_WORK_DIR="$WORK/empty-bpm-tree" \
		VM_MODE=interactive TEST_VM_KERNEL="$WORK/bpm-tree-kernel" \
		TEST_VM_BPM_TREE_CONFIG="$WORK/empty-bpm-tree.conf" "$RUNNER" \
		>"$WORK/empty-bpm-tree.out" 2>&1 &&
	grep -q "TEST_VM_BPM_TREE_CONFIG is not a readable, non-empty regular file" \
		"$WORK/empty-bpm-tree.out" &&
	printf 'tree config\n' >"$WORK/bpm-tree.conf" &&
	! TEST_VM_WORK_DIR="$WORK/test-bpm-tree" \
		VM_MODE=test TEST_VM_KERNEL="$WORK/bpm-tree-kernel" \
		TEST_VM_BPM_TREE_CONFIG="$WORK/bpm-tree.conf" "$RUNNER" \
		>"$WORK/test-bpm-tree.out" 2>&1 &&
	grep -q "TEST_VM_BPM_TREE_CONFIG is supported only for interactive make -C testing vm" \
		"$WORK/test-bpm-tree.out"
'

	test_expect_success 'test-vm passes a public package certificate into the guest' '
	grep -q "TEST_VM_PACKAGE_CERT" ../testing/Makefile &&
	grep -q "TEST_VM_BUNDLE_INPUTS" ../testing/Makefile &&
	grep -q "PACKAGE_CERT=\"\${TEST_VM_PACKAGE_CERT:-}\"" \
		../contrib/build-test-vm-bundle.sh &&
	grep -q "package-cert.der" ../contrib/build-test-vm-bundle.sh &&
	grep -q "export TEST_VM_PACKAGE_CERT=/mnt/shirudo-package-cert/package-cert.der" \
		"$RUNNER" &&
	grep -q "supported only for interactive make -C testing vm" "$RUNNER" &&
	grep -q "TEST_VM_PACKAGE_CERT" ../contrib/test-vm-guest.sh &&
	grep -q "install -m 0644 \"\$package_cert\"" \
		../contrib/test-vm-guest.sh
'

test_expect_success 'test-vm validates a custom package certificate before boot' '
	printf kernel >"$WORK/package-cert-kernel" &&
	! TEST_VM_WORK_DIR="$WORK/missing-package-cert" \
		VM_MODE=interactive \
		TEST_VM_KERNEL="$WORK/package-cert-kernel" \
		TEST_VM_PACKAGE_CERT="$WORK/no-package-cert.der" "$RUNNER" \
		>"$WORK/missing-package-cert.out" 2>&1 &&
	grep -q "TEST_VM_PACKAGE_CERT is not a readable, non-empty regular file" \
		"$WORK/missing-package-cert.out"
'

test_expect_success 'test-vm bootstraps a BPM OCI repository from the host' '
	grep -q "TEST_VM_BPM_OCI_REPOSITORY" ../testing/Makefile &&
	grep -q "TEST_VM_BPM_OCI_INDEX_CERT" ../testing/Makefile &&
	grep -q "BPM_OCI_REPOSITORY_RAW=\"\${TEST_VM_BPM_OCI_REPOSITORY:-}\"" \
		"$RUNNER" &&
	grep -q "export TEST_VM_BPM_OCI_SOURCE" "$RUNNER" &&
	grep -q "export TEST_VM_BPM_OCI_INPUT=/mnt/shirudo-bpm-oci" "$RUNNER" &&
	grep -q "registries.d/\${BPM_OCI_SOURCE}.conf" "$RUNNER" &&
	grep -q "keys/\${BPM_OCI_SOURCE}.pem" "$RUNNER" &&
	grep -q "repository.env" "$RUNNER" &&
	grep -q "mount_tag=shirudo-bpm-oci" "$RUNNER" &&
	grep -q "registry\.test" ../contrib/test-vm-guest.sh &&
	grep -q "install -m 0644.*staged_conf.*conf_file" \
		../contrib/test-vm-guest.sh &&
	grep -q "install -m 0644.*staged_env.*repository_env" \
		../contrib/test-vm-guest.sh
'

test_expect_success 'test-vm validates BPM OCI repository handoff as a pair' '
	printf kernel >"$WORK/bpm-oci-kernel" &&
	! TEST_VM_WORK_DIR="$WORK/missing-bpm-oci-cert" \
		TEST_VM_KERNEL="$WORK/bpm-oci-kernel" \
		TEST_VM_BPM_OCI_REPOSITORY=example=oci://registry.example.com \
		"$RUNNER" >"$WORK/missing-bpm-oci-cert.out" 2>&1 &&
	grep -q "TEST_VM_BPM_OCI_REPOSITORY and TEST_VM_BPM_OCI_INDEX_CERT must be set together" \
		"$WORK/missing-bpm-oci-cert.out" &&
	! TEST_VM_WORK_DIR="$WORK/missing-bpm-oci-repository" \
		TEST_VM_KERNEL="$WORK/bpm-oci-kernel" \
		TEST_VM_BPM_OCI_INDEX_CERT="$WORK/missing-index-cert.pem" \
		"$RUNNER" >"$WORK/missing-bpm-oci-repository.out" 2>&1 &&
	grep -q "TEST_VM_BPM_OCI_REPOSITORY and TEST_VM_BPM_OCI_INDEX_CERT must be set together" \
		"$WORK/missing-bpm-oci-repository.out"
'

test_expect_success 'make -C testing test runs the complete pipeline in order' '
	grep -q "^test-op:" ../testing/Makefile &&
	! grep -Eq "^(check:|.*\bcheck\b.*\.PHONY)" ../testing/Makefile &&
	grep -q "^bundle: test-vm-bundle" ../testing/Makefile &&
	grep -A5 "^test:$" ../testing/Makefile | grep -q "\$(MAKE) -C \$(ROOT) -f testing/Makefile bundle" &&
	grep -A5 "^test:$" ../testing/Makefile | grep -q "\$(MAKE) -C \$(ROOT) -f testing/Makefile test-op" &&
	grep -A5 "^test:$" ../testing/Makefile | grep -q "\$(MAKE) -C \$(ROOT) -f testing/Makefile test-tgt" &&
	! grep -A5 "^test:$" ../testing/Makefile | grep -q "\$(MAKE) bpf-next"
'

test_expect_success 'operator and target runners have disjoint explicit scopes' '
	grep -q "for t in t0\[0-9\]\[0-9\]\[0-9\]-\*.sh" ../testing/run-tests.sh &&
	! grep -q "t1101" ../testing/run-tests.sh &&
	for test_name in \
		t1200-target-fixtures.sh \
		t1118-bpm-tree.sh \
		t1119-bpm-tree-sequential.sh \
		t1120-bpm-tree-delete.sh \
		t1102-eventlog-full.sh \
		t1103-version-gate.sh \
		t1104-payload-mismatch.sh \
		t1107-load-unload.sh \
		t1108-tpm-chain.sh \
		t1111-upatch-get.sh \
		t1114-uprobe-multi.sh \
		t1115-map-export-all.sh \
		t1116-otel-backend.sh \
		t1117-otel-serialized-metric.sh \
		t1122-initrd.sh \
		t1123-keys.sh \
		t1124-keys-add.sh \
		t1126-keys-revoke.sh \
		tamperproof/t1101-seal.sh \
		tamperproof/t1105-siggate.sh \
		tamperproof/t1110-lsm-deny.sh \
		tamperproof/t1112-prog-load-keyring-gate.sh \
		tamperproof/t1113-mount-lockdown.sh \
		tamperproof/t1130-map-lockdown.sh \
		tamperproof/t1131-pr-set-mm-identity.sh \
		tamperproof/t1121-bpf-keyring.sh \
		tamperproof/t1125-key-permission.sh \
		tamperproof/t1106-keyring-swap.sh
	do
		grep -q "$test_name" ../testing/run-target-tests.sh || return 1
	done &&
	forbidden=$(printf '%s%s' SHIRUDO_ INTEGRATION) &&
	! grep -R -q "$forbidden" ../testing/Makefile ../contrib ../testing
'

test_done
