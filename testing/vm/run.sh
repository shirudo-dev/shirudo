#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Boot an Ubuntu guest with a selected Linux kernel and an swtpm vTPM.
# In test mode it runs the target tests of the family TEST_VM_SUITE names,
# or the TPM register tests for "register"; in serve mode the guest only
# prepares itself and the host runs the family's target tests in it over
# SSH; in interactive mode it prepares the guest and leaves QEMU and swtpm
# running. Node mode boots another node of the end2end suite, with the role
# TEST_VM_NODE_ROLE names, core by default or edge: prepared like the
# suite's VM, with no tests and no timers, and left running until
# TEST_VM_TIMEOUT or a --stop.
#
# VM_MODE=test|serve|interactive|node selects the mode. VM_NAME optionally
# selects a stable state directory; if omitted, a unique name is allocated
# atomically. VM_TENANT is used as the map-export tenant when OTEL export is
# enabled. VM_VERBOSE=1 streams the QEMU output of a VM that runs tests to
# the terminal as well as the console log.
#
# TEST_VM_SERVE_COMMAND names a program a serve-mode VM runs on the host,
# with the VM's name as its argument, instead of the target tests.
# TEST_VM_ENFORCEMENT=shared boots the runtime image built for shared
# enforcement, as the shared family always does.
# TEST_VM_ROLE=operator boots the operator of the end-to-end test in serve
# mode: no TPM, no initrd and no shirudo kernel arguments, the operator
# package built in the guest, and alone the signing key in
# TEST_VM_OPERATOR_KEYS.
# TEST_VM_PRIVATE_DIR names a new directory outside the checkout for the
# key the host logs in with and the VM's disk, which holds the guest's own
# key, for a VM no other may log in to: by default both lie in the VM's
# state directory, which every VM reads through its share of the checkout.
# The caller removes the directory.

set -euo pipefail

# The guest boots with the host's own QEMU, swtpm and dracut; a library path
# a shirudo build needed for its OpenSSL would load the wrong libraries into
# them. A serve command gets it back.
HOST_LD_LIBRARY_PATH="${LD_LIBRARY_PATH-}"
unset LD_LIBRARY_PATH

SECONDS=0

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
	COLOR_BOLD=$'\033[1m'
	COLOR_GREEN=$'\033[32m'
	COLOR_RED=$'\033[31m'
	COLOR_YELLOW=$'\033[33m'
	COLOR_CYAN=$'\033[36m'
	COLOR_RESET=$'\033[0m'
else
	COLOR_BOLD=""
	COLOR_GREEN=""
	COLOR_RED=""
	COLOR_YELLOW=""
	COLOR_CYAN=""
	COLOR_RESET=""
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=testing/vm/arch.sh
. "${REPO_ROOT}/testing/vm/arch.sh"
# TEST_VM_QEMU names another emulator, such as RHEL's /usr/libexec/qemu-kvm.
QEMU_BIN="${TEST_VM_QEMU:-$TEST_VM_ARCH_QEMU}"
VM_ROOT_INPUT="${TEST_VM_WORK_DIR:-${REPO_ROOT}/build/test-vm}"
if [[ "$VM_ROOT_INPUT" == /* ]]; then
	VM_ROOT="$VM_ROOT_INPUT"
else
	VM_ROOT="$REPO_ROOT/$VM_ROOT_INPUT"
fi
TEST_VM_HOST_BUNDLE="${TEST_VM_HOST_BUNDLE:-${VM_ROOT}/host-bundle}"
CACHE_DIR="${VM_ROOT}/cache"
RUNTIME_CACHE_INPUT="${TEST_VM_RUNTIME_CACHE_DIR:-${CACHE_DIR}/runtime}"
if [[ "$RUNTIME_CACHE_INPUT" == /* ]]; then
	RUNTIME_CACHE_DIR="$RUNTIME_CACHE_INPUT"
else
	RUNTIME_CACHE_DIR="$REPO_ROOT/$RUNTIME_CACHE_INPUT"
fi
VMS_DIR="${VM_ROOT}/vms"
# Where the shirudo of a coverage build writes its counters in a guest:
# under /run, which the initrd hands to the root, and outside what
# shirudo seals. COVERAGE_DIR keeps what each guest wrote for coverage.sh.
GCOV_PREFIX_DIR=/run/shirudo-gcov
GCOV_COLLECT="[ ! -d $GCOV_PREFIX_DIR ] || tar -C $GCOV_PREFIX_DIR -cf /mnt/shirudo-out/gcov.tar ."
COVERAGE_DIR="${VM_ROOT}/coverage"
LOGS_DIR="${VM_ROOT}/logs"
DEFAULT_KERNEL="${REPO_ROOT}/artifacts/bpf-next-kernel-debs/${TEST_VM_ARCH_KIMAGE}"
CPUS="${TEST_VM_CPUS:-4}"
MEMORY="${TEST_VM_MEMORY:-4G}"
DISK_SIZE="${TEST_VM_DISK_SIZE:-30G}"
VM_TIMEOUT="${TEST_VM_TIMEOUT:-3600}"
VM_MODE="${VM_MODE:-test}"
VM_ROLE="${TEST_VM_ROLE:-target}"
SERVE_COMMAND="${TEST_VM_SERVE_COMMAND:-}"
OPERATOR_KEYS="${TEST_VM_OPERATOR_KEYS:-}"
OPERATOR_DISK_SIZE=16G
VM_SUITE="${TEST_VM_SUITE:-}"
ENFORCEMENT="${TEST_VM_ENFORCEMENT:-}"
NODE_ROLE="${TEST_VM_NODE_ROLE:-core}"
TEST_MODE="${TEST_VM_MODE:-verity}"
SKIP_SEAL="${TEST_VM_SKIP_SEAL:-0}"
VM_INITRD="${TEST_VM_INITRD:-1}"
VM_INITRD_MODULES="${TEST_VM_INITRD_MODULES:-base systemd systemd-initrd dracut-systemd rootfs-block fs-lib udev-rules terminfo shirudo}"
INITRD=""
VM_VERBOSE="${VM_VERBOSE:-0}"
VM_NAME_REQUEST="${VM_NAME:-}"
VM_TENANT="${VM_TENANT:-}"
VM_SSH_COMMAND="${VM_SSH_COMMAND:-}"
SSH_PORT_REQUEST="${TEST_VM_SSH_PORT:-}"
PRIVATE_DIR="${TEST_VM_PRIVATE_DIR:-}"
KERNEL_URL="${TEST_VM_KERNEL_URL:-}"
KERNEL_SHA256="${TEST_VM_KERNEL_SHA256:-}"
KERNEL_OVERRIDE="${TEST_VM_KERNEL:-}"
KERNEL_ARTIFACT_INPUT="${TEST_VM_KERNEL_ARTIFACT_DIR:-}"
if [[ -n "$KERNEL_ARTIFACT_INPUT" && "$KERNEL_ARTIFACT_INPUT" != /* ]]; then
	KERNEL_ARTIFACT_DIR="$REPO_ROOT/$KERNEL_ARTIFACT_INPUT"
else
	KERNEL_ARTIFACT_DIR="$KERNEL_ARTIFACT_INPUT"
fi
MAP_EXPORT_ENDPOINT="${TEST_VM_MAP_EXPORT_ENDPOINT:-}"
LEGACY_MAP_EXPORT_TENANT_ID="${TEST_VM_MAP_EXPORT_TENANT_ID:-}"
MAP_EXPORT_INSECURE="${TEST_VM_MAP_EXPORT_INSECURE:-}"
MAP_EXPORT_CA="${TEST_VM_MAP_EXPORT_CA:-}"
OCI_CA="${TEST_VM_OCI_CA:-}"
BPM_TREE_CONFIG="${TEST_VM_BPM_TREE_CONFIG:-}"
PACKAGE_CERT="${TEST_VM_PACKAGE_CERT:-}"
BPM_OCI_REPOSITORY_RAW="${TEST_VM_BPM_OCI_REPOSITORY:-}"
BPM_OCI_INDEX_REPOSITORY="${TEST_VM_BPM_OCI_INDEX_REPOSITORY:-}"
BPM_OCI_INDEX_CERT="${TEST_VM_BPM_OCI_INDEX_CERT:-}"
BPM_OCI_SOURCE="default"
BPM_OCI_ENDPOINT=""
MAP_EXPORT_TENANT_ID=""
MAP_EXPORT_ENABLED=0
RUN_DIR=""
SSH_DIR=""
SSH_KEY=""
SSH_PORT=""
SSH_PUBLIC_KEY=""
SSH_PORT_LOCK_FD=""
SWTPM_PIDFILE=""
SWTPM_UNIT_FILE=""
QEMU_PID=""
QEMU_UNIT_FILE=""
QEMU_STATUS=1
PROGRESS_LINES=0
GUEST_STATUS=""
SERVE_STATUS=0
GUEST_MEMORY_REPORT=""
HOST_MEMORY_REPORT=""
FAILURE_LOG_DIR=""
FINAL_STATUS=1
LEAVE_RUNNING=0
# Each entry is command:Debian package:RPM package.
HOST_DEPENDENCIES=(
	"curl:curl:curl"
	"sha256sum:coreutils:coreutils"
	"awk:mawk:gawk"
	"${QEMU_BIN}:${TEST_VM_ARCH_QEMU_DEB}:${TEST_VM_ARCH_QEMU_RPM}"
	"qemu-img:qemu-utils:qemu-img"
	"swtpm:swtpm:swtpm"
	"cloud-localds:cloud-image-utils:xorriso"
	"timeout:coreutils:coreutils"
	"flock:util-linux:util-linux"
	"ssh-keygen:openssh-client:openssh-clients"
	"ss:iproute2:iproute"
)

SSH_PORT_MIN=22000
SSH_PORT_MAX=22999

log()
{
	printf '[test-vm] %s\n' "$*" >&2
}

summary_log()
{
	printf '[test-vm] %s\n' "$*"
}

die()
{
	log "error: $*"
	exit 1
}

valid_vm_name()
{
	[[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$ ]]
}

validate_mode()
{
	[[ "$TEST_MODE" == verity ]] || die "TEST_VM_MODE must be verity"
	[[ -z "$SERVE_COMMAND" || ( "$VM_MODE" == serve && -x "$SERVE_COMMAND" ) ]] ||
		die "TEST_VM_SERVE_COMMAND must name a program, in serve mode"
	case "$VM_ROLE" in
	target)
		[[ -z "$OPERATOR_KEYS" ]] ||
			die "only an operator VM gets TEST_VM_OPERATOR_KEYS"
		;;
	operator)
		[[ "$VM_MODE" == serve && -n "$SERVE_COMMAND" && "$VM_INITRD" == 0 ]] ||
			die "an operator VM runs in serve mode with TEST_VM_SERVE_COMMAND and TEST_VM_INITRD=0"
		[[ -s "$OPERATOR_KEYS/signing_key.pem" ]] ||
			die "TEST_VM_OPERATOR_KEYS must name the directory of the operator's signing key"
		return 0
		;;
	*)
		die "TEST_VM_ROLE must be 'target' or 'operator'"
		;;
	esac
	if [[ "$VM_SUITE" != register ]]; then
		[[ "$VM_INITRD" == 1 && "$SKIP_SEAL" == 0 ]] ||
			die "dm-verity requires TEST_VM_INITRD=1 and TEST_VM_SKIP_SEAL=0"
	fi
	case "$VM_MODE" in
	interactive|serve|test) ;;
	node)
		[[ "$VM_SUITE" == end2end ]] ||
			die "node mode boots a node of the end2end suite only"
		[[ "$NODE_ROLE" == core || "$NODE_ROLE" == edge ]] ||
			die "TEST_VM_NODE_ROLE must be 'core' or 'edge'"
		;;
	*) die "VM_MODE must be 'interactive', 'serve', 'test' or 'node'" ;;
	esac
	case "$VM_SUITE" in
	'')
		[[ "$VM_MODE" == interactive ]] ||
			die "$VM_MODE mode requires TEST_VM_SUITE: register or a test family"
		;;
	register)
		[[ "$VM_MODE" == test && "$VM_INITRD" == 0 && "$SKIP_SEAL" == 0 ]] ||
			die "register suite requires test mode without a production initrd"
		;;
	end2end) ;;
	*)
		[[ "$VM_SUITE" =~ ^[a-z0-9-]+$ &&
		   -d "$REPO_ROOT/testing/functional/$VM_SUITE" ]] ||
			die "TEST_VM_SUITE must be register, end2end or a directory of testing/functional: $VM_SUITE"
		;;
	esac
	case "$SKIP_SEAL" in
	0|1) ;;
	*) die "TEST_VM_SKIP_SEAL must be '0' or '1'" ;;
	esac
	case "$VM_INITRD" in
	0|1) ;;
	*) die "TEST_VM_INITRD must be '0' or '1'" ;;
	esac
}

validate_private_dir()
{
	local dir repo

	[[ -n "$PRIVATE_DIR" ]] || return 0
	dir="$(realpath -m "$PRIVATE_DIR")"
	repo="$(realpath -m "$REPO_ROOT")"
	[[ "$dir" != "$repo"/* && ! -e "$dir" ]] ||
		die "TEST_VM_PRIVATE_DIR must name a new directory outside the repository"
	PRIVATE_DIR="$dir"
}

validate_map_export()
{
	local configured=0

	if [[ -n "$VM_TENANT" && -n "$LEGACY_MAP_EXPORT_TENANT_ID" &&
	      "$VM_TENANT" != "$LEGACY_MAP_EXPORT_TENANT_ID" ]]; then
		die "VM_TENANT and TEST_VM_MAP_EXPORT_TENANT_ID conflict"
	fi
	if [[ -z "$VM_TENANT" ]]; then
		VM_TENANT="$LEGACY_MAP_EXPORT_TENANT_ID"
	fi
	MAP_EXPORT_TENANT_ID="$VM_TENANT"

	[[ -n "$MAP_EXPORT_ENDPOINT" ]] && configured=$((configured + 1))
	[[ -n "$MAP_EXPORT_INSECURE" ]] && configured=$((configured + 1))
	[[ -n "$MAP_EXPORT_CA" ]] && configured=$((configured + 1))
	if (( configured == 0 )); then
		return
	fi
	[[ -n "$MAP_EXPORT_TENANT_ID" ]] ||
		die "TEST_VM_MAP_EXPORT_ENDPOINT and VM_TENANT must be set together"
	[[ -n "$MAP_EXPORT_ENDPOINT" ]] ||
		die "TEST_VM_MAP_EXPORT_CA and TEST_VM_MAP_EXPORT_INSECURE require TEST_VM_MAP_EXPORT_ENDPOINT"
	if [[ -z "$MAP_EXPORT_INSECURE" ]]; then
		MAP_EXPORT_INSECURE=false
	fi
	[[ "$MAP_EXPORT_INSECURE" == "true" ||
	   "$MAP_EXPORT_INSECURE" == "false" ]] ||
		die "TEST_VM_MAP_EXPORT_INSECURE must be true or false"
	case "$MAP_EXPORT_ENDPOINT" in
	https://*)
		[[ "$MAP_EXPORT_INSECURE" == "false" ]] ||
			die "HTTPS map-export endpoints require TEST_VM_MAP_EXPORT_INSECURE=false"
		;;
	http://*)
		[[ "$MAP_EXPORT_INSECURE" == "true" ]] ||
			die "HTTP map-export endpoints require TEST_VM_MAP_EXPORT_INSECURE=true"
		;;
	*)
		die "TEST_VM_MAP_EXPORT_ENDPOINT must use http:// or https://"
		;;
	esac
	if [[ -n "$MAP_EXPORT_CA" ]]; then
		[[ -f "$MAP_EXPORT_CA" && -r "$MAP_EXPORT_CA" ]] ||
			die "TEST_VM_MAP_EXPORT_CA is not a readable regular file: $MAP_EXPORT_CA"
	fi
	[[ ${#MAP_EXPORT_ENDPOINT} -lt 2048 ]] ||
		die "TEST_VM_MAP_EXPORT_ENDPOINT is too long"
	[[ "$MAP_EXPORT_ENDPOINT" != *[[:space:]]* ]] ||
		die "TEST_VM_MAP_EXPORT_ENDPOINT must not contain whitespace"
	[[ "$MAP_EXPORT_TENANT_ID" =~ ^[A-Za-z0-9._-]{1,128}$ ]] ||
		die "VM_TENANT must contain 1..128 characters from A-Z, a-z, 0-9, '.', '_', '-'"
	MAP_EXPORT_ENABLED=1
}

validate_oci_ca()
{
	if [[ -n "$OCI_CA" ]]; then
		[[ -f "$OCI_CA" && -r "$OCI_CA" && -s "$OCI_CA" ]] ||
			die "TEST_VM_OCI_CA is not a readable, non-empty regular file: $OCI_CA"
	fi
}

validate_package_cert()
{
	[[ -z "$PACKAGE_CERT" ]] && return 0
	[[ "$VM_MODE" == interactive ]] ||
		die "TEST_VM_PACKAGE_CERT is supported only for interactive make -C testing vm"
	[[ -f "$PACKAGE_CERT" && -r "$PACKAGE_CERT" && -s "$PACKAGE_CERT" ]] ||
		die "TEST_VM_PACKAGE_CERT is not a readable, non-empty regular file: $PACKAGE_CERT"
}

validate_bpm_tree_config()
{
	[[ -z "$BPM_TREE_CONFIG" ]] && return 0
	[[ "$VM_MODE" == interactive ]] ||
		die "TEST_VM_BPM_TREE_CONFIG is supported only for interactive make -C testing vm"
	[[ -f "$BPM_TREE_CONFIG" && -r "$BPM_TREE_CONFIG" && -s "$BPM_TREE_CONFIG" ]] ||
		die "TEST_VM_BPM_TREE_CONFIG is not a readable, non-empty regular file: $BPM_TREE_CONFIG"
}

validate_bpm_oci()
{
	if [[ -z "$BPM_OCI_REPOSITORY_RAW" && -z "$BPM_OCI_INDEX_CERT" ]]; then
		return 0
	fi
	[[ -n "$BPM_OCI_REPOSITORY_RAW" && -n "$BPM_OCI_INDEX_CERT" ]] ||
		die "TEST_VM_BPM_OCI_REPOSITORY and TEST_VM_BPM_OCI_INDEX_CERT must be set together"
	case "$BPM_OCI_REPOSITORY_RAW" in
	*=oci://*)
		BPM_OCI_SOURCE="${BPM_OCI_REPOSITORY_RAW%%=*}"
		BPM_OCI_ENDPOINT="${BPM_OCI_REPOSITORY_RAW#*=}"
		;;
	oci://*)
		BPM_OCI_ENDPOINT="$BPM_OCI_REPOSITORY_RAW"
		;;
	*)
		die "TEST_VM_BPM_OCI_REPOSITORY must be oci://host or name=oci://host"
		;;
	esac
	[[ "$BPM_OCI_SOURCE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] ||
		die "TEST_VM_BPM_OCI_REPOSITORY source name is invalid"
	[[ "$BPM_OCI_ENDPOINT" =~ ^oci://[^/!?#@=[:space:]]+$ ]] ||
		die "TEST_VM_BPM_OCI_REPOSITORY must use an oci://host endpoint"
	[[ ${#BPM_OCI_ENDPOINT} -lt 512 ]] ||
		die "TEST_VM_BPM_OCI_REPOSITORY is too long"
	[[ -f "$BPM_OCI_INDEX_CERT" && -r "$BPM_OCI_INDEX_CERT" && -s "$BPM_OCI_INDEX_CERT" ]] ||
		die "TEST_VM_BPM_OCI_INDEX_CERT is not a readable, non-empty regular file: $BPM_OCI_INDEX_CERT"
	[[ -n "$BPM_OCI_INDEX_REPOSITORY" ]] ||
		die "TEST_VM_BPM_OCI_INDEX_REPOSITORY must be set"
	[[ "$BPM_OCI_INDEX_REPOSITORY" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*/bpm-index$ ]] ||
		die "TEST_VM_BPM_OCI_INDEX_REPOSITORY must end in /bpm-index"
}

# The tool that builds the cloud-init seed: cloud-localds, or an ISO 9660
# writer where that is not packaged, as on RHEL.
seed_tool()
{
	local tool

	for tool in cloud-localds xorriso genisoimage mkisofs; do
		if command -v "$tool" >/dev/null 2>&1; then
			printf '%s\n' "$tool"
			return 0
		fi
	done
	return 1
}

# A NoCloud seed is a file system labelled cidata that holds the user-data,
# meta-data and network-config files.
make_seed()
{
	local -a writer
	local tool

	tool="$(seed_tool)" || die "no tool to build the cloud-init seed"
	if [[ "$tool" == cloud-localds ]]; then
		cloud-localds --network-config="$NETWORK_CONFIG" "$SEED" \
			"$USER_DATA" "$META_DATA"
		return
	fi
	writer=("$tool")
	[[ "$tool" != xorriso ]] || writer+=(-as mkisofs)
	"${writer[@]}" -quiet -volid cidata -joliet -rock -output "$SEED" \
		"$USER_DATA" "$META_DATA" "$NETWORK_CONFIG" >/dev/null
}

# cloud-localds stands for any tool that make_seed can use.
have_command()
{
	if [[ "$1" == cloud-localds ]]; then
		seed_tool >/dev/null
	else
		command -v "$1" >/dev/null 2>&1
	fi
}

print_dependency_install_command()
{
	printf '  %s\n' "$(test_vm_install_cmd "$@")"
}

check_host_dependencies()
{
	local command_name
	local deb_package
	local package
	local requirement
	local rpm_package
	local -a missing_commands=()
	local -a missing_packages=()
	local -A package_seen=()

	for requirement in "${HOST_DEPENDENCIES[@]}"; do
		IFS=: read -r command_name deb_package rpm_package <<<"$requirement"
		package="$(test_vm_pkg "$deb_package" "$rpm_package")"
		if ! have_command "$command_name"; then
			missing_commands+=("$command_name")
			if [[ -z "${package_seen[$package]+present}" ]]; then
				missing_packages+=("$package")
				package_seen[$package]=1
			fi
		fi
	done

	if (( ${#missing_commands[@]} != 0 )); then
		log "error: missing host commands: ${missing_commands[*]}"
		log "Install them with:"
		print_dependency_install_command "${missing_packages[@]}" >&2
		exit 1
	fi
}

valid_sha256()
{
	[[ "$1" =~ ^[[:xdigit:]]{64}$ ]]
}

validate_kernel_selection()
{
	if [[ -n "$KERNEL_OVERRIDE" && -n "$KERNEL_URL" ]]; then
		die "TEST_VM_KERNEL and TEST_VM_KERNEL_URL are mutually exclusive"
	fi
	if [[ -n "$KERNEL_URL" ]]; then
		valid_sha256 "$KERNEL_SHA256" ||
			die "TEST_VM_KERNEL_URL requires a 64-character TEST_VM_KERNEL_SHA256"
	elif [[ -n "$KERNEL_OVERRIDE" ]]; then
		[[ -s "$KERNEL_OVERRIDE" ]] ||
			die "kernel image not found: $KERNEL_OVERRIDE"
	else
		[[ -s "$DEFAULT_KERNEL" ]] ||
			die "kernel image not found: $DEFAULT_KERNEL; stage a CI kernel artifact there"
	fi
}

validate_kernel_artifact()
{
	[[ -z "$KERNEL_ARTIFACT_DIR" ]] && return 0
	[[ -d "$KERNEL_ARTIFACT_DIR/lib/modules" ]] ||
		die "kernel artifact has no lib/modules directory: $KERNEL_ARTIFACT_DIR"
}

validate_host_bundle()
{
	local runtime_key runtime_image policy_fixture
	[[ -x "$TEST_VM_HOST_BUNDLE/root/usr/local/bin/shirudo" ]] ||
		die "host VM bundle is missing; run 'make -C testing test-vm-bundle' first: $TEST_VM_HOST_BUNDLE"
	[[ -s "$TEST_VM_HOST_BUNDLE/fixtures/cert.der" ]] ||
		die "host VM bundle has no target-test certificate: $TEST_VM_HOST_BUNDLE"
	[[ -s "$TEST_VM_HOST_BUNDLE/fixtures/shirudo-test-basic.upatch" ]] ||
		die "host VM bundle has no target-test fixtures: $TEST_VM_HOST_BUNDLE"
	if [[ "$VM_SUITE" == end2end ]]; then
		[[ -s "$TEST_VM_HOST_BUNDLE/fixtures/kernel-obs.upatch" ]] ||
			die "host VM bundle has no kernel-obs fixture: $TEST_VM_HOST_BUNDLE"
		policy_fixture="$TEST_VM_HOST_BUNDLE/fixtures/shirudo-test-policy-exec-graph.upatch"
		[[ -s "$policy_fixture" ]] ||
			die "host VM bundle has no policy exec graph fixture: $TEST_VM_HOST_BUNDLE"
	elif [[ "$VM_SUITE" == bpm ]]; then
		[[ -s "$TEST_VM_HOST_BUNDLE/fixtures/tree-oci/shirudo/upatch-tree/manifests/stable" &&
		   -s "$TEST_VM_HOST_BUNDLE/fixtures/shirudo-test-tree-match.upatch" &&
		   -s "$TEST_VM_HOST_BUNDLE/fixtures/shirudo-test-tree-skip.upatch" ]] ||
			die "host VM bundle has no BPM tree fixtures: $TEST_VM_HOST_BUNDLE"
	fi
	[[ -s "$TEST_VM_HOST_BUNDLE/runtime-image-key" ]] ||
		die "host VM bundle has no prepared runtime image; run 'make -C testing bundle'"
	runtime_key="$(<"$TEST_VM_HOST_BUNDLE/runtime-image-key")"
	[[ "$runtime_key" =~ ^rootfs-[0-9a-f]{64}-packages-[0-9a-f]{64}(-disk-[A-Za-z0-9_]+)?-v[0-9]+$ ]] ||
		die "host VM bundle has an invalid prepared runtime image key"
	runtime_image="$RUNTIME_CACHE_DIR/$runtime_key.qcow2"
	[[ -s "$runtime_image" ]] ||
		die "prepared runtime image is missing: $runtime_image; run 'make -C testing bundle'"
}

# A node is stopped from outside, so its counters are asked for first. A
# VM that does not answer at once has none worth the wait.
collect_coverage()
{
	local dir="$1" key="$1/ssh/id_ed25519"

	[[ -d "$TEST_VM_HOST_BUNDLE/coverage" && -s "$dir/ssh.port" ]] || return 0
	[[ ! -s "$dir/ssh.key" ]] || key="$(<"$dir/ssh.key")"
	[[ -r "$key" ]] || return 0
	SSH_DIR="$dir/ssh"
	SSH_KEY="$key"
	SSH_PORT="$(<"$dir/ssh.port")"
	ssh_options
	timeout 30 ssh "${SSH_ARGS[@]}" -o BatchMode=yes root@127.0.0.1 \
		"$GCOV_COLLECT" </dev/null >/dev/null 2>&1 || true
}

# The result directory goes with the next VM of the name.
keep_coverage()
{
	local dir="$1"

	[[ -s "$dir/result/gcov.tar" ]] || return 0
	mkdir -p "$COVERAGE_DIR"
	mv -- "$dir/result/gcov.tar" \
		"$(mktemp --suffix=.tar "$COVERAGE_DIR/$(basename "$dir").XXXXXX")"
}

vm_has_builder()
{
	[[ "$VM_MODE" == node || "$VM_MODE" == interactive ]]
}

# The bindings of every VM whose builder wrote an enroll.json, in one file
# for one enroll-put: those enrolled before are loaded again, which
# changes nothing.
merge_enroll_files()
{
	local files=("$VMS_DIR"/*/enroll.json)

	[[ -s "${files[0]}" ]] ||
		die "no VM under $VMS_DIR has an enroll.json; start one with 'make -C testing vm'"
	python3 - "$VM_ROOT/enroll.json" "${files[@]}" <<'PY'
import json, sys
nodes = [n for path in sys.argv[2:] for n in json.load(open(path))["nodes"]]
with open(sys.argv[1], "w") as f:
    f.write('{"source": "test-vm", "nodes": [\n')
    f.write(",\n".join(" " + json.dumps(n) for n in nodes))
    f.write("\n]}\n")
PY
}

# The builds the VMs of directories $@ boot, each once.
shirudo_builds()
{
	local dir

	for dir; do
		[[ ! -s "$dir/shirudo-build" ]] || cat "$dir/shirudo-build"
	done | sort -u
}

run_enroll()
{
	local builds

	if [[ -z "$VM_NAME_REQUEST" ]]; then
		merge_enroll_files
		mapfile -t builds < <(shirudo_builds "$VMS_DIR"/*/)
		exec "$REPO_ROOT/testing/vm/stack.sh" enroll "$VM_ROOT/enroll.json" "${builds[@]}"
	fi
	select_named_run_dir
	[[ -s "$RUN_DIR/enroll.json" ]] ||
		die "VM '$VM_NAME' has no enroll.json: only 'make vm' and end2end nodes have a builder"
	mapfile -t builds < <(shirudo_builds "$RUN_DIR")
	exec "$REPO_ROOT/testing/vm/stack.sh" enroll "$RUN_DIR/enroll.json" "${builds[@]}"
}

# An interactive VM runs the runtime image, which it names in os-release
# as the image test-vm, so that the backend reads the SBOM make vm-sbom
# loads for it. The version stands for the runtime image key.
record_image()
{
	IMAGE_VERSION="$(printf '%s' "$RUNTIME_KEY" | sha256sum | cut -c1-12)"
	printf 'test-vm\t%s\t%s\n' "$IMAGE_VERSION" "$RUNTIME_KEY" >"$RUN_DIR/image"
}

# The images the VMs of directories $@ run, each once, a line of image_id,
# image_version and runtime image key apiece.
vm_images()
{
	local dir

	for dir; do
		[[ ! -s "$dir/image" ]] || cat "$dir/image"
	done | sort -u
}

run_sbom()
{
	local images image_id image_version runtime_key sbom line args=()

	if [[ -z "$VM_NAME_REQUEST" ]]; then
		mapfile -t images < <(vm_images "$VMS_DIR"/*/)
		[[ ${#images[@]} -gt 0 ]] ||
			die "no VM under $VMS_DIR names its image; start one with 'make -C testing vm'"
	else
		select_named_run_dir
		mapfile -t images < <(vm_images "$RUN_DIR")
		[[ ${#images[@]} -gt 0 ]] ||
			die "VM '$VM_NAME' names no image: only 'make vm' names one"
	fi
	if [[ -s "$CACHE_DIR/libguestfs/supermin.env" ]]; then
		# shellcheck source=/dev/null
		. "$CACHE_DIR/libguestfs/supermin.env"
	fi
	# The SBOM is kept beside its image, so that the bytes sbom-put
	# stores once are the same at every run.
	for line in "${images[@]}"; do
		IFS=$'\t' read -r image_id image_version runtime_key <<<"$line"
		sbom="$RUNTIME_CACHE_DIR/$runtime_key.cdx.json"
		if [[ ! -s "$sbom" ]]; then
			log "writing the SBOM of runtime image $runtime_key"
			"$REPO_ROOT/testing/vm/runtime-sbom.sh" \
				"$RUNTIME_CACHE_DIR/$runtime_key.qcow2" "$sbom"
		fi
		args+=("$image_id" "$image_version" "$sbom")
	done
	exec "$REPO_ROOT/testing/vm/stack.sh" sbom "${args[@]}"
}

start_swtpm()
{
	local _

	chmod 0700 "$RUN_DIR/tpm"
	# An end2end node's or an interactive VM's TPM comes from a builder the
	# operator trusts, which records the names of its keys before the guest
	# boots, and carries an endorsement certificate from its maker's CA.
	if vm_has_builder; then
		HOST_LD_LIBRARY_PATH="$HOST_LD_LIBRARY_PATH" \
		"$REPO_ROOT/testing/vm/tpm-builder.sh" "$RUN_DIR/tpm" "$RUN_DIR/tpm-names" \
			"$RUN_DIR/ek-ca.pem" "$RUN_DIR/enroll.json" "$VM_NAME" \
			>>"$RUN_DIR/swtpm.log" 2>&1 ||
			die "could not create the keys of the vTPM; see $RUN_DIR/swtpm.log"
		# The build the VM boots, for the operator to allow as it enrolls
		# the keys; the binary needs no TPM to say it.
		"$TEST_VM_HOST_BUNDLE/root/usr/local/bin/shirudo" version --version-id \
			>"$RUN_DIR/shirudo-build" 2>>"$RUN_DIR/swtpm.log" ||
			die "cannot read the version_id of the bundle's shirudo; see $RUN_DIR/swtpm.log"
		log "builder's records of the vTPM keys and the build: $RUN_DIR/enroll.json, $RUN_DIR/shirudo-build (make vm-enroll loads them)"
	fi
	if user_systemd_available; then
		SWTPM_UNIT_FILE="${RUN_DIR}/swtpm.unit"
		SWTPM_UNIT="shirudo-vm-${VM_NAME}-swtpm.service"
		start_user_unit "$SWTPM_UNIT" "$RUN_DIR/swtpm.log" \
			swtpm socket --tpmstate "dir=${RUN_DIR}/tpm,mode=0700" \
				--ctrl "type=unixio,path=tpm/swtpm-sock" \
				--tpm2 --log "file=${RUN_DIR}/swtpm.log,level=20"
		printf '%s\n' "$SWTPM_UNIT" >"$SWTPM_UNIT_FILE"
		SWTPM_PID="$(user_unit_pid "$SWTPM_UNIT")" || die "could not determine swtpm systemd PID"
		printf '%s\n' "$SWTPM_PID" >"$SWTPM_PIDFILE"
	else
		# Ubuntu's AppArmor profile for swtpm closes an inherited terminal, and
		# swtpm --daemon never returns when it starts without fds 0 to 2.
		swtpm socket --tpmstate "dir=${RUN_DIR}/tpm,mode=0700" \
			--ctrl "type=unixio,path=tpm/swtpm-sock" \
			--tpm2 --log "file=${RUN_DIR}/swtpm.log,level=20" \
			--pid "file=${SWTPM_PIDFILE}" --daemon </dev/null 2>&1 |
			sed 's/^/[test-vm] swtpm: /' >&2
	fi
	for _ in {1..50}; do
		[[ -S "$SWTPM_SOCKET" ]] && return 0
		sleep 0.1
	done
	die "swtpm control socket did not appear"
}

stop_swtpm()
{
	local pid

	if [[ -n "$SWTPM_UNIT_FILE" ]]; then
		stop_user_unit_file "$SWTPM_UNIT_FILE"
		SWTPM_UNIT_FILE=""
	fi
	[[ -n "$SWTPM_PIDFILE" && -s "$SWTPM_PIDFILE" ]] || return 0
	pid="$(<"$SWTPM_PIDFILE")"
	[[ "$pid" =~ ^[0-9]+$ ]] || { rm -f -- "$SWTPM_PIDFILE"; return 0; }
	if kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
		for _ in {1..20}; do
			kill -0 "$pid" 2>/dev/null || break
			sleep 0.1
		done
		kill -KILL "$pid" 2>/dev/null || true
	fi
	rm -f -- "$SWTPM_PIDFILE"
}

stop_qemu()
{
	[[ -n "$QEMU_PID" ]] || return 0
	if [[ -n "$QEMU_UNIT_FILE" ]]; then
		stop_user_unit_file "$QEMU_UNIT_FILE"
		QEMU_UNIT_FILE=""
	fi
	if kill -0 "$QEMU_PID" 2>/dev/null; then
		kill "$QEMU_PID" 2>/dev/null || true
		for _ in {1..50}; do
			kill -0 "$QEMU_PID" 2>/dev/null || break
			sleep 0.1
		done
		kill -KILL "$QEMU_PID" 2>/dev/null || true
	fi
	if [[ -n "$RUN_DIR" ]]; then
		rm -f -- "$RUN_DIR/qemu.pid"
	fi
	QEMU_PID=""
}

stop_user_unit_file()
{
	local unit_file="$1" unit

	[[ -s "$unit_file" ]] || return 0
	unit="$(<"$unit_file")"
	if [[ "$unit" =~ ^[A-Za-z0-9_.@:-]+\.service$ ]]; then
		systemctl --user stop "$unit" 2>/dev/null || true
		systemctl --user reset-failed "$unit" 2>/dev/null || true
	fi
	rm -f -- "$unit_file"
}

user_systemd_available()
{
	command -v systemd-run >/dev/null 2>&1 &&
		command -v systemctl >/dev/null 2>&1 &&
		systemctl --user show-environment >/dev/null 2>&1
}

start_user_unit()
{
	local unit="$1" log_path="$2"
	shift 2

	systemctl --user stop "$unit" >/dev/null 2>&1 || true
	systemctl --user reset-failed "$unit" >/dev/null 2>&1 || true
	systemd-run --user --unit="$unit" --collect \
		--working-directory="$RUN_DIR" \
		--property=KillMode=mixed \
		--property="StandardOutput=append:$log_path" \
		--property="StandardError=append:$log_path" \
		-- "$@" >/dev/null
}

user_unit_pid()
{
	local unit="$1" pid
	for _ in {1..50}; do
		pid="$(systemctl --user show --value --property=MainPID "$unit" 2>/dev/null || true)"
		if [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then
			printf '%s\n' "$pid"
			return 0
		fi
		sleep 0.1
	done
	return 1
}

stop_pid_file()
{
	local pidfile="$1" pid cmdline state_dir expected

	[[ -s "$pidfile" ]] || return 0
	pid="$(<"$pidfile")"
	[[ "$pid" =~ ^[0-9]+$ ]] || { rm -f -- "$pidfile"; return 0; }
	state_dir="$(dirname "$pidfile")"
	expected=swtpm
	if [[ "$(basename "$pidfile")" == qemu.pid ]]; then
		state_dir="$(dirname "$state_dir")"
		expected="$QEMU_BIN"
	fi
	if kill -0 "$pid" 2>/dev/null; then
		cmdline="$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)"
		if [[ "$cmdline" == *"$expected"* && "$cmdline" == *"$state_dir"* ]]; then
			kill "$pid" 2>/dev/null || true
			for _ in {1..50}; do
				kill -0 "$pid" 2>/dev/null || break
				sleep 0.1
			done
			kill -KILL "$pid" 2>/dev/null || true
		fi
	fi
	rm -f -- "$pidfile"
}

check_access_dependency()
{
	local command_name="$1"

	command -v "$command_name" >/dev/null 2>&1 ||
		die "missing host command: $command_name"
}

select_named_run_dir()
{
	[[ -n "$VM_NAME_REQUEST" ]] ||
		die "VM_NAME is required for VM console/SSH access"
	valid_vm_name "$VM_NAME_REQUEST" ||
		die "VM_NAME must start with an alphanumeric and contain only A-Z, a-z, 0-9, '.', '_', or '-' (max 63 characters)"
	RUN_DIR="${VMS_DIR}/${VM_NAME_REQUEST}"
	[[ -d "$RUN_DIR" ]] ||
		die "VM_NAME '$VM_NAME_REQUEST' has no state directory under $VMS_DIR"
	VM_NAME="$VM_NAME_REQUEST"
}

select_latest_run_dir()
{
	local vm_dir vm_name created_at latest_created_at latest_vm_name

	[[ -d "$VMS_DIR" ]] || die "no saved VM states found under $VMS_DIR"
	latest_created_at=""
	latest_vm_name=""
	for vm_dir in "$VMS_DIR"/*/; do
		[[ -d "$vm_dir" ]] || continue
		[[ -s "${vm_dir}created-at" ]] ||
			die "VM state '$(basename "$vm_dir")' has no creation timestamp; run 'make -C testing vm-clean'"
		created_at="$(<"${vm_dir}created-at")"
		[[ "$created_at" =~ ^[0-9]{19}$ ]] ||
			die "VM state '$(basename "$vm_dir")' has an invalid creation timestamp"
		vm_name="$(basename "$vm_dir")"
		if [[ -z "$latest_created_at" ||
		      "$created_at" > "$latest_created_at" ||
		      ( "$created_at" == "$latest_created_at" &&
		        "$vm_name" > "$latest_vm_name" ) ]]; then
			latest_created_at="$created_at"
			latest_vm_name="$vm_name"
		fi
	done
	[[ -n "$latest_vm_name" ]] || die "no saved VM states found under $VMS_DIR"
	VM_NAME="$latest_vm_name"
	RUN_DIR="${VMS_DIR}/${VM_NAME}"
}

require_running_vm()
{
	local pid cmdline

	select_named_run_dir
	[[ -s "$RUN_DIR/qemu.pid" ]] ||
		die "VM '$VM_NAME' is not running; start it with 'make -C testing vm VM_NAME=$VM_NAME'"
	pid="$(<"$RUN_DIR/qemu.pid")"
	[[ "$pid" =~ ^[0-9]+$ ]] ||
		die "VM '$VM_NAME' has an invalid QEMU PID file"
	if ! kill -0 "$pid" 2>/dev/null; then
		die "VM '$VM_NAME' is not running; start it with 'make -C testing vm VM_NAME=$VM_NAME'"
	fi
	cmdline="$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)"
	[[ "$cmdline" == *"$QEMU_BIN"* &&
	   "$cmdline" == *"$RUN_DIR"* ]] ||
		die "VM '$VM_NAME' has a stale or unrelated QEMU PID file"
}

run_console()
{
	require_running_vm
	check_access_dependency socat
	[[ -S "$RUN_DIR/console.sock" ]] ||
		die "VM '$VM_NAME' has no serial console socket"
	log "attaching to VM console: $VM_NAME (Ctrl-] detaches)"
	cd "$RUN_DIR" || die "cannot enter $RUN_DIR"
	exec socat 'STDIO,raw,echo=0,escape=0x1d' UNIX-CONNECT:console.sock
}

ssh_options()
{
	SSH_ARGS=(
		-F /dev/null
		-o ConnectTimeout=2
		-o ConnectionAttempts=1
		-o IdentitiesOnly=yes
		-o StrictHostKeyChecking=accept-new
		-o GlobalKnownHostsFile=/dev/null
		-o UserKnownHostsFile="${SSH_DIR}/known_hosts"
		-o IdentityFile="$SSH_KEY"
		-o ServerAliveInterval=15
		-o ServerAliveCountMax=8
		-p "$SSH_PORT"
	)
}

wait_for_ssh()
{
	local _

	for _ in {1..60}; do
		ssh "${SSH_ARGS[@]}" -o BatchMode=yes root@127.0.0.1 true \
			</dev/null >/dev/null 2>&1 && return 0
		sleep 1
	done
	return 1
}

# The family's target tests, run in the prepared guest from an SSH session
# with the environment the guest wrote for them. What they print goes to
# the guest log, where test mode puts it.
run_target_tests_over_ssh()
{
	local guest_log="$RUN_DIR/result/guest.log" pid status

	ssh_options
	wait_for_ssh || {
		log "error: SSH did not become ready for VM '$VM_NAME'"
		return 255
	}
	log "running target tests over SSH: $VM_SUITE"
	: >>"$guest_log"
	GUEST_LOG_BYTES="$(wc -c <"$guest_log")"
	ssh "${SSH_ARGS[@]}" -o BatchMode=yes root@127.0.0.1 \
		"cd /workspace/shirudo/testing && . /etc/shirudo-test-vm.env && exec ./run-target-tests.sh $VM_SUITE" \
		</dev/null >>"$guest_log" 2>&1 &
	pid=$!
	while kill -0 "$pid" 2>/dev/null; do
		show_progress
		sleep 0.2
	done
	wait "$pid"
	status=$?
	show_progress
	return "$status"
}

# The serve command runs with the caller's environment, less what made this
# VM an operator and the file of its SSH key, since it boots other VMs.
run_serve_command()
{
	log "running $(basename "$SERVE_COMMAND") for VM '$VM_NAME'"
	env -u TEST_VM_ROLE -u TEST_VM_SERVE_COMMAND -u TEST_VM_OPERATOR_KEYS \
		-u TEST_VM_PRIVATE_DIR \
		${HOST_LD_LIBRARY_PATH:+LD_LIBRARY_PATH="$HOST_LD_LIBRARY_PATH"} \
		"$SERVE_COMMAND" "$VM_NAME" </dev/null
}

# A serve-mode guest that prepared itself waits for the host-done marker in
# its result share, then powers itself off as a test-mode guest does.
serve_target_tests()
{
	local guest_status="" _

	if [[ -s "$RUN_DIR/result/status" ]]; then
		guest_status="$(<"$RUN_DIR/result/status")"
	fi
	[[ "$guest_status" == 0 ]] || return 0
	if [[ -n "$SERVE_COMMAND" ]]; then
		run_serve_command
	else
		run_target_tests_over_ssh
	fi
	SERVE_STATUS=$?
	: >"$RUN_DIR/result/host-done"
	for _ in {1..1200}; do
		kill -0 "$QEMU_PID" 2>/dev/null || return 0
		sleep 0.1
	done
	die "VM '$VM_NAME' did not power off after its target tests (status $SERVE_STATUS)"
}

run_ssh()
{
	if [[ -z "$VM_NAME_REQUEST" ]]; then
		select_latest_run_dir
		VM_NAME_REQUEST="$VM_NAME"
	fi
	require_running_vm
	check_access_dependency ssh
	SSH_DIR="${RUN_DIR}/ssh"
	SSH_KEY="$SSH_DIR/id_ed25519"
	[[ ! -s "$RUN_DIR/ssh.key" ]] || SSH_KEY="$(<"$RUN_DIR/ssh.key")"
	[[ -s "$RUN_DIR/ssh.port" && -r "$SSH_KEY" ]] ||
		die "VM '$VM_NAME' has no SSH access metadata"
	SSH_PORT="$(<"$RUN_DIR/ssh.port")"
	[[ "$SSH_PORT" =~ ^[0-9]+$ ]] ||
		die "VM '$VM_NAME' has an invalid SSH port"
	ssh_options
	wait_for_ssh ||
		die "SSH did not become ready for VM '$VM_NAME'"
	if [[ -n "$VM_SSH_COMMAND" ]]; then
		exec ssh "${SSH_ARGS[@]}" root@127.0.0.1 "$VM_SSH_COMMAND"
	fi
	# Only the runtime image's binary holds authority in the guest, so
	# the shell a person types in names that one shirudo. A script on
	# stdin gets the plain shell, where an alias would not expand.
	if [[ -t 0 ]]; then
		exec ssh -t "${SSH_ARGS[@]}" root@127.0.0.1 \
			'exec bash --rcfile <(cat ~/.bashrc 2>/dev/null; echo "alias shirudo=shirudo-runtime")'
	fi
	exec ssh "${SSH_ARGS[@]}" root@127.0.0.1
}

stop_named_state()
{
	local pidfile unit_file vm_dir

	[[ -n "$VM_NAME_REQUEST" ]] ||
		die "VM_NAME is required for named VM stop/cleanup"
	valid_vm_name "$VM_NAME_REQUEST" ||
		die "VM_NAME must start with an alphanumeric and contain only A-Z, a-z, 0-9, '.', '_', or '-' (max 63 characters)"
	vm_dir="${VMS_DIR}/${VM_NAME_REQUEST}"
	[[ -d "$vm_dir" ]] ||
		die "VM_NAME '$VM_NAME_REQUEST' has no state directory under $VMS_DIR"
	collect_coverage "$vm_dir"
	while IFS= read -r -d '' unit_file; do
		stop_user_unit_file "$unit_file"
	done < <(find "$vm_dir" -type f \( -name qemu.unit -o -name swtpm.unit \) -print0)
	while IFS= read -r -d '' pidfile; do
		stop_pid_file "$pidfile"
	done < <(find "$vm_dir" -type f \( -name qemu.pid -o -name swtpm.pid \) -print0)
	keep_coverage "$vm_dir"
}

stop_all_state()
{
	local pidfile unit_file

	if [[ -d "$VMS_DIR" ]]; then
		while IFS= read -r -d '' unit_file; do
			stop_user_unit_file "$unit_file"
		done < <(find "$VMS_DIR" -type f \( -name qemu.unit -o -name swtpm.unit \) -print0)
		while IFS= read -r -d '' pidfile; do
			stop_pid_file "$pidfile"
		done < <(find "$VMS_DIR" -type f \( -name qemu.pid -o -name swtpm.pid \) -print0)
	fi
}

stop_state()
{
	[[ -n "$VM_ROOT" && "$VM_ROOT" != "/" ]] ||
		die "refusing to stop unsafe VM root '$VM_ROOT'"
	if [[ -n "$VM_NAME_REQUEST" ]]; then
		stop_named_state
		log "stopped VM: $VM_NAME_REQUEST (state preserved)"
	else
		stop_all_state
		log "stopped all tracked VMs (state preserved)"
	fi
}

clean_state()
{
	local pidfile vm_dir

	[[ -n "$VM_ROOT" && "$VM_ROOT" != "/" ]] ||
		die "refusing to clean unsafe VM root '$VM_ROOT'"
	if [[ -n "$VM_NAME_REQUEST" ]]; then
		stop_named_state
		vm_dir="${VMS_DIR}/${VM_NAME_REQUEST}"
		rm -rf -- "$vm_dir" "${LOGS_DIR}/${VM_NAME_REQUEST}"
		log "removed VM state and logs: $VM_NAME_REQUEST"
		return 0
	fi
	# The bundles, the cache and the local stack stay: rebuilding them is
	# slow, and make -C testing clean and make stack-down remove them.
	stop_all_state
	rm -rf -- "$VMS_DIR" "$LOGS_DIR" "$VM_ROOT/enroll.json"
	log "removed the state and logs of every VM under $VM_ROOT"
}

save_failure_logs()
{
	local copied=0
	local path
	local saved

	[[ -n "$RUN_DIR" && -d "$RUN_DIR" ]] || return 0
	saved="${LOGS_DIR}/$(basename "$RUN_DIR")"
	for log_file in console.log qemu.log guest.log swtpm.log failed-tests failed-suites; do
		if [[ -f "$RUN_DIR/$log_file" ]]; then
			path="$RUN_DIR/$log_file"
		elif [[ -f "$RUN_DIR/result/$log_file" ]]; then
			path="$RUN_DIR/result/$log_file"
		else
			continue
		fi
		mkdir -p "$saved"
		cp "$path" "$saved/"
		copied=1
	done
	if [[ "$copied" -eq 1 ]]; then
		FAILURE_LOG_DIR="$saved"
	fi
}

print_memory_summary()
{
	local report

	if [[ -s "$RUN_DIR/result/boot-memory" ]]; then
		report="$(tr '\n' ' ' <"$RUN_DIR/result/boot-memory")"
		summary_log "guest memory: ${report% }"
	fi
	if [[ -s "$HOST_MEMORY_REPORT" ]]; then
		report="$(tr '\n' ' ' <"$HOST_MEMORY_REPORT")"
		summary_log "host QEMU memory: ${report% }"
	fi
}

format_elapsed()
{
	local elapsed="$1"
	local hours minutes seconds

	hours=$((elapsed / 3600))
	minutes=$(((elapsed % 3600) / 60))
	seconds=$((elapsed % 60))
	printf '%02d:%02d:%02d' "$hours" "$minutes" "$seconds"
}

print_test_summary()
{
	local result result_color elapsed guest_log console_log qemu_log failed_tests failed_suites
	local build_mode="unknown"
	local kind script title suite
	local individual_failures=0
	local suite_failures=0
	local bpffs_warning=0
	local result_share_warning=0
	declare -A recorded_suites=()

	[[ "$VM_MODE" == test || "$VM_MODE" == serve ]] || return 0
	[[ -n "$RUN_DIR" && -d "$RUN_DIR" ]] || return 0

	guest_log="$RUN_DIR/result/guest.log"
	console_log="$RUN_DIR/console.log"
	qemu_log="$RUN_DIR/qemu.log"
	failed_tests="$RUN_DIR/result/failed-tests"
	failed_suites="$RUN_DIR/result/failed-suites"
	if [[ -f "$guest_log" ]]; then
		if grep -qF 'host bundle dependency mode: bpf-next-deps' "$guest_log"; then
			build_mode="host bundle (bpf-next deps)"
		elif grep -qF 'host bundle dependency mode: vendored-tools' "$guest_log"; then
			build_mode="host bundle (vendored tools)"
		fi
	fi

	if [[ "$FINAL_STATUS" -eq 0 ]]; then
		result=PASS
		result_color="$COLOR_GREEN"
	else
		result=FAIL
		result_color="$COLOR_RED"
	fi

	summary_log "${COLOR_BOLD}summary${COLOR_RESET}"
	if [[ -n "$GUEST_STATUS" && "$FINAL_STATUS" -ne 0 ]]; then
		summary_log "result: ${result_color}${result}${COLOR_RESET} (guest status $GUEST_STATUS)"
	else
		summary_log "result: ${result_color}${result}${COLOR_RESET}"
	fi
	summary_log "vm: $VM_NAME"
	summary_log "elapsed: $(format_elapsed "$SECONDS")"
	summary_log "bpf-next dependencies: ${COLOR_CYAN}${build_mode}${COLOR_RESET}"
	print_memory_summary

	if [[ "$FINAL_STATUS" -ne 0 ]]; then
		if [[ -s "$failed_tests" ]]; then
			summary_log "${COLOR_RED}failed tests:${COLOR_RESET}"
			while IFS=$'\t' read -r kind script title; do
				[[ "$kind" == test ]] || continue
				script="${script#./}"
				recorded_suites["$script"]=1
				summary_log "  ${COLOR_RED}$script: $title${COLOR_RESET}"
				individual_failures=1
			done <"$failed_tests"
		fi
		if [[ -s "$failed_suites" ]]; then
			while IFS= read -r suite; do
				suite="${suite#./}"
				if [[ -z "${recorded_suites[$suite]+present}" ]]; then
					if [[ "$suite_failures" -eq 0 ]]; then
						summary_log "${COLOR_RED}failed suites:${COLOR_RESET}"
					fi
					summary_log "  ${COLOR_RED}$suite (no individual TAP failure recorded)${COLOR_RESET}"
					suite_failures=1
				fi
			done <"$failed_suites"
		fi
		if [[ "$individual_failures" -eq 0 && ! -s "$failed_suites" ]]; then
			summary_log "${COLOR_RED}failed tests: none recorded (failure occurred before the test suite)${COLOR_RESET}"
		fi
	fi

	summary_log "state: $RUN_DIR"
	summary_log "guest log: $guest_log"
	summary_log "console log: $console_log"
	summary_log "qemu log: $qemu_log"
	if [[ -n "$FAILURE_LOG_DIR" ]]; then
		summary_log "failure logs: $FAILURE_LOG_DIR"
	fi

	if [[ -f "$console_log" ]]; then
		if grep -Eq 'Failed unmounting .*var-lib-shirudo.*bpffs|Failed to unmount /oldroot/run/shirudo/bpffs: Operation not permitted' "$console_log"; then
			bpffs_warning=1
		fi
		if grep -Eq 'Failed unmounting .*mnt-shirudo.*out|Failed to unmount /oldroot: Device or resource busy' "$console_log"; then
			result_share_warning=1
		fi
	fi
	if [[ "$bpffs_warning" -eq 1 ]]; then
		summary_log "cleanup: ${COLOR_YELLOW}bpffs unmount denied by shirudo lockdown (expected)${COLOR_RESET}"
	fi
	if [[ "$result_share_warning" -eq 1 ]]; then
		summary_log "cleanup: ${COLOR_YELLOW}9p result share was busy during shutdown (non-fatal)${COLOR_RESET}"
	fi
}

print_quiet_progress()
{
	local guest_log="$RUN_DIR/result/guest.log"
	local line_count

	[[ ( "$VM_MODE" == test || "$VM_MODE" == serve ) &&
	   "$VM_VERBOSE" != 1 ]] || return 0
	[[ -f "$guest_log" ]] || return 0
	line_count="$(wc -l <"$guest_log")"
	[[ "$line_count" =~ ^[0-9]+$ ]] || return 0
	(( line_count > PROGRESS_LINES )) || return 0
	awk -v start=$((PROGRESS_LINES + 1)) '
		NR >= start && /^(not )?ok [0-9]+ - / {
			printf "[test-vm] test: %s\n", $0
			fflush()
		}
	' "$guest_log"
	PROGRESS_LINES="$line_count"
}

CONSOLE_BYTES=0
GUEST_LOG_BYTES=0

stream_verbose_console()
{
	local console_log="$RUN_DIR/console.log"
	local byte_count

	[[ ( "$VM_MODE" == test || "$VM_MODE" == serve ) &&
	   "$VM_VERBOSE" == 1 ]] || return 0
	[[ -f "$console_log" ]] || return 0
	byte_count="$(wc -c <"$console_log")"
	[[ "$byte_count" =~ ^[0-9]+$ ]] || return 0
	(( byte_count > CONSOLE_BYTES )) || return 0
	tail -c "+$((CONSOLE_BYTES + 1))" "$console_log"
	CONSOLE_BYTES="$byte_count"
}

# A serve-mode guest's tests print over SSH, not to its console.
stream_verbose_tests()
{
	local guest_log="$RUN_DIR/result/guest.log"
	local byte_count

	[[ "$VM_MODE" == serve && "$VM_VERBOSE" == 1 ]] || return 0
	[[ -f "$guest_log" ]] || return 0
	byte_count="$(wc -c <"$guest_log")"
	[[ "$byte_count" =~ ^[0-9]+$ ]] || return 0
	(( byte_count > GUEST_LOG_BYTES )) || return 0
	tail -c "+$((GUEST_LOG_BYTES + 1))" "$guest_log"
	GUEST_LOG_BYTES="$byte_count"
}

show_progress()
{
	if [[ "$VM_VERBOSE" == 1 ]]; then
		stream_verbose_console
		stream_verbose_tests
	else
		print_quiet_progress
	fi
}

cleanup()
{
	if [[ -n "$SSH_PORT_LOCK_FD" ]]; then
		flock -u "$SSH_PORT_LOCK_FD" 2>/dev/null || true
		eval "exec ${SSH_PORT_LOCK_FD}>&-"
		SSH_PORT_LOCK_FD=""
	fi
	if [[ "$LEAVE_RUNNING" -eq 0 ]]; then
		stop_qemu
		stop_swtpm
	fi
	if [[ "$FINAL_STATUS" -ne 0 ]]; then
		save_failure_logs
	fi
	if [[ "$LEAVE_RUNNING" -eq 0 && -n "$RUN_DIR" ]]; then
		keep_coverage "$RUN_DIR"
	fi
	if [[ ( "$VM_MODE" == test || "$VM_MODE" == serve ) &&
	      -n "$RUN_DIR" && -d "$RUN_DIR" ]]; then
		print_test_summary
		if [[ "$FINAL_STATUS" -eq 0 ]]; then
			# A passed run keeps its logs, not the disks it booted.
			rm -f -- "${PRIVATE_DIR:-$RUN_DIR}/rootfs.qcow2" \
				"$RUN_DIR/initrd.img" "$RUN_DIR/seed.img"
			rm -rf -- "$RUN_DIR/initrd-seed"
		else
			log "warning: the guest overlay contains an ephemeral signing key"
		fi
	elif [[ -n "$RUN_DIR" && -d "$RUN_DIR" ]]; then
		log "preserved VM state: $RUN_DIR"
		# Only the operator VM sees the signing key; a target's overlay
		# never holds one.
		if [[ "$VM_ROLE" == operator ]]; then
			log "warning: the guest overlay contains an ephemeral signing key"
		fi
	fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# The release string from the kernel image's setup header or, for an image
# without one such as arm64's, from the artifact's module tree.
kernel_release_of()
{
	local -a modules
	local v

	v="$(file -b "$1" 2>/dev/null | sed -n 's/.*version \([^ ]*\).*/\1/p')"
	if [[ -z "$v" && -n "$KERNEL_ARTIFACT_DIR" ]]; then
		modules=("$KERNEL_ARTIFACT_DIR"/lib/modules/*/)
		[[ ${#modules[@]} -eq 1 && -d "${modules[0]}" ]] &&
			v="$(basename "${modules[0]}")"
	fi
	[[ -n "$v" ]] || return 1
	printf '%s\n' "$v"
}

# An initrd that runs shirudo-initrd.service, built by the generator
# from the bundle's binary and certificate. The guest's root file system
# is a stock cloud image, so a seed unit in the initrd copies both onto
# it before shirudo runs: init records the root's binary as the lasting
# identity and the cloud-init stage later finds the files in place.
# The bootstrap the initrd pins, and so the runtime image the VM boots.
seed_bootstrap()
{
	if [[ "$ENFORCEMENT" == shared || "$VM_SUITE" == shared ]]; then
		printf 'bootstrap-shared.conf\n'
	else
		printf 'bootstrap.conf\n'
	fi
}

build_initrd()
{
	local kver gen unit seed trusted fp cert work_dir
	local -a args
	work_dir="${RUN_DIR}"
	if [[ -n "${INITRD_CACHE_BUILD_DIR:-}" ]]; then
		work_dir="$INITRD_CACHE_BUILD_DIR"
	fi

	kver="$(kernel_release_of "$KERNEL")" ||
		die "cannot read the kernel release from $KERNEL"
	gen="$REPO_ROOT/tools/gen-initrd/shirudo-gen-initrd"
	unit="$work_dir/shirudo-initrd.service"
	sed 's|@bindir@|/usr/local/bin|g' \
		"$REPO_ROOT/systemd/shirudo-initrd.service.in" >"$unit"
	seed="$work_dir/initrd-seed"
	mkdir -p "$seed/usr/lib/systemd/system/initrd.target.wants"
	cp "$REPO_ROOT/testing/vm/files/shirudo-test-seed.service" \
		"$seed/usr/lib/systemd/system/shirudo-test-seed.service"
	cp "$REPO_ROOT/testing/vm/files/seed-root.sh" \
		"$seed/shirudo-test-seed-root.sh"
	ln -sf ../shirudo-test-seed.service \
		"$seed/usr/lib/systemd/system/initrd.target.wants/shirudo-test-seed.service"
	# The bundle's own-keyring certificate rides along as a second
	# trusted certificate, for the tests of the enrolled set.
	trusted="$work_dir/trusted"
	mkdir -p "$trusted"
	fp="$("$TEST_VM_HOST_BUNDLE/root/usr/local/bin/shirudo" bpm key fingerprint \
		"$TEST_VM_HOST_BUNDLE/fixtures/own.der" 2>/dev/null)" ||
		die "cannot fingerprint the bundle's own certificate"
	cp "$TEST_VM_HOST_BUNDLE/fixtures/own.der" "$trusted/$fp.der"
	cp "$TEST_VM_HOST_BUNDLE/fixtures/own.vouch" "$trusted/$fp.vouch"
	[[ -s "$TEST_VM_HOST_BUNDLE/verity/manifest" ]] ||
		die "verity fixtures missing from the host bundle"
	(cd "$TEST_VM_HOST_BUNDLE/verity" && sha256sum -c manifest) ||
		die "verity fixture checksum mismatch"
	mkdir -p "$seed/shirudo-test-images"
	cp "$TEST_VM_HOST_BUNDLE/verity/"*.{img,verity,roothash,p7s} \
		"$seed/shirudo-test-images/"
	cp "$TEST_VM_HOST_BUNDLE/verity/$(seed_bootstrap)" \
		"$seed/shirudo-test-images/bootstrap.conf"
	cp "$REPO_ROOT/testing/vm/files/seed-images.sh" \
		"$seed/shirudo-test-seed-images.sh"
	cat "$REPO_ROOT/testing/vm/files/shirudo-test-seed-images.conf" \
		>>"$seed/usr/lib/systemd/system/shirudo-test-seed.service"
	cert="$work_dir/cert.der"
	cp "$TEST_VM_HOST_BUNDLE/fixtures/cert.der" "$cert"
	args=(--kver "$kver" --output "$work_dir/initrd.img"
	      --binary "$TEST_VM_HOST_BUNDLE/root/usr/local/bin/shirudo"
	      --binary-path /usr/local/bin/shirudo
	      --cert "$cert"
	      --trusted-dir "$trusted"
	      --unit "$unit" --module-dir "$REPO_ROOT/tools/gen-initrd")
	args+=(--bootstrap-conf "$seed/shirudo-test-images/bootstrap.conf")
	if [[ -n "$KERNEL_ARTIFACT_DIR" ]]; then
		args+=(--kmoddir "$KERNEL_ARTIFACT_DIR/lib/modules")
	else
		args+=(--no-kernel)
	fi
	log "building an initrd with shirudo for $kver"
	# shellcheck disable=SC2086
	if ! "$gen" "${args[@]}" -- --no-hostonly --no-hostonly-cmdline \
	     --modules "$VM_INITRD_MODULES" --include "$seed" / \
	     >"$RUN_DIR/initrd-build.log" 2>&1; then
		tail -40 "$RUN_DIR/initrd-build.log" >&2
		die "initrd build failed; see $RUN_DIR/initrd-build.log"
	fi
	INITRD="$work_dir/initrd.img"
}

initrd_cache_key()
{
	local kver
	kver="$(kernel_release_of "$KERNEL")" ||
		die "cannot read the kernel release from $KERNEL"
	{
		printf '%s\n' "$kver" "$(dracut --version)" "$(seed_bootstrap)"
		sha256sum "$KERNEL"
		if [[ -n "$KERNEL_ARTIFACT_DIR" ]]; then
			sha256sum "$KERNEL_ARTIFACT_DIR/${TEST_VM_ARCH_KIMAGE}.sha256sum"
		fi
		sha256sum "$TEST_VM_HOST_BUNDLE/root/usr/local/bin/shirudo" \
			"$TEST_VM_HOST_BUNDLE/fixtures/cert.der" \
			"$TEST_VM_HOST_BUNDLE/fixtures/own.der" \
			"$TEST_VM_HOST_BUNDLE/fixtures/own.vouch" \
			"$REPO_ROOT/tools/gen-initrd/shirudo-gen-initrd" \
			"$REPO_ROOT/systemd/shirudo-initrd.service.in" \
			"$REPO_ROOT/testing/vm/files/shirudo-test-seed.service" \
			"$REPO_ROOT/testing/vm/files/seed-root.sh" \
			"$REPO_ROOT/testing/vm/files/seed-images.sh" \
			"$REPO_ROOT/testing/vm/files/shirudo-test-seed-images.conf"
		(
			cd "$TEST_VM_HOST_BUNDLE" &&
			find verity -type f -print0 | sort -z | xargs -0 sha256sum
		)
	} | sha256sum | awk '{print $1}'
}

# The operator's image: the runtime image with the toolchain that builds the
# operator package, and clang 23 the way CI installs it. The key file beside
# it marks it complete, as for the runtime image.
prepare_operator_image()
{
	local packages="$REPO_ROOT/testing/vm/operator-packages"
	local clang="$REPO_ROOT/.github/scripts/install-clang.sh"
	local key

	# The bundle builder chose the kernel of the libguestfs appliance, a
	# downloaded one on a host without its own.
	if [[ -s "$CACHE_DIR/libguestfs/supermin.env" ]]; then
		# shellcheck source=/dev/null
		. "$CACHE_DIR/libguestfs/supermin.env"
	fi
	key="operator-$({
		printf '%s\n' "$RUNTIME_KEY" "$OPERATOR_DISK_SIZE"
		sha256sum <"$packages"
		sha256sum <"$clang"
	} | sha256sum | cut -d' ' -f1)"
	"$REPO_ROOT/testing/vm/prepare-runtime.sh" --rootfs "$ROOTFS" \
		--cache-dir "$RUNTIME_CACHE_DIR" --package-file "$packages" \
		--setup-script "$clang" --runtime-key "$key" \
		--runtime-disk-size "$OPERATOR_DISK_SIZE" \
		--key-output "$RUNTIME_CACHE_DIR/.$key.key"
	ROOTFS="$RUNTIME_CACHE_DIR/$key.qcow2"
}

prepare_initrd()
{
	local key cache_dir build_dir lock_fd
	key="$(initrd_cache_key)"
	cache_dir="$CACHE_DIR/initrd/$key"
	mkdir -p "$CACHE_DIR/initrd"
	exec {lock_fd}>"$CACHE_DIR/initrd.lock"
	flock "$lock_fd"
	if [[ ! -s "$cache_dir/initrd.img" ]]; then
		build_dir="$cache_dir.tmp.$$"
		mkdir -p "$build_dir"
		INITRD_CACHE_BUILD_DIR="$build_dir" build_initrd
		mv "$build_dir" "$cache_dir"
	fi
	INITRD="$RUN_DIR/initrd.img"
	cp "$cache_dir/initrd.img" "$INITRD"
	flock -u "$lock_fd"
	exec {lock_fd}>&-
}

resolve_kernel()
{
	local cache_kernel expected actual tmp

	if [[ -n "$KERNEL_OVERRIDE" && -n "$KERNEL_URL" ]]; then
		die "TEST_VM_KERNEL and TEST_VM_KERNEL_URL are mutually exclusive"
	fi

	if [[ -n "$KERNEL_URL" ]]; then
		valid_sha256 "$KERNEL_SHA256" ||
			die "TEST_VM_KERNEL_URL requires a 64-character TEST_VM_KERNEL_SHA256"
		expected="${KERNEL_SHA256,,}"
		cache_kernel="${CACHE_DIR}/kernels/${expected}/${TEST_VM_ARCH_KIMAGE}"
		mkdir -p "$(dirname "$cache_kernel")"
		if [[ -s "$cache_kernel" ]]; then
			actual="$(sha256sum "$cache_kernel" | awk '{print $1}')"
			if [[ "$actual" != "$expected" ]]; then
				rm -f -- "$cache_kernel"
			fi
		fi
		if [[ ! -s "$cache_kernel" ]]; then
			tmp="${cache_kernel}.tmp.$$"
			log "downloading kernel: $KERNEL_URL"
			curl -fL --retry 3 --output "$tmp" "$KERNEL_URL"
			actual="$(sha256sum "$tmp" | awk '{print $1}')"
			[[ "$actual" == "$expected" ]] || {
				rm -f -- "$tmp"
				die "downloaded kernel SHA-256 mismatch"
			}
			mv "$tmp" "$cache_kernel"
		fi
		printf '%s\n' "$cache_kernel"
		return
	fi

	if [[ -n "$KERNEL_OVERRIDE" ]]; then
		[[ -s "$KERNEL_OVERRIDE" ]] || die "kernel image not found: $KERNEL_OVERRIDE"
		printf '%s\n' "$(cd "$(dirname "$KERNEL_OVERRIDE")" && pwd)/$(basename "$KERNEL_OVERRIDE")"
		return
	fi

	[[ -s "$DEFAULT_KERNEL" ]] ||
		die "kernel image not found: $DEFAULT_KERNEL; stage a CI kernel artifact there"
	if [[ -s "${DEFAULT_KERNEL}.sha256sum" ]]; then
		(cd "$(dirname "$DEFAULT_KERNEL")" &&
			sha256sum -c "${DEFAULT_KERNEL##*/}.sha256sum" >/dev/null)
	else
		die "kernel checksum not found: ${DEFAULT_KERNEL}.sha256sum"
	fi
	printf '%s\n' "$DEFAULT_KERNEL"
}

allocate_ssh_access()
{
	local port

	SSH_DIR="${RUN_DIR}/ssh"
	SSH_KEY="${PRIVATE_DIR:-$SSH_DIR}/id_ed25519"
	mkdir -p "$SSH_DIR"
	(
		umask 077
		mkdir -p "$(dirname "$SSH_KEY")"
		ssh-keygen -q -t ed25519 -N '' -f "$SSH_KEY"
	)
	[[ -z "$PRIVATE_DIR" ]] ||
		printf '%s\n' "$SSH_KEY" >"$RUN_DIR/ssh.key"
	SSH_PUBLIC_KEY="$(<"$SSH_KEY.pub")"

	exec {SSH_PORT_LOCK_FD}>"${VM_ROOT}/ssh-port.lock"
	flock "$SSH_PORT_LOCK_FD"
	if [[ -n "$SSH_PORT_REQUEST" ]]; then
		[[ "$SSH_PORT_REQUEST" =~ ^[0-9]+$ &&
		   "$SSH_PORT_REQUEST" -ge 1024 &&
		   "$SSH_PORT_REQUEST" -le 65535 ]] ||
			die "TEST_VM_SSH_PORT must be an unused port from 1024 through 65535"
		if ss -Hln "sport = :$SSH_PORT_REQUEST" 2>/dev/null | grep -q .; then
			die "TEST_VM_SSH_PORT is already in use: $SSH_PORT_REQUEST"
		fi
		SSH_PORT="$SSH_PORT_REQUEST"
	else
		port="$SSH_PORT_MIN"
		while (( port <= SSH_PORT_MAX )); do
			if ! ss -Hln "sport = :$port" 2>/dev/null | grep -q .; then
				SSH_PORT="$port"
				break
			fi
			port=$((port + 1))
		done
		[[ -n "$SSH_PORT" ]] ||
			die "no free localhost SSH port in ${SSH_PORT_MIN}-${SSH_PORT_MAX}"
	fi
	printf '%s\n' "$SSH_PORT" >"$RUN_DIR/ssh.port"
}

wait_for_ssh_listener()
{
	local _

	for _ in {1..50}; do
		if ss -Hln "sport = :$SSH_PORT" 2>/dev/null | grep -q .; then
			if [[ -n "$SSH_PORT_LOCK_FD" ]]; then
				flock -u "$SSH_PORT_LOCK_FD"
				eval "exec ${SSH_PORT_LOCK_FD}>&-"
				SSH_PORT_LOCK_FD=""
			fi
			return 0
		fi
		sleep 0.1
	done
	die "QEMU did not open localhost SSH port $SSH_PORT"
}

allocate_run_dir()
{
	mkdir -p "$VMS_DIR" "$LOGS_DIR"
	if [[ -n "$VM_NAME_REQUEST" ]]; then
		valid_vm_name "$VM_NAME_REQUEST" ||
			die "VM_NAME must start with an alphanumeric and contain only A-Z, a-z, 0-9, '.', '_', or '-' (max 63 characters)"
		RUN_DIR="${VMS_DIR}/${VM_NAME_REQUEST}"
		[[ ! -e "$RUN_DIR" ]] ||
			die "VM_NAME '$VM_NAME_REQUEST' already has state at $RUN_DIR"
		mkdir "$RUN_DIR" || die "could not create VM state directory $RUN_DIR"
		VM_NAME="$VM_NAME_REQUEST"
	else
		RUN_DIR="$(mktemp -d "${VMS_DIR}/${VM_MODE}${VM_SUITE:+-$VM_SUITE}-XXXXXX")" ||
			die "could not allocate a unique VM state directory"
		VM_NAME="$(basename "$RUN_DIR")"
	fi
	date +%s%N >"$RUN_DIR/created-at" ||
		die "could not record VM creation time"
	mkdir -p "$RUN_DIR/result" "$RUN_DIR/tpm"
}

while [[ "$#" -gt 0 ]]; do
	case "$1" in
	--stop)
		[[ "$#" -eq 1 ]] || die "--stop does not accept additional arguments"
		stop_state
		exit 0
		;;
	--clean)
		[[ "$#" -eq 1 ]] || die "--clean does not accept additional arguments"
		clean_state
		exit 0
		;;
	--console)
		[[ "$#" -eq 1 ]] || die "--console does not accept additional arguments"
		run_console
		exit 0
		;;
	--ssh)
		[[ "$#" -eq 1 ]] || die "--ssh does not accept additional arguments"
		run_ssh
		exit 0
		;;
	--enroll)
		[[ "$#" -eq 1 ]] || die "--enroll does not accept additional arguments"
		run_enroll
		;;
	--sbom)
		[[ "$#" -eq 1 ]] || die "--sbom does not accept additional arguments"
		run_sbom
		;;
	--verbose)
		VM_VERBOSE=1
		shift
		;;
	*)
		die "unknown argument '$1'"
		;;
	esac
done

validate_mode
validate_private_dir
validate_kernel_selection
validate_kernel_artifact
validate_map_export
validate_oci_ca
validate_package_cert
validate_bpm_tree_config
validate_bpm_oci
[[ -z "$BPM_TREE_CONFIG" && -z "$PACKAGE_CERT" && -z "$BPM_OCI_REPOSITORY_RAW" ]] ||
	die "custom trust and repository inputs must be built into signed config fixtures"
if [[ "$VM_INITRD" == 1 ]]; then
	HOST_DEPENDENCIES+=("dracut:dracut-core:dracut" "lsinitrd:dracut-core:dracut" "file:file:file")
fi
if vm_has_builder; then
	HOST_DEPENDENCIES+=("tpm2_createprimary:tpm2-tools:tpm2-tools"
		"swtpm_ioctl:swtpm-tools:swtpm-tools" "openssl:openssl:openssl")
fi
check_host_dependencies
# tpm2-tools load tpm2-tss's swtpm TCTI only when tpm-builder.sh runs. grep
# reads all of ldconfig's output, which pipefail would otherwise fail on
# SIGPIPE.
if vm_has_builder &&
	! PATH="$PATH:/sbin:/usr/sbin" ldconfig -p |
		grep 'libtss2-tcti-swtpm\.so' >/dev/null; then
	log "error: missing the swtpm TCTI of tpm2-tss, libtss2-tcti-swtpm.so"
	log "Install it with:"
	print_dependency_install_command \
		"$(test_vm_pkg libtss2-tcti-swtpm0t64 tpm2-tss)" >&2
	[[ "$TEST_VM_HOST_PKG" == dnf ]] ||
		log "Before Ubuntu 24.04 and Debian 13 the package is libtss2-tcti-swtpm0."
	exit 1
fi
validate_host_bundle
[[ "$CPUS" =~ ^[1-9][0-9]*$ ]] || die "TEST_VM_CPUS must be a positive integer"
[[ "$VM_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "TEST_VM_TIMEOUT must be a positive integer"
# The operator serves through the target VM's whole run.
[[ "$VM_ROLE" != operator ]] || VM_TIMEOUT=$((VM_TIMEOUT * 2))

mkdir -p "$CACHE_DIR"
allocate_run_dir
allocate_ssh_access
KERNEL="$(resolve_kernel)"
[[ "$VM_INITRD" == 0 ]] || prepare_initrd

[[ "$TEST_VM_ARCH_SUPPORTED" == 1 ]] ||
	die "test-vm supports x86_64 and aarch64 hosts only, not $TEST_VM_ARCH"
[[ -r /dev/kvm && -w /dev/kvm ]] || die "/dev/kvm is required and must be accessible"

RUNTIME_KEY="$(<"$TEST_VM_HOST_BUNDLE/runtime-image-key")"
ROOTFS="$RUNTIME_CACHE_DIR/$RUNTIME_KEY.qcow2"
IMAGE_VERSION=
[[ "$VM_MODE" != interactive ]] || record_image
[[ "$VM_ROLE" != operator ]] || prepare_operator_image
[[ "$VM_ROLE" != operator ]] ||
	"$REPO_ROOT/testing/vm/list-source.sh" "$RUN_DIR/result/source-files"
OVERLAY="${PRIVATE_DIR:-$RUN_DIR}/rootfs.qcow2"
SEED="${RUN_DIR}/seed.img"
USER_DATA="${RUN_DIR}/user-data"
META_DATA="${RUN_DIR}/meta-data"
NETWORK_CONFIG="${RUN_DIR}/network-config"
SWTPM_SOCKET="${RUN_DIR}/tpm/swtpm-sock"
SWTPM_PIDFILE="${RUN_DIR}/tpm/swtpm.pid"
OTEL_CA_DIR=""
OCI_CA_DIR=""
BPM_TREE_DIR=""
PACKAGE_CERT_DIR=""
BPM_OCI_DIR=""

if [[ "$MAP_EXPORT_ENABLED" -eq 1 && -n "$MAP_EXPORT_CA" ]]; then
	OTEL_CA_DIR="${RUN_DIR}/otel-ca"
	mkdir -p "$OTEL_CA_DIR"
	install -m 0644 "$MAP_EXPORT_CA" "$OTEL_CA_DIR/ca.pem"
fi

if [[ -n "$OCI_CA" ]]; then
	OCI_CA_DIR="${RUN_DIR}/oci-ca"
	mkdir -p "$OCI_CA_DIR"
	install -m 0644 "$OCI_CA" "$OCI_CA_DIR/ca.crt"
fi

if [[ -n "$BPM_TREE_CONFIG" ]]; then
	BPM_TREE_DIR="${RUN_DIR}/bpm-tree"
	mkdir -p "$BPM_TREE_DIR"
	# This share contains configuration only; credentials and private signing
	# keys remain outside the VM tree-configuration handoff.
	install -m 0644 "$BPM_TREE_CONFIG" "$BPM_TREE_DIR/upatch-tree.conf"
fi

if [[ -n "$PACKAGE_CERT" ]]; then
	PACKAGE_CERT_DIR="${RUN_DIR}/package-cert"
	mkdir -p "$PACKAGE_CERT_DIR"
	install -m 0644 "$PACKAGE_CERT" "$PACKAGE_CERT_DIR/package-cert.der"
fi

if [[ -n "$BPM_OCI_ENDPOINT" ]]; then
	BPM_OCI_DIR="${RUN_DIR}/bpm-oci"
	mkdir -p "$BPM_OCI_DIR/keys" "$BPM_OCI_DIR/registries.d"
	install -m 0644 "$BPM_OCI_INDEX_CERT" \
		"$BPM_OCI_DIR/keys/${BPM_OCI_SOURCE}.pem"
	{
		printf '%s\n' "endpoint = $BPM_OCI_ENDPOINT" \
			"index_repository = $BPM_OCI_INDEX_REPOSITORY" \
			"key_file = /etc/shirudo/bpm/keys/${BPM_OCI_SOURCE}.pem"
	} >"$BPM_OCI_DIR/registries.d/${BPM_OCI_SOURCE}.conf"
	chmod 0644 "$BPM_OCI_DIR/registries.d/${BPM_OCI_SOURCE}.conf"
	printf 'BPM_OCI_REPOSITORY=%q\n' "$BPM_OCI_ENDPOINT" \
		>"$BPM_OCI_DIR/repository.env"
	chmod 0644 "$BPM_OCI_DIR/repository.env"
fi

qemu-img create -q -f qcow2 -F qcow2 -b "$ROOTFS" "$OVERLAY"
qemu-img resize -q "$OVERLAY" "$DISK_SIZE"

cat >"$META_DATA" <<EOF
instance-id: shirudo-${VM_NAME}
local-hostname: ${VM_NAME}
EOF

cat >"$NETWORK_CONFIG" <<'EOF'
version: 2
ethernets:
  eth0:
    dhcp4: true
    optional: false
EOF

# The image-reboot family runs its target tests over two boots of one VM:
# the guest reboots between them, which keeps the disk and resets the TPM.
VM_BOOTS=1
[[ "$VM_MODE" != test || "$VM_SUITE" != image-reboot ]] || VM_BOOTS=2

cat >"$USER_DATA" <<'EOF'
#cloud-config
growpart:
  mode: auto
  devices: ['/']
resize_rootfs: true
write_files:
  - path: /usr/local/sbin/shirudo-test-vm-bootstrap
    owner: root:root
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      set -uo pipefail
      # A two-boot family runs this again on its second boot, from the
      # unit guest.sh installs, and cloud-init may too, as the reboot cut
      # its first run short: one of them runs, and the mark says which boot.
      exec 9>/run/shirudo-test-vm-bootstrap.lock
      flock -n 9 || exit 0
      [ ! -e /etc/shirudo-test-vm-second-boot ] || export TEST_VM_BOOT=2
      mkdir -p /mnt/shirudo-src /mnt/shirudo-bundle /mnt/shirudo-out /mnt/shirudo-kernel /mnt/shirudo-package-cert /mnt/shirudo-bpm-tree
      if ! mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600 shirudo-out /mnt/shirudo-out; then
        echo "test-vm: could not mount result share" >/dev/console
        poweroff -f
        exit 1
      fi
      if ! mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600,ro shirudo-bundle /mnt/shirudo-bundle; then
        echo "test-vm: could not mount host bundle share" >/dev/console
        poweroff -f
        exit 1
      fi
      exec > >(tee -a /dev/console /mnt/shirudo-out/guest.log) 2>&1
      rc=0
EOF
if [[ -n "$PACKAGE_CERT" ]]; then
cat >>"$USER_DATA" <<'EOF'
      if ! mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600,ro shirudo-package-cert /mnt/shirudo-package-cert; then
        echo "test-vm: could not mount package certificate share" >/dev/console
        poweroff -f
        exit 1
      fi
EOF
fi
if [[ -n "$BPM_TREE_CONFIG" ]]; then
	printf '      export TEST_VM_BPM_TREE_INPUT=/mnt/shirudo-bpm-tree\n' >>"$USER_DATA"
fi
if [[ -n "$KERNEL_ARTIFACT_DIR" ]]; then
	cat >>"$USER_DATA" <<'EOF'
      if ! mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600,ro shirudo-kernel /mnt/shirudo-kernel; then
        echo "test-vm: could not mount kernel artifact share" >/dev/console
        poweroff -f
        exit 1
      fi
      export TEST_VM_KERNEL_MODULES=/mnt/shirudo-kernel/lib/modules
EOF
fi
printf '      export TEST_VM_LOCAL_STACK=%q\n' "${TEST_VM_LOCAL_STACK:-0}" >>"$USER_DATA"
printf '      export VM_MODE=%q\n' "$VM_MODE" >>"$USER_DATA"
printf '      export TEST_VM_MODE=%q\n' "$TEST_MODE" >>"$USER_DATA"
printf '      export TEST_VM_SUITE=%q\n' "$VM_SUITE" >>"$USER_DATA"
printf '      export TEST_VM_BOOTS=%q\n' "$VM_BOOTS" >>"$USER_DATA"
printf '      export TEST_FILTER=%q\n' "${TEST_FILTER:-}" >>"$USER_DATA"
printf '      export TEST_VM_NODE_ROLE=%q\n' "$NODE_ROLE" >>"$USER_DATA"
printf '      export TEST_VM_SKIP_SEAL=%q\n' "$SKIP_SEAL" >>"$USER_DATA"
printf '      export TEST_VM_INITRD=%q\n' "$VM_INITRD" >>"$USER_DATA"
printf '      export TEST_VM_SSH_PUBLIC_KEY=%q\n' "$SSH_PUBLIC_KEY" >>"$USER_DATA"
printf '      export TEST_VM_ROLE=%q\n' "$VM_ROLE" >>"$USER_DATA"
printf '      export TEST_VM_IMAGE_VERSION=%q\n' "$IMAGE_VERSION" >>"$USER_DATA"
if [[ -n "$OCI_CA_DIR" ]]; then
	printf '      export TEST_VM_OCI_CA=/mnt/shirudo-oci/ca.crt\n' >>"$USER_DATA"
fi
if [[ -n "$PACKAGE_CERT" ]]; then
	printf '      export TEST_VM_PACKAGE_CERT=/mnt/shirudo-package-cert/package-cert.der\n' \
		>>"$USER_DATA"
fi
if [[ -n "$BPM_OCI_ENDPOINT" ]]; then
	printf '      export TEST_VM_BPM_OCI_SOURCE=%q\n' \
		"$BPM_OCI_SOURCE" >>"$USER_DATA"
	printf '      export TEST_VM_BPM_OCI_INPUT=/mnt/shirudo-bpm-oci\n' \
		>>"$USER_DATA"
fi
if [[ "$MAP_EXPORT_ENABLED" -eq 1 ]]; then
	{
		printf '      export TEST_VM_MAP_EXPORT_ENDPOINT=%q\n' \
			"$MAP_EXPORT_ENDPOINT"
		printf '      export TEST_VM_MAP_EXPORT_TENANT_ID=%q\n' \
			"$MAP_EXPORT_TENANT_ID"
		printf '      export TEST_VM_MAP_EXPORT_INSECURE=%q\n' \
			"$MAP_EXPORT_INSECURE"
		if [[ -n "$OTEL_CA_DIR" ]]; then
			printf '      export TEST_VM_MAP_EXPORT_CA=/mnt/shirudo-otel/ca.pem\n'
		fi
	} >>"$USER_DATA"
fi
cat >>"$USER_DATA" <<'EOF'
      if [ -n "${TEST_VM_BPM_TREE_INPUT:-}" ]; then
        mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600,ro shirudo-bpm-tree /mnt/shirudo-bpm-tree || rc=$?
      fi
EOF
cat >>"$USER_DATA" <<'EOF'
      if [ -n "${TEST_VM_OCI_CA:-}" ]; then
        mkdir -p /mnt/shirudo-oci
        mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600,ro shirudo-oci /mnt/shirudo-oci || rc=$?
      fi
EOF
cat >>"$USER_DATA" <<'EOF'
      if [ -n "${TEST_VM_BPM_OCI_INPUT:-}" ]; then
        mkdir -p /mnt/shirudo-bpm-oci
        mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600,ro shirudo-bpm-oci /mnt/shirudo-bpm-oci || rc=$?
      fi
EOF
cat >>"$USER_DATA" <<'EOF'
      if [ -n "${TEST_VM_MAP_EXPORT_CA:-}" ]; then
        mkdir -p /mnt/shirudo-otel
        mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600,ro shirudo-otel /mnt/shirudo-otel || rc=$?
      fi
EOF
cat >>"$USER_DATA" <<'EOF'
      if [ "$TEST_VM_ROLE" = operator ]; then
        mkdir -p /mnt/shirudo-operator-keys
        mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600,ro shirudo-operator-keys /mnt/shirudo-operator-keys || rc=$?
      fi
      mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600,ro shirudo-src /mnt/shirudo-src || rc=$?
      if [ "$rc" -eq 0 ]; then
        bash /mnt/shirudo-src/testing/vm/guest.sh || rc=$?
      fi
      if [ "$rc" -eq 75 ]; then
        # guest.sh asks for the family's second boot, which publishes the
        # status; a reboot that does not come fails the run.
        sync
        systemctl reboot
        sleep 300
        rc=1
      fi
      printf '%s\n' "$rc" >/mnt/shirudo-out/status
      sync
      if { [ "${VM_MODE:-test}" = interactive ] ||
           [ "${VM_MODE:-test}" = node ]; } && [ "$rc" -eq 0 ]; then
        while :; do sleep 3600; done
      fi
      if [ "${VM_MODE:-test}" = serve ] && [ "$rc" -eq 0 ]; then
        while [ ! -e /mnt/shirudo-out/host-done ]; do sleep 1; done
      fi
EOF
printf '      %s || :\n      sync\n' "$GCOV_COLLECT" >>"$USER_DATA"
cat >>"$USER_DATA" <<'EOF'
      poweroff
      sleep 10
      poweroff -f
runcmd:
  - [ /usr/local/sbin/shirudo-test-vm-bootstrap ]
EOF

make_seed

cd "$RUN_DIR" || die "cannot enter $RUN_DIR"
[[ "$VM_ROLE" != target ]] || start_swtpm

log "booting $(basename "$KERNEL") with ${CPUS} CPUs and ${MEMORY} memory"

KERNEL_LSM_ARGS=""
# systemd gives the variable to every unit, in the initrd and in the root.
KERNEL_COVERAGE_ARGS=""
[[ ! -d "$TEST_VM_HOST_BUNDLE/coverage" ]] ||
	KERNEL_COVERAGE_ARGS="systemd.setenv=GCOV_PREFIX=$GCOV_PREFIX_DIR"
if [[ "$VM_ROLE" == target ]]; then
	# The bpf keyring is left open for init to enrol the certificate and
	# seal it, as a production initrd does.
	KERNEL_LSM_ARGS="lsm=bpf bpf.keyring_unsealed=1"
	KERNEL_LSM_ARGS+=" dm_verity.keyring_unsealed=1 initcall_debug ignore_loglevel"
	if [[ "$VM_INITRD" == 1 && "$VM_SUITE" == tpm ]]; then
		KERNEL_LSM_ARGS+=" trace_event=syscalls:sys_exit_pivot_root"
	fi
fi
KERNEL_NET_DEVICE="virtio-net-pci,netdev=net0"

# The virt machine has no if=virtio mapping, so its disks are explicit PCI
# devices, declared so that the root disk is vda.
case "$TEST_VM_ARCH" in
x86_64)
	MACHINE_ARGS=(-cpu host -machine q35)
	DISK_ARGS=(
		-drive "file=${OVERLAY},if=virtio,format=qcow2"
		-drive "file=${SEED},if=virtio,format=raw,readonly=on"
	)
	TPM_DEVICE="tpm-tis,tpmdev=tpm0"
	;;
aarch64)
	MACHINE_ARGS=(-cpu host -machine "virt,gic-version=host")
	DISK_ARGS=(
		-drive "file=${OVERLAY},if=none,id=rootdisk,format=qcow2"
		-device "virtio-blk-pci,drive=rootdisk"
		-drive "file=${SEED},if=none,id=seeddisk,format=raw,readonly=on"
		-device "virtio-blk-pci,drive=seeddisk"
	)
	TPM_DEVICE="tpm-tis-device,tpmdev=tpm0"
	;;
esac

QEMU_ARGS=(
	-enable-kvm \
	"${MACHINE_ARGS[@]}" \
	-smp "$CPUS" \
	-m "$MEMORY" \
	"${DISK_ARGS[@]}" \
	-kernel "$KERNEL" \
	-append "root=/dev/vda1 rootwait rw console=${TEST_VM_ARCH_CONSOLE},115200n8 loglevel=7 net.ifnames=0 ${KERNEL_LSM_ARGS} ${KERNEL_COVERAGE_ARGS}" \
	-netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
	-device "$KERNEL_NET_DEVICE" \
	-virtfs "local,id=shirudo-src,path=${REPO_ROOT},mount_tag=shirudo-src,security_model=none,readonly=on" \
	-virtfs "local,id=shirudo-bundle,path=${TEST_VM_HOST_BUNDLE},mount_tag=shirudo-bundle,security_model=none,readonly=on" \
	-virtfs "local,id=shirudo-out,path=${RUN_DIR}/result,mount_tag=shirudo-out,security_model=none" \
	-chardev "socket,id=console,path=console.sock,server=on,wait=off,logfile=${RUN_DIR}/console.log,logappend=on" \
	-serial chardev:console \
	-display none \
	-monitor none
)
# Any reboot but the one a two-boot family asks for ends the run.
[[ "$VM_BOOTS" == 2 ]] || QEMU_ARGS+=(-no-reboot)

if [[ -n "$KERNEL_ARTIFACT_DIR" ]]; then
	QEMU_ARGS+=(
		-virtfs "local,id=shirudo-kernel,path=${KERNEL_ARTIFACT_DIR},mount_tag=shirudo-kernel,security_model=none,readonly=on"
	)
fi

if [[ "$VM_ROLE" == target ]]; then
	QEMU_ARGS+=(
		-chardev "socket,id=chrtpm,path=tpm/swtpm-sock"
		-tpmdev emulator,id=tpm0,chardev=chrtpm
		-device "$TPM_DEVICE"
	)
else
	QEMU_ARGS+=(
		-virtfs "local,id=shirudo-operator-keys,path=${OPERATOR_KEYS},mount_tag=shirudo-operator-keys,security_model=none,readonly=on"
	)
fi

if [[ -n "$INITRD" ]]; then
	QEMU_ARGS+=(-initrd "$INITRD")
fi

if [[ -n "$OTEL_CA_DIR" ]]; then
	QEMU_ARGS+=(
		-virtfs "local,id=shirudo-otel,path=${OTEL_CA_DIR},mount_tag=shirudo-otel,security_model=none,readonly=on"
	)
fi

if [[ -n "$OCI_CA_DIR" ]]; then
	QEMU_ARGS+=(
		-virtfs "local,id=shirudo-oci,path=${OCI_CA_DIR},mount_tag=shirudo-oci,security_model=none,readonly=on"
	)
fi

if [[ -n "$BPM_OCI_DIR" ]]; then
	QEMU_ARGS+=(
		-virtfs "local,id=shirudo-bpm-oci,path=${BPM_OCI_DIR},mount_tag=shirudo-bpm-oci,security_model=none,readonly=on"
	)
fi

if [[ -n "$PACKAGE_CERT_DIR" ]]; then
	QEMU_ARGS+=(
		-virtfs "local,id=shirudo-package-cert,path=${PACKAGE_CERT_DIR},mount_tag=shirudo-package-cert,security_model=none,readonly=on"
	)
fi

if [[ -n "$BPM_TREE_DIR" ]]; then
	QEMU_ARGS+=(
		-virtfs "local,id=shirudo-bpm-tree,path=${BPM_TREE_DIR},mount_tag=shirudo-bpm-tree,security_model=none,readonly=on"
	)
fi

wait_for_guest_status()
{
	local elapsed=0

	while [[ ! -s "$RUN_DIR/result/status" ]]; do
		kill -0 "$QEMU_PID" 2>/dev/null ||
			die "QEMU exited before guest preparation completed"
		if (( elapsed >= VM_TIMEOUT )); then
			log "console log: $RUN_DIR/console.log"
			log "qemu log: $RUN_DIR/qemu.log"
			die "target readiness timed out after ${VM_TIMEOUT}s"
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	read_guest_status
}

read_guest_status()
{
	[[ -s "$RUN_DIR/result/status" ]] ||
		die "guest did not publish a test result"
	GUEST_STATUS="$(<"$RUN_DIR/result/status")"
	[[ "$GUEST_STATUS" =~ ^[0-9]+$ ]] ||
		die "invalid guest result: $GUEST_STATUS"
	[[ "$GUEST_STATUS" -eq 0 ]] ||
		die "guest preparation/test failed with status $GUEST_STATUS"
}

host_memory_pid()
{
	local child_pid cmdline

	[[ -n "$QEMU_PID" ]] || return 0
	cmdline="$(tr '\0' ' ' <"/proc/$QEMU_PID/cmdline" 2>/dev/null || true)"
	if [[ "$cmdline" == *"$QEMU_BIN"* ]]; then
		printf '%s\n' "$QEMU_PID"
		return 0
	fi
	if [[ -r "/proc/$QEMU_PID/task/$QEMU_PID/children" ]]; then
		while read -r child_pid; do
			[[ "$child_pid" =~ ^[1-9][0-9]*$ ]] || continue
			cmdline="$(tr '\0' ' ' <"/proc/$child_pid/cmdline" 2>/dev/null || true)"
			if [[ "$cmdline" == *"$QEMU_BIN"* ]]; then
				printf '%s\n' "$child_pid"
				return 0
			fi
		done <"/proc/$QEMU_PID/task/$QEMU_PID/children"
	fi
	printf '%s\n' "$QEMU_PID"
}

capture_host_memory_report()
{
	local report="$RUN_DIR/result/host-memory" memory_pid

	memory_pid="$(host_memory_pid)"

	{
		printf 'configured_memory=%s\n' "$MEMORY"
		printf 'qemu_pid=%s\n' "${memory_pid:-unavailable}"
		if [[ -n "$memory_pid" && -r "/proc/$memory_pid/status" ]]; then
			awk '/^VmRSS:/ { printf "qemu_vmrss_kb=%s\n", $2 }
			     /^VmSize:/ { printf "qemu_vmsize_kb=%s\n", $2 }' \
				"/proc/$memory_pid/status"
			if [[ -r "/proc/$memory_pid/smaps_rollup" ]]; then
				awk '/^Pss:/ { printf "qemu_pss_kb=%s\n", $2 }' \
					"/proc/$memory_pid/smaps_rollup"
			fi
		else
			printf 'qemu_vmrss_kb=unavailable\nqemu_vmsize_kb=unavailable\n'
			printf 'qemu_pss_kb=unavailable\n'
		fi
	} >"$report"
	HOST_MEMORY_REPORT="$report"
}

if [[ "$VM_MODE" == node ]]; then
	# Bounded like a test run, so that a node its caller lost stops.
	nohup timeout --signal=TERM --kill-after=30 "$VM_TIMEOUT" \
		"$QEMU_BIN" "${QEMU_ARGS[@]}" \
		>"$RUN_DIR/qemu.log" 2>&1 </dev/null &
	QEMU_PID=$!
	printf '%s\n' "$QEMU_PID" >"$RUN_DIR/qemu.pid"
	wait_for_ssh_listener
	wait_for_guest_status
	capture_host_memory_report
	LEAVE_RUNNING=1
	FINAL_STATUS=0
	log "node ready: name=$VM_NAME state=$RUN_DIR ssh_port=$SSH_PORT"
	print_memory_summary
elif [[ "$VM_MODE" == interactive ]]; then
	if user_systemd_available; then
		QEMU_UNIT_FILE="$RUN_DIR/qemu.unit"
		QEMU_UNIT="shirudo-vm-$VM_NAME-qemu.service"
		start_user_unit "$QEMU_UNIT" "$RUN_DIR/qemu.log" \
			"$QEMU_BIN" "${QEMU_ARGS[@]}"
		printf '%s\n' "$QEMU_UNIT" >"$QEMU_UNIT_FILE"
		QEMU_PID="$(user_unit_pid "$QEMU_UNIT")" || die "could not determine QEMU systemd PID"
	else
		nohup "$QEMU_BIN" "${QEMU_ARGS[@]}" \
			>"$RUN_DIR/qemu.log" 2>&1 < /dev/null &
		QEMU_PID=$!
	fi
	printf '%s\n' "$QEMU_PID" >"$RUN_DIR/qemu.pid"
	wait_for_ssh_listener
	wait_for_guest_status
	capture_host_memory_report
	LEAVE_RUNNING=1
	FINAL_STATUS=0
	log "VM ready: name=$VM_NAME state=$RUN_DIR qemu_pid=$QEMU_PID swtpm_pid=$(<"$SWTPM_PIDFILE")"
	print_memory_summary
	log "console log: $RUN_DIR/console.log"
	log "console: make -C testing vm-console VM_NAME=$VM_NAME"
	log "ssh: make -C testing vm-ssh"
else
	set +e
	timeout --signal=TERM --kill-after=30 "$VM_TIMEOUT" \
		"$QEMU_BIN" "${QEMU_ARGS[@]}" \
		>"$RUN_DIR/qemu.log" 2>&1 &
	QEMU_PID=$!
	# run.sh --ssh reaches a serve-mode VM by its PID file while it serves.
	[[ "$VM_MODE" != serve ]] || printf '%s\n' "$QEMU_PID" >"$RUN_DIR/qemu.pid"
	wait_for_ssh_listener
	while :; do
		show_progress
		[[ -s "$RUN_DIR/result/status" ]] && break
		kill -0 "$QEMU_PID" 2>/dev/null || break
		sleep 0.2
	done
	capture_host_memory_report
	[[ "$VM_MODE" != serve ]] || serve_target_tests
	wait "$QEMU_PID"
	QEMU_STATUS=$?
	rm -f -- "$RUN_DIR/qemu.pid"
	for _ in {1..5}; do
		show_progress
		sleep 0.1
	done
	set -e

	if [[ "$QEMU_STATUS" -eq 124 ]]; then
		die "VM timed out after ${VM_TIMEOUT}s"
	fi
	[[ "$QEMU_STATUS" -eq 0 ]] ||
		die "QEMU exited with status $QEMU_STATUS"
	QEMU_PID=""
	read_guest_status
	if [[ "$SERVE_STATUS" -ne 0 ]]; then
		[[ -z "$SERVE_COMMAND" ]] ||
			die "$(basename "$SERVE_COMMAND") failed with status $SERVE_STATUS"
		[[ "$SERVE_STATUS" -ne 255 ]] ||
			die "the SSH session that ran the target tests failed"
		die "target tests failed over SSH with status $SERVE_STATUS"
	fi

	FINAL_STATUS=0
fi

exit "$FINAL_STATUS"
