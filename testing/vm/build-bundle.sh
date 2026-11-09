#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build the host-side payload imported by testing/vm/run.sh. The bundle is
# shared by all VMs, while TPM state and the test workspace remain per-VM.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=testing/vm/arch.sh
. "${REPO_ROOT}/testing/vm/arch.sh"
BUNDLE_DIR="${TEST_VM_HOST_BUNDLE:-${REPO_ROOT}/build/test-vm/host-bundle}"
WORK_DIR="${TEST_VM_WORK_DIR:-${REPO_ROOT}/build/test-vm}"
HOST_PRIVATE_DIR="${TEST_VM_HOST_PRIVATE_DIR:-/tmp/shirudo-test-vm-private-$(id -u)}"
RUNTIME_CACHE_DIR="${TEST_VM_RUNTIME_CACHE_DIR:-${WORK_DIR}/cache/runtime}"
LIBGUESTFS_KERNEL_CACHE="${WORK_DIR}/cache/libguestfs/ubuntu"
UBUNTU_CODENAME="${TEST_VM_UBUNTU_CODENAME:-resolute}"
PACKAGE_FILE="$REPO_ROOT/testing/vm/runtime-packages"
DEFAULT_ROOTFS_URL="https://cloud-images.ubuntu.com/releases/server/26.04/release/ubuntu-26.04-server-cloudimg-${TEST_VM_ARCH_DEB}.img"
ROOTFS_URL="${TEST_VM_ROOTFS_URL:-$DEFAULT_ROOTFS_URL}"
ROOTFS_SHA256="${TEST_VM_ROOTFS_SHA256:-}"
ROOTFS_NAME="ubuntu-26.04-server-cloudimg-${TEST_VM_ARCH_DEB}.img"
ROOTFS_CACHE="${WORK_DIR}/cache/rootfs/${ROOTFS_NAME}"
LOCK_FILE="${BUNDLE_DIR}.lock"
STAMP_FILE="${TEST_VM_BUNDLE_STAMP:-${BUNDLE_DIR}/.stamp}"
STAMP_INPUTS="${TEST_VM_BUNDLE_INPUTS:-}"
PACKAGE_CERT="${TEST_VM_PACKAGE_CERT:-}"
OPERATOR_KEYS_DIR="${HOST_PRIVATE_DIR}/operator-keys"
RUNTIME_PREP_VERSION=4
TEST_VM_MODE=${TEST_VM_MODE:-verity}
RUNTIME_DISK_SIZE="${TEST_VM_RUNTIME_DISK_SIZE:-8G}"

log()
{
	printf '[test-vm-bundle] %s\n' "$*" >&2
}

die()
{
	log "error: $*"
	exit 1
}

validate_host_private_dir()
{
	local repo_root host_private_dir

	repo_root="$(realpath -m "$REPO_ROOT")"
	host_private_dir="$(realpath -m "$HOST_PRIVATE_DIR")"
	[[ "$host_private_dir" != "$repo_root" &&
	   "$host_private_dir" != "$repo_root"/* ]] ||
		die "TEST_VM_HOST_PRIVATE_DIR must be outside the repository"
	install -d -m 0700 "$HOST_PRIVATE_DIR"
	chmod 0700 "$HOST_PRIVATE_DIR"
}

validate_package_cert()
{
	[[ -z "$PACKAGE_CERT" ]] && return 0
	[[ -f "$PACKAGE_CERT" && -r "$PACKAGE_CERT" && -s "$PACKAGE_CERT" ]] ||
		die "TEST_VM_PACKAGE_CERT is not a readable, non-empty regular file: $PACKAGE_CERT"
}

# require_command COMMAND DEB-PACKAGE [RPM-PACKAGE]
require_command()
{
	local command_name="$1" deb_package="$2" rpm_package="${3:-$2}"
	command -v "$command_name" >/dev/null 2>&1 ||
		die "missing host command: $command_name (install with: $(test_vm_install_cmd "$(test_vm_pkg "$deb_package" "$rpm_package")"))"
}

check_libguestfs_host()
{
	local kernel="" candidate
	if [[ -n "${SUPERMIN_KERNEL:-}" ]]; then
		[[ -r "$SUPERMIN_KERNEL" ]] ||
			die "SUPERMIN_KERNEL is not readable: $SUPERMIN_KERNEL"
	else
		for candidate in /boot/vmlinuz* /lib/modules/*/vmlinuz; do
			if [[ -r "$candidate" ]]; then
				kernel="$candidate"
				break
			fi
		done
		if [[ -z "$kernel" ]]; then
			prepare_ubuntu_libguestfs_kernel
			log "libguestfs host check: using cached Ubuntu $UBUNTU_CODENAME kernel"
		fi
	fi
	if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
		log "libguestfs host check: /dev/kvm unavailable; appliance will use slower TCG"
	else
		log "libguestfs host check: KVM available"
	fi
}

prepare_ubuntu_libguestfs_kernel()
{
	local cache_dir index metadata package version kernel_version filename deb tmp
	local module_package module_filename kernel_info module_info module_root

	require_command dpkg-deb dpkg
	cache_dir="$LIBGUESTFS_KERNEL_CACHE/$UBUNTU_CODENAME"
	index="$cache_dir/Packages.gz"
	metadata="$cache_dir/kernel.info"
	mkdir -p "$cache_dir"
	if [[ ! -s "$metadata" || "$(awk -F '\t' '{print NF; exit}' "$metadata")" != 5 ]]; then
		curl -fsSL --retry 3 \
			--output "${index}.tmp" \
			"${TEST_VM_ARCH_MIRROR}/dists/${UBUNTU_CODENAME}-updates/main/binary-${TEST_VM_ARCH_DEB}/Packages.gz" \
			|| die "could not download Ubuntu $UBUNTU_CODENAME kernel package index"
		mv -- "${index}.tmp" "$index"
		kernel_info="$(awk -v want_arch="$TEST_VM_ARCH_DEB" -v RS='' -v FS='\n' '
			{
				package=arch=version=filename=""
				for (i = 1; i <= NF; i++) {
					if ($i ~ /^Package: /) package=substr($i, 10)
					if ($i ~ /^Architecture: /) arch=substr($i, 15)
					if ($i ~ /^Version: /) version=substr($i, 10)
					if ($i ~ /^Filename: /) filename=substr($i, 11)
				}
				if (package ~ /^linux-image-[0-9].*-generic$/ &&
				    arch == want_arch && version != "" && filename != "")
					print version "\t" package "\t" filename
			}
		' <(gzip -dc "$index") | sort -V | tail -1)"
		[[ -n "$kernel_info" ]] ||
			die "Ubuntu $UBUNTU_CODENAME has no $TEST_VM_ARCH_DEB generic kernel package"
		IFS=$'\t' read -r version package filename <<<"$kernel_info"
		kernel_version="${package#linux-image-}"
		module_info="$(awk -v want="linux-modules-$kernel_version" \
			-v want_arch="$TEST_VM_ARCH_DEB" -v RS='' -v FS='\n' '
			{
				package=arch=version=filename=""
				for (i = 1; i <= NF; i++) {
					if ($i ~ /^Package: /) package=substr($i, 10)
					if ($i ~ /^Architecture: /) arch=substr($i, 15)
					if ($i ~ /^Version: /) version=substr($i, 10)
					if ($i ~ /^Filename: /) filename=substr($i, 11)
				}
				if (package == want && arch == want_arch && version != "" && filename != "")
					print package "\t" filename
			}
		' <(gzip -dc "$index") | sort -V | tail -1)"
		[[ -n "$module_info" ]] ||
			die "Ubuntu $UBUNTU_CODENAME has no matching $kernel_version modules package"
		IFS=$'\t' read -r module_package module_filename <<<"$module_info"
		printf '%s\t%s\t%s\t%s\t%s\n' "$version" "$package" "$filename" \
			"$module_package" "$module_filename" >"${metadata}.tmp"
		mv -- "${metadata}.tmp" "$metadata"
	fi
	IFS=$'\t' read -r version package filename module_package module_filename <"$metadata"
	[[ -n "$version" && -n "$package" && -n "$filename" &&
	   -n "$module_package" && -n "$module_filename" ]] ||
		die "invalid cached Ubuntu kernel metadata: $metadata"
	kernel_version="${package#linux-image-}"
	deb="$cache_dir/$package.deb"
	if [[ ! -s "$deb" ]]; then
		curl -fsSL --retry 3 --output "${deb}.tmp" \
			"${TEST_VM_ARCH_MIRROR}/$filename" ||
			die "could not download Ubuntu kernel package $package"
		mv -- "${deb}.tmp" "$deb"
	fi
	local module_deb="$cache_dir/$module_package.deb"
	if [[ ! -s "$module_deb" ]]; then
		curl -fsSL --retry 3 --output "${module_deb}.tmp" \
			"${TEST_VM_ARCH_MIRROR}/$module_filename" ||
			die "could not download Ubuntu kernel modules package $module_package"
		mv -- "${module_deb}.tmp" "$module_deb"
	fi
	version="${version%% *}"
	tmp="$cache_dir/.root.tmp.$$"
	rm -rf -- "$tmp"
	mkdir -p "$tmp"
	dpkg-deb -x "$deb" "$tmp"
	dpkg-deb -x "$module_deb" "$tmp"
	module_root="$tmp/lib/modules"
	[[ -d "$module_root/$kernel_version" ]] || module_root="$tmp/usr/lib/modules"
	if [[ ! -r "$module_root/$kernel_version/modules.dep" ]]; then
		if [[ "$module_root" == "$tmp/usr/lib/modules" ]]; then
			mkdir -p "$tmp/lib"
			ln -s ../usr/lib/modules "$tmp/lib/modules"
			module_root="$tmp/lib/modules"
		fi
		depmod -b "$tmp" "$kernel_version"
	fi
	[[ -r "$tmp/boot/vmlinuz-$kernel_version" &&
	   -r "$module_root/$kernel_version/modules.dep" ]] ||
		die "Ubuntu kernel package $package lacks a usable kernel/module tree"
	if [[ ! -r "$cache_dir/boot/vmlinuz-$kernel_version" ||
	      ! -r "$cache_dir/lib/modules/$kernel_version/modules.dep" ]]; then
		mkdir -p "$cache_dir/boot" "$cache_dir/lib"
		[[ -L "$cache_dir/lib/modules" ]] && rm -f -- "$cache_dir/lib/modules"
		mkdir -p "$cache_dir/lib/modules"
		cp -a "$tmp/boot/." "$cache_dir/boot/"
		cp -a "$module_root/." "$cache_dir/lib/modules/"
	fi
	[[ -r "$cache_dir/boot/vmlinuz-$kernel_version" &&
	   -r "$cache_dir/lib/modules/$kernel_version/modules.dep" ]] ||
		die "Ubuntu kernel package lacks a usable kernel/module tree"
	rm -rf -- "$tmp"
	export SUPERMIN_KERNEL="$cache_dir/boot/vmlinuz-$kernel_version"
	export SUPERMIN_MODULES="$cache_dir/lib/modules/$kernel_version"
	export SUPERMIN_KERNEL_VERSION="$kernel_version"
	return 0
}

# Each entry is command:Debian package:RPM package.
for dependency in \
	"flock:util-linux:util-linux" "curl:curl:curl" \
	"sha256sum:coreutils:coreutils" "awk:gawk:gawk" \
	"qemu-img:qemu-utils:qemu-img" \
	"virt-customize:libguestfs-tools:guestfs-tools" \
	"openssl:openssl:openssl" "gzip:gzip:gzip" "depmod:kmod:kmod"; do
	IFS=: read -r command_name deb_package rpm_package <<<"$dependency"
	require_command "$command_name" "$deb_package" "$rpm_package"
done
# The Debian libguestfs appliance brings up its network with dhclient,
# which Ubuntu 24.04 no longer installs; without it apt in the appliance
# reaches nothing.
[[ "$TEST_VM_HOST_PKG" != apt ]] || require_command dhclient isc-dhcp-client
require_command veritysetup cryptsetup-bin cryptsetup
require_command mkfs.ext4 e2fsprogs e2fsprogs
check_libguestfs_host

resolve_rootfs()
{
	local sums expected actual tmp
	mkdir -p "$(dirname "$ROOTFS_CACHE")"
	if [[ -n "$ROOTFS_SHA256" ]]; then
		expected="${ROOTFS_SHA256,,}"
	elif [[ "$ROOTFS_URL" != "$DEFAULT_ROOTFS_URL" ]]; then
		die "a custom TEST_VM_ROOTFS_URL requires TEST_VM_ROOTFS_SHA256"
	else
		sums="${ROOTFS_CACHE}.SHA256SUMS"
		curl -fsSL --retry 3 --output "$sums" \
			https://cloud-images.ubuntu.com/releases/server/26.04/release/SHA256SUMS
		expected="$(awk -v name="*$ROOTFS_NAME" '$2 == name {print $1; exit}' "$sums")"
		rm -f -- "$sums"
	fi
	[[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] ||
		die "could not determine a valid SHA-256 for $ROOTFS_NAME"
	if [[ -s "$ROOTFS_CACHE" ]]; then
		actual="$(sha256sum "$ROOTFS_CACHE" | awk '{print $1}')"
		[[ "$actual" == "$expected" ]] || rm -f -- "$ROOTFS_CACHE"
	fi
	if [[ ! -s "$ROOTFS_CACHE" ]]; then
		tmp="${ROOTFS_CACHE}.tmp.$$"
		log "downloading Ubuntu runtime rootfs: $ROOTFS_URL"
		curl -fL --retry 3 --output "$tmp" "$ROOTFS_URL"
		actual="$(sha256sum "$tmp" | awk '{print $1}')"
		[[ "$actual" == "$expected" ]] || {
			rm -f -- "$tmp"
			die "downloaded rootfs SHA-256 mismatch"
		}
		mv -- "$tmp" "$ROOTFS_CACHE"
	fi
	ROOTFS_DIGEST="$expected"
}

prepare_runtime_image()
{
	local package_digest disk_size_key
	package_digest="$(sha256sum "$PACKAGE_FILE" | awk '{print $1}')"
	disk_size_key="${RUNTIME_DISK_SIZE//[^A-Za-z0-9]/_}"
	RUNTIME_KEY="rootfs-${ROOTFS_DIGEST}-packages-${package_digest}-disk-${disk_size_key}-v${RUNTIME_PREP_VERSION}"
	RUNTIME_IMAGE="$RUNTIME_CACHE_DIR/$RUNTIME_KEY.qcow2"
	if [[ ! -s "$RUNTIME_IMAGE" ]]; then
		"$REPO_ROOT/testing/vm/prepare-runtime.sh" \
			--rootfs "$ROOTFS_CACHE" \
			--cache-dir "$RUNTIME_CACHE_DIR" \
			--package-file "$PACKAGE_FILE" \
			--runtime-key "$RUNTIME_KEY" \
			--runtime-disk-size "$RUNTIME_DISK_SIZE" \
			--key-output "$RUNTIME_CACHE_DIR/.${RUNTIME_KEY}.key"
	fi
}

bundle_is_current()
{
	local input

	[[ -s "$BUNDLE_DIR/test-mode" &&
	   "$(cat "$BUNDLE_DIR/test-mode")" == "$TEST_VM_MODE" ]] || return 1

	[[ -f "$STAMP_FILE" && -n "$STAMP_INPUTS" ]] || return 1
	[[ -x "$BUNDLE_DIR/root/usr/local/bin/shirudo" ]] || return 1
	[[ -s "$BUNDLE_DIR/runtime-image-key" ]] || return 1
	[[ -s "$OPERATOR_KEYS_DIR/keys/signing_key.pem" ]] || return 1
	cmp -s "$OPERATOR_KEYS_DIR/keys/cert.der" \
		"$BUNDLE_DIR/fixtures/cert.der" || return 1
	[[ "$(<"$BUNDLE_DIR/runtime-image-key")" == "$RUNTIME_KEY" ]] || return 1
	[[ -s "$RUNTIME_IMAGE" ]] || return 1
	for input in $STAMP_INPUTS; do
		[[ -e "$input" ]] || return 1
		[[ "$input" -nt "$STAMP_FILE" ]] && return 1
	done
	return 0
}

command -v flock >/dev/null 2>&1 ||
	die "flock is required; install it with: $(test_vm_install_cmd util-linux)"

[[ "$TEST_VM_MODE" == verity ]] || die "TEST_VM_MODE must be verity"
validate_package_cert

mkdir -p "$(dirname "$BUNDLE_DIR")"
exec 9>"$LOCK_FILE"
flock 9
validate_host_private_dir

resolve_rootfs
prepare_runtime_image
# run.sh prepares the operator VM's image with prepare-runtime.sh as well,
# and needs the appliance kernel chosen above.
mkdir -p "$WORK_DIR/cache/libguestfs"
for name in SUPERMIN_KERNEL SUPERMIN_MODULES SUPERMIN_KERNEL_VERSION; do
	[[ -z "${!name:-}" ]] || printf 'export %s=%q\n' "$name" "${!name}"
done >"$WORK_DIR/cache/libguestfs/supermin.env"

if bundle_is_current; then
	log "reusing current host bundle: $BUNDLE_DIR"
	exit 0
fi

# Without libtpms the make rule skips tpmsim-cmd, which the bundle carries.
require_command pkg-config pkg-config pkgconf-pkg-config
pkg-config --exists libtpms ||
	die "libtpms is required for testing/helper/tpmsim-cmd; install it with: $(test_vm_install_cmd "$(test_vm_pkg libtpms-dev libtpms-devel)")"

jobs=$(nproc)
log "building host shirudo payload and test helpers"
make -C "$REPO_ROOT" -j"$jobs" all
make -C "$REPO_ROOT" -j"$jobs" shirudo-build
make -C "$REPO_ROOT" -j"$jobs" quote-check
make -C "$REPO_ROOT/testing" -j"$jobs" test-helpers

TMP_DIR="$(mktemp -d "${BUNDLE_DIR}.tmp.XXXXXX")"
FIXTURE_WORK="$(mktemp -d "${HOST_PRIVATE_DIR}/fixtures.XXXXXX")"
cleanup()
{
	rm -rf -- "$TMP_DIR" "$FIXTURE_WORK"
}
trap cleanup EXIT

# t7108 reaches the tree walk limits: the guest runs a target that walks
# 4 operations back from a cursor past 0 and 6 from 0. t7110 reaches past
# the keepalive window, which the target lowers to the last 7 operations.
make -C "$REPO_ROOT" -j"$jobs" \
	TREE_LIMIT_CFLAGS="-DTREE_MAX_WALK_OPS=4 -DTREE_MAX_JOIN_OPS=6 -DKEEPALIVE_WINDOW_OPS=7" \
	DESTDIR="$TMP_DIR/root" install-target
make -C "$REPO_ROOT" -j"$jobs" -f Makefile.shirudo \
	PROFILE=target CONFIG_MK=config-target.mk verity-test-helpers

install -d "$TMP_DIR/test-helpers/testing/helper" \
	"$TMP_DIR/test-helpers/testing/fixtures" \
	"$TMP_DIR/test-helpers/testing/end2end"
while IFS= read -r helper; do
	install -m 0755 "$REPO_ROOT/$helper" "$TMP_DIR/test-helpers/$helper"
done <<'EOF'
testing/helper/test-register
testing/helper/test-register-cli
testing/helper/test-config-attest
testing/helper/test-config-update
testing/helper/tpmsim-cmd
testing/helper/test-tpm-wire
testing/helper/test-nv-cphash
testing/helper/test-nv-writer
testing/helper/test-keyring-seal
testing/helper/test-tpm-preopened
testing/helper/test-config
testing/helper/test-bpf-load
testing/helper/test-bpf-cmd
testing/helper/test-perf-attach
testing/helper/test-otel-map
testing/helper/test-upatch-map-types
testing/helper/test-upatch-prog-metadata
testing/helper/test-upatch-decode
testing/helper/test-upatch-serializer-pages
testing/helper/test-signed-load
testing/helper/test-upatch-link-lockdown
testing/helper/test-xdp
testing/helper/test-exec-churn
testing/end2end/exec-paths
testing/end2end/policy-exec
testing/helper/otel-mock.py
testing/helper/test-oci-registry.py
EOF
# The backend's quote checker, a static PIE, checks the quotes of t4104.
install -m 0755 "$REPO_ROOT/tools/quote-check/shirudo-quote-check" \
	"$TMP_DIR/test-helpers/testing/helper/shirudo-quote-check"

# A second TPM for t6125: the host's emulator and the libraries of its own.
if swtpm="$(command -v swtpm)"; then
	install -d "$TMP_DIR/test-helpers/swtpm"
	install -m 0755 "$swtpm" "$TMP_DIR/test-helpers/swtpm/"
	while IFS= read -r lib; do
		install -m 0644 "$lib" "$TMP_DIR/test-helpers/swtpm/"
	done < <(ldd "$swtpm" | awk '/libtpms|libswtpm/ { print $3 }')
fi


wait_fixture_jobs()
{
	local failed=0
	local pid

	for pid in "${pids[@]}"; do
		wait "$pid" || failed=1
	done
	((failed == 0)) || die "building fixtures failed"
	pids=()
}

queue_fixture()
{
	"$@" &
	pids+=("$!")
	if ((${#pids[@]} == jobs)); then
		wait_fixture_jobs
	fi
}

build_fixture()
{
	local source="$1"
	local name="$2"
	local keys_dir="$3"

	(
		cd "$REPO_ROOT"
		"$REPO_ROOT/tools/shirudo-build/shirudo-build" \
			"$REPO_ROOT/testing/fixtures/$source" \
			-o "$TMP_DIR/fixtures/$name.upatch" \
			--name "$name" --vmlinux "$REPO_ROOT/vendor/linux/vmlinux.h" \
			--extra-cflags "-I$REPO_ROOT/vendor/libbpf" \
			--key "$keys_dir/signing_key.pem" \
			--cert "$keys_dir/cert.der"
	)
}

build_many_fixture()
{
	local name="shirudo-test-many-$1"
	local payload
	cd "$REPO_ROOT"
	"$REPO_ROOT/tools/shirudo-build/shirudo-build" \
		"$REPO_ROOT/testing/fixtures/status-many.bpf.c" \
		-o "$TMP_DIR/fixtures/many/$name.upatch" \
		--name "$name" --vmlinux "$REPO_ROOT/vendor/linux/vmlinux.h" \
		--extra-cflags "-I$REPO_ROOT/vendor/libbpf" \
		--key "$FIXTURE_WORK/trusted/signing_key.pem" \
		--cert "$FIXTURE_WORK/trusted/cert.der" >/dev/null
	payload="$($REPO_ROOT/shirudo upatch info \
		"$TMP_DIR/fixtures/many/$name.upatch" --json |
		python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
	"$REPO_ROOT/tools/shirudo-build/shirudo-build" --unload \
		"$name" --payload-sha256 "$payload" \
		-o "$TMP_DIR/fixtures/many/$name.unload.upatch" \
		--key "$FIXTURE_WORK/trusted/signing_key.pem" \
		--cert "$FIXTURE_WORK/trusted/cert.der" >/dev/null
}

build_tree_test_registry()
{
	local registry_dir="$TMP_DIR/fixtures/tree-oci"
	local payloads="$FIXTURE_WORK/tree-payload"
	local reference

	# One append-only tree that t7101 to t7107 and t7109 walk in order:
	# the tree state a target writes is sealed, so no test can start
	# over, and each generation extends the one before it.
	python3 - "$registry_dir" \
		"$TMP_DIR/fixtures/shirudo-test-tree-match.upatch" \
		"$TMP_DIR/fixtures/shirudo-test-tree-skip.upatch" \
		"$TMP_DIR/fixtures/shirudo-test-tree-match.unload.upatch" \
		"$payloads" "$tree_match_payload" "$tree_skip_payload" \
		"$tree_match_unload_payload" "$TEST_VM_ARCH" \
		"$TMP_DIR/fixtures/shirudo-test-tree-skip.unload.upatch" \
		"$TMP_DIR/fixtures/shirudo-test-uprobe-multi.upatch" \
		"$tree_skip_unload_payload" "$uprobe_payload" <<'PY'
import hashlib
import json
import pathlib
import sys

registry, match_path, skip_path, match_unload_path, payloads = \
    map(pathlib.Path, sys.argv[1:6])
match_payload, skip_payload, match_unload_payload, node_arch = sys.argv[6:10]
skip_unload_path, absent_path = map(pathlib.Path, sys.argv[10:12])
skip_unload_payload, absent_payload = sys.argv[12:14]


def digest(body):
    return "sha256:" + hashlib.sha256(body).hexdigest()


def write(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)


# payload_sha256 is the upatch header's digest of loader_insns || data,
# which the target compares against the fetched artifact's header; an
# unload directive carries its own, not its load's. The layer digest
# covers the whole file and is a different value again.
def artifact(repository, path, title, payload_sha256):
    body = path.read_bytes()
    layer_digest = digest(body)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": [{
            "mediaType": "application/vnd.shirudo.upatch.v1",
            "digest": layer_digest,
            "size": len(body),
            "annotations": {"org.opencontainers.image.title": title},
        }],
    }
    manifest_body = json.dumps(manifest, separators=(",", ":")).encode()
    manifest_digest = digest(manifest_body)
    repo_root = registry.joinpath(*repository.split("/"))
    write(repo_root / "manifests" / manifest_digest, manifest_body)
    write(repo_root / "blobs" / layer_digest, body)
    return {
        "repository": "oci://127.0.0.1:5443/" + repository,
        "manifest_digest": manifest_digest,
        "layer_digest": layer_digest,
        "payload_sha256": "sha256:" + payload_sha256,
    }


# fixes, when given, goes where a publisher writes it: after the artifact,
# outside the digest.
def operation(seq, name, selector, artifact_info, op="add", fixes=None):
    unsigned = {
        "seq": seq,
        "op": op,
        "id": name,
        "selector": selector,
        "artifact": artifact_info,
    }
    operation_digest = digest(json.dumps(unsigned, separators=(",", ":"))
                              .encode())
    published = dict(unsigned)
    if fixes is not None:
        published["fixes"] = fixes
    return dict(published, operation_digest=operation_digest)


match_artifact = artifact("shirudo/tree-match", match_path,
                         "shirudo-test-tree-match.upatch", match_payload)
skip_artifact = artifact("shirudo/tree-skip", skip_path,
                        "shirudo-test-tree-skip.upatch", skip_payload)
match_unload_artifact = artifact("shirudo/tree-match-unload",
                                 match_unload_path,
                                 "shirudo-test-tree-match.unload.upatch",
                                 match_unload_payload)
skip_unload_artifact = artifact("shirudo/tree-skip-unload", skip_unload_path,
                                "shirudo-test-tree-skip.unload.upatch",
                                skip_unload_payload)
# Its uprobe target is a file the bpm family's VM does not have.
absent_artifact = artifact("shirudo/tree-absent", absent_path,
                           "shirudo-test-uprobe-multi.upatch", absent_payload)

this_node = {"architecture": [node_arch], "labels": {"env": ["tree-test"]}}
other_node = {"architecture": [node_arch],
              "labels": {"env": ["not-this-node"]}}
# Selected by the kernel config alone, which t7104 takes away and gives.
kconfig_node = {"architecture": [node_arch], "kconfig": {"CONFIG_BPF": ["y"]}}
operations = [
    operation(1, "shirudo-test-tree-match", {}, match_artifact),
    operation(2, "shirudo-test-tree-skip", other_node, skip_artifact),
    operation(3, "shirudo-test-tree-skip", this_node, skip_artifact),
    operation(4, "shirudo-test-tree-match", this_node,
              match_unload_artifact, op="delete"),
    operation(5, "shirudo-test-tree-match", this_node, match_artifact),
    operation(6, "shirudo-test-tree-match", kconfig_node,
              match_unload_artifact, op="delete"),
    # t7105 loads this upatch by hand first.
    operation(7, "shirudo-test-tree-match", this_node, match_artifact),
    # t7106: an outcome of each kind, an operation after one without a
    # match for the sync it stops, and an artifact no test fetched yet.
    operation(8, "shirudo-test-tree-match", this_node, match_artifact),
    operation(9, "shirudo-test-tree-skip", other_node, skip_artifact),
    operation(10, "shirudo-test-uprobe-multi", this_node, absent_artifact),
    operation(11, "shirudo-test-tree-match", other_node, match_artifact),
    operation(12, "shirudo-test-tree-skip", this_node, skip_artifact),
    operation(13, "shirudo-test-tree-skip", this_node, skip_unload_artifact,
              op="delete"),
    # t7107: fixes as a publisher writes it, then fixes no publisher
    # writes, on a delete and on an operation without a match.
    operation(14, "shirudo-test-tree-skip", this_node, skip_artifact,
              fixes=["EXAMPLE-0101"]),
    operation(15, "shirudo-test-tree-skip", this_node, skip_unload_artifact,
              op="delete",
              fixes={"not": ["an", "array"], "n": [1, None, "\u0007"]}),
    operation(16, "shirudo-test-tree-match", other_node, match_artifact,
              fixes=["", "B", "A", "A", "x y\n"] +
                    ["ID-%d" % i for i in range(17)]),
    # t7109: an add, a delete and an add this node takes, then three it
    # passes over, the masks of node A and node B of the release example.
    operation(17, "shirudo-test-tree-match", this_node, match_artifact),
    operation(18, "shirudo-test-tree-match", this_node,
              match_unload_artifact, op="delete"),
    operation(19, "shirudo-test-tree-match", this_node, match_artifact),
    operation(20, "shirudo-test-tree-skip", other_node, skip_artifact),
    operation(21, "shirudo-test-tree-skip", other_node,
              skip_unload_artifact, op="delete"),
    operation(22, "shirudo-test-tree-skip", other_node, skip_artifact),
]
heads = {"stable": 2, "updated": 3, "deleted": 4, "restored": 5,
         "kconfig": 6, "reloaded": 7, "outcomes": 10, "stopped": 12,
         "fetched": 13, "fixes": 16, "keepalive": 19, "unmatched": 22}
for generation, (reference, head) in enumerate(heads.items(), start=1):
    publication = {
        "schema": 1,
        "tree_id": "shirudo-test-tree",
        "generation": generation,
        "base": {"seq": 0},
        "operations": operations[:head],
        "head": {"seq": head},
    }
    payloads.with_name(payloads.name + "-" + reference + ".json") \
        .write_bytes(json.dumps(publication, separators=(",", ":"))
                     .encode())
PY

	for reference in stable updated deleted restored kconfig reloaded \
			 outcomes stopped fetched fixes keepalive unmatched; do
		openssl cms -sign -binary -md sha512 \
			-in "$payloads-$reference.json" \
			-signer "$FIXTURE_WORK/trusted/cert.der" \
			-inkey "$FIXTURE_WORK/trusted/signing_key.pem" \
			-outform DER -out "$payloads-$reference.sig" \
			-nosmimecap -nocerts -keyid
	done

	python3 - "$registry_dir" "$payloads" <<'PY'
import hashlib
import json
import pathlib
import sys

registry, payloads = map(pathlib.Path, sys.argv[1:3])
repo = registry / "shirudo" / "upatch-tree"


def digest(body):
    return "sha256:" + hashlib.sha256(body).hexdigest()


def write(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)


for reference in ("stable", "updated", "deleted", "restored", "kconfig",
                  "reloaded", "outcomes", "stopped", "fetched", "fixes",
                  "keepalive", "unmatched"):
    stem = payloads.name + "-" + reference
    payload = payloads.with_name(stem + ".json").read_bytes()
    signature = payloads.with_name(stem + ".sig").read_bytes()
    payload_digest = digest(payload)
    signature_digest = digest(signature)
    write(repo / "blobs" / payload_digest, payload)
    write(repo / "blobs" / signature_digest, signature)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": [
            {"mediaType": "application/vnd.shirudo.upatch.tree.v1+json",
             "digest": payload_digest, "size": len(payload)},
            {"mediaType": "application/vnd.shirudo.upatch.tree.signature.v1",
             "digest": signature_digest, "size": len(signature)},
        ],
    }
    write(repo / "manifests" / reference,
          json.dumps(manifest, separators=(",", ":")).encode())
PY
}

# The tree t7108 walks: one operation per append with --segment-ops 2, so
# segments of two, published by bpm tree append to a registry on the
# loopback. Each generation's manifest stays as g<k>, and the test moves the
# reference the target follows from one to the next. Its artifacts name the
# registry's port, so the guest serves the copy on the same one.
build_tree_segments_registry()
{
	local work="$FIXTURE_WORK/segments"
	local registry="$TMP_DIR/fixtures/segments-oci"
	local repo="$registry/shirudo/segments"
	local builder="$REPO_ROOT/tools/shirudo-build/shirudo-build"
	local pid port pkg op k

	mkdir -p "$work"
	for pkg in match other; do
		mkdir "$work/seg-$pkg"
		cp "$REPO_ROOT/testing/fixtures/segments/seg-$pkg/"* "$work/seg-$pkg/"
		ln -s "$REPO_ROOT/vendor" "$work/seg-$pkg/vendor"
		ln -s "$REPO_ROOT/bpf" "$work/seg-$pkg/bpf"
		(
			cd "$work"
			SHIRUDO_BUILD="$builder" "$REPO_ROOT/shirudo" bpm build \
				"$work/seg-$pkg" --version 1.0.0 \
				--keys-dir "$FIXTURE_WORK/trusted" \
				--vmlinux "$REPO_ROOT/vendor/linux/vmlinux.h" >/dev/null
		)
	done
	port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
	python3 "$REPO_ROOT/testing/helper/test-oci-registry.py" \
		--root "$registry" --port "$port" --writable \
		--ready-file "$work/ready" &
	pid=$!
	for k in $(seq 50); do
		[ -e "$work/ready" ] && break
		sleep 0.1
	done
	[ -e "$work/ready" ] || die "the segment registry did not start"
	# k = 1, 2, 0 mod 3: add the upatch this node takes, add one it does
	# not, delete the first.
	for k in $(seq 28); do
		case $((k % 3)) in
		1) pkg=match op=add ;;
		2) pkg=other op=add ;;
		*) pkg=match op=delete ;;
		esac
		env -u BPM_OCI_CA_FILE -u BPM_OCI_USERNAME -u BPM_OCI_PASSWORD \
			BPM_OCI_SCHEME=http REGISTRY_AUTH_FILE="$work/absent-auth.json" \
			NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 \
			SHIRUDO_BUILD="$builder" "$REPO_ROOT/shirudo" bpm tree append \
			"$work/seg-$pkg-1.0.0.bee" \
			"oci://127.0.0.1:$port/shirudo/segments" \
			--keys-dir "$FIXTURE_WORK/trusted" --tree-id shirudo-test-segments \
			--segment-ops 2 --op "$op" >/dev/null ||
			{ kill "$pid"; die "bpm tree append $k of the segment tree failed"; }
		cp "$repo/manifests/stable" "$repo/manifests/g$k"
	done
	# The guest has no shirudo-build: t7108 checks what bpm tree show
	# --walk printed of the whole tree here against the copy it serves.
	env -u BPM_OCI_CA_FILE -u BPM_OCI_USERNAME -u BPM_OCI_PASSWORD \
		BPM_OCI_SCHEME=http REGISTRY_AUTH_FILE="$work/absent-auth.json" \
		NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 \
		SHIRUDO_BUILD="$builder" "$REPO_ROOT/shirudo" bpm tree show \
		"oci://127.0.0.1:$port/shirudo/segments" \
		--cert "$FIXTURE_WORK/trusted/cert.der" --walk \
		>"$TMP_DIR/fixtures/segments-show-walk.json" ||
		{ kill "$pid"; die "bpm tree show --walk of the segment tree failed"; }
	kill "$pid"
	wait "$pid" 2>/dev/null || :
	printf '%s\n' "$port" >"$registry/port"

	# What the publisher refuses to write, re-signed as a registry that
	# holds the operator's key could: t7108's forks and a broken link.
	python3 - "$repo" "$work" <<'PY'
import hashlib
import json
import pathlib
import sys

repo, work = map(pathlib.Path, sys.argv[1:3])
DOC = "application/vnd.shirudo.upatch.tree.v1+json"


def digest(body):
    return "sha256:" + hashlib.sha256(body).hexdigest()


def manifest(ref):
    return (repo / "manifests" / ref).read_bytes()


def document(ref):
    layers = json.loads(manifest(ref))["layers"]
    blob = [layer for layer in layers if layer["mediaType"] == DOC][0]
    return json.loads((repo / "blobs" / blob["digest"]).read_bytes())


def with_digest(op):
    canonical = {k: v for k, v in op.items()
                 if k not in ("operation_digest", "fixes")}
    body = json.dumps(canonical, separators=(",", ":")).encode()
    return dict(canonical, operation_digest=digest(body))


g20, g22, g24 = document("g20"), document("g22"), document("g24")
pred = {"schema": 1, "tree_id": g20["tree_id"], "generation": 21,
        "parent_manifest_digest": digest(manifest("g20")),
        "base": {"seq": 20,
                 "segment_manifest_digest": digest(manifest("g18")),
                 "history_root": "ab" * 32},
        "operations": g22["operations"], "head": {"seq": 22}}
forked = dict(g20["operations"][0], selector={"labels": {"env": ["forked"]}})
docs = {
    # A predecessor that starts from another history than the node's.
    "fork-pred": pred,
    # The current segment, its first operation not the one nodes took.
    "fork-prefix": {"schema": 1, "tree_id": g20["tree_id"], "generation": 21,
                    "parent_manifest_digest": digest(manifest("g20")),
                    "base": g20["base"],
                    "operations": [with_digest(forked), g20["operations"][1],
                                   g22["operations"][0]],
                    "head": {"seq": 21}},
    # A segment that names a sealed one ending a step before its base.
    "head-gap": {"schema": 1, "tree_id": g20["tree_id"], "generation": 23,
                 "parent_manifest_digest": digest(manifest("g22")),
                 "base": {"seq": 23,
                          "segment_manifest_digest": digest(manifest("g22")),
                          "history_root": "cd" * 32},
                 "operations": [g24["operations"][1]], "head": {"seq": 24}},
}
for name, doc in docs.items():
    (work / (name + ".json")).write_bytes(
        json.dumps(doc, separators=(",", ":")).encode())
PY
	for name in fork-pred fork-prefix head-gap fork-base; do
		if [ "$name" = fork-base ]; then
			python3 - "$repo" "$work" <<'PY'
import hashlib
import json
import pathlib
import sys

repo, work = map(pathlib.Path, sys.argv[1:3])
pred_manifest = (repo / "manifests" / "fork-pred").read_bytes()
pred = json.loads((work / "fork-pred.json").read_bytes())
for layer in json.loads((repo / "manifests" / "g24").read_bytes())["layers"]:
    if layer["mediaType"] == "application/vnd.shirudo.upatch.tree.v1+json":
        g24 = json.loads((repo / "blobs" / layer["digest"]).read_bytes())
root = bytes.fromhex(pred["base"]["history_root"])
for op in pred["operations"]:
    root = hashlib.sha256(b"shirudo-tree-history\0" + root +
                          bytes.fromhex(op["operation_digest"][7:])).digest()
pred_digest = "sha256:" + hashlib.sha256(pred_manifest).hexdigest()
# The segment after the forked predecessor, consistent with it.
doc = {"schema": 1, "tree_id": pred["tree_id"], "generation": 23,
       "parent_manifest_digest": pred_digest,
       "base": {"seq": 22, "segment_manifest_digest": pred_digest,
                "history_root": root.hex()},
       "operations": g24["operations"], "head": {"seq": 24}}
(work / "fork-base.json").write_bytes(
    json.dumps(doc, separators=(",", ":")).encode())
PY
		fi
		openssl cms -sign -binary -md sha512 -in "$work/$name.json" \
			-signer "$FIXTURE_WORK/trusted/cert.der" \
			-inkey "$FIXTURE_WORK/trusted/signing_key.pem" \
			-outform DER -out "$work/$name.sig" \
			-nosmimecap -nocerts -keyid
		python3 - "$repo" "$work" "$name" <<'PY'
import hashlib
import json
import pathlib
import sys

repo, work = map(pathlib.Path, sys.argv[1:3])
name = sys.argv[3]


def digest(body):
    return "sha256:" + hashlib.sha256(body).hexdigest()


payload = (work / (name + ".json")).read_bytes()
signature = (work / (name + ".sig")).read_bytes()
for body in (payload, signature):
    (repo / "blobs" / digest(body)).write_bytes(body)
manifest = json.dumps({
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "layers": [
        {"mediaType": "application/vnd.shirudo.upatch.tree.v1+json",
         "digest": digest(payload), "size": len(payload)},
        {"mediaType": "application/vnd.shirudo.upatch.tree.signature.v1",
         "digest": digest(signature), "size": len(signature)},
    ],
}, separators=(",", ":")).encode()
for ref in (name, digest(manifest)):
    (repo / "manifests" / ref).write_bytes(manifest)
PY
	done
}

build_obs_fixture()
{
	local keys_dir="$1"
	local source_dir="$FIXTURE_WORK/kernel-obs"

	# The fixture watches reserved addresses so attempts against the
	# watch list can be exercised without external network state.
	mkdir -p "$source_dir/decoders"
	for source in \
		kernel-obs.bpf.c obs_common.h obs_table.h obs_priv.bpf.c \
		obs_exec.bpf.c obs_net.bpf.c obs_dns.bpf.c obs_file.bpf.c \
		gen_watch.py gen_file_watch.py file-watch.list; do
		cp "$REPO_ROOT/upatches/kernel-obs/$source" "$source_dir/$source"
	done
	cp "$REPO_ROOT/upatches/kernel-obs/decoders/"*.lua "$source_dir/decoders/"
	cat >"$source_dir/watch.list" <<'EOF'
203.0.113.10/32
2001:db8::10/128
EOF
	python3 "$source_dir/gen_watch.py" \
		"$source_dir/watch.list" "$source_dir/watch_generated.h"
	python3 "$source_dir/gen_file_watch.py" \
		"$source_dir/file-watch.list" "$source_dir/file_watch_generated.h"

	(
		cd "$REPO_ROOT"
		"$REPO_ROOT/tools/shirudo-build/shirudo-build" \
			"$source_dir/kernel-obs.bpf.c" \
			-o "$TMP_DIR/fixtures/kernel-obs.upatch" \
			--name kernel-obs --vmlinux "$REPO_ROOT/vendor/linux/vmlinux.h" \
			--extra-cflags "-I$REPO_ROOT/vendor/libbpf" \
		--key "$keys_dir/signing_key.pem" \
		--cert "$keys_dir/cert.der"
	)
	sed 's/^#define BPF_NO_KFUNC_PROTOTYPES/#define TEST_CRED_ANOMALY\
#define BPF_NO_KFUNC_PROTOTYPES/' \
		"$source_dir/kernel-obs.bpf.c" \
		>"$source_dir/kernel-obs-cred-anomaly.bpf.c"
	(
		cd "$REPO_ROOT"
		"$REPO_ROOT/tools/shirudo-build/shirudo-build" \
			"$source_dir/kernel-obs-cred-anomaly.bpf.c" \
			-o "$TMP_DIR/fixtures/kernel-obs-cred-anomaly.upatch" \
			--name kernel-obs --vmlinux "$REPO_ROOT/vendor/linux/vmlinux.h" \
			--extra-cflags "-I$REPO_ROOT/vendor/libbpf" \
			--key "$keys_dir/signing_key.pem" \
			--cert "$keys_dir/cert.der"
	)
}

build_policy_labels_fixture()
{
	local source_dir="$FIXTURE_WORK/policy-labels"
	local package="$FIXTURE_WORK/policy-labels-1.0.0.bee"

	mkdir -p "$source_dir"
	cp "$REPO_ROOT/testing/fixtures/policy-labels/Beefile" \
		"$REPO_ROOT/testing/fixtures/policy-labels/policy-labels.bpf.c" \
		"$source_dir/"
	ln -s "$REPO_ROOT/vendor" "$source_dir/vendor"
	ln -s "$REPO_ROOT/bpf" "$source_dir/bpf"
	(
		cd "$FIXTURE_WORK"
		SHIRUDO_BUILD="$REPO_ROOT/tools/shirudo-build/shirudo-build" \
			"$REPO_ROOT/shirudo" bpm build "$source_dir" \
			--version 1.0.0 --keys-dir "$FIXTURE_WORK/trusted" \
			--vmlinux "$REPO_ROOT/vendor/linux/vmlinux.h"
	)
	tar -xOf "$package" \
		policy-labels-1.0.0/upatches/policy-labels.upatch \
		>"$TMP_DIR/fixtures/shirudo-test-policy-labels.upatch"
	tar -xOf "$package" \
		policy-labels-1.0.0/upatches/policy-labels.unload.upatch \
		>"$TMP_DIR/fixtures/shirudo-test-policy-labels.unload.upatch"
}

build_policy_exec_graph_fixture()
{
	local source_dir="$FIXTURE_WORK/policy-exec-graph"
	local package="$FIXTURE_WORK/policy-exec-graph-1.0.0.bee"

	mkdir -p "$source_dir"
	cp "$REPO_ROOT/testing/fixtures/policy-exec-graph/Beefile" \
		"$REPO_ROOT/testing/fixtures/policy-exec-graph/policy-exec-graph.bpf.c" \
		"$source_dir/"
	ln -s "$REPO_ROOT/vendor" "$source_dir/vendor"
	ln -s "$REPO_ROOT/bpf" "$source_dir/bpf"
	(
		cd "$FIXTURE_WORK"
		SHIRUDO_BUILD="$REPO_ROOT/tools/shirudo-build/shirudo-build" \
			"$REPO_ROOT/shirudo" bpm build "$source_dir" \
			--version 1.0.0 --keys-dir "$FIXTURE_WORK/trusted" \
			--vmlinux "$REPO_ROOT/vendor/linux/vmlinux.h"
	)
	tar -xOf "$package" \
		policy-exec-graph-1.0.0/upatches/policy-exec-graph.upatch \
		>"$TMP_DIR/fixtures/shirudo-test-policy-exec-graph.upatch"
	tar -xOf "$package" \
		policy-exec-graph-1.0.0/upatches/policy-exec-graph.unload.upatch \
		>"$TMP_DIR/fixtures/shirudo-test-policy-exec-graph.unload.upatch"
}

log "building target-test fixtures on the operator host"
mkdir -p "$TMP_DIR/fixtures/decoders" "$FIXTURE_WORK/trusted" \
	"$FIXTURE_WORK/foreign" "$FIXTURE_WORK/own" "$FIXTURE_WORK/third"
# Fixture keys are ML-DSA-87 like every shirudo key; the host OpenSSL must
# be 3.5 or newer, which the operator build already requires.
"$REPO_ROOT/shirudo" genkey --keys-dir "$FIXTURE_WORK/trusted" >/dev/null
"$REPO_ROOT/shirudo" genkey --keys-dir "$FIXTURE_WORK/foreign" >/dev/null
"$REPO_ROOT/shirudo" genkey --keys-dir "$FIXTURE_WORK/own" >/dev/null
"$REPO_ROOT/shirudo" genkey --keys-dir "$FIXTURE_WORK/third" >/dev/null

"${CC:-cc}" -O0 -g -Wl,--build-id=sha1 \
	-o /tmp/shirudo-test-uprobe-target \
	"$REPO_ROOT/testing/fixtures/uprobe-target.c"

pids=()
queue_fixture build_fixture basic.bpf.c shirudo-test-basic "$FIXTURE_WORK/trusted"
queue_fixture build_fixture basic.bpf.c shirudo-test-lifecycle "$FIXTURE_WORK/trusted"
queue_fixture build_fixture basic.bpf.c shirudo-test-tree-match "$FIXTURE_WORK/trusted"
queue_fixture build_fixture basic.bpf.c shirudo-test-tree-skip "$FIXTURE_WORK/trusted"
queue_fixture build_fixture marker.bpf.c shirudo-test-marker "$FIXTURE_WORK/trusted"
queue_fixture build_fixture map-export.bpf.c shirudo-test-map-export "$FIXTURE_WORK/trusted"
queue_fixture build_fixture otel-backend.bpf.c shirudo-test-otel-backend "$FIXTURE_WORK/trusted"
queue_fixture build_fixture serialized-metric.bpf.c shirudo-test-serialized-metric "$FIXTURE_WORK/trusted"
queue_fixture build_fixture arena-tree-serializer.bpf.c shirudo-test-arena-tree "$FIXTURE_WORK/trusted"
queue_fixture build_fixture uprobe-multi.bpf.c shirudo-test-uprobe-multi "$FIXTURE_WORK/trusted"
queue_fixture build_fixture uretprobe-multi.bpf.c shirudo-test-uretprobe-multi "$FIXTURE_WORK/trusted"
queue_fixture build_fixture uprobe-multi-sleepable.bpf.c shirudo-test-uprobe-multi-sleepable "$FIXTURE_WORK/trusted"
queue_fixture build_fixture uprobe.bpf.c shirudo-test-uprobe "$FIXTURE_WORK/trusted"
queue_fixture build_fixture uretprobe.bpf.c shirudo-test-uretprobe "$FIXTURE_WORK/trusted"
queue_fixture build_fixture scope-netfilter.bpf.c shirudo-test-scope-netfilter "$FIXTURE_WORK/trusted"
queue_fixture build_fixture scope-cgroup.bpf.c shirudo-test-scope-cgroup "$FIXTURE_WORK/trusted"
queue_fixture build_fixture scope-kprobe.bpf.c shirudo-test-scope-kprobe "$FIXTURE_WORK/trusted"
queue_fixture build_fixture xdp-virtual.bpf.c shirudo-test-xdp-virtual "$FIXTURE_WORK/trusted"
queue_fixture build_fixture xdp-virtual.bpf.c shirudo-test-xdp-conflict "$FIXTURE_WORK/trusted"
queue_fixture build_fixture xdp-vm.bpf.c shirudo-test-xdp-vm "$FIXTURE_WORK/trusted"
queue_fixture build_fixture basic.bpf.c shirudo-test-foreign "$FIXTURE_WORK/foreign"
queue_fixture build_fixture basic.bpf.c shirudo-test-own-keyring "$FIXTURE_WORK/own"
queue_fixture build_policy_labels_fixture
queue_fixture build_policy_exec_graph_fixture
queue_fixture build_obs_fixture "$FIXTURE_WORK/trusted"
wait_fixture_jobs

basic_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-basic.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
marker_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-marker.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
map_export_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-map-export.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
lifecycle_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-lifecycle.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
tree_match_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-tree-match.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
tree_skip_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-tree-skip.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
uprobe_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-uprobe-multi.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
uretprobe_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-uretprobe-multi.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
uprobe_sleepable_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-uprobe-multi-sleepable.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
uprobe_single_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-uprobe.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
uretprobe_single_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-uretprobe.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
otel_backend_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-otel-backend.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
serialized_metric_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-serialized-metric.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
arena_tree_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-arena-tree.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
observability_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/kernel-obs.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
observability_anomaly_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/kernel-obs-cred-anomaly.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
for xdp_kind in virtual conflict vm; do
	xdp_name="shirudo-test-xdp-$xdp_kind"
	xdp_payload="$($REPO_ROOT/shirudo upatch info \
		"$TMP_DIR/fixtures/$xdp_name.upatch" --json | \
		python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
	"$REPO_ROOT/tools/shirudo-build/shirudo-build" --unload "$xdp_name" \
		--payload-sha256 "$xdp_payload" \
		-o "$TMP_DIR/fixtures/$xdp_name.unload.upatch" \
		--key "$FIXTURE_WORK/trusted/signing_key.pem" \
		--cert "$FIXTURE_WORK/trusted/cert.der"
done

for scope in netfilter cgroup kprobe; do
	scope_payload="$($REPO_ROOT/shirudo upatch info \
		"$TMP_DIR/fixtures/shirudo-test-scope-$scope.upatch" --json |
		python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
	queue_fixture "$REPO_ROOT/tools/shirudo-build/shirudo-build" --unload \
		"shirudo-test-scope-$scope" --payload-sha256 "$scope_payload" \
		-o "$TMP_DIR/fixtures/shirudo-test-scope-$scope.unload.upatch" \
		--key "$FIXTURE_WORK/trusted/signing_key.pem" \
		--cert "$FIXTURE_WORK/trusted/cert.der"
done
wait_fixture_jobs
# Enough loaded upatches to outgrow the fixed part of a status document.
mkdir -p "$TMP_DIR/fixtures/many"
pids=()
for i in $(seq -w 1 80); do
	queue_fixture build_many_fixture "$i"
done
wait_fixture_jobs
pids=()
while read -r name payload output; do
	queue_fixture "$REPO_ROOT/tools/shirudo-build/shirudo-build" --unload \
		"$name" --payload-sha256 "$payload" \
		-o "$TMP_DIR/fixtures/$output" \
		--key "$FIXTURE_WORK/trusted/signing_key.pem" \
		--cert "$FIXTURE_WORK/trusted/cert.der"
done <<EOF
shirudo-test-basic $basic_payload shirudo-test-basic.unload.upatch
shirudo-test-basic $(printf 'aa%.0s' {1..32}) shirudo-test-basic-mismatch.unload.upatch
shirudo-test-marker $marker_payload shirudo-test-marker.unload.upatch
shirudo-test-lifecycle $lifecycle_payload shirudo-test-lifecycle.unload.upatch
shirudo-test-tree-match $tree_match_payload shirudo-test-tree-match.unload.upatch
shirudo-test-tree-skip $tree_skip_payload shirudo-test-tree-skip.unload.upatch
shirudo-test-map-export $map_export_payload shirudo-test-map-export.unload.upatch
shirudo-test-otel-backend $otel_backend_payload shirudo-test-otel-backend.unload.upatch
shirudo-test-serialized-metric $serialized_metric_payload shirudo-test-serialized-metric.unload.upatch
shirudo-test-arena-tree $arena_tree_payload shirudo-test-arena-tree.unload.upatch
kernel-obs $observability_payload kernel-obs.unload.upatch
kernel-obs $observability_anomaly_payload kernel-obs-cred-anomaly.unload.upatch
shirudo-test-uprobe-multi $uprobe_payload shirudo-test-uprobe-multi.unload.upatch
shirudo-test-uretprobe-multi $uretprobe_payload shirudo-test-uretprobe-multi.unload.upatch
shirudo-test-uprobe-multi-sleepable $uprobe_sleepable_payload shirudo-test-uprobe-multi-sleepable.unload.upatch
shirudo-test-uprobe $uprobe_single_payload shirudo-test-uprobe.unload.upatch
shirudo-test-uretprobe $uretprobe_single_payload shirudo-test-uretprobe.unload.upatch
EOF
wait_fixture_jobs

tree_match_unload_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-tree-match.unload.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
tree_skip_unload_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-tree-skip.unload.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
build_tree_test_registry
build_tree_segments_registry

mv /tmp/shirudo-test-uprobe-target \
	"$TMP_DIR/fixtures/shirudo-test-uprobe-target"

cp "$FIXTURE_WORK/trusted/cert.der" "$TMP_DIR/fixtures/cert.der"
cp "$FIXTURE_WORK/own/cert.der" "$TMP_DIR/fixtures/own.der"
# The own certificate joins the enrolled set vouched for by the trusted
# key; the third one is for the tests of `keys add` at runtime.
cp "$FIXTURE_WORK/third/cert.der" "$TMP_DIR/fixtures/third.der"
for vouched in own third; do
	"$REPO_ROOT/tools/shirudo-build/shirudo-build" keys vouch \
		"$TMP_DIR/fixtures/$vouched.der" \
		-o "$TMP_DIR/fixtures/$vouched.vouch" \
		--key "$FIXTURE_WORK/trusted/signing_key.pem" \
		--cert "$FIXTURE_WORK/trusted/cert.der" >/dev/null
done
if [[ -n "$PACKAGE_CERT" ]]; then
	install -m 0644 "$PACKAGE_CERT" "$TMP_DIR/fixtures/package-cert.der"
else
	install -m 0644 "$FIXTURE_WORK/trusted/cert.der" \
		"$TMP_DIR/fixtures/package-cert.der"
fi
(
	cd "$TMP_DIR/fixtures"
	sha256sum -- *.upatch cert.der own.der own.vouch third.der \
		third.vouch package-cert.der > manifest
)

"$REPO_ROOT/testing/vm/bundle-images.sh" "$TMP_DIR" "$FIXTURE_WORK" \
	"$FIXTURE_WORK/trusted" "$FIXTURE_WORK/own"
printf '%s\n' "$TEST_VM_MODE" >"$TMP_DIR/test-mode"

printf 'shirudo-test-vm-bundle-v1\n' >"$TMP_DIR/format"
printf 'vendored-tools\n' >"$TMP_DIR/dependency-mode"
printf 'shirudo-test-vm-bundle-stamp-v1\n' >"$TMP_DIR/.stamp"
printf '%s\n' "$RUNTIME_KEY" >"$TMP_DIR/runtime-image-key"

# The end-to-end test publishes a package the target trusts, with the key
# that signs the fixtures. Keep its private half outside the guest share.
rm -rf -- "$OPERATOR_KEYS_DIR"
install -d -m 0700 "$OPERATOR_KEYS_DIR"
cp -a "$FIXTURE_WORK/trusted" "$OPERATOR_KEYS_DIR/keys"
chmod 0600 "$OPERATOR_KEYS_DIR/keys/signing_key.pem"

rm -rf -- "$BUNDLE_DIR"
mv -- "$TMP_DIR" "$BUNDLE_DIR"
touch "$STAMP_FILE"
trap - EXIT
log "ready: $BUNDLE_DIR"
