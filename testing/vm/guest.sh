#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Guest-side half of testing/vm/run.sh. The host checkout is mounted
# read-only at /mnt/shirudo-src; all build writes stay in this VM.

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
export HOME=/root
export LOGNAME=root
export USER=root
LOWER=/mnt/shirudo-src
# shellcheck source=testing/vm/arch.sh
. "$LOWER/testing/vm/arch.sh"
BUNDLE=/mnt/shirudo-bundle
UPPER=/var/tmp/shirudo-upper
OVERLAY_WORK=/var/tmp/shirudo-overlay-work
WORKSPACE=/workspace/shirudo
VM_MODE="${VM_MODE:-test}"
VM_ROLE="${TEST_VM_ROLE:-target}"
SHIRUDO_BIN=/usr/local/bin/shirudo
VM_INITRD="${TEST_VM_INITRD:-1}"

log()
{
	printf '[test-vm guest] %s\n' "$*"
}

report_boot_memory()
{
	local total available used percent

	total="$(awk '$1 == "MemTotal:" { print $2; exit }' /proc/meminfo)"
	available="$(awk '$1 == "MemAvailable:" { print $2; exit }' /proc/meminfo)"
	[[ "$total" =~ ^[0-9]+$ && "$available" =~ ^[0-9]+$ ]] || {
		log "could not read guest memory totals"
		return 1
	}
	used=$((total - available))
	percent="$(awk -v used="$used" -v total="$total" \
		'BEGIN { printf "%.2f", (used * 100) / total }')"
	{
		printf 'guest_mem_total_kb=%s\n' "$total"
		printf 'guest_mem_available_kb=%s\n' "$available"
		printf 'guest_mem_used_kb=%s\n' "$used"
		printf 'guest_mem_used_percent=%s\n' "$percent"
	} > /mnt/shirudo-out/boot-memory
	log "guest memory: total=${total}KiB available=${available}KiB used=${used}KiB (${percent}%)"
}

install_kernel_modules()
{
	local module_root="${TEST_VM_KERNEL_MODULES:-}"
	local release source target module

	[[ -z "$module_root" ]] && return 0
	release="$(uname -r)"
	source="${module_root}/${release}"
	target="/lib/modules/${release}"
	[[ -d "$source" ]] || {
		log "kernel module artifact has no modules for ${release}"
		return 1
	}
	install -d /lib/modules
	install -d "$target"
	rsync -a --delete "${source}/" "${target}/"
	depmod -a "$release"

	for module in veth bridge 8021q nf_flow_table nf_flow_table_inet; do
		modprobe "$module"
	done
	for module in veth bridge 8021q nf_flow_table nf_flow_table_inet; do
		if [[ -d "/sys/module/$module" ]]; then
			continue
		fi
		# Built-in modules without parameters need not appear in sysfs.
		grep -Eq "(^|/)$module\.ko$" "$target/modules.builtin" || {
			log "required networking module is unavailable: $module"
			return 1
		}
	done
	# nf_flow_table_procfs (CONFIG_NF_FLOW_TABLE_PROCFS) is built into
	# nf_flow_table.ko when enabled; it therefore does not have a separate
	# /sys/module entry. Validate the
	# procfs interface exposed by the feature instead.
	test -r /proc/net/stat/nf_flowtable
}

install_kernel_config()
{
	local source="/mnt/shirudo-kernel/kernel.config"
	local release

	[[ -r "$source" ]] || return 0
	release="$(uname -r)"
	install -d /boot
	install -m 0644 "$source" "/boot/config-${release}"
	log "installed kernel config for ${release}"
}

configure_oci_ca()
{
	local ca_file="${TEST_VM_OCI_CA:-}"

	[[ -z "$ca_file" ]] && return 0
	[[ "$ca_file" == /mnt/shirudo-oci/ca.crt && -s "$ca_file" ]] || {
		log "OCI CA file is missing from the host share"
		return 1
	}
	install -d -m 0755 /usr/local/share/ca-certificates
	install -m 0644 "$ca_file" \
		/usr/local/share/ca-certificates/shirudo-oci-ca.crt
	update-ca-certificates
}

configure_bpm_oci_repository()
{
	local input_dir="${TEST_VM_BPM_OCI_INPUT:-}"
	local source="${TEST_VM_BPM_OCI_SOURCE:-}"
	local endpoint cert_file staged_conf staged_env
	local key_file conf_file repository_env

	[[ -z "$input_dir" && -z "$source" ]] && return 0
	[[ -n "$input_dir" && -n "$source" ]] || {
		log "BPM OCI staged input directory and source must be supplied together"
		return 1
	}
	[[ "$source" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || {
		log "BPM OCI repository source name is invalid"
		return 1
	}
	cert_file="${input_dir}/keys/${source}.pem"
	staged_conf="${input_dir}/registries.d/${source}.conf"
	staged_env="${input_dir}/repository.env"
	[[ -s "$cert_file" && -s "$staged_conf" && -s "$staged_env" ]] || {
		log "BPM OCI staged input is incomplete"
		return 1
	}
	endpoint="$(sed -n 's/^endpoint = //p' "$staged_conf")"
	[[ "$endpoint" =~ ^oci://[^/!?#@=[:space:]]+$ ]] || {
		log "BPM OCI staged configuration has an invalid endpoint"
		return 1
	}

	if [[ "${endpoint#oci://}" == registry.test ||
		"${endpoint#oci://}" == registry.test:* ]]; then
		sed -E -i '/^[^#]*[[:space:]]registry\.test([[:space:]]|$)/d' /etc/hosts
		printf '%s\n' '10.0.2.2 registry.test' >>/etc/hosts
	fi

	key_file="/etc/shirudo/bpm/keys/${source}.pem"
	conf_file="/etc/shirudo/bpm/registries.d/${source}.conf"
	repository_env="/etc/shirudo/bpm/repository.env"
	environment_file="/etc/shirudo/bpm/environment"
	install -d -m 0755 /etc/shirudo/bpm/keys /etc/shirudo/bpm/registries.d
	install -m 0644 "$cert_file" "${key_file}.tmp"
	mv -f "${key_file}.tmp" "$key_file"
	install -m 0644 "$staged_conf" "${conf_file}.tmp"
	mv -f "${conf_file}.tmp" "$conf_file"
	install -d -m 0755 /etc/shirudo/bpm
	install -m 0644 "$staged_env" "${repository_env}.tmp"
	mv -f "${repository_env}.tmp" "$repository_env"
	# The BPM tree and individual upatches are signed by the active package
	# certificate.  The repository certificate above is for OCI admission.
	if [[ -s /usr/local/share/ca-certificates/shirudo-oci-ca.crt ]]; then
		printf '%s\n' 'BPM_OCI_CA_FILE=/usr/local/share/ca-certificates/shirudo-oci-ca.crt' \
			>"${environment_file}.tmp"
		chmod 0644 "${environment_file}.tmp"
		mv -f "${environment_file}.tmp" "$environment_file"
	else
		rm -f "$environment_file"
	fi
}

configure_bpm_tree()
{
	local tree_input="${TEST_VM_BPM_TREE_INPUT:-}"
	local config_file="${tree_input}/upatch-tree.conf"
	local target=/etc/shirudo/bpm/upatch-tree.conf
	local temporary="${target}.tmp.$$"

	[[ -z "$tree_input" ]] && return 0
	[[ -f "$config_file" && -s "$config_file" ]] || {
		log "BPM tree configuration is missing or empty"
		return 1
	}
	install -d -m 0755 /etc/shirudo/bpm
	install -m 0644 "$config_file" "$temporary"
	mv -f "$temporary" "$target"
}

configure_map_export()
{
	local endpoint="${TEST_VM_MAP_EXPORT_ENDPOINT:-}"
	local tenant_id="${TEST_VM_MAP_EXPORT_TENANT_ID:-}"
	local insecure="${TEST_VM_MAP_EXPORT_INSECURE:-}"
	local ca_file="${TEST_VM_MAP_EXPORT_CA:-}"

	if [[ -z "$endpoint" && -z "$tenant_id" && -z "$insecure" &&
	      -z "$ca_file" ]]; then
		return 0
	fi
	[[ -n "$endpoint" && -n "$tenant_id" &&
	   ("$insecure" == "true" || "$insecure" == "false") ]] || {
		log "invalid map-export bridge settings"
		return 1
	}
	if [[ "$endpoint" == https://* ]]; then
		[[ "$insecure" == "false" ]] || {
			log "secure HTTPS map-export requires insecure=false"
			return 1
		}
	elif [[ "$endpoint" == http://* ]]; then
		[[ "$insecure" == "true" ]] || {
			log "cleartext HTTP map-export requires insecure=true"
			return 1
		}
	else
		log "map-export endpoint must use http:// or https://"
		return 1
	fi
	if [[ -n "$ca_file" ]]; then
		[[ "$ca_file" == /mnt/shirudo-otel/ca.pem && -s "$ca_file" ]] || {
			log "OTEL CA file is missing from the host share"
			return 1
		}
		install -d -m 0750 /etc/shirudo/otel
		install -m 0644 "$ca_file" /etc/shirudo/otel/ca.pem
		install -d -m 0750 /etc/shirudo
		printf '%s\n' \
			'OTEL_EXPORTER_OTLP_CERTIFICATE=/etc/shirudo/otel/ca.pem' \
			>/etc/shirudo/map-export.env
		chmod 0640 /etc/shirudo/map-export.env
	fi

	log "configuring OTEL map-export bridge"
	# QEMU user networking exposes the host as 10.0.2.2. Remove any
	# stale entry first so repeated boots always use the bridge address.
	sed -E -i '/^[^#]*[[:space:]]otel\.test([[:space:]]|$)/d' /etc/hosts
	printf '%s\n' '10.0.2.2 otel.test' >>/etc/hosts
	install -d -m 0755 /etc/shirudo
	printf '%s\n' \
		"map_export.otel_endpoint = $endpoint" \
		"map_export.otel_insecure = $insecure" \
		"map_export.tenant_id = $tenant_id" \
		>/etc/shirudo/shirudo.conf
}

# The end-to-end nodes and the interactive VMs run an image that the
# keepalive backend knows by its os-release id and version, the latter
# test-vm at the version the host gives for its runtime image. Their root
# is not a dm-verity image, so the command line names no roothash= and the
# backend binds them as declared.
configure_image_identity()
{
	if [[ "${TEST_VM_SUITE:-}" == end2end ]]; then
		cat /usr/lib/os-release "$LOWER/testing/vm/files/end2end.os-release" \
			>/etc/os-release.tmp
	elif [[ -n "${TEST_VM_IMAGE_VERSION:-}" ]]; then
		{
			cat /usr/lib/os-release
			printf 'IMAGE_ID=test-vm\nIMAGE_VERSION=%s\n' "$TEST_VM_IMAGE_VERSION"
		} >/etc/os-release.tmp
	else
		return 0
	fi
	mv -f /etc/os-release.tmp /etc/os-release
}

# Target tests run from this script in test mode and from an SSH session
# otherwise, which inherits nothing from it.
write_target_test_env()
{
	{
		printf 'export SHIRUDO_BIN=%q\n' "$SHIRUDO_BIN"
		printf 'export SHIRUDO_TEST_KEY_FIXTURES=%q\n' "$BUNDLE/verity"
		printf 'export SHIRUDO_TEST_RESULTS=%q\n' /mnt/shirudo-out/verity
		printf 'export SHIRUDO_TEST_FIXTURES_DIR=%q\n' "$BUNDLE/fixtures"
		printf 'export SHIRUDO_TEST_FAILURES_FILE=%q\n' \
			/mnt/shirudo-out/failed-tests
		printf 'export SHIRUDO_TEST_SUITE_FAILURES_FILE=%q\n' \
			/mnt/shirudo-out/failed-suites
		printf 'export TEST_FILTER=%q\n' "${TEST_FILTER:-}"
	} >/etc/shirudo-test-vm.env
}

# The operator holds the signing key and is no target: it has no TPM, and its
# shirudo is the operator package, built here for the distribution it runs
# on, as that package must be, from the files git sees in the checkout,
# which the host lists.
prepare_operator()
{
	local src=/var/tmp/shirudo-operator-src
	local build_log=/mnt/shirudo-out/operator-build.log
	local files=/mnt/shirudo-out/source-files
	local debs

	if [[ -e /dev/tpm0 || -e /dev/tpmrm0 ]]; then
		log "the operator VM has a TPM"
		return 1
	fi
	[[ -s /mnt/shirudo-operator-keys/signing_key.pem ]] || {
		log "the operator VM has no signing key"
		return 1
	}
	[[ -s "$files" ]] || {
		log "the host listed no files of the checkout"
		return 1
	}
	sed -E -i '/^[^#]*[[:space:]]registry\.test([[:space:]]|$)/d' /etc/hosts
	printf '%s\n' '10.0.2.2 registry.test' >>/etc/hosts

	log "building the operator package"
	rm -rf -- "$src"
	mkdir -p "$src"
	rsync -a --from0 --files-from="$files" --ignore-missing-args \
		"$LOWER"/ "$src"/
	if ! make -C "$src/packaging" -j"$(nproc)" bindeb-pkg PKG_ROLES=operator \
		>"$build_log" 2>&1; then
		tail -40 "$build_log"
		log "the operator package did not build; see operator-build.log"
		return 1
	fi
	debs=("$src"/shirudo-operator_*.deb)
	[[ ${#debs[@]} -eq 1 && -s "${debs[0]}" ]] || {
		log "expected one operator package in $src"
		return 1
	}
	dpkg -i "${debs[0]}"
	shirudo version
}

configure_oci_ca
configure_bpm_oci_repository
configure_map_export
configure_image_identity

[[ -s /etc/shirudo-test-vm-runtime ]] || {
	log "prepared runtime image is missing; run make -C testing bundle"
	exit 1
}
log "using prepared Ubuntu runtime image"

log "configuring loopback root SSH for direct target access"
install -d -m 0700 /root/.ssh
ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519
cat /root/.ssh/id_ed25519.pub >>/root/.ssh/authorized_keys
if [[ -n "${TEST_VM_SSH_PUBLIC_KEY:-}" ]]; then
	printf '%s\n' "$TEST_VM_SSH_PUBLIC_KEY" >>/root/.ssh/authorized_keys
fi
chmod 0600 /root/.ssh/authorized_keys
install -d -m 0755 /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/99-shirudo-test-vm.conf <<'EOF'
PermitRootLogin prohibit-password
PasswordAuthentication no
EOF
passwd -d root >/dev/null
systemctl enable --now ssh
systemctl enable --now "serial-getty@${TEST_VM_ARCH_CONSOLE}.service"

mkdir -p "$UPPER" "$OVERLAY_WORK" "$WORKSPACE"
if mount -t overlay overlay \
	-o "lowerdir=${LOWER},upperdir=${UPPER},workdir=${OVERLAY_WORK}" \
	"$WORKSPACE"; then
	log "preparing a guest overlay over the read-only checkout"
else
	log "overlay-on-9p unavailable; copying the test checkout into the guest"
	rm -rf -- "$WORKSPACE"
	mkdir -p "$WORKSPACE"
	rsync -a --exclude=/.git/ --exclude=/artifacts/ --exclude=/build/ \
		"$LOWER"/ "$WORKSPACE"/
fi

cd "$WORKSPACE"

if [[ "$VM_ROLE" == operator ]]; then
	prepare_operator
	log "operator prepared; the host runs its steps over SSH"
	exit 0
fi

log "installing networking modules from the booted kernel artifact"
install_kernel_modules
install_kernel_config

log "importing host-built shirudo payload"
log "host bundle dependency mode: $(<"$BUNDLE/dependency-mode")"
install -d /usr/local/bin
# Booted from the shirudo initrd the binary is already in place and its
# inode is the identity init recorded; replacing it would lock the root
# out of its own pins.
cmp -s "$BUNDLE/root/usr/local/bin/shirudo" /usr/local/bin/shirudo ||
	install -m 0755 "$BUNDLE/root/usr/local/bin/shirudo" /usr/local/bin/shirudo
TARGET_UNITS=(
	shirudo.service
	shirudo-map-export.service
	shirudo-map-export.timer
	shirudo-keepalive.service
	shirudo-keepalive.timer
	shirudo-xdp-reconcile.service
	shirudo-xdp-reconcile.timer
	shirudo-bpm-repo-update.service
	shirudo-bpm-repo-update.timer
	shirudo-bpm-tree-sync.service
	shirudo-bpm-tree-sync.timer
)
install -d /usr/lib/systemd/system
for unit in "${TARGET_UNITS[@]}"; do
	install -m 0644 \
		"$BUNDLE/root/usr/lib/systemd/system/$unit" \
		"/usr/lib/systemd/system/$unit"
done
	systemctl daemon-reload
cp -a "$BUNDLE/test-helpers/." "$WORKSPACE/"

log "checking custom-kernel and vTPM prerequisites"
mountpoint -q /sys/kernel/security || mount -t securityfs securityfs /sys/kernel/security
grep -qw bpf /sys/kernel/security/lsm
grep -aq signature_size /sys/kernel/btf/vmlinux
test -c /dev/tpm0
test -c /dev/tpmrm0
tpm2_getrandom 8 >/dev/null
if [[ -r /sys/module/bpf/parameters/keyring_unsealed ]]; then
	log "bpf.keyring_unsealed=$(</sys/module/bpf/parameters/keyring_unsealed)"
else
	log "bpf.keyring_unsealed parameter is missing"
fi
if ! grep -F 'keyring .bpf' /proc/keys; then
	log ".bpf keyring is absent from /proc/keys"
fi

if [[ "$VM_INITRD" == 1 ]]; then
	log "initrd shirudo journal"
	journalctl -b -u shirudo-initrd.service --no-pager | tail -40 || true
fi

if [[ "${TEST_VM_SUITE:-}" == register ]]; then
	[[ "$VM_INITRD" == 0 ]] || {
		log "register protocol tests must precede production initialization"
		exit 1
	}
	log "running register protocol tests with a TPM writer"
	: >/mnt/shirudo-out/failed-tests
	: >/mnt/shirudo-out/failed-suites
	(
		cd testing
		. ./test-filter.sh
		for t in functional/tpm/t400[34]-*.sh; do
			test_matches "$t" || continue
			SHIRUDO_TEST_REGISTER_VM=1 \
				SHIRUDO_TEST_FAILURES_FILE=/mnt/shirudo-out/failed-tests \
				sh "$t"
		done
	)
	exit 0
fi

(cd "$BUNDLE/verity" && sha256sum -c manifest)
if ! mountpoint -q /run/shirudo/runtime ||
   ! mountpoint -q /run/shirudo/config; then
	log "the initrd did not mount the runtime and config images; its shirudo journal is above"
	exit 1
fi
install -m 0755 "$BUNDLE/verity/shirudo-runtime" /usr/local/bin/shirudo-runtime
SHIRUDO_BIN=/usr/local/bin/shirudo-runtime
for unit in "${TARGET_UNITS[@]}"; do
	case "$unit" in *.service) ;; *) continue ;; esac
	unit_file="/usr/lib/systemd/system/$unit"
	exec_starts=$(sed -nE \
		's#^ExecStart=(-?)[^[:space:]]*/shirudo([[:space:]]|$)#ExecStart=\1/usr/local/bin/shirudo-runtime\2#p' \
		"$unit_file")
	exec_count=$(awk '/^ExecStart=/ { count++ } END { print count + 0 }' \
		"$unit_file")
	replacement_count=$(printf '%s\n' "$exec_starts" |
		awk '/^ExecStart=/ { count++ } END { print count + 0 }')
	if [[ "$exec_count" -eq 0 || "$replacement_count" -ne "$exec_count" ]]; then
		log "could not rewrite every ExecStart in $unit_file ($replacement_count/$exec_count)"
		exit 1
	fi
	mkdir -p "/etc/systemd/system/$unit.d"
	{
		printf '[Service]\nExecStart=\n%s\n' "$exec_starts"
	} >"/etc/systemd/system/$unit.d/runtime.conf"
done
systemctl daemon-reload
"$SHIRUDO_BIN" init
test -e /run/shirudo/bpffs/lsm_link
if [[ "$VM_INITRD" == 1 ]]; then
	log "checking that the initrd brought enforcement up"
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["lsm_attached"] is True, d["lsm_attached"]
assert d["tpm"]["bound_in"] == "initrd", d["tpm"]
'
	test ! -e /run/shirudo/eventlog.pending
fi
"$SHIRUDO_BIN" status --json >/tmp/shirudo-status.json
python3 - /tmp/shirudo-status.json <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as status_file:
    status = json.load(status_file)
tpm = status.get("tpm") or {}
if not tpm.get("chain"):
    raise SystemExit("shirudo status reported no bound register")
if tpm.get("chain_matches_eventlog") is not True:
    raise SystemExit("register does not match the shirudo eventlog")
PY

if [[ "$VM_MODE" == node ]]; then
	log "this node of the end2end suite takes the ${TEST_VM_NODE_ROLE} role"
	"$SHIRUDO_BIN" image update "/var/lib/shirudo/images/config-${TEST_VM_NODE_ROLE}"
fi
if [[ "${TEST_VM_SUITE:-}" == end2end ]]; then
	"$SHIRUDO_BIN" status --keepalive >/mnt/shirudo-out/keepalive.json
fi

if [[ "${TEST_VM_LOCAL_STACK:-0}" == 1 ]]; then
	"$SHIRUDO_BIN" image update /var/lib/shirudo/images/config-local-stack
	install -d /etc/shirudo/bpm
	printf '%s\n' 'BPM_OCI_CA_FILE=/usr/local/share/ca-certificates/shirudo-oci-ca.crt' \
		>/etc/shirudo/bpm/environment
fi

if [[ -n "${TEST_VM_BPM_TREE_INPUT:-}" ]]; then
	log "performing initial BPM tree sync"
	tree_sync_ok=0
	for tree_sync_attempt in 1 2 3; do
		if systemctl start shirudo-bpm-tree-sync.service; then
			tree_sync_ok=1
			break
		fi
		log "initial BPM tree sync attempt ${tree_sync_attempt} failed"
		systemctl status shirudo-bpm-tree-sync.service --no-pager || true
		journalctl -u shirudo-bpm-tree-sync.service -n 40 --no-pager || true
		[[ "$tree_sync_attempt" -lt 3 ]] && sleep 3
	done
	if [[ "$tree_sync_ok" -ne 1 ]]; then
		log "initial BPM tree sync failed after retries"
		exit 1
	fi
fi

report_boot_memory
write_target_test_env

if [[ "$VM_MODE" == node ]]; then
	log "node prepared; node mode runs no tests and starts no timers"
	exit 0
fi

if [[ "$VM_MODE" == interactive ]]; then
	# init above was deliberately run directly so the current boot gets one
	# TPM measurement; enable the service only for future boots and start the
	# periodic timers after initialization has completed.
	systemctl enable shirudo.service
	systemctl enable --now shirudo-map-export.timer
	systemctl enable --now shirudo-keepalive.timer
	install -D -m 0644 "$BUNDLE/root/usr/lib/udev/rules.d/90-shirudo-xdp-reconcile.rules" \
		/usr/lib/udev/rules.d/90-shirudo-xdp-reconcile.rules
	udevadm control --reload
	systemctl enable --now shirudo-xdp-reconcile.timer
	systemctl enable --now shirudo-bpm-repo-update.timer
	systemctl enable --now shirudo-bpm-tree-sync.timer

	log "guest prepared; interactive mode skipping integration tests"
	exit 0
fi

: >/mnt/shirudo-out/failed-tests
: >/mnt/shirudo-out/failed-suites
if [[ "$VM_MODE" == serve ]]; then
	log "guest prepared; the host runs the target tests over SSH"
	exit 0
fi

log "running target tests: $TEST_VM_SUITE"
(
	cd testing
	. /etc/shirudo-test-vm.env
	./run-target-tests.sh "$TEST_VM_SUITE"
)
log "integration suite passed"
