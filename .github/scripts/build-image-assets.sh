#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -euo pipefail

: "${SHIRUDO_DIR:?SHIRUDO_DIR must name the Shirudo checkout}"
: "${SHIRUDO_PACKAGE_DIR:?SHIRUDO_PACKAGE_DIR must name the downloaded Shirudo package artifact}"
: "${OUTPUT_DIR:?OUTPUT_DIR must name the artifact output directory}"

config_root="${SHIRUDO_DIR}/infra/image-inputs/config-root"
runtime_conf="${SHIRUDO_DIR}/infra/image-inputs/runtime-root/etc/shirudo/shirudo.conf"
bpf_cert="${SHIRUDO_DIR}/infra/certs/shirudo.der"
work_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/shirudo-image-build.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

config_keys_dir="${work_dir}/config-image-signing"
image_dir="${work_dir}/images"
asset_dir="${work_dir}/assets"
config_prefix="${image_dir}/initial"
runtime_prefix="${image_dir}/runtime"
runtime_service="${image_dir}/runtime-service.conf"
asset_tarball="${OUTPUT_DIR}/shirudo-image-assets.tar.gz"

test -d "$config_root"
test -s "$runtime_conf"
test -s "$bpf_cert"
test -x "${SHIRUDO_DIR}/tools/gen-image/shirudo-gen-image"
test -x "${SHIRUDO_DIR}/tools/gen-image/shirudo-gen-runtime"

install -d -m 0700 "$config_keys_dir" "$image_dir" "$asset_dir" "$OUTPUT_DIR"

additional_config_cert_args=()
if [[ -n "${SHIRUDO_ADDITIONAL_CONFIG_CERT_B64:-}" ]]; then
	additional_config_cert="${work_dir}/additional-config-cert.der"
	printf '%s' "$SHIRUDO_ADDITIONAL_CONFIG_CERT_B64" |
		base64 --decode > "$additional_config_cert"
	openssl x509 -inform DER -in "$additional_config_cert" -noout >/dev/null
	additional_config_cert_args+=(--config-cert "$additional_config_cert")
fi

target_deb="$(find "$SHIRUDO_PACKAGE_DIR" -type f -name 'shirudo-target_*_amd64.deb' -print -quit)"
operator_deb="$(find "$SHIRUDO_PACKAGE_DIR" -type f -name 'shirudo-operator_*_amd64.deb' -print -quit)"
if [[ -z "$target_deb" || -z "$operator_deb" ]]; then
	echo "shirudo-deb artifact must contain target and operator amd64 packages" >&2
	exit 1
fi

target_root="${work_dir}/target-package"
dpkg-deb -x "$target_deb" "$target_root"
target_binary="${target_root}/usr/bin/shirudo"
builder=/usr/libexec/shirudo/shirudo-build
sudo apt-get install -y --no-install-recommends "$operator_deb"
test -x "$target_binary"
test -x "$builder"
shirudo_binary="$(command -v shirudo)"
sudo setcap cap_ipc_lock+ep "$shirudo_binary"
getcap "$shirudo_binary" | grep -Fq 'cap_ipc_lock=ep'
sudo setcap cap_ipc_lock+ep "$builder"
getcap "$builder" | grep -Fq 'cap_ipc_lock=ep'
# The config signer is temporary and exists only for this image build.
shirudo genkey --keys-dir "$config_keys_dir"

"${SHIRUDO_DIR}/tools/gen-image/shirudo-gen-image" \
	--source "$config_root" \
	--output "$config_prefix" \
	--kind config \
	--keys-dir "$config_keys_dir" \
	--builder "$builder"

"${SHIRUDO_DIR}/tools/gen-image/shirudo-gen-runtime" \
	--binary "$target_binary" \
	--bootstrap-conf "$runtime_conf" \
	--cert "$bpf_cert" \
	--config-cert "${config_keys_dir}/cert.der" \
	"${additional_config_cert_args[@]}" \
	--output "$runtime_prefix" \
	--keys-dir "$config_keys_dir" \
	--builder "$builder" \
	--unit-output "$runtime_service"

for suffix in img verity roothash p7s; do
	test -s "${config_prefix}.${suffix}"
	test -s "${runtime_prefix}.${suffix}"
	install -m 0644 "${config_prefix}.${suffix}" "$asset_dir/initial.${suffix}"
	install -m 0644 "${runtime_prefix}.${suffix}" "$asset_dir/runtime.${suffix}"
done

install -m 0644 "$runtime_service" "$asset_dir/runtime-service.conf"
install -m 0755 "$target_binary" "$asset_dir/shirudo-target"

runtime_root_hash="$(cat "${runtime_prefix}.roothash")"
if [[ ! "$runtime_root_hash" =~ ^[[:xdigit:]]{64}$ ]]; then
	echo "Invalid runtime root hash: ${runtime_root_hash}" >&2
	exit 1
fi
printf 'runtime.image = /var/lib/shirudo/images/runtime\nruntime.root_hash = %s\n' \
	"$runtime_root_hash" > "$asset_dir/initrd-bootstrap.conf"
chmod 0644 "$asset_dir/initrd-bootstrap.conf"

tar -czf "$asset_tarball" -C "$asset_dir" \
	shirudo-target \
	initial.img initial.verity initial.roothash initial.p7s \
	runtime.img runtime.verity runtime.roothash runtime.p7s \
	runtime-service.conf initrd-bootstrap.conf
(cd "$OUTPUT_DIR" && sha256sum "$(basename "$asset_tarball")" \
	> "$(basename "$asset_tarball").sha256")

# Check the published bundle contains the complete signed image asset set.
tar -tzf "$asset_tarball" | LC_ALL=C sort > "${work_dir}/asset-list"
cat > "${work_dir}/expected-asset-list" <<'EOF'
initrd-bootstrap.conf
initial.img
initial.p7s
initial.roothash
initial.verity
runtime-service.conf
runtime.img
runtime.p7s
runtime.roothash
runtime.verity
shirudo-target
EOF
LC_ALL=C sort -o "${work_dir}/expected-asset-list" \
	"${work_dir}/expected-asset-list"
diff -u "${work_dir}/expected-asset-list" "${work_dir}/asset-list"
