#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -euo pipefail
umask 022
source_dir=$(cd "$(dirname "$0")/../.." && pwd)
templates="$source_dir/testing/vm/files"
[ "$#" -eq 4 ] || exit 2
bundle=$1
work=$2
keys=$3
boot_keys=$4
"$source_dir/testing/vm/image-fixtures.sh" --keys-dir "$keys" \
	--boot-keys-dir "$boot_keys" \
	--segments-port "$(cat "$bundle/fixtures/segments-oci/port")" \
	--output "$work/verity"
mkdir "$bundle/verity"
cp -a "$work/verity/public/." "$bundle/verity/"
sed 's/@config_image@/config-boot-keys/g' "$templates/runtime.conf.in" \
	>"$work/runtime.conf"
"$source_dir/tools/gen-image/shirudo-gen-runtime" \
	--binary "$bundle/root/usr/local/libexec/shirudo/shirudo-runtime" \
	--bootstrap-binary "$bundle/root/usr/local/bin/shirudo" \
	--bootstrap-conf "$work/runtime.conf" --cert "$keys/cert.der" \
	--config-cert "$work/verity/public/config-c.der" \
	--config-cert "$work/verity/public/config-d.der" --output "$bundle/verity/runtime" \
	--keys-dir "$keys" --builder "$source_dir/tools/shirudo-build/shirudo-build" \
	--size 64 \
	--extra-binary "$source_dir/build/verity-tests/shirudo-policy-probe" \
	--extra-binary "$source_dir/build/verity-tests/shirudo-image-fault" \
	--unit-output "$bundle/verity/runtime-service.conf" \
	>"$bundle/verity/runtime.root"
sed "s/@root_hash@/$(cat "$bundle/verity/runtime.root")/g" \
	"$templates/bootstrap.conf.in" >"$bundle/verity/bootstrap.conf"
command=$(sed -n 's/^ExecStart=\(.*\) init$/\1/p' \
	"$bundle/verity/runtime-service.conf")
[ -n "$command" ]
command_escaped=$(printf '%s' "$command" | sed 's/[\&|]/\\&/g')
sed "s|@runtime_command@|$command_escaped|g" "$templates/shirudo-runtime.in" \
	>"$bundle/verity/shirudo-runtime"
chmod 0755 "$bundle/verity/shirudo-runtime"
(cd "$bundle/verity" && sha256sum -- *.img *.verity *.roothash *.p7s *.der \
	*.fingerprint *.upatch bootstrap.conf runtime-service.conf shirudo-runtime >manifest)
