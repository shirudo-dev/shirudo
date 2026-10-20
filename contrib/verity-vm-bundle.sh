#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -euo pipefail
source_dir=$(cd "$(dirname "$0")/.." && pwd)
[ "$#" -eq 4 ] || exit 2
bundle=$1
work=$2
keys=$3
boot_keys=$4
"$source_dir/contrib/verity-vm-config-fixtures.sh" --keys-dir "$keys" \
	--boot-keys-dir "$boot_keys" --output "$work/verity"
mkdir "$bundle/verity"
cp -a "$work/verity/public/." "$bundle/verity/"
cat >"$work/runtime.conf" <<'EOF'
config.image = /var/lib/shirudo/images/config-boot-keys
config.verification_key = /run/shirudo/runtime/etc/shirudo/config-cert.der
config.pcr = 14
tpm.tcti = device:/dev/tpmrm0
EOF
"$source_dir/tools/gen-image/shirudo-gen-runtime" \
	--binary "$bundle/root/usr/local/bin/shirudo" \
	--bootstrap-conf "$work/runtime.conf" --cert "$keys/cert.der" \
	--config-cert "$keys/cert.der" --output "$bundle/verity/runtime" \
	--keys-dir "$keys" --builder "$source_dir/tools/shirudo-build/shirudo-build" \
	--extra-binary "$source_dir/build/verity-tests/shirudo-policy-probe" \
	--extra-binary "$source_dir/build/verity-tests/shirudo-image-fault" \
	--unit-output "$bundle/verity/runtime-service.conf" \
	>"$bundle/verity/runtime.root"
printf 'runtime.image = /var/lib/shirudo/images/runtime\nruntime.root_hash = %s\n' \
	"$(cat "$bundle/verity/runtime.root")" >"$bundle/verity/bootstrap.conf"
command=$(sed -n 's/^ExecStart=\(.*\) init$/\1/p' \
	"$bundle/verity/runtime-service.conf")
[ -n "$command" ]
printf '#!/bin/sh\nexec %s "$@"\n' "$command" >"$bundle/verity/shirudo-runtime"
chmod 0755 "$bundle/verity/shirudo-runtime"
(cd "$bundle/verity" && sha256sum -- *.img *.verity *.roothash *.p7s *.der \
	*.fingerprint *.upatch bootstrap.conf runtime-service.conf shirudo-runtime >manifest)
