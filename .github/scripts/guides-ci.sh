#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Resolve the kernel pin and run the Linux guides on a prepared CI host.
# Validate the Lima template on macOS.

set -eu

cd "$(git rev-parse --show-toplevel)"

case "${1:-}" in
kernel-run)
	run_id=$(testing/vm/kernel-artifact.sh run-id)
	printf 'Using kernel package run %s\n' "$run_id"
	printf 'run_id=%s\n' "$run_id" >>"$GITHUB_OUTPUT"
	;;
run)
	# shellcheck source=/dev/null
	. build/vm-toolchain.env
	export BPF_VMLINUX_BTF="$PWD/artifacts/bpf-next-kernel-debs/vmlinux.btf"
	export TEST_VM_TIMEOUT=900
	sudo prlimit --pid "$$" --memlock=unlimited:unlimited
	exec python3 .github/scripts/check-guides.py
	;;
validate-lima)
	command -v limactl >/dev/null || brew install lima
	exec limactl validate --param "checkout=$PWD" infra/lima/shirudo.yaml
	;;
*)
	printf 'usage: %s kernel-run|run|validate-lima\n' "$0" >&2
	exit 2
	;;
esac
