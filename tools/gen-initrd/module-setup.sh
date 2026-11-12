#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# dracut module "shirudo": put shirudo into the initrd so that
# shirudo-initrd.service brings enforcement up before the switch to the
# root file system (Documentation/internals/boot-flow.rst).
#
# Everything is taken from the installed system; a dracut.conf(5) file
# can point elsewhere, which is how the test VM builds an initrd from a
# bundle:
#   shirudo_binary=<file>       the binary to copy
#   shirudo_binary_path=<path>  where it lives on the root file system,
#                               which is where the initrd runs it from
#   shirudo_cert=<file>         the primary certificate (default:
#                               /var/lib/shirudo/keys/cert.der)
#   shirudo_trusted_dir=<dir>   the further trusted certificates
#                               (default: trusted/ beside the primary)
#   shirudo_conf=<file>         shirudo.conf, when the TPM has an owner
#                               password (default: /etc/shirudo/shirudo.conf)
#   shirudo_unit=<file>         shirudo-initrd.service (default: the
#                               installed unit)
#
# initdir, moddir, dracutsysrootdir, systemdsystemunitdir and SYSTEMCTL
# are dracut's.
# shellcheck disable=SC2154

shirudo_binary_default() {
	local b

	b=$(find_binary shirudo) && [[ -n $b ]] && printf '%s\n' "$b"
}

check() {
	local bin cert

	bin=${shirudo_binary:-$(shirudo_binary_default)}
	if [[ -z $bin || ! -x $bin ]]; then
		dinfo "shirudo: no shirudo binary installed"
		return 1
	fi
	cert=${shirudo_cert:-$dracutsysrootdir/var/lib/shirudo/keys/cert.der}
	if [[ ! -s $cert ]]; then
		dinfo "shirudo: no certificate at $cert; not included"
		return 255
	fi
	return 0
}

# The phase measurements come from dracut's systemd-pcrextend module,
# called systemd-pcrphase before dracut 103; tpm2-tss rides along when
# its own check lets it, otherwise the drivers below are what the TPM
# needs. A module whose check fails outright is left out, and the
# generator's check of the result says what is missing.
depends() {
	local deps="systemd systemd-initrd" m rc

	for m in systemd-pcrextend systemd-pcrphase tpm2-tss; do
		module_check "$m" >/dev/null 2>&1
		rc=$?
		[[ $rc == 0 || $rc == 255 ]] && deps+=" $m"
	done
	echo "$deps"
}

installkernel() {
	hostonly='' instmods tpm tpm_tis_core tpm_tis tpm_crb
	hostonly='' instmods dm_mod dm_verity loop ext4
}

install() {
	local bin path cert conf unit trusted f

	bin=${shirudo_binary:-$(shirudo_binary_default)}
	path=${shirudo_binary_path:-${bin#"$dracutsysrootdir"}}
	cert=${shirudo_cert:-$dracutsysrootdir/var/lib/shirudo/keys/cert.der}
	conf=${shirudo_conf:-$dracutsysrootdir/etc/shirudo/shirudo.conf}
	unit=${shirudo_unit:-$dracutsysrootdir$systemdsystemunitdir/shirudo-initrd.service}

	# This authenticated initrd binary bootstraps the runtime image. Later
	# invocations use only executables and libraries from that image.
	inst_binary "$bin" "$path" || return 1
	# bpm key keeps cert.der as a symlink into keys/; the initrd gets
	# the file, not a link into a tree it does not have.
	trusted=${shirudo_trusted_dir:-$(dirname "$cert")/trusted}
	cert=$(readlink -f "$cert") || return 1
	inst_simple "$cert" /etc/shirudo/keys/cert.der || return 1
	# The trusted set is enrolled with the primary, each certificate
	# with the vouch that admits it; the revoked ones stay on the root,
	# where init reads them through its bind.
	if [[ -d $trusted ]]; then
		for f in "$trusted"/*.der "$trusted"/*.vouch; do
			[[ -f $f ]] || continue
			inst_simple "$(readlink -f "$f")" \
				"/etc/shirudo/keys/trusted/${f##*/}" || return 1
		done
	fi
	[[ -r $conf ]] || return 1
	inst_simple "$conf" /etc/shirudo/shirudo.conf || return 1
	inst_multiple mount || return 1
	# dracut run as root keeps the owner of what it copies, and init
	# refuses keys and configuration another user could change. Run as
	# anyone else, it writes every member of the archive as 0:0.
	if [[ $EUID == 0 ]]; then
		chown -R 0:0 "$initdir/etc/shirudo" || return 1
	fi
	inst_simple "$unit" "$systemdsystemunitdir/shirudo-initrd.service" ||
		return 1
	$SYSTEMCTL -q --root "$initdir" enable shirudo-initrd.service ||
		return 1
	return 0
}
