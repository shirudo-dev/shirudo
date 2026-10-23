# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# bash completion for shirudo
#
# Command and subcommand name lists are pulled live from the binary via
# `shirudo <command> --list-cmds`, so adding a (sub)command in the
# C dispatch table makes it appear here automatically -- this file does
# NOT need editing for new names. Per-command FLAG lists are still
# hand-maintained below; update them when a flag is added or removed.
#
# Install: copied to $(sharedir)/bash-completion/completions/shirudo by
# `make install`. To try it in place: `source completion/shirudo.bash`.

_shirudo()
{
	local cur cword cmd sub bin
	cur="${COMP_WORDS[COMP_CWORD]}"
	cword=$COMP_CWORD
	bin="${COMP_WORDS[0]}"

	# First word: the top-level command, pulled live from the binary
	# the user is completing -- always matches that build.
	if (( cword == 1 )); then
		local cmds
		cmds=$("$bin" --list-cmds 2>/dev/null)
		COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
		return
	fi

	cmd="${COMP_WORDS[1]}"
	sub="${COMP_WORDS[2]}"
	case "$cmd" in
	image)
		if (( cword == 2 )); then
			local subs
			subs=$("$bin" image --list-cmds 2>/dev/null)
			COMPREPLY=( $(compgen -W "$subs" -- "$cur") )
		elif [[ $cur == -* && $sub == build ]]; then
			COMPREPLY=( $(compgen -W "-o --kind --keys-dir --key \
				--cert --salt" -- "$cur") )
		elif [[ $cur == -* && $sub == verify ]]; then
			COMPREPLY=( $(compgen -W "--cert" -- "$cur") )
		else
			COMPREPLY=( $(compgen -f -- "$cur") )
		fi
		;;
	upatch)
		if (( cword == 2 )); then
			local subs
			subs=$("$bin" upatch --list-cmds 2>/dev/null)
			COMPREPLY=( $(compgen -W "$subs" -- "$cur") )
		elif [[ $cur == -* ]]; then
			case "$sub" in
			load|unload)
				COMPREPLY=( $(compgen -W "--expect-chain= \
					--expect-version-id= --no-precheck \
					--no-version-check --report=" \
					-- "$cur") )
				;;
			info|list)
				COMPREPLY=( $(compgen -W "--json" -- "$cur") )
				;;
			map)
				COMPREPLY=( $(compgen -W "--json= --show-full \
					--otel \
					--otel-endpoint= --otel-insecure \
					--otel-retries= --s3-uri=s3://" -- "$cur") )
				;;
			get)
				# no flags beyond --help
				COMPREPLY=()
			;;
			esac
		else
			COMPREPLY=( $(compgen -f -X '!*.upatch' -- "$cur") \
				    $(compgen -d -- "$cur") )
		fi
		;;
	bpm)
		if (( cword == 2 )); then
			local subs
			subs=$("$bin" bpm --list-cmds 2>/dev/null)
			COMPREPLY=( $(compgen -W "$subs" -- "$cur") )
		elif [[ $sub == config && cword -eq 3 ]]; then
			COMPREPLY=( $(compgen -W "register" -- "$cur") )
		elif [[ $sub == config && ${COMP_WORDS[3]} == register && cword -eq 4 ]]; then
			COMPREPLY=( $(compgen -W "add list remove" -- "$cur") )
		elif [[ $sub == config && ${COMP_WORDS[3]} == register && ${COMP_WORDS[4]} == add && $cur == -* ]]; then
			COMPREPLY=( $(compgen -W "--key-file=" -- "$cur") )
		elif [[ $sub == repo && cword -eq 3 ]]; then
			COMPREPLY=( $(compgen -W "update" -- "$cur") )
		elif [[ $sub == build && ${COMP_WORDS[COMP_CWORD-1]} == -f ]]; then
			COMPREPLY=( $(compgen -f -X '!*.bee' -- "$cur") \
				    $(compgen -d -- "$cur") )
		elif [[ $sub == build && ${COMP_WORDS[COMP_CWORD-1]} == --keys-dir ]]; then
			COMPREPLY=( $(compgen -d -- "$cur") )
		elif [[ $sub == build && $cur == -* ]]; then
			COMPREPLY=( $(compgen -W "-f --version --keys-dir" -- "$cur") )
		elif [[ $sub == build ]]; then
			COMPREPLY=( $(compgen -d -- "$cur") )
		elif [[ $sub == tree && cword -eq 3 ]]; then
			COMPREPLY=( $(compgen -W "sync append" -- "$cur") )
		elif [[ $sub == tree && ${COMP_WORDS[3]} == sync && $cur == -* ]]; then
			COMPREPLY=( $(compgen -W "--dry-run --report=" -- "$cur") )
		elif [[ $sub == tree && ${COMP_WORDS[3]} == append && $cur == -* ]]; then
			COMPREPLY=( $(compgen -W "--keys-dir --key --cert --tree-id \
				--reference --op" -- "$cur") )
		elif [[ $sub == tree && ${COMP_WORDS[3]} == append ]]; then
			COMPREPLY=( $(compgen -f -X '!*.bee' -- "$cur") $(compgen -d -- "$cur") )
		elif [[ $sub == push && $cur == -* ]]; then
			COMPREPLY=( $(compgen -W "--keys-dir --index-cert --index-key" -- "$cur") )
		elif [[ $sub == push ]]; then
			COMPREPLY=( $(compgen -f -X '!*.bee' -- "$cur") $(compgen -d -- "$cur") )
		elif [[ $sub == key && cword -eq 3 ]]; then
			local subs
			subs=$("$bin" bpm key --list-cmds 2>/dev/null)
			COMPREPLY=( $(compgen -W "$subs" -- "$cur") )
		elif [[ $sub == key && (${COMP_WORDS[3]} == add ||
			${COMP_WORDS[3]} == fingerprint) ]]; then
			COMPREPLY=( $(compgen -f -X '!*.bee' -- "$cur") $(compgen -f -- "$cur") )
		elif [[ $sub == install && $cword -eq 3 ]]; then
			COMPREPLY=( $(compgen -W "example/package" -- "$cur") )
		fi
		;;
	build)
		if [[ $cur == -* ]]; then
			COMPREPLY=( $(compgen -W "-o --name --key --cert \
				--vmlinux --extra-cflags --unload \
				--payload-sha256 --emit-artifacts" -- "$cur") )
		else
			COMPREPLY=( $(compgen -f -X '!*.bpf.c' -- "$cur") \
				    $(compgen -f -X '!*.bpf.o' -- "$cur") \
				    $(compgen -d -- "$cur") )
		fi
		;;
	init)
		COMPREPLY=( $(compgen -W "--check-only" -- "$cur") )
		;;
	status)
		COMPREPLY=( $(compgen -W "--json \
			--include-system --include-eventlog \
			--include-kernellog --include-modules \
			--include-maps --show-full" -- "$cur") )
		;;
	attest)
		if [[ $cword -eq 2 && $cur != -* ]]; then
			COMPREPLY=( $(compgen -W "verify predict challenge" -- "$cur") )
		elif [[ $sub == verify ]]; then
			COMPREPLY=( $(compgen -W "--evidence= --nonce= --ak-name= \
				--cert= --upatch= --expect= --tree-root= \
				--expect-chain= --expect-pcr= --expect-credential= \
				--allow-runtime-events --strict-anchor \
				--expect-config-root= --expect-config-pcr=" -- "$cur") )
		elif [[ $sub == predict ]]; then
			COMPREPLY=( $(compgen -W "--cert= --upatch= --expect= \
				--tree-root= --event=" -- "$cur") )
		elif [[ $sub == challenge ]]; then
			COMPREPLY=( $(compgen -W "--evidence= --ek-ca= --out=" \
				-- "$cur") )
		else
			COMPREPLY=( $(compgen -W "--nonce= --pcrs= --challenge= \
				--out=" -- "$cur") )
		fi
		;;
	keys)
		if (( cword == 2 )); then
			local subs
			subs=$("$bin" keys --list-cmds 2>/dev/null)
			COMPREPLY=( $(compgen -W "$subs --keys-dir=" -- "$cur") )
		elif [[ $cur == -* ]]; then
			case "$sub" in
			add)
				COMPREPLY=( $(compgen -W "--vouch= --keys-dir=" \
					-- "$cur") )
				;;
			vouch)
				COMPREPLY=( $(compgen -W "-o --keys-dir= --key \
					--cert" -- "$cur") )
				;;
			revoke)
				COMPREPLY=( $(compgen -W "--promote= --force" \
					-- "$cur") )
				;;
			esac
		else
			COMPREPLY=( $(compgen -f -- "$cur") )
		fi
		;;
	genkey)
		COMPREPLY=( $(compgen -W "--keys-dir= --force -f" -- "$cur") )
		;;
	config|version|help)
		# nothing to complete beyond --help / --list-cmds
		;;
	esac

	# A "--flag=" completion takes a value -- don't append a space.
	if (( ${#COMPREPLY[@]} == 1 )) && [[ ${COMPREPLY[0]} == *= ]]; then
		compopt -o nospace 2>/dev/null
	fi
}
complete -F _shirudo shirudo
