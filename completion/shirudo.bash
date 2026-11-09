# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# bash completion for shirudo
#
# Command and subcommand names come from the binary through
# `shirudo <command> --list-cmds`, so a new (sub)command in the C dispatch
# table appears here by itself. The option lists are kept by hand: update
# them when an option is added or removed. A valued option takes its
# value after a space or after `=`, so the lists offer the bare name,
# except where the parser takes `=` only.
#
# Install: copied to $(sharedir)/bash-completion/completions/shirudo by
# `make install`. To try it in place: `source completion/shirudo.bash`.

_shirudo()
{
	local cur prev cword cmd sub bin
	cur="${COMP_WORDS[COMP_CWORD]}"
	prev="${COMP_WORDS[COMP_CWORD-1]}"
	cword=$COMP_CWORD
	bin="${COMP_WORDS[0]}"

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
			COMPREPLY=( $(compgen -W "-o --output --kind --keys-dir \
				--key --cert --salt --builder" -- "$cur") )
		elif [[ $cur == -* && $sub == verify ]]; then
			COMPREPLY=( $(compgen -W "--cert" -- "$cur") )
		elif [[ $cur == -* && $sub == stage ]]; then
			COMPREPLY=( $(compgen -W "--cancel" -- "$cur") )
		elif [[ $cur == -* && $sub == status ]]; then
			COMPREPLY=( $(compgen -W "--json" -- "$cur") )
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
				COMPREPLY=( $(compgen -W "--expect-chain \
					--expect-version-id --no-precheck \
					--no-version-check --report" -- "$cur") )
				;;
			info|list)
				COMPREPLY=( $(compgen -W "--json" -- "$cur") )
				;;
			map)
				COMPREPLY=( $(compgen -W "--json= --show-full \
					--all --peek --otel --otel-endpoint \
					--otel-insecure --otel-retries \
					--tenant-id --s3-uri" -- "$cur") )
				;;
			get)
				COMPREPLY=( $(compgen -W "--json --show-full" \
					-- "$cur") )
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
			COMPREPLY=( $(compgen -W "register update" -- "$cur") )
		elif [[ $sub == config && ${COMP_WORDS[3]} == update &&
			($prev == --base-package || $prev == --file) ]]; then
			COMPREPLY=( $(compgen -f -X '!*.bee' -- "$cur") )
		elif [[ $sub == config && ${COMP_WORDS[3]} == update &&
			$prev == --keys-dir ]]; then
			COMPREPLY=( $(compgen -d -- "$cur") )
		elif [[ $sub == config && ${COMP_WORDS[3]} == update &&
			$prev == --rodata-input ]]; then
			COMPREPLY=( $(compgen -f -- "$cur") $(compgen -d -- "$cur") )
		elif [[ $sub == config && ${COMP_WORDS[3]} == update &&
			$cur == -* ]]; then
			COMPREPLY=( $(compgen -W "--base-package --version --file \
				--keys-dir --rodata-input" -- "$cur") )
		elif [[ $sub == config && ${COMP_WORDS[3]} == update ]]; then
			COMPREPLY=( $(compgen -f -X '!*.bee' -- "$cur") \
				    $(compgen -d -- "$cur") )
		elif [[ $sub == config && ${COMP_WORDS[3]} == register &&
			cword -eq 4 ]]; then
			COMPREPLY=( $(compgen -W "add list remove" -- "$cur") )
		elif [[ $sub == config && ${COMP_WORDS[3]} == register &&
			${COMP_WORDS[4]} == list ]]; then
			COMPREPLY=( $(compgen -W "--json" -- "$cur") )
		elif [[ $sub == config && ${COMP_WORDS[3]} == register &&
			${COMP_WORDS[4]} == add && $cur == -* ]]; then
			COMPREPLY=( $(compgen -W "--cert" -- "$cur") )
		elif [[ ($sub == list || ($sub == key && ${COMP_WORDS[3]} == list)) &&
			$cur == -* ]]; then
			COMPREPLY=( $(compgen -W "--json" -- "$cur") )
		elif [[ $sub == repo && cword -eq 3 ]]; then
			COMPREPLY=( $(compgen -W "update" -- "$cur") )
		elif [[ $sub == info && cword -eq 3 ]]; then
			COMPREPLY=( $(compgen -W "upatches data" -- "$cur") \
				    $(compgen -f -X '!*.bee' -- "$cur") \
				    $(compgen -d -- "$cur") )
		elif [[ $sub == info && ${COMP_WORDS[3]} == upatches &&
			cword -eq 4 ]]; then
			COMPREPLY=( $(compgen -f -X '!*.bee' -- "$cur") \
				    $(compgen -d -- "$cur") )
		elif [[ $sub == info && ${COMP_WORDS[3]} == upatches &&
			cword -eq 5 ]]; then
			COMPREPLY=( $(compgen -W "--all" -- "$cur") )
		elif [[ $sub == info && ${COMP_WORDS[3]} == data && cword -eq 4 ]]; then
			COMPREPLY=( $(compgen -f -X '!*.bee' -- "$cur") \
				    $(compgen -d -- "$cur") )
		elif [[ $sub == info && ${COMP_WORDS[3]} == data && cword -eq 5 ]]; then
			COMPREPLY=( $(compgen -f -X '!*.upatch' -- "$cur") \
				    $(compgen -d -- "$cur") )
		elif [[ $sub == info && ${COMP_WORDS[3]} == data && cword -eq 6 ]]; then
			COMPREPLY=( $(compgen -W "--json" -- "$cur") )
		elif [[ $sub == info ]]; then
			COMPREPLY=( $(compgen -f -X '!*.bee' -- "$cur") \
				    $(compgen -d -- "$cur") )
		elif [[ $sub == build && $prev == --file ]]; then
			COMPREPLY=( $(compgen -f -X '!*.bee' -- "$cur") \
				    $(compgen -d -- "$cur") )
		elif [[ $sub == build && $prev == --keys-dir ]]; then
			COMPREPLY=( $(compgen -d -- "$cur") )
		elif [[ $sub == build && $prev == --vmlinux ]]; then
			COMPREPLY=( $(compgen -f -- "$cur") )
		elif [[ $sub == build && $prev == --rodata-input ]]; then
			COMPREPLY=( $(compgen -f -- "$cur") $(compgen -d -- "$cur") )
		elif [[ $sub == build && $cur == -* ]]; then
			COMPREPLY=( $(compgen -W "--file --version --keys-dir \
				--vmlinux --rodata-input" -- "$cur") )
		elif [[ $sub == build ]]; then
			COMPREPLY=( $(compgen -d -- "$cur") )
		elif [[ $sub == tree && cword -eq 3 ]]; then
			COMPREPLY=( $(compgen -W "sync append" -- "$cur") )
		elif [[ $sub == tree && ${COMP_WORDS[3]} == sync && $cur == -* ]]; then
			COMPREPLY=( $(compgen -W "--dry-run --report" -- "$cur") )
		elif [[ $sub == tree && ${COMP_WORDS[3]} == append && $prev == --previous-cert ]]; then
			COMPREPLY=( $(compgen -f -- "$cur") )
		elif [[ $sub == tree && ${COMP_WORDS[3]} == append && $cur == -* ]]; then
			COMPREPLY=( $(compgen -W "--keys-dir --key --cert --previous-cert --tree-id \
				--reference --op" -- "$cur") )
		elif [[ $sub == tree && ${COMP_WORDS[3]} == append ]]; then
			COMPREPLY=( $(compgen -f -X '!*.bee' -- "$cur") \
				    $(compgen -d -- "$cur") )
		elif [[ $sub == push && $cur == -* ]]; then
			COMPREPLY=( $(compgen -W "--keys-dir --index-cert \
				--index-key --new-index" -- "$cur") )
		elif [[ $sub == push ]]; then
			COMPREPLY=( $(compgen -f -X '!*.bee' -- "$cur") \
				    $(compgen -d -- "$cur") )
		elif [[ $sub == key && cword -eq 3 ]]; then
			local subs
			subs=$("$bin" bpm key --list-cmds 2>/dev/null)
			COMPREPLY=( $(compgen -W "$subs" -- "$cur") )
		elif [[ $sub == key && (${COMP_WORDS[3]} == add ||
			${COMP_WORDS[3]} == fingerprint) ]]; then
			COMPREPLY=( $(compgen -f -- "$cur") )
		fi
		;;
	build)
		if [[ $cur == -* ]]; then
			COMPREPLY=( $(compgen -W "-o --output --name --keys-dir \
				--key --cert --vmlinux --extra-cflags --unload \
				--payload-sha256 --emit-artifacts" -- "$cur") )
		else
			COMPREPLY=( $(compgen -f -X '!*.bpf.c' -- "$cur") \
				    $(compgen -f -X '!*.bpf.o' -- "$cur") \
				    $(compgen -d -- "$cur") )
		fi
		;;
	init)
		COMPREPLY=( $(compgen -W "--check-only --json" -- "$cur") )
		;;
	status)
		COMPREPLY=( $(compgen -W "--json --otel --check --show-full \
			--include-system --include-eventlog" -- "$cur") )
		;;
	attest)
		if [[ $cword -eq 2 && $cur != -* ]]; then
			COMPREPLY=( $(compgen -W "verify predict challenge" -- "$cur") )
		elif [[ $sub == verify ]]; then
			COMPREPLY=( $(compgen -W "--evidence --nonce --ak-name \
				--ek-name --cert --upatch --expect --tree-root \
				--expect-chain --expect-pcr --expect-bind-pcr \
				--expect-credential --expect-config-root \
				--expect-config-pcr --allow-runtime-events \
				--strict-anchor --require-initrd --json" -- "$cur") )
		elif [[ $sub == predict ]]; then
			COMPREPLY=( $(compgen -W "--cert --upatch --expect \
				--tree-root --event --writer-public --bind-pcr \
				--json" -- "$cur") )
		elif [[ $sub == challenge ]]; then
			COMPREPLY=( $(compgen -W "--evidence --ek-ca --ak-name \
				--ek-name --trust-presented-ek -o --output" \
				-- "$cur") )
		else
			COMPREPLY=( $(compgen -W "--nonce --pcrs --challenge \
				-o --output" -- "$cur") )
		fi
		;;
	keys)
		if (( cword == 2 )); then
			local subs
			subs=$("$bin" keys --list-cmds 2>/dev/null)
			COMPREPLY=( $(compgen -W "$subs --keys-dir --json" -- "$cur") )
		elif [[ $cur == -* ]]; then
			case "$sub" in
			add)
				COMPREPLY=( $(compgen -W "--vouch --keys-dir" \
					-- "$cur") )
				;;
			vouch)
				COMPREPLY=( $(compgen -W "-o --output --keys-dir \
					--key --cert" -- "$cur") )
				;;
			esac
		else
			COMPREPLY=( $(compgen -f -- "$cur") )
		fi
		;;
	genkey)
		COMPREPLY=( $(compgen -W "--keys-dir --force -f" -- "$cur") )
		;;
	config|version|help)
		;;
	esac

	# A completion that ends in `=` takes its value right after it.
	if (( ${#COMPREPLY[@]} == 1 )) && [[ ${COMPREPLY[0]} == *= ]]; then
		compopt -o nospace 2>/dev/null
	fi
}
complete -F _shirudo shirudo
