# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# bash completion for shirudo
#
# The binary names what there is to complete. `--list-cmds` at each level
# of the command line lists its subcommands, none for a command without,
# and `--list-opts` a command's options, one a line, a value's
# placeholder after a tab. What stays here is what the binary cannot
# say: what a placeholder asks for, which files a command's arguments
# are, and the options of `image build`, which shirudo-gen-verity parses.
#
# Install: copied to $(sharedir)/bash-completion/completions/shirudo by
# `make install`. To try it in place: `source completion/shirudo.bash`.

# Whether the word $2 is one of the lines of $1.
_shirudo_listed()
{
	local line

	while IFS= read -r line; do
		[[ $line == "$2" ]] && return 0
	done <<<"$1"
	return 1
}

# What to offer for the value of an option whose placeholder is $1.
_shirudo_value()
{
	local cur=$2

	case $1 in
	*'<'*)	;;
	*'|'*)
		COMPREPLY=( $(compgen -W "${1//|/ }" -- "$cur") )
		return ;;
	esac
	case $1 in
	*dir*)
		COMPREPLY=( $(compgen -d -- "$cur") ) ;;
	'<hex>'|'<64-hex>'|'<n>'|'<0-10>'|'<id>'|'<url>'|'<uri>'|'<version>'|\
	'<ref>'|'<list>'|'<upatch-name>'|*'=<hex>'|*':'*|sha256:*|"'<flags>'")
		;;
	*)
		COMPREPLY=( $(compgen -f -- "$cur") ) ;;
	esac
}

# Files of the type the arguments of the command $1 are.
_shirudo_args()
{
	local cur=$2 first=$3

	case $1 in
	'upatch load'|'upatch unload'|'upatch info')
		COMPREPLY=( $(compgen -f -X '!*.upatch' -- "$cur")
			    $(compgen -d -- "$cur") ) ;;
	build)
		COMPREPLY=( $(compgen -f -X '!*.bpf.c' -- "$cur")
			    $(compgen -f -X '!*.o' -- "$cur")
			    $(compgen -f -X '!*.jar' -- "$cur")
			    $(compgen -d -- "$cur") ) ;;
	'bpm info')
		[[ -n $first ]] || COMPREPLY=( $(compgen -W "upatches data" -- "$cur") )
		COMPREPLY+=( $(compgen -f -X '!*.bee' -- "$cur")
			     $(compgen -f -X '!*.upatch' -- "$cur")
			     $(compgen -d -- "$cur") ) ;;
	'bpm install'|'bpm push'|'bpm tree append'|'bpm config update')
		COMPREPLY=( $(compgen -f -X '!*.bee' -- "$cur")
			    $(compgen -d -- "$cur") ) ;;
	'bpm build')
		COMPREPLY=( $(compgen -d -- "$cur") ) ;;
	'upatch get'|'upatch map'|'bpm uninstall'|'bpm pull'|'bpm repo update'|\
	'bpm config register'*|'bpm tree show')
		;;
	*)
		COMPREPLY=( $(compgen -f -- "$cur") ) ;;
	esac
}

_shirudo()
{
	local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
	local bin=${COMP_WORDS[0]} cmd=() subs opts line name meta first i

	for (( i = 1; i < COMP_CWORD; i++ )); do
		subs=$("$bin" "${cmd[@]}" --list-cmds 2>/dev/null)
		_shirudo_listed "$subs" "${COMP_WORDS[i]}" || break
		cmd+=( "${COMP_WORDS[i]}" )
	done
	subs=$("$bin" "${cmd[@]}" --list-cmds 2>/dev/null)
	if (( i == COMP_CWORD )) && [[ -n $subs && $cur != -* ]]; then
		COMPREPLY=( $(compgen -W "$subs" -- "$cur") )
		return
	fi
	(( ${#cmd[@]} )) || return

	if [[ ${cmd[*]} == 'image build' ]]; then
		opts=$'-o\t<prefix>\n--output\t<prefix>\n--kind\tconfig|runtime\n--keys-dir\t<dir>\n--key\t<private.pem>\n--cert\t<cert.der>\n--salt\t<64-hex>'
	else
		opts=$("$bin" "${cmd[@]}" --list-opts 2>/dev/null)
	fi
	if [[ $cur == -* ]]; then
		local names=()

		while IFS=$'\t' read -r name meta; do
			[[ -n $name ]] && names+=( "$name" )
		done <<<"$opts"
		COMPREPLY=( $(compgen -W "${names[*]}" -- "$cur") )
		# An option that ends in = takes its value right after it.
		if (( ${#COMPREPLY[@]} == 1 )) && [[ ${COMPREPLY[0]} == *= ]]; then
			compopt -o nospace 2>/dev/null
		fi
		return
	fi
	while IFS=$'\t' read -r name meta; do
		if [[ $name == "$prev" && -n $meta ]]; then
			_shirudo_value "$meta" "$cur"
			return
		fi
	done <<<"$opts"
	first=
	for (( i = ${#cmd[@]} + 1; i < COMP_CWORD; i++ )); do
		[[ ${COMP_WORDS[i]} == -* ]] || { first=${COMP_WORDS[i]}; break; }
	done
	_shirudo_args "${cmd[*]}" "$cur" "$first"
}
complete -F _shirudo shirudo
