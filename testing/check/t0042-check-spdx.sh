#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0042 -- .github/scripts/check-spdx.sh: the tag every source needs, its form
# by file type, the two expressions, the dual licence of everything a
# BPF object compiles and a Beefile ships, the licences vendored C may
# carry, on a throwaway repository, and the tree itself.

cd "$(dirname "$0")/.."
. ./test-lib.sh
command -v git >/dev/null 2>&1 || test_skip_all "git not installed"
ROOT=$(cd .. && pwd)
S=$ROOT/.github/scripts/check-spdx.sh
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# A file with the given first lines, each argument one line.
put() {
	f=$1
	shift
	mkdir -p "$(dirname "$f")"
	printf '%s\n' "$@" >"$f"
}

repo() {
	rm -rf "$1" && mkdir -p "$1" && git init -q "$1"
}

check() {
	(cd "$1" && git add -A && sh "$S") >"$W/out" 2>"$W/err"
}

R=$W/good
repo "$R"
put "$R/good.c" '// SPDX-License-Identifier: BSD-2-Clause' 'int x;'
put "$R/good.h" '/* SPDX-License-Identifier: BSD-2-Clause */' 'int x;'
put "$R/good.sh" '#!/bin/sh' '# SPDX-License-Identifier: BSD-2-Clause'
put "$R/lib.sh" '# SPDX-License-Identifier: BSD-2-Clause'
put "$R/tool" '#!/bin/bash' '# SPDX-License-Identifier: BSD-2-Clause'
put "$R/Makefile" '# SPDX-License-Identifier: BSD-2-Clause'
put "$R/Makefile.config" '# SPDX-License-Identifier: BSD-2-Clause'
put "$R/unit.service.in" '# SPDX-License-Identifier: BSD-2-Clause'
put "$R/d.lua" '-- SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause'
put "$R/block.rst" '..' '   SPDX-License-Identifier: BSD-2-Clause' '   Copyright (c) 2026'
put "$R/line.rst" '.. SPDX-License-Identifier: BSD-2-Clause'
put "$R/notes.md" 'no tag here'
put "$R/data.json" '{}'
put "$R/vendor/x.c" '// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)' 'int x;'
put "$R/vendor/uapi.h" '/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */'
put "$R/vendor/libbpf/bpf/bpf_helper_defs.h" '/* This is auto-generated file. */'
put "$R/vendor/README.md" 'no tag here'
put "$R/vendor/linux/vmlinux.h" 'struct task_struct;'
put "$R/pkg/vmlinux.h" 'struct task_struct;'
put "$R/Documentation/coding-style.rst" 'Linux kernel coding style'
put "$R/bpf/lsm.c" '// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause' \
	'#include "vmlinux.h"' '#include <bpf/bpf_helpers.h>' '#include "common.h"'
put "$R/bpf/lib/common.h" '/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */'
put "$R/pkg/Beefile" '[package]' 'license = "GPL-2.0 OR BSD-2-Clause"' \
	'[[files]]' 'source = "p.bpf.c"' '[[files]]' 'source = "decoders/x.lua"' \
	'[[files]]' 'source = "gen.py"'
put "$R/pkg/p.bpf.c" '// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause' \
	'#include "vmlinux.h"' '#include "common.h"'
put "$R/pkg/decoders/x.lua" '-- SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause'
put "$R/pkg/gen.py" '#!/usr/bin/env python3' '# SPDX-License-Identifier: BSD-2-Clause'

test_expect_success 'a tree of well-tagged files passes' '
	check "$R" &&
	grep -q "SPDX: 18 files checked" "$W/out"
'

B=$W/bad
repo "$B"
put "$B/style.c" '/* SPDX-License-Identifier: BSD-2-Clause */'
put "$B/style.h" '// SPDX-License-Identifier: BSD-2-Clause'
put "$B/late.sh" '#!/bin/sh' '#' '# SPDX-License-Identifier: BSD-2-Clause'
put "$B/none.py" 'import os'
put "$B/tool" '#!/bin/bash' 'echo'
put "$B/other.c" '// SPDX-License-Identifier: MIT'
put "$B/dual.c" '// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0'
put "$B/indent.rst" '..' 'SPDX-License-Identifier: BSD-2-Clause'
put "$B/prog.bpf.c" '// SPDX-License-Identifier: BSD-2-Clause'
put "$B/bpf/lsm.c" '// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause' \
	'#include "lib.h"' '  #  include "sub/inner.h"'
put "$B/bpf/lib.h" '/* SPDX-License-Identifier: BSD-2-Clause */'
put "$B/bpf/sub/inner.h" '/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */' \
	'#include "../deep.h"'
put "$B/bpf/deep.h" '/* SPDX-License-Identifier: BSD-2-Clause */'
put "$B/fx/a.bpf.c" '// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause' \
	'#include "common.h"'
put "$B/bpf/lib/common.h" '/* SPDX-License-Identifier: BSD-2-Clause */'
put "$B/pkg/Beefile" '[package]' 'license = "GPL-2.0 OR BSD-2-Clause"' \
	'[[files]]' 'source = "decoders/x.lua"' '[[files]]' 'source = "gen.py"'
put "$B/pkg/decoders/x.lua" '-- SPDX-License-Identifier: BSD-2-Clause'
put "$B/pkg/gen.py" '# SPDX-License-Identifier: BSD-2-Clause'
put "$B/nolic/Beefile" '[package]' 'name = "x"'
put "$B/vendor/types.h" '/* SPDX-License-Identifier: GPL-2.0 */'
put "$B/vendor/bare.c" 'int x;'

test_expect_success 'a tree of badly tagged files fails' '
	! check "$B" &&
	grep -q "^16 SPDX problems" "$W/err"
'

test_expect_success 'the form of the tag follows the file type' '
	grep -q "^style.c: the tag of a c file reads .// SPDX-License-Identifier: BSD-2-Clause., found: /\* SPDX" "$W/err" &&
	grep -q "^style.h: the tag of a h file reads ./\* SPDX-License-Identifier: BSD-2-Clause \*/., found: // SPDX" "$W/err" &&
	grep -q "^indent.rst: the tag of a rst file reads .   SPDX-License-Identifier: BSD-2-Clause., found: SPDX" "$W/err"
'

test_expect_success 'the tag sits on the first line, or the second after a shebang' '
	grep -q "^late.sh: SPDX tag on line 3, expected on line 2" "$W/err" &&
	grep -q "^none.py: no SPDX-License-Identifier tag on line 1" "$W/err" &&
	grep -q "^tool: no SPDX-License-Identifier tag on line 2" "$W/err"
'

test_expect_success 'only the two expressions of the tree are accepted' '
	grep -q "^other.c: licence expression .MIT. is neither" "$W/err" &&
	grep -q "^dual.c: licence expression .BSD-2-Clause OR GPL-2.0. is neither" "$W/err"
'

test_expect_success 'BPF objects and the headers they include carry the dual licence' '
	grep -q "^prog.bpf.c: compiled into a BPF object but licensed .BSD-2-Clause." "$W/err" &&
	grep -q "^bpf/lib.h: compiled into a BPF object (included from bpf/lsm.c) but licensed" "$W/err" &&
	grep -q "^bpf/deep.h: compiled into a BPF object (included from bpf/sub/inner.h) but licensed" "$W/err" &&
	grep -q "^bpf/lib/common.h: compiled into a BPF object (included from fx/a.bpf.c) but licensed" "$W/err" &&
	! grep -q "^bpf/sub/inner.h" "$W/err"
'

test_expect_success 'a package ships its sources under the licence of its Beefile' '
	grep -q "^pkg/decoders/x.lua: shipped by pkg/Beefile under .GPL-2.0 OR BSD-2-Clause. but licensed .BSD-2-Clause." "$W/err" &&
	! grep -q "^pkg/gen.py" "$W/err" &&
	grep -q "^nolic/Beefile: no license field" "$W/err"
'

test_expect_success 'vendored C carries a licence the binaries can take' '
	grep -q "^vendor/types.h: licence expression .GPL-2.0. is not one vendored code may carry" "$W/err" &&
	grep -q "^vendor/bare.c: vendored without an SPDX-License-Identifier tag on line 1" "$W/err"
'

test_expect_success 'the tree passes' '
	(cd "$ROOT" && sh "$S") >"$W/out" 2>"$W/err" &&
	grep -q "^SPDX: [0-9]* files checked" "$W/out"
'

test_done
