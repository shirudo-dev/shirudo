---
name: bpf-coccinelle
description: Checks upatch BPF code with shirudo's Coccinelle rules for concurrency hazards, runs them on one file or package outside the tree, reads a match, and adds a rule for a pattern worth refusing for good. Use while writing or reviewing a upatch's BPF C, when check-coccinelle.sh reports a bpf_ rule, or when a hazard keeps coming back and should get a rule.
---

# Coccinelle for upatch BPF code

The rules live in `testing/coccinelle/`, each a pattern the tree is kept
free of; `.github/scripts/check-coccinelle.sh` runs them over every
tracked C file and CI fails on a match. The six `bpf_` rules catch the
hazards of `Documentation/upatches/write/memory-consistency/hazards.rst`
that one function shows:

| Rule | Reports |
|---|---|
| `bpf_map_rmw` | a load, add and store through a value other CPUs share: a non-per-CPU map value, inode, socket or cgroup storage |
| `bpf_check_then_insert` | a lookup that finds nothing, then an insert with `BPF_ANY` |
| `bpf_cas_unchecked` | a compare-and-swap whose result nobody reads |
| `bpf_publish` | `WRITE_ONCE()` of a pointer, which orders nothing before it |
| `bpf_user_double_fetch` | two reads of the same user address |
| `bpf_map_use_after_delete` | a read through a lookup's pointer after a delete from that map |

## Run them

On the tree, from the checkout root, by rule name:

```sh
.github/scripts/check-coccinelle.sh bpf_map_rmw bpf_check_then_insert \
	bpf_cas_unchecked bpf_publish bpf_user_double_fetch bpf_map_use_after_delete
```

On a file the tree does not track, such as a upatch under development,
run spatch from the checkout root, where the `#spatch` line of each rule
finds `testing/coccinelle/bpf.macros`:

```sh
for r in testing/coccinelle/bpf_*.cocci; do
	spatch -D report --very-quiet --include-headers --sp-file "$r" <dir>/*.bpf.c <dir>/*.h
done
```

## Make sure the file was parsed

A function Coccinelle cannot parse is skipped without a word, and a rule
that saw nothing reports nothing. When a file is new or uses new macros,
check it parses:

```sh
spatch --parse-c --macro-file testing/coccinelle/bpf.macros <file>.bpf.c
```

and look for `BAD` lines. A macro it trips on gets a definition in
`bpf.macros`. A macro that expands to nothing and leaves a `;` at file
scope derails the rest of the file, so define it as a declaration, as
`BUILD_BUG_ON` is. A file with its own token-pasting macros, such as
`upatches/kernel-obs/obs_table.h`, cannot be parsed at all: review and
blitmus cover it (`bpf-concurrency` skill).

## Read a match

Each line is `<rule>: <file>:<line>: <message>`. Fix the code as the
hazard's section in `hazards.rst` says. There is no comment that hides
a match: when the code is safe for a reason the rule cannot see, write
it so that the rule sees it, such as reading the compare-and-swap result
or inserting with `BPF_NOEXIST`. The rules see one function at a time,
so a hazard spread over two passes them. No rule refuses per-CPU
scratch: whether it is a hazard depends on the kernel's preemption
model and on the programs that share the map, which a rule cannot tell,
so review decides.

## Add a rule

A pattern worth refusing for good gets a rule, with the tree fixed first
so that CI stays green. Write it from scratch, or carry it with its SPDX
and copyright lines from a project that offers it under a BSD-2-Clause
branch; read GPL-only collections for ideas, never copy them. Then:

- Start the file with the SPDX and copyright lines and a comment that
  says what the pattern breaks and on which kernels, as the others do,
  then `#spatch --no-includes --macro-file testing/coccinelle/bpf.macros`
  and `virtual report`.
- Put `attribute name SEC;` in the first rule, as every rule of the
  tree does. Without it Coccinelle takes a map defined as
  `} name SEC(".maps");` for a typedef, and no pattern matches a call
  that passes `&name`.
- Add a sample to `write_bpf_samples()` in
  `testing/ci-checks/t0006-check-coccinelle.sh` that the rule must report
  and a safe form it must leave alone, and add the rule to `BPF_RULES`.
- Say `exists` in the header of a rule whose pattern spans a `...`,
  such as a lookup and a later update: without it the pattern must hold
  on every path, and the one where an `if (p)` skips the update defeats
  it.
- Mind the SmPL traps: a `*` in column 0 is star mode, which matches
  without the `*` and puts the whole file in context mode, and a `(` there
  opens a disjunction, so indent such lines by a space; `=~` takes OCaml
  regular expressions, so prefer identifier sets; `x == NULL` also
  matches `!x`; one position cannot appear twice in a disjunction;
  expression and statement branches cannot be mixed.
- Give each form the rule reports a sample: a branch that never matches
  passes every run of the tree unnoticed.
- Run it on the tree with `check-coccinelle.sh <rule>` and on its sample
  with `make -C testing ci-checks`, and name the rule in
  `hazards.rst` where its hazard is described.
