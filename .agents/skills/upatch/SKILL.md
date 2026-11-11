---
name: upatch
description: Write, build, sign, inspect and package a shirudo upatch. Covers the BPF C program written for the target kernels' preemption model and at a low cost on machines large and small, `shirudo build` for a .upatch and its unload directive, the Beefile and `shirudo bpm build` for a .bee package, `bpm info` to inspect one, `bpm push` and `bpm tree append` to publish, and loading it on a test target. Use when asked to create, change or ship an upatch or a bpm package, or to reproduce a failed upatch build or load.
---

# Upatch

`Documentation/upatches/` is the reference: `learn/concepts.rst`, then
under `write/` the attach kinds, maps, arenas and serializers, decoders,
pitfalls and memory consistency, under `publish/` the Beefile and
publishing, and under `test/` testing and debugging a failed load.
`Documentation/start/guides/first-upatch.rst` and `publish-package.rst`
walk through every command below.

## Write the program

- Plain C against `vmlinux.h` with CO-RE: never a hard-coded struct
  offset, which signs fine and is refused by the verifier on another
  kernel (`verifier_rejected`).
- Attach only with the kinds `write/attach-kinds.rst` lists. Refuse an
  operation in an `lsm` program, never in `fmod_ret`
  (`write/pitfalls.rst`).
- `char _license[] SEC("license") = "Dual BSD/GPL";`, and
  `SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause` on every file the
  object compiles and on each Lua decoder.
- Keep accumulated records in one `BPF_MAP_TYPE_ARENA` map with a
  `shirudo_serialize__<map>` program that walks them;
  `upatches/kernel-obs/obs_table.h` is the template.
- Where runs share state across CPUs or interleave on one, follow the
  `bpf-concurrency` skill, for the kernels below.
- `shirudo build` compiles with `-mcpu=v4 -fno-jump-tables` itself, so
  the whole v4 instruction set is there: write load-acquire,
  store-release, sign extension and signed division directly.

## Know the kernels it runs on

Which hazards apply, and so which locking and memory ordering the code
needs, depends on the target kernels' preemption model
(`Documentation/upatches/write/memory-consistency/hazards.rst`). Settle
it before writing code that shares state:

- When the task does not say which kernels the upatch is for, ask:
  distribution kernels (`PREEMPT_DYNAMIC`, booted `full` or `lazy`),
  `PREEMPT_RT`, `PREEMPT_LAZY` alone as the test VM runs, or a mix.
- On a target, `CONFIG_PREEMPT_RCU` in `/proc/config.gz` or
  `/boot/config-$(uname -r)` says whether RCU is preemptible, `uname -v`
  names `PREEMPT_DYNAMIC` or `PREEMPT_RT`, and with `PREEMPT_DYNAMIC`
  `/sys/kernel/debug/sched/preempt` shows the mode it booted in.
- Without an answer, write for preemptible RCU, the weakest guarantee
  and what distribution kernels give: the code is then right on every
  model.
- Write for that model and no stronger one: a guard or atomic that no
  interleaving on the target needs costs every run. The upatch's
  `README.md` names the model it is written for, as
  `upatches/kernel-obs/README.md` does.

## Keep its cost low

An upatch runs on every event of its hooks, on servers with hundreds of
CPUs and on embedded devices with little memory, and shirudo bounds
neither how often its programs run nor how large its maps are
(`Documentation/operate/plan/overhead.rst`). Make each run cheap:

- Attach to the narrowest hook that sees the event, `tp_btf`, `fentry`
  or `lsm` rather than `kprobe`, and not to one that fires for every
  syscall when one call matters.
- Decide early whether an event matters, with the cheapest test first,
  and return. Keep map lookups, helper calls and reads of user memory
  off the path most runs take, and bound the work of each run; leave
  sums, sorting and formatting to the serializer, the decoder or
  userspace.
- Put settings in `const volatile` variables in `.rodata`, as
  `[[upatches.rodata]]` entries write them: the verifier knows their
  values at load and prunes the branches they turn off.
- On many CPUs, a value every CPU writes moves its cache line from CPU
  to CPU on every write, atomic or not. Count in a per-CPU map and sum
  on export: its value stays in its CPU's cache, and needs an atomic only
  where the model lets a second run interleave on that CPU. Keep fields
  that different CPUs write in different 64-byte lines, and keep
  `bpf_spin_lock()` and other locks off hot paths; publish with release
  and acquire instead.
- On little memory, remember that a map takes its memory at load: a
  hash map preallocates `max_entries` unless it has
  `BPF_F_NO_PREALLOC`, and a per-CPU map holds a value for every
  possible CPU. Size each map for what it must hold, use an LRU map
  where old entries may go, and keep records in the arena, whose pages
  are taken only as the program allocates them.
- Measure before shipping: with `sysctl kernel.bpf_stats_enabled=1` the
  kernel counts each program's runs and run time, which `bpftool prog
  show` prints. shirudo's lockdown leaves program information readable,
  but the test VM image has no `bpftool`; bring one. Say in the
  `README.md` what the upatch costs where that is more than a little.

## Build and sign one upatch

```sh
shirudo genkey --keys-dir <keys>          # once; the operator's key pair
shirudo build <prog>.bpf.c --keys-dir <keys> -o <name>.upatch
shirudo upatch info <name>.upatch         # --json for scripts
shirudo build --unload <name> --keys-dir <keys> -o <name>.unload.upatch \
	--payload-sha256 "$(shirudo upatch info --json <name>.upatch | jq -r .payload_sha256)"
```

- In a checkout, build the helper with `make shirudo-build` and name it
  with `SHIRUDO_BUILD=<checkout>/tools/shirudo-build/shirudo-build`.
- The helper runs the clang it was built for, `SHIRUDO_CLANG_PATH`,
  `/usr/bin/clang` unless set, and that must be clang 23: an older one
  stops at a release store with `Cannot select: ... AtomicStore`.
- It looks for `vmlinux.h` as `./vmlinux.h`, `./vendor/linux/vmlinux.h`
  or the installed one, unless `--vmlinux` names it. Run it from the
  checkout, or link `vendor/` and `bpf/` into the package directory as
  the publishing guide does.

## Build a package

The Beefile (`publish/beefile.rst`) names the package and its upatches,
and optionally generated `.rodata` (`[[upatches.rodata]]`), tree
metadata (`[upatches.tree]`) and extra files. A `README.md` beside it
is what `bpm info` prints.

```sh
shirudo bpm build <dir> --version <semver> --keys-dir <keys>   # <name>-<version>.bee here
shirudo bpm info <name>-<version>.bee
shirudo bpm info upatches <name>-<version>.bee [--all]
shirudo bpm info data <name>-<version>.bee upatches/<upatch>.upatch [--json]
```

The version is SemVer 2.0.0 and nothing else. `bpm info data` decodes
the `.rodata` a rodata entry wrote, the quickest check of a generator.

## Publish

```sh
shirudo bpm push <name>-<version>.bee oci://<registry>/<namespace>/<repo> --keys-dir <keys>
shirudo bpm tree append <name>-<version>.bee oci://<registry>/<repository> [<append-options>]
```

`push` signs the namespace's index along with the package. Pass
`--new-index` for the first package of a namespace and never after.
`BPM_OCI_SCHEME=http` is for a registry on the loopback only. `tree
append` adds a load or delete operation to a signed upatch tree that
targets sync; `Documentation/reference/cli/bpm.rst` lists its options.
It refuses an `add` whose XDP programs select a device class another
upatch of the tree selects on the same nodes: give each class to one
upatch, or the two entries selectors that exclude each other.

## Load it on a target

Only in the test VM (the `testing` skill), with the guest's
`shirudo-runtime`: `upatch load <name>.upatch`, `upatch map`, then
`upatch unload <name>.unload.upatch`; a package with `bpm install` and
`bpm uninstall`. A failed load names a category from
`Documentation/reference/failure-categories.rst`;
`Documentation/upatches/test/debugging.rst` says what each one means and
how to find the cause.
