---
name: bpf-concurrency
description: Writes or reviews BPF code in a shirudo upatch whose runs share state, across CPUs at once or interleaved on one. Covers shared map values, per-CPU scratch, inserting and deleting entries, compare-and-swap, publishing records, double buffers, user memory, and the runs the kernel skips. Use when a upatch program updates state other runs read, when a lock, atomic, acquire or release is involved, or to check such code with the Coccinelle rules and blitmus.
paths:
  - "upatches/**/*.bpf.c"
  - "upatches/**/*.h"
---

# Concurrent BPF code in upatches

The rules and their reasons are in
`Documentation/upatches/write/memory-consistency/hazards.rst`, where
each hazard has a section and a table says where it applies, and in
`Documentation/upatches/write/pitfalls.rst`, on the runs a program does
not see. `memory-consistency/blitmus.rst` shows how to test ordering
between CPUs. Read the sections for the hazards the code meets; this
skill is the order to work in.

## 1. Map the shared state

For every map value, arena record or variable more than one run
touches, write down the programs that read and write it, their program
types, and what holds it: a plain map, a per-CPU map, task, inode,
socket or cgroup storage, an arena, or the stack.

## 2. Fix the model

When the task does not say which kernels the upatch is for, write for
preemptible RCU, which is right on every model, as the `upatch` skill
says; it also says how to read a target's model. Runs on
different CPUs at once happen on every kernel. A second run on
the same CPU before the first ends depends on the kernel's preemption
model and the program types, as the table in "Where each hazard
applies" says. Distribution kernels boot `PREEMPT_DYNAMIC` as `full` or
`lazy`, with preemptible RCU; the test kernel has `PREEMPT_LAZY` alone,
so the VM suite shows same-CPU interleaving only for `syscall` and
sleepable programs. When the code is correct only under one model, its
`README.md` says which, as `upatches/kernel-obs/README.md` does.

## 3. Apply each fix where its hazard applies, and only there

| Hazard (section in hazards.rst) | Fix |
|---|---|
| Updates of shared values | `__sync_fetch_and_add()` and its kin on a value other CPUs share |
| Inserting a missing key | `BPF_NOEXIST`, and on `-EEXIST` look it up again |
| Using a value after deleting its entry | read or copy the value first |
| Compare-and-swap | check every result; a failed one changes and orders nothing |
| Publishing a record | `__atomic_store_n(&p, v, __ATOMIC_RELEASE)` or a value-returning atomic, never `WRITE_ONCE()`; read through `READ_ONCE()` and an address dependency, or a load-acquire where the index is compared with a constant first |
| Switching buffers | expect writes into the half being drained |
| Reading user memory twice | read it once |
| Per-CPU memory used as scratch | where a second run can come: task storage no softirq program uses, the stack, or a busy flag taken with `__atomic_exchange_n()` and released with a release store; a per-CPU counter there with an atomic |

A fix where no interleaving needs it costs every run and hides the
reasoning; leave the plain form where only one guarded program, or only
`kprobe` and `kretprobe` programs, touch the memory.

## 4. Plan for what the program does not see

The kernel skips `kprobe` and `kretprobe` runs while another runs on the
CPU or the CPU is in a `bpf()` map call, nested `fentry`, `fexit`,
`fmod_ret` and `tp_btf` runs, `kretprobe` returns beyond its
instances and `uretprobe` and `uretprobe.multi` returns beyond the
task's 64, so a detector can miss what it looks for; on a target,
`shirudo status` (`MISSED`, `missed_runs`) and `shirudo upatch get`
show the skips the kernel counts, and `-` or `null` for the uprobe
kinds, whose skips it does not count. Refuse an
operation in an `lsm` program wherever a hook covers it, and in
`fmod_ret` only where none does: a skipped `fmod_ret` run lets the
call through, and a task can arrange the skip.
An `lsm` program does not see what an LSM before it refused, and its
hook runs before the operation, which can still fail. In a softirq the
current task is whichever one was interrupted. Walk RCU pointers under
`bpf_rcu_read_lock()` in a sleepable program, check map update and
delete results where a lost update matters, size LRU maps with room to
spare, and read values userspace rewrites under `BPF_F_LOCK`. Prefer
`lsm`, `tp_btf` and `fentry` to `kprobe`, which misses calls the
compiler inlined. `pitfalls.rst` explains each.

## 5. Check

```sh
.github/scripts/check-coccinelle.sh bpf_cas_unchecked bpf_check_then_insert \
	bpf_map_rmw bpf_map_use_after_delete bpf_publish bpf_user_double_fetch
```

The `bpf-coccinelle` skill shows how to run them on files the tree does
not track and how to make sure Coccinelle parsed them. The rules see
one function at a time and cannot parse a file with its own
token-pasting macros, such as `obs_table.h`. Write the ordering
between CPUs such code relies on as litmus tests, with a control test
the CPU may break, and run them with blitmus on x86-64, arm64 and
riscv64, built with clang 23 (`blitmus.rst`): a pass on x86-64 alone
says little. blitmus covers `READ_ONCE()`, `WRITE_ONCE()`, acquire,
release, full barriers and the add, exchange and compare-and-exchange
atomics, not the or, and and xor atomics, `bpf_spin_lock()` or RCU.
Review decides what neither tool sees: hazards spread over functions,
same-CPU interleaving and what maps and helpers do inside.
