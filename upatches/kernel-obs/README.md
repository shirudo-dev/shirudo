# kernel-obs

The `kernel-obs` package installs the `kernel-obs` upatch and the
`userns-unshare-counter` upatch. `kernel-obs` provides host
observability for executed programs, network peers and volumes,
listeners, DNS answers, watched destinations, privilege transitions
and access to credential and persistence files. Every hook observes;
nothing in this package enforces. `userns-unshare-counter` counts calls
to `unshare()` that request a new user namespace; it does not block or
change them. Its `userns_unshare_calls` per-CPU map holds the count.

Each table lives in one BPF arena and holds one export interval: the
export flips to a fresh buffer, drains the previous one and clears it,
so a table never fills up for good and every snapshot reports the
allocations it had to refuse (`interval.overflow`) and records a
previous, unfinished export left behind (`interval.lost`). Records are
per-interval deltas with first- and last-seen wall-clock timestamps.

Run installation and map commands on the target. The target needs
shirudo initialized before loading the package.

## Verify the signing key

Use the package reference supplied by your publisher:

```sh
PACKAGE=oci://quay.io/namespace/kernel-obs:0.0.1
shirudo bpm key fingerprint "$PACKAGE"
```

Compare the printed SHA-256 public-key fingerprint with the one the
publisher gave you through a trusted channel and proceed only when they
match. For first-time target setup, import the verified certificate
before initializing shirudo:

```sh
sudo shirudo bpm key add "$PACKAGE"
sudo shirudo bpm key list
```

## Install the package

```sh
sudo shirudo bpm install "$PACKAGE"
sudo shirudo upatch list
```

`shirudo bpm info "$PACKAGE"` prints this document without installing.

## Tables

To inspect the unshare counter, use `shirudo upatch map
userns-unshare-counter userns_unshare_calls`. Running `unshare -U true`
triggers the traced path.

| Map | Key | Records |
| --- | --- | --- |
| `exec` | executable, calling image, cgroup, euid | name, resolved path, uid, effective capabilities, pid, exec count; scripts yield one record for the script and a flagged one for the interpreter |
| `net` | executable, cgroup, protocol, role, peer address and port | connects or datagrams sent, packets and bytes in each direction, pid; accepted and listener-side peers aggregate by address, without the ephemeral port |
| `socket` | creator and current caller, family, type, protocol and operation | socket creation attempts for every family, plus bind/connect/listen/accept/send/receive/option/shutdown activity for IP, packet, XDP, UNIX, NETLINK and VSOCK sockets |
| `listen` | executable, cgroup, protocol, local address and port | TCP listens and UDP binds to a fixed port, with backlog |
| `watch` | executable, cgroup, protocol, destination | attempts and packets towards addresses in `watch.list` |
| `dns` | executable, cgroup, answered address | up to four names that resolved to the address, with counts |
| `priv` | executable, cgroup, kind, subtype, euid | setuid to root, root without an exec or setuid to explain it, ptrace attach, mount, executable mmap and mprotect requests, kernel file and module loads, user namespace creation, bpf() use |
| `file` | executable, cgroup, euid, open mode, path | opens matching `file-watch.list`, with the filesystem magic |
| `watch_stat` | per-CPU counters | metric: socket-level checks against the watch list and matches |

Records include first- and last-seen timestamps and available task
identity. Executable identity is `{dev, ino}` with a cgroup id. Socket
records keep separate `owner` and `actor` identities with known and
inferred flags. Other tables flag a task that started before the upatch
loaded as `caller_inferred` when its mapped executable is first observed.

The `mmap_exec` privilege records report mapping requests that include
`PROT_EXEC`; `mprotect_exec` records transitions that newly grant it.
Their subtype is the requested protection bits; `mmap_exec` stores
mapping flags in `aux`, while `mprotect_exec` stores the VMA length.
`name` is the backing file name or `anonymous`. These hooks observe
requests, not whether the mapping succeeds or code runs.

Socket records describe attempts at the LSM hook; byte counts are
requested send or receive lengths, not confirmed transfers. Socket type
flags such as `SOCK_CLOEXEC` and `SOCK_NONBLOCK` are stripped before the
creation hook, so records retain the base type. Families without detailed
operation hooks still get creation, family, type and protocol records.
Sockets already open when the upatch loads are not enumerated; their owner
is marked inferred when an operation is first observed. Kernel-space
creations are not recorded. UNIX paths, message payloads and VSOCK peer
identifiers are not recorded. AF_PACKET and AF_XDP ring records cover setup
and wakeup calls, not individual frames.

Packet counts come from the cgroup hooks on the root cgroup and cover
every socket on the host, including sockets created before the load,
which are attributed to their cgroup alone until their owner is known.
Packets are counted as the socket layer sees them, before segmentation
offload splits them on the wire.

## Watch lists

`watch.list` holds IPv4 and IPv6 addresses or prefixes; attempts to
reach them are recorded in `watch` in addition to `net`. The shipped
list names the cloud instance metadata addresses and the public
DNS-over-HTTPS resolvers. `file-watch.list` holds base names,
`parent/name` pairs or `parent/*` directory rules, optionally with a
trailing `w` for opens for writing only. Both are compiled into the
signed object: edit the list, run `make lists` in this directory and
rebuild the package. There is nothing to configure on the target.

To update only the watch addresses in an existing `.upatch`, run
`python3 rewrite_watch_upatch.py watch.list kernel-obs.upatch`. It takes
the same address and CIDR format as `gen_watch.py`, preserves the compiled
loader and BTF, and re-signs the changed `.rodata` with the operator key
from `/var/lib/shirudo/keys` (or `--keys-dir`). Use `--dry-run` to check
that the new tries fit the arrays in the existing BTF layout, or `-o` to
write a separate artifact. The tool refuses a list that needs more trie
nodes than the existing arrays hold; changing those capacities still
requires rebuilding the BPF object.

The Beefile also declares `watch.list` as the input for both watch trie
variables. `bpm build` uses `gen_watch_rodata.py` to create their raw BTF
values. The input name is derived from the basename before its first dot,
so `watch.list` is named `watch`; override it for one build with:

```sh
shirudo bpm build ./upatches/kernel-obs --version 0.1.1 \
	--rodata-input watch=./customer/watch.list
```

To update the data without recompiling BPF, `bpm config update` reads the
Beefile and updater dependencies from a previously built package. This
chooses to trust and run the package's updater on the operator; those files
are not covered by the upatch CMS signature. It then writes a new versioned
package:

```sh
shirudo bpm config update \
	--base-package oci://registry.example.com/shirudo/kernel-obs:0.1.0 \
	--version 0.1.1 \
	--rodata-input watch=./customer/watch.list
```

Pass `-f ./upatches/kernel-obs/Beefile` to use the local Beefile
and updater files instead. The target receives only the newly signed
upatch and never runs the updater.

## Read the tables

```sh
sudo shirudo upatch map kernel-obs
sudo shirudo upatch map kernel-obs exec
sudo shirudo upatch map kernel-obs exec --json
sudo shirudo upatch map kernel-obs net --show-full
sudo shirudo upatch map kernel-obs priv --json=./priv.ndjson
```

Reading a table drains it, exactly as the map-export timer does; add
`--peek` to look at the interval being collected without taking it
from the exporter.

## Preemption model

`kernel-obs` is written for the preemption model of the kernel the test
VM runs: `CONFIG_PREEMPT_LAZY` alone, without `CONFIG_PREEMPT_DYNAMIC`
and so without preemptible RCU (`CONFIG_PREEMPT_RCU`). The VM suite is
where the package is loaded and its tables are checked, in CI and in a
local `make tests`, so its concurrency is reviewed against the kernel
that suite runs rather than against one no test exercises.

On that kernel the `lsm` and `cgroup_skb` programs run with preemption
disabled, so no other task's run starts on a CPU before one ends; a
softirq can still run an ingress program on top of an egress one, and
the sleepable `lsm.s` programs can sleep. The DNS parser builds a query
in a per-CPU scratch buffer without a guard: only egress runs use it,
and those come from the task that sends the query, so on that kernel
none starts before another ends. Runs on different CPUs share the arena
tables on every kernel, so the tables take and count their entries with
atomics, publish a buffer with a release store, and an export expects
late writes into the buffer it drains.

A kernel with preemptible RCU, which `CONFIG_PREEMPT`,
`CONFIG_PREEMPT_RT` and `CONFIG_PREEMPT_DYNAMIC` bring, is outside that
model. `PREEMPT_DYNAMIC` is the kernel's default and what distribution
kernels use, and since 7.0 it boots only in its `full` or `lazy` mode;
before, distribution kernels mostly booted it as `voluntary`, which does
not preempt a running program. On such a kernel another task's egress
run can preempt a DNS query parse on the same CPU and overwrite the
scratch, so that a DNS record carries the name of another query. The
record is wrong, nothing more: `kernel-obs` observes and decides
nothing.

## Limits

DNS over TCP, TLS and HTTPS is not parsed; the resolvers are on the
watch list instead, and DNS on ports other than 53 is not looked at.
IPv6 extension headers are not walked. Forwarded traffic does not pass
the cgroup hooks and is not counted.

## Open work

The DNS parser correlates a UDP response with its request by network
namespace, addresses, ports and transaction ID. It does not yet:

- [ ] compare the response's question name, case-insensitively, and its
      class with the request's;
- [ ] check the response's opcode, RCODE and TC bits, and decide whether a
      truncated response yields no record or a partial one;
- [ ] keep A answers to A queries and AAAA answers to AAAA queries;
- [ ] age out pending requests, so a late response cannot match a later
      reuse of the same flow and ID;
- [ ] reject IP fragments, check the IP and UDP lengths against the packet
      and hold the 1232-byte parsing budget on the packet itself;
- [ ] walk IPv6 extension headers, or reject packets that carry one;
- [ ] reject an embedded NUL in a label and bound every compression
      pointer it skips, against loops and out-of-packet targets;
- [ ] count a full pending table, LRU displacement, stale responses and
      answers past its cap of 75, instead of dropping them silently;
- [ ] cover malformed packets on the target, which needs a live packet
      harness; `dns_obs_matrix.py` in shirudo's tests only builds them.
