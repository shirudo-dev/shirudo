# kernel-obs

The `kernel-obs` package installs the `kernel-obs` upatch: host
observability for executed programs, network peers and volumes,
listeners, DNS answers, watched destinations, privilege transitions
and access to credential and persistence files. Every hook observes;
nothing in this package enforces.

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

| Map | Key | Records |
| --- | --- | --- |
| `exec` | executable, calling image, cgroup, euid | name, resolved path, uid, effective capabilities, pid, exec count; scripts yield one record for the script and a flagged one for the interpreter |
| `net` | executable, cgroup, protocol, role, peer address and port | connects or datagrams sent, packets and bytes in each direction, pid; accepted and listener-side peers aggregate by address, without the ephemeral port |
| `listen` | executable, cgroup, protocol, local address and port | TCP listens and UDP binds to a fixed port, with backlog |
| `watch` | executable, cgroup, protocol, destination | attempts and packets towards addresses in `watch.list` |
| `dns` | executable, cgroup, answered address | up to four names that resolved to the address, with counts |
| `priv` | executable, cgroup, kind, subtype, euid | setuid to root, root without an exec or setuid to explain it, ptrace attach, mount, executable mmap and mprotect requests, kernel file and module loads, user namespace creation, bpf() use |
| `file` | executable, cgroup, euid, open mode, path | opens matching `file-watch.list`, with the filesystem magic |
| `watch_stat` | per-CPU counters | metric: socket-level checks against the watch list and matches |

Every record carries the executable as `{dev, ino}` of the file, the
cgroup id, and `first_seen_unix_nano` and `last_seen_unix_nano`. A task
that started before the upatch loaded is attributed from its mapped
executable and flagged `caller_inferred` on its next exec.

The `mmap_exec` privilege records report mapping requests that include
`PROT_EXEC`; `mprotect_exec` records transitions that newly grant it.
Their subtype is the requested protection bits; `mmap_exec` stores
mapping flags in `aux`, while `mprotect_exec` stores the VMA length.
`name` is the backing file name or `anonymous`. These hooks observe
requests, not whether the mapping succeeds or code runs.

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

## Limits

DNS over TCP, TLS and HTTPS is not parsed; the resolvers are on the
watch list instead. IPv6 extension headers are not walked. Forwarded
traffic does not pass the cgroup hooks and is not counted. The
`dns.todo` file lists the remaining DNS parser gaps.
