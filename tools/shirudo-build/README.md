# shirudo-build

`shirudo-build` is the **operator-only** artifact-producing dispatcher
for shirudo. It compiles BPF source, runs libbpf's `gen_loader`, CMS-
signs the resulting loader bytes with the operator's private key, and
serialises the result as a `.upatch` container ready for
direct target-side loading.

## Why a separate binary

Target-side `shirudo` never forks or execs. The operator-only
`shirudo build`, `shirudo keys vouch` and operator BPM commands
dispatch to this separate helper with `execv`; when compiling `.bpf.c`
input, the helper forks and execs `clang -target bpf`. The helper ships
only in the operator package, so no target-side code path can reach the
compiler or the operator signing code. It hosts the operator-only BPM
commands: `shirudo bpm build` (Beefile to signed `.bee`), `shirudo bpm
push` (package and certificate referrer, with an optional signed index), and
`shirudo bpm tree append` (signed upatch tree). The CMS signer and these
command implementations are linked only into `shirudo-build`.

The core `shirudo` binary's `builtin-build.c` dispatches to the helper
using this resolution order: the `SHIRUDO_BUILD` environment override,
the compiled-in `$(libexecdir)/shirudo/shirudo-build` path, then
`shirudo-build` found on `$PATH`. The last case supports using a
checkout's locally built binaries without installing them. `shirudo
bpm build|push|tree append` hand their full argument vector to
`shirudo-build bpm ...` the same way.

The core binary includes those BPM subcommands in `shirudo bpm --help`
only when it can resolve this helper. If help shows only target
subcommands, set `SHIRUDO_BUILD` or add the helper directory to `PATH` as
shown below; otherwise `shirudo bpm build` is reported as unknown.

The rationale is in `Documentation/architecture.rst` (operator and
target boundary) and `AGENTS.md` (the no-subprocess invariant).

## Modes

| Input | Action |
|---|---|
| `<source.bpf.c>` | compile (fork/exec clang) → gen_loader → sign → package |
| `<file.bpf.o>` | gen_loader → sign → package (skip compile) |
| `--unload <name>` | emit signed UNLOAD directive `.upatch` |
| `keys vouch <cert.der>` | sign a vouch for another certificate |
| `bpm build [context] --version <v>` | compile, sign and package every Beefile upatch into a `.bee` |
| `bpm push <pkg.bee> oci://...` | publish the package and certificate referrer; with signing material, also update the signed index |
| `bpm tree append <pkg.bee> oci://...` | publish the next generation of a signed upatch tree |

## Install location

`$(libexecdir)/shirudo/shirudo-build`, typically
`/usr/local/libexec/shirudo/shirudo-build`.

`make install-operator` installs it alongside `shirudo` at this path.
The operator package includes both binaries and depends on `clang` and
`llvm` to compile `.bpf.c` inputs. Building from source also needs a
`vmlinux.h` for the target kernel; pass `--vmlinux` when it is not in
the default search paths.

For checkout/developer use, build both binaries and put their directories
first on `PATH`:

```sh
PATH="$PWD/tools/shirudo-build:$PWD:$PATH" \
  shirudo bpm build --version 1.0.0 --keys-dir "$HOME/.config/bpm"
```

## From BPF source to an OCI upatch tree

For a single standalone upatch, build the source directly:

```sh
shirudo build ./shield.bpf.c --keys-dir /var/lib/shirudo/keys
shirudo upatch info ./shield.bpf.upatch
```

To publish an upatch through a tree, put the source in a package context with
a `Beefile`. `bpm build` compiles and signs the source into a `.upatch`,
generates its matching unload directive, and bundles both into a `.bee`.
`tree append` then publishes the artifacts and adds a signed operation to the
OCI tree. It builds the upatch from the Beefile source itself; the standalone
`shirudo build` command is not a prerequisite.

Example layout:

```text
example-shield/
├── Beefile
└── shield.bpf.c
```

Example `Beefile`:

```toml
[package]
name = "example-shield"
description = "Example BPF shield"
license = "BSD-2-Clause"
authors = ["Example Org"]

[[upatches]]
source = "shield.bpf.c"
load_target = "upatches/shield.upatch"
unload_target = "upatches/shield.unload.upatch"

[upatches.tree]
id = "example-shield"
load_artifact = "upatches/shield.upatch"
unload_artifact = "upatches/shield.unload.upatch"
```

Build and inspect the package, then publish its tree entry:

```sh
shirudo bpm build ./example-shield --version 1.0.0 \
  --keys-dir /var/lib/shirudo/keys
shirudo bpm info ./example-shield-1.0.0.bee
shirudo bpm tree append ./example-shield-1.0.0.bee \
  oci://registry.example.com/shirudo/example-shield-tree \
  --keys-dir /var/lib/shirudo/keys
```

Signing keys are supplied to the operator commands, not embedded in the BPF
source or `Beefile`. The directory passed with `--keys-dir` contains
`signing_key.pem` and `cert.der`; `bpm build` uses them to sign each upatch,
`bpm push` uses them to sign the repository index, and `tree append` uses them
to sign the tree publication.

Without an explicit directory, the commands use `SHIRUDO_KEYS_DIR` or the
compiled default `/var/lib/shirudo/keys`. `tree append` also accepts
`--key <signing_key.pem>` and `--cert <cert.der>` as individual overrides.
Keep the private key on the operator; the package carries the public
certificate.

The first append creates the tree; later appends extend its signed history.
Add selector fields under `[upatches.tree.selector]` to limit which kernel
releases, build IDs, architectures, Kconfig values, or node labels receive
the upatch. To publish the `.bee` as an installable package as well, push it
to the package repository with signing material so the signed repository
index is updated:

```sh
shirudo bpm push ./example-shield-1.0.0.bee \
  oci://registry.example.com/shirudo/example-shield \
  --keys-dir /var/lib/shirudo/keys
```

Package publication and tree publication are separate operations.

## Uprobe multi attach points

One upatch BPF program can attach to multiple entry points in one user-space
ELF with:

```c
SEC("uprobe.multi//absolute/path/to/program:*Func")
int probe(struct pt_regs *ctx)
{
	return 0;
}
```

The portion after the colon is a standard libbpf glob: `*` matches any
sequence and `?` matches one character. Thus `*Func` can match unrelated
functions such as `fooFunc` and `barFunc`. Comma/`|` alternation is not
supported; use a single glob that covers the desired names. Each section
targets one absolute ELF path, entry probes only.

`shirudo-build` resolves matching `STT_FUNC` symbols to sorted, unique ELF
file offsets and records the ELF's GNU build ID in UPGM v2 metadata. The build
fails if the path is not absolute, the glob is empty or longer than 127 bytes,
no function matches, the ELF lacks a GNU build ID, or more than 1,048,576
offsets match. The target verifies the build ID before loading any BPF state.
