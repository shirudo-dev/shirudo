---
name: kernel
description: "Changes the kernel shirudo is tested on: the carried patches under testing/kernel/patches and the pages that name them, the pinned bpf-next commit, building, publishing and staging the test kernel, the artifact pin in kernel-artifact.sh, vmlinux.h and BTF, and reading kernel source at the pin. Use before moving either pin, and when touching testing/kernel, a carried patch, the kernel configuration, or a check that reads the kernel's BTF."
---

# Kernel

The test kernel is bpf-next at the commit in
`testing/kernel/bpf-next.commit` with every patch of
`testing/kernel/patches/` applied, configured from the fragments beside
them. The references:

- `Documentation/internals/kernel-patches.rst`, each carried patch, what
  it changes, why shirudo needs it and what fails without it.
- `Documentation/internals/kernel-interfaces.rst`, the upstream commits
  shirudo needs ("Kernel baseline") and every hook and kfunc with the
  patch it needs.
- `Documentation/operate/plan/system-requirements.rst`, what a target
  kernel needs, its configuration and the pre-flight checks.
- `Documentation/contribute/testing/testing.rst`, the CI kernel, its
  publication and the artifact the VM boots.

The `testing` skill boots VMs on the staged kernel; this skill changes
that kernel. Load the `docs` skill for the pages a change touches and
the `commits` skill for the shirudo commit that carries it. Read
[pages.md](pages.md) before adding or dropping a patch or moving a pin:
it lists every page and file that names a patch, a hook or the pin.

## Inputs

| Input | Read by |
|---|---|
| `testing/kernel/bpf-next.commit` | `build-kernel.sh`; 40 hex digits, nothing else |
| `testing/kernel/patches/*.patch` | `build-kernel.sh`, `git am --3way` in file name order, every run |
| `testing/kernel/kernel-ci.conf`, `kernel-ci.<arch>.conf` | `build-kernel.sh`, merged over `allnoconfig` |
| `testing/vm/kernel-artifact.sh` | VM goals and CI: the published run, a SHA-256 per architecture |

A pull request or push that changes `testing/kernel/`,
`.github/scripts/build-test-kernel.sh` or
`.github/workflows/build-kernel-packages.yml` makes the CI suite build
x86-64 and arm64 and run its VM tests on that x86-64 build
(`.github/scripts/select-test-kernel.sh`). Every other run downloads
the artifact `kernel-artifact.sh` pins, so a change to the pin alone
builds nothing.

## Never on the host

- `.github/scripts/build-test-kernel.sh` deletes directories under
  `/usr` and `/opt` and installs packages, with sudo. Its package list
  is what a Debian or Ubuntu host needs for `build-kernel.sh`; install
  them, or ask the user to, and run `build-kernel.sh` itself.
- `.github/scripts/tests.sh setup` installs packages and writes udev
  rules with sudo. Stage an artifact with
  `testing/vm/kernel-artifact.sh stage <dir>` instead.
- `.github/scripts/publish-test-kernel.sh` creates a release; only its
  workflow runs it, and `testing/ci-checks/t0010-publish-test-kernel.sh`
  with a stub `gh` first on `PATH`.

Not the first two even as a dry run with stubbed commands. A kernel
build fetches bpf-next history from git.kernel.org and runs long (CI
gives it 120 minutes per architecture): say so before starting one.
Kernel source goes into a patch, never into shirudo's C, which is
BSD-2-Clause.

## Carried patches

Two kinds, each with its row and section in `kernel-patches.rst`:

- Functional patches change what an LSM program may do: add a hook
  (`tpm_command`, `mm_read_access`), make hooks sleepable, trust a
  pointer, change a kfunc. Without one, pre-flight fails, the `bpf2` or
  `seal` object does not load, or the seal falls back to a weaker check,
  as each section's "Without it" says.
- Build fixes change how the kernel builds or names itself: the kbuild
  patch drops `.0` and `-rc` from the release, the riscv one keeps LLVM
  from breaking vmlinux BTF.

A patch is `git format-patch` output: the author in `From:`, a subject
in the kernel's form (`bpf: Treat dentry->d_parent as a trusted
pointer`), a body that says why, written to go upstream as the kernel's
`Documentation/process/submitting-patches.rst` asks, the author's
`Signed-off-by:`, then the diffstat and the diff. An agent never adds a
`Signed-off-by:`; the person gives it. The file name is
`NNNN-<subject>.patch`. The number sets the apply order and is the name
the pages use ("carried patch 0024"): never renumber, leave the gap a
dropped patch leaves, and give a patch the next number after the
highest. `testing/kernel/patches/.gitattributes` keeps whitespace
verbatim; an editor that strips trailing blanks breaks context lines.
Run the check at the end of [pages.md](pages.md) after any change to
the set: every patch documented, every hook it adds used.

### Add a patch

1. Open a kernel worktree at the pin with the carried patches applied
   ("Read kernel source" below), and commit the change there, with the
   person as author and no `Signed-off-by:` of the agent's.
2. Write it out under the next number, with the whole subject in the
   file name, and check it:

   ```sh
   git -C <wt> format-patch -1 --start-number <N> \
   	--filename-max-length=128 -o <checkout>/testing/kernel/patches
   <wt>/scripts/checkpatch.pl --strict <patch>
   ```
3. `testing/kernel/build-kernel.sh --config-only`: it applies every
   patch to the pin as the build does and verifies the configuration.
4. Add the patch's summary row and section to `kernel-patches.rst` in
   the commit that adds the patch.
5. Land it first, without the code that needs it, then publish and
   move the artifact pin together with that code and the rest of the
   pages [pages.md](pages.md) lists. Code on a hook the pinned artifact
   lacks fails every later run, because those runs download the pin.
6. The code needs no list of hooks: `kernel_lsm_hooks`
   (`util/preflight.c`) reads them from the embedded `bpf2` and `seal`
   objects, and `kernel-artifact.sh` from the `SEC("lsm/...")` lines of
   `bpf/*.c`. A check `util/kernel_abi.c` hard-codes is the exception,
   such as `bpf_lsm_tpm_command` in the signed-loader ABI check, with
   its cases in `testing/unit/kernel_abi.c`.
7. Verify: the patch's pull request passes the CI suite on the kernel it
   built, and `.github/scripts/check-docs.sh` passes on both changes.

### Move the pin

1. Take a full commit hash from bpf-next.
2. In a kernel worktree at that commit, apply the series:
   `git -C <wt> am --3way <checkout>/testing/kernel/patches/*.patch`.
   Resolve a patch that stops and `git am --continue`. A patch whose
   change the commit already has is upstream: `git am --skip` and drop
   it (below).
3. Write out again only the patches that stopped or printed `Falling
   back to patching base and 3-way merge`, each under its own number
   and file name (step 2 of "Add a patch"). The others stay byte for
   byte, which keeps the review small. `build-kernel.sh` fetches only
   recent history (`--shallow-since`), so a three-way fallback there
   needs a patch written against a recent base.
4. Write the hash to `testing/kernel/bpf-next.commit`.
5. `testing/kernel/build-kernel.sh --config-only`. A `lint:` line names
   a fragment symbol the tree no longer has; `CONFIG_<X> wanted <v> by
   <fragment>, final .config has <w>` is an option whose dependencies
   went missing. Fix the fragment.
6. Recheck "In bpf-next" for every patch at the commit, as the paragraph
   under the summary table of `kernel-patches.rst` describes, and name
   the commit there.
7. Land this as one change; its CI suite builds and tests the kernel.
   Then publish it and move the artifact pin (below) with the pages
   that name the commit the suite runs.
8. Verify the published kernel by commit (below) and run the VM
   families the change reaches (`testing` skill).

### Drop a patch

1. Find the upstream commit in the commit to move to,
   `git -C <kernel-tree> log --oneline <commit> -- <files of the patch>`,
   and check that upstream's form is what `bpf/` uses: hook name and
   arguments, the sleepable set, the kfunc's checks. Where it differs,
   change the programs and any check in `util/kernel_abi.c` with them.
2. Move the pin to a commit that contains it and `git rm` the patch in
   the same change.
3. Update the pages [pages.md](pages.md) lists: the patch leaves
   `kernel-patches.rst`, and its upstream commit takes its row in
   `system-requirements.rst` and joins "Kernel baseline".
4. Verify as for moving the pin.

### Publish and move the artifact pin

Dispatching needs write access to `shirudo-dev/shirudo`; ask first.

1. `gh workflow run build-kernel-packages.yml --ref main`. Only a
   dispatched run uploads `kernel-ci-source`, so the build a CI suite
   run makes cannot be published.
2. Within the 14 days the run keeps its artifacts,
   `gh workflow run publish-test-kernel.yml --ref main -f run_id=<run>`.
   It creates the prerelease `test-kernel-<run>` with both bundles, the
   source and `SHA256SUMS`.
3. In `testing/vm/kernel-artifact.sh` set `PINNED_RUN_ID`, and from
   `gh release download test-kernel-<run> --repo shirudo-dev/shirudo --pattern SHA256SUMS --output -`
   `PINNED_AMD64_SHA256` (`kernel-packages-x86-64-ci.zip`) and
   `PINNED_ARM64_SHA256` (`kernel-packages-arm64-ci.zip`), all three in
   one change.
4. Verify the kernel by commit.

## Verify a kernel by commit

The release string does not say what a kernel carries. bpf-next's
`Makefile` names the release it follows, not the one its features go
into, and the kbuild patch drops `.0` and `-rc`: the test kernel
reports `<VERSION>.<PATCHLEVEL>-shirudo-ci-<yyyymmdd>`. Check the commit
and the BTF:

```sh
testing/vm/kernel-artifact.sh download   # into build/kernel-ci-artifact/; the staged kernel stays
testing/vm/kernel-artifact.sh run-id
grep -E '^(commit|patches|fragments_sha256)=' build/kernel-ci-artifact/*/BUILD-INFO
cat testing/kernel/bpf-next.commit; ls testing/kernel/patches
cat testing/kernel/kernel-ci.conf testing/kernel/kernel-ci.<arch>.conf | sha256sum
tr '\0' '\n' <"$(find build/kernel-ci-artifact -name 'vmlinux-*.btf')" | grep -x 'bpf_lsm_<hook>'
```

- `BUILD-INFO` sits beside the packages, in `build/kernel-ci-artifact/`
  after a fetch or download and in `build/test-kernel/pkgs/` after a
  build by hand; the staged directory has none. `commit=` is the pin,
  `patched_commit=` the head after `git am`.
- The package version ends in `.g` and the pin's first 12 hex digits.
- Only `fetch` writes `kernel-run-id`; a kernel staged with `stage` or
  by other means has none. A staged kernel is used as it is, whatever
  run it came from.
- On a target, `shirudo init --check-only` checks the running kernel's
  BTF: `signed_loader_kernel_abi`, `kernel_lsm_hooks`,
  `module_signatures`.

## What the floor means for code

- The floor is the pinned commit with the carried patches. The programs
  of `bpf/` and the code that loads them are written for that verifier,
  those hooks and kfuncs: no probe with a fallback, no construct kept
  for an older verifier. A missing feature fails the build, pre-flight
  or the load ("No legacy kernel fallbacks" in
  `Documentation/internals/design-decisions.rst`).
- Gate on BTF, never on the release or `LINUX_VERSION_CODE`. Do not use
  libbpf's `LINUX_KERNEL_VERSION` extern: with two release components
  `get_kernel_version()` returns 0 and the object fails to load.
- `VM_KERNEL_MIN` in `testing/Makefile` is the lowest release `KERNEL=`
  accepts for a VM, not a statement about bpf-next's features.
- upatches are written for the kernels they ship to: the `upatch` skill.

## Build, stage and BTF

Read [build.md](build.md) before building a kernel by hand, staging
one for the VM, or changing how a build picks `vmlinux.h` and the BTF.
The defaults:

```sh
testing/kernel/build-kernel.sh --config-only   # patches and .config only
testing/kernel/build-kernel.sh --llvm 20       # as CI builds, host arch
testing/vm/kernel-artifact.sh stage build/test-kernel/pkgs/<arch>/<release>-<stamp>
```

Every run applies every patch, with no option to skip one. Staging
replaces the kernel every VM goal and BPF build of the checkout uses.
`vendor/linux/vmlinux.h` is generated from the staged kernel's BTF, and
`make bpf-deps`, which refreshes `vendor/libbpf/`, runs only when asked.

## Read kernel source

A kernel tree at the commit the kernel was built from, the pin unless
`BUILD-INFO` says otherwise, with the carried patches applied, is the
ground truth for kernel behavior: not the host's running kernel, a
distribution's tree or memory. Keep the tree's own checkout as it is
and add a worktree:

```sh
pin=$(cat testing/kernel/bpf-next.commit)
git -C <kernel-tree> fetch https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git "$pin"
git -C <kernel-tree> worktree add --detach <wt> "$pin"
git -C <wt> am --3way <checkout>/testing/kernel/patches/*.patch
```

After a build by hand, `build/test-kernel/src/` is that tree; read it,
do not edit it. Name the commit with every file and function a finding
cites.

## Production kernels

The tree builds only test kernels: `kernel-ci.conf` calls its profile
small and non-deployable. A production kernel needs the same changes,
and `system-requirements.rst` says the `shirudo-dev/kernel` repository
builds its artifacts; nothing here builds, pins or checks them. Tell the
user when a change to the patches has to reach those kernels too;
`Documentation/operate/plan/hardening.rst` lists the options a
production kernel takes beyond the requirements.
