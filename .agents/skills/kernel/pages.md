# Pages and files that follow the kernel

Find every mention of what changes first, in the pages, the agent guide
and the skills:

```sh
git grep -n -e '<hook>' -e '<NNNN>' -e 'carried patch' -e '<12-hex pin>' \
	Documentation AGENTS.md .agents/skills
```

## A carried patch

| File | What names the patch |
|---|---|
| `Documentation/internals/kernel-patches.rst` | The summary row (Patch, Author, In bpf-next, Architectures), the paragraph under it that says how "In bpf-next" was checked and at which commit, and a section with Subject, Files, What it changes, Why shirudo needs it, Without it |
| `Documentation/operate/plan/system-requirements.rst` | A row of "Kernel source"; the `kernel_lsm_hooks` row of "Pre-flight checks" names the carried hooks |
| `Documentation/internals/kernel-interfaces.rst` | The paragraph after "Kernel baseline" lists what bpf-next lacks; the LSM hook and kfunc tables name the patch a hook or kfunc needs |
| `Documentation/internals/enforcement.rst`, `Documentation/internals/seal.rst` | The hook's verdicts, and patches named by number |
| `Documentation/concepts/background/xattrs.rst`, `Documentation/concepts/background/tpm.rst` | The background of the xattr and TPM patches |
| `Documentation/security/threat-model.rst` | Assumption A3 lists every carried change and the checks that test it; the `Enforced at` field of a fact box names each program, which `.github/scripts/check-docs.sh` requires; the prose names patches by number |
| `Documentation/start/faq.rst` | "Which kernel does a target need?" counts the patches |
| `Documentation/contribute/arch-support.rst` | The "Kernel project patch set" row, per architecture |
| `AGENTS.md`, `.agents/skills/` | Patches named by number |
| `util/kernel_abi.c`, `testing/unit/kernel_abi.c` | A check that hard-codes a carried hook |

## Dropping it

- `kernel-patches.rst`: its row and section go. A change a target still
  needs on an older tree stays as a sentence naming the upstream commit,
  as the x86 ftrace fix `31ac959c915c` does there.
- `system-requirements.rst`: its "Kernel source" row becomes
  "Upstream commit `<12-hex>`", with the subject, why shirudo needs it
  and which trees predate it and need it applied.
- `kernel-interfaces.rst`: the commit joins "Kernel baseline" with its
  subject and first release, or `bpf-next`, and leaves the paragraph of
  what bpf-next lacks.
- `threat-model.rst`: the change leaves A3's "Upstream has none of
  these".

## Moving a pin

| File | What names the pin | Changes with |
|---|---|---|
| `testing/kernel/bpf-next.commit` | The bpf-next commit | The pin |
| `Documentation/internals/kernel-patches.rst` | The commit "In bpf-next" was checked at | The pin |
| `testing/vm/kernel-artifact.sh` | `PINNED_RUN_ID`, `PINNED_AMD64_SHA256`, `PINNED_ARM64_SHA256` | The artifact pin |
| `Documentation/operate/plan/system-requirements.rst` | "The test suite runs bpf-next commit", and the release the test kernel reports under "Target kernel" | The artifact pin |

## The configuration

| File | What it holds |
|---|---|
| `testing/kernel/kernel-ci.conf`, `kernel-ci.<arch>.conf` | The option, under a comment that says why the test kernel needs it |
| `Documentation/operate/plan/system-requirements.rst` | "Kernel configuration" for an option shirudo needs, with the pre-flight check that finds it missing; "Attach points for upatches" for one an attach kind needs |
| `Documentation/operate/plan/hardening.rst` | An option the trust model assumes beyond the requirements |

## Check the set

Every patch has its section in `kernel-patches.rst`, and every hook a
patch adds has a program:

```sh
for p in testing/kernel/patches/*.patch; do
	p=${p##*/}
	grep -qF "$p" Documentation/internals/kernel-patches.rst || echo "undocumented $p"
done
for h in $(sed -n 's/^+LSM_HOOK([^,]*, [^,]*, \([a-z_]*\),.*/\1/p' testing/kernel/patches/*.patch); do
	git grep -qE "SEC\(\"lsm(\.s)?/$h\"\)" -- bpf upatches || echo "unused hook $h"
done
```

`kernel-patches.rst` lists the changes shirudo needs, so a patch no
program uses has no place there: report it to the user rather than
document it as needed or leave it unexplained.
