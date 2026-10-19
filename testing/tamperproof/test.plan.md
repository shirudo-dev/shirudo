# Tamperproof test plan

This matrix records coverage reviewed on 2026-10-17. Update the status and
test reference when a case is implemented or re-reviewed. “Covered” means an
assertion exists in the named test; it does not mean the test was run during
this review.

## Priority finding

**Resolved bypass: root could invoke a pinned serializer with
`BPF_PROG_TEST_RUN`.** Kernel-obs serializers are pinned signed syscall
programs. A non-PEEK serializer context can flip arena buffers and clear
drained state, allowing a root caller to drain observations without a
writable map FD. The LSM now restricts userspace `BPF_PROG_TEST_RUN` to
Shirudo's recorded executable; verified kernel-context loader calls remain
allowed. `t1130-map-lockdown.sh` asserts the denial and then
checks that Shirudo can still export the pre-existing Python exec record.

## Coverage matrix

| ID | Attack or policy case | Status | Existing test | Planned assertion or notes |
|---|---|---|---|---|
| TP-01 | Unsigned userspace `BPF_PROG_LOAD` | Covered | `t1110-lsm-deny.sh`; baseline also in `t1113-mount-lockdown.sh` | Keep EACCES denial assertion. |
| TP-02 | Foreign-signed upatch, signer absent from trusted keyring | Covered | `t1105-siggate.sh` | Keep rejection assertion. |
| TP-03 | Valid signature presented through caller-selected, non-Shirudo keyring | Covered | `t1112-prog-load-keyring-gate.sh` | Keep assertion that distinguishes policy denial from signature failure. |
| TP-04 | Replace the named Shirudo keyring with a same-named keyring | Covered | `t1106-keyring-swap.sh` | Keep status mismatch and load refusal checks; this destructive test runs last. |
| TP-05 | Add a key to the sealed BPF keyring | Covered | `t1121-bpf-keyring.sh` | Keep sealing denial and enrollment checks. |
| TP-06 | Unlink, clear, revoke, invalidate, re-permission, timeout, or link a key in the anchor | Covered | `t1125-key-permission.sh` | Keep per-operation denial assertions and status check. |
| TP-07 | Root modifies a labelled file under `/var/lib/shirudo` or changes its xattr | Covered | `t1101-seal.sh` | Keep write and xattr denial assertions. |
| TP-08 | Direct or lazy unmount, remount, or mount over private bpffs | Covered | `t1113-mount-lockdown.sh` | Keep mountpoint and enforcement-survival checks. |
| TP-09 | Obtain writable serializer-array or arena FD by pinned path | Covered | `t1130-map-lockdown.sh` | Current test covers `shirudo_ser` and `obs_i_arena`. |
| TP-10 | Obtain writable map FD by map ID | Covered | `t1130-map-lockdown.sh` | Current test covers both maps. |
| TP-11 | Read-only map FD access as a positive control | Covered | `t1130-map-lockdown.sh` | Preserve both path and map-ID read-only checks. |
| TP-12 | Update serializer map or freeze serializer/arena map directly | Covered | `t1130-map-lockdown.sh` | Current test attempts update on serializer array and freeze on both. |
| TP-13 | Writable mmap of arena | Covered | `t1130-map-lockdown.sh` | Preserve denial check. |
| TP-14 | Invoke pinned serializer with destructive `BPF_PROG_TEST_RUN` context | Covered | `t1130-map-lockdown.sh` | Root receives `EACCES`; Shirudo export still succeeds and contains the Python exec record created before the attempt. |
| TP-15 | Delete map element; update/delete batch; lookup-and-delete variants | Not covered | None | Add raw-syscall denial cases for each applicable command. Policy default-denies them, but that behavior is not asserted. |
| TP-16 | Create a BPF map from a non-Shirudo executable | Not covered | None in tamperproof | Add direct negative test for `BPF_MAP_CREATE`; cover authorized Shirudo loader creation as positive control. |
| TP-17 | Create links or pin existing objects from root | Not covered | None | `BPF_LINK_CREATE` and `BPF_OBJ_PIN` are allowed. Test whether root can create an unwanted attachment or pin and whether the resulting object affects enforcement/state. |
| TP-18 | Detach/update links or attach/detach programs from root | Not covered | None | Add negative raw-syscall cases for `BPF_LINK_DETACH`, `BPF_LINK_UPDATE`, `BPF_PROG_ATTACH`, and `BPF_PROG_DETACH`. |
| TP-19 | Root assigns Shirudo's executable identity using `PR_SET_MM` | Covered | `t1131-pr-set-mm-identity.sh` and `t1131-pr-set-mm-identity.py` | Requires `CAP_SYS_RESOURCE`; verify both `PR_SET_MM_EXE_FILE` and `PR_SET_MM_MAP` are denied to non-Shirudo callers. |
| TP-20 | Obtain or transfer Shirudo's open map FDs via `/proc/<pid>/fd`, `pidfd_getfd`, or `SCM_RIGHTS` | Not covered | None | Test each applicable acquisition/transfer route and verify a received FD cannot be used to mutate protected maps. |
| TP-21 | Concurrent or repeated serializer invocation changes/loses records | Not covered | None | Add after TP-14 policy fix; exercise repeated and concurrent export attempts and verify record integrity. |
| TP-22 | Root puts the public seal label on a file, or runs a binary a mounted file system labels, and then writes, renames, unlinks or relabels a labelled file | Covered | `t1132-seal-scratch.sh` | Only Shirudo may set the label, and the seal admits the executable `init` recorded, not one that carries the label. A failure is a bypass of the seal. |

## Review notes

- The default-deny branch in `bpf/bpf2.c` appears to reject several
  untested map mutation and link teardown commands. Treat that as policy
  implementation evidence, not test coverage.
- `t1130-map-lockdown.sh` proves direct writable-FD, update, freeze, and
  mmap paths for the selected maps. It does not prove all indirect ways of
  invoking signed code that mutates those maps.
- Run the target suite after implementing the open cases; this review was a
  source and test inspection, not a test execution.
