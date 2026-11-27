---
name: end2end-tests
description: Writes shirudo's end-to-end tests in testing/end2end/, the t90?? self-tests that run first on the host, the t91?? tests node A runs, and the host tests t9109 to t9114 that end2end/host.sh runs against fresh nodes. Covers host.sh and its rounds, node-lib.sh (node_wait, node_sh b and edge), pipeline-lib.sh, the operator VM and operator.sh, the node roles and their config images, the registry and the keepalive backend, wiring a test into the run and into t1007, what the host needs, and the logs to read. Use when adding or changing an end-to-end test, a step of host.sh or operator.sh, or what the nodes are prepared with.
paths:
  - "testing/end2end/**"
---

# End-to-end tests

The end2end tier shows a flow that crosses the operator, an OCI
registry, targets and the keepalive backend, which no lower tier can:
delivery, the keepalive pipeline, a tree's segments, a shield rolled out
and back. It is the costliest tier: a run builds the operator package
in a VM and boots up to five targets. A single command or hook goes in
a family, a function in a unit suite: "Choose a tier" in the `testing`
skill.

`Documentation/contribute/testing/testing.rst`, from "Run the
end-to-end tests" through "An application sandboxed and released", is
the reference for what the run does, with Figure 1 for its order. This
skill adds how to write a test into it.

## The run

`make -C testing end2end` runs the `t90??` tests of `testing/end2end/`
on the host, builds the bundle, and runs `testing/end2end/host.sh`. That
starts the containers and the operator VM, which runs `host.sh` again
with its own name: `operator.sh publish` builds and publishes, node B
boots, node A runs its tests, `operator.sh verify` checks node A's
evidence. Then host.sh runs the host tests in rounds, each on fresh
nodes. `<name>` below is `end2end-<pid>`, or `VM_NAME` when set.

| Test | Runs | Sources | Started by |
|---|---|---|---|
| `t90??`, as `t9001` | on the host, before any VM | `test-lib.sh` | `run-tests.sh end2end` |
| `t9101` to `t9107` | as root in node A, in number order, over SSH from the host | `integration-lib.sh`, `target_guard` | `run-target-tests.sh end2end` |
| `t9109` to `t9114` | on the host, as the user who runs make, root in CI | `test-lib.sh`, `vm/stack-lib.sh`, `end2end/node-lib.sh`, `end2end/pipeline-lib.sh` | `host_test` in `host.sh`, in the order it names them |

| Node | VM | Role | When |
|---|---|---|---|
| operator | `<name>-operator` | no TPM, no shirudo kernel arguments, the only VM with the signing key | until node A's evidence is verified |
| node A | `<name>-end2end` | `config-end2end`, `role=edge`, activated by `t9105` | beside node B |
| node B | `<name>-end2end-b` | `config-core`, `role=core` | through round 1 |
| edge node | `<name>-end2end-edge` | `config-edge`, `role=edge` | round 1: `t9109`, `t9110`, `t9112` |
| second pair | `<name>-2-end2end-edge`, `<name>-2-end2end-b` | as above | round 2: `t9111` |
| third edge node | `<name>-3-end2end-edge` | `role=edge` | round 3, x86-64 only: `t9113` |
| fourth edge node | `<name>-4-end2end-edge` | `role=edge` | round 4: `t9114` |

The nodes beside node A boot in node mode (`make -C testing
vm-node-end2end END2END_NODE=b|edge`): prepared like node A, with their
config image active, but they run no tests and start no timers. A test
starts what it needs (`unit_ok edge shirudo-bpm-tree-sync.service`,
`shirudo-keepalive.service`). Each round after the first boots fresh
nodes and a registry started again without a volume (`second_pair`,
`lone_node`); the backend stays the same for every round.

What runs on the host:

| Service | Address |
|---|---|
| Registry, TLS from the throwaway CA `$E2E/ca.pem` | `127.0.0.1:15443`; the operator VM and node A name it `registry.test:15443` |
| Collector and ClickHouse for node A's exports | `https://127.0.0.1:14318`, `http://127.0.0.1:18123` |
| Keepalive backend: collector and ClickHouse | `https://127.0.0.1:14320`, `http://127.0.0.1:18125` |

The containers are named `shirudo-end2end-*` (`STACK_NAME`). The guests
reach the host as `10.0.2.2`. A tree names each package by the address
it was appended through, so a node that syncs a tree appended at
`127.0.0.1:15443` first runs `node_reach`, which starts
`end2end/tcp_forward.py` in it.

## Write a host test

Most tests of the tier are host tests: the host holds the operator key,
the registry and the backend, and reaches every node.

1. Number it after the last `t91??`, checked as for any test (the
   `functional-tests` skill, "Place and number it"); the order it runs
   in is where `host.sh` names it.
2. Start from `t9113-shield-rollout.sh`. Its header says that `host.sh`
   runs it, after which test, against which nodes. It changes to
   `testing/`, sources `test-lib.sh`, and refuses to run without the
   run around it:

   ```sh
   [ -n "${END2END_BACKEND-}" ] && [ -n "${END2END_KEYS-}" ] ||
   	test_skip_all "end2end/host.sh runs it after t9111, with a keepalive backend"
   ```

   then sources `./vm/stack-lib.sh`, `./end2end/node-lib.sh` and
   `./end2end/pipeline-lib.sh`, and waits with `node_wait edge 0`.
   `host_test` fails a test that skips (`<number> was skipped`), so each
   `test_skip_all` there marks a broken run, never a result.
3. Set what `pipeline-lib.sh` reads before calling it: `W`, `CHECKS`,
   `STATE`, `RUNTIME`, `E2E`, `STACK_NAME`, `TREE_ID` and `WINDOW` where
   used, and `S`, `KEYS`, `BACKEND`, `REGISTRY` and `TREE` for
   `tree_append_pushed`, `tree_ingest`, `sync_to` and `head_report`.
4. Act through the libraries rather than open-coding SSH, SQL or
   registry calls:
   - `node-lib.sh`: `node_wait <node> [<seconds>]`, `node_sh <node>
     <command line>` with the test's standard input and output,
     `node_builder_name <node> ak|ek`. `host_test` sets `NODES_DIR` and
     `NODES_HOST` for it.
   - `pipeline-lib.sh`: `on` (`node_sh` with no input), `unit_ok`,
     `node_reach`; `ch`, `ch_wait`, `ch_cmp` and `refresh` against the
     backend's ClickHouse; `node_view`, `view`, `ak_record`, `ak`,
     `latest_cmp`, `history_cmp`, `status_log` and `status_cmp` for a
     node's records against the backend's rows; `registry_mark` and
     `requests` to read what the registry served between two marks;
     `manifest_status`, `tree_append_pushed`, `tree_ingest`, `sync_to`
     and `head_report` for a package rolled out to the edge node.
   - `testing/vm/stack-lib.sh`: `stack_backend_schema`,
     `stack_backend_client`, `stack_oci_log`.
5. A test that needs an empty backend drops and loads it again, as the
   case `the backend starts empty` of `t9113` does; one that needs a
   tree from scratch checks that the registry holds none
   (`manifest_status ... = 404`).
6. Build what it publishes on the host: a Beefile under
   `testing/fixtures/pipeline/<package>/` built with `"$S" bpm build`
   (`t9109` builds `xfs-fix`), or a package published with
   `tools/put-shields` (`t9113`, `t9114`). What needs a JDK the operator
   VM builds (`build_shield_jars` in `operator.sh`) and `host.sh` copies
   to `$E2E/shield/`.
7. Wire it into the run, all in the same commit:
   - `host_test t91<NN>-<what>` in `host.sh`, in the round whose nodes it
     needs. A test that needs nodes that ran nothing gets a round of its
     own, `lone_node -<n> <ordinal>` before it and `node_down edge ""`
     and `node_clean edge` after, as `t9114`'s round has. Update the
     header comment of `host.sh`, which lists the rounds.
   - The file in the `case` of `testing/run-target-tests.sh` that
     leaves the host tests out, or node A runs it.
   - The case `the runners split the tests by number` of
     `testing/functional/build/t1007-test-vm-cli.sh`: a `test -e` of
     the file, the `grep -Fqx` of its `host_test` line (with the tab
     when the line is indented, as `t9113`'s), and of the
     `run-target-tests.sh` line.
   - `testing.rst`: the sentence that lists the host tests in their
     order, a section like "An application sandboxed and released",
     and the figure, `Documentation/figures/contribute-end2end-run.tex`
     with its SVG, when a round is added (the `docs` skill); its row in
     `test-coverage.rst` under ``end2end`` (9).

## Write a node A test

Node A is one VM for its whole suite, so a test finds what earlier ones
loaded and activated: `t9105` activates `config-end2end` and syncs the
operator's tree, `t9106` writes the evidence that `operator.sh verify`
checks. A test there:

- sources `integration-lib.sh`, calls `target_guard`, and never skips
  as a whole (`run-target-tests.sh` fails it; `t9107` without
  `build/test-vm/end2end/backend-tree.digest` is the runner's one
  exception);
- reads `$PWD/../build/test-vm/end2end/` (`ca.pem`, `nonce`) through the
  read-only checkout and writes what the host reads after into
  `/mnt/shirudo-out/end2end/`, `result/end2end/` of node A's VM;
- uses `end2end/kernel-obs-lib.sh` for a `kernel-obs` scenario, as
  `t9101` does;
- gets a package of its own from `operator.sh`: a `publish_<x>`
  function called from `publish()`, which pushes to
  `registry.test:15443` and appends to `shirudo/end2end-tree` with
  `role=edge`, and a check in `verify()` that the evidence names it.

## What the host needs

Everything a VM goal needs (the `testing` skill, "Before a VM goal" and
"Run unconfined"), and also: `docker`, which `host.sh` requires;
tpm2-tools, swtpm-tools, the swtpm TCTI `libtss2-tcti-swtpm0t64` and
`openssl` for the nodes' vTPM builder; network the first time, for the
operator VM's image (clang 23 from apt.llvm.org, a JDK);
`TEST_VM_HOST_PRIVATE_DIR` outside the checkout; and the memory of
three guests at once, about 10 GiB with the defaults, plus five
containers. `make -C testing end2end` builds the quote checker
`host.sh` needs. With `VM=0` only the `t90??` tests run.

## Run and read

1. Check what runs without a VM: `make -C testing end2end VM=0`,
   `shellcheck` on the files changed, as the `shell` skill runs it, and
   after wiring `make -C testing functional/build VM=0
   TEST_FILTER='^t1007-'`.
2. Run the whole tier; no test of it runs alone. `TEST_FILTER` reaches
   node A's runner, where it would leave out what later steps need,
   and `host.sh` runs every host test whatever it says.

   ```sh
   make -C testing end2end
   ```

3. Read the result. The `end2end:` lines say which step ran last.
   - `<number> failed; see build/test-vm/end2end/<number>.log` or `was
     skipped`: a host test. Its TAP is in that log.
   - `host.sh failed with status <n>`: the operator VM's serve command,
     that is the publication, node A or the verification. The
     `end2end operator:` lines say which step; the operator's
     `build/test-vm/vms/<name>-operator/result/operator-build.log` and
     `result/end2end/` hold its build and what it published.
   - node A's TAP is in `build/test-vm/vms/<name>-end2end/result/guest.log`;
     `the SSH session that ran the target tests failed` is the SSH
     channel, not a test.
   - `... did not boot; see build/test-vm/end2end/node-<b|edge><round>.log`
     (`node-edge-3.log` for round 3): the node's boot, with its state in
     `build/test-vm/vms/<name><round>-end2end-<b|edge>/`.
   - `status_cmp` prints each node's backend log, its records' tamper
     arrays and its counters when `node_status` differs.
4. Fix and run the tier again. While it runs, `make -C testing vm-ssh
   VM_NAME=<name>-operator` or `<name>-end2end` opens a shell; never
   stop, clean or reuse the run's VMs. A `pkill -f <pattern>` inside a
   `node_sh` command line also kills the remote shell that carries the
   pattern: write it as `pkill -f '[p]attern'`, which that shell's
   command line does not match.
