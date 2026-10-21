# Upatch infrastructure test plan

This matrix records coverage reviewed on 2026-10-19. Update the status and
test reference when a case is implemented or re-reviewed. “Covered” means an
assertion exists in the named test; it does not mean the test was run during
this review.

## Coverage matrix

| ID | Mechanism case | Status | Existing test | Planned assertion or notes |
|---|---|---|---|---|
| UI-01 | Operator signing accepts ML-DSA-87 and rejects RSA | Covered | `t0029-mldsa-sign.sh` | Keep the algorithm rejection, CMS structure, size, signed-content verification and tamper rejection checks. |
| UI-02 | Malformed `.upatch` files fail cleanly | Covered | `t0004-upatch-parse.sh` | Empty, truncated, random, bogus-magic, missing-file and directory inputs must fail without a signal. |
| UI-03 | Reader validates file size, structured header and section bounds | Covered | `t0004-upatch-parse.sh` | Oversized file, unsupported version, both reserved words, zero required lengths, header overlap, and out-of-file or overflowing ranges fail cleanly; a structured control parses. |
| UI-04 | Valid signed decoder metadata is reported and executed | Covered | `t0005-upatch-decoders.sh` | Keep metadata fields, JSON output, OTLP value conversion, instruction and memory limits, and invalid UTF-8 checks. |
| UI-05 | Malformed decoder trailer and source ranges are handled as absent | Covered | `t0005-upatch-decoders.sh` | Malformed trailer, offset, entry count, source range, and unterminated fixed string leave offline inspection successful with no decoders reported. |
| UI-06 | Supported attachment forms produce the expected build metadata | Covered | `t0009-cgroup-skb-metadata.sh`, `t0009-uprobe-multi-metadata.sh`, `t0011-override-metadata.sh`, `t0012-netfilter-metadata.sh` | Preserve checks for cgroup ingress/egress, uprobe.multi targets, kprobe override, fmod_ret, and netfilter metadata. |
| UI-07 | Unsupported attachment sections fail with actionable build errors | Covered | `t0010-unsupported-network-sections.sh` | Preserve rejection checks for sk_skb, socket filters and generic cgroup skb sections. |
| UI-08 | Serializer metadata binds a serializer to its target map | Covered | `t0007-upatch-serializer-metadata.sh` | Keep the signed arena-tree artifact metadata check. |
| UI-09 | Builder rejects invalid serializer declarations | Covered | `t0007-upatch-serializer-metadata.sh` | Missing output map, missing or reserved target map, and duplicate serializer targets fail with the builder diagnostic. |
| UI-10 | Map type names and generic-read/serializer policy are stable | Covered | `t0006-upatch-map-types.sh` | Keep arena naming, arena serializer requirement, array generic-read, and skipped-type naming assertions. |
| UI-11 | Serializer ABI, invocation nonce, locking and paged JSON shape | Covered | `t0008-upatch-serializer-pages.sh` | The helper checks the serializer ABI and nonce validation, map-lock behavior, and a synthetic two-page JSON view. Keep the CLI path and NDJSON assertions. |
| UI-12 | Loaded arena serializer returns a complete multi-page snapshot | Covered | `t1133-upatch-arena-serializer.sh` | Load the signed arena-tree fixture; verify all three pages, cursor progression, all records, completion, and a serializer error result. |
| UI-13 | Target load archives and pins an upatch; matching unload removes it | Covered | `t1107-load-unload.sh`, `t1200-target-fixtures.sh` | Keep positive lifecycle checks for attachment, pin, archive and unload. |
| UI-14 | Target refuses unload on payload mismatch and load on version mismatch | Covered | `t1104-payload-mismatch.sh`, `t1103-version-gate.sh` | Keep the refusal categories and checks that a mismatched unload leaves the pin intact. |
| UI-15 | Target rejects an artifact signed by an untrusted key | Covered | `t1200-target-fixtures.sh` | Keep the foreign-signed fixture rejection and valid non-Shirudo keyring denial. |
| UI-16 | `upatch get` reads loaded source information from the kernel | Covered | `t1111-upatch-get.sh` | The current assertion checks that the loaded marker source appears in output. Detailed JSON and line-location assertions are not present. |
| UI-17 | uprobe.multi verifies target identity and attaches all matched offsets | Covered | `t1114-uprobe-multi.sh` | Keep build-ID mismatch refusal, target/function status, and execution of both matched functions. |
| UI-18 | `upatch map` emits detailed map JSON and appends NDJSON records | Covered | `t0008-upatch-serializer-pages.sh`, `otel/t1115-map-export-all.sh`, `t1200-target-fixtures.sh` | Keep output-path validation, schema and per-map JSON checks. This row covers the upatch map interface, not exporter transport. |
| UI-19 | Target executes a serializer and decodes its output | Covered | `otel/t1117-otel-serialized-metric.sh` | Keep the serialized-counter fixture assertions for decoded values and cumulative metric fields; generic exporter behavior is outside this matrix. |

## Review notes

- This plan covers the upatch artifact and loader mechanism, its build-time
  metadata, and the direct map, serializer and decoder support paths.
- It does not track behavior of particular upatch payloads or package/tree
  delivery and generic telemetry transport.
- The structured parser and decoder-metadata gaps correspond to validation
  rules in `Documentation/upatch-spec.rst`; policy text alone is not test
  coverage.
- `t1133-upatch-arena-serializer.sh` loads the arena-tree fixture and checks
  the real target serializer over its full three-page result and error path.
- `make -C testing test-op` and `make -C testing test-tgt` passed on
  2026-10-19, including the parser, decoder, metadata, tamper and target
  arena-serializer assertions listed above.
