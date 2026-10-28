# OTEL test plan

## Scope

This plan records coverage for OpenTelemetry export across host-side serialization and transport, target map export, status keepalives, systemd/package wiring, and the shared TLS policy. Tests live primarily in `testing/otel/`; related coverage includes `testing/t0030-tls-policy.sh`, `testing/upatch/t0005-upatch-decoders.sh`, and `testing/fuzz/fuzz-otel.c`.

## Coverage

| Area | Checks |
| --- | --- |
| CLI and configuration | Invalid OTEL option combinations; map-export defaults, valid values, invalid values, bounds, unknown keys, tenant ID syntax, and duplicate handling. |
| Map classification and local rendering | Structural classification of unsigned per-CPU integer maps as metrics and other map categories as logs; aligned per-CPU strides in local JSON and OTLP log output. |
| OTLP payloads | Nested log body and map/upatch attributes; absent location; gauge and cumulative monotonic counter payloads; metric start time; selected logs/metrics paths and endpoint suffixing. |
| OTLP transport | JSON requests, decoded authorization, gzip, retry success, retryable status matrix (429/502/503/504), fatal statuses, retry exhaustion, partial rejection, zero-rejection partial success, malformed response, disconnect, timeout, delta/date `Retry-After` and cap, loopback cleartext policy, HTTPS verification and insecure override. |
| OTEL environment | Signal-specific endpoint, protocol, compression, and headers override generic values; explicit custom endpoints and base URL signal suffix behavior. |
| Payload limits | Decoded record and OTLP request accepted at and above a measured boundary, rejected one byte below, with no HTTP request for rejected payloads. Mock records decoded payload size after gzip. |
| Tenant handling | Header decoding and validation, configured tenant and CLI override on target mixed log/metric `--all`, and no tenant leakage into S3 PUT while applying it to the OTLP reference. |
| S3 export | Credential and bucket/region validation; path traversal and query rejection; escaped prefix; `AWS_DEFAULT_REGION` fallback; gzip snapshot, digest/checksum, SigV4, session token and metadata; compact reference; large serialized snapshot; retryable PUT status matrix (408/409/429/500/502/503/504), duplicate object, exhausted retries, reference retry without duplicate upload, and upload/reference failure ordering. |
| Status keepalive | Deterministic severity/body mapping for all documented statuses; status/version fields; no stdout output; JSON output retained with `--json --otel`; no implicit endpoint when none is configured. |
| Target map export | Detailed JSON records, JSON-lines append and I/O failure, mixed log/metric automatic export, CLI endpoint over config, and tenant propagation. |
| Target service and timer | Installed map-export service delivers decoder-backed maps; slow collector fixture checks the timer does not overlap an active export. |
| Serialized metrics | Two serializer pages, repeated peek, drain, subsequent empty interval, reload reset, and service export of decoder-backed cumulative metrics. |
| Services and packaging | Static service/timer ordering, conditions, environment file, command, cadence, install paths, operator exclusion, and Debian/RPM scriptlets. |
| TLS policy | `testing/t0030-tls-policy.sh` covers shared TLS policy; OTEL host tests independently check certificate verification and insecure mode where TLS prerequisites are available. |

## Remaining gaps

The suggested execution order has been implemented. Useful follow-up coverage remains:

1. Full endpoint precedence across CLI, signal-specific environment, generic environment, config, and defaults, plus separate metrics-signal precedence.
2. OTEL endpoint precedence for signal-specific CA, client certificate/key, timeout, and header edge cases such as malformed escapes, reserved names, and duplicate tenant sources.
3. Exact payload-schema assertions for every documented resource, scope, map attribute, metric name/kind combination, and multiple datapoints; broader empty/large/signed map fixtures.
4. Target export failure/drain behavior across timer intervals, timer-delivered keepalive integration, optional system fields, and service failure status reporting.
5. S3 `AWS_CA_BUNDLE` TLS verification, partial collector reference responses, and exact reference/snapshot size metadata assertions.
6. Explicit upper bound and malformed configuration tests for transport timeouts, response-buffer boundary cases, and compression-size semantics beyond the current decoded payload assertions.

These are coverage opportunities, not findings that the implementation is incorrect. Do not count prerequisite-skipped TLS or target tests as exercising their assertions.

## Test commands

Host coverage is selected by `testing/run-tests.sh` (`testing/otel/t0[0-9][0-9]-*.sh`). Target integration scripts `t1115`, `t1116`, and `t1117` require an initialized test VM and fixtures in `SHIRUDO_TEST_FIXTURES_DIR`. The shared TLS test is `testing/t0030-tls-policy.sh`. Run with the repository's documented `make -C testing test-op` and target harness when runtime validation is requested.
