# Rebuilding exported kernel-CVE upatches

This bundle contains the generated `kernel-cve.bee` package definition, combined manifest, the shared `vmlinux.h`, BPF C sources, and (for entries that have them) signed payloads, object files, logs, certificates, and per-record JSON metadata.

From a compatible Shirudo checkout, copy this directory beneath `upatches/` and run the normal Jbrust shield builder for `kernel-cve` with the destination project's signer. Replace the package signer with the destination project's signer when rebuilding the signed entry.

The Beefile entries use recoverable `.bpf.c` sources. All sources include `vmlinux.h`; the single copy at `kernel-cve/vmlinux.h` is found because the shield builder runs with `kernel-cve/` as its working directory. Do not add per-entry copies under `sources/*/observability/`.
