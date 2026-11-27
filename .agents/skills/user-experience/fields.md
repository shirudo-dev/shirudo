# Field names

The names of the fields that more than one command shows, in text, in a
table and in JSON. A field gets one row; a command that shows it uses
the row's names. The last column lists the spellings the tree also
carries for the same field, which a change copies nowhere and a change
to that command brings in line.

- [Upatches](#upatches)
- [Certificates and keys](#certificates-and-keys)
- [Measurement](#measurement)
- [Packages](#packages)
- [Results](#results)

## Upatches

| Field | Label | Column | JSON key | Shown by | Also spelled |
|---|---|---|---|---|---|
| Name of the upatch | `Name:` | NAME | `name` | `upatch info`, `upatch list`, `upatch get`, `status` | |
| Name under the signature | `Name:` under `Signed sections:` | | `signed_name` | `upatch info` | |
| Load or unload | `Type:` | TYPE | `type`, `load` or `unload` | `upatch info`, `upatch list` | `LOAD`, `UNLOAD-directive` in `upatch info` text |
| Payload kind | `Payload type:` | KIND, as TYPE is taken | `payload_type`, `bpf` or `java` | `upatch info`, `upatch list` | |
| Payload digest | `Payload sha256:` | PAYLOAD | `payload_sha256` | `upatch info`, `upatch get`, `upatch list` | |
| Payload an unload names | `Unload payload:` | | `unload_payload_sha256` | `upatch info` | |
| Path of the file | `Path:` | | `path` | `upatch info`, `keys` | `File:` in `upatch info` |
| Size of the file | `File size:` | | `file_size` | `upatch info` | |
| Whether it is loaded | `Loaded:` | LOADED | `loaded` | `upatch list` | |
| Whether it is archived | `Archived:` | | `archived` | `upatch list` | |
| Where a program attaches | `Location:` | LOCATION | `location` | `upatch get`, `status` | |
| Runs the kernel skipped | `Missed runs:` | MISSED | `missed_runs` | `upatch get`, `status` | |
| Kernel program ID | `Program ID:` | | `program_id` | `upatch get` | `prog_id` in `upatch get` JSON |
| Upatch a map belongs to | `Upatch:` | UPATCH | `upatch` | `upatch map` | `Name:` in the map dump, whose JSON `name` is the map |
| Name of a map | `Map:` | MAP | `name` in a map object | `upatch map`, `upatch get` | |
| Capacity of a map | `Max entries:` | MAX ENTRIES | `max_entries` | `upatch map` | ENTRIES with `max=<n>` cells in the map list |

## Certificates and keys

| Field | Label | Column | JSON key | Shown by | Also spelled |
|---|---|---|---|---|---|
| SHA-256 of the certificate's SPKI | `Fingerprint:` | FINGERPRINT | `fingerprint` | `keys`, `status`, `bpm key fingerprint`, `bpm key list`, `keys vouch`, `keys revoke` | `SPKI fingerprint:` and `spki_fingerprint` in `keys` cert and signing key; `spki_sha256_fingerprint` in the package format |
| SHA-256 of the certificate's DER | `Certificate sha256:` | | `cert_sha256` | `keys`, `status`, `init`, `keys revoke`, eventlog | `Fingerprint:` and `fingerprint` in `keys` cert; `sha256` in `keys` trusted set and `status` |
| Subject | `Subject:` | | `subject` | `keys`, `status` | |
| Issuer | `Issuer:` | | `issuer` | `keys` | |
| Key algorithm | `Algorithm:` | | `algorithm` | `keys`, `status` | `Public key:` in `keys` cert |
| Start of validity | `Not before:` | | `not_before` | `keys`, `status` | `Issued:` in `keys`, `issued` in `status` text |
| Keyring serial | `Serial:` | | `serial` | `keys`, `status` | `keyring_serial` in a `status` section |
| Serial `init` froze | `Frozen serial:` | | `frozen_serial` | `keys`, `status` | `serial_pinned`, `keyring_serial_pinned` in `status` |
| Key in a keyring | `Serial:`, `Description:` | SERIAL, DESCRIPTION | `serial`, `description` | `keys`, `status` | `key_serial`, `key_description` in `status`; `serial=` cells in `keys` text |

## Measurement

| Field | Label | Column | JSON key | Shown by | Also spelled |
|---|---|---|---|---|---|
| Digest of the enrolled set | `Set digest:` | | `set_digest` | `attest predict`, `init`, `status` eventlog | `set_sha256` in the keepalive |
| Value of the measurement register | `Chain:` | | `chain` | `status`, `--expect-chain` | `tpm.chain_after` in the operation report, `register.value` in evidence, `register %s` in messages |
| Register after `init` | `Register at boot:` | | `register_at_boot` | `attest predict` | text `register_at_boot:` |
| Digest of an event | `Digest:` | DIGEST | `digest` | `status` eventlog | |
| Name of the register's NV index | `NV name:` | | `nv_name` | `status` | `Register name:` in `status` text |
| Root hash of the active config | `Root hash:` | | `root_hash` | `image status`, `status` | `Config root hash:` in `image status`; `config_root` in the keepalive |
| TPM resets so far | `Reset count:` | | `reset_count` | `image status`, `status` | `TPM reset count:` in `image status` |

## Packages

| Field | Label | Column | JSON key | Shown by | Also spelled |
|---|---|---|---|---|---|
| Package name | `Name:` | NAME | `name` | `bpm list` | |
| Package version | `Version:` | VERSION | `version` | `bpm list` | |
| Where it came from | `Source:` | SOURCE | `source` | `bpm list` | |
| Manifest digest of a package | | | `manifest_digest` | `bpm tree show`, the signed index | the options `--package-digest` and `--base-digest` take it |

## Results

| Field | Label | Column | JSON key | Shown by | Also spelled |
|---|---|---|---|---|---|
| Outcome of a check | `OK`, `FAIL`, `NOTE` marks | | `result`, `ok`, `fail` or `note` | `attest verify`, `attest challenge`, `init --check-only` | `ok` as a boolean in `init --check-only` |
| Outcome of the whole run | `verdict:` | | `verdict`, `ok` or `fail` | `attest verify`, `attest challenge` | `N of M passed` in `init --check-only` |
| Verdict on the host | `Status:` | | `status` | `status` | `verdict` in the keepalive |
| State of a condition | | STATUS | `status`, `OK`, `WARN` or `ALERT` | `status` | |
| Outcome of an operation | | | `result`, `ok` or `failed` | `--report` of `upatch load`, `unload`, `reconcile` | none in the `bpm tree sync` report |
| Format version | | | `schema` | every JSON document | missing in `image status` |
