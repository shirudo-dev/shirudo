# Building Shirudo images

`shirudo-gen-image` runs on the operator. It uses `mkfs.ext4` from
`e2fsprogs`, then calls the operator-only `shirudo-build` helper to construct
and sign the dm-verity tree. The helper invokes `veritysetup format` from
`cryptsetup-bin` (Debian/Ubuntu) or `cryptsetup` (Fedora/RHEL), and the
generator verifies the result with `veritysetup verify`. Targets use kernel
APIs and do not need these programs. Offline `shirudo image verify` also
requires the operator helper and `veritysetup`; it checks the signed
root signature and exact file sizes before verifying the retained data and
hash files.

The source directory becomes the image root. A config source contains
`etc/shirudo/` and additional `keys/trusted/` and `keys/revoked/` directories;
bootstrap settings and the initial BPF certificate belong in the executable
image. Keep private operator keys outside both images. Config symlinks and
special files are refused.

```sh
tools/gen-image/shirudo-gen-image --source config-root --output config \
    --keys-dir operator-keys --builder tools/shirudo-build/shirudo-build
```

Use `--kind runtime` for the executable image. The deployment must arrange
for the dynamic loader and libraries to come from that image too. The host
root filesystem is not replaced.

The four outputs are `config.img`, `config.verity`, `config.roothash` and
`config.p7s`. Download the complete set before requesting activation. The
printed SHA-256 root is also suitable for authenticating a runtime image
from the UKI. Existing outputs are never overwritten.

The standard verity superblock occupies the first 4096-byte block; the
hash tree starts at block one. Format 1, SHA-256, 4096-byte blocks and a
32-byte salt are fixed. The `.roothash` file contains exactly 64 lowercase
ASCII hex bytes with no newline. The detached ML-DSA-87 CMS signature covers
those root bytes. `--kind` is a packaging hint only. The runtime must match
the exact UKI root, regardless of a config signature; config images never
grant executable authority.

The trusted initrd enrolls the config certificate into the kernel's
`.dm-verity` keyring and seals it before host startup. Boot requires
`dm_verity.keyring_unsealed=1`. Kernel built-in dm-verity trust remains
accepted. After interrupted config activation, Shirudo refuses further
updates and attestation while the node keeps running. The operator chooses
when to reboot; Shirudo never reboots automatically and has no same-boot
recovery command.

For a target binary linked against glibc, `shirudo-gen-runtime` packages the
ELF interpreter and its complete library closure without modifying the
binary. Use a trusted, native target binary on the operator. It prints the
explicit loader invocation to use after mounting the runtime image. The
invocation disables the host loader cache and supplies only library paths
inside the image. The LSM also denies executable mappings from outside the
approved image, so missing libraries fail instead of falling back to the host.

```sh
tools/gen-image/shirudo-gen-runtime --binary ./shirudo-target \
    --bootstrap-conf bootstrap.conf --cert initial-bpf-cert.der \
    --config-cert config-signing-cert.der --output runtime \
    --keys-dir operator-keys --builder tools/shirudo-build/shirudo-build
```

The packaged config-verification certificate is
`/run/shirudo/runtime/etc/shirudo/config-cert.der`; use that absolute path
for `config.verification_key` in the bootstrap configuration. The initial
BPF certificate is `keys/cert.der` inside the image. Runtime images have no
shell or debugger unless the operator explicitly supplies one.

The generated service content is kept in `runtime-service.conf.in` beside
the scripts. Keep that template with the scripts when copying this directory.
The generator substitutes only the interpreter and library paths.

Pass `--unit-output runtime-service.conf` to generate a systemd drop-in for
the root phase. Install it as
`/etc/systemd/system/shirudo.service.d/verity.conf`. It clears the writable
`init.env` file and starts the loader and Shirudo binary from the runtime
image. Generate the initrd with `shirudo-gen-initrd --bootstrap-conf <file>`;
this bootstrap file carries `runtime.image` and `runtime.root_hash`, while
the file inside the runtime image carries config verification settings.
The initrd's first invocation still uses its authenticated bootstrap binary.
The state filesystem at `/sysroot/var/lib/shirudo` must be mounted writable
in the initrd for durable pending config selection; the legacy mode keeps
its existing read-only bind. Image mode is bootstrapped exclusively by the
trusted initrd before untrusted workloads start. It does not migrate a
running unprotected system: pre-existing writable mappings and held file
descriptors would fall outside that bootstrap guarantee. State entries must
be regular files or directories; symlinks, special files and failed labels
stop initialization. After attaching guards, initialization re-applies the
state labels to populate the inode protection cache.

`--extra-binary <trusted-ELF>` adds a deliberately trusted executable and its
library dependencies, for example a test probe. Every executable
in this image has equal authority; omit this option in deployment unless
that additional authority is intended.
