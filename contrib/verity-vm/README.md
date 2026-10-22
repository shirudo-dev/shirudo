# VM image fixtures

The configs, service units and guest scripts used by the image tests live
here. The calling scripts copy these files and substitute the values named
between `@` characters in `.in` templates.

`seed-root.sh` installs the boot files in the initrd and `seed-images.sh`
installs the runtime and signed config fixtures. `install-guest.sh` finishes the manual VM setup.
The runtime service template used by the operator is kept separately in
`tools/gen-image/runtime-service.conf.in`.
