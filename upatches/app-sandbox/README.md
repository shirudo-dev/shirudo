# app-sandbox

The `app-sandbox` package installs the `app-sandbox` upatch, which puts
applications in sandboxes. A sandbox restricts every task that executed
one of its files, and the tasks those start, in three things:

- what it executes: its own files and those of the policies it names;
- where it connects and sends: the networks it names;
- which files it creates, renames and opens for writing or truncates:
  none whose name matches a pattern it denies.

The package ships sandboxes for Apache httpd and PHP-FPM that keep a web
application from writing the PHP files it serves, from starting other
programs and from reaching beyond private networks: what an attacker
who found a hole in the application does first. Replace them with
sandboxes for your own applications.

Its tree entry names the PHP2Shell advisories, CVE-2026-109618 and
CVE-2026-109619, as `fixes`, so that a backend that reads the tree
counts a node that loaded the upatch as shielded against them. The
sandboxes do not close the hole in PHP: a request can still run the
attacker's code in the application. They keep that code from leaving a
PHP file behind, from running another program and from connecting out.
Upgrade PHP as well.

A sandbox restricts and never grants: a task in it keeps every limit it
had. It is not a boundary against root outside the sandbox, and a file
replaced after the load is a new file without the label, see "Limits".

## Define a sandbox

A sandbox has two parts. The `Beefile` gives it a name, a policy bit and
the executables that put a task in it, as a `[[upatches.policy]]` table
(see `Documentation/reference/formats/beefile.rst`):

```toml
[[upatches.policy]]
id = "apache"
bit = 0x1
paths = ["/usr/sbin/apache2", "/usr/sbin/httpd"]
```

The last component of a path may be a pattern, as in
`/usr/sbin/php-fpm*` for the PHP-FPM of any version: the target labels
every regular file of the directory that matches it.

`sandbox.toml` gives the rules of the sandbox of that name:

```toml
[networks]
localnet = ["127.0.0.0/8", "10.0.0.0/8", "::1/128"]

[sandbox.apache]
exec = ["apache-helpers"]
network = ["@localnet", "192.0.2.10/32"]

[sandbox.apache.deny]
create = ["*.php"]
rename = ["*.php"]
write = ["*.php"]
```

| Key | Without it | With it |
|---|---|---|
| `exec` | The task executes anything. | It executes only files labeled with its own policy or with one of the policy IDs listed, each a `[[upatches.policy]]` table of the Beefile. `exec = []` allows its own files alone. |
| `network` | The task connects anywhere. | It connects and sends only to the networks listed, IPv4 or IPv6 in CIDR form, or `@<name>` for a list of `[networks]`. An IPv4 network also covers its IPv4-mapped IPv6 form. It creates no raw and no packet socket. `network = []` allows no IP peer. |
| `deny.create` | | It creates no file, directory, device, symbolic link or hard link with a matching name. |
| `deny.rename` | | It renames no file from or to a matching name. |
| `deny.write` | | It opens no file with a matching name for writing and does not truncate one. |

A pattern is matched against the last component of the path. It is the
name itself, or holds one `*` for any run of bytes, and `?` for any one
byte, with at most 32 bytes on each side of the `*`.

A script is executed with its interpreter, and the kernel asks for
both: a sandbox with `exec` runs a script only when the script and its
interpreter are each labeled with a policy the sandbox allows.

The package holds up to 32 sandboxes with `exec`, 128 networks and 64
patterns. A task in two sandboxes, one that executed files of both, is
held to the rules of each.

`gen_policy.py` turns `sandbox.toml` into the `sandbox_policy` variable
of the upatch when `shirudo bpm build` runs, and fails the build for a
sandbox the Beefile declares no policy for, a network or a pattern it
cannot read and a table it does not know. Read back what a build holds
with:

```sh
shirudo bpm info data app-sandbox-<version>.bee upatches/app-sandbox.upatch
```

## Build and publish

Build in a directory that holds shirudo's BPF headers and a `vmlinux.h`
(see `Documentation/start/guides/publish-package.rst`):

```sh
shirudo bpm build upatches/app-sandbox --version 1.0.0 --keys-dir <keys>
shirudo bpm push app-sandbox-1.0.0.bee oci://<registry>/<namespace>/app-sandbox --keys-dir <keys>
shirudo bpm tree append app-sandbox-1.0.0.bee oci://<registry>/<tree> --keys-dir <keys>
```

The Beefile has a tree entry without a selector, with the advisories
above as its `fixes`, so every node that syncs the tree loads the
upatch; on a node without the applications it labels nothing and
restricts nothing. Add a selector to load it only where they run:

```toml
[upatches.tree.selector.labels]
role = ["web"]
```

`tools/put-shields`, and `make shields` with it, publishes the package
with the other shields of `upatches/`.

`--rodata-input sandbox=<file>` builds with other rules for the
policies of the Beefile, and `shirudo bpm config update` signs new rules
into a package already built, without compiling it again.

## What a load does

The load labels each path of the Beefile that exists on the target with
its policy bit, in the `security.bpf.shirudo.policy` xattr. shirudo
gives a task the bits of every file it executes, and its children
inherit them, so a task enters a sandbox at its next `execve()` of a
labeled file: restart the application after the first load. An unload
leaves the labels, which restrict nothing once the upatch is gone.

Every refusal is `EACCES`.

## Limits

- A path that does not exist at the load is not labeled, and a file
  that replaces a labeled one, as a package upgrade does, is a new file
  without the label, whether a path or a pattern named it. Load the upatch again after the application is
  installed or upgraded.
- The file rules name files, not their contents: a descriptor that was
  open for writing before the task entered the sandbox, or that another
  process passes to it, still writes.
- The network rules cover `connect()` and the address of `sendmsg()`
  and `sendto()` on IPv4 and IPv6 sockets. Other address families pass,
  and so does what a task receives or accepts.
- Root outside a sandbox can remove nothing of it, as only shirudo's
  runtime sets the label, but a task that root starts from an unlabeled
  file is in no sandbox.

## Kernels and cost

The programs keep no state of their own: they read the task's policy
bits and the rules, which never change after the load, so they are
right on every preemption model.

A task in no sandbox pays one task-storage lookup at each hook, and
none when it opens a file for reading. The hooks are the LSM hooks of
`execve()`, `connect()`, `sendmsg()`, `socket()`, the creation, linking
and renaming of a directory entry, an open for writing and a change of
size. A task in a sandbox pays a scan of the rules on top: at most 128
networks, or 64 patterns of at most 64 bytes.
