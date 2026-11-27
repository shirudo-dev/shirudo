# Bug classes that matter here

Contents:

- Parse before verify
- Checked is not used
- Signed, not bound
- Fail open
- Library misuse
- Error paths
- Leaks
- Use after free
- Logic errors
- Hook logic
- Measurement gaps
- State windows
- Sibling paths
- Self-report trusted
- Encoding ambiguity
- Bytes as strings
- Hook bypass
- Unattended availability
- Text and secrets
- Environment and exec
- Linked code

Hunt each class in both halves, the BPF programs and the userspace C,
and with the kernel source open: a checkout of the kernel the test VM
boots, which `testing/kernel/build-kernel.sh` builds with the carried
patch set. Neither half can be judged without it. For a hook,
read the callers of `security_<hook>()`, what each does with the return
value and what it holds while it calls; for a helper or kfunc, what it
returns, when it fails and whether it sleeps; for a system call, a
`bpf()` command or an ioctl shirudo makes, what its flags mean and which
errors come back; for the verifier, what it has proved and what it
leaves to the program. A statement about the kernel cites file and line
of that tree, as one about a guard does.

`testing/coccinelle` has rules for the mechanical shapes of several
classes below (`openssl_ret`, `errno_clobber`, `alloc_unchecked`,
`fd_leak`, `double_close`, `use_after_free`, `read_unterminated`,
`file_as_string`, `name_after_fd`, the `bpf_` rules): a clean
`check-coccinelle.sh` says those shapes are absent, not the class.

- **Parse before verify.** Anything read before its signature or digest
  is checked (`upatch info`, `bpm info`, manifests, indexes, the
  evidence on the verifier) gets the worst input: offsets, counts,
  integer overflow (`<shirudo/overflow.h>`), recursion, loops and output
  that grow with input.
- **Checked is not used.** The bytes verified differ from the bytes
  loaded or applied: reopened by path, read twice, a file root can
  rewrite after the check, a name resolved through a mount root built,
  a symbolic link in a directory of the path, which `O_NOFOLLOW` does
  not refuse. A check on a descriptor followed by a lookup of the same
  path by name (`realpath()`, `stat()`, `access()`) checks what the
  name leads to then, not what the descriptor was reached through: the
  walk goes one name at a time through descriptors, as
  `check_trusted()` and `seal_open_dir()` do. `open_trusted()` opens a
  name renamed over before its check again and checks each descriptor
  in full; a retry that kept anything from an earlier attempt would be
  this class.
- **Signed, not bound.** A signature covers bytes, not where they are
  used: content signed for another name, version, architecture,
  repository or generation, an index and a package from two
  publications, state brought back from an older copy, a decision that
  rests on the target's clock, which root sets. R1, R8, R14 and R16
  concede the replay of whole signed artifacts: look for the mix a
  check should have refused.
- **Fail open.** An error path that skips a check, a measurement or a
  refusal: label read errors beyond ENODATA and EOPNOTSUPP, a partial
  load, a retry where the design refuses (`tampered`), a default when a
  setting is missing, a short read taken for the whole.
- **Library misuse.** A call that breaks the contract of what it calls,
  in OpenSSL, libcurl, tpm2-tss, libelf, libbpf, zlib, LuaJIT or libc,
  or of a BPF helper or kfunc: a result not checked, or read by another
  library's convention (OpenSSL's 1, 0 and negative, a `TSS2_RC`, a
  `CURLcode`, libbpf's negative errno or NULL, zlib's `Z_STREAM_END`, a
  helper's NULL or negative), an object freed by the wrong owner or the
  wrong function, a buffer or length the callee reads differently, an
  option left at a default the design rules out, an error queue or
  `errno` read after another call overwrote it.
- **Error paths.** The paths tests take least. On every return after
  the first resource is taken, check that what was taken is released,
  what was changed is undone in reverse order, the lock is dropped, and
  the error reaches the caller without a later cleanup overwriting it.
  A partial write, a half-made pin directory or a temporary file left
  behind is state root can use, and a `ret` set and then lost is an
  operation reported as done.
- **Leaks.** Memory, and above all descriptors. A link, program or map
  descriptor that outlives its use keeps the object attached after its
  pin is gone (U17), a leaked secret is never cleared, and a leak per
  item of outside input ends in `EMFILE` or `ENOMEM` at a point the
  input chose. In BPF, what the verifier does not track: a map entry
  never deleted, arena memory never freed, storage that outlives its
  owner.
- **Use after free.** A pointer into a buffer that was freed, grown
  with `xreallocarray()` or handed to a library that owns it now, a
  field of a parsed document after its body is gone, a second free on
  an error path, a `__cleanup` that runs before the last use. In BPF, a
  map value used after its entry was deleted or replaced, a pointer
  kept across a call that sleeps or leaves the RCU read section, arena
  memory another run frees (the `bpf-concurrency` skill).
- **Logic errors.** The check that is there and wrong: an inverted or
  off-by-one condition, `<` for `<=`, the wrong variable after a copy,
  a `switch` whose default allows, a prefix compared where the whole
  must match, a mask a bit off, checks in an order that keeps the
  second from running, a hook that returns the wrong sign or returns
  before its check. No tool finds these: say from the threat model and
  the callers what the function must do, then read whether it does.
- **Hook logic.** In the programs of `bpf/`: a failed read, a helper
  error, storage that cannot be allocated or a bounded walk that gives
  up, taken as allow; a hook whose return the kernel ignores relied on
  to refuse; a decision on user memory the kernel reads again; a map
  the design takes as fixed that a program can still write
  (`BPF_F_RDONLY_PROG`); state shared by runs that interleave, as the
  `bpf-concurrency` skill describes.
- **Measurement gaps.** A state change without its register extend, in
  another order, without domain separation, outside the register lock,
  or a record the verifier folds that no digest covers.
- **State windows.** A control that holds in the running state and not
  around it: before `init` attaches the gates (T6), between a load's
  pins and its extend, with a config selection pending (T12), after a
  failed `init` (U11, U16), after a revocation.
- **Sibling paths.** One effect by several routes: `upatch load`, boot
  restore, `upatch reconcile`, `bpm upgrade` and a revocation purge all
  change what is loaded or attached. Compare their checks for
  equivalence, not presence, and read each undo and error path as
  closely as its success.
- **Self-report trusted.** A verifier check on a field of the target's
  own account. A check that trusts what the target wrote about itself is
  no check.
- **Encoding ambiguity.** Two inputs that hash or sign the same: lengths
  not bound, hex case, separators, names truncated rather than refused.
  Or one input that two readers take differently: a duplicate key,
  member or section, shirudo's reading of a loader, BTF or tar against
  the kernel's or the operator's, padding or uninitialized bytes in
  what is hashed, signed or measured.
- **Bytes as strings.** Bytes that came with a length handed to a
  function that reads up to a terminator: `strcmp()`, `strlen()`,
  `strchr()`, `strstr()`, `strcspn()`, `strtok_r()`, a `%s`. For each
  place bytes enter, settle where the length comes from and whether a
  terminator is written before such a function runs, an over-read
  otherwise; what a NUL among the bytes does, refused or the string
  ends short, so that a digest or a signature covers bytes a compare
  never saw, a name on disk is not the name checked, or the kernel
  reads what shirudo did not; whether a fixed-size field is compared
  whole or up to a terminator that need not be there; whether a digest
  over several strings delimits or counts each; whether a length is
  narrowed before it bounds a copy or a compare; and whether a name is
  checked once before it is printed, hashed or put in a path. Bytes
  become a string through `span_to_str()`, `read_text_line()` or
  `json_parse()`, and a field through the `memchr()` of its parser:
  look for the reader that has none of them, and for a strict JSON
  writer given text nobody checked, which fails the whole document. The
  `read_unterminated` and `file_as_string` rules match a buffer a read
  left unterminated and a file searched as a string; a field whose NUL
  another function checked and a copy terminated by hand they do not
  see.
- **Hook bypass.** Another syscall reaching what a hook refuses: both
  rename endpoints, hard links, truncate, xattrs, idmapped mounts, a
  descriptor opened before the mark, `bool kernel` misread. Take the
  routes from the kernel source: the callers of `security_<hook>()` and
  what reaches the effect past them, not what you remember of them.
- **Unattended availability.** A registry or package that loops, wedges
  or fills the disk on every timer run, or holds the register lock so
  that every upatch command refuses. A crash of a one-shot command on
  its own operator's input is not this.
- **Text and secrets.** Unverified names printed without
  `text_sanitize()`; key material not cleared with `memzero_explicit()`
  on every path out, or compared without `memneq_explicit()`; secrets in
  logs; what G8 keeps from a task without authority leaving in a log
  line, `status` output, an error message or an export.
- **Environment and exec.** The target runs no subprocess. Look for
  variables, search paths and libraries a process with runtime authority
  takes from root (U3, U7), and at what else an exec keeps for it: open
  descriptors, the working and root directory, resource limits, signal
  state, namespaces.
- **Linked code.** The target links OpenSSL, libcurl, tpm2-tss, libelf,
  zlib, zstd, LuaJIT and libbpf statically, at the versions
  `Makefile.target-deps`, `vendor/libbpf` and the build host give
  (`.github/scripts/gen-sbom.sh` lists them). A published flaw in one
  is a finding when the build keeps the affected code and an
  adversary's bytes reach it. The proofs stop at these libraries, and a
  sanitizer sees only what was built with it.
