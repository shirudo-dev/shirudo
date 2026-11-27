---
name: commits
description: "Writes shirudo's commit messages and shapes a series of commits. Covers one logical change per commit, the subject `area: imperative summary` within 75 characters, a short body that says why the change is needed before what it does, charts for races and call chains, the Fixes:, Link:, Co-developed-by: and Signed-off-by: trailers, and the checks a message passes. Use before every git commit in shirudo, for code, documentation, tests, scripts and CI alike, and when rewording, splitting, reordering or squashing commits."
---

# Commits

Load this skill before you commit anything.
`Documentation/contribute/code/contributing.rst` is the reference for
the message, the sign-off and the tags; this skill is how to apply it.
A message is short, precise and says why the change is needed: the
problem and its impact first, then what the change does about it. The
diff shows what changed, so leave that out.

## Before you commit

1. One logical change per commit, and each commit builds and passes on
   its own, so the history bisects. A refactor, a mechanical change and
   a behavior change are separate commits, the refactor first. A copy
   or a bug found along the way is fixed in a commit of its own before
   the change that needed it.
2. The same commit updates the pages, the skills and the proofs that
   describe what it changes (AGENTS.md), and nothing else.
3. Read `git log --format=%s -- <the files>` for the area prefix the
   files take and how recent messages there read.
4. Write the message as "The message" below says.
5. Add the tags of "Tags". An agent never adds a `Signed-off-by:`, on
   its own or anyone else's behalf: only a person can certify the
   Developer's Certificate of Origin, and that line is left to the
   human who reviews and submits the work.
6. Check the commits, and reword until `check-style.sh` and the `awk`
   line pass and `check-dco.sh` reports nothing but the missing
   `Signed-off-by:`:

   ```sh
   git log --reverse --format='--- %h%n%B' origin/main..HEAD |
   	awk '/^--- /{c=$2; next} length > 75 && !/^  / && !/^[A-Z][a-z]+(-[a-z]+)*: / {print c": "$0}'
   .github/scripts/check-style.sh origin/main..HEAD
   .github/scripts/check-dco.sh origin/main..HEAD
   ```

   `check-style.sh` refuses a subject past 75 characters but not a long
   body line, so the `awk` line is the only check of the body's width;
   indented lines are quoted output and tags are never wrapped: both are
   exempt. After editing a message by script, rewrap the whole
   paragraph, not the line that changed. `check-dco.sh` fails until the
   person who submits the series signs it off.

## The message

`Documentation/contribute/code/contributing.rst` sets the form: the
subject `area: imperative summary`, specific ("seal: refuse the
runtime to a task that shares its file system context", not "seal:
fixes") and at most 75 characters; the body wrapped at 75 columns, the
problem and its impact before the change. Write it for a reviewer who
reads it once:

- Short, plain sentences, one idea each. No filler and no long
  background; drop any sentence the reviewer does not need to
  understand the problem or the fix.
- Plain paragraphs for a simple bug. `[BUG]`, `[CAUSE]` and `[FIX]`
  headings only where the symptom, the cause and the fix each take
  several paragraphs.
- Quote what a program printed, an error, a log line or a call trace,
  as it printed it: quoted text has no column limit and is never
  folded.

- Where a chart explains the problem faster than prose, draw one.
- The length follows the reasoning, not the diff: a one-line fix can
  need three paragraphs, and deleting dead code one sentence.
- When old code changes or goes, say why it once made sense and why
  that reason is gone, citing the commits that added it and that broke
  it.
- State the scope: what the change deliberately leaves alone, whether
  it is the minimal fix and what the full one would be and why it waits,
  what was tested and what was not, and what would make it be undone.
- Where a bug has a short reproducer, give it: the command or the small
  program, and what it printed.
- Where an interface changes, show the old and the new call in a short
  snippet.
- A mechanical change gives the exact command that made it, `git grep
  -l ... | xargs sed -i ...`, says how to review it, for instance with
  `git show -w`, and lists the cases fixed by hand.
- A revert has the subject `Revert "<subject>"` and starts with `This
  reverts commit <hash> ("<subject>").`, then gives the symptom as
  reported, why it is reverted rather than fixed now, and what comes
  next. A partial revert says what it keeps.
- A side note, such as advice for a backport or a nit outside the
  change, goes in a `[ ... ]` paragraph after the main text.

## Tags

The tags go in one block at the end, one per line, as
`contributing.rst` defines them under "Tags".

- `Fixes:` names the commit that brought the bug, by its first twelve
  hash characters and its subject, both filled in by git, never typed:

  ```sh
  c=<commit>
  git cat-file -e "$c" &&
  	printf 'Fixes: %s ("%s")\n' "$(git rev-parse --short=12 "$c")" \
  		"$(git log -1 --format=%s "$c")"
  ```

  Use it on every fix whose origin is known, documentation fixes
  included. Before amending or folding a fix into an earlier commit,
  check that the commit is not on `origin/main` yet
  (`git merge-base --is-ancestor <commit> origin/main` exits 1): a
  published commit gets the fix on top, with `Fixes:`.
- `Link:` points at a report or a discussion; the message still makes
  sense without following it. `Closes:` follows a `Reported-by:` when
  the commit fixes the whole report.
- `Co-developed-by:` is followed at once by that person's
  `Signed-off-by:`, and the sign-offs keep the order of the work. A
  contributor's commit taken over keeps its author, and a rework is
  said in the message, not in a note between the sign-offs.
- Every name in the author, a `Signed-off-by:` or a `Co-developed-by:`
  is a person's full name, a given name and a surname, capitalized,
  with an address the person answers at: `check-dco.sh` refuses a
  handle, a given name alone, a name in lowercase, a noreply address
  and anything called `[bot]`.
- `Reported-by:`, `Suggested-by:` and `Cc:` may credit someone who
  acted in public; every other tag needs that person's permission.

## Charts

An ASCII chart earns its place for:

- a race: show the window, side by side, rather than describe it;
- an error path seen from several callers, where one cleans up what
  another already did;
- a call chain across layers where the bug shows on one path only;
- the order of steps, as in a load's pins, archive and extend, or
  `init`'s phases.

Function names only, no file paths or line numbers, and only the
functions that matter. A state or an outcome goes in plain words under
the function name. A race takes one column per racing context: a
command, root, a CPU, a kworker.

A race, a load that root stops between its pins and its extend:

```
 shirudo upatch load                root
 upatch_load()
 |-upatch_apply()
 | \-attach_and_pin_progs()
 |   The links are attached
 |                                  kill -9 <pid>
 |                                  The load ends here
 \-upatch_chain_event_locked()
   Never runs: pins without a record in the register.
```

A call chain where the bug shows on one path, an exec that fails past
its point of no return:

```
 load_elf_binary()
 |-begin_new_exec()
 | \-security_bprm_committed_creds()
 |   The task now holds runtime authority
 |
 \-create_elf_tables()
   Fails: SIGSEGV, and the core dump runs as the task
   \-coredump_file()
     Unlinks the core_pattern path with that authority.
```
