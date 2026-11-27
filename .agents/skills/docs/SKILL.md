---
name: docs
description: Keeps Documentation/ in step with a change to shirudo. Covers which pages describe a command, option, message, failure category, tamper or integrity counter, LSM hook, file, unit, environment variable, setting, format, Beefile key, test, kernel patch or threat, how to write the change in the voice of its page, and how to check the result. Use whenever code changes behavior a page describes, when a test is added or removed, and when writing or reviewing a page.
---

# Documentation

A change to behavior updates the pages that describe it in the same
commit, and a page that no longer matches the code is a bug, whichever
of the two is wrong. `Documentation/contribute/documentation/writing-docs.rst`
is the style guide.

## Find the pages

Search for every name the change adds, renames or removes, in the pages
and the skills alike:

```sh
git grep -n '<name>' Documentation completion .agents/skills
```

Then go through the pages each kind of change has:

| Change | Pages |
|---|---|
| Command, option, usage | `reference/cli/<command>.rst`, the command's help text, `reference/cheat-sheet.rst`, the guides that run it; `completion/shirudo.bash` only for what `--list-cmds` and `--list-opts` cannot say: a placeholder's meaning, a command's file arguments |
| Error message, exit status, failure category | `reference/failure-categories.rst` |
| Tamper counter | `security/tamper-counters.rst` |
| Integrity counter | `security/integrity-counters.rst` |
| LSM hook | `internals/enforcement.rst`, the fact boxes of `security/threat-model.rst` |
| File or directory | `reference/files.rst` |
| systemd unit | `reference/systemd-units.rst` |
| Environment variable | `reference/environment.rst` |
| Setting | `reference/configuration.rst` |
| Eventlog event | `reference/eventlog.rst` |
| `.upatch`, Beefile, upatch tree, package and index, status JSON, OTLP, keepalive or map export format | `reference/formats/<format>.rst` |
| Beefile key | `reference/formats/beefile.rst` |
| Threat closed or opened, residual risk | `security/threat-model.rst` |
| Test or fuzz target | `contribute/testing/test-coverage.rst` |
| Carried kernel patch | `internals/kernel-patches.rst` |
| How a mechanism works | its page under `internals/` |

## Write

- Each page has one type, set by its `:page-type:` line, and the voice
  of that type ("Page types" in the style guide): a reference page
  states facts in tables and exact syntax, a how-to gives numbered
  steps, an explanation goes from the problem to the mechanism and its
  limits.
- American English. Commands, options, paths and values go in double
  backticks; a source file is linked with `` :src:`<path>` ``.
- Name only hooks, counters, tests and options that exist.
- A figure is drawn in TikZ, `Documentation/figures/<name>.tex`, never
  as an SVG by hand: `\usepackage{shirudo-figure}` gives the units (one
  is a pixel of the page at full width, y downwards), IBM Plex Sans and
  Mono at 12.3, 13.3 or 14.3 px (`\figsmall`, `\figbody`, `\figlarge`)
  and the colors by role (`fig-ink`, `fig-muted`, `fig-line`,
  `fig-accent`, `fig-s1` to `fig-s4`, ...). Use only those, a lighter
  shade as an opacity of one: `make -C Documentation figures` turns each
  role into the pages' variable, and the page inlines the SVG, so the
  figure follows the light or dark theme the reader picks. Commit the
  `.tex` and the SVG of `Documentation/images/` together, include it with
  `.. figure:: /images/<name>.svg` and an `:alt:`, and look at the
  rendered SVG (`rsvg-convert`) before handing it over.
- A new page carries `:page-type:` and `:audience:` and goes into its
  section's toctree. Nothing that is not about the project as a whole
  goes in the top-level directory, and no README or notes file goes beside the code but those AGENTS.md excepts.

## Check

```sh
.github/scripts/check-docs.sh
make -C Documentation check       # DOCS_CONTAINER=0 without podman or docker
make docs                         # renders, serves on 127.0.0.1:8000 and watches until stopped: run it in the background
```

`check-docs.sh` checks the options of console examples, the failure
categories, tamper and integrity counters, hooks, tests, proofs and
units the pages name, the whole of each field of a threat's fact box
with a hook by its section name, and that every proof has a row on the
proof coverage page and every source file a proof that reads it or a
line among the files without one, and that every figure is what its
TikZ source makes. It cannot check the prose: read each changed
paragraph against the code.
