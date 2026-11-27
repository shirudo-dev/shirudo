---
name: writing
description: "Writes and edits shirudo's prose so that it reads as an engineer wrote it for another: pages, commit messages, code comments, program messages and help, skills and pull request text. Covers saying the point instead of building up to it, letting the content set the shape, plain words and verbs, plain formatting, leaving out talk about the text itself, the tree's own wording rules, what a rewrite never touches, and a grep over the changed lines. Use whenever writing or reviewing prose in shirudo, and before a page, a commit message, a comment or a help text is handed over."
---

# Writing

The reader is an engineer who reads a text once, often in the middle of
a task. Every sentence states something that reader does not know yet.
A first draft drifts toward the most common phrasing, and the patterns
below are where that drift shows: they make a text longer, vaguer and
easy to recognize as generated. Fix the sentence, not the word: when a
pattern turns up, say the point plainly, and rewrite the paragraph if a
sentence stays awkward.

`Documentation/contribute/documentation/writing-docs.rst` is the style
guide of the pages, and the `docs`, `commits`, `user-experience` and
`coding` skills say what each kind of text needs. This skill is the
prose they share.

## Write, then check

1. Collect the facts first: what changed, what was run and on what,
   what it printed. Draft from those, and from a text of the same kind
   in the tree, never from adjectives.
2. Write the point first: the fact, the decision or the change, then
   only the reasoning the reader lacks.
3. Delete the opening and closing lines that only lead in or sum up,
   then read the draft for the patterns below, the first groups first.
4. Rewrite what they mark. Keep every fact, name, number, version,
   command, path, link and quoted line exactly as it was. A draft that
   is mostly filler is rewritten from the facts, not polished.
5. Run the greps of "Check" on the changed lines, then judge each hit
   in a pass of its own, and reread the changed paragraphs as their
   reader would. The text is done when every sentence carries a fact
   and every hit left has a reason.

## Claim only what holds

- Say what was done and checked, on what, and what was not. "All tests
  pass", "fully backward compatible" or a ticked box stand only for a
  run that happened: write "the unit and functional tiers pass on
  x86-64; the VM families did not run".
- State a reason only when it is known. A "why" read off the diff is a
  guess: find it in the code, the history or the report, or say what is
  still unclear.
- A sentence that would fit any project ("improves maintainability and
  robustness", "makes the code cleaner") says nothing. Name the effect:
  which bug no longer happens, which call got cheaper, by how much.
- Use the precise term where one exists, and the mechanism where the
  reader needs it: "the verifier rejects the program", not "the kernel
  may not accept it". A warning names the behavior ("the load fails
  with `EPERM`"), never "may lead to unexpected behavior".
- Keep a qualifier a claim depends on: the kernel, the architecture,
  the configuration, the bound a proof covers. A claim made general
  beyond what was checked is wrong, however confident it reads.

## Say it

- A contrast against a claim nobody made ("not just a loader, but a
  platform", "this is not about speed, it is about trust") adds weight
  without adding a fact. State what the thing is. Keep a "not" only
  where it corrects a belief the reader is likely to hold.
- An announcement of the point ("here is what you need to know", "it is
  worth noting that", "importantly", "note that") goes; start with the
  point.
- A last line that restates its paragraph, and a closing "in short" or
  "overall" over what was just said, go.
- A saying that dresses an ordinary point as an insight ("at its core",
  "the real question is", "the key idea") goes; state the point.
- An answer to an objection nobody raised, often left over from an
  earlier draft, goes.
- Two thoughts joined by a colon reveal ("the fix arrives only when a
  machine boots a kernel that carries it: days or weeks later") become
  two plain sentences.

## Let the content set the shape

- A list has as many items as there are. Three is not a default, and
  neither is a lesson after the examples.
- Sentences in a row do not open the same way.
- Prose has no dashes as connectors, `--` or an em dash: use a comma, a
  period or parentheses. Options, commands and code keep theirs.
- One hedge where the uncertainty is real, with what it depends on
  ("on a kernel without the patch"); otherwise state it. "May
  potentially" and "could possibly" are two hedges for one doubt.
- Name the actor: "the kernel verifies the signature", not "the
  signature is verified".
- Short sentences with one idea each, in short paragraphs, but not a
  run of them all the same length: two steps of one thought join with
  "because", "so" or "but". Break a long block with a list only where
  the reader scans it.
- A how-to talks to its reader, "run", "you"; a rewrite that turns it
  into an impersonal summary loses that.

## Plain words

- Use the plain verb: "is", "has", "does", not "serves as", "acts as",
  "functions as", "features", "offers" or "boasts".
- Keep the action in the verb: "verifies", not "performs the
  verification of"; "decides", not "makes a decision on".
- Leave out the words that mark generated text when they are used for
  weight, in any form ("delves", "showcasing"): "delve", "underscore",
  "showcase", "intricate", "meticulous", "commendable", "notably",
  "additionally", "enhance", "insights", "nuanced", "leverage",
  "robust", "seamless", "comprehensive", "crucial", "pivotal", "vital",
  "landscape", "ecosystem", "testament", "foster", "empower",
  "streamline", "elevate", "unlock", "holistic", "journey", "realm". A
  technical sense stays: a CBMC harness, a mutex unlock. Swapping the
  word for a synonym fixes nothing; rewrite the sentence so it states
  its fact.
- Do not inflate: an ordinary fact is not "a key part of", "plays a
  crucial role in" or "a significant step toward" anything.
- A participle tail that only adds weight (", ensuring that ...",
  ", highlighting ...", ", reflecting ...") becomes its own sentence
  with an actor, or goes.
- Say the relation: "associated with", "related to", "in terms of" and
  "with respect to" hide it.
- Name the source or leave the claim out: "it is widely known" and
  "experts agree" vouch for nothing.
- No marketing: "powerful", "blazing fast", "elegant", "best-in-class".
  A security claim names its mechanism and its limit, never "secure",
  "tamper-proof" or "guarantees" alone.
- One term for one concept, as the glossary defines it. A synonym for
  variety makes the reader wonder whether a second thing is meant.
- Leave out filler: "simply", "just", "easily", "obviously", "please",
  "in order to" (write "to").

## Plain formatting

- No bold or italics for emphasis in the tree's text, and no bold label
  at the head of every list item: a list item starts with its point, a
  set of labeled values is a table.
- Headings in sentence case that name what the section holds, never one
  written for effect, never "Topic: detail", never a leading "The".
- The first sentence under a heading does not repeat the heading.
- No template sections in a commit message or another short text
  ("Summary", "Changes", "Testing"): paragraphs in the order the
  `commits` skill gives.
- No emojis, arrows, check marks or decorative rules, and no symbol in
  place of a word: "about", not "≈"; "passes", not "✅"; "to", not "→".

## Nothing about the text itself

- Write about the subject, not about the text, the change or the
  writing of it. A page describes what exists, never what it replaced
  or that something is "new" or "now"; history goes in the commit
  message. A commit message describes the code, never "this patch" or
  "in this commit we". An opening line that says what a reference page
  lists is fine; describing the layout the reader can see is not.
- No chat leftovers in the tree: no "great question", "I hope this
  helps", "let me know", "certainly" and no question to the reader at
  the end.
- No placeholder and no guess: a value you could not check is checked
  or left out, never filled in with a plausible one.

## The tree's own rules

- "shirudo" and "upatch" are always lowercase, at the start of a
  sentence too: rephrase rather than capitalize. "a upatch", never "an
  upatch".
- American English: initialize, behavior, license, enroll.
- No extra "the" before a generic noun: "for kernel and userspace
  applications", not "for the kernel and userspace applications";
  "bugs that remain", not "the bugs that remain".
- shirudo protects its own assets; the protection of a device or a
  workload comes from upatches. Never write that shirudo protects a
  machine.
- Never name an outside project, company or person as the model a text
  follows.

## What a rewrite never touches

Code, inline literals, commands, options, paths, URLs, link targets,
frontmatter, test and function names, and quoted program output, which
keeps its own words even where they break these rules. A rewrite keeps
every fact, number, version and claim. It never drops a specific detail
to read smoother, and never adds one that was not checked.

Over-correction is its own failure: a text stripped of its qualifiers,
its specifics or the reader's "you" reads smoother and says less. One
pattern alone proves nothing, people write "crucial" too, and no
detector or score decides whether a text is done.

## Check

Read every hit of this grep on the lines a change adds; a hit is a
question, not a verdict:

```sh
added() { git diff -U0 "$@" | grep '^+[^+]'; }
added | grep -n -i -E \
	"\b(delve|underscor|showcas|intricate|meticulous|commendable|notably|additionally|enhanc|insights?\b|nuanced|leverag|robust|seamless|comprehensive|crucial|pivotal|vital|landscape|ecosystem|testament|foster|empower|streamlin|elevat|holistic|journey|realm)|serves as|acts as|functions as|performs the|worth noting|importantly|note that|in order to|\b(simply|just|easily|obviously|please)\b|, (ensuring|highlighting|reflecting|underscoring)| -- | — |\bnot (just|only)\b|in short|overall,|all tests pass|unexpected behavior|\ban upatch"
added | grep -n -E '\bShirudo|\bUpatch|^\+(Summary|Changes|Testing):?$'
added | grep -n -P '[^\x00-\x7F]'
```

The last grep finds every byte outside ASCII: a name or a quoted string
keeps its letters, a symbol becomes a word. For a commit message, pipe
`git log -1 --format=%B` into the same greps in place of `added`. Then read the
text once more as its reader: whether a sentence is needed is a judgment
the grep cannot make.
