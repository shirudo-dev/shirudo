..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: shirudo contributors

Commits and sign-off
====================

shirudo follows the Linux kernel's development conventions for commits:
the coding style in :doc:`/contribute/code/coding-style`, a kernel-style commit
message, a mandatory ``Signed-off-by:`` line, and the same set of attribution
tags. This page states the parts of that process that apply here. The
kernel's ``Documentation/process/submitting-patches.rst`` is the
reference for anything not covered.

Participation in the project is governed by the Code of Conduct in
:src:`CODE_OF_CONDUCT.md` at the repository root. Conduct concerns go to
conduct@shirudo.dev.

Commit messages
---------------

The kernel's ``submitting-patches.rst`` ("Describe your changes") and
``maintainer-tip.rst`` ("Changelog") set the standard. The rules below
are theirs, applied here.

The subject line is ``area: imperative summary`` in at most about 70
characters, where ``area`` names the part of the tree being changed
(``bpm:``, ``packaging:``, ``docs:``, ``tree:``, ``build:`` and so on).
``check-style.sh`` refuses a subject longer than 75 characters. The
body, wrapped at 75 columns, is the permanent record read by reviewers
now and by whoever bisects to the commit years later, so write it for
them:

- Describe the problem first. Whether the change is a one-line fix or a
  feature, something motivated it. Say what, and convince the reader it
  is worth fixing. The diff already shows what changed. The message
  exists to record why.
- Describe the user-visible impact: the crash, the refused load, the
  wrong report, the invariant that was violated. Quote the actual error
  or log line when there is one.
- Then describe what the change does about it, in plain English, so
  the reviewer can check that the code does what was intended. Mention
  alternatives that were tried and rejected, and the costs of the one
  chosen.
- Quantify claims: a performance, size or latency improvement comes
  with numbers, a heuristic with its trade-off.
- Use the imperative mood ("make X do Y", "refuse Z"), as if giving an
  order to the code base. Not "this patch", not "I changed", not "we
  modify". Write in abstract terms about the code, not as a story of
  what the author did.
- Structure it as short paragraphs in the order context, problem,
  solution. If the explanation is getting long, the commit is probably
  doing more than one thing. Split it.
- Refer to other commits by at least twelve hash characters plus the
  subject in parentheses, so the reference stays readable without a
  repository at hand.
- Make it self-contained. Links to reports or discussions are welcome
  (``Link:``, ``Closes:``), but the message must make sense without
  following them.
- Keep it short and to the point. Leave out what the diff says, repeat
  nothing from the subject, and never use emojis.

An example of the form, from the kernel (commit 43a1e3744548 by Linus
Torvalds, ``security/keys: fix missed RCU read section on lookup``,
with the ``Cc:`` lines of its trailer left out)::

    security/keys: fix missed RCU read section on lookup

    Nicholas Carlini reports that the keyring code calls assoc_array_find()
    in find_key_to_update() without holding the RCU read lock, while the
    assoc_array_gc() code really is designed around removing the node from
    the tree and then freeing it after an RCU grace-period.

    The regular key handling doesn't see this because holding the keyring
    semaphore hides any lifetime issues, but the persistent key handling
    uses a different model.

    Instead of extending the keyring locking, just do the simple RCU locking
    that the assoc_array was designed for.

    Reported-by: Nicholas Carlini <npc@anthropic.com>
    Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>

Three paragraphs: who found what and why it is a real bug, why it went
unnoticed, and which of the possible fixes was chosen and why. Nothing
about which lines moved. The diff shows that.

Sign your work
--------------

Every human-authored commit carries a ``Signed-off-by:`` line. The
sign-off certifies the Developer's Certificate of Origin, reproduced
here from the kernel's ``submitting-patches.rst``::

    Developer's Certificate of Origin 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I
        have the right to submit it under the open source license
        indicated in the file; or

    (b) The contribution is based upon previous work that, to the best
        of my knowledge, is covered under an appropriate open source
        license and I have the right under that license to submit that
        work with modifications, whether created in whole or in part
        by me, under the same open source license (unless I am
        permitted to submit under a different license), as indicated
        in the file; or

    (c) The contribution was provided directly to me by some other
        person who certified (a), (b) or (c) and I have not modified
        it.

    (d) I understand and agree that this project and the contribution
        are public and that a record of the contribution (including all
        personal information I submit with it, including my sign-off) is
        maintained indefinitely and may be redistributed consistent with
        this project or the open source license(s) involved.

If you can certify that, add::

    Signed-off-by: Random J Developer <random@developer.example.org>

using a known identity: the name you are known by, a given name and a
surname, as the author and in the sign-off alike. Anonymous or
pseudonymous sign-offs are not accepted, so a handle, a given name
alone or a name in lowercase is refused. Neither is an address nobody
answers at: a GitHub noreply address, the address a coding agent writes
with, or anything called ``[bot]`` is rejected as the author, in a
``Signed-off-by:`` and in a ``Co-developed-by:``. The sole exception is
Dependabot's numbered GitHub noreply author identity (the numeric
prefix may vary) and ``dependabot[bot] <support@github.com>`` sign-off,
which Dependabot uses on generated commits. This is an automation
exception, not a human certification of the DCO.
``git commit -s`` and ``git revert -s`` add the line for you.

A commit without a valid sign-off is not merged. A maintainer who
applies a commit adds their own sign-off after the author's, so the
chain of ``Signed-off-by:`` lines records the real route the change
took. The first sign-off is the author's. The last is the person who
submits the commit.

:src:`.github/scripts/check-dco.sh` checks every commit in a range except
merge commits:

- The subject is one line, followed by a blank line.
- The body says more than its tags.
- The commit has a ``Signed-off-by:`` from its author, spelled exactly
  like that and in the form ``Name <address>``.
- No author, sign-off or ``Co-developed-by:`` names an identity that
  contains ``noreply``, ``no-reply`` or ``[bot]``, in any case, except
  for Dependabot's numbered GitHub noreply author identity and
  ``dependabot[bot] <support@github.com>`` sign-off combination.
- The author, every sign-off and every ``Co-developed-by:`` name a
  person in full: two words or more, made of letters, with a hyphen, an
  apostrophe or a period inside a word, and the first and the last word
  capitalized. ``Random J. van der Developer`` passes; ``rjdev``,
  ``Random``, ``random developer`` and ``Random Developer2`` do not. A
  name without an ASCII letter, such as one written in Chinese, can be
  one word: the check reads ASCII alone and takes every other character
  for a letter.

CI runs it on every pull request and every push to ``main``, in the
``DCO`` workflow.

Only a person can certify the DCO. Coding agents and other automated
tools must never add a ``Signed-off-by:`` line. The human who reviews
and submits the work signs it off and takes responsibility for it.

Tags
----

The tags below are used exactly as in the kernel. All of them go in the
trailer block together with the sign-offs, one per line.

``Co-developed-by:``
    Attributes co-authorship when several people worked on one commit.
    Every ``Co-developed-by:`` is immediately followed by the
    ``Signed-off-by:`` of that co-author, and the sign-offs keep the
    chronological order of the work. The submitter's sign-off is
    last::

        Co-developed-by: First Co-Author <first@example.org>
        Signed-off-by: First Co-Author <first@example.org>
        Signed-off-by: Submitting Author <author@example.org>

``Fixes:``
    Names the commit that introduced the bug being fixed, as the first
    twelve characters of its hash and its subject in parentheses::

        Fixes: 1234567890ab ("bpm: publish signed indexes from C")

    Use it on every bug fix whose origin is known. It is how the fix is
    traced back and how release branches decide what to pick up.

``Reported-by:``
    Credits the person who found and reported the bug. It is for bugs,
    not feature requests, and is followed by a ``Closes:`` tag with the
    URL of the report when one exists (``Link:`` when the commit fixes
    only part of what was reported).

``Suggested-by:``
    Credits the person whose idea the change implements.

``Tested-by:``
    Records that the named person tested the commit successfully in
    some environment. Say where when it matters, with a ``# suffix``::

        Tested-by: Alice Example <alice@example.org> # arm64, swtpm

``Reviewed-by:``
    States that the named person carried out a technical review and
    found the change acceptable, under the kernel's reviewer's
    statement of oversight. ``Acked-by:`` is the lighter form: approval
    from someone responsible for the affected area who did not review
    in that depth.

``Cc:``
    Lists people who had the chance to comment.

``Reported-by:``, ``Suggested-by:`` and ``Cc:`` may be added when the
person acted in public. Every other tag needs that person's explicit
permission. When a later version of a change differs substantially,
drop the ``Tested-by:``, ``Reviewed-by:`` and ``Acked-by:`` tags it had
collected and say so in the cover text, so a tag never vouches for code
its author has not seen.

Before sending
--------------

Run the checks CI runs on a pull request, as :ref:`run-ci-checks` lists
them in order, and the tests the change touches. Then check that:

- Each commit holds one logical change that builds and passes on its
  own, so the history bisects. CI builds every commit of a pull request,
  and every commit a push adds to ``main``, on its own in the ``Build
  every commit`` workflow; ``build-commits.sh`` does the same locally.
- Each commit carries your ``Signed-off-by:``, which
  ``.github/scripts/check-dco.sh origin/main..HEAD`` checks.
- A change to ``Documentation/`` renders: the build turns every Sphinx
  warning into an error. See :doc:`/contribute/documentation/writing-docs`.
- Read :doc:`/security/threat-model` before changing anything on a
  security-relevant path, and say in the commit message which invariant
  the change preserves or extends.
