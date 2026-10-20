.. SPDX-License-Identifier: BSD-2-Clause
.. Copyright (c) 2026 Authors of shirudo

==============
Contributing
==============

shirudo follows the Linux kernel's development conventions for commits:
the coding style in `coding-style <coding-style.rst>`__, a kernel-style commit message,
a mandatory ``Signed-off-by:`` line, and the same set of attribution
tags. This page states the parts of that process that apply here; the
kernel's ``Documentation/process/submitting-patches.rst`` is the
reference for anything not covered.

Participation in the project is governed by the Code of Conduct in
``CODE_OF_CONDUCT.md`` at the repository root; conduct concerns go to
conduct@shirudo.ai.

Commit messages
===============

The kernel's ``submitting-patches.rst`` ("Describe your changes") and
``maintainer-tip.rst`` ("Changelog") set the standard; the rules below
are theirs, applied here.

The subject line is ``area: imperative summary`` in at most about 70
characters, where ``area`` names the part of the tree being changed
(``bpm:``, ``packaging:``, ``docs:``, ``tree:``, ``build:`` and so on).
The body, wrapped at 75 columns, is the permanent record read by
reviewers now and by whoever bisects to the commit years later, so it
is written for them:

* Describe the problem first. Whether the change is a one-line fix or
  a new feature, something motivated it; say what, and convince the
  reader it is worth fixing. The diff already shows *what* changed;
  the message exists to record *why*.
* Describe the user-visible impact: the crash, the refused load, the
  wrong report, the invariant that was violated. Quote the actual
  error or log line when there is one.
* Then describe what the change does about it, in plain English, so
  the reviewer can check that the code does what was intended. Mention
  alternatives that were tried and rejected, and the costs of the one
  chosen.
* Quantify claims: a performance, size or latency improvement comes
  with numbers; a heuristic comes with its trade-off.
* Use the imperative mood ("make X do Y", "refuse Z"), as if giving an
  order to the code base. Not "this patch", not "I changed", not "we
  modify". Write in abstract terms about the code, not as a story of
  what the author did.
* Structure it as short paragraphs in the order context, problem,
  solution. If the explanation is getting long, the commit is probably
  doing more than one thing; split it.
* Refer to other commits by at least twelve hash characters plus the
  subject in parentheses, so the reference stays readable without a
  repository at hand.
* Make it self-contained. Links to reports or discussions are welcome
  (``Link:``, ``Closes:``), but the message must make sense without
  following them.
* Short and to the point. Leave out what the diff says, repeat nothing
  from the subject, and never use emojis.

An example of the form, from the kernel (commit 43a1e3744548 by Linus
Torvalds, ``security/keys: fix missed RCU read section on lookup``)::

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
about which lines moved; the diff shows that.

Sign your work
==============

Every commit carries a ``Signed-off-by:`` line, with no exception. The
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

using a known identity; anonymous or pseudonymous sign-offs are not
accepted, and neither is an address nobody answers at: a GitHub noreply
address, the address a coding agent writes with, or anything called
``[bot]`` is rejected as the author, in a ``Signed-off-by:`` and in a
``Co-developed-by:``. ``git commit -s`` and ``git revert -s`` add the
line for you.
A commit without a valid sign-off is not merged, and a maintainer who
applies a commit adds their own sign-off after the author's, so the
chain of ``Signed-off-by:`` lines records the real route the change
took. The first sign-off is the author's; the last is the person who
submits the commit. ``.github/scripts/check-dco.sh`` verifies that
every commit in a range has a one-line subject, a body that says more
than its tags and its author's sign-off from a real address, and CI
runs it on every pull request as the ``DCO`` check.

Only a person can certify the DCO. Coding agents and other automated
tools must never add a ``Signed-off-by:`` line; the human who reviews
and submits the work signs it off and takes responsibility for it.

Tags
====

The tags below are used exactly as in the kernel. All of them go in
the trailer block together with the sign-offs, one per line.

``Co-developed-by:``
    Attributes co-authorship when several people worked on one commit.
    Every ``Co-developed-by:`` is immediately followed by the
    ``Signed-off-by:`` of that co-author, and the sign-offs keep the
    chronological order of the work; the submitter's sign-off is last::

        Co-developed-by: First Co-Author <first@example.org>
        Signed-off-by: First Co-Author <first@example.org>
        Signed-off-by: Submitting Author <author@example.org>

``Fixes:``
    Names the commit that introduced the bug being fixed, as the first
    twelve characters of its hash and its subject in parentheses::

        Fixes: 1234567890ab ("bpm: publish signed indexes from C")

    Use it on every bug fix whose origin is known; it is how the fix is
    traced back and how release branches decide what to pick up.

``Reported-by:``
    Credits the person who found and reported the bug. It is for bugs,
    not feature requests, and is followed by a ``Closes:`` tag with the
    URL of the report when one exists (``Link:`` when the commit fixes
    only part of what was reported).

``Suggested-by:``
    Credits the person whose idea the change implements.

``Tested-by:``
    Records that the named person tested the commit successfully in some
    environment. Say where when it matters, with a ``# suffix``::

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
person acted in public; every other tag needs that person's explicit
permission. When a later version of a change differs substantially, drop
the ``Tested-by:``, ``Reviewed-by:`` and ``Acked-by:`` tags it had
collected and say so in the cover text, so a tag never vouches for code
its author has not seen.

Before sending
==============

* Build both profiles and the helper (``make``, ``make shirudo-build``)
  and run ``make -C testing test-op``; run ``make -C testing test-tgt`` when the change
  touches target-side behaviour.  CI runs the target suite in both
  configurations as the ``Target tests`` check.  Run the host-side suite once more
  with ``make -C testing SANITIZE=address,undefined test-op`` when the change
  touches memory handling or binary formats; CI runs the same sweep.
* Run ``make -C Documentation html-docs`` when the change touches ``Documentation/``;
  every document must render clean under docutils' strict mode.
* Run ``.github/scripts/check-spdx.sh`` when the change adds a file:
  every source carries an SPDX tag in the kernel's form for its type,
  ``BSD-2-Clause`` for userspace and ``GPL-2.0 OR BSD-2-Clause`` for
  everything compiled into a BPF object, the headers it includes and
  the decoders a package ships. Run
  ``.github/scripts/check-dco.sh origin/main..HEAD`` on the commits. CI
  runs both.
* Run ``.github/scripts/check-style.sh origin/main..HEAD`` on the
  commits: it runs the kernel's ``checkpatch.pl`` in strict mode over
  the C each commit touches, at its default limit of 100 columns, and
  over its message, with the checks that have no meaning in userspace
  switched off, each listed in the script with its reason, and it
  rejects a block comment whose text starts on the ``/*`` line, the
  netdev form. ``--diff`` checks the uncommitted changes, ``--files``
  whole files and ``--types`` lists what stays enabled. CI runs it as
  the ``Checkpatch`` check.
* Keep each commit to one logical change that builds and passes on its
  own, so the history bisects. CI builds every commit of a pull request
  on its own as the ``Build every commit`` check;
  ``.github/scripts/build-commits.sh origin/main..HEAD`` does the same
  locally.
* Read `threat-model <threat-model.rst>`__ before changing anything on a
  security-relevant path, and say in the commit message which invariant
  the change preserves or extends.
