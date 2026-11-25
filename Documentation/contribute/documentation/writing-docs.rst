..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: shirudo contributors

Writing docs
============

These rules keep the documentation accurate, consistent and easy to
read. They apply to every page under ``Documentation/``. When the code
and a page disagree, the code is right and the page is a bug.

Readers
-------

Every page serves one of four readers. State which one in the page
metadata, and write for that reader.

Operators
    DevOps and SecOps engineers who deploy, run and troubleshoot targets.
    They are often in the middle of a task or an incident, and they scan.

upatch authors
    Engineers who turn a kernel fix or an observation into a signed
    upatch and ship it as a package.

shirudo contributors
    Developers who change shirudo itself, its tests and its build.

Kernel developers and security reviewers
    Readers who need to understand the design, the kernel interfaces it
    relies on and the threat model well enough to judge them.

Page types
----------

Each page has exactly one type. Do not mix types on one page; link to
the other page instead.

.. list-table::
   :header-rows: 1
   :widths: 18 82

   * - Type
     - Purpose and voice
   * - Tutorial
     - Teaches by doing, from a clean start to a working result. Second
       person, numbered steps, a short explanation of what each step
       achieved.
   * - How-to
     - Gets one task done. Second person and imperative mood. Before you
       begin, numbered steps with one action each, a verify step, next
       steps.
   * - Explanation
     - Builds understanding of a concept, a mechanism or a design
       decision. Explanatory prose: the problem, why the obvious approach
       fails, the mechanism, its limits. "We" means the design.
   * - Reference
     - States facts to look up: commands, options, formats, settings,
       events, errors. Tables and exact syntax, no narrative.

Operator pages, procedures, troubleshooting, the CLI reference and the
cheat sheet are written as how-to or reference pages. Concepts, internals
and design rationale are explanation pages.

Explanation pages
~~~~~~~~~~~~~~~~~

Explain one thing at a time, in short paragraphs that each carry one
idea and open with it. Walk the reader from the problem to the mechanism:
what goes wrong without it, why the first approach that comes to mind
does not work, what the mechanism does, and where it stops. Number figures
and refer to them from the text. Put asides in footnotes. This is the
documentation of an infrastructure project, not a textbook: no quizzes,
no epigraphs, no exercises.

Threat model entries
~~~~~~~~~~~~~~~~~~~~

Each threat is an explanation followed by a fact box, a field list with
the ``facts`` class:

.. code-block:: rst

   .. rst-class:: facts

   :Adversary: ADV-B, root on the target without the signing key
   :Enforced at: ``lsm/bpf``, ``lsm/inode_unlink``, ``lsm/sb_umount``
   :Refusal: ``EACCES`` from the denied system call
   :Counters: ``BpfCommand``, ``PinUnlink``, ``BpffsUmount``
   :Tests: ``t6106``, ``t6107``, ``t6120``
   :Proofs: ``upatch-header``, ``Shirudo.Chain``
   :Residual: R3

Name only hooks, counters, tests and proofs that exist, a hook by the
section of its program, ``lsm/`` or ``lsm.s/``, a proof by its name in
:src:`testing/proofs/cbmc/proofs.list` or its Lean 4 module, and add
``:Proofs:`` only where a proof covers the check the threat rests on.
Every LSM program of :src:`bpf/` stands in the ``:Enforced at:`` field
of some threat, one that refuses nothing after the others with what it
does, and every tamper counter in a ``:Counters:`` field. ``make -C
Documentation check`` verifies all of this against the tree.

Page metadata
-------------

Every page starts with the SPDX comment and two metadata fields, before
the title. The theme shows them as one line under the title.

.. code-block:: rst

   ..
      SPDX-License-Identifier: BSD-2-Clause
      Copyright (c) 2026 Authors of shirudo

   :page-type: How-to
   :audience: Operators

   Respond to a tampered target
   ============================

Use ``Tutorial``, ``How-to``, ``Explanation`` or ``Reference`` for
``:page-type:``. Index pages of a section carry no metadata.

Titles and headings
-------------------

- Write titles and headings in sentence case: "Boot integration", not
  "Boot Integration".
- Do not start a title with "The", and do not use the "Topic: detail"
  form. Write "Signed loader path", not "The signed-loader path", and
  "Seal labels and task marks", not "The seal: labels and task marks".
- Name how-to pages with a verb and an object: "Rotate a signing key".
  Name explanation and reference pages with a noun phrase.
- Do not number headings. The navigation gives the order.
- Use ``=`` under the page title, ``-`` for sections and ``~`` for
  subsections. Split a page rather than going deeper.
- The title of a page and its entry in the navigation are the same text.

Words
-----

- Write American English: initialize, behavior, license.
- shirudo, upatch and upatches are always lowercase: at the start of a
  sentence, in a heading, in a navigation label and in a compound such
  as "shirudo-patched". Rephrase a sentence rather than capitalize them.
  The rule holds for the text the programs print, which pages quote, and
  for code comments and commit messages too.
- Use one term for one concept and define it in the
  :doc:`/concepts/glossary`. Link the term with ``:term:`` where a reader
  may not know it.
- Write in the present tense and the active voice, and name the actor:
  "The kernel verifies the loader's signature", not "The signature is
  verified".
- Describe what exists. Change history, bug stories and "now" or "new"
  belong in commit messages, not in the documentation.
- Prefer short sentences with one idea each. Do not chain clauses with
  semicolons in procedures and reference pages.
- End a list item with a period only when it is a sentence. Link lists,
  noun phrases and short "Label: value" items end without one. If any
  item of a list is a sentence, or a label followed by a paragraph, end
  every item of that list with a period.
- Leave out filler words such as "simply", "just", "easily", "obviously"
  and "please", and Latin abbreviations such as "e.g.", "i.e." and "etc.".
- Do not use italics or bold for emphasis. Write the sentence so the
  important part comes first.
- Every security claim names its mechanism and its limit, and links the
  residual risk if there is one. Do not write "secure", "tamper-proof" or
  "guarantees" without the mechanism.
- No emojis and no marketing language.

Literals and code
-----------------

- Format every literal as inline code: commands, options, file names,
  paths, keyrings (``.bpf``), extended attributes, units, failure
  categories (``tampered``), hooks, kernel symbols and Kconfig options.
- Write command examples as ``console`` blocks. The prompt says where the
  command runs: ``operator$`` on the operator host, ``target#`` as root
  on a target, ``$`` and ``#`` for anything else. The copy button leaves
  prompts and output out.

  .. code-block:: rst

     .. code-block:: console

        operator$ shirudo attest verify --evidence=ev.json --nonce=$NONCE \
            --ak-name=<ak-name> --cert=signer.der --upatch=fix.upatch
        target# shirudo status

- Put one shirudo command in a block unless the commands only make sense
  together. Introduce each block with a sentence that ends in a colon.
- Write placeholders as ``<lowercase-words>`` and say what each one is.
  Use long option forms, with ``=`` where the parser requires it.
- Show real output, copied from a run in the test VM, with timestamps and
  host-specific values removed. Run every command a page shows in the
  test VM before the page lands.

Links and cross-references
--------------------------

- Link pages with ``:doc:`` and sections with ``:ref:``. Give a section a
  label only when another page links to it.
- Link text is the title of the target, or a phrase that names it. Never
  "here" or "click here".
- Collect further reading at the end of a page under "Next steps" or
  "Related", not in the middle of a procedure.
- State a fact once and link to it. The CLI reference, the formats and
  the failure categories are the single home of what they describe.

Admonitions
-----------

Use ``.. warning::`` only for an action that breaks the trust model,
locks out a target or cannot be undone, and say why and what to do
instead. Use ``.. note::`` rarely. Never put two admonitions in a row and
never open a page with one.

Tables and figures
------------------

- Prefer ``list-table`` for tables, with a header row.
- A literal in a table cell breaks only after ``/ . _ - = , : |``, which
  the build marks, so a long path or option does not set the width of
  its column. A literal with none of them, such as a hex digest, still
  does: give it a line of its own after the table.
- Include a figure with ``.. figure:: /images/<name>.svg`` and an
  ``:alt:`` that says what it shows. Number it in the caption ("Figure
  1.") and refer to it from the text before it appears.
- Draw a figure in TikZ, in ``Documentation/figures/<name>.tex``, and
  never edit its SVG by hand. Start from a figure there: the
  ``standalone`` class with ``shirudo-figure``, whose units are pixels of
  the page at full width, whose text is IBM Plex Sans and Mono as on the
  pages, and whose colors are roles (``fig-ink``, ``fig-muted``,
  ``fig-line``, ``fig-accent``, the chart series ``fig-s1`` to
  ``fig-s4`` and the rest it defines). Use those colors alone, a lighter
  shade as the same color with an opacity: the page writes the figure
  into its HTML and gives each role the value of the theme the reader
  picked, light or dark.
- ``make -C Documentation figures`` draws the SVG of every figure whose
  source changed, with LaTeX, TikZ and dvisvgm on the host; commit the
  source and the SVG together. The check fails on an SVG that its source
  no longer makes.

Building and checking
---------------------

Render and serve the documentation on ``http://127.0.0.1:8000``:

.. code-block:: console

   $ make docs

If ``fswatch`` or ``inotifywait`` is on your ``PATH``, the preview rebuilds
when files under ``Documentation/`` change. Refresh the page to see the
new build. Install ``fswatch`` or the ``inotify-tools`` package to enable
automatic rebuilds.

Render it and check it against the code, as CI does:

.. code-block:: console

   $ make -C Documentation check

The build turns every Sphinx warning into an error. The check verifies
that the commands, options, failure categories, tamper counters, hooks,
tests and units a page names exist in the tree, and that every figure is
what its TikZ source makes.

Related
-------

- :doc:`/contribute/code/contributing` for commit messages and the sign-off
- :doc:`/contribute/code/coding-style` for the C code
