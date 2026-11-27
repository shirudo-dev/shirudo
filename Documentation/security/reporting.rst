..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: All readers

Report a vulnerability
======================

Report a security problem in shirudo privately, so that it can be fixed
before it is public.

Before you begin
----------------

- Reproduce the problem on the ``main`` branch. shirudo has no releases
  or supported release branches yet, so ``main`` is what the policy
  covers.
- Check the :doc:`threat-model`. A gap listed under threats to resolve
  or residual risks is known. A report is still welcome when it shows a
  path the entry does not describe, a larger consequence, or a
  reproduction of an entry marked as a reading of the code.
- Note the commit of shirudo, the kernel tree and commit, and the parts
  of the kernel configuration and command line that matter for the
  problem.

Report the problem
------------------

1. Do not open a public issue, discussion or pull request about it, and
   do not raise it on shirudo's Zulip.
2. Open the shirudo repository on GitHub,
   https://github.com/shirudo-dev/shirudo, and go to its Security tab.
3. Select Report a vulnerability, which opens the private report form,
   https://github.com/shirudo-dev/shirudo/security/advisories/new.
4. Describe the problem: what an attacker needs, the steps that
   reproduce it, what it breaks, and the IDs of the goals, assumptions
   or threats in the :doc:`threat-model` it affects.
5. Submit the report.

Verify
------

GitHub lists the report as a draft security advisory in the repository's
Security tab, visible to you and the maintainers only. Follow up there.

Policy
------

The repository's `security policy
<https://github.com/shirudo-dev/shirudo/blob/main/SECURITY.md>`__,
:src:`SECURITY.md`, is the policy of record. It says:

- Do not report a vulnerability in a public issue, discussion or chat,
  such as shirudo's Zulip. Use GitHub's Report a vulnerability
  feature instead.
- shirudo is pre-release and has no stable releases or supported
  release branches. Reports about the ``main`` branch are welcome, to
  harden it before the first release.
- The policy will change as the project matures.

Next steps
----------

- :doc:`threat-model` for what shirudo protects and the known gaps
- :doc:`/contribute/code/contributing` if you send the fix yourself, after
  the advisory is agreed
