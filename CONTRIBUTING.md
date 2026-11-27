# Contributing to shirudo

Thanks for your interest in contributing to shirudo. The
[contribution guide](Documentation/contribute/code/contributing.rst)
says how to write, test and submit a change. Contributions follow these
rules:

1. shirudo decides which BPF code a host runs, and most changes need
   experience with the kernel and BPF. The bar to contribute is high
   for that reason. If you are new to open source or to BPF, another
   project is a better place to start.

2. You understand every line you submit. You can explain what your
   change does, why it is correct and how it works with the rest of
   shirudo, without an AI tool at hand, and you answer the review
   yourself.

3. First-time and newer contributors may open a pull request directly.
   If its author turns out not to understand the submitted code, or
   cannot explain what the changes do, the pull request is closed and
   the author is banned from opening new ones. The maintainers decide
   on a ban and on lifting it.

4. Every contribution comes from a GitHub account that represents a
   human. You may use AI tools, but you take personal responsibility
   for the content, as if you had written it without them.

5. Every commit carries a `Signed-off-by:` line, the Developer's
   Certificate of Origin, in your full name. With it you certify that
   you have the right to contribute the content under the project's
   license, also where an AI tool helped write it. Only a person signs
   off, never a tool.

6. Bugs, regressions and feature requests are
   [GitHub issues](https://github.com/shirudo-dev/shirudo/issues).
   Report a security problem privately, as [SECURITY.md](SECURITY.md)
   describes, never in public. On
   [shirudo's Zulip](https://shirudo.zulipchat.com), questions and help
   with using shirudo go to the
   [#help channel](https://shirudo.zulipchat.com/#narrow/channel/659552-help),
   ideas and design discussion to the
   [#ideas-design channel](https://shirudo.zulipchat.com/#narrow/channel/659583-ideas-design);
   open a GitHub issue for a bug or a feature request that comes out
   of a discussion there.

7. Everyone who takes part, in issues, pull requests and reviews and on
   Zulip, follows the [Code of Conduct](CODE_OF_CONDUCT.md). It says
   what behavior is not acceptable and how to report it.

8. A new feature or a change to the design starts as a GitHub issue or
   a discussion in
   [#ideas-design](https://shirudo.zulipchat.com/#narrow/channel/659583-ideas-design),
   so that its direction is agreed before you write it. A pull request
   that implements an issue the maintainers accepted is the most likely
   to be merged.

9. Reviewing contributions takes the maintainers' time. They are under
   no obligation to review or answer issues, pull requests and
   discussions, and may close a pull request that does not follow
   these rules without review.

10. An issue without activity for three months is labeled `stale` and
    closed after three more. A pull request is labeled after one month
    and closed after one more. A comment or a push takes the label off
    again, and the maintainers keep an issue or a pull request open
    regardless with the `pinned` label.
