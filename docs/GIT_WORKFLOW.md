# VulnHunterX Git workflow

Follow [CONTRIBUTING.md](../CONTRIBUTING.md): work on a focused feature branch and submit a pull request with the change's purpose and validation. These are contributor conventions; this document does not claim remotely configured branch protection or mandatory reviewer counts.

## Before editing

Inspect `git status --short` and the current branch. Preserve user changes and local reference files. Existing untracked work does not require a reset or prevent a documentation task. For implementation work, use the supplied task branch or create a suitable branch when authorized; avoid direct commits to `main`.

## Reviewable changes

Keep one coherent change per PR and keep the final PR testable as a whole. No unrelated phase plan or Telegram task branches apply to this repository.

Use the established commit prefixes: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, and `chore:`. Keep mechanical formatting separate from behavioral changes when practical.

Do not commit secrets, target checkouts, generated output, virtual environments, or benchmark runs. Stage intended files explicitly; inspect the staged diff before a commit. Avoid force pushes or rewriting shared history.

## Validation and PR content

Run the commands appropriate to the change in [code standards](CODE_STANDARDS.md). Inspect whitespace with `git diff --check` and review the complete intended diff, including new files.

A PR description should state the problem, resulting behavior, compatibility changes, and commands actually run. Identify unavailable tooling and existing failures. For removal work, list removed entry points and migration instructions; do not present a proposed compatibility policy as already implemented.

## External actions and release handling

Local edits and validation can proceed within the requested scope. Commit, push, PR creation, merge, tagging, and publication require authorization for those actions; do not infer them from a request to analyze or write documents. Avoid adding repeated approval steps to actions already authorized in the session.

Follow the release tooling under `scripts/` for an authorized release. `scripts/prepare_release.sh` removes and rebuilds `dist/`, so inspect its behavior before running it. Use a normal revert or corrective commit for rollback rather than rewriting shared history; do not erase stored scan artifacts during rollback.
