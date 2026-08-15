# CLAUDE.md

Development rules for this repository, stated by the operator on 2026-08-15.

## Branching

Every feature is implemented in a git worktree on its own branch; the main checkout at `G:\q\lockfile-sentinel` always stays on `master` and is never switched to a feature branch. Worktrees live on the temp-drive scratchpad, not inside the repository. Pull requests target `master`; PR titles and bodies are very concise, the body at or under 150 characters. History is never rebased: when a branch falls behind `master`, `master` is merged into it with a merge commit, and divergence between open branches is resolved the same way.

## Coordination

Cross-session coordination goes through the mcp-router `comm` plugin: a session reads the channels at start, posts a claim to `#lockfile-sentinel-dev` before taking work, and posts again when the work lands. Shell `git` is refused on this host; the mcp-router `git` plugin is the route, with `cwd` pointing at the worktree and `sessionId` passed on both `add` and `commit`.

## Language Level

Code targets Python 3.12 or newer and uses 3.12+ syntax where it helps (PEP 695 type aliases already appear in `lockfile_sentinel.py`).

## Pre-Commit Gate

Before any commit, all five analyzers run and every finding is fixed rather than suppressed: `mypy` (3.12 floor, all four programs), `pylint` (must stay 10/10), `bandit -r . -x ./tests`, `semgrep scan --config auto`, and SonarScanner against the local SonarQube at `http://localhost:9000` (project key `maximmasiutin_lockfile-sentinel`), including code-smell and cognitive-complexity findings. The Sonar token is per-host and is passed on the command line, never committed.

## Comments

Comments state the present constraint only; a calendar date or a change narrative in a comment is refused by the commit gate (comment-history rule). The change story belongs in the commit message.
