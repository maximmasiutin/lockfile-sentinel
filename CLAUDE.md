# lockfile-sentinel

## Branching

- All features and fixes are implemented in a git worktree, one branch per worktree, and land via pull request. Place the worktree in the session scratchpad on the temp drive.
- The main checkout `$(MAXIM_REPOS_DIR)\lockfile-sentinel` must always stay on `master`. Never switch branches, commit, or edit files in it directly.

## Code and Gates

- Target Python 3.12+ syntax.
- Before any commit, run mypy, pylint, bandit, semgrep, and SonarScanner, and fix every finding, including SonarQube code smells and complexity findings.
- Coordinate with other live sessions through the mcp-router `comm` plugin (channel `lockfile-sentinel`).
