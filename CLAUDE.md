# lockfile-sentinel

## Branching

- All features and fixes are implemented in a git worktree (`.claude/worktrees/`), one branch per worktree, and land via pull request.
- The main checkout `$(MAXIM_REPOS_DIR)\lockfile-sentinel` must always stay on `master`. Never switch branches, commit, or edit files in it directly.
