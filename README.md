# lockfile-sentinel

A fast, zero-dependency npm supply-chain scanner. Originally built to detect the Shai-Hulud worm, it now cross-checks lockfiles against the live OSV.dev database to catch a wide range of malicious packages.

Inputs are lockfiles, `package.json` ranges and repository trees by filename, so a poisoning that has already been installed and one that the next install would pull are both reported, and known worm payload artifacts are found by name wherever they sit.

The scanner is one file, the standard library only, Python 3.12 or newer. Download it and run it.

## Python 3.12 Is a Requirement, Not a Preference

The code uses syntax that older interpreters reject at parse time, so a 3.11 run fails immediately with a syntax error rather than misbehaving later. That is deliberate: a security tool that half-runs on an unsupported interpreter is worse than one that refuses to start.

What it relies on: PEP 604 unions written as `X | None` rather than `Optional[X]`, PEP 695 `type` aliases for the shapes the walk passes around, `TypedDict` for the scheduled-job table so a mistyped key is caught before it reaches Task Scheduler, and `tempfile`, `pathlib` and `concurrent.futures` behaviour as of 3.12. There are no third-party dependencies at all, so nothing else constrains the version.

Static analysis is part of the contract rather than an afterthought. The three files pass `mypy` with no issues, `pylint` at 10.00/10 against the committed `.pylintrc`, and `bandit` with no findings; the `.pylintrc` records why each disabled check is a property of the design instead of a warning being hidden.

```bash
python -m mypy --python-version 3.12 lockfile_sentinel.py update_scanners.py schedule_tasks.py
python -m pylint lockfile_sentinel.py update_scanners.py schedule_tasks.py
python -m bandit -r . -x ./tests
python -m pytest -q
```

Two optional companions keep its inputs current and are not needed to scan: `update_scanners.py` builds or updates osv-scanner, refreshes the campaign overlay and the OSV offline database, and refreshes the Trivy databases; `schedule_tasks.py` installs those four jobs on a daily schedule through Windows Task Scheduler or cron, idempotently. Each is standalone too.

## Quick Start

```bash
curl -O https://raw.githubusercontent.com/maximmasiutin/lockfile-sentinel/v0.1.0/lockfile_sentinel.py
python lockfile_sentinel.py --selftest
python lockfile_sentinel.py --root /path/to/repositories
```

`--selftest` is worth running first. It writes a lockfile pinning two packages with published malicious-package advisories into a temporary directory, scans it, asserts both are reported, and deletes it. A scanner that reports nothing looks exactly like a scanner that is broken, and the self-test is what tells the two apart.

For the live cross-check, install [osv-scanner](https://github.com/google/osv-scanner) and put it on `PATH`. Without it the offline layer still runs.

## What It Reports

Three tiers per repository, so a clean answer distinguishes "no npm here at all" from "npm, but the watched packages are absent" from "present and poisoned".

Every finding names the layer that produced it. The offline table matches text, needs no network and is the only layer that can flag a declared range that has not been installed yet. The live OSV.dev database resolves the whole dependency tree, so it is the only layer that sees a transitive dependency, and it runs only where a lockfile exists.

Every repository with npm tooling also carries a coverage line, which is the part that matters most: a repository with no verdict from the live database is not a repository the live database called clean, and the report says which happened and why.

Where a finding belongs to a known campaign, the campaign is named rather than described as "not Shai-Hulud". Where Trivy is installed, the individual lockfiles that produced a finding are re-checked against it, and a Trivy match is reported as independent confirmation. Trivy silence is reported as exactly that and never weakens a finding, because Trivy's npm feed carries no malicious-package advisories at all.

## Usage

```bash
python lockfile_sentinel.py --root .                      # sweep one tree
python lockfile_sentinel.py --root a --root b --jobs 16   # several, in parallel
python lockfile_sentinel.py --status                      # what is current, scan nothing
python lockfile_sentinel.py --json -o findings.json       # machine-readable
python lockfile_sentinel.py --lockfile path/package-lock.json   # one file, verbosely
python lockfile_sentinel.py --osv source -r ./app         # pass through to osv-scanner
```

Exit codes are 0 when nothing was found, 1 when something was, and 2 when the scan could not be performed. A check that could not run never reports health.

## A Repository With No Lockfile

This is the question worth answering before you rely on a clean result, because the answer is not the reassuring one.

The scanner does not resolve dependencies. It installs nothing, contacts no registry, and expands no dependency tree. Where a repository commits only `package.json` and no lockfile, the live OSV.dev cross-check does not run at all, and the report says so on that repository's coverage line rather than leaving it to be assumed.

What still happens without a lockfile is narrower than it sounds. Declared ranges in `package.json` are compared against the offline table of package versions already known to be malicious, so a direct dependency whose range could resolve to one of those is reported, which is the only way to warn about a poisoning the next install would pull. Payload artifacts are still found by filename anywhere in the tree.

What does not happen is everything else. Transitive dependencies are invisible, because nothing resolves them. A malicious package the offline table does not already name is invisible, because the layer that would have caught it needs a lockfile. So a repository with no lockfile reported as not vulnerable means only that nothing known was declared in its manifest.

If you need a verdict for such a repository, generate a lockfile first and scan that:

```bash
npm install --package-lock-only --ignore-scripts
python lockfile_sentinel.py --root .
```

`--ignore-scripts` matters here: resolving a tree that may pin a compromised package should not run that package's install hooks.

## Limits

These are properties of the current code, stated because a scanner's blind spots matter more than its features. All of them under-report rather than over-report.

`node_modules` is not walked unless `--include-node-modules` is given. Declared and resolved versions are still found, but an installed payload artifact inside `node_modules` is exactly where the worm writes it. Use the flag when the question is "did this machine execute it" rather than "is this tree pinned to it".

The range test understands `*`, `latest`, `next`, an exact version, and the `^`, `~`, `>=` and `>` prefixes. Compound ranges, `||` alternations, hyphen ranges and `x`-wildcards are reported as not reachable even where they are, so that finding is a floor rather than a complete answer. Resolved versions and the live cross-check are unaffected.

Version comparison uses the leading `major.minor.patch` only, so a prerelease suffix is ignored for ordering.

A lockfile the scanner cannot extract is reported by name with the reason, never skipped silently.

## Cache

The campaign overlay and fetched advisories live in the platform cache directory, or in `LOCKFILE_SENTINEL_CACHE` when set. Nothing is written beside the script.

## Licence

GPL-3.0-only. See [LICENSE.txt](LICENSE.txt).

Running the scanner puts you under no obligation, and its output is yours. Copyleft attaches to passing the program on, so scanning a proprietary repository with it creates no obligation for that repository whatsoever. If you redistribute the file on its own, section 4 asks that the licence text go with it.

This project is not affiliated with, endorsed by, or connected to OSV.dev, Google, Aqua Security, or any vendor whose product name resembles this one.
