# Lockfile Sentinel 0.2.0

Copyright (c) 2026 Maxim Masiutin. Released under [GPL-3.0-only](LICENSE.txt).

A fast, zero-dependency npm supply-chain scanner. Originally built to detect the Shai-Hulud worm, it now cross-checks lockfiles against the live OSV.dev database to catch a wide range of malicious packages.

Inputs are lockfiles, `package.json` ranges and repository trees by filename, so a poisoning that has already been installed and one that the next install would pull are both reported, and known worm payload artifacts are found by name wherever they sit.

The scanner is one file, the standard library only, and needs Python 3.12 or newer. CI tests 3.12, the floor, on Linux, Windows and macOS, plus Python 3.14 on Linux. Download it and run it.

## Python 3.12 Is a Requirement, Not a Preference

The code uses syntax that older interpreters reject at parse time, so a 3.11 run fails immediately with a syntax error rather than misbehaving later. That is deliberate: a security tool that half-runs on an unsupported interpreter is worse than one that refuses to start.

What it relies on: PEP 604 unions written as `X | None` rather than `Optional[X]`, PEP 695 `type` aliases for the shapes the walk passes around, `TypedDict` for the scheduled-job table so a mistyped key is caught before it reaches Task Scheduler, and `tempfile`, `pathlib` and `concurrent.futures` behaviour as of 3.12. There are no third-party dependencies at all, so nothing else constrains the version.

Static analysis is part of the contract rather than an afterthought. All four shipped programs pass `mypy` with no issues and `pylint` at 10.00/10 against the committed `.pylintrc`, and `bandit` reports nothing over the repository outside `tests/`; the `.pylintrc` records why each disabled check is a property of the design instead of a warning being hidden. The test suite is deliberately outside the `mypy` and `pylint` scope, so "all four" means the four named below rather than every Python file in the tree.

```bash
python -m mypy --python-version 3.12 lockfile_sentinel.py update_scanners.py schedule_tasks.py bump_version.py
python -m pylint lockfile_sentinel.py update_scanners.py schedule_tasks.py bump_version.py
python -m bandit -r . -x ./tests
python -m pytest -q
```

All four run in CI on Python 3.12 across Linux, Windows and macOS, with an additional Python 3.14 Linux job. The scope matches the commands above: `mypy` and `pylint` cover the four named files, `bandit` covers the repository except `tests/`, and `pytest` covers the suite. The floor catches accidental newer syntax on every supported OS; the newest interpreter catches removals and stricter runtime behaviour without multiplying every intermediate version across the OS matrix.

A green tick is worth less than it looks, and the two halves of why are worth separating because only one of them lives in this repository. What the workflow file guarantees is that the checks run: on every pull request, and on a push to `master` after the commit has already landed, where a failing run removes nothing. Whether a failing run *blocks* anything is not in this repository at all. That is branch protection, a setting in the GitHub project rather than a file you can read here, and it differs in a fork, so this paragraph cannot state it and stay true. Check it yourself if it matters; a red run stops a merge only where a required status check says so.

Two more are run by hand against changed files before a merge: `semgrep`, with the `p/python` and `p/security-audit` rule sets, and SonarQube Community Build, whose quality gate has to come back clean. Nothing in the repository enforces either, so they are a practice rather than a gate. That is worth stating because nothing a reader can inspect tells the two apart. They sit outside CI because one needs a rule download and the other a server, and putting them in the workflow would trade a check that always runs for one that fails whenever a network does. If that stops being true they belong in the workflow.

Three of the six can raise a security finding, namely `bandit`, `semgrep` and SonarQube, and the other three speak to consistency and behaviour rather than to security. CI runs exactly one of those three. So a green run means `mypy` and `pylint` found no inconsistency in the four programs, the `pytest` suite passed, and `bandit` reported nothing in the scan it is configured for; it says nothing whatever about `semgrep` or SonarQube.

Two optional companions keep its inputs current and are not needed to scan: `update_scanners.py` builds or updates osv-scanner, refreshes the campaign overlay and the OSV offline database, and refreshes the Trivy databases; `schedule_tasks.py` installs those four jobs on a daily schedule through Windows Task Scheduler or cron, idempotently. Each is standalone too.

## Quick Start

```bash
curl -O https://raw.githubusercontent.com/maximmasiutin/lockfile-sentinel/v0.2.0/lockfile_sentinel.py
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
python lockfile_sentinel.py --json -o findings.json --source-revision "$GITHUB_SHA"
python lockfile_sentinel.py --lockfile path/package-lock.json   # one file, verbosely
python lockfile_sentinel.py --osv source -r ./app         # pass through to osv-scanner
```

Exit codes state coverage, not just findings: 0 means complete requested coverage and nothing found, 1 means complete requested coverage with findings, and 2 means the scan or its requested coverage was incomplete, whether or not findings exist. A requested layer that is missing or partial, an unreadable applicable input, or a report that could not be written all return 2, and the findings gathered before the gap are still in the report. A layer declined with `--no-osv`, `--no-overlay` or `--no-trivy` is a recorded policy choice, never a failure. A check that could not run never reports health.

## Machine-Readable Output

`--json` writes a versioned envelope rather than a bare list. `schema` names the format, `lockfile-sentinel-report` version 1, and a consumer rejects a name or version it does not know rather than guessing; field additions within version 1 are non-breaking. `tool` names the producer and its version. `invocation` records the run's id, start and finish stamps, resolved roots, `--include-node-modules`, and the layers the caller requested, so a layer declined by a `--no-*` flag reads as policy rather than as a layer that broke. A pipeline should pass its checked-out commit with `--source-revision`; the report records the normalized SHA-1 or SHA-256 commit ID, and a consumer should reject a report whose revision differs from the workflow revision. The scanner does not guess from ambient Git state because one invocation may cover multiple roots.

Coverage is data, not prose and not a boolean. `layers` carries one state object per detection layer, `builtin`, `overlay`, `osv` and `trivy`, each with `requested`, a `state` from `completed`, `partial`, `not_requested`, `unavailable` or `failed`, a stable `reason_code`, and the counts and provenance behind it, binary paths and versions, the overlay's digest and generation stamp, submitted and resolved counts, and duration. Each repository carries the same model in `coverage`, with `not_applicable` for a repository the layer had nothing to do in, so non-applicability and failure never share a value and a consumer never reconstructs coverage from other fields. `inputs` and `totals` reconcile the discovered, read, submitted and resolved counts at the top level.

`findings` is the canonical flat array a pipeline consumes: one entry per fact with a stable id, a `kind` from `malicious_resolved`, `malicious_range` or `payload_artifact`, the package and version or range, the evidencing files relative to their repository, advisory ids, a campaign tag where one is known, and every `detection_layers` entry that saw it, so the offline table and OSV flagging the same resolved version is one finding with two layers rather than an equivalence every consumer rediscovers. `errors` is a bounded list of structured entries with stable codes, scope, and a retryable flag; when it is cut, the cut is the last entry.

With `--output` set, in-progress snapshots go to `<output>.partial`, written atomically, and the requested path is written once, atomically, at the end; a consumer polling the final path never sees half-written JSON, and a killed run leaves the partial behind as parseable evidence marked incomplete. Snapshots carry `invocation.complete: false` with a null finish stamp. The final report sets the finish stamp and sets `complete` true only when every requested layer completed over every input, so a finished run with a coverage gap is `complete: false` with exit 2. On success the partial is removed. The format is pinned by `lockfile-sentinel-report.schema.json`, with a worked example in `lockfile-sentinel-report.example.json`; `--status --json` emits its own document, `lockfile-sentinel-status` version 1, pinned by `lockfile-sentinel-status.schema.json`, whose exit codes (0 fresh, 1 stale, 2 unknown) are documented apart from the scan's. Plain status mode makes no network request; `--status --check-live` adds one explicit probe of api.osv.dev and reports reachability and latency.

Child-tool JSON is retained in memory up to 128 MiB per invocation while stdout and stderr are drained concurrently; stderr retains only its final 1 MiB. Exceeding the JSON limit terminates the child and records `child_output_too_large` as incomplete coverage rather than truncating the document or treating it as zero findings. No temporary file or directory is involved.

## Which Lockfiles Are Scanned

Five filenames, matched exactly: `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` and `bun.lock`. Any of those five, or a `package.json`, marks a repository as having npm tooling at all, which is what separates "no npm here" from "npm, but no lockfile" in the report; a repository holding a lockfile and no manifest still counts.

Each of the five gets the format-agnostic text pass, and the two npm-schema files, `package-lock.json` and `npm-shrinkwrap.json`, get a structural JSON pass on top of it, which is what catches an entry pinning a version with no `resolved` URL. `bun.lock` is JSONC rather than JSON, so it gets the text pass alone; its resolution strings carry the `name@version` tokens the patterns match. Coverage of Bun mattered enough to state its reason: the Shai-Hulud payload marker is `bun_environment.js`, and a scanner that finds the Bun payload by filename had no business walking past Bun's lockfile, which it did until this section's own gap was closed.

Comments are stripped before the text pass in the three formats that admit them: the `//` and `/* */` pair in `bun.lock`, and `#` line comments in `yarn.lock` and `pnpm-lock.yaml`. A comment installs nothing, so a commented-out entry naming a poisoned version is not a pin the tree contains. The stripping is string-aware in both dialects, and the `#` form follows YAML's rules rather than splitting on the marker, which is what keeps the `.tgz#<sha>` fragment of a resolved URL part of the line the tarball patterns match.

Where `npm-shrinkwrap.json` and `package-lock.json` coexist, both are scanned, deliberately, although npm itself would ignore the lock and install from the shrinkwrap. The scanner's subject is poisoned pins wherever they sit, not the one tree the next `npm install` would build: a stale lock naming a poisoned version means the repository pinned that version at some point, which is worth a human look, and every finding names the file that produced it so the reader can weigh the shadowing. Suppressing the shadowed file would also hand an attacker a silencer, since dropping a clean shrinkwrap beside a poisoned lock would end the reporting on a file still in the tree. `yarn.lock` beside either gets the same treatment for the same reason.

No lockfile from a non-npm ecosystem is read. A `Cargo.lock` or `composer.lock` repository is outside this scanner's subject, and reporting it as not vulnerable would claim a verdict about an ecosystem nothing here examines.

The payload artifact match by filename is applied to every file the walk visits, whatever else that file is. It reaches only as far as the walk does: `.git` is always skipped, `node_modules` unless `--include-node-modules` is given, and a symlinked directory or one that cannot be read is skipped too. That default matters more than it looks, because `bun_environment.js` is written on install, which puts it inside `node_modules`, so the marker most likely to be present is the one a default sweep does not reach. Pass `--include-node-modules` when the question is whether the payload landed. The declared range check against the offline table needs a `package.json`, so a repository committing none does not get it.

Every repository with npm tooling carries a `read:` line naming the manifests and lockfiles that were opened, as paths relative to that repository, so the enumeration can be checked against the tree rather than taken on trust. A file that was found and could not be read is named separately rather than listed as read, long lists are capped, and the remainder is counted rather than dropped.

`--lockfile` and `--lockfiles-from` bypass the name check entirely and check whatever path they are given, so an unscanned format can be checked by hand. Both layers run and each file's line names the one that spoke, so a version the offline table knows is reported whether or not the live database has caught up, and the offline table runs even where osv-scanner is absent. Diagnosis mode has its own exit codes: 1 when anything was found or any file could not be read or extracted, 0 when every file was read, extracted and came back clean, and 2 when nothing was found but a layer that should have run did not, such as an osv-scanner that is absent or times out. `--no-osv` is a deliberate scoping rather than a failure, so a clean run under it returns 0; a requested live layer that could not run returns 2, in diagnosis mode and in the sweep alike.

```bash
python lockfile_sentinel.py --lockfile path/npm-shrinkwrap.json
```

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

## Releasing

The version is written in four kinds of place: the header line of every Python file, the `__version__` of every program, the title of this file and the tag pinned in the quick-start URL above. It is duplicated rather than imported because each program has to work when it is copied out on its own, and an import would tie a standalone copy back to a checkout it may not have.

`bump_version.py` is what sets them, and `tests/test_headers.py` is what refuses a release where one was missed:

```bash
python bump_version.py --check       # do they all agree?
python bump_version.py --dry-run 0.2.0
python bump_version.py 0.2.0
python bump_version.py --minor       # or step the current version
git tag v0.2.0
```

A site that matches nothing is an error rather than a silent skip, because a pattern that has stopped matching looks exactly like a project that is already correct. The changelog is never rewritten: its headings are the record of what was released, so the new version must already have a section there, and the bump stops if it does not.

## Cache

The campaign overlay and fetched advisories live in the platform cache directory, or in `LOCKFILE_SENTINEL_CACHE` when set. Nothing is written beside the script.

## Licence

Copyright (c) 2026 Maxim Masiutin.

GPL-3.0-only. See [LICENSE.txt](LICENSE.txt). Every source file carries the same notice in its header, alongside the program name and the version it belongs to, so a copy that has been separated from this repository still says what it is and what governs it.

Running the scanner puts you under no obligation, and its output is yours. Copyleft attaches to passing the program on, so scanning a proprietary repository with it creates no obligation for that repository whatsoever. If you redistribute the file on its own, section 4 asks that the licence text go with it.

This project is not affiliated with, endorsed by, or connected to OSV.dev, Google, Aqua Security, or any vendor whose product name resembles this one.
