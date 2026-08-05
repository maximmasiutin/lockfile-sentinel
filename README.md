# lockfile-sentinel

A fast, zero-dependency npm supply-chain scanner. Originally built to detect the Shai-Hulud worm, it now cross-checks lockfiles against the live OSV.dev database to catch a wide range of malicious packages.

Inputs are lockfiles, `package.json` ranges and repository trees by filename, so a poisoning that has already been installed and one that the next install would pull are both reported, and known worm payload artifacts are found by name wherever they sit.

One file, the standard library only, Python 3.12 or newer. Download it and run it.

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

## Limits

These are properties of the current code, stated because a scanner's blind spots matter more than its features. All of them under-report rather than over-report.

`node_modules` is not walked unless `--include-node-modules` is given. Declared and resolved versions are still found, but an installed payload artifact inside `node_modules` is exactly where the worm writes it. Use the flag when the question is "did this machine execute it" rather than "is this tree pinned to it".

The range test understands `*`, `latest`, `next`, an exact version, and the `^`, `~`, `>=` and `>` prefixes. Compound ranges, `||` alternations, hyphen ranges and `x`-wildcards are reported as not reachable even where they are, so that finding is a floor rather than a complete answer. Resolved versions and the live cross-check are unaffected.

Version comparison uses the leading `major.minor.patch` only, so a prerelease suffix is ignored for ordering.

A lockfile the scanner cannot extract is reported by name with the reason, never skipped silently.

## Cache

The campaign overlay and fetched advisories live in the platform cache directory, or in `LOCKFILE_SENTINEL_CACHE` when set. Nothing is written beside the script.

## Licence

GPL-3.0-or-later. See [LICENSE.txt](LICENSE.txt).

Running the scanner puts you under no obligation, and its output is yours. Copyleft attaches to passing the program on, so scanning a proprietary repository with it creates no obligation for that repository whatsoever. If you redistribute the file on its own, section 4 asks that the licence text go with it.

This project is not affiliated with, endorsed by, or connected to OSV.dev, Google, Aqua Security, or any vendor whose product name resembles this one.
