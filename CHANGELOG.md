# Changelog

All notable changes are recorded here. Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html), and each release is tagged so a raw file URL can be pinned to it.

## 0.1.0

First public release.

### Added

- Three-tier repository sweep: whether npm tooling exists, whether a watched package is present in any version, and whether a present or reachable version is a known malicious one.
- Live cross-check of every discovered lockfile against the OSV.dev malicious-package database through osv-scanner, batched, with a failing batch isolated by binary search so one unreadable lockfile cannot cost the other ninety-nine.
- Campaign attribution: a finding names the campaign behind it, taken from the advisory's own text, instead of being labelled as unrelated to the campaign someone happened to be looking for.
- Coverage reporting: every repository with npm tooling states whether the live database ran against it and, when it did not, why. A repository with no verdict is not a repository that was called clean.
- Trivy corroboration for the lockfiles that produced a finding, reported as independent confirmation when Trivy agrees and as nothing at all when Trivy is silent, because its npm feed carries no malicious-package advisories.
- Payload artifact detection by filename anywhere in a scanned tree.
- `--selftest`, which writes a control lockfile pinning two packages with published advisories to a temporary directory, asserts both layers report them, and deletes it.
- `--status`, reporting what each input is and how old it is, with exit 1 for stale and 2 for unknown.
- `--lockfile` and `--lockfiles-from`, which submit named lockfiles one at a time with the full scanner output, for investigating an extraction failure without re-walking a tree.
- Parallel directory walking with `--jobs`, and progress reporting with percentage, elapsed time and an estimate against a repository count taken in a first pass.
- Campaign overlay refreshed from the consolidated indicator feed, throttled by the overlay's own age, cached outside the repository.
- `update_scanners.py`, one program with four targets: build or update osv-scanner, refresh the campaign overlay from the consolidated indicator feed, refresh the OSV offline database, and refresh the Trivy vulnerability and Java databases. Each target self-throttles, every download is scanned with ClamAV where ClamAV is installed, and `status` reports the age of all four without changing any.
- `schedule_tasks.py`, which installs those four as daily jobs through Windows Task Scheduler or cron, idempotently, with staggered start times and a random spread.
- Nothing is written beside the scripts. Logs, state and downloaded databases live under the cache directory, which is `LOCKFILE_SENTINEL_CACHE` when set.
- `--show-cron` on the scheduler, which renders the crontab block that would be installed, on any platform, so a system-wide schedule can be reviewed before it is written.
- Released under GPL-3.0-or-later.
