# Changelog

All notable changes are recorded here. Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html), and each release is tagged so a raw file URL can be pinned to it.

## 0.2.0

### Changed

- Breaking change to `--json`: it now emits a versioned envelope object instead of a bare per-repository array. The array moved unchanged to the `repositories` field; `schema` names the format (`lockfile-sentinel-report`, version 1), `tool` names the producer and its version, and `invocation` records the run's id, start and finish stamps, resolved roots, `--include-node-modules`, and the requested layers, so a `--no-*` flag reads as policy rather than as a layer that broke. The in-progress writes made after the walk and after each OSV batch carry `invocation.complete: false` with a null finish stamp, and only the final write sets `complete: true`, so a report left by a killed run can no longer be mistaken for a final one. Field additions within schema version 1 are non-breaking; a consumer rejects a schema name or version it does not know rather than guessing.

- Breaking change to scan exit codes: 0 and 1 now assert complete requested coverage as well as the finding count, and anything short of that returns 2 even when findings exist, which are still present in the report. A requested-but-missing osv-scanner, a rejected or unsubmitted lockfile, an unreadable applicable input, a stale overlay after a failed refresh, and a report that could not be written all return 2. Layers declined with `--no-osv`, `--no-overlay` or `--no-trivy` are recorded policy choices, not failures.
- With `--output`, in-progress snapshots now go to `<output>.partial` and the requested path is written once, atomically, on completion, so a consumer of the final path can never read a mid-run report; the partial is removed on success and left behind by a killed run as parseable incomplete evidence. All report and summary writes are atomic (temp file, fsync, rename). An empty lockfile now counts as resolved rather than as a permanent coverage gap, matching the verdict osv-scanner itself gives one.
- Overlay refreshes are serialised through the operating system's advisory lock on a file beside the overlay (`msvcrt.locking` on Windows, `fcntl.flock` elsewhere), and the overlay is written atomically, so concurrent runs cannot interleave writes; the kernel admits exactly one holder and releases the lock when its holder exits, so no staleness heuristic exists to race.

### Added

- Per-layer state objects under `layers` (`builtin`, `overlay`, `osv`, `trivy`), each with `requested`, `state` (`completed`, `partial`, `not_requested`, `unavailable`, `failed`), a stable `reason_code`, counts, binary paths and versions, the overlay digest, and durations; per-repository `coverage` objects with the same vocabulary plus `not_applicable`, carrying discovered, readable, submitted, resolved and failed counts, so a consumer never reconstructs coverage from booleans or prose.
- A canonical `findings` array: one entry per fact with a stable derived id, kind (`malicious_resolved`, `malicious_range`, `payload_artifact`), package, version or range, evidencing files relative to the repository, advisory ids, Trivy confirmations, campaign tag, and every detection layer that saw it, so the same version flagged by the offline table and OSV is one finding with two layers.
- A bounded structured `errors` array with stable codes (`manifest_unreadable`, `lockfile_unreadable`, `osv_submission_failed`, `binary_not_found`, `trivy_failed`, and others), scope, and a retryable flag; a truncated list says so in its last entry.
- `--status --json`, a machine-readable status document (`lockfile-sentinel-status` version 1) with semantic parity to the human status report: tool and database versions and paths, ages and thresholds in seconds, a state per source and an overall state with its exit code. `--status --check-live` adds one explicit probe of api.osv.dev; plain status mode never touches the network.
- `lockfile-sentinel-report.schema.json`, a JSON Schema for the report, and `lockfile-sentinel-report.example.json`, a worked example, both pinned to the renderer by tests; `lockfile-sentinel-status.schema.json` for the status document, pinned likewise.

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
- `--path-var` on the scheduler, which writes Windows task paths through an environment variable, so moving the checkout means updating one variable rather than re-registering every task.
- Released under GPL-3.0-only.
