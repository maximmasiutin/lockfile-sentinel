# Changelog

All notable changes are recorded here. Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html), and each release is tagged so a raw file URL can be pinned to it.

## 0.2.0

### Changed

- Breaking change to `--json`: it now emits a versioned envelope object instead of a bare per-repository array. The array moved unchanged to the `repositories` field; `schema` names the format (`lockfile-sentinel-report`, version 1), `tool` names the producer and its version, and `invocation` records the run's id, start and finish stamps, resolved roots, `--include-node-modules`, and the requested layers, so a `--no-*` flag reads as policy rather than as a layer that broke. The in-progress writes made after the walk and after each OSV batch carry `invocation.complete: false` with a null finish stamp, and only the final write sets `complete: true`, so a report left by a killed run can no longer be mistaken for a final one. Field additions within schema version 1 are non-breaking; a consumer rejects a schema name or version it does not know rather than guessing.

- Breaking change to scan exit codes: 0 and 1 now assert complete requested coverage as well as the finding count, and anything short of that returns 2 even when findings exist, which are still present in the report. A requested-but-missing osv-scanner, a rejected or unsubmitted lockfile, an unreadable applicable input, a stale overlay after a failed refresh, and a report that could not be written all return 2. Layers declined with `--no-osv`, `--no-overlay` or `--no-trivy` are recorded policy choices, not failures.
- With `--output`, in-progress snapshots now go to `<output>.partial` and the requested path is written once, atomically, on completion, so a consumer of the final path can never read a mid-run report; the partial is removed on success and left behind by a killed run as parseable incomplete evidence. All report and summary writes are atomic (temp file, fsync, rename). An empty lockfile now counts as resolved rather than as a permanent coverage gap, matching the verdict osv-scanner itself gives one.
- Overlay refreshes are serialised through a lock file beside the overlay that the operating system itself releases when its holder exits (a non-blocking `fcntl.flock` on POSIX, a delete-on-close exclusive create on Windows), and the overlay is written atomically, so concurrent runs cannot interleave writes and no staleness heuristic exists to race.

### Added

- Per-layer state objects under `layers` (`builtin`, `overlay`, `osv`, `trivy`), each with `requested`, `state` (`completed`, `partial`, `not_requested`, `unavailable`, `failed`), a stable `reason_code`, counts, binary paths and versions, the overlay digest, and durations; per-repository `coverage` objects with the same vocabulary plus `not_applicable`, carrying discovered, readable, submitted, resolved and failed counts, so a consumer never reconstructs coverage from booleans or prose.
- A canonical `findings` array: one entry per fact with a stable derived id, kind (`malicious_resolved`, `malicious_range`, `payload_artifact`), package, version or range, evidencing files relative to the repository, advisory ids, Trivy confirmations, campaign tag, and every detection layer that saw it, so the same version flagged by the offline table and OSV is one finding with two layers.
- A bounded structured `errors` array with stable codes (`manifest_unreadable`, `lockfile_unreadable`, `osv_submission_failed`, `binary_not_found`, `trivy_failed`, and others), scope, and a retryable flag; a truncated list says so in its last entry.
- `--status --json`, a machine-readable status document (`lockfile-sentinel-status` version 1) with semantic parity to the human status report: tool and database versions and paths, ages and thresholds in seconds, a state per source and an overall state with its exit code. `--status --check-live` adds one explicit probe of api.osv.dev; plain status mode never touches the network.
- `lockfile-sentinel-report.schema.json`, a JSON Schema for the report, and `lockfile-sentinel-report.example.json`, a worked example, both pinned to the renderer by tests; `lockfile-sentinel-status.schema.json` for the status document, pinned likewise.

### Fixed

- A commented-out entry in `yarn.lock` or `pnpm-lock.yaml` no longer registers as a resolved pin. Both formats admit `#` line comments and the text pass matched raw text, so a commented poisoned `name@version` reported a repository vulnerable for a version its tree does not contain. Stripping follows YAML's own rules rather than splitting on the marker: a `#` opens a comment only at the start of a line or after whitespace, which leaves the `.tgz#<sha>` fragment ending a resolved URL part of the line the tarball patterns match; a `#` inside either quote style is data; and a quote opens a string only where a value may start, so an apostrophe in a bare scalar cannot shield the comment behind it. `bun.lock` already had this for its JSONC comments, and the three text formats now agree on what a comment is.

- A Trivy binary upgrade now makes the cached databases due regardless of their future `NextUpdate` stamps: the binary version that wrote each promoted cache is recorded, a mismatch forces exactly one refresh, and `status` reports the mismatch as stale, so an air-gapped host learns about a schema the new binary cannot read from the updater instead of from an obscure scan error. The metadata's own schema version is carried through freshness reporting instead of being discarded.

- A refresh with nowhere to stage is refused before the download, exiting 2 with every candidate base and its free-space figure, instead of proceeding into the size-unchecked system temporary directory and dying a gigabyte later on an obscure write error from inside Trivy.
- A missing cache parent no longer disqualifies the cache volume as a scratch base: it is created up front, as promotion would have moments later, so a first run on a fresh host stages on the roomy volume instead of falling through to the small one.
- A refresh whose scratch directory could not be removed exits 3, distinct from success and from failure, so a scheduled run turns amber instead of leaking up to a gigabyte per night behind an exit 0; pre-existing `temp-*` leftovers in the chosen base are counted and reported at the start of each run.

- Trivy database promotion is recoverable across filesystems: the staged cache is brought onto the destination volume as an `.incoming` sibling before the live cache is touched, every step after that copy is an atomic rename, and a failed final swap renames the previous cache straight back, so the live cache is never left absent or half written.
- `--skip-java-db` no longer deletes the cached Java index: promotion carries a database the run deliberately skipped forward from the outgoing cache by rename, so the flag now costs nothing instead of a re-download on the following run.
- The scratch free-space requirement is derived from the databases the run will actually stage, so a vulnerability-only refresh no longer demands the full 5 GB and no longer falls through to the unchecked system temporary directory on a base that had ample room.

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
