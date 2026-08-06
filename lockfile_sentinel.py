"""lockfile-sentinel: an npm supply-chain scanner in one file.

A fast, zero-dependency npm supply-chain scanner. Originally built to detect the
Shai-Hulud worm, it now cross-checks lockfiles against the live OSV.dev database
to catch a wide range of malicious packages.

Inputs are lockfiles, package.json ranges and repository trees by filename, so a
poisoning that has been installed and one that the next install would pull are
both reported, and worm payload artifacts are found by name wherever they sit.

Reports, per repository (a directory containing a .git entry, or a
top-level directory under a scanned root when no .git is present):

1. Does npm/pnpm/yarn tooling exist at all (package.json or a lockfile)?
2. If yes, is any watched package (keyv, cacheable, and related) present
   in any version at all, declared or resolved?
3. If yes, is any version present or reachable the actual poisoned one?

Also flags known worm payload artifact filenames anywhere in the tree.

Two independent detection layers feed tier 3:

- A small built-in table of packages/scopes known poisoned at the time
  this script was written, checked against lockfile text and package.json
  ranges with no external dependency.
- OSV-Scanner (https://github.com/google/osv-scanner), if found on PATH
  (or via --osv-scanner-bin / the OSV_SCANNER_BIN environment variable),
  run once per batch of discovered lockfiles and cross-checked against its
  live malicious-package (MAL-*) database. This is the authoritative
  layer: it covers the full campaign, not just the packages hardcoded
  below, and resolves the whole dependency tree (direct and transitive)
  from each lockfile. It is looked up in this order: --osv-scanner-bin,
  OSV_SCANNER_BIN, a Go build under GOBIN or GOPATH/bin, PATH, then
  ~/go/bin, which resolves on Windows, Linux and macOS alike. The Go
  location is preferred over PATH so a build made by
  update_scanners.py wins over an older packaged copy. It is invoked only with
  the exact lockfile paths this script already found relevant, never
  pointed at a directory to walk on its own.

Before sweeping it refreshes the campaign overlay, throttled, so the offline
table stays current without a download on every run. --no-refresh skips it.

--osv passes everything after it straight to `osv-scanner scan` and exits with
its code, for an ad-hoc scan that has nothing to do with the campaign sweep.

--selftest proves the detector still detects: it writes a lockfile pinning two
packages with published malicious-package advisories into a temporary directory,
scans it, asserts both are reported, and deletes it. A scanner that reports
nothing is indistinguishable from a scanner that is broken, which is what the
self-test exists to tell apart.

One file, standard library only, Python 3.12 or newer. It runs on Windows, Linux
and macOS, and needs osv-scanner only for the live cross-check.

Usage:
    python lockfile_sentinel.py --root /path/to/repos
    python lockfile_sentinel.py --root . --include-node-modules
    python lockfile_sentinel.py --selftest
    python lockfile_sentinel.py --status
    python lockfile_sentinel.py --no-osv
    python lockfile_sentinel.py --json -o findings.json
    python lockfile_sentinel.py --lockfile path/to/package-lock.json
    python lockfile_sentinel.py --osv source -r /path/to/app
"""

# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Maxim Masiutin
# https://github.com/maximmasiutin/lockfile-sentinel
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <https://www.gnu.org/licenses/>.
#
# This file is meant to be copied and run on its own, so it carries its own
# licence and its own way home: an orphaned copy can be traced back here to
# check whether a newer one exists, which is the same problem --version solves
# from the other end. Section 4 of the licence asks that a copy of the licence
# text accompany the program when it is passed on, and the repository above is
# where that copy lives.

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import time
import urllib.request
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

__version__ = "0.1.0"

# name -> every version known poisoned for that package. This built-in table is
# the offline floor, and the campaign overlay fetched from the indicator feed is
# merged over it at startup (see load_overlay and refresh_overlay).
POISONED_VERSIONS: dict[str, list[str]] = {
    "keyv": ["6.0.0"],
    "cacheable": ["2.5.1"],
    "cacheable-request": ["13.0.20"],
    "cache-manager": ["7.2.10"],
    "flat-cache": ["6.1.24"],
    "file-entry-cache": ["11.1.7"],
    "@cacheable/memory": ["2.2.1"],
    "@cacheable/net": ["2.1.1"],
    "@cacheable/node-cache": ["3.1.2"],
    "@cacheable/utils": ["2.5.1"],
}

OVERLAY_NAME = "compromised-npm-packages.json"


def format_elapsed(seconds: float) -> str:
    """Render a duration as mm:ss, or h:mm:ss once it passes an hour."""
    if seconds < 0:
        return "N/A"
    if seconds >= 3600:
        return f"{int(seconds) // 3600:d}:{(int(seconds) % 3600) // 60:02d}:{int(seconds) % 60:02d}"
    return f"{int(seconds) // 60:02d}:{int(seconds) % 60:02d}"


def cache_dir() -> Path:
    """Where the refreshed campaign overlay and fetched advisories are kept.

    A generated database belongs in a cache directory rather than beside the
    script, so this honours LOCKFILE_SENTINEL_CACHE, then the platform cache
    location, and creates nothing until something is written."""
    explicit = os.environ.get("LOCKFILE_SENTINEL_CACHE")
    if explicit:
        return Path(explicit)
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "lockfile-sentinel"
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "lockfile-sentinel"


def default_overlay_path() -> Path:
    """The campaign overlay inside the cache directory."""
    return cache_dir() / OVERLAY_NAME


OVERLAY_PATH = default_overlay_path()
EXE_NAME = "osv-scanner.exe" if os.name == "nt" else "osv-scanner"

# The consolidated, multi-vendor indicator feed for the Shai-Hulud campaign,
# which dedupes reporting from several vendors into one CSV. It is fetched
# directly rather than vendored, so the overlay is as current as the feed.
IOC_FEED_URL = (
    "https://raw.githubusercontent.com/DataDog/indicators-of-compromise/"
    "main/shai-hulud-2.0/consolidated_iocs.csv"
)

POISONED_SCOPES: dict[str, str] = {
    "@keyv/": "6.0.0",
}

# One-line explanation and remediation per known OSV malicious-package (MAL-*)
# advisory, so the vulnerable-repo summary says what each hit actually is
# instead of just an advisory id. Every note opens by naming the thing itself,
# the campaign or the mechanism, never by naming a campaign the package does
# not belong to: a reader who is told what a hit is not still has to go and
# find out what it is. The negated form also fed the campaign matcher below the
# word it searches for, so a note reading "not Shai-Hulud" matched as
# Shai-Hulud whenever the OSV lookup was unavailable.
ADVISORY_NOTES: dict[str, str] = {
    "MAL-2026-11524": (
        "SHAI-HULUD: trojanized keyv 6.0.0, preinstall credential stealer (2026-08-04). "
        "Remove or downgrade at once and rotate every reachable credential."
    ),
    "MAL-2026-11963": (
        "SHAI-HULUD: trojanized cacheable 2.5.1, preinstall credential stealer (2026-08-04). "
        "Remove or downgrade at once and rotate every reachable credential."
    ),
    "MAL-2023-462": (
        "Hijacked build-artifact bucket, April 2023. fsevents 1.0.0-1.2.10 fetched a pre-built "
        "macOS binary from a cloud bucket that a third party took over to serve info-gathering code. The "
        "bucket was suspended 2023-04-27, so the delivery vector is dead and a new install "
        "today gets no malicious binary. fsevents is an optional macOS-only native dependency, "
        "never installed on Windows or Linux, and is almost always pulled in transitively by "
        "old build tooling (chokidar, webpack, watchpack). Remediation is hygiene: upgrade the "
        "chain to fsevents 2.x. Fixed in 1.2.11."
    ),
    "MAL-2025-21003": (
        "Registry name-squat hold. The npm package named 'fs' at 0.0.1-security is an inert "
        "security-hold placeholder stub with no functional code; Node's real fs is a built-in "
        "module. Remediation is to remove the stray dependency."
    ),
}

# Campaign names, most specific first, matched against the text of an OSV
# advisory. The point is to answer "what is this": every hit gets the name of
# the campaign or mechanism it belongs to, and where no campaign name is
# recoverable the advisory's own summary stands in, which still says what the
# package is.
#
# The taxonomy is public reporting as of 2026-08-05, and the Shai-Hulud
# generations are distinct enough to be worth separating: they differ in payload
# and in what they steal, so the remediation differs too.
#
#   https://unit42.paloaltonetworks.com/npm-supply-chain-attack/
#   https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/
#   https://www.stepsecurity.io/blog/shai-hulud-here-we-go-again-mass-npm-supply-chain-attack-hits-the-antv-ecosystem
#   https://www.tenable.com/blog/mini-shai-hulud-frequently-asked-questions
#   https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack
CAMPAIGN_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"mini[\s-]*shai[\s-]*hulud", "Mini Shai-Hulud, the fourth generation, active since April 2026"),
    (r"sha1[\s-]*hulud", "SHA1-Hulud, the second generation of November 2025, which added a wiper"),
    (r"sandworm[_\s-]*mode", "Shai-Hulud SANDWORM_MODE, the variant that enumerates CI/CD before propagating"),
    (r"third\s+coming", "Shai-Hulud: The Third Coming, the wave that began 2026-04-22"),
    (r"here\s+we\s+go\s+again", "Shai-Hulud: Here We Go Again, the wave of 2026-08-04"),
    (r"miasma[\s-]*train", "miasma-train-p1, the AsyncAPI release-pipeline compromise of 2026-07-14"),
    (r"\bmiasma\b", "Miasma, the @redhat-cloud-services namespace compromise of 2026-06-01"),
    (r"shai[\s-]*hulud", "Shai-Hulud, the self-propagating npm worm first seen in September 2025"),
    (r"\bteampcp\b", "TeamPCP, the group behind the Shai-Hulud family"),
)

PAYLOAD_FILENAMES: frozenset[str] = frozenset(
    {
        "math_init.js",
        "Math_Symbol.js",
        "bun_environment.js",
        "setup_bun.js",
        "cloud.json",
        "contents.json",
        "truffleSecrets.json",
    }
)

NPM_MARKER_FILES: frozenset[str] = frozenset(
    {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}
)
LOCKFILE_NAMES: frozenset[str] = frozenset(
    {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"}
)
ALWAYS_SKIP_DIRS: frozenset[str] = frozenset({".git"})
DEPENDENCY_FIELDS: tuple[str, ...] = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)


@dataclass
class RepoStatus:
    """Shai-Hulud exposure status for one repository."""

    name: str
    path: str
    has_npm: bool = False
    npm_files: list[str] = field(default_factory=list)
    lockfiles: list[str] = field(default_factory=list)
    present_versions: dict[str, set[str]] = field(default_factory=dict)
    range_only: dict[str, set[str]] = field(default_factory=dict)
    poisoned_versions: dict[str, set[str]] = field(default_factory=dict)
    poisoned_ranges: dict[str, set[str]] = field(default_factory=dict)
    payload_files: list[str] = field(default_factory=list)
    osv_checked: bool = False
    # How many of this repository's lockfiles the live database actually
    # resolved. osv_checked is true only when that equals all of them, and this
    # count is what lets the coverage line say "3 of 4" rather than implying
    # none succeeded when one merely failed.
    osv_resolved_count: int = 0
    osv_malicious: dict[str, set[str]] = field(default_factory=dict)
    osv_advisory_ids: dict[str, set[str]] = field(default_factory=dict)
    trivy_checked: bool = False
    trivy_confirmed: dict[str, set[str]] = field(default_factory=dict)
    # The lockfiles that actually produced a finding, as opposed to every
    # lockfile in the repository. The Trivy re-check submits only these.
    flagged_lockfiles: set[str] = field(default_factory=set)

    def package_present(self) -> bool:
        """Any watched package present, resolved or declared, in any version."""
        return bool(self.present_versions or self.range_only)

    def vulnerable(self) -> bool:
        """Any resolved version matches the poisoned version, a declared
        range could resolve to it, a payload artifact is present, or
        OSV-Scanner's live database flagged a resolved version as malicious."""
        return bool(
            self.poisoned_versions
            or self.poisoned_ranges
            or self.payload_files
            or self.osv_malicious
        )

    def shai_hulud_hit(self) -> bool:
        """This repo is exposed to the Shai-Hulud campaign specifically: a
        poisoned version resolved, a range could resolve to one, a worm
        payload artifact is present, or OSV flagged a Shai-Hulud-family
        package as malicious."""
        return bool(
            self.poisoned_versions
            or self.poisoned_ranges
            or self.payload_files
            or any(_is_shai_hulud_name(name) for name in self.osv_malicious)
        )


def version_key(version: str) -> tuple[int, int, int]:
    """Parse the leading major.minor.patch integers of a version string."""
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        return (0, 0, 0)
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def range_may_resolve_to(range_spec: str, poisoned_version: str) -> bool:
    """Check whether a package.json semver range could resolve to poisoned_version."""
    spec = range_spec.strip()
    if spec in ("*", "latest", "next", ""):
        return True
    if spec.startswith(("workspace:", "file:", "git:", "git+", "http:", "https:", "link:")):
        return False

    # Anything with more than one comparator is rejected before the prefix tests
    # below, because those read only the first one. ">=5.0.0 <6.0.0" would
    # otherwise match its lower bound and report 6.0.0 as reachable when the
    # upper bound excludes it, which is a false positive rather than the
    # documented under-report.
    if "||" in spec or any(ch.isspace() for ch in spec):
        return False

    target = version_key(poisoned_version)
    if spec.startswith("^"):
        base = version_key(spec[1:])
        return base[0] == target[0] and target >= base
    if spec.startswith("~"):
        base = version_key(spec[1:])
        return base[0] == target[0] and base[1] == target[1] and target >= base
    if spec.startswith(">="):
        return target >= version_key(spec[2:])
    if spec.startswith(">"):
        return target > version_key(spec[1:])
    if re.match(r"^\d+\.\d+\.\d+$", spec):
        return version_key(spec) == target
    return False


def _escape_package_name(name: str) -> str:
    """Escape a package name for regex, allowing / and its URL-encoded form."""
    return re.escape(name).replace(r"\/", "(?:/|%2[fF])")


# Yarn 2 and later write "keyv@npm:6.0.0" rather than "keyv@6.0.0", both in a
# descriptor and in the resolution line, and such a lockfile often carries no
# tarball URL at all. Without this the offline layer sees nothing in a Berry
# lockfile that pins a poisoned version outright, and with the live database
# disabled or unavailable the scan exits clean. The protocol is optional so the
# classic form still matches, and %3A covers the URL-encoded spelling.
_PROTOCOL = r"(?:npm(?::|%3[aA]))?"


def _version_patterns(name: str) -> tuple[re.Pattern[str], re.Pattern[str]]:
    """Build the tarball-URL and bare-token regexes that capture any version
    of one watched package from raw lockfile text."""
    basename = name.rsplit("/", maxsplit=1)[-1]
    escaped_name = _escape_package_name(name)
    tarball = re.compile(
        rf"{escaped_name}/-/{re.escape(basename)}-([0-9][\w.\-+]*)\.tgz"
    )
    token = re.compile(
        rf"(?<![\w@./-]){escaped_name}@{_PROTOCOL}([0-9][\w.\-+]*)(?![\w.-])"
    )
    return tarball, token


_VERSION_PATTERNS: dict[str, tuple[re.Pattern[str], re.Pattern[str]]] = {
    name: _version_patterns(name) for name in POISONED_VERSIONS
}


def _scope_patterns(prefix: str) -> tuple[re.Pattern[str], re.Pattern[str]]:
    """Build tarball-URL and bare-token regexes that capture (name, version)
    for any package published under a poisoned scope such as '@keyv/'."""
    escaped_prefix = _escape_package_name(prefix)
    tarball = re.compile(
        rf"({escaped_prefix}[a-z0-9._-]+)/-/[a-z0-9._-]+-([0-9][\w.\-+]*)\.tgz"
    )
    token = re.compile(
        rf"(?<![\w@./-])({escaped_prefix}[a-z0-9._-]+)@{_PROTOCOL}([0-9][\w.\-+]*)(?![\w.-])"
    )
    return tarball, token


_SCOPE_PATTERNS: dict[str, tuple[re.Pattern[str], re.Pattern[str]]] = {
    prefix: _scope_patterns(prefix) for prefix in POISONED_SCOPES
}


def load_overlay(path: Path) -> dict[str, list[str]]:
    """Load compromised-npm-packages.json (as written by
    update_scanners.py malicious-packages) into {name: [versions]}. Returns {} if the file
    is absent or malformed, so the scanner silently falls back to its built-in
    table rather than failing when the overlay has never been generated."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        return {}
    result: dict[str, list[str]] = {}
    for name, versions in packages.items():
        if isinstance(name, str) and isinstance(versions, list):
            clean = [v for v in versions if isinstance(v, str) and v]
            if clean:
                result[name] = clean
    return result


def apply_overlay(overlay: dict[str, list[str]]) -> int:
    """Merge an overlay of name -> versions into POISONED_VERSIONS and rebuild the
    lockfile-matching regexes, so newly added package names are actually scanned in
    lockfile text. Returns the number of package@version tuples added. Every name
    carried by the overlay is treated as Shai-Hulud-family, which is correct: the
    overlay is the campaign-scoped feed, not the whole OSV malicious set."""
    global _VERSION_PATTERNS
    added = 0
    for name, versions in overlay.items():
        existing = POISONED_VERSIONS.setdefault(name, [])
        for version in versions:
            if version not in existing:
                existing.append(version)
                added += 1
    _VERSION_PATTERNS = {name: _version_patterns(name) for name in POISONED_VERSIONS}
    return added


def record_resolved_version(
    status: RepoStatus, name: str, version: str, poisoned_versions: Iterable[str]
) -> None:
    """Record one concretely-resolved version of a watched package."""
    status.present_versions.setdefault(name, set()).add(version)
    if version in set(poisoned_versions):
        status.poisoned_versions.setdefault(name, set()).add(version)


def record_declared_range(
    status: RepoStatus, name: str, spec: str, poisoned_versions: Iterable[str]
) -> None:
    """Record one declared-but-unresolved package.json version range."""
    status.range_only.setdefault(name, set()).add(spec)
    if any(range_may_resolve_to(spec, v) for v in poisoned_versions):
        status.poisoned_ranges.setdefault(name, set()).add(spec)


def scan_package_json(path: Path, status: RepoStatus) -> None:
    """Record every watched-package dependency range declared in a package.json."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return
    if not isinstance(data, dict):
        return
    for field_name in DEPENDENCY_FIELDS:
        deps = data.get(field_name)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(spec, str):
                continue
            if name in POISONED_VERSIONS:
                record_declared_range(status, name, spec, POISONED_VERSIONS[name])
                continue
            for prefix, poisoned_version in POISONED_SCOPES.items():
                if name.startswith(prefix):
                    record_declared_range(status, name, spec, [poisoned_version])
                    break


def _poison_count(status: RepoStatus) -> int:
    """How many poisoned package@version pairs have been recorded so far."""
    return sum(len(v) for v in status.poisoned_versions.values())


def _watched(name: str) -> list[str] | None:
    """The poisoned versions to test a package name against, or None."""
    if name in POISONED_VERSIONS:
        return POISONED_VERSIONS[name]
    for prefix, poisoned_version in POISONED_SCOPES.items():
        if name.startswith(prefix):
            return [poisoned_version]
    return None


def scan_npm_lockfile_json(path: Path, status: RepoStatus) -> None:
    """Read an npm lockfile as JSON rather than as text.

    The text patterns match a registry tarball URL or a name@version token, and
    both are absent from a v2 or v3 entry that carries no `resolved` field,
    which happens for workspace links and for lockfiles written with the
    registry omitted. Such an entry pins a version like any other, so matching
    only text would miss a poisoned pin that is plainly stated in the file.

    Both lockfile shapes are read: `packages`, keyed by path, in v2 and v3, and
    the nested `dependencies` tree in v1."""
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return
    if not isinstance(data, dict):
        return

    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, entry in packages.items():
            if not isinstance(entry, dict) or not isinstance(key, str):
                continue
            version = entry.get("version")
            if not isinstance(version, str) or not version:
                continue
            # "node_modules/@scope/name" and "a/node_modules/name" both name the
            # package after the last node_modules segment; "" is the root project.
            name = key.rsplit("node_modules/", 1)[-1] if "node_modules/" in key else ""
            if not name:
                continue
            watched = _watched(name)
            if watched is not None:
                record_resolved_version(status, name, version, watched)

    def walk_v1(tree: object) -> None:
        """Walk the nested v1 dependency tree, which nests the same shape."""
        if not isinstance(tree, dict):
            return
        for name, entry in tree.items():
            if not isinstance(name, str) or not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if isinstance(version, str) and version:
                watched = _watched(name)
                if watched is not None:
                    record_resolved_version(status, name, version, watched)
            walk_v1(entry.get("dependencies"))

    if "packages" not in data:
        walk_v1(data.get("dependencies"))


def scan_lockfile(path: Path, status: RepoStatus) -> None:
    """Record every watched-package version actually resolved in a lockfile.

    Two passes, because neither alone is complete. The text pass covers every
    lockfile format with one code path, npm, pnpm and yarn alike, and catches a
    version wherever it appears. The JSON pass reads npm lockfiles structurally
    and catches entries the text pass cannot see, such as a v3 entry with no
    `resolved` URL. Recording the same version twice is harmless, since versions
    are collected into sets.

    A lockfile that contributes a poisoned version is remembered by name, so a
    later re-check can submit that file alone rather than every lockfile the
    repository happens to contain."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    before = _poison_count(status)
    if path.name.lower().endswith(".json"):
        scan_npm_lockfile_json(path, status)
    for name, (tarball_re, token_re) in _VERSION_PATTERNS.items():
        for pattern in (tarball_re, token_re):
            for version in pattern.findall(text):
                record_resolved_version(status, name, version, POISONED_VERSIONS[name])
    for prefix, poisoned_version in POISONED_SCOPES.items():
        tarball_re, token_re = _SCOPE_PATTERNS[prefix]
        for pattern in (tarball_re, token_re):
            for name, version in pattern.findall(text):
                record_resolved_version(status, name, version, [poisoned_version])
    if _poison_count(status) > before:
        status.flagged_lockfiles.add(str(path))


def scan_payload_filename(path: Path, status: RepoStatus) -> None:
    """Record a file whose name matches a known Shai-Hulud payload artifact."""
    if path.name in PAYLOAD_FILENAMES:
        status.payload_files.append(str(path))


def _walk(
    root: Path, include_node_modules: bool
) -> list[tuple[Path, list[str], list[str]]]:
    """Walk a directory tree, returning (dirpath, dirnames, filenames) triples.

    dirnames as returned includes ignored directory names (.git, and
    node_modules when excluded) so callers can still detect them; only the
    traversal itself skips descending into them.
    """
    results: list[tuple[Path, list[str], list[str]]] = []
    stack = [root]
    while stack:
        current = stack.pop()
        dirnames: list[str] = []
        filenames: list[str] = []
        # os.scandir rather than Path.iterdir with is_dir/is_file: on Windows the
        # directory read already carries the attributes, so scandir answers both
        # questions from cache while the Path form pays a separate stat per entry
        # per question. Over a clone tree of a few hundred repositories that is
        # the difference between minutes and tens of minutes, and the walk is
        # the phase a person waits on.
        # follow_symlinks=False on both tests, which classifies a symlink as
        # neither a directory nor a file and so skips it. Following them would
        # let a directory symlink inside a scanned tree walk and read files
        # outside the root the caller named, which is the boundary SECURITY.md
        # promises for an untrusted tree, and a symlink cycle would make the
        # walk unbounded. The cost is that a lockfile reached only through a
        # symlink is not scanned, which under-reports rather than escaping.
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            dirnames.append(entry.name)
                        elif entry.is_file(follow_symlinks=False):
                            filenames.append(entry.name)
                    except OSError:
                        continue
        except OSError:
            continue
        results.append((current, dirnames, filenames))
        for name in dirnames:
            if name in ALWAYS_SKIP_DIRS:
                continue
            if name == "node_modules" and not include_node_modules:
                continue
            stack.append(current / name)
    return results


def _find_repo_roots(triples: list[tuple[Path, list[str], list[str]]]) -> list[Path]:
    """Identify every directory that is a git repository root, deepest first."""
    repo_roots = [dirpath for dirpath, dirnames, _ in triples if ".git" in dirnames]
    return sorted(repo_roots, key=lambda p: len(p.parts), reverse=True)


def _owner_repo(dirpath: Path, repo_roots: list[Path], root: Path) -> Path:
    """Find the deepest known repo root that contains dirpath, else fall back
    to the top-level directory under root."""
    for candidate in repo_roots:
        if dirpath == candidate or candidate in dirpath.parents:
            return candidate
    try:
        relative = dirpath.relative_to(root)
    except ValueError:
        return root
    if not relative.parts:
        return root
    return root / relative.parts[0]


def _repo_label(root: Path, repo_path: Path) -> str:
    """Build a short, readable repo label rooted at the scanned root's name."""
    try:
        relative = repo_path.relative_to(root)
    except ValueError:
        return str(repo_path)
    label = "/".join(relative.parts) if relative.parts else "."
    return f"{root.name}/{label}"


def _progress(message: str) -> None:
    """Write one progress line to stderr and flush it immediately, so a
    long-running scan shows live progress and a killed run leaves a log that
    reflects exactly how far it got rather than a buffer lost on exit."""
    sys.stderr.write(message + "\n")
    sys.stderr.flush()


def _normalize_path(path_str: str) -> str:
    """Normalize a path for cross-platform, case-insensitive dict lookups."""
    return os.path.normcase(os.path.normpath(path_str))


class WalkProgress:
    """Percentage, elapsed and estimate for the walk, which is the slow phase.

    The walk had no progress reporting at all: it printed one line per
    repository as it discovered them, which on a clone tree of a few hundred
    repositories is a wall of names that says nothing about how far along it is
    or how long is left. The OSV pass reports through this same class, but it
    runs after the walk finishes, so the phase a person actually waits on was
    the one with nothing to watch.

    A walk cannot know its size from inside, so the total is taken first from
    the top-level entries of each root, which for a clone tree is one unit per
    repository. Counting units of roughly equal cost is what makes the estimate
    mean anything."""

    def __init__(self, total: int, desc: str = "walking") -> None:
        self.total = total
        self.desc = desc
        self.current = 0
        self.started = time.monotonic()
        self.last_print = 0.0

    def advance(self, label: str, count: int = 1, units_left: int = 0) -> None:
        """Report the unit about to be processed, and count the one before it.

        Reporting on entry rather than on completion matters on a real clone
        tree, where one repository can take minutes: on completion the line
        appears only once the slow unit is over, so the wait it was meant to
        explain has already happened. Naming the unit as it starts makes a long
        silence attributable to a specific repository. The count is therefore
        units started, which shifts the estimate by one unit out of hundreds."""
        self.current += count
        # The estimate is heuristic and it under-counts a tree whose repositories
        # nest deeper than the counting pass looks. Clamping alone was wrong: a
        # run here sat at 100.0% with an ETA of 00:00 for the last six
        # directories and several minutes of real work. So when the count is
        # overtaken and units remain, the total grows to admit them, and only a
        # final unit with nothing left to do gets clamped.
        if self.total and self.current >= self.total:
            self.total = self.current + units_left if units_left > 0 else self.current
        # The first unit prints immediately, because last_print starts at zero:
        # a silent interval at the start is exactly the case that needs a line,
        # since one repository can take minutes and the wait is unexplained.
        now = time.monotonic()
        if now - self.last_print < 5.0 and self.current < self.total:
            return
        self.last_print = now
        elapsed = now - self.started
        rate = self.current / elapsed if elapsed > 0 else 0
        remaining = (self.total - self.current) / rate if rate > 0 else 0
        pct = 100.0 * self.current / self.total if self.total else 100.0
        _progress(f"  [{self.desc}] {self.current}/{self.total} ({pct:.1f}%) | "
                  f"Elapsed: {format_elapsed(elapsed)} | ETA: {format_elapsed(remaining)} | "
                  f"Speed: {rate:.1f}/s | {label}")

    def finish(self) -> None:
        """Report the totals once the phase is over."""
        elapsed = time.monotonic() - self.started
        _progress(f"  [{self.desc}] Complete: {self.current} items in {format_elapsed(elapsed)}")


def _attribute(
    triples: list[tuple[Path, list[str], list[str]]],
    root: Path,
    extra_roots: list[Path],
    statuses: dict[Path, RepoStatus],
    lockfile_index: dict[str, RepoStatus],
) -> None:
    """Charge every file in these triples to the repository that owns it."""
    repo_roots = _find_repo_roots(triples) + list(extra_roots)
    repo_roots.sort(key=lambda p: len(p.parts), reverse=True)
    for dirpath, _dirnames, filenames in triples:
        owner = _owner_repo(dirpath, repo_roots, root)
        if owner not in statuses:
            statuses[owner] = RepoStatus(name=_repo_label(root, owner), path=str(owner))
        status = statuses[owner]
        for filename in filenames:
            file_path = dirpath / filename
            if filename in NPM_MARKER_FILES:
                status.has_npm = True
                status.npm_files.append(str(file_path))
            if filename == "package.json":
                scan_package_json(file_path, status)
            elif filename in LOCKFILE_NAMES:
                scan_lockfile(file_path, status)
                status.lockfiles.append(str(file_path))
                lockfile_index[_normalize_path(str(file_path))] = status
            scan_payload_filename(file_path, status)


def top_level_units(root: Path, include_node_modules: bool) -> list[Path]:
    """The directories under a root that the walk treats as units of work."""
    if not root.is_dir():
        return []
    try:
        entries = list(root.iterdir())
    except OSError:
        return []
    units = []
    for entry in entries:
        if not entry.is_dir():
            continue
        if entry.name in ALWAYS_SKIP_DIRS:
            continue
        if entry.name == "node_modules" and not include_node_modules:
            continue
        units.append(entry)
    return units


def count_repositories(unit: Path, include_node_modules: bool, max_depth: int = 2) -> int:
    """Estimate how many repositories sit at or under one top-level unit.

    This is the denominator for the progress line, and it is a heuristic on
    purpose. Counting repositories exactly would mean walking every tree to find
    every .git, which is the expensive work the progress is meant to describe.
    Instead this descends at most max_depth levels and stops the moment it finds
    a .git, because nothing inside a repository is another repository worth
    counting here. On a clone tree laid out as root/repo that is one directory
    read per repository, and it finishes in seconds.

    A unit with no repository under it still counts as one, because that is how
    the report attributes it: files under no git root are charged to the
    top-level directory."""
    found = 0
    stack = [(unit, 0)]
    while stack:
        current, depth = stack.pop()
        dirnames: list[str] = []
        has_git = False
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if not entry.is_dir():
                            continue
                    except OSError:
                        continue
                    if entry.name == ".git":
                        has_git = True
                    elif entry.name == "node_modules" and not include_node_modules:
                        continue
                    else:
                        dirnames.append(entry.name)
        except OSError:
            continue
        if has_git:
            found += 1
            continue
        if depth >= max_depth:
            continue
        for name in dirnames:
            stack.append((current / name, depth + 1))
    return found if found else 1


def scan_root(
    root: Path, include_node_modules: bool, progress: WalkProgress | None = None,
    jobs: int = 1,
) -> tuple[dict[Path, RepoStatus], dict[str, RepoStatus]]:
    """Walk one root directory tree, building a per-repo exposure status map
    and an index of every lockfile path relevant for a later OSV-Scanner pass.

    The tree is taken one top-level directory at a time rather than in a single
    pass, so progress can be reported against a known total and so the triples
    for one subtree can be released before the next is read. Attribution is
    unchanged: a repository root inside a subtree can only own files inside it,
    and a root that is itself a git repository is carried in as an outer owner
    so a subtree without its own .git still belongs to it."""
    statuses: dict[Path, RepoStatus] = {}
    lockfile_index: dict[str, RepoStatus] = {}
    if not root.is_dir():
        return statuses, lockfile_index
    _progress(f"walking {root} ...")

    extra_roots = [root] if (root / ".git").exists() else []

    # The root's own files first, without descending, so they are charged before
    # any subtree claims them.
    try:
        root_files = [e.name for e in root.iterdir() if e.is_file()]
    except OSError:
        root_files = []
    if root_files:
        _attribute([(root, [], root_files)], root, extra_roots, statuses, lockfile_index)

    units = top_level_units(root, include_node_modules)

    if jobs <= 1:
        for unit in units:
            if progress is not None:
                progress.advance(_repo_label(root, unit), 0)
            before = len(statuses)
            triples = _walk(unit, include_node_modules)
            _attribute(triples, root, extra_roots, statuses, lockfile_index)
            if progress is not None:
                progress.advance(_repo_label(root, unit), len(statuses) - before)
        return statuses, lockfile_index

    # The walk is bound by directory reads rather than by processor time, and
    # each top-level directory is an independent subtree, so reading several at
    # once is the one change that makes a large clone tree finish in a sensible
    # time. Measured over a 226-repository clone tree: sequentially
    # the first two repositories took 44 s and the run projected about an hour
    # and a half.
    #
    # Each worker builds its own maps and the caller merges them, so no lock is
    # needed: the units are disjoint, because every owner a unit can produce
    # lies inside that unit.
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {
            pool.submit(_scan_unit, unit, root, include_node_modules, extra_roots): unit
            for unit in units
        }
        pending = len(futures)
        for future in as_completed(futures):
            unit = futures[future]
            pending -= 1
            try:
                unit_statuses, unit_lockfiles = future.result()
            except OSError as exc:
                _progress(f"  could not read {unit}: {exc}")
                continue
            _merge_statuses(statuses, unit_statuses)
            for key, owner in unit_lockfiles.items():
                lockfile_index[key] = statuses.get(Path(owner.path), owner)
            if progress is not None:
                # Count the repositories this unit actually produced, so the bar
                # measures repositories rather than top-level directories and a
                # unit holding several of them advances by all of them.
                progress.advance(_repo_label(root, unit), max(1, len(unit_statuses)), pending)
    return statuses, lockfile_index


def _merge_statuses(into: dict[Path, RepoStatus], other: dict[Path, RepoStatus]) -> None:
    """Fold one unit's results into the accumulated map, merging shared owners.

    A plain dict update is wrong whenever two units charge files to the same
    owner, which happens exactly when the scanned root is itself a git
    repository: every unit without its own .git attributes to that outer root,
    so each worker returns a separate status for the same key and the last one
    written silently replaced all the findings before it. Scanning a single
    repository with more than one job is the common case for that, so the loss
    was quiet and easy to miss."""
    for key, src in other.items():
        dst = into.get(key)
        if dst is None:
            into[key] = src
            continue
        dst.has_npm = dst.has_npm or src.has_npm
        dst.npm_files.extend(src.npm_files)
        dst.lockfiles.extend(src.lockfiles)
        dst.payload_files.extend(src.payload_files)
        dst.flagged_lockfiles |= src.flagged_lockfiles
        for attribute in ("present_versions", "range_only", "poisoned_versions",
                          "poisoned_ranges", "osv_malicious", "osv_advisory_ids",
                          "trivy_confirmed"):
            target = getattr(dst, attribute)
            for name, values in getattr(src, attribute).items():
                target.setdefault(name, set()).update(values)


def _scan_unit(
    unit: Path, root: Path, include_node_modules: bool, extra_roots: list[Path]
) -> tuple[dict[Path, RepoStatus], dict[str, RepoStatus]]:
    """Walk and attribute one top-level unit into maps of its own."""
    statuses: dict[Path, RepoStatus] = {}
    lockfile_index: dict[str, RepoStatus] = {}
    triples = _walk(unit, include_node_modules)
    _attribute(triples, root, extra_roots, statuses, lockfile_index)
    return statuses, lockfile_index


def find_osv_scanner(explicit_bin: str | None) -> str | None:
    """Locate the osv-scanner executable.

    Order: an explicit path, then OSV_SCANNER_BIN, then the binary this stack
    builds under GOBIN or GOPATH/bin, then PATH, then a last look under
    ~/go/bin. The local build is preferred over PATH so a package-manager copy
    cannot shadow the build update_scanners.py produced and gated. Works
    unchanged on Windows, Linux and macOS."""
    for candidate in (explicit_bin, os.environ.get("OSV_SCANNER_BIN")):
        if candidate and shutil.which(candidate):
            return shutil.which(candidate)

    go = shutil.which("go")
    if go:
        for var in ("GOBIN", "GOPATH"):
            try:
                out = subprocess.run(  # nosec B603
                    [go, "env", var], capture_output=True, text=True, timeout=60, check=False
                ).stdout.strip()
            except (OSError, subprocess.SubprocessError):
                out = ""
            if not out:
                continue
            root = Path(out) if var == "GOBIN" else Path(out) / "bin"
            candidate_path = root / EXE_NAME
            if candidate_path.exists():
                return str(candidate_path)

    found = shutil.which("osv-scanner")
    if found:
        return found
    go_bin = str(Path.home() / "go" / "bin")
    return shutil.which("osv-scanner", path=os.pathsep.join([os.environ.get("PATH", ""), go_bin]))


def _parse_ioc_csv(text: str) -> dict[str, set[str]]:
    """Parse the consolidated indicator feed into {package: {versions}}.

    The version column joins several versions inside one quoted field, and some
    rows carry a 99.x placeholder standing in for "all or unknown", which is
    dropped rather than matched against a real install."""
    packages: dict[str, set[str]] = {}
    reader = csv.DictReader(io.StringIO(text))
    fields = {f.lower().strip(): f for f in (reader.fieldnames or [])}
    name_key = next((fields[c] for c in ("package_name", "name", "package") if c in fields), None)
    version_key = next(
        (fields[c] for c in ("package_versions", "versions", "version") if c in fields), None
    )
    if not name_key or not version_key:
        raise ValueError(f"unexpected columns in the feed: {reader.fieldnames}")
    for row in reader:
        name = (row.get(name_key) or "").strip()
        if not name:
            continue
        raw = (row.get(version_key) or "").replace(";", ",").replace(" ", ",")
        for token in raw.split(","):
            version = token.strip().strip('"')
            if version and not version.startswith("99."):
                packages.setdefault(name, set()).add(version)
    return packages


def refresh_overlay(overlay_file: Path, min_interval: int, timeout: int = 60) -> None:
    """Refresh the campaign overlay from the indicator feed, throttled.

    Throttling is what makes this affordable ahead of every run: the file's own
    modification time decides, so no state file is needed. A failure is reported
    and never stops a scan, because the overlay already on disk, or the built-in
    table underneath it, still gives a usable floor."""
    if min_interval > 0 and overlay_file.exists():
        age = (time.time() - overlay_file.stat().st_mtime) / 60.0
        if age < min_interval:
            _progress(f"overlay refreshed {age:.1f} min ago, not fetching again")
            return
    _progress(f"refreshing the campaign overlay from {IOC_FEED_URL}")
    try:
        request = urllib.request.Request(
            IOC_FEED_URL, headers={"User-Agent": f"lockfile-sentinel/{__version__}"}
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
            body = response.read().decode("utf-8", errors="replace")
        packages = _parse_ioc_csv(body)
    except Exception as exc:  # noqa: BLE001 - a stale overlay beats no scan
        _progress(f"could not refresh the overlay ({exc}); using what is on disk")
        return

    for name, versions in POISONED_VERSIONS.items():
        packages.setdefault(name, set()).update(versions)
    payload = {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": [IOC_FEED_URL],
        "package_count": len(packages),
        "version_count": sum(len(v) for v in packages.values()),
        "packages": {name: sorted(v) for name, v in sorted(packages.items())},
    }
    try:
        overlay_file.parent.mkdir(parents=True, exist_ok=True)
        overlay_file.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        _progress(f"could not write {overlay_file} ({exc})")
        return
    _progress(f"overlay refreshed: {len(packages)} packages, "
              f"{payload['version_count']} versions")


def resolve_trivy() -> str | None:
    """Find trivy on PATH, or report that there is none to corroborate with."""
    return shutil.which("trivy")


def run_selftest(osv_bin: str | None, timeout: int) -> int:
    """Prove the detector still detects, without shipping anything poisonous.

    A scanner that reports nothing looks exactly like a scanner that is broken:
    the database may have failed to load, the parser may have skipped the file,
    the binary may be stale. The only way to tell the two apart is to feed it
    something that must be reported.

    The control is written to a temporary directory and deleted afterwards, so
    the repository never carries a lockfile pinning live malicious versions for
    someone to install by accident. It pins keyv 6.0.0 and cacheable 2.5.1,
    which carry published malicious-package advisories, and asserts that both
    layers report them.

    Returns 0 when both were reported, 1 when either was missed, 2 when the
    check could not be performed at all, because a check that could not run must
    never report health."""
    control = {
        "name": "lockfile-sentinel-selftest",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"name": "lockfile-sentinel-selftest", "version": "1.0.0",
                 "dependencies": {"keyv": "6.0.0", "cacheable": "2.5.1"}},
            "node_modules/keyv": {
                "version": "6.0.0",
                "resolved": "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz",
            },
            "node_modules/cacheable": {
                "version": "2.5.1",
                "resolved": "https://registry.npmjs.org/cacheable/-/cacheable-2.5.1.tgz",
            },
        },
    }
    expected = {"keyv": "6.0.0", "cacheable": "2.5.1"}

    with tempfile.TemporaryDirectory(prefix="lockfile-sentinel-selftest-") as work:
        lockfile = Path(work) / "package-lock.json"
        lockfile.write_text(json.dumps(control, indent=2), encoding="utf-8")

        status = RepoStatus(name="selftest", path=work)
        scan_lockfile(lockfile, status)
        offline_hits = {
            name: sorted(versions) for name, versions in status.poisoned_versions.items()
        }
        missed_offline = [n for n, v in expected.items() if v not in status.poisoned_versions.get(n, set())]
        print(f"offline table: {offline_hits or 'nothing'}")

        if not osv_bin:
            print("osv-scanner not found, so only the offline layer was tested")
            print("FAIL: the offline table missed " + ", ".join(missed_offline)
                  if missed_offline else "PASS: the offline table reported both")
            return 1 if missed_offline else 2

        found = _run_osv_batch(osv_bin, [str(lockfile)], timeout)
        if found is None:
            print("FAIL: osv-scanner could not extract the control lockfile")
            return 2
        live = {name for hits in found.values() for name, _version, _ids in hits}
        missed_live = [n for n in expected if n not in live]
        print(f"live database: {sorted(live) or 'nothing'}")

    if missed_offline or missed_live:
        for name in missed_offline:
            print(f"FAIL: the offline table did not report {name}")
        for name in missed_live:
            print(f"FAIL: the live database did not report {name}")
        return 1
    print("PASS: both layers reported both known-malicious packages")
    return 0


def _trivy_findings(trivy: str, lockfile: str, timeout: int) -> dict[str, set[str]] | None:
    """Scan one lockfile with Trivy, returning {package@version: {advisory ids}}.

    None means Trivy could not be asked, which is different from Trivy having
    nothing to say and must not be reported as the latter."""
    try:
        proc = subprocess.run(  # nosec B603
            [trivy, "fs", "--scanners", "vuln", "--format", "json", "--quiet", lockfile],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode not in (0, 1):
        return None
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return None
    found: dict[str, set[str]] = {}
    for result in data.get("Results") or []:
        if not isinstance(result, dict):
            continue
        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            name = vuln.get("PkgName")
            version = vuln.get("InstalledVersion")
            ident = vuln.get("VulnerabilityID")
            if isinstance(name, str) and isinstance(version, str) and isinstance(ident, str):
                found.setdefault(f"{name}@{version}", set()).add(ident)
    return found


def trivy_recheck(statuses: list[RepoStatus], trivy: str, timeout: int) -> None:
    """Ask Trivy about the findings only, and record it as corroboration.

    Trivy is a third database with an independent build pipeline, so when it
    knows a package this scanner flagged, that is worth stating. When it does
    not, that is worth nothing at all, and the report says so rather than
    letting silence read as clearance.

    The reason is measured rather than assumed. Scanned against this stack's own
    positive control on 2026-08-05, with a vulnerability database five hours
    old, Trivy reported zero findings for keyv 6.0.0 and cacheable 2.5.1, both
    of which carry OSV malicious-package advisories. Trivy's npm feed does not
    carry MAL- entries, so its silence on a Shai-Hulud finding is the expected
    result and never evidence that the finding is wrong.

    Only the individual lockfiles that produced a finding are submitted, not the
    repositories that contain them and not their other lockfiles, so a clean
    estate costs nothing and a flagged monorepo costs one scan per implicated
    file. A finding with no lockfile behind it, such as a payload artifact found
    by name, has nothing for Trivy to read and is not submitted at all."""
    vulnerable = [s for s in statuses if s.vulnerable() and s.flagged_lockfiles]
    if not vulnerable:
        return
    submissions = sum(len(s.flagged_lockfiles) for s in vulnerable)
    _progress(f"trivy re-check: {submissions} implicated lockfile(s) "
              f"across {len(vulnerable)} repository(ies)")
    for status in vulnerable:
        for lockfile in sorted(status.flagged_lockfiles):
            findings = _trivy_findings(trivy, lockfile, timeout)
            if findings is None:
                _progress(f"  [trivy] could not scan {lockfile}")
                continue
            status.trivy_checked = True
            flagged = set(status.poisoned_versions) | set(status.osv_malicious)
            for key, ids in findings.items():
                name = key.rsplit("@", 1)[0]
                if name in flagged:
                    status.trivy_confirmed.setdefault(key, set()).update(ids)
        if status.trivy_checked and not status.trivy_confirmed:
            _progress(f"  [trivy] consulted for {status.name}, nothing matched")


def _read_json(path: Path) -> dict:
    """Load a JSON file, or {} when it is absent or malformed."""
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _age_line(label: str, when: float | None, stale_after_hours: float) -> tuple[str, bool]:
    """Render one source's timestamp and age, and say whether it is stale."""
    if when is None:
        return f"  {label:<28} unknown", True
    age = time.time() - when
    stamp = datetime.fromtimestamp(when, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    marker = "  STALE" if age > stale_after_hours * 3600 else ""
    # The shared formatter gives MM:SS below an hour and H:MM:SS above it, which
    # is unambiguous in a progress line but not after the word "ago". Name the
    # unit so 21:28 cannot be read as twenty-one hours.
    units = "h:mm:ss" if age >= 3600 else "mm:ss"
    return (f"  {label:<28} {stamp}, {format_elapsed(age)} {units} ago{marker}",
            age > stale_after_hours * 3600)


def report_status(overlay_file: Path, osv_bin: str | None) -> int:
    """Report when each thing the scanner relies on was last updated.

    A scanner is only as current as its inputs, and every one of them is
    refreshed by a different mechanism on a different cadence, so the question
    "is this scan trustworthy right now" has no single answer to read anywhere.
    This gathers all of them.

    Exit 0 when everything is fresh, 1 when something is stale, 2 when a source
    could not be determined at all, following the house rule that a check which
    could not run must not report health."""
    lines = ["Supply-chain scanner status", "==========================="]
    stale = False
    unknown = False

    # 1. The engine itself, and when its version was last checked.
    state = _read_json(cache_dir() / "logs" / "update-osv-scanner.state.json")
    version = "not found"
    if osv_bin:
        try:
            out = subprocess.run(  # nosec B603
                [osv_bin, "--version"], capture_output=True, text=True, timeout=60, check=False
            )
            match = re.search(r"osv-scanner version:\s*([0-9]\S*)", out.stdout + out.stderr)
            version = match.group(1) if match else "unreadable"
        except (OSError, subprocess.SubprocessError):
            version = "unreadable"
    lines.append(f"  {'osv-scanner binary':<28} {version} at {osv_bin or 'not found'}")
    if state.get("lastCommit"):
        lines.append(f"  {'built from commit':<28} {str(state['lastCommit'])[:12]}")
    line, is_stale = _age_line("version last checked", state.get("lastCheckUnix"), 24)
    lines.append(line)
    stale = stale or is_stale
    unknown = unknown or state.get("lastCheckUnix") is None

    # 2. The campaign overlay, by its own stamp and by the refresher's state.
    overlay = _read_json(overlay_file)
    if overlay:
        lines.append(f"  {'overlay packages':<28} {overlay.get('package_count', '?')} packages, "
                     f"{overlay.get('version_count', '?')} versions")
        lines.append(f"  {'overlay file':<28} {overlay_file}")
        generated = overlay.get("generated_utc")
        stamp = None
        if isinstance(generated, str):
            try:
                stamp = datetime.strptime(generated, "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=timezone.utc).timestamp()
            except ValueError:
                stamp = None
        line, is_stale = _age_line("overlay generated", stamp, 24)
        lines.append(line)
        stale = stale or is_stale
        unknown = unknown or stamp is None
    else:
        lines.append(f"  {'overlay file':<28} absent or unreadable at {overlay_file}")
        unknown = True

    # The refresh age comes from update_scanners.py's state file when that is what
    # keeps the overlay current, and from the overlay's own mtime otherwise.
    # refresh_overlay in this file throttles on the mtime and writes no state
    # file, so reading the state file alone reported a permanent unknown, and a
    # permanent exit 1, on any host where the scanner does its own refreshing.
    refresh = _read_json(cache_dir() / "logs" / "update-malicious-packages.state.json")
    last_refresh = refresh.get("lastRefreshUnix")
    if last_refresh is None:
        try:
            last_refresh = overlay_file.stat().st_mtime
        except OSError:
            last_refresh = None
    line, is_stale = _age_line("overlay last refreshed", last_refresh, 24)
    lines.append(line)
    stale = stale or is_stale
    unknown = unknown or last_refresh is None

    # 3. The built-in floor, which has no timestamp because it ships in the code.
    builtin = sum(len(v) for v in POISONED_VERSIONS.values())
    lines.append(f"  {'built-in table':<28} {builtin} package@version pairs (in the source)")

    # 4. The live database, which is the layer with no local copy to age.
    lines.append(f"  {'OSV live database':<28} queried per scan at api.osv.dev, no local copy")

    # 5. The offline database. This must resolve exactly as
    # update_scanners.offline_db_dir() does: osv-scanner's own variable first,
    # then the cache root. Reading only the variable reported "not present"
    # immediately after a 206 MB refresh had landed in the cache, because the
    # updater sets that variable for its child process alone.
    offline = os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY")
    offline_dir = Path(offline) if offline else cache_dir() / "osv-offline-db"
    if offline_dir.is_dir():
        newest = max((p.stat().st_mtime for p in offline_dir.rglob("*") if p.is_file()),
                     default=None)
        line, _ = _age_line("OSV offline database", newest, 24 * 7)
        lines.append(line)
    else:
        lines.append(f"  {'OSV offline database':<28} not present ({offline_dir}); "
                     f"online mode is always current")

    for line in lines:
        print(line)

    if unknown:
        return 2
    return 1 if stale else 0


def diagnose_lockfiles(osv_bin: str | None, paths: list[str], timeout: int) -> int:
    """Test named lockfiles one at a time, saying exactly what happened to each.

    This is the fast loop for the failure the batch scanner reports. A full
    sweep walks hundreds of repositories before it reaches the OSV pass, so
    iterating on a broken lockfile that way costs ten minutes a try. Here the
    walk is skipped entirely and each file is submitted alone, which also
    removes the binary search: a file that fails is the file that failed.

    Returns 0 when every file extracted, 1 when any did not, 2 when the scanner
    could not be found."""
    if not osv_bin:
        _progress("FAIL: osv-scanner not found")
        return 2
    _progress(f"diagnosing {len(paths)} lockfile(s) with {osv_bin}")
    failed = 0
    for given in paths:
        # Resolve before submitting: osv-scanner reports the absolute path in
        # its results, so a relative path in and an absolute path out never
        # match and every finding is lost. The sweep passes absolute paths and
        # never hit this; a hand-typed one does.
        path = str(Path(given).resolve()) if os.path.exists(given) else given
        if not os.path.exists(path):
            _progress(f"MISSING: {path}")
            failed += 1
            continue
        result = _run_osv_batch(osv_bin, [path], timeout, debug=True)
        if result is None:
            failed += 1
            _progress(f"FAILED : {path}")
            _progress(f"    reason: {_describe_lockfile(path)}")
            for line in _verbose_lockfile_dump(path):
                _progress(line)
            continue
        hits = result.get(_normalize_path(path), [])
        if not hits and len(result) == 1:
            # One file in, one source out: whatever it was keyed by, it is this
            # file. Guards against any further path-shape disagreement.
            hits = next(iter(result.values()))
        if hits:
            detail = ", ".join(
                f"{name}@{version} ({', '.join(sorted(ids))})" for name, version, ids in hits
            )
            _progress(f"OK     : {path} -> {detail}")
        else:
            _progress(f"OK     : {path} -> no malicious-package advisories")
    _progress(f"diagnosis complete: {len(paths) - failed} extracted, {failed} failed")
    return 1 if failed else 0


def run_passthrough(osv_bin: str | None, args: list[str]) -> int:
    """Hand every argument to `osv-scanner scan` and return its exit code.

    Order is preserved exactly as given, subcommand included, because osv-scanner
    cares where its subcommand sits. Exit codes are its own: 0 no vulnerabilities,
    1 vulnerabilities found, which is a finding rather than a tool failure, and
    anything else a real error. 2 here means the scanner could not be located."""
    if not osv_bin:
        _progress("FAIL: osv-scanner not found. Install it and put it on PATH, or build it "
                  "with: python update_scanners.py osv-scanner --force")
        return 2
    _progress(f"running {osv_bin} scan {' '.join(args)}")
    try:
        return subprocess.run([osv_bin, "scan", *args], check=False).returncode  # nosec B603
    except (OSError, subprocess.SubprocessError) as exc:
        _progress(f"FAIL: could not run {osv_bin} ({exc})")
        return 2


def _chunked(items: list[str], size: int) -> list[list[str]]:
    """Split a list into consecutive chunks of at most size items each."""
    return [items[i : i + size] for i in range(0, len(items), size)]


def _extract_malicious_findings(
    osv_json: dict[str, object]
) -> dict[str, list[tuple[str, str, set[str]]]]:
    """Parse one OSV-Scanner JSON payload into
    {normalized_source_path: [(package_name, version, malicious_ids), ...]}.

    Only vulnerabilities whose id or aliases carry the OSV malicious-packages
    'MAL-' prefix are kept; ordinary CVE-style advisories are deliberately
    dropped here since they are outside this scanner's purpose."""
    by_source: dict[str, list[tuple[str, str, set[str]]]] = {}
    results = osv_json.get("results")
    if not isinstance(results, list):
        return by_source
    for result in results:
        source = result.get("source", {})
        source_path = source.get("path")
        if not isinstance(source_path, str):
            continue
        packages = result.get("packages", [])
        if not isinstance(packages, list):
            continue
        hits: list[tuple[str, str, set[str]]] = []
        for pkg_entry in packages:
            package = pkg_entry.get("package", {})
            name = package.get("name")
            version = package.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            malicious_ids: set[str] = set()
            for vuln in pkg_entry.get("vulnerabilities", []) or []:
                candidate_ids = [vuln.get("id", "")] + list(vuln.get("aliases", []) or [])
                malicious_ids.update(cid for cid in candidate_ids if cid.startswith("MAL-"))
            if malicious_ids:
                hits.append((name, version, malicious_ids))
        if hits:
            by_source[_normalize_path(source_path)] = hits
    return by_source


def _describe_lockfile(path: str) -> str:
    """Say what is odd about a lockfile that the scanner refused to extract.

    osv-scanner reports only "extraction failed on specified lockfile", which
    names neither the file nor the reason, so the reason is worked out here.
    An empty file, a path over the Windows MAX_PATH limit and a file that is not
    the format its name claims are the three that actually occur."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return f"cannot be read ({exc})"
    notes = [f"{size} bytes"]
    if size == 0:
        notes.append("empty, so there is nothing to extract")
    if len(path) >= 260:
        notes.append(f"path is {len(path)} characters, at or over the Windows MAX_PATH limit")
    if size > 0 and path.lower().endswith(".json"):
        try:
            with open(path, encoding="utf-8-sig", errors="replace") as handle:
                head = handle.read(400).lstrip()
            if not head.startswith("{"):
                notes.append("does not begin with an object, so it is not the JSON it claims")
            elif "<<<<<<<" in head:
                notes.append("contains merge conflict markers")
        except OSError as exc:
            notes.append(f"unreadable ({exc})")
    return ", ".join(notes)


def _verbose_lockfile_dump(path: str) -> list[str]:
    """Everything cheap that could explain why the scanner refused a lockfile.

    osv-scanner says only "extraction failed on specified lockfile", so the file
    has to be examined here. These are the checks that have actually explained
    such a failure: an encoding the parser does not expect, a pointer file
    standing in for the real one, a conflict left in the tree, and a lockfile
    format version the installed scanner does not model."""
    lines: list[str] = []
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return [f"      cannot stat: {exc}"]
    lines.append(f"      size: {size} bytes, path length {len(path)}")
    try:
        with open(path, "rb") as handle:
            raw = handle.read(8192)
    except OSError as exc:
        lines.append(f"      cannot read: {exc}")
        return lines

    lines.append(f"      first bytes: {raw[:24]!r}")
    if raw.startswith(b"\xef\xbb\xbf"):
        lines.append("      starts with a UTF-8 byte order mark")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        lines.append("      UTF-16 byte order mark, so it is not the UTF-8 the parser expects")
    if b"<<<<<<<" in raw or b">>>>>>>" in raw:
        lines.append("      contains merge conflict markers")
    if raw.startswith(b"version https://git-lfs"):
        lines.append("      is a Git LFS pointer, not the lockfile itself")
    if size == 0:
        lines.append("      empty, so there is nothing to extract")

    name = os.path.basename(path).lower()
    text = raw.decode("utf-8", errors="replace")
    if name.endswith(".json"):
        try:
            with open(path, encoding="utf-8-sig") as handle:
                document = json.load(handle)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            lines.append(f"      does NOT parse as JSON: {exc}")
        else:
            if isinstance(document, dict):
                lines.append(
                    f"      parses as JSON, lockfileVersion="
                    f"{document.get('lockfileVersion')!r}, top-level keys="
                    f"{sorted(document)[:8]}"
                )
                if "lockfileVersion" not in document:
                    lines.append("      has no lockfileVersion, so it is not an npm lockfile")
            else:
                lines.append(f"      parses as JSON but is a {type(document).__name__}, not an object")
    elif name == "pnpm-lock.yaml":
        head = [line for line in text.splitlines()[:6] if line.strip()]
        lines.append(f"      first lines: {head}")
        match = re.search(r"lockfileVersion:\s*'?([\d.]+)'?", text)
        lines.append(
            f"      lockfileVersion: {match.group(1)}" if match
            else "      no lockfileVersion line found"
        )
    elif name == "yarn.lock":
        lines.append("      yarn berry format (__metadata present)" if "__metadata:" in text
                     else "      yarn classic v1 format")
    return lines


def _run_osv_batch(
    osv_bin: str, paths: list[str], timeout: int, debug: bool = False
) -> dict[str, list[tuple[str, str, set[str]]]] | None:
    """Run one osv-scanner invocation over the given lockfiles. Returns None
    on any failure (spawn error, unexpected exit code, unparsable output) so
    the caller can retry at finer granularity instead of losing every result
    in the batch to one bad file."""
    cmd = [osv_bin, "scan"]
    for lockfile_path in paths:
        cmd.extend(["--lockfile", lockfile_path])
    cmd.extend(["--format", "json"])
    try:
        proc = subprocess.run(  # nosec B603
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        _progress(f"osv-scanner failed to start: {exc}")
        return None
    # 128 is "No package sources found", which is not a failure: the file
    # extracted and simply declared no dependencies, which is what a scaffold
    # lockfile looks like. It only ever surfaces when such a file is scanned
    # alone, so without this the binary search reports a perfectly good lockfile
    # as unrecoverable. Measured on three of them in these trees.
    if proc.returncode == 128:
        _progress(f"  no packages declared in {len(paths)} lockfile(s), nothing to check")
        return {}

    if proc.returncode not in (0, 1):
        # A failure here costs the whole group, so it is always reported in
        # full. The scanner's own last line names neither the file nor the
        # reason, and the reason is one line further up: the emojipanel lockfile
        # in these trees failed on "cannot unmarshal bool into Go struct field
        # Dependency.dependencies.dependencies.resolved of type string", which is
        # a boolean where npm's schema says a string. Nothing about that is
        # recoverable from the summary line, and hiding it behind a flag means
        # the next investigation starts by re-running the ten-minute sweep.
        detail = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else ""
        _progress(f"osv-scanner exited {proc.returncode} on {len(paths)} lockfile(s): {detail}")
        _progress(f"  command: {os.path.basename(cmd[0])} scan ... ({len(paths)} lockfile(s), "
                  f"timeout {timeout}s)")
        for stream, label in ((proc.stderr, "stderr"), (proc.stdout, "stdout")):
            for line in (stream or "").splitlines():
                if line.strip():
                    _progress(f"  {label}: {line.rstrip()}")
        # Listing the group is what turns "one of these hundred" into a name.
        # A small group is always listed; a large one only when asked, because
        # a hundred paths per retry buries the error that caused them.
        if len(paths) <= 8 or debug:
            for path in paths:
                _progress(f"  in this group: {path}")
        else:
            _progress(f"  group of {len(paths)} not listed; pass --osv-debug to list it")
        return None
    try:
        return _extract_malicious_findings(json.loads(proc.stdout or "{}"))
    except json.JSONDecodeError:
        _progress(f"osv-scanner produced non-JSON output on {len(paths)} lockfile(s)")
        return None


def _scan_with_isolation(
    osv_bin: str, paths: list[str], timeout: int,
    debug: bool = False, failures: list[str] | None = None,
) -> tuple[dict[str, list[tuple[str, str, set[str]]]], set[str]]:
    """Scan the given lockfiles, isolating any bad file by binary search.

    One malformed lockfile makes osv-scanner abort the whole invocation, so a
    failed group is split in half and each half retried. A bad file is thus
    isolated in O(log n) re-runs rather than the O(n) of a per-file retry,
    while every healthy file in the group is still scanned. Returns (malicious
    hits per lockfile, set of paths that were successfully scanned)."""
    result = _run_osv_batch(osv_bin, paths, timeout, debug)
    if result is not None:
        return result, {_normalize_path(p) for p in paths}
    if len(paths) == 1:
        # The end of the binary search, and the only place the offending file is
        # known. Say which file and why, or the whole cascade above reads as an
        # unexplained failure and the same question gets asked next run.
        _progress(f"  unrecoverable, skipped: {paths[0]}")
        _progress(f"    reason: {_describe_lockfile(paths[0])}")
        for line in _verbose_lockfile_dump(paths[0]):
            _progress(line)
        if failures is not None:
            failures.append(paths[0])
        return {}, set()
    mid = len(paths) // 2
    _progress(f"  splitting failed group of {len(paths)} into {mid} + {len(paths) - mid}")
    left_findings, left_ok = _scan_with_isolation(osv_bin, paths[:mid], timeout, debug, failures)
    right_findings, right_ok = _scan_with_isolation(osv_bin, paths[mid:], timeout, debug, failures)
    return {**left_findings, **right_findings}, left_ok | right_ok


def run_osv_scanner(
    osv_bin: str,
    lockfile_paths: list[str],
    batch_size: int,
    timeout: int,
    on_batch_done: Callable[[dict[str, list[tuple[str, str, set[str]]]], set[str]], None]
    | None = None,
    debug: bool = False,
) -> tuple[dict[str, list[tuple[str, str, set[str]]]], set[str]]:
    """Run osv-scanner against exactly the given lockfiles, batched to keep
    each command line bounded. A batch that fails outright (one malformed
    lockfile is enough) is isolated by binary search, so only the genuinely
    bad file is lost rather than every other result in the batch.

    After each batch, on_batch_done (if given) is called with the results so
    far, letting the caller persist an updated report incrementally so a
    killed run still leaves everything scanned up to that point on disk.

    Returns (malicious hits per lockfile, set of lockfile paths that were
    actually, successfully submitted) so the caller can report osv_checked
    accurately instead of claiming every discovered lockfile was checked."""
    combined: dict[str, list[tuple[str, str, set[str]]]] = {}
    processed: set[str] = set()

    # A file that cannot extract aborts the whole invocation it is part of, and
    # the binary search then costs a run per halving to find it. An empty
    # lockfile is the common case and is recognisable without asking the
    # scanner, so it is dropped here with a note instead.
    usable: list[str] = []
    for path in lockfile_paths:
        try:
            if os.path.getsize(path) == 0:
                _progress(f"skipping empty lockfile, nothing to extract: {path}")
                continue
        except OSError as exc:
            _progress(f"skipping unreadable lockfile ({exc}): {path}")
            continue
        usable.append(path)
    lockfile_paths = usable

    batches = _chunked(lockfile_paths, batch_size)
    failures: list[str] = []

    # The OSV pass is where the wall clock goes, and it is the one phase whose
    # size is known in advance, so it is the phase worth tracking. Counting
    # lockfiles rather than batches makes the rate and the estimate meaningful
    # when a batch is split by the isolation retry.
    tracker = WalkProgress(len(lockfile_paths), desc="osv-scanner") if lockfile_paths else None

    done = 0
    for batch_num, batch in enumerate(batches, start=1):
        _progress(f"osv-scanner batch {batch_num}/{len(batches)}: {len(batch)} lockfile(s)...")
        batch_findings, batch_ok = _scan_with_isolation(
            osv_bin, batch, timeout, debug, failures
        )
        combined.update(batch_findings)
        processed.update(batch_ok)
        done += len(batch)
        if tracker is not None:
            tracker.advance(f"{len(combined)} lockfile(s) with findings", count=len(batch))
        if on_batch_done is not None:
            on_batch_done(combined, processed)

    if tracker is not None:
        tracker.finish()

    # Write the offending files out so the next investigation is seconds rather
    # than another full walk. Re-running against this list reproduces the
    # failure over a handful of files instead of a few hundred repositories.
    if failures:
        listing = cache_dir() / "logs" / "osv-extraction-failures.txt"
        try:
            listing.parent.mkdir(parents=True, exist_ok=True)
            listing.write_text("\n".join(failures) + "\n", encoding="utf-8")
            _progress(f"{len(failures)} lockfile(s) failed extraction; wrote the list to {listing}")
            _progress(f"  reproduce on those alone: python lockfile_sentinel.py "
                      f"--lockfiles-from {listing} --osv-debug")
        except OSError as exc:
            _progress(f"could not write the failure list ({exc})")
    return combined, processed


def apply_osv_results(
    lockfile_index: dict[str, RepoStatus],
    osv_findings: dict[str, list[tuple[str, str, set[str]]]],
    processed_paths: set[str],
) -> None:
    """Attach OSV-Scanner malicious-package hits back onto their owning repo,
    and mark osv_checked only for repos whose lockfiles were all actually,
    successfully submitted (not merely discovered).

    Every lockfile has to succeed, not just one. A repository with several
    lockfiles where only one extracted was being reported as fully covered, so
    the coverage line claimed all of them had been submitted and resolved while
    the one that failed might be the one carrying the malicious transitive
    dependency. Partial coverage is reported as no coverage, because the whole
    point of the coverage line is to stop a repository nothing checked from
    reading as a repository that came back clean."""
    for owner in {id(s): s for s in lockfile_index.values()}.values():
        owned = [_normalize_path(p) for p in owner.lockfiles]
        owner.osv_resolved_count = sum(1 for p in owned if p in processed_paths)
        owner.osv_checked = bool(owned) and owner.osv_resolved_count == len(owned)
    for normalized_path, hits in osv_findings.items():
        owner = lockfile_index.get(normalized_path)
        if owner is None:
            continue
        # Record which lockfile carried the hit, in its original spelling, so a
        # re-check submits that file rather than the whole repository.
        for candidate in owner.lockfiles:
            if _normalize_path(candidate) == normalized_path:
                owner.flagged_lockfiles.add(candidate)
                break
        for name, version, ids in hits:
            owner.osv_malicious.setdefault(name, set()).add(version)
            owner.osv_advisory_ids.setdefault(f"{name}@{version}", set()).update(ids)


def _is_shai_hulud_name(name: str) -> bool:
    """Check whether a package name belongs to the Shai-Hulud family this
    script's built-in table watches, as opposed to some unrelated malicious
    package OSV-Scanner's broader 'MAL-' cross-check also happens to catch."""
    return name in POISONED_VERSIONS or any(
        name.startswith(prefix) for prefix in POISONED_SCOPES
    )


def _format_versions(versions: dict[str, set[str]]) -> str:
    """Render a package-name -> version-set map as 'name (v1, v2), name2 (v3)'."""
    parts = []
    for name in sorted(versions):
        version_list = ", ".join(sorted(versions[name]))
        parts.append(f"{name} ({version_list})")
    return ", ".join(parts)


_ADVISORY_CACHE: dict[str, dict] = {}


def _advisory_cache_dir() -> Path:
    """Where fetched advisories are kept, beside the campaign overlay."""
    return OVERLAY_PATH.parent / "advisories"


def fetch_advisory(advisory_id: str, timeout: int = 20) -> dict:
    """Fetch one advisory from OSV.dev, through a cache on disk.

    An advisory is immutable enough for this purpose and there are only ever a
    handful per run, so a cached copy beside the overlay means a repeated scan
    costs no requests at all. Any failure returns an empty record, because a
    naming aid that cannot reach the network must not stop a scan."""
    if advisory_id in _ADVISORY_CACHE:
        return _ADVISORY_CACHE[advisory_id]

    cache_file = _advisory_cache_dir() / f"{advisory_id}.json"
    try:
        record = json.loads(cache_file.read_text(encoding="utf-8"))
        _ADVISORY_CACHE[advisory_id] = record
        return record
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        pass

    record = {}
    try:
        request = urllib.request.Request(
            f"https://api.osv.dev/v1/vulns/{advisory_id}",
            headers={"User-Agent": f"lockfile-sentinel/{__version__}"},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
            record = json.loads(response.read().decode("utf-8"))
    except Exception:  # noqa: BLE001 - naming is an aid, never a gate
        record = {}

    if record:
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(record), encoding="utf-8")
        except OSError:
            pass
    _ADVISORY_CACHE[advisory_id] = record
    return record


def campaign_of(advisory_id: str, lookup: bool = True) -> str | None:
    """Name the campaign an advisory belongs to, or None when it names none.

    The advisory's own summary and details are the source, because they carry
    the campaign name in the words the responders used. Only when the text
    matches nothing known does this give up, and the caller then falls back to
    the summary itself, which still says what the package is."""
    text = ""
    if lookup:
        record = fetch_advisory(advisory_id)
        text = f"{record.get('summary', '')} {record.get('details', '')}".lower()
    if not text:
        text = ADVISORY_NOTES.get(advisory_id, "").lower()
    for pattern, label in CAMPAIGN_PATTERNS:
        if re.search(pattern, text):
            return label
    return None


def advisory_summary(advisory_id: str, lookup: bool = True) -> str:
    """One line saying what this advisory is, preferring OSV's own words."""
    if advisory_id in ADVISORY_NOTES:
        return ADVISORY_NOTES[advisory_id]
    if lookup:
        record = fetch_advisory(advisory_id)
        summary = str(record.get("summary") or "").strip()
        if summary:
            details = str(record.get("details") or "").strip().replace("\n", " ")
            if details:
                return f"{summary}. {details[:240]}".strip()
            return summary
    return "malicious-package advisory (see OSV.dev)"


def _advisory_note(advisory_id: str, lookup: bool = True) -> str:
    """Return the note for an advisory, naming its campaign where one is known."""
    campaign = campaign_of(advisory_id, lookup)
    summary = advisory_summary(advisory_id, lookup)
    if campaign:
        return f"{campaign}. {summary}"
    return summary


def _coverage_line(status: RepoStatus, osv_bin: str | None) -> str:
    """Say what OSV-Scanner did for this repository, and when it did not, why.

    A repository with no OSV verdict is not a repository OSV called clean, and
    the two are indistinguishable unless the report says which happened."""
    if status.osv_checked:
        return f"  osv-scanner: {len(status.lockfiles)} lockfile(s) submitted and resolved"
    if not osv_bin:
        return "  osv-scanner: not run (scanner not found), so only the offline layer applies here"
    if not status.lockfiles:
        return (
            "  osv-scanner: not run (no lockfile in this repository), so nothing was resolved "
            "and transitive dependencies were never seen"
        )
    if status.osv_resolved_count:
        return (
            f"  osv-scanner: only {status.osv_resolved_count} of {len(status.lockfiles)} "
            "lockfile(s) resolved, so treat this repository as unchecked by the live "
            "database: the one that failed may be the one that mattered"
        )
    return (
        f"  osv-scanner: {len(status.lockfiles)} lockfile(s) found but not successfully submitted, "
        "so treat this repository as unchecked by the live database"
    )


DETECTION_LEGEND: tuple[str, ...] = (
    "How each verdict below was reached",
    "-----------------------------------",
    "Two layers run, and every finding names the one that produced it.",
    "",
    "  offline table  This script's own list of poisoned package@versions, the built-in table",
    "                 plus the campaign overlay. It matches text: resolved versions in a",
    "                 lockfile, declared ranges in a package.json, and known worm payload",
    "                 filenames anywhere in the tree. It needs no network and no lockfile, and",
    "                 it is the only layer that can flag a declared range that has not been",
    "                 installed yet. It sees only the names it already knows.",
    "",
    "  osv-scanner    The live OSV.dev malicious-package database, queried per lockfile. It",
    "                 resolves the whole dependency tree, so it is the only layer that sees a",
    "                 transitive dependency, and it covers packages absent from the table",
    "                 above. It runs only where a lockfile exists, so a repository with just a",
    "                 package.json gets no verdict from it at all.",
    "",
    "Neither layer subsumes the other. A repository is reported clean only in the sense of",
    "what the layers that actually ran could see, which is why each entry states its coverage.",
    "",
)


def render_vulnerable_summary(statuses: list[RepoStatus], lookup: bool = True) -> list[str]:
    """Build the trailing summary that lists ONLY vulnerable repositories,
    split into Shai-Hulud exposure and unrelated malicious-package hits, each
    line carrying the package, version, and advisory id, followed by a note
    per distinct advisory. This is the actionable digest of the whole run."""
    vulnerable = [s for s in statuses if s.vulnerable()]
    shai = [s for s in vulnerable if s.shai_hulud_hit()]
    unrelated = [s for s in vulnerable if not s.shai_hulud_hit()]
    seen_advisories: set[str] = set()

    lines: list[str] = [
        "",
        "================================================================",
        "VULNERABLE REPOSITORIES SUMMARY",
        "================================================================",
        f"Vulnerable repositories:                 {len(vulnerable)}",
        f"  Shai-Hulud campaign exposure:          {len(shai)}",
        f"  Other malicious packages (OSV):        {len(unrelated)}",
        "",
    ]

    lines.append(f"SHAI-HULUD CAMPAIGN EXPOSURE ({len(shai)})")
    if not shai:
        lines.append("  none")
    for status in sorted(shai, key=lambda s: s.name.lower()):
        lines.append(f"  [{status.name}]")
        if status.poisoned_versions:
            lines.append(
                f"    [offline table] resolved poisoned: {_format_versions(status.poisoned_versions)}"
            )
        if status.poisoned_ranges:
            lines.append(
                "    [offline table] range could resolve to poisoned: "
                f"{_format_versions({k: {'/'.join(sorted(v))} for k, v in status.poisoned_ranges.items()})}"
            )
        for payload_file in status.payload_files:
            lines.append(f"    [offline table] payload artifact: {payload_file}")
        for key, ids in sorted(status.osv_advisory_ids.items()):
            shai_ids = sorted(i for i in ids if _is_shai_hulud_name(key.rsplit("@", 1)[0]))
            if shai_ids:
                lines.append(f"    [osv-scanner] {key}: {', '.join(shai_ids)}")
                seen_advisories.update(shai_ids)
        for key, ids in sorted(status.trivy_confirmed.items()):
            lines.append(f"    [trivy] confirms {key}: {', '.join(sorted(ids))}")
    lines.append("")

    lines.append(f"MALICIOUS PACKAGES FROM OTHER CAMPAIGNS ({len(unrelated)})")
    if not unrelated:
        lines.append("  none")
    for status in sorted(unrelated, key=lambda s: s.name.lower()):
        hit_parts: list[str] = []
        for key, ids in sorted(status.osv_advisory_ids.items()):
            hit_parts.append(f"{key} ({', '.join(sorted(ids))})")
            seen_advisories.update(ids)
        lines.append(f"  [{status.name}]  [osv-scanner] {'; '.join(hit_parts)}")
        for advisory in sorted({a for ids in status.osv_advisory_ids.values() for a in ids}):
            campaign = campaign_of(advisory, lookup)
            if campaign:
                lines.append(f"    {advisory} belongs to {campaign}")
    lines.append("")

    if seen_advisories:
        lines.append("ADVISORY NOTES")
        for advisory_id in sorted(seen_advisories):
            lines.append(f"  {advisory_id}: {_advisory_note(advisory_id, lookup)}")
        lines.append("")

    return lines


def render_human(statuses: list[RepoStatus], osv_bin: str | None, lookup: bool = True) -> str:
    """Format the per-repo tiered report."""
    total = len(statuses)
    with_npm = [s for s in statuses if s.has_npm]
    with_package = [s for s in with_npm if s.package_present()]
    vulnerable = [s for s in statuses if s.vulnerable()]
    osv_checked = [s for s in statuses if s.osv_checked]

    lines: list[str] = [
        "Shai-Hulud per-repo exposure report",
        "====================================",
        f"Repositories scanned:            {total}",
        f"Repositories with npm tooling:    {len(with_npm)}",
        f"Repositories with watched deps:   {len(with_package)}",
        f"Repositories vulnerable:          {len(vulnerable)}",
        (
            f"OSV-Scanner cross-check:          {osv_bin} "
            f"({len(osv_checked)} repo(s) submitted)"
            if osv_bin
            else "OSV-Scanner cross-check:          skipped (scanner not found)"
        ),
        "",
        *DETECTION_LEGEND,
    ]

    for status in sorted(statuses, key=lambda s: s.name.lower()):
        lines.append(f"[{status.name}]")
        if not status.has_npm:
            lines.append("  npm: no")
            lines.append("")
            continue
        lines.append("  npm: yes")
        lines.append(_coverage_line(status, osv_bin))
        if not status.package_present() and not status.vulnerable():
            lines.append("  watched packages present: no")
            lines.append("  vulnerable: no")
            lines.append("")
            continue
        if not status.package_present():
            lines.append("  watched packages present: no (OSV-Scanner found unrelated hits below)")
        if status.present_versions:
            lines.append(
                f"  watched packages resolved: {_format_versions(status.present_versions)}"
            )
        if status.range_only:
            lines.append(
                f"  watched packages declared (unresolved range): "
                f"{_format_versions({k: {'/'.join(sorted(v))} for k, v in status.range_only.items()})}"
            )
        if status.vulnerable():
            lines.append("  vulnerable: YES")
            if status.poisoned_versions:
                lines.append(
                    f"    [offline table] a lockfile resolves a watched package to a version on "
                    f"the poisoned list: {_format_versions(status.poisoned_versions)}"
                )
            if status.poisoned_ranges:
                lines.append(
                    f"    [offline table] a package.json range could resolve to a poisoned version "
                    f"on the next install: "
                    f"{_format_versions({k: {'/'.join(sorted(v))} for k, v in status.poisoned_ranges.items()})}"
                )
            if status.payload_files:
                lines.append(
                    "    [offline table] file name(s) matching a known worm payload artifact:"
                )
                for payload_file in status.payload_files:
                    lines.append(f"      {payload_file}")
            shai_hulud_hits = {
                k: v for k, v in status.osv_malicious.items() if _is_shai_hulud_name(k)
            }
            other_hits = {
                k: v for k, v in status.osv_malicious.items() if not _is_shai_hulud_name(k)
            }
            if shai_hulud_hits:
                lines.append(
                    f"    [osv-scanner] the live database flags a resolved dependency, "
                    f"Shai-Hulud family: {_format_versions(shai_hulud_hits)}"
                )
            if other_hits:
                # Name the campaign rather than the one it is not. Where the
                # advisories agree on a campaign it is stated; where they do not,
                # the advisory's own summary is used, which still says what it is.
                other_ids = {
                    advisory
                    for key, ids in status.osv_advisory_ids.items()
                    if key.rsplit("@", 1)[0] in other_hits
                    for advisory in ids
                }
                campaigns = {c for c in (campaign_of(a, lookup) for a in sorted(other_ids)) if c}
                if campaigns:
                    attribution = "; ".join(sorted(campaigns))
                else:
                    attribution = "; ".join(
                        sorted({advisory_summary(a, lookup) for a in sorted(other_ids)})
                    )
                lines.append(
                    f"    [osv-scanner] the live database flags a resolved dependency: "
                    f"{_format_versions(other_hits)}"
                )
                lines.append(f"      attributed to: {attribution}")
            if status.osv_malicious:
                for key, ids in sorted(status.osv_advisory_ids.items()):
                    lines.append(f"      {key}: {', '.join(sorted(ids))}")
            if status.trivy_confirmed:
                for key, ids in sorted(status.trivy_confirmed.items()):
                    lines.append(
                        f"    [trivy] independently confirms {key}: {', '.join(sorted(ids))}"
                    )
            elif status.trivy_checked:
                lines.append(
                    "    [trivy] consulted and had nothing on these packages, which is the "
                    "expected result: its npm feed carries no malicious-package advisories, so "
                    "this neither confirms nor weakens the finding"
                )
        else:
            lines.append("  vulnerable: no")
        lines.append("")
    lines.extend(render_vulnerable_summary(statuses, lookup))
    return "\n".join(lines).rstrip() + "\n"


def render_json(statuses: list[RepoStatus]) -> str:
    """Serialize the per-repo statuses to JSON."""

    def to_dict(status: RepoStatus) -> dict[str, object]:
        return {
            "name": status.name,
            "path": status.path,
            "has_npm": status.has_npm,
            "npm_files": status.npm_files,
            "lockfiles": status.lockfiles,
            "present_versions": {k: sorted(v) for k, v in status.present_versions.items()},
            "range_only": {k: sorted(v) for k, v in status.range_only.items()},
            "poisoned_versions": {k: sorted(v) for k, v in status.poisoned_versions.items()},
            "poisoned_ranges": {k: sorted(v) for k, v in status.poisoned_ranges.items()},
            "payload_files": status.payload_files,
            "osv_checked": status.osv_checked,
            "osv_malicious": {k: sorted(v) for k, v in status.osv_malicious.items()},
            "osv_advisory_ids": {k: sorted(v) for k, v in status.osv_advisory_ids.items()},
            "package_present": status.package_present(),
            "vulnerable": status.vulnerable(),
        }

    return json.dumps([to_dict(s) for s in statuses], indent=2)


def main() -> int:
    """Entry point: parse arguments, scan all roots, and print or write results."""
    parser = argparse.ArgumentParser(
        prog="lockfile-sentinel",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"lockfile-sentinel {__version__}"
    )
    parser.add_argument(
        "--root",
        action="append",
        dest="roots",
        help="Root directory to scan; repeatable. Default: the current directory.",
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="Prove the detector works: scan a temporary lockfile pinning two packages with "
        "published malicious-package advisories and assert both are reported.",
    )
    parser.add_argument(
        "--include-node-modules",
        action="store_true",
        help="Also walk into node_modules directories (slower).",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    parser.add_argument("-o", "--output", help="Write output to this file instead of stdout.")
    parser.add_argument(
        "--summary-out",
        help="Also write the vulnerable-repositories summary (only the vulnerable repos, "
        "split into Shai-Hulud and unrelated, with advisory notes) to this separate file.",
    )
    parser.add_argument(
        "--no-osv",
        action="store_true",
        help="Skip the OSV-Scanner cross-check; use only the built-in poisoned-package table.",
    )
    parser.add_argument(
        "--no-overlay",
        action="store_true",
        help="Do not load compromised-npm-packages.json; use only the built-in table.",
    )
    parser.add_argument(
        "--overlay-file",
        default=str(OVERLAY_PATH),
        help="Path to the campaign overlay written by update_scanners.py malicious-packages "
        "(default: the cache directory, see LOCKFILE_SENTINEL_CACHE).",
    )
    parser.add_argument(
        "--osv-scanner-bin",
        help="Explicit path to the osv-scanner executable (else PATH / OSV_SCANNER_BIN env var).",
    )
    parser.add_argument(
        "--osv-batch-size",
        type=int,
        default=100,
        help="Max lockfiles per osv-scanner invocation (default: 100).",
    )
    parser.add_argument(
        "--osv-timeout",
        type=int,
        default=120,
        help="Timeout in seconds per osv-scanner batch (default: 120).",
    )
    parser.add_argument(
        "--no-refresh",
        action="store_true",
        help="Skip the throttled campaign-overlay refresh before scanning.",
    )
    parser.add_argument(
        "--min-interval",
        type=int,
        default=60,
        help="Minutes before the campaign overlay is fetched again (default: 60).",
    )
    parser.add_argument(
        "--lockfile",
        action="append",
        dest="lockfiles",
        help="Diagnose this lockfile alone, skipping the walk. Repeatable.",
    )
    parser.add_argument(
        "--lockfiles-from",
        help="Diagnose the lockfiles listed one per line in this file, skipping the walk. "
        "A failing run writes exactly such a list to logs/osv-extraction-failures.txt "
        "under the cache directory (LOCKFILE_SENTINEL_CACHE, else the platform cache).",
    )
    parser.add_argument(
        "--osv-debug",
        action="store_true",
        help="Log the full osv-scanner output and the group contents whenever it fails, "
        "instead of the single line it volunteers.",
    )
    parser.add_argument(
        "--no-advisory-lookup",
        action="store_true",
        help="Do not fetch advisory records from OSV.dev to name the campaign behind a finding. "
        "Names then come from the built-in notes alone.",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=min(16, (os.cpu_count() or 4) * 2),
        help="Directories read in parallel during the walk (default: twice the core count, "
        "capped at 16). 1 walks sequentially.",
    )
    parser.add_argument(
        "--no-trivy",
        action="store_true",
        help="Do not re-check flagged findings against Trivy's database.",
    )
    parser.add_argument(
        "--trivy-timeout",
        type=int,
        default=300,
        help="Timeout in seconds per Trivy re-check (default: 300).",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Report when each database and the scanner binary were last updated, and how long "
        "ago, then exit. 0 all fresh, 1 something stale, 2 something unknown.",
    )
    parser.add_argument(
        "--osv",
        nargs=argparse.REMAINDER,
        metavar="ARG",
        help="Pass everything that follows to `osv-scanner scan` and exit with its code, "
        "instead of running the repository sweep.",
    )
    args = parser.parse_args()

    # Status reports on the inputs and changes nothing, so it runs before the
    # checks that would refresh them and skew the very ages it is reporting.
    if args.status:
        return report_status(Path(args.overlay_file), find_osv_scanner(args.osv_scanner_bin))

    if args.selftest:
        return run_selftest(find_osv_scanner(args.osv_scanner_bin), args.osv_timeout)

    # Diagnosis mode short-circuits everything: named lockfiles, one at a time,
    # no walk. This is the loop for investigating an extraction failure.
    named: list[str] = list(args.lockfiles or [])
    if args.lockfiles_from:
        try:
            named.extend(
                line.strip()
                for line in Path(args.lockfiles_from).read_text(encoding="utf-8").splitlines()
                if line.strip()
            )
        except OSError as exc:
            _progress(f"FAIL: could not read {args.lockfiles_from} ({exc})")
            return 2
    if named:
        return diagnose_lockfiles(
            find_osv_scanner(args.osv_scanner_bin), named, args.osv_timeout
        )

    # Passthrough mode short-circuits the sweep: no walk, no overlay, no report.
    # The overlay refresh below does not apply to it, because osv-scanner never
    # reads the overlay and the download would feed nothing.
    if args.osv is not None:
        return run_passthrough(find_osv_scanner(args.osv_scanner_bin), args.osv)

    # Refresh before the overlay is loaded below, or the run scans with the
    # previous campaign list and refreshes only for the next one.
    if not args.no_refresh and not args.no_overlay:
        refresh_overlay(Path(args.overlay_file), args.min_interval)

    if not args.no_overlay:
        overlay = load_overlay(Path(args.overlay_file))
        if overlay:
            added = apply_overlay(overlay)
            _progress(
                f"overlay: {len(overlay)} campaign packages from {args.overlay_file} "
                f"(+{added} versions over the built-in table)"
            )
        else:
            _progress(
                f"overlay: none loaded ({args.overlay_file} absent or empty); "
                "using built-in table. Run: python update_scanners.py malicious-packages"
            )

    # Default to the current directory rather than to anything guessed: a
    # scanner that silently walks somewhere the caller did not name is a scanner
    # whose report cannot be trusted to describe what they meant.
    # Resolved, not taken as given. osv-scanner reports absolute source paths in
    # its results, so a relative root produced relative index keys that never
    # matched the absolute keys coming back, and every live-database finding for
    # that run was silently discarded while the coverage line still claimed the
    # lockfile had been submitted and resolved. A package the offline table does
    # not already know would have been reported clean.
    roots = [Path(r).resolve() for r in (args.roots or ["."])]

    # A root that does not resolve is fatal, not skippable. Skipping it left
    # all_statuses empty, printed "Repositories scanned: 0" and exited 0, so a
    # mistyped path in an automation produced a clean bill of health for a tree
    # nothing had looked at. Exit 2 is the documented code for a check that
    # could not be performed.
    unusable = [r for r in roots if not r.is_dir()]
    if unusable:
        for root in unusable:
            reason = "does not exist" if not root.exists() else "is not a directory"
            _progress(f"FAIL: root {root} {reason}")
        _progress("refusing to report on a scan that could not cover every root given")
        return 2

    # Size the walk before starting it, so the percentage and the estimate have
    # a denominator. Counting repositories rather than top-level directories is
    # what makes the number mean something on a tree where one directory holds
    # several repositories, and stopping at each .git keeps the pass to seconds.
    counted = 0
    for root in roots:
        if not root.is_dir():
            continue
        _progress(f"counting repositories under {root} ...")
        started_count = time.monotonic()
        root_total = sum(
            count_repositories(unit, args.include_node_modules)
            for unit in top_level_units(root, args.include_node_modules)
        )
        counted += root_total
        _progress(f"  {root_total} repository(ies) in "
                  f"{format_elapsed(time.monotonic() - started_count)}")
    walk_progress = WalkProgress(counted, desc="walk")

    all_statuses: list[RepoStatus] = []
    lockfile_index: dict[str, RepoStatus] = {}
    for root in roots:
        statuses, root_lockfile_index = scan_root(
            root, args.include_node_modules, walk_progress, args.jobs
        )
        all_statuses.extend(statuses.values())
        lockfile_index.update(root_lockfile_index)
    walk_progress.finish()

    osv_bin = None if args.no_osv else find_osv_scanner(args.osv_scanner_bin)

    def render() -> str:
        return (render_json(all_statuses) if args.json
                else render_human(all_statuses, osv_bin, not args.no_advisory_lookup))

    def persist(text: str) -> None:
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text if text.endswith("\n") else text + "\n")

    # Write the tier 1/2 report as soon as the walk is done, before OSV runs.
    # From this point a killed run still leaves a complete per-repo report on
    # disk; OSV batches below only upgrade it in place.
    if args.output:
        persist(render())
        _progress(f"tier 1/2 report written to {args.output}; starting OSV cross-check")

    if osv_bin and lockfile_index:
        def on_batch_done(
            findings: dict[str, list[tuple[str, str, set[str]]]], processed: set[str]
        ) -> None:
            apply_osv_results(lockfile_index, findings, processed)
            if args.output:
                persist(render())

        run_osv_scanner(
            osv_bin,
            list(lockfile_index.keys()),
            args.osv_batch_size,
            args.osv_timeout,
            on_batch_done=on_batch_done,
            debug=args.osv_debug,
        )

    # Trivy is asked only about what was already flagged, so this runs after the
    # sweep and never widens the scan.
    if not args.no_trivy:
        trivy_bin = resolve_trivy()
        if trivy_bin:
            trivy_recheck(all_statuses, trivy_bin, args.trivy_timeout)
        else:
            _progress("trivy re-check skipped: trivy not found")

    persist(render())

    if args.summary_out:
        summary_text = "\n".join(
            render_vulnerable_summary(all_statuses, not args.no_advisory_lookup)
        ).lstrip("\n") + "\n"
        Path(args.summary_out).write_text(summary_text, encoding="utf-8")
        _progress(f"vulnerable-repositories summary written to {args.summary_out}")

    return 1 if any(s.vulnerable() for s in all_statuses) else 0


if __name__ == "__main__":
    sys.exit(main())
