"""Lockfile Sentinel: an npm supply-chain scanner in one file.

A fast, zero-dependency npm supply-chain scanner. Originally built to detect the
Shai-Hulud worm, it now cross-checks lockfiles against the live OSV.dev database
to catch a wide range of malicious packages.

Inputs are lockfiles, package.json ranges and repository trees by filename, so a
poisoning that has been installed and one that the next install would pull are
both reported, and worm payload artifacts are found by name wherever they sit.

Reports, per repository (a directory containing a .git entry, or a
top-level directory under a scanned root when no .git is present):

1. Does npm/pnpm/yarn/bun tooling exist at all (package.json or a lockfile)?
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
    python lockfile_sentinel.py --status --json
    python lockfile_sentinel.py --status --check-live
    python lockfile_sentinel.py --no-osv
    python lockfile_sentinel.py --json -o findings.json
    python lockfile_sentinel.py --lockfile path/to/package-lock.json
    python lockfile_sentinel.py --osv source -r /path/to/app
"""

# Lockfile Sentinel 0.2.0
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
import hashlib
import io
import json
import math
import os
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__version__ = "0.2.0"

# The machine-readable contracts this program emits, named and versioned so a
# consumer can refuse a document it does not understand instead of guessing.
# Scan reports and status reports are different documents answering different
# questions, so each carries its own name; the version is a single integer
# because every planned change is an added field, and an added field is
# non-breaking under either name.
REPORT_SCHEMA_NAME = "lockfile-sentinel-report"
REPORT_SCHEMA_VERSION = 1
STATUS_SCHEMA_NAME = "lockfile-sentinel-status"
STATUS_SCHEMA_VERSION = 1

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

# Counted before any overlay merge, because apply_overlay grows the table in
# place and the report has to state what shipped in the source separately from
# what the feed added on this particular day.
_BUILTIN_PACKAGE_COUNT: int = len(POISONED_VERSIONS)
_BUILTIN_VERSION_COUNT: int = sum(len(v) for v in POISONED_VERSIONS.values())

# PEP 695 aliases, which is one of the reasons this file requires 3.12. The walk
# passes the same two shapes everywhere, and naming them once makes the
# signatures below say what they carry instead of restating a nested generic.
type WalkTriples = list[tuple[Path, list[str], list[str]]]
type StatusesByOwner = dict[Path, "RepoStatus"]
type LockfileIndex = dict[str, "RepoStatus"]



class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse any redirect that leaves https.

    Every URL this program fetches is https, but a redirect is the server's
    choice, not the caller's: a compromised or spoofed endpoint answering 301
    with an http:// location would downgrade the fetch to cleartext and hand
    the overlay or an advisory to whoever sits on the path. The same hole was
    found and closed in update_scanners.py; this file is standalone by design,
    so it carries its own copy."""

    def redirect_request(
        self, req: urllib.request.Request, fp: Any, code: int, msg: str,
        headers: Any, newurl: str,
    ) -> urllib.request.Request | None:
        if not newurl.lower().startswith("https://"):
            raise urllib.error.HTTPError(
                newurl, code, "redirect to a non-https URL refused", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open_https(request: urllib.request.Request, timeout: int) -> Any:
    """Open one https request through the downgrade-refusing opener.

    The opener is built per call rather than kept at module level, so a test
    that stubs the network stubs one seam and a run pays three builds at
    most: the overlay refresh, an advisory fetch, and the live check."""
    if not request.full_url.lower().startswith("https://"):
        raise ValueError(f"refusing to fetch a non-https URL: {request.full_url}")
    opener = urllib.request.build_opener(_HttpsOnlyRedirects)
    return opener.open(request, timeout=timeout)  # nosec B310


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
# The taxonomy follows the public reporting below, and the Shai-Hulud
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

# The five LOCKFILE_NAMES entries get scan_lockfile's text pass, one code
# path for all of them, and the names ending .json get the structural JSON
# pass on top of it.
# npm-shrinkwrap.json shares package-lock.json's schema outright, so it takes
# the same structural path; bun.lock does not end .json, so the JSON pass is
# never dispatched to it, and extending that pass to it would need a JSONC
# parser since bun writes trailing commas. Its "name@version" resolution
# strings are exactly what the token patterns match. The campaign's own
# payload marker is bun_environment.js, so a scanner that finds the Bun
# payload by filename had no business walking past Bun's lockfile.
# Named once each: the bun lockfile, the JSON suffix and the manifest name are
# each tested in several places, and a scanner whose dispatch literals can
# drift apart is a scanner whose passes can disagree about which file is which.
BUN_LOCKFILE_NAME = "bun.lock"
JSON_SUFFIX = ".json"
MANIFEST_NAME = "package.json"

# The one timestamp shape this program writes and reads back: RFC 3339 UTC,
# whole seconds, Z suffix. Stated once so the writer and the parsers cannot
# disagree about fractional seconds or the offset spelling.
ISO_UTC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

LOCKFILE_NAMES: frozenset[str] = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        BUN_LOCKFILE_NAME,
    }
)
# Derived rather than restated, so a lockfile added to the set above marks npm
# tooling without a second edit: the original coverage gap was exactly a name
# present in one hand-kept list and absent from the other. package.json is the
# one member that is not a lockfile, being a marker and a range source only,
# and it never passes through scan_lockfile.
NPM_MARKER_FILES: frozenset[str] = LOCKFILE_NAMES | {MANIFEST_NAME}

# How many unreadable-directory paths a repository stores and serializes; the
# count of them is kept in full separately.
UNREADABLE_DIRS_STORED_LIMIT: int = 100
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
    # Directories the walk could not enumerate. Anything beneath one was never
    # seen, so a repository carrying an entry here is incomplete coverage, not
    # a clean tree that happened to be small. The list is a bounded preview,
    # because a hostile tree can manufacture unreadable directories by the
    # thousand; the total carries the real count and is what the verdicts use.
    unreadable_dirs: list[str] = field(default_factory=list)
    unreadable_dir_total: int = 0
    # npm_files records what the walk found; these two record whether it yielded
    # anything. unreadable_files covers both halves of that: a manifest whose
    # permissions deny access or which disappeared between enumeration and
    # scanning was never opened, and one holding invalid JSON, or JSON that is
    # not an object, was opened and told the scanner nothing. Both contributed
    # exactly as much to the verdict, and a report that cannot separate either
    # from a file it actually read claims coverage it does not have.
    read_files: list[str] = field(default_factory=list)
    unreadable_files: list[str] = field(default_factory=list)
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
    # The lockfiles the scanner ran against and rejected, and the ones that were
    # never handed to it at all (empty at submission time, or unreadable when
    # sized). Together with the resolved count these are what let the coverage
    # object state submitted and resolved as numbers instead of one boolean.
    osv_failed_count: int = 0
    osv_skipped_count: int = 0
    # Lockfiles the scanner never answered on (timeout, spawn failure,
    # unparsable output), and lockfiles that were empty and so resolved
    # vacuously without a submission. Both are needed for the coverage counts
    # to reconcile: submitted has to mean what was actually handed over.
    osv_unavailable_count: int = 0
    osv_empty_count: int = 0
    osv_malicious: dict[str, set[str]] = field(default_factory=dict)
    osv_advisory_ids: dict[str, set[str]] = field(default_factory=dict)
    trivy_checked: bool = False
    trivy_confirmed: dict[str, set[str]] = field(default_factory=dict)
    trivy_submitted_count: int = 0
    trivy_failed_count: int = 0
    # Which file produced each poisoned coordinate, keyed (kind, name,
    # version-or-spec) with kind "resolved" or "range". The findings array names
    # its evidence, and without this the best a finding could claim is "one of
    # the files this repository holds". OSV attribution is exact, since the
    # scanner reports per source path; offline attribution is exact too, since
    # each file is matched into a probe of its own before merging, so every
    # file carrying a coordinate is listed however many carried it first.
    evidence: dict[tuple[str, str, str], set[str]] = field(default_factory=dict)
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


def scan_package_json(path: Path, status: RepoStatus) -> bool:
    """Record every watched-package dependency range declared in a package.json.

    Returns whether the file was read and parsed as a JSON object, which is a
    weaker claim than finding anything in it: a manifest declaring no watched
    dependency at all still returns True, because it was read and it did
    contribute, by contributing nothing. False covers a file that could not be
    opened or decoded and one whose JSON is not an object, since a manifest
    nothing could parse tells the caller exactly as little as one nothing could
    open."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(data, dict):
        return False
    # Scanned into a probe of this manifest alone, then merged, so a poisoned
    # range already declared by an earlier manifest is still attributed here
    # rather than credited only to the first file that carried it.
    probe = RepoStatus(name=status.name, path=status.path)
    _scan_dependency_fields(data, probe)
    for attribute in ("range_only", "poisoned_ranges"):
        target = getattr(status, attribute)
        for name, specs in getattr(probe, attribute).items():
            target.setdefault(name, set()).update(specs)
    for name, specs in probe.poisoned_ranges.items():
        for spec in specs:
            status.evidence.setdefault(("range", name, spec), set()).add(str(path))
    return True


def _scan_dependency_fields(data: dict[str, Any], status: RepoStatus) -> None:
    """Record every watched range across the four dependency fields."""
    for field_name in DEPENDENCY_FIELDS:
        deps = data.get(field_name)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if isinstance(spec, str):
                _record_watched_range(status, name, spec)


def _record_watched_range(status: RepoStatus, name: str, spec: str) -> None:
    """Record one declared range if the package is watched, by name or scope."""
    if name in POISONED_VERSIONS:
        record_declared_range(status, name, spec, POISONED_VERSIONS[name])
        return
    for prefix, poisoned_version in POISONED_SCOPES.items():
        if name.startswith(prefix):
            record_declared_range(status, name, spec, [poisoned_version])
            return


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


def scan_npm_lockfile_json(text: str, status: RepoStatus) -> None:
    """Parse an npm lockfile as JSON rather than matching it as text.

    The text patterns match a registry tarball URL or a name@version token, and
    both are absent from a v2 or v3 entry that carries no `resolved` field,
    which happens for workspace links and for lockfiles written with the
    registry omitted. Such an entry pins a version like any other, so matching
    only text would miss a poisoned pin that is plainly stated in the file.

    Takes the text the caller already read rather than opening the file again.
    A second open is a second chance to fail: a lockfile removed between the two
    reads left this pass silently skipped while the caller still recorded the
    file as read, so the report could name a lockfile it had only half examined,
    and the half that did not run is the only one that sees a versioned entry
    with no `resolved` field. Reusing the text removes the window rather than
    reporting it.

    A byte-order mark is stripped here because the caller decodes as plain
    utf-8, which leaves it in the string, and json.loads rejects it.

    Both lockfile shapes are read: `packages`, keyed by path, in v2 and v3, and
    the nested `dependencies` tree in v1."""
    try:
        data = json.loads(text.lstrip("\ufeff"))
    except json.JSONDecodeError:
        return
    if not isinstance(data, dict):
        return

    packages = data.get("packages")
    if isinstance(packages, dict):
        _scan_lock_packages(packages, status)
    if "packages" not in data:
        _walk_v1_dependencies(data.get("dependencies"), status)


def _record_watched_version(status: RepoStatus, name: str, version: object) -> None:
    """Record one resolved version if it is a string and the name is watched."""
    if not isinstance(version, str) or not version:
        return
    watched = _watched(name)
    if watched is not None:
        record_resolved_version(status, name, version, watched)


def _scan_lock_packages(packages: dict[str, Any], status: RepoStatus) -> None:
    """Read the v2/v3 `packages` map, which is keyed by install path."""
    for key, entry in packages.items():
        if not isinstance(entry, dict) or not isinstance(key, str):
            continue
        # "node_modules/@scope/name" and "a/node_modules/name" both name the
        # package after the last node_modules segment; "" is the root project.
        name = key.rsplit("node_modules/", 1)[-1] if "node_modules/" in key else ""
        if name:
            _record_watched_version(status, name, entry.get("version"))


def _walk_v1_dependencies(tree: object, status: RepoStatus) -> None:
    """Walk the nested v1 dependency tree, which nests the same shape."""
    if not isinstance(tree, dict):
        return
    for name, entry in tree.items():
        if not isinstance(name, str) or not isinstance(entry, dict):
            continue
        _record_watched_version(status, name, entry.get("version"))
        _walk_v1_dependencies(entry.get("dependencies"), status)


def _strip_jsonc_comments(text: str) -> str:
    """Remove // and /* */ comments from JSONC, leaving string contents alone.

    String awareness is the whole job. Every registry URL carries the line
    comment marker inside a string, `https://` and all, so a stripper that did
    not track string state would truncate the exact lines the tarball patterns
    match and silently lose every finding in the file. Escapes are honoured so
    a quote written as \\" inside a string cannot end it early.

    Newlines inside a block comment are kept, so removing one never joins two
    lines into a token that neither line carried."""
    out: list[str] = []
    position = 0
    length = len(text)
    while position < length:
        char = text[position]
        if char == '"':
            position = _copy_string(text, position, out)
        elif char == "/" and text[position + 1:position + 2] == "/":
            position = text.find("\n", position)
            if position == -1:
                position = length
        elif char == "/" and text[position + 1:position + 2] == "*":
            position = _skip_block_comment(text, position, out)
        else:
            out.append(char)
            position += 1
    return "".join(out)


def _copy_string(text: str, position: int, out: list[str]) -> int:
    """Copy one JSON string, opening quote included, honouring escapes.

    Returns the position just past the closing quote, or the end of the text
    for an unterminated string, which is copied as it stands."""
    length = len(text)
    out.append(text[position])
    position += 1
    while position < length:
        char = text[position]
        out.append(char)
        if char == "\\" and position + 1 < length:
            out.append(text[position + 1])
            position += 2
            continue
        position += 1
        if char == '"':
            break
    return position


def _skip_block_comment(text: str, position: int, out: list[str]) -> int:
    """Skip one block comment, keeping its newlines so lines never join."""
    length = len(text)
    position += 2
    while position + 1 < length and not (
        text[position] == "*" and text[position + 1] == "/"
    ):
        if text[position] == "\n":
            out.append("\n")
        position += 1
    return position + 2


def scan_lockfile(path: Path, status: RepoStatus) -> bool:
    """Record every watched-package version actually resolved in a lockfile.

    Two passes, because neither alone is complete. The text pass covers every
    lockfile format with one code path, npm, pnpm, yarn and bun alike, and
    catches a version wherever it appears. The JSON pass is dispatched on the
    .json suffix and reads npm-schema lockfiles structurally,
    package-lock.json and npm-shrinkwrap.json both since shrinkwrap is the
    same document under another name, and catches entries the text pass
    cannot see, such as a v3 entry with no `resolved` URL. bun.lock does not
    carry that suffix, so it gets the text pass alone, which suffices: its
    resolution strings carry the name@version tokens the patterns match, and
    the strict JSON pass could not read it anyway, bun writing JSONC with
    trailing commas. Recording the same version twice is harmless, since
    versions are collected into sets.

    A lockfile that contributes a poisoned version is remembered by name, so a
    later re-check can submit that file alone rather than every lockfile the
    repository happens to contain.

    Both passes work from a single read, so a file that is opened once is
    examined twice rather than opened twice and possibly examined once. Reading
    it again for the JSON pass would have made the structural half depend on the
    file still being there, and that half is the only one that sees a versioned
    entry carrying no `resolved` field.

    Returns whether the file was read. The one read decides it: a lockfile whose
    JSON is malformed was still read and still matched by the patterns, which is
    a real npm lockfile state rather than a failure to look."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    if path.name.lower() == BUN_LOCKFILE_NAME:
        # JSONC admits comments, and the token patterns match raw text, so a
        # commented-out entry naming a poisoned version would otherwise be
        # recorded as a resolved pin the effective tree does not contain. A
        # comment installs nothing, so stripping it loses no real pin.
        text = _strip_jsonc_comments(text)
    # Matched into a probe of this file alone, then merged, so a poisoned pair
    # already known from an earlier lockfile is still attributed to this one:
    # diffing against the repository-wide state credited only the first file
    # that carried each coordinate, and the findings' evidence lists silently
    # omitted every duplicate occurrence.
    probe = RepoStatus(name=status.name, path=status.path)
    if path.name.lower().endswith(JSON_SUFFIX):
        scan_npm_lockfile_json(text, probe)
    _match_text_patterns(text, probe)
    for attribute in ("present_versions", "poisoned_versions"):
        target = getattr(status, attribute)
        for name, versions in getattr(probe, attribute).items():
            target.setdefault(name, set()).update(versions)
    if probe.poisoned_versions:
        status.flagged_lockfiles.add(str(path))
        for name, versions in probe.poisoned_versions.items():
            for version in versions:
                status.evidence.setdefault(
                    ("resolved", name, version), set()).add(str(path))
    return True


def _match_text_patterns(text: str, status: RepoStatus) -> None:
    """Run every tarball and token pattern over the lockfile text."""
    for name, (tarball_re, token_re) in _VERSION_PATTERNS.items():
        for pattern in (tarball_re, token_re):
            for version in pattern.findall(text):
                record_resolved_version(status, name, version, POISONED_VERSIONS[name])
    for prefix, poisoned_version in POISONED_SCOPES.items():
        tarball_re, token_re = _SCOPE_PATTERNS[prefix]
        for pattern in (tarball_re, token_re):
            for name, version in pattern.findall(text):
                record_resolved_version(status, name, version, [poisoned_version])


def scan_payload_filename(path: Path, status: RepoStatus) -> None:
    """Record a file whose name matches a known Shai-Hulud payload artifact."""
    if path.name in PAYLOAD_FILENAMES:
        status.payload_files.append(str(path))


def _walk(
    root: Path, include_node_modules: bool,
    unreadable_dirs: list[Path] | None = None,
) -> WalkTriples:
    """Walk a directory tree, returning (dirpath, dirnames, filenames) triples.

    dirnames as returned includes ignored directory names (.git, and
    node_modules when excluded) so callers can still detect them; only the
    traversal itself skips descending into them.

    A directory that cannot be enumerated is recorded in unreadable_dirs
    rather than skipped in silence: everything beneath it goes unseen, and a
    scan that cannot say so would report clean coverage over a subtree it
    never entered.
    """
    results: WalkTriples = []
    stack = [root]
    while stack:
        current = stack.pop()
        listing = _list_directory(current)
        if listing is None:
            if unreadable_dirs is not None:
                unreadable_dirs.append(current)
            continue
        dirnames, filenames = listing
        results.append((current, dirnames, filenames))
        stack.extend(
            current / name for name in dirnames
            if _descends_into(name, include_node_modules)
        )
    return results


def _list_directory(current: Path) -> tuple[list[str], list[str]] | None:
    """Classify one directory's entries, or None when it cannot be read.

    os.scandir rather than Path.iterdir with is_dir/is_file: on Windows the
    directory read already carries the attributes, so scandir answers both
    questions from cache while the Path form pays a separate stat per entry
    per question. Over a clone tree of a few hundred repositories that is
    the difference between minutes and tens of minutes, and the walk is
    the phase a person waits on.

    follow_symlinks=False on both tests, which classifies a symlink as
    neither a directory nor a file and so skips it. Following them would
    let a directory symlink inside a scanned tree walk and read files
    outside the root the caller named, which is the boundary SECURITY.md
    promises for an untrusted tree, and a symlink cycle would make the
    walk unbounded. The cost is that a lockfile reached only through a
    symlink is not scanned, which under-reports rather than escaping."""
    dirnames: list[str] = []
    filenames: list[str] = []
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
        return None
    return dirnames, filenames


def _descends_into(name: str, include_node_modules: bool) -> bool:
    """Whether the walk enters a directory of this name."""
    if name in ALWAYS_SKIP_DIRS:
        return False
    return name != "node_modules" or include_node_modules


def _find_repo_roots(triples: WalkTriples) -> list[Path]:
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
    triples: WalkTriples,
    root: Path,
    extra_roots: list[Path],
    statuses: dict[Path, RepoStatus],
    lockfile_index: dict[str, RepoStatus],
    unreadable_dirs: list[Path] | None = None,
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
            _attribute_file(dirpath / filename, filename, status, lockfile_index)
    for unreadable in unreadable_dirs or []:
        owner = _owner_repo(unreadable, repo_roots, root)
        if owner not in statuses:
            statuses[owner] = RepoStatus(name=_repo_label(root, owner), path=str(owner))
        status = statuses[owner]
        status.unreadable_dir_total += 1
        if len(status.unreadable_dirs) < UNREADABLE_DIRS_STORED_LIMIT:
            status.unreadable_dirs.append(str(unreadable))


def _attribute_file(
    file_path: Path, filename: str, status: RepoStatus,
    lockfile_index: dict[str, RepoStatus],
) -> None:
    """Scan one file into its owning repository's status."""
    if filename in NPM_MARKER_FILES:
        status.has_npm = True
        status.npm_files.append(str(file_path))
    # None where the file is neither a manifest nor a lockfile, which is
    # a different thing from a file that was one and failed to read.
    was_read: bool | None = None
    if filename == MANIFEST_NAME:
        was_read = scan_package_json(file_path, status)
    elif filename in LOCKFILE_NAMES:
        was_read = scan_lockfile(file_path, status)
        status.lockfiles.append(str(file_path))
        lockfile_index[_normalize_path(str(file_path))] = status
    if was_read is not None:
        target = status.read_files if was_read else status.unreadable_files
        target.append(str(file_path))
    scan_payload_filename(file_path, status)


def top_level_units(root: Path, include_node_modules: bool) -> list[Path]:
    """The directories under a root that the walk treats as units of work.

    A symlinked child is skipped here, not only inside the walk. Path.is_dir()
    follows symlinks, so a directory symlink directly under the root was handed
    to the walk as its starting point, and scandir then enumerated the target
    however carefully the walk treated symlinks below it. That left the tree
    boundary intact everywhere except at the one level an attacker controls
    most cheaply."""
    if not root.is_dir():
        return []
    try:
        entries = list(root.iterdir())
    except OSError:
        return []
    units = []
    for entry in entries:
        if entry.is_symlink() or not entry.is_dir():
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
        scanned = _count_subdirectories(current, include_node_modules)
        if scanned is None:
            continue
        has_git, dirnames = scanned
        if has_git:
            found += 1
        elif depth < max_depth:
            stack.extend((current / name, depth + 1) for name in dirnames)
    return found if found else 1


def _count_subdirectories(
    current: Path, include_node_modules: bool
) -> tuple[bool, list[str]] | None:
    """One directory read for the counting pass: whether it holds a .git, and
    the child directories worth descending into. None when it cannot be read.

    follow_symlinks=False for the same reason the walk uses it: this pass
    descends too, so a nested symlink would take the counting outside the root
    even once the walk itself stopped doing so."""
    dirnames: list[str] = []
    has_git = False
    try:
        with os.scandir(current) as entries:
            for entry in entries:
                try:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                if entry.name == ".git":
                    has_git = True
                elif entry.name != "node_modules" or include_node_modules:
                    dirnames.append(entry.name)
    except OSError:
        return None
    return has_git, dirnames


def scan_root(
    root: Path, include_node_modules: bool, progress: WalkProgress | None = None,
    jobs: int = 1,
) -> tuple[StatusesByOwner, LockfileIndex]:
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
        # Symlinks skipped for the same reason as in top_level_units: a
        # symlinked file directly under the root would otherwise be read from
        # wherever it points.
        root_files = [e.name for e in root.iterdir() if not e.is_symlink() and e.is_file()]
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
            unreadable_dirs: list[Path] = []
            triples = _walk(unit, include_node_modules, unreadable_dirs)
            _attribute(triples, root, extra_roots, statuses, lockfile_index,
                       unreadable_dirs)
            if progress is not None:
                progress.advance(_repo_label(root, unit), len(statuses) - before)
        return statuses, lockfile_index

    _scan_units_in_parallel(
        units, root, include_node_modules, extra_roots,
        statuses, lockfile_index, progress, jobs,
    )
    return statuses, lockfile_index


def _scan_units_in_parallel(
    units: list[Path], root: Path, include_node_modules: bool,
    extra_roots: list[Path], statuses: StatusesByOwner,
    lockfile_index: LockfileIndex, progress: WalkProgress | None, jobs: int,
) -> None:
    """Walk the top-level units concurrently and merge their results.

    The walk is bound by directory reads rather than by processor time, and
    each top-level directory is an independent subtree, so reading several at
    once is the one change that makes a large clone tree finish in a sensible
    time. Measured over a 226-repository clone tree: sequentially
    the first two repositories took 44 s and the run projected about an hour
    and a half.

    Each worker builds its own maps and the caller merges them, so no lock is
    needed: the units are disjoint, because every owner a unit can produce
    lies inside that unit."""
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


def _merge_statuses(into: StatusesByOwner, other: StatusesByOwner) -> None:
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
        dst.unreadable_dir_total += src.unreadable_dir_total
        dst.unreadable_dirs.extend(src.unreadable_dirs)
        del dst.unreadable_dirs[UNREADABLE_DIRS_STORED_LIMIT:]
        dst.read_files.extend(src.read_files)
        dst.unreadable_files.extend(src.unreadable_files)
        dst.lockfiles.extend(src.lockfiles)
        dst.payload_files.extend(src.payload_files)
        dst.flagged_lockfiles |= src.flagged_lockfiles
        for attribute in ("present_versions", "range_only", "poisoned_versions",
                          "poisoned_ranges", "osv_malicious", "osv_advisory_ids",
                          "trivy_confirmed", "evidence"):
            target = getattr(dst, attribute)
            for name, values in getattr(src, attribute).items():
                target.setdefault(name, set()).update(values)


def _scan_unit(
    unit: Path, root: Path, include_node_modules: bool, extra_roots: list[Path]
) -> tuple[StatusesByOwner, LockfileIndex]:
    """Walk and attribute one top-level unit into maps of its own."""
    statuses: dict[Path, RepoStatus] = {}
    lockfile_index: dict[str, RepoStatus] = {}
    unreadable_dirs: list[Path] = []
    triples = _walk(unit, include_node_modules, unreadable_dirs)
    _attribute(triples, root, extra_roots, statuses, lockfile_index, unreadable_dirs)
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

    go_built = _go_built_scanner()
    if go_built:
        return go_built

    found = shutil.which("osv-scanner")
    if found:
        return found
    go_bin = str(Path.home() / "go" / "bin")
    return shutil.which("osv-scanner", path=os.pathsep.join([os.environ.get("PATH", ""), go_bin]))


def _go_built_scanner() -> str | None:
    """The osv-scanner binary a local Go toolchain built, if one exists."""
    go = shutil.which("go")
    if not go:
        return None
    for var in ("GOBIN", "GOPATH"):
        try:
            result = subprocess.run(  # nosec B603
                [go, "env", var], capture_output=True, text=True, timeout=60, check=False
            )
            out = result.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            out = ""
        if not out:
            continue
        root = Path(out) if var == "GOBIN" else Path(out) / "bin"
        candidate_path = root / EXE_NAME
        if candidate_path.exists():
            return str(candidate_path)
    return None


def _parse_ioc_csv(text: str) -> dict[str, set[str]]:
    """Parse the consolidated indicator feed into {package: {versions}}.

    The version column joins several versions inside one quoted field, and some
    rows carry a 99.x placeholder standing in for "all or unknown", which is
    dropped rather than matched against a real install."""
    packages: dict[str, set[str]] = {}
    reader = csv.DictReader(io.StringIO(text))
    fields = {f.lower().strip(): f for f in (reader.fieldnames or [])}
    name_key = next((fields[c] for c in ("package_name", "name", "package") if c in fields), None)
    # Not "version_key": that is a module-level function here, and shadowing it
    # inside a parser that also compares versions is a trap waiting for an edit.
    versions_column = next(
        (fields[c] for c in ("package_versions", "versions", "version") if c in fields), None
    )
    if not name_key or not versions_column:
        raise ValueError(f"unexpected columns in the feed: {reader.fieldnames}")
    for row in reader:
        name = (row.get(name_key) or "").strip()
        if not name:
            continue
        raw = (row.get(versions_column) or "").replace(";", ",").replace(" ", ",")
        for token in raw.split(","):
            version = token.strip().strip('"')
            if version and not version.startswith("99."):
                packages.setdefault(name, set()).add(version)
    return packages


def refresh_overlay(overlay_file: Path, min_interval: int, timeout: int = 60) -> str:
    """Refresh the campaign overlay from the indicator feed, throttled.

    Throttling is what makes this affordable ahead of every run: the file's own
    modification time decides, so no state file is needed. A failure is reported
    and never stops a scan, because the overlay already on disk, or the built-in
    table underneath it, still gives a usable floor.

    Returns what happened, as one of "throttled", "refreshed", "locked",
    "failed" or "write_failed", so the machine report can distinguish an
    overlay that is current because it was just fetched from one that is
    whatever age the disk left it. The prose above the return sites is for the
    operator; the word is for the report.

    Refreshes are serialised through an operating-system advisory lock on a
    file beside the overlay, so two concurrent runs do not both download.
    The OS releases the lock the moment its holder exits, killed or not,
    which is why there is no staleness heuristic here: every timestamp-based
    takeover protocol tried in review had a takeover race one level further
    down, and the kernel's own lock has none. The lock file itself is inert
    and stays on disk. The overlay is written to a temporary name and renamed
    into place, so a reader never sees a half-written table."""
    if min_interval > 0 and overlay_file.exists():
        age = (time.time() - overlay_file.stat().st_mtime) / 60.0
        if age < min_interval:
            _progress(f"overlay refreshed {age:.1f} min ago, not fetching again")
            return "throttled"

    lock_file = overlay_file.with_name(overlay_file.name + ".lock")
    lock_fd = _acquire_overlay_lock(overlay_file, lock_file)
    if lock_fd is None:
        return "locked"

    try:
        _progress(f"refreshing the campaign overlay from {IOC_FEED_URL}")
        try:
            request = urllib.request.Request(
                IOC_FEED_URL, headers={"User-Agent": f"lockfile-sentinel/{__version__}"}
            )
            with _open_https(request, timeout=timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
            packages = _parse_ioc_csv(body)
        # A stale overlay beats no scan, so any fetch failure degrades quietly.
        except Exception as exc:  # noqa: BLE001
            _progress(f"could not refresh the overlay ({exc}); using what is on disk")
            return "failed"

        for name, versions in POISONED_VERSIONS.items():
            packages.setdefault(name, set()).update(versions)
        payload = {
            "generated_utc": datetime.now(timezone.utc).strftime(ISO_UTC_FORMAT),
            "sources": [IOC_FEED_URL],
            "package_count": len(packages),
            "version_count": sum(len(v) for v in packages.values()),
            "packages": {name: sorted(v) for name, v in sorted(packages.items())},
        }
        try:
            _write_atomic(overlay_file, json.dumps(payload, indent=2) + "\n")
        except OSError as exc:
            _progress(f"could not write {overlay_file} ({exc})")
            return "write_failed"
        _progress(f"overlay refreshed: {len(packages)} packages, "
                  f"{payload['version_count']} versions")
        return "refreshed"
    finally:
        _release_overlay_lock(lock_fd)


def _acquire_overlay_lock(overlay_file: Path, lock_file: Path) -> int | None:
    """Take the OS advisory lock on the lock file, or None when it is held.

    The kernel is the arbiter: the exclusive lock is granted to exactly one
    open descriptor across processes, and it evaporates when its holder
    exits, cleanly or not. That is what no timestamp protocol can offer, and
    why the file itself is opened rather than exclusively created; the file
    persisting on disk means nothing."""
    try:
        overlay_file.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(lock_file), os.O_CREAT | os.O_RDWR)
    except OSError as exc:
        _progress(f"could not open the overlay lock ({exc}); using what is on disk")
        return None
    if _lock_descriptor(fd):
        return fd
    os.close(fd)
    _progress("another refresh holds the overlay lock; using what is on disk")
    return None


def _lock_descriptor(fd: int) -> bool:
    """Take a non-blocking exclusive OS lock on an open descriptor."""
    try:
        if sys.platform == "win32":
            import msvcrt  # pylint: disable=import-outside-toplevel
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            # fcntl exists only on POSIX, which the sys.platform guard above proves;
            # the analysis host is Windows, so the import check is disabled here.
            import fcntl  # pylint: disable=import-outside-toplevel,import-error
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def _release_overlay_lock(fd: int) -> None:
    """Release the advisory lock and close the descriptor."""
    try:
        if sys.platform == "win32":
            import msvcrt  # pylint: disable=import-outside-toplevel
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            # fcntl exists only on POSIX, which the sys.platform guard above proves;
            # the analysis host is Windows, so the import check is disabled here.
            import fcntl  # pylint: disable=import-outside-toplevel,import-error
            fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        os.close(fd)
    except OSError:
        pass


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
        if isinstance(result, dict):
            _collect_trivy_vulns(result, found)
    return found


def _collect_trivy_vulns(result: dict[str, Any], found: dict[str, set[str]]) -> None:
    """Fold one Trivy result's vulnerabilities into {package@version: {ids}}."""
    for vuln in result.get("Vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        name = vuln.get("PkgName")
        version = vuln.get("InstalledVersion")
        ident = vuln.get("VulnerabilityID")
        if isinstance(name, str) and isinstance(version, str) and isinstance(ident, str):
            found.setdefault(f"{name}@{version}", set()).add(ident)


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
        _trivy_recheck_repo(status, trivy, timeout)
        if status.trivy_checked and not status.trivy_confirmed:
            _progress(f"  [trivy] consulted for {status.name}, nothing matched")


def _trivy_recheck_repo(status: RepoStatus, trivy: str, timeout: int) -> None:
    """Submit one repository's flagged lockfiles to Trivy and record matches."""
    for lockfile in sorted(status.flagged_lockfiles):
        status.trivy_submitted_count += 1
        findings = _trivy_findings(trivy, lockfile, timeout)
        if findings is None:
            status.trivy_failed_count += 1
            _progress(f"  [trivy] could not scan {lockfile}")
            continue
        status.trivy_checked = True
        flagged = set(status.poisoned_versions) | set(status.osv_malicious)
        for key, ids in findings.items():
            if key.rsplit("@", 1)[0] in flagged:
                status.trivy_confirmed.setdefault(key, set()).update(ids)


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


def _live_check(timeout: int = 10) -> dict[str, Any]:
    """Probe api.osv.dev once, for --status --check-live.

    Ordinary status mode reads only the disk, because freshness on disk does
    not prove reachability and a status command that surprises the caller with
    network traffic is a status command scripts cannot trust. This probe is the
    explicit opt-in: one small advisory fetched, latency measured, any failure
    reported as a fact rather than raised."""
    started = time.monotonic()
    try:
        request = urllib.request.Request(
            "https://api.osv.dev/v1/vulns/MAL-2025-21003",
            headers={"User-Agent": f"lockfile-sentinel/{__version__}"},
        )
        with _open_https(request, timeout=timeout) as response:
            response.read(64)
    # The failure is the finding here, so every exception becomes the answer.
    except Exception as exc:  # noqa: BLE001
        return {"attempted": True, "reachable": False,
                "latency_ms": int((time.monotonic() - started) * 1000),
                "error": str(exc)[:200]}
    return {"attempted": True, "reachable": True,
            "latency_ms": int((time.monotonic() - started) * 1000), "error": None}


def _freshness(unknown: bool, stale: bool) -> str:
    """The three-way verdict, with unknown outranking stale outranking fresh."""
    if unknown:
        return "unknown"
    return "stale" if stale else "fresh"


def _status_engine(osv_bin: str | None) -> dict[str, Any]:
    """The osv-scanner binary's freshness facts: version, build, last check."""
    engine_state = _read_json(cache_dir() / "logs" / "update-osv-scanner.state.json")
    checked_unix = _as_unix_time(engine_state.get("lastCheckUnix"))
    engine_stale = checked_unix is not None and time.time() - checked_unix > 24 * 3600
    return {
        "path": osv_bin,
        "version": _osv_version(osv_bin) if osv_bin else None,
        "built_from_commit": (str(engine_state["lastCommit"])[:12]
                              if engine_state.get("lastCommit") else None),
        "version_checked_unix": checked_unix,
        "stale_after_seconds": 24 * 3600,
        "state": _freshness(checked_unix is None, engine_stale),
    }


def _overlay_generated_unix(overlay: dict[str, Any]) -> float | None:
    """The overlay's own generation stamp as a unix time, or None."""
    generated = overlay.get("generated_utc")
    if not isinstance(generated, str):
        return None
    try:
        return datetime.strptime(generated, ISO_UTC_FORMAT).replace(
            tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def _overlay_refresh_unix(overlay_file: Path) -> float | None:
    """When the overlay was last refreshed, from state file or mtime.

    The refresh age comes from update_scanners.py's state file when that is
    what keeps the overlay current, and from the overlay's own mtime
    otherwise. refresh_overlay in this file throttles on the mtime and writes
    no state file, so reading the state file alone reported a permanent
    unknown, and a permanent exit 1, on any host where the scanner does its
    own refreshing."""
    refresh = _read_json(cache_dir() / "logs" / "update-malicious-packages.state.json")
    last_refresh = _as_unix_time(refresh.get("lastRefreshUnix"))
    if last_refresh is not None:
        return last_refresh
    try:
        return overlay_file.stat().st_mtime
    except OSError:
        return None


# The last unix second datetime.max can represent in UTC, which is the
# ceiling a stored timestamp must clear to be renderable at all.
_MAX_UNIX_TIME: float = datetime(
    9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc).timestamp()


def _as_unix_time(value: Any) -> float | None:
    """A numeric unix time, or None for anything else, booleans included.

    bool is a subclass of int, so a state file corrupted to `true` would
    otherwise read as timestamp 1, compute a confidently wrong freshness and
    emit a boolean where the published schema promises a number or null. A
    non-finite float is refused for the same reason: json.loads accepts NaN
    and Infinity, either of which would classify the source as fresh, crash
    the human rendering in fromtimestamp, and serialize as tokens that are
    not JSON at all. The finite value is then bounded to what a datetime can
    represent, because 1e300 is finite, reads as impossibly fresh, and still
    overflows fromtimestamp; a negative value predates the unix epoch and no
    updater on this stack has run before 1970."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value):
        return None
    stamp = float(value)
    if stamp < 0 or stamp > _MAX_UNIX_TIME:
        return None
    return stamp


def _status_overlay(overlay_file: Path) -> dict[str, Any]:
    """The campaign overlay's freshness facts, by its stamp and its refresh."""
    overlay = _read_json(overlay_file)
    generated_unix = _overlay_generated_unix(overlay) if overlay else None
    generated = overlay.get("generated_utc") if overlay else None
    last_refresh = _overlay_refresh_unix(overlay_file)
    if overlay:
        generated_stale = (generated_unix is not None
                           and time.time() - generated_unix > 24 * 3600)
        refresh_stale = (last_refresh is not None
                         and time.time() - last_refresh > 24 * 3600)
        state = _freshness(generated_unix is None or last_refresh is None,
                           generated_stale or refresh_stale)
    else:
        state = "absent"
    # Counted from the packages map rather than read from the document's own
    # count fields, which a corrupted or hand-edited overlay can carry as
    # NaN, booleans or strings: those would flow straight into the status
    # JSON, where the schema promises an integer or null and NaN is not JSON.
    packages = overlay.get("packages") if overlay else None
    if isinstance(packages, dict):
        package_count: int | None = len(packages)
        version_count: int | None = sum(
            len(v) for v in packages.values() if isinstance(v, list))
    else:
        package_count = None
        version_count = None
    return {
        "path": str(overlay_file),
        "present": bool(overlay),
        "package_count": package_count,
        "version_count": version_count,
        "generated_utc": generated if isinstance(generated, str) else None,
        "generated_unix": generated_unix,
        "last_refresh_unix": last_refresh,
        "stale_after_seconds": 24 * 3600,
        "state": state,
    }


def _status_live(check_live: bool) -> dict[str, Any]:
    """The live database, which is the layer with no local copy to age."""
    live: dict[str, Any] = {
        "mode": "online",
        "note": "queried per scan at api.osv.dev, no local copy",
        "live_check": _live_check() if check_live else None,
        "state": "fresh",
    }
    live_check = live["live_check"]
    if isinstance(live_check, dict) and not live_check.get("reachable"):
        live["state"] = "unknown"
    return live


def _status_offline_db() -> dict[str, Any]:
    """The offline database's freshness facts, or its absence as a mode.

    This must resolve exactly as update_scanners.offline_db_dir() does:
    osv-scanner's own variable first, then the cache root. Reading only the
    variable reported "not present" immediately after a 206 MB refresh had
    landed in the cache, because the updater sets that variable for its child
    process alone.

    An absent offline database is a mode, not a fault: online mode is always
    current, so neither staleness nor unknown follows from it, matching the
    human report that has always said so in words."""
    offline = os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY")
    offline_dir = Path(offline) if offline else cache_dir() / "osv-offline-db"
    newest: float | None = None
    if offline_dir.is_dir():
        newest = max((p.stat().st_mtime for p in offline_dir.rglob("*") if p.is_file()),
                     default=None)
        state = _freshness(newest is None, newest is not None
                           and time.time() - newest > 7 * 24 * 3600)
    else:
        state = "absent"
    return {
        "path": str(offline_dir),
        "present": offline_dir.is_dir(),
        "newest_file_unix": newest,
        "stale_after_seconds": 7 * 24 * 3600,
        "state": state,
    }


def gather_status(overlay_file: Path, osv_bin: str | None,
                  check_live: bool = False) -> dict[str, Any]:
    """Collect every freshness fact the status report states, as data.

    The human report is rendered from this document, so the two cannot
    disagree: every fact and every health decision exists here first, and the
    prose is derived presentation. Each source carries a state of "fresh",
    "stale", "unknown" or "absent", and the overall verdict is computed from
    the same states the document shows."""
    osv_scanner = _status_engine(osv_bin)
    overlay_source = _status_overlay(overlay_file)
    builtin = {
        "package_version_pairs": sum(len(v) for v in POISONED_VERSIONS.values()),
        "state": "fresh",
    }
    live = _status_live(check_live)
    offline_db = _status_offline_db()

    watched = [osv_scanner, overlay_source, builtin, live]
    unknown = any(source["state"] in ("unknown", "absent") for source in watched)
    stale = any(source["state"] == "stale" for source in watched)
    # An overlay that is absent reads as unknown overall, matching the human
    # report's exit 2, while the offline database is excluded on purpose: its
    # absence is a mode, since online mode is always current.
    overall = _freshness(unknown, stale)
    return {
        "schema": {"name": STATUS_SCHEMA_NAME, "version": STATUS_SCHEMA_VERSION},
        "tool": {"name": "lockfile-sentinel", "version": __version__},
        "generated_utc": _utc_now_iso(),
        "sources": {
            "osv_scanner": osv_scanner,
            "overlay": overlay_source,
            "builtin_table": builtin,
            "osv_live": live,
            "osv_offline_db": offline_db,
        },
        "overall": {
            "state": overall,
            "exit_code": {"fresh": 0, "stale": 1, "unknown": 2}[overall],
        },
    }


def render_status_human(doc: dict[str, Any]) -> list[str]:
    """Render the status document as the prose report it has always printed."""
    lines = ["Supply-chain scanner status", "==========================="]
    sources = doc["sources"]

    engine = sources["osv_scanner"]
    version = engine["version"] or ("unreadable" if engine["path"] else "not found")
    lines.append(f"  {'osv-scanner binary':<28} {version} at {engine['path'] or 'not found'}")
    if engine["built_from_commit"]:
        lines.append(f"  {'built from commit':<28} {engine['built_from_commit']}")
    lines.append(_age_line("version last checked", engine["version_checked_unix"], 24)[0])

    overlay = sources["overlay"]
    if overlay["present"]:
        lines.append(f"  {'overlay packages':<28} {overlay['package_count'] or '?'} packages, "
                     f"{overlay['version_count'] or '?'} versions")
        lines.append(f"  {'overlay file':<28} {overlay['path']}")
        lines.append(_age_line("overlay generated", overlay["generated_unix"], 24)[0])
    else:
        lines.append(f"  {'overlay file':<28} absent or unreadable at {overlay['path']}")
    lines.append(_age_line("overlay last refreshed", overlay["last_refresh_unix"], 24)[0])

    builtin = sources["builtin_table"]
    lines.append(f"  {'built-in table':<28} {builtin['package_version_pairs']} "
                 "package@version pairs (in the source)")

    live = sources["osv_live"]
    lines.append(f"  {'OSV live database':<28} {live['note']}")
    live_check = live["live_check"]
    if isinstance(live_check, dict):
        verdict = ("reachable" if live_check.get("reachable")
                   else f"UNREACHABLE ({live_check.get('error')})")
        lines.append(f"  {'api.osv.dev live check':<28} {verdict}, "
                     f"{live_check.get('latency_ms')} ms")

    offline_db = sources["osv_offline_db"]
    if offline_db["present"]:
        lines.append(_age_line("OSV offline database", offline_db["newest_file_unix"],
                               24 * 7)[0])
    else:
        lines.append(f"  {'OSV offline database':<28} not present ({offline_db['path']}); "
                     f"online mode is always current")
    return lines


def report_status(overlay_file: Path, osv_bin: str | None,
                  as_json: bool = False, check_live: bool = False,
                  output: str | None = None) -> int:
    """Report when each thing the scanner relies on was last updated.

    A scanner is only as current as its inputs, and every one of them is
    refreshed by a different mechanism on a different cadence, so the question
    "is this scan trustworthy right now" has no single answer to read anywhere.
    This gathers all of them, as the lockfile-sentinel-status document under
    --json and as prose derived from that same document otherwise.

    Exit 0 when everything is fresh, 1 when something is stale, 2 when a source
    could not be determined at all, following the house rule that a check which
    could not run must not report health. These codes are the status command's
    own and are documented apart from the scan's exit codes, which answer a
    different question."""
    doc = gather_status(overlay_file, osv_bin, check_live=check_live)
    if as_json:
        text = json.dumps(doc, indent=2) + "\n"
    else:
        text = "\n".join(render_status_human(doc)) + "\n"
    if output:
        # The advertised -o option applies here too: a status pipeline that
        # asked for a file and got stdout has silently lost its document.
        try:
            _write_atomic(Path(output), text)
        except OSError as exc:
            _progress(f"FAIL: could not write the status to {output} ({exc})")
            return 2
    else:
        sys.stdout.write(text)
    overall = doc["overall"]
    return int(overall["exit_code"])


def _diagnose_offline(path: str) -> tuple[bool, dict[str, set[str]]]:
    """Match one named lockfile against the offline table.

    Returns whether the file was read, and the poisoned package versions it
    resolves. The status built here is discarded: diagnosis mode reports per
    file rather than per repository, and nothing downstream consumes it."""
    status = RepoStatus(name=path, path=str(Path(path).parent))
    was_read = scan_lockfile(Path(path), status)
    return was_read, status.poisoned_versions


_OVERLAY_STALE_AFTER_HOURS: float = 24.0


def _prepare_offline_table(args: argparse.Namespace) -> dict[str, Any]:
    """Refresh and load the campaign overlay into the offline table.

    Refreshing has to precede loading, or the run matches against the previous
    campaign list and downloads the current one only for the next run.

    Every mode that consults the offline table calls this, which is the point of
    it being a function: the sweep and diagnosis mode disagreeing about which
    table they match against is how one of them ends up reporting a version the
    other already knew as clean.

    Returns the overlay layer object for the machine report. The states follow
    the shared vocabulary: not_requested under --no-overlay, completed when a
    fresh table is loaded, partial when the table loaded but is stale after a
    refresh that was asked for and did not land, unavailable when nothing
    loaded at all."""
    overlay_file = Path(args.overlay_file)
    refresh_requested = not args.no_refresh and not args.no_overlay
    refresh_outcome: str | None = None
    if refresh_requested:
        refresh_outcome = refresh_overlay(overlay_file, args.min_interval)

    layer: dict[str, Any] = {
        "requested": not args.no_overlay,
        "state": "not_requested",
        "reason_code": None,
        "message": None,
        "path": str(overlay_file),
        "generated_utc": None,
        "digest_sha256": None,
        "package_count": None,
        "version_count": None,
        "refresh_requested": refresh_requested,
        "refresh_outcome": refresh_outcome,
        "stale_after_hours": _OVERLAY_STALE_AFTER_HOURS,
    }
    if args.no_overlay:
        return layer

    overlay = load_overlay(overlay_file)
    if not overlay:
        layer["state"] = "unavailable"
        layer["reason_code"] = "overlay_missing"
        layer["message"] = (
            f"{overlay_file} absent or empty; only the built-in table applies"
        )
    else:
        _describe_loaded_overlay(layer, overlay_file, overlay,
                                 refresh_requested, refresh_outcome)

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
    return layer


def _describe_loaded_overlay(
    layer: dict[str, Any], overlay_file: Path, overlay: dict[str, list[str]],
    refresh_requested: bool, refresh_outcome: str | None,
) -> None:
    """Fill the layer object for an overlay that did load: digest, counts,
    generation stamp, and whether its age contradicts a requested refresh."""
    try:
        layer["digest_sha256"] = hashlib.sha256(overlay_file.read_bytes()).hexdigest()
    except OSError:
        pass
    generated = _read_json(overlay_file).get("generated_utc")
    layer["generated_utc"] = generated if isinstance(generated, str) else None
    layer["package_count"] = len(overlay)
    layer["version_count"] = sum(len(v) for v in overlay.values())
    stale = True
    try:
        stale = (time.time() - overlay_file.stat().st_mtime
                 ) > _OVERLAY_STALE_AFTER_HOURS * 3600
    except OSError:
        pass
    if stale and refresh_requested and refresh_outcome != "refreshed":
        # A stale table after a refresh that was asked for means the
        # refresh failed, since the throttle never withholds one this old.
        layer["state"] = "partial"
        layer["reason_code"] = "overlay_refresh_failed"
        layer["message"] = (
            "the overlay is older than the staleness threshold and the "
            "requested refresh did not land"
        )
    else:
        layer["state"] = "completed"


def diagnose_lockfiles(
    osv_bin: str | None, paths: list[str], timeout: int, live_requested: bool = True
) -> int:
    """Test named lockfiles one at a time, saying exactly what happened to each.

    This is the fast loop for the failure the batch scanner reports. A full
    sweep walks hundreds of repositories before it reaches the OSV pass, so
    iterating on a broken lockfile that way costs ten minutes a try. Here the
    walk is skipped entirely and each file is submitted alone, which also
    removes the binary search: a file that fails is the file that failed.

    Both layers run, and each file's line says which of them spoke. The offline
    table needs no network and no scanner, so it runs even where osv-scanner is
    absent: this mode used to submit to osv-scanner alone and exit 2 without it,
    which meant the command most likely to be pointed at a lockfile the walk has
    no name for reported nothing at all, and reported a version the offline
    table already knew as clean whenever the live database had not caught up.

    Returns 1 when anything was found or any file could not be read or
    extracted, 0 when every file was read, extracted and came back clean, and 2
    when nothing was found but a layer that should have run did not, since a
    check that could not run cannot report health. A scanner that times out,
    fails to spawn or returns unparsable output is a layer that did not run, not
    a file that failed: it says nothing whatever about the lockfile in front of
    it.

    live_requested distinguishes a live layer that could not run from one the
    caller asked to skip. --no-osv scopes the check deliberately, so a clean run
    under it returns 0 the same way the sweep does: 2 is for a check the caller
    expected and did not get, not for one they declined."""
    if not osv_bin and not live_requested:
        _progress(
            "--no-osv given, so the live database is not consulted. The offline "
            "table still runs; a version it does not name will not be reported "
            "by this run."
        )
    elif not osv_bin:
        _progress(
            "osv-scanner not found, so the live database is not consulted. "
            "The offline table still runs; a version it does not name will not "
            "be reported by this run."
        )
    else:
        _progress(f"diagnosing {len(paths)} lockfile(s) with {osv_bin}")
    tally = {"failed": 0, "missing": 0, "unread": 0, "found": 0, "examined": 0}
    # True once the live layer failed to reach a verdict on any file, which is
    # different from it rejecting one and is what stops a clean run reporting
    # health it cannot vouch for.
    unavailable = live_requested and not osv_bin
    for given in paths:
        # Resolve before submitting: osv-scanner reports the absolute path in
        # its results, so a relative path in and an absolute path out never
        # match and every finding is lost. The sweep passes absolute paths and
        # never hit this; a hand-typed one does.
        path = str(Path(given).resolve()) if os.path.exists(given) else given
        if not os.path.exists(path):
            _progress(f"MISSING: {path}")
            tally["missing"] += 1
            continue
        unavailable = _diagnose_one(osv_bin, path, timeout, tally) or unavailable
    failed = tally["failed"]
    missing = tally["missing"]
    unread = tally["unread"]
    found = tally["found"]
    examined = tally["examined"]

    # "examined" counts a file at least one layer got through, which is not the
    # same as a file both layers got through: a lockfile osv-scanner cannot
    # extract is still matched against the offline table, and one the offline
    # pass cannot open may still extract. Either combination is exactly what
    # this mode exists to investigate, so both count as examined and the
    # per-file lines above say which layer spoke.
    _progress(
        f"diagnosis complete: {len(paths)} named, {examined} examined, "
        f"{found} with findings, {missing} missing, {unread} unreadable, "
        f"{failed} extraction failure(s)"
    )
    if found or failed or unread or missing:
        return 1
    return 2 if unavailable else 0


def _diagnose_one(
    osv_bin: str | None, path: str, timeout: int, tally: dict[str, int]
) -> bool:
    """Run both layers over one named lockfile, updating the tallies.

    Returns whether the live layer failed to reach a verdict here. A hit is
    counted once per file rather than once per layer: both layers naming the
    same lockfile is the expected result for a poisoned file, not two
    findings, and a summary that says two for one file overstates the scale
    of what was found."""
    was_read, poisoned = _diagnose_offline(path)
    hit_here = bool(poisoned)
    if not was_read:
        tally["unread"] += 1
        _progress(f"UNREAD : {path} -> the offline table could not read this file")
    elif poisoned:
        _progress(f"POISON : {path} -> [offline table] {_format_versions(poisoned)}")
    else:
        _progress(f"OK     : {path} -> [offline table] no known poisoned version")

    if not osv_bin:
        tally["found"] += hit_here
        tally["examined"] += was_read
        return False
    verdict, live_hit = _diagnose_live(osv_bin, path, timeout)
    if verdict != "answered":
        tally["found"] += hit_here
        tally["examined"] += was_read
        tally["failed"] += verdict == "rejected"
        return verdict == "unavailable"
    tally["found"] += hit_here or live_hit
    # Extraction succeeded, so this file was examined whatever the offline
    # read did. The two layers open the file separately and can disagree
    # about whether it is readable, which is why this counts the layers that
    # got through rather than deriving the answer from one of them.
    tally["examined"] += 1
    return False


def _diagnose_live(osv_bin: str, path: str, timeout: int) -> tuple[str, bool]:
    """Submit one file to the live layer: ("answered"|"rejected"|"unavailable", hit)."""
    failure: dict[str, str] = {}
    result = _run_osv_batch(osv_bin, [path], timeout, debug=True, failure=failure)
    if result is None:
        if failure.get("cause") == "rejected":
            _progress(f"FAILED : {path} -> [osv-scanner] extraction failed")
            _progress(f"    reason: {_describe_lockfile(path)}")
            for line in _verbose_lockfile_dump(path):
                _progress(line)
            return "rejected", False
        # The scanner never reached a verdict, so nothing here is known
        # about the file. Dumping its bytes as though it were the
        # suspect would send the reader after the wrong thing.
        _progress(f"SKIPPED: {path} -> [osv-scanner] no verdict, the scanner did not run")
        return "unavailable", False
    hits = result.get(_normalize_path(path), [])
    if not hits and len(result) == 1:
        # One file in, one source out: whatever it was keyed by, it is this
        # file. Guards against any further path-shape disagreement.
        hits = next(iter(result.values()))
    if hits:
        detail = ", ".join(
            f"{name}@{version} ({', '.join(sorted(ids))})" for name, version, ids in hits
        )
        _progress(f"POISON : {path} -> [osv-scanner] {detail}")
        return "answered", True
    _progress(f"OK     : {path} -> [osv-scanner] no malicious-package advisories")
    return "answered", False


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
    osv_json: dict[str, Any]
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
        hits = [hit for pkg_entry in packages
                if (hit := _malicious_hit(pkg_entry)) is not None]
        if hits:
            by_source[_normalize_path(source_path)] = hits
    return by_source


def _malicious_hit(pkg_entry: dict[str, Any]) -> tuple[str, str, set[str]] | None:
    """One package entry's MAL- advisories, or None when it carries none."""
    package = pkg_entry.get("package", {})
    name = package.get("name")
    version = package.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        return None
    malicious_ids: set[str] = set()
    for vuln in pkg_entry.get("vulnerabilities", []) or []:
        candidate_ids = [vuln.get("id", "")] + list(vuln.get("aliases", []) or [])
        malicious_ids.update(cid for cid in candidate_ids if cid.startswith("MAL-"))
    if not malicious_ids:
        return None
    return name, version, malicious_ids


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
    if size > 0 and path.lower().endswith(JSON_SUFFIX):
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

    _dump_byte_hints(raw, size, lines)
    _dump_format_hints(os.path.basename(path).lower(), path,
                       raw.decode("utf-8", errors="replace"), lines)
    return lines


def _dump_byte_hints(raw: bytes, size: int, lines: list[str]) -> None:
    """The byte-level oddities that have actually explained a refusal."""
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


def _dump_json_hints(path: str, lines: list[str]) -> None:
    """What a strict JSON parse says about a .json lockfile."""
    try:
        with open(path, encoding="utf-8-sig") as handle:
            document = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        lines.append(f"      does NOT parse as JSON: {exc}")
        return
    if not isinstance(document, dict):
        lines.append(f"      parses as JSON but is a {type(document).__name__}, not an object")
        return
    lines.append(
        f"      parses as JSON, lockfileVersion="
        f"{document.get('lockfileVersion')!r}, top-level keys="
        f"{sorted(document)[:8]}"
    )
    if "lockfileVersion" not in document:
        lines.append("      has no lockfileVersion, so it is not an npm lockfile")


def _dump_format_hints(name: str, path: str, text: str, lines: list[str]) -> None:
    """The format-specific shape checks, dispatched on the lockfile's name."""
    if name.endswith(JSON_SUFFIX):
        _dump_json_hints(path, lines)
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
    elif name == BUN_LOCKFILE_NAME:
        # JSONC rather than JSON: bun writes trailing commas, so failing the
        # strict parser is this format's healthy state, not a defect to report.
        match = re.search(r'"lockfileVersion"\s*:\s*(\d+)', text)
        # An absent field is not proof of a foreign file: this dump prints for a
        # file the scanner refused, and a truncated bun.lock has lost exactly
        # the head this regex looks in, so certainty here would send the reader
        # away from the corruption that is the actual finding.
        lines.append(
            f"      bun JSONC format, lockfileVersion: {match.group(1)}" if match
            else "      no lockfileVersion field found: truncated, malformed, "
                 "or not a bun lockfile"
        )


def _run_osv_batch(
    osv_bin: str, paths: list[str], timeout: int, debug: bool = False,
    failure: dict[str, str] | None = None,
) -> dict[str, list[tuple[str, str, set[str]]]] | None:
    """Run one osv-scanner invocation over the given lockfiles. Returns None
    on any failure (spawn error, unexpected exit code, unparsable output) so
    the caller can retry at finer granularity instead of losing every result
    in the batch to one bad file.

    A caller that passes `failure` gets the cause recorded in it, because None
    covers two different things and only one of them is about the file. An
    unexpected exit code means the scanner ran and rejected this input, which is
    a fact about the lockfile. A timeout, a spawn error or unparsable output
    mean the scanner never reached a verdict, which is a fact about the tooling,
    and reporting the second as the first tells the reader to go and look at a
    lockfile that may be perfectly sound."""
    cmd = [osv_bin, "scan"]
    for lockfile_path in paths:
        cmd.extend(["--lockfile", lockfile_path])
    cmd.extend(["--format", "json"])
    try:
        proc = subprocess.run(  # nosec B603
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as exc:
        _progress(f"osv-scanner timed out after {timeout}s: {exc}")
        if failure is not None:
            failure["cause"] = "unavailable"
        return None
    except (OSError, subprocess.SubprocessError) as exc:
        _progress(f"osv-scanner failed to start: {exc}")
        if failure is not None:
            failure["cause"] = "unavailable"
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
        _report_osv_rejection(proc, cmd, paths, timeout, debug)
        if failure is not None:
            failure["cause"] = "rejected"
        return None
    try:
        return _extract_malicious_findings(json.loads(proc.stdout or "{}"))
    except json.JSONDecodeError:
        _progress(f"osv-scanner produced non-JSON output on {len(paths)} lockfile(s)")
        if failure is not None:
            failure["cause"] = "unavailable"
        return None


def _report_osv_rejection(
    proc: subprocess.CompletedProcess[str], cmd: list[str], paths: list[str],
    timeout: int, debug: bool,
) -> None:
    """Report an osv-scanner exit that rejected its input, in full.

    A failure here costs the whole group, so it is always reported in
    full. The scanner's own last line names neither the file nor the
    reason, and the reason is one line further up: the emojipanel lockfile
    in these trees failed on "cannot unmarshal bool into Go struct field
    Dependency.dependencies.dependencies.resolved of type string", which is
    a boolean where npm's schema says a string. Nothing about that is
    recoverable from the summary line, and hiding it behind a flag means
    the next investigation starts by re-running the ten-minute sweep."""
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


def _scan_with_isolation(
    osv_bin: str, paths: list[str], timeout: int,
    debug: bool = False, failures: list[str] | None = None,
    outages: list[str] | None = None,
) -> tuple[dict[str, list[tuple[str, str, set[str]]]], set[str]]:
    """Scan the given lockfiles, isolating any bad file by binary search.

    One malformed lockfile makes osv-scanner abort the whole invocation, so a
    failed group is split in half and each half retried. A bad file is thus
    isolated in O(log n) re-runs rather than the O(n) of a per-file retry,
    while every healthy file in the group is still scanned. Returns (malicious
    hits per lockfile, set of paths that were successfully scanned)."""
    failure: dict[str, str] = {}
    result = _run_osv_batch(osv_bin, paths, timeout, debug, failure=failure)
    if result is not None:
        return result, {_normalize_path(p) for p in paths}
    if failure.get("cause") == "unavailable":
        # A timeout, spawn failure or unparsable output is systemic, not a
        # property of one file, so splitting would multiply the outage by an
        # invocation per lockfile. The whole group is recorded unanswered and
        # the binary search is reserved for genuine rejections.
        _progress(f"  no verdict on a group of {len(paths)}, the scanner did not run")
        if outages is not None:
            outages.extend(paths)
        return {}, set()
    if len(paths) == 1:
        _record_isolated_failure(paths[0], failure, failures, outages)
        return {}, set()
    mid = len(paths) // 2
    _progress(f"  splitting failed group of {len(paths)} into {mid} + {len(paths) - mid}")
    left_findings, left_ok = _scan_with_isolation(
        osv_bin, paths[:mid], timeout, debug, failures, outages)
    right_findings, right_ok = _scan_with_isolation(
        osv_bin, paths[mid:], timeout, debug, failures, outages)
    return {**left_findings, **right_findings}, left_ok | right_ok


def _record_isolated_failure(
    path: str, failure: dict[str, str],
    failures: list[str] | None, outages: list[str] | None,
) -> None:
    """The end of the binary search, and the only place the offending file is
    known. A rejection is explained in full, because the cascade above reads
    as an unexplained failure otherwise and the same question gets asked next
    run. A scanner that never answered is recorded as an outage instead:
    nothing is known about the file, and dumping its bytes as though it were
    the suspect would send the reader after the wrong thing."""
    if failure.get("cause") == "unavailable":
        _progress(f"  no verdict, the scanner did not run against: {path}")
        if outages is not None:
            outages.append(path)
        return
    _progress(f"  unrecoverable, skipped: {path}")
    _progress(f"    reason: {_describe_lockfile(path)}")
    for line in _verbose_lockfile_dump(path):
        _progress(line)
    if failures is not None:
        failures.append(path)


@dataclass
class OsvRunReport:
    """What one whole OSV pass did, counted for the machine report.

    The findings and the processed set already travel back through the return
    value; these are the paths that did not make it, split by why, because a
    lockfile the scanner rejected and a lockfile that was never handed to it
    are different coverage facts and the report states each as itself."""

    submitted: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    # Paths on which the scanner never reached a verdict: a timeout, a spawn
    # failure or unparsable output. A rejected lockfile is a fact about the
    # file; these are facts about the tooling, retryable and reported as such,
    # because sending the operator to repair a sound lockfile is the exact
    # misdirection the split exists to prevent.
    unavailable: list[str] = field(default_factory=list)
    skipped_empty: list[str] = field(default_factory=list)
    skipped_unreadable: list[str] = field(default_factory=list)
    duration_ms: int = 0


def run_osv_scanner(
    osv_bin: str,
    lockfile_paths: list[str],
    batch_size: int,
    timeout: int,
    on_batch_done: Callable[[dict[str, list[tuple[str, str, set[str]]]], set[str]], None]
    | None = None,
    debug: bool = False,
    run_report: OsvRunReport | None = None,
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
    started = time.monotonic()

    lockfile_paths = _filter_usable_lockfiles(lockfile_paths, processed, run_report)

    batches = _chunked(lockfile_paths, batch_size)
    failures: list[str] = []
    outages: list[str] = []

    # The OSV pass is where the wall clock goes, and it is the one phase whose
    # size is known in advance, so it is the phase worth tracking. Counting
    # lockfiles rather than batches makes the rate and the estimate meaningful
    # when a batch is split by the isolation retry.
    tracker = WalkProgress(len(lockfile_paths), desc="osv-scanner") if lockfile_paths else None

    for batch_num, batch in enumerate(batches, start=1):
        _progress(f"osv-scanner batch {batch_num}/{len(batches)}: {len(batch)} lockfile(s)...")
        batch_findings, batch_ok = _scan_with_isolation(
            osv_bin, batch, timeout, debug, failures, outages
        )
        combined.update(batch_findings)
        processed.update(batch_ok)
        if run_report is not None:
            # Synced per batch rather than once at the end, so a snapshot
            # written from the callback below describes only the batches that
            # have actually run and its counts reconcile mid-flight too; the
            # submitted list likewise grows batch by batch instead of claiming
            # up front that every future path was already handed over.
            run_report.submitted.extend(batch)
            run_report.failed[:] = failures
            run_report.unavailable[:] = outages
        if tracker is not None:
            tracker.advance(f"{len(combined)} lockfile(s) with findings", count=len(batch))
        if on_batch_done is not None:
            on_batch_done(combined, processed)

    if tracker is not None:
        tracker.finish()

    if failures:
        _write_failure_list(failures)
    if run_report is not None:
        run_report.failed[:] = failures
        run_report.unavailable[:] = outages
        run_report.duration_ms = int((time.monotonic() - started) * 1000)
    return combined, processed


def _filter_usable_lockfiles(
    lockfile_paths: list[str], processed: set[str], run_report: OsvRunReport | None
) -> list[str]:
    """Drop the files the scanner is known to abort on, with a note each.

    A file that cannot extract aborts the whole invocation it is part of, and
    the binary search then costs a run per halving to find it. An empty
    lockfile is the common case and is recognisable without asking the
    scanner, so it is dropped here with a note instead. It still counts as
    resolved: a file with nothing in it has nothing to resolve, which is the
    same verdict the scanner itself gives such a file when it is submitted
    alone (exit 128, "no package sources"), and treating vacuous coverage as
    missing coverage would fail a whole scan over a scaffold file."""
    usable: list[str] = []
    for path in lockfile_paths:
        try:
            if os.path.getsize(path) == 0:
                _progress(f"skipping empty lockfile, nothing to extract: {path}")
                processed.add(_normalize_path(path))
                if run_report is not None:
                    run_report.skipped_empty.append(path)
                continue
        except OSError as exc:
            _progress(f"skipping unreadable lockfile ({exc}): {path}")
            if run_report is not None:
                run_report.skipped_unreadable.append(path)
            continue
        usable.append(path)
    return usable


def _write_failure_list(failures: list[str]) -> None:
    """Write the offending files out so the next investigation is seconds
    rather than another full walk. Re-running against this list reproduces the
    failure over a handful of files instead of a few hundred repositories."""
    listing = cache_dir() / "logs" / "osv-extraction-failures.txt"
    try:
        listing.parent.mkdir(parents=True, exist_ok=True)
        listing.write_text("\n".join(failures) + "\n", encoding="utf-8")
        _progress(f"{len(failures)} lockfile(s) failed extraction; wrote the list to {listing}")
        _progress(f"  reproduce on those alone: python lockfile_sentinel.py "
                  f"--lockfiles-from {listing} --osv-debug")
    except OSError as exc:
        _progress(f"could not write the failure list ({exc})")


def apply_osv_results(
    lockfile_index: dict[str, RepoStatus],
    osv_findings: dict[str, list[tuple[str, str, set[str]]]],
    processed_paths: set[str],
    failed_paths: frozenset[str] | set[str] = frozenset(),
    skipped_paths: frozenset[str] | set[str] = frozenset(),
    unavailable_paths: frozenset[str] | set[str] = frozenset(),
    empty_paths: frozenset[str] | set[str] = frozenset(),
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
    for status in {id(s): s for s in lockfile_index.values()}.values():
        owned = [_normalize_path(p) for p in status.lockfiles]
        status.osv_resolved_count = sum(1 for p in owned if p in processed_paths)
        status.osv_failed_count = sum(1 for p in owned if p in failed_paths)
        status.osv_skipped_count = sum(1 for p in owned if p in skipped_paths)
        status.osv_unavailable_count = sum(1 for p in owned if p in unavailable_paths)
        status.osv_empty_count = sum(1 for p in owned if p in empty_paths)
        status.osv_checked = bool(owned) and status.osv_resolved_count == len(owned)
    for normalized_path, hits in osv_findings.items():
        found = lockfile_index.get(normalized_path)
        if found is None:
            continue
        owner = found
        # Record which lockfile carried the hit, in its original spelling, so a
        # re-check submits that file rather than the whole repository.
        source = normalized_path
        for candidate in owner.lockfiles:
            if _normalize_path(candidate) == normalized_path:
                owner.flagged_lockfiles.add(candidate)
                source = candidate
                break
        for name, version, ids in hits:
            owner.osv_malicious.setdefault(name, set()).add(version)
            owner.osv_advisory_ids.setdefault(f"{name}@{version}", set()).update(ids)
            owner.evidence.setdefault(("resolved", name, version), set()).add(source)


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
        with _open_https(request, timeout=timeout) as response:
            record = json.loads(response.read().decode("utf-8"))
    # Naming is an aid, never a gate, so any failure leaves the record empty.
    except Exception:  # noqa: BLE001
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


_SCANNED_LINE_LIMIT: int = 12


def _display(text: str) -> str:
    """Escape anything in a path that a report line cannot safely print.

    Every path in this report comes from a tree the scanner did not write and
    may have no reason to trust. A directory name may legally contain a newline
    on Unix, which would let a crafted tree emit its own "vulnerable: no" line
    into the report, and it may contain a terminal escape sequence, which would
    let it repaint or hide what the reader sees. Neither is exotic to arrange in
    a repository somebody else controls.

    The backslash is escaped first and for its own sake: without that, a file
    genuinely named "\\x0a" would render identically to one carrying a real
    newline, and the escaping meant to remove ambiguity would have introduced
    it. Escape widths follow the Python convention, two hex digits below 0x100,
    four below 0x10000 and eight above it, so a non-BMP code point does not
    produce a \\u run nothing can parse.

    Escaping is applied to the display copy alone. The paths handed to
    osv-scanner and written to the JSON output stay exactly as the filesystem
    gave them, because those consumers need the real name."""
    out: list[str] = []
    for char in text:
        code = ord(char)
        if char == "\\":
            out.append("\\\\")
        elif char.isprintable():
            out.append(char)
        elif code < 0x100:
            out.append(f"\\x{code:02x}")
        elif code < 0x10000:
            out.append(f"\\u{code:04x}")
        else:
            out.append(f"\\U{code:08x}")
    return "".join(out)


def _display_item(text: str) -> str:
    """Escape a path that will be joined into a comma-separated list.

    The comma is a delimiter on those lines, and a directory name may contain
    one. A single file under a directory named "pkg, fake" would otherwise print
    as two entries, so one unread manifest could pose as two read ones, which is
    the same overstatement of coverage the line exists to prevent, reached
    through punctuation instead of through a missing read.

    Lines that print one path each, such as the payload artifact list, use
    _display directly, since a comma is not a delimiter there and escaping it
    would obscure a filename for no gain."""
    return _display(text).replace(",", "\\x2c")


def _repo_relative(root: Path, entries: list[str]) -> list[str]:
    """Render each path for display, relative to the repository and sorted.

    Paths are relative rather than absolute because the repository is already
    named on the line above, and the part that carries information is where
    inside it each file sat: a workspace manifest under packages/ and the root
    manifest are different facts. Separators are normalised to forward slashes
    so the same tree reports identically on every platform."""
    shown: list[str] = []
    for entry in entries:
        path = Path(entry)
        try:
            relative = path.relative_to(root)
        except ValueError:
            # A file charged to a repository it does not sit under should not
            # silently become a bare name that reads as a root manifest.
            shown.append(_display_item(path.as_posix()))
            continue
        shown.append(_display_item(relative.as_posix()))
    shown.sort()
    if len(shown) > _SCANNED_LINE_LIMIT:
        remainder = len(shown) - _SCANNED_LINE_LIMIT
        shown = shown[:_SCANNED_LINE_LIMIT] + [f"and {remainder} more"]
    return shown


def _scanned_lines(status: RepoStatus) -> list[str]:
    """Name the manifests and lockfiles this repository was actually read for.

    The rest of the report says what was found without saying what was opened,
    and the two differ in the way that matters: a lockfile whose name is absent
    from LOCKFILE_NAMES is walked past in silence, so a repository reported as
    not vulnerable may be one whose lockfile nothing ever read. Naming what was
    read is the only thing in the report that makes that visible.

    A file that was found and could not be read gets its own line rather than a
    place in the first one. Listing it as read would be the very failure this
    pair of lines exists to expose, and dropping it would be the same failure
    made quieter, since the reader would then see neither the file nor the
    reason it contributed nothing.

    A monorepo can carry hundreds, so each list is capped and the remainder is
    counted rather than dropped: a truncated list that does not say it was
    truncated reads as the whole of what was opened. Payload artifacts are
    matched over every file in the tree regardless, so these lines are about the
    npm layer alone."""
    root = Path(status.path)
    lines: list[str] = []
    if status.read_files:
        lines.append(f"  read: {', '.join(_repo_relative(root, status.read_files))}")
    else:
        lines.append("  read: nothing (no npm manifest or lockfile was opened here)")
    if status.unreadable_files:
        lines.append(
            "  found but unreadable: "
            f"{', '.join(_repo_relative(root, status.unreadable_files))}"
        )
    if status.unreadable_dirs:
        lines.append(
            "  directories that could not be entered (nothing beneath them was "
            f"seen): {', '.join(_repo_relative(root, status.unreadable_dirs))}"
        )
    return lines


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
        lines.extend(_shai_summary_block(status, seen_advisories))
    lines.append("")

    lines.append(f"MALICIOUS PACKAGES FROM OTHER CAMPAIGNS ({len(unrelated)})")
    if not unrelated:
        lines.append("  none")
    for status in sorted(unrelated, key=lambda s: s.name.lower()):
        lines.extend(_unrelated_summary_block(status, seen_advisories, lookup))
    lines.append("")

    if seen_advisories:
        lines.append("ADVISORY NOTES")
        for advisory_id in sorted(seen_advisories):
            lines.append(f"  {advisory_id}: {_advisory_note(advisory_id, lookup)}")
        lines.append("")

    return lines


def _shai_summary_block(status: RepoStatus, seen_advisories: set[str]) -> list[str]:
    """One Shai-Hulud-exposed repository's summary lines."""
    lines = [f"  [{_display(status.name)}]"]
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
        lines.append(f"    [offline table] payload artifact: {_display(payload_file)}")
    for key, ids in sorted(status.osv_advisory_ids.items()):
        shai_ids = sorted(i for i in ids if _is_shai_hulud_name(key.rsplit("@", 1)[0]))
        if shai_ids:
            lines.append(f"    [osv-scanner] {key}: {', '.join(shai_ids)}")
            seen_advisories.update(shai_ids)
    for key, ids in sorted(status.trivy_confirmed.items()):
        lines.append(f"    [trivy] confirms {key}: {', '.join(sorted(ids))}")
    return lines


def _unrelated_summary_block(
    status: RepoStatus, seen_advisories: set[str], lookup: bool
) -> list[str]:
    """One repository's summary lines for hits outside the campaign."""
    hit_parts: list[str] = []
    for key, ids in sorted(status.osv_advisory_ids.items()):
        hit_parts.append(f"{key} ({', '.join(sorted(ids))})")
        seen_advisories.update(ids)
    lines = [f"  [{_display(status.name)}]  [osv-scanner] {'; '.join(hit_parts)}"]
    for advisory in sorted({a for ids in status.osv_advisory_ids.values() for a in ids}):
        campaign = campaign_of(advisory, lookup)
        if campaign:
            lines.append(f"    {advisory} belongs to {campaign}")
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
        lines.extend(_repo_report_block(status, osv_bin, lookup))
        lines.append("")
    lines.extend(render_vulnerable_summary(statuses, lookup))
    return "\n".join(lines).rstrip() + "\n"


def _repo_report_block(status: RepoStatus, osv_bin: str | None, lookup: bool) -> list[str]:
    """One repository's tiered lines in the human report."""
    lines = [f"[{_display(status.name)}]"]
    if not status.has_npm:
        lines.append("  npm: no")
        return lines
    lines.append("  npm: yes")
    lines.extend(_scanned_lines(status))
    lines.append(_coverage_line(status, osv_bin))
    if not status.package_present() and not status.vulnerable():
        lines.append("  watched packages present: no")
        lines.append("  vulnerable: no")
        return lines
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
        lines.extend(_vulnerable_detail_lines(status, lookup))
    else:
        lines.append("  vulnerable: no")
    return lines


def _offline_detail_lines(status: RepoStatus) -> list[str]:
    """The offline table's evidence lines for one vulnerable repository."""
    lines: list[str] = []
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
            lines.append(f"      {_display(payload_file)}")
    return lines


def _osv_detail_lines(status: RepoStatus, lookup: bool) -> list[str]:
    """The live database's evidence lines for one vulnerable repository."""
    lines: list[str] = []
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
    return lines


def _vulnerable_detail_lines(status: RepoStatus, lookup: bool) -> list[str]:
    """Everything under "vulnerable: YES": each layer's evidence in turn."""
    lines = _offline_detail_lines(status)
    lines.extend(_osv_detail_lines(status, lookup))
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
    return lines


def _utc_now_iso() -> str:
    """The current instant as RFC 3339 UTC, whole seconds, Z suffix."""
    return datetime.now(timezone.utc).strftime(ISO_UTC_FORMAT)


def _relative_posix(root: str, path: str) -> str:
    """A path relative to its repository in forward slashes, for the report.

    Unlike the display helpers this does not escape anything: JSON escapes
    control characters itself, and a consumer needs the name the filesystem
    gave. A path outside the root is returned absolute rather than mangled."""
    try:
        return Path(path).relative_to(Path(root)).as_posix()
    except ValueError:
        return Path(path).as_posix()


_TOOL_VERSION_CACHE: dict[tuple[str, str], str | None] = {}


def _tool_version(binary: str | None, pattern: str) -> str | None:
    """Ask a tool for its version, or None when it cannot be asked.

    Memoised per binary, because the layer objects are rebuilt for every
    report snapshot and a subprocess per snapshot would put the version query
    on the batch loop's clock."""
    if not binary:
        return None
    if (binary, pattern) in _TOOL_VERSION_CACHE:
        return _TOOL_VERSION_CACHE[(binary, pattern)]
    version: str | None = None
    try:
        out = subprocess.run(  # nosec B603
            [binary, "--version"], capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.SubprocessError):
        out = None
    if out is not None:
        match = re.search(pattern, out.stdout + out.stderr)
        version = match.group(1) if match else None
    _TOOL_VERSION_CACHE[(binary, pattern)] = version
    return version


def _osv_version(osv_bin: str | None) -> str | None:
    """osv-scanner's own version string, or None."""
    return _tool_version(osv_bin, r"osv-scanner version:\s*(\d\S*)")


def _trivy_version(trivy_bin: str | None) -> str | None:
    """Trivy's own version string, or None."""
    return _tool_version(trivy_bin, r"Version:\s*([0-9]\S*)")


def _finding_id(*parts: str) -> str:
    """A stable identifier for one finding, derived from what it names.

    The hash input is the coordinates the plan specifies: repository, kind,
    package or artifact, version or range, and the advisory ids. Sixteen hex
    characters keep it short enough to grep for while leaving collisions out of
    practical reach for the counts involved."""
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:16]


def _repo_osv_coverage(
    status: RepoStatus, requested: bool, available: bool
) -> dict[str, Any]:
    """The OSV coverage object for one repository: a state and its counts.

    Non-applicability and failure never share a value, and a consumer that
    meets an unknown applicable state is expected to fail loudly rather than
    read an unfamiliar condition as clean."""
    discovered = len(status.lockfiles)
    unreadable = sum(
        1 for p in status.unreadable_files if os.path.basename(p) in LOCKFILE_NAMES
    )
    resolved = status.osv_resolved_count
    failed = status.osv_failed_count
    unavailable = status.osv_unavailable_count
    empty = status.osv_empty_count
    # An empty lockfile resolves vacuously without ever being handed to the
    # scanner, so it is inside resolved and outside submitted; submitted has
    # to mean what actually crossed the process boundary or the counts here
    # stop reconciling with the run-level ones.
    submitted = resolved - empty + failed + unavailable
    reasons: list[str] = []
    if not requested:
        state = "not_requested"
    elif discovered == 0:
        state = "not_applicable"
    elif not available:
        state = "unavailable"
        reasons.append("binary_not_found")
    elif resolved == discovered:
        state = "completed"
    else:
        state = "partial" if resolved else "failed"
        if failed:
            reasons.append("scanner_rejected_lockfile")
        if unavailable:
            reasons.append("scanner_unavailable")
        if resolved + failed + unavailable < discovered:
            reasons.append("lockfile_not_submitted")
    return {
        "state": state,
        "reason_codes": reasons,
        "discovered": discovered,
        "readable": discovered - unreadable,
        "submitted": submitted,
        "resolved": resolved,
        "empty": empty,
        "failed": failed,
        "unavailable": unavailable,
    }


def _repo_trivy_coverage(
    status: RepoStatus, requested: bool, available: bool
) -> dict[str, Any]:
    """The Trivy corroboration object for one repository.

    Trivy is asked only about lockfiles that already produced a finding, so a
    repository with none is not_applicable rather than unchecked: there was
    nothing to corroborate, which is a different fact from a check that could
    not run."""
    flagged = len(status.flagged_lockfiles)
    reasons: list[str] = []
    if not requested:
        state = "not_requested"
    elif flagged == 0:
        state = "not_applicable"
    elif not available:
        state = "unavailable"
        reasons.append("binary_not_found")
    elif status.trivy_failed_count:
        state = "partial"
        reasons.append("trivy_scan_failed")
    else:
        state = "completed"
    return {
        "state": state,
        "reason_codes": reasons,
        "flagged_lockfiles": flagged,
        "submitted": status.trivy_submitted_count,
        "failed": status.trivy_failed_count,
        "confirmed_packages": len(status.trivy_confirmed),
    }


def builtin_layer() -> dict[str, Any]:
    """The built-in table's layer object: it ships in the source, so it always
    runs and its provenance is the tool version itself."""
    return {
        "requested": True,
        "state": "completed",
        "reason_code": None,
        "message": None,
        "package_count": _BUILTIN_PACKAGE_COUNT,
        "version_count": _BUILTIN_VERSION_COUNT,
    }


def osv_layer(requested: bool, osv_bin: str | None,
              run: OsvRunReport, discovered: int,
              resolved: int) -> dict[str, Any]:
    """The OSV layer object: what ran, against what, and how it ended."""
    layer: dict[str, Any] = {
        "requested": requested,
        "state": "not_requested",
        "reason_code": None,
        "message": None,
        "binary": osv_bin,
        "version": _osv_version(osv_bin) if requested else None,
        "lockfiles_discovered": discovered,
        "submitted": len(run.submitted),
        "resolved": resolved,
        "failed": len(run.failed),
        "unavailable": len(run.unavailable),
        "skipped_empty": len(run.skipped_empty),
        "skipped_unreadable": len(run.skipped_unreadable),
        "duration_ms": run.duration_ms,
    }
    if not requested:
        return layer
    if discovered == 0:
        # Nothing for the layer to do completes it whatever is installed, the
        # same way the Trivy layer completes with nothing to confirm; a tree
        # with no lockfiles must not exit 2 over a scanner it never needed.
        layer["state"] = "completed"
        layer["reason_code"] = "nothing_to_scan"
    elif not osv_bin:
        layer["state"] = "unavailable"
        layer["reason_code"] = "binary_not_found"
        layer["message"] = ("osv-scanner was requested and is not installed, so "
                           "no lockfile was resolved against the live database")
    elif resolved == discovered:
        layer["state"] = "completed"
    else:
        layer["state"] = "partial" if resolved else "failed"
        if run.failed:
            layer["reason_code"] = "scanner_rejected_lockfile"
        elif run.unavailable:
            layer["reason_code"] = "scanner_unavailable"
        else:
            layer["reason_code"] = "lockfile_not_submitted"
    return layer


def trivy_layer(requested: bool, trivy_bin: str | None,
                statuses: list[RepoStatus]) -> dict[str, Any]:
    """The Trivy corroboration layer object.

    Trivy is only ever asked about findings, so a clean estate completes this
    layer with nothing submitted rather than leaving it unknowable."""
    flagged_repos = [s for s in statuses if s.flagged_lockfiles]
    submitted = sum(s.trivy_submitted_count for s in statuses)
    failed = sum(s.trivy_failed_count for s in statuses)
    layer: dict[str, Any] = {
        "requested": requested,
        "state": "not_requested",
        "reason_code": None,
        "message": None,
        "binary": trivy_bin,
        "version": _trivy_version(trivy_bin) if requested else None,
        "repositories_flagged": len(flagged_repos),
        "lockfiles_submitted": submitted,
        "lockfiles_failed": failed,
    }
    if not requested:
        return layer
    if not flagged_repos:
        layer["state"] = "completed"
        layer["reason_code"] = "nothing_to_confirm"
    elif not trivy_bin:
        layer["state"] = "unavailable"
        layer["reason_code"] = "binary_not_found"
        layer["message"] = ("trivy corroboration was requested, findings exist, "
                           "and trivy is not installed")
    elif failed:
        layer["state"] = "partial"
        layer["reason_code"] = "trivy_scan_failed"
    else:
        layer["state"] = "completed"
    return layer


def build_findings(statuses: list[RepoStatus]) -> list[dict[str, Any]]:
    """The canonical findings array: one entry per fact, whoever saw it.

    When the offline table and OSV flag the same resolved version, that is one
    finding carrying both detection layers, not two findings a consumer has to
    recognise as the same. The per-repository summary maps stay in the report
    for human inspection; this array is the shape a pipeline flattens."""
    findings: list[dict[str, Any]] = []
    for status in statuses:
        findings.extend(_resolved_findings(status))
        findings.extend(_range_findings(status))
        findings.extend(_payload_findings(status))
    findings.sort(key=lambda f: (
        str(f["repository"]), str(f["kind"]), str(f.get("package") or ""),
        str(f.get("version") or f.get("range") or f.get("artifact") or ""),
    ))
    return findings


def _resolved_findings(status: RepoStatus) -> list[dict[str, Any]]:
    """One repository's malicious_resolved findings, both layers merged."""
    findings: list[dict[str, Any]] = []
    for name in sorted(set(status.poisoned_versions) | set(status.osv_malicious)):
        offline_versions = status.poisoned_versions.get(name, set())
        osv_versions = status.osv_malicious.get(name, set())
        for version in sorted(offline_versions | osv_versions):
            layers = [
                layer for layer, hit in (
                    ("offline_table", version in offline_versions),
                    ("osv", version in osv_versions),
                ) if hit
            ]
            advisories = sorted(status.osv_advisory_ids.get(f"{name}@{version}", set()))
            sources = sorted(
                _relative_posix(status.path, p)
                for p in status.evidence.get(("resolved", name, version), set())
            )
            findings.append({
                "id": _finding_id(status.path, "malicious_resolved", name,
                                  version, ",".join(advisories)),
                "kind": "malicious_resolved",
                "ecosystem": "npm",
                "package": name,
                "version": version,
                "range": None,
                "repository": status.name,
                "repository_path": status.path,
                "source_files": sources,
                "advisories": advisories,
                "detection_layers": layers,
                "campaign": "shai-hulud" if _is_shai_hulud_name(name) else None,
                "trivy_confirmed": sorted(
                    status.trivy_confirmed.get(f"{name}@{version}", set())
                ),
            })
    return findings


def _range_findings(status: RepoStatus) -> list[dict[str, Any]]:
    """One repository's malicious_range findings."""
    findings: list[dict[str, Any]] = []
    for name in sorted(status.poisoned_ranges):
        for spec in sorted(status.poisoned_ranges[name]):
            sources = sorted(
                _relative_posix(status.path, p)
                for p in status.evidence.get(("range", name, spec), set())
            )
            findings.append({
                "id": _finding_id(status.path, "malicious_range", name, spec, ""),
                "kind": "malicious_range",
                "ecosystem": "npm",
                "package": name,
                "version": None,
                "range": spec,
                "repository": status.name,
                "repository_path": status.path,
                "source_files": sources,
                "advisories": [],
                "detection_layers": ["offline_table"],
                "campaign": "shai-hulud" if _is_shai_hulud_name(name) else None,
                "trivy_confirmed": [],
            })
    return findings


def _payload_findings(status: RepoStatus) -> list[dict[str, Any]]:
    """One repository's payload_artifact findings."""
    findings: list[dict[str, Any]] = []
    for payload in sorted(status.payload_files):
        artifact = os.path.basename(payload)
        relative = _relative_posix(status.path, payload)
        findings.append({
            # The relative path joins the identity, because one worm drops the
            # same filename in several directories and two findings sharing an
            # id would deduplicate into one occurrence lost.
            "id": _finding_id(status.path, "payload_artifact", artifact, relative, ""),
            "kind": "payload_artifact",
            "ecosystem": "npm",
            "package": None,
            "version": None,
            "range": None,
            "artifact": artifact,
            "repository": status.name,
            "repository_path": status.path,
            "source_files": [relative],
            "advisories": [],
            "detection_layers": ["offline_table"],
            # The payload filenames are the worm's own, so the campaign tag
            # is a statement about the artifact rather than an inference.
            "campaign": "shai-hulud",
            "trivy_confirmed": [],
        })
    return findings


_ERROR_LIMIT: int = 200
_ERROR_MESSAGE_LIMIT: int = 300


def _error(code: str, scope: str, message: str, *, repository: str | None = None,
           file: str | None = None, retryable: bool = False) -> dict[str, Any]:
    """One structured, bounded error entry."""
    return {
        "code": code,
        "scope": scope,
        "repository": repository,
        "file": file,
        "retryable": retryable,
        "message": message[:_ERROR_MESSAGE_LIMIT],
    }


def collect_errors(
    layers: dict[str, dict[str, Any]],
    statuses: list[RepoStatus],
    osv_run: OsvRunReport,
) -> list[dict[str, Any]]:
    """Everything that went wrong, as stable codes rather than prose.

    The list is bounded so a tree of ten thousand unreadable files cannot turn
    the report into a log; when it is cut, the cut itself is the last entry,
    because a truncated list that does not say so reads as the whole story."""
    errors: list[dict[str, Any]] = []
    for layer_name in ("overlay", "osv", "trivy"):
        layer = layers.get(layer_name, {})
        # partial counts too: a requested layer that half-ran makes the run
        # exit 2, and an exit 2 whose error list is empty sends the consumer
        # hunting through the layers by hand for the reason.
        if layer.get("requested") and layer.get("state") in (
                "unavailable", "failed", "partial"):
            errors.append(_error(
                str(layer.get("reason_code") or f"{layer_name}_unavailable"),
                "layer",
                f"the {layer_name} layer was requested and did not complete",
            ))
    for path in osv_run.failed:
        errors.append(_error(
            "osv_submission_failed", "file",
            "osv-scanner rejected this lockfile", file=path,
        ))
    for path in osv_run.skipped_unreadable:
        errors.append(_error(
            "lockfile_unreadable", "file",
            "this lockfile could not be read at submission time", file=path,
        ))
    for path in osv_run.unavailable:
        errors.append(_error(
            "osv_scanner_unavailable", "file",
            "osv-scanner never reached a verdict here (timeout, spawn failure "
            "or unparsable output); the lockfile itself may be sound",
            file=path, retryable=True,
        ))
    for status in sorted(statuses, key=lambda s: s.name.lower()):
        errors.extend(_repository_errors(status))
    if len(errors) > _ERROR_LIMIT:
        dropped = len(errors) - _ERROR_LIMIT
        errors = errors[:_ERROR_LIMIT]
        errors.append(_error(
            "error_list_truncated", "invocation",
            f"{dropped} further error(s) were dropped from this list",
        ))
    return errors


def _repository_errors(status: RepoStatus) -> list[dict[str, Any]]:
    """One repository's structured errors: unreadable files, Trivy failures."""
    errors: list[dict[str, Any]] = []
    for path in sorted(status.unreadable_dirs):
        errors.append(_error(
            "directory_unreadable", "file",
            "could not be enumerated; anything beneath it was never seen",
            repository=status.name, file=path,
        ))
    for path in sorted(status.unreadable_files):
        code = ("manifest_unreadable"
                if os.path.basename(path) == MANIFEST_NAME
                else "lockfile_unreadable")
        errors.append(_error(
            code, "file", "found but could not be read or parsed",
            repository=status.name, file=path,
        ))
    if status.trivy_failed_count:
        errors.append(_error(
            "trivy_failed", "repository",
            f"trivy could not scan {status.trivy_failed_count} flagged "
            "lockfile(s)", repository=status.name, retryable=True,
        ))
    return errors


def repo_to_dict(status: RepoStatus, osv_requested: bool, osv_available: bool,
                 trivy_requested: bool, trivy_available: bool) -> dict[str, Any]:
    """One repository as the report carries it: summary maps plus coverage."""
    lockfile_unreadable = sum(
        1 for p in status.unreadable_files if os.path.basename(p) in LOCKFILE_NAMES
    )
    return {
        "name": status.name,
        "path": status.path,
        "has_npm": status.has_npm,
        "npm_files": status.npm_files,
        # Unescaped, unlike the human report: a consumer of this file needs
        # the name the filesystem gave, and JSON escapes a control character
        # on its own rather than letting it forge a field.
        "read_files": status.read_files,
        "unreadable_files": status.unreadable_files,
        "unreadable_dirs": status.unreadable_dirs,
        "lockfiles": status.lockfiles,
        "counts": {
            "manifests_discovered": sum(
                1 for p in status.npm_files if os.path.basename(p) == MANIFEST_NAME
            ),
            "lockfiles_discovered": len(status.lockfiles),
            "files_read": len(status.read_files),
            "files_unreadable": len(status.unreadable_files),
            "lockfiles_unreadable": lockfile_unreadable,
            "dirs_unreadable": status.unreadable_dir_total,
        },
        "present_versions": {k: sorted(v) for k, v in status.present_versions.items()},
        "range_only": {k: sorted(v) for k, v in status.range_only.items()},
        "poisoned_versions": {k: sorted(v) for k, v in status.poisoned_versions.items()},
        "poisoned_ranges": {k: sorted(v) for k, v in status.poisoned_ranges.items()},
        "payload_files": status.payload_files,
        "osv_checked": status.osv_checked,
        "osv_malicious": {k: sorted(v) for k, v in status.osv_malicious.items()},
        "osv_advisory_ids": {k: sorted(v) for k, v in status.osv_advisory_ids.items()},
        "trivy_confirmed": {k: sorted(v) for k, v in status.trivy_confirmed.items()},
        "coverage": {
            "osv": _repo_osv_coverage(status, osv_requested, osv_available),
            "trivy": _repo_trivy_coverage(status, trivy_requested, trivy_available),
        },
        "package_present": status.package_present(),
        "vulnerable": status.vulnerable(),
    }


def build_report(
    statuses: list[RepoStatus],
    *,
    roots: list[str],
    include_node_modules: bool,
    layers: dict[str, dict[str, Any]],
    errors: list[dict[str, Any]],
    osv_run: OsvRunReport,
    invocation_id: str,
    started_utc: str,
    finished_utc: str | None,
    complete: bool,
) -> dict[str, Any]:
    """Assemble the versioned scan report around the per-repository statuses.

    Everything in it is deterministic for a fixed tree apart from the
    invocation block, which is the block that exists to be different each
    time: it is what lets a consumer tell a final report of the intended
    invocation from a stale file another run left behind."""
    osv_requested = bool(layers.get("osv", {}).get("requested"))
    osv_available = layers.get("osv", {}).get("binary") is not None
    trivy_requested = bool(layers.get("trivy", {}).get("requested"))
    trivy_available = layers.get("trivy", {}).get("binary") is not None
    repositories = [
        repo_to_dict(s, osv_requested, osv_available, trivy_requested, trivy_available)
        for s in sorted(statuses, key=lambda s: (s.name.lower(), s.path))
    ]
    findings = build_findings(statuses)
    return {
        "schema": {"name": REPORT_SCHEMA_NAME, "version": REPORT_SCHEMA_VERSION},
        "tool": {"name": "lockfile-sentinel", "version": __version__},
        "invocation": {
            "id": invocation_id,
            "started_utc": started_utc,
            "finished_utc": finished_utc,
            "complete": complete,
            "roots": roots,
            "include_node_modules": include_node_modules,
            "requested_layers": [
                name for name in ("builtin", "overlay", "osv", "trivy")
                if layers.get(name, {}).get("requested")
            ],
        },
        "layers": layers,
        "inputs": {
            "manifests_discovered": sum(
                1 for s in statuses for p in s.npm_files
                if os.path.basename(p) == MANIFEST_NAME
            ),
            "lockfiles_discovered": sum(len(s.lockfiles) for s in statuses),
            "lockfiles_submitted": len(osv_run.submitted),
            "lockfiles_resolved": sum(s.osv_resolved_count for s in statuses),
            "lockfiles_failed": len(osv_run.failed),
            "files_read": sum(len(s.read_files) for s in statuses),
            "files_unreadable": sum(len(s.unreadable_files) for s in statuses),
            "dirs_unreadable": sum(s.unreadable_dir_total for s in statuses),
        },
        "totals": {
            "repositories": len(statuses),
            "with_npm_tooling": sum(1 for s in statuses if s.has_npm),
            "with_watched_packages": sum(1 for s in statuses if s.package_present()),
            "vulnerable": sum(1 for s in statuses if s.vulnerable()),
            "findings": len(findings),
        },
        "repositories": repositories,
        "findings": findings,
        "errors": errors,
    }


def report_is_complete(layers: dict[str, dict[str, Any]],
                       statuses: list[RepoStatus]) -> bool:
    """Whether every requested layer ran to completion over every input.

    This is the fact the exit code states: 0 and 1 both assert complete
    requested coverage, and everything short of that is 2, findings or not. A
    layer the caller declined does not count against it, because a flag like
    --no-osv is a policy choice recorded in the report, not a failure."""
    for layer in layers.values():
        if layer.get("requested") and layer.get("state") not in ("completed",):
            return False
    for status in statuses:
        if status.unreadable_files or status.unreadable_dir_total:
            return False
        if status.lockfiles and not status.osv_checked \
                and layers.get("osv", {}).get("requested"):
            return False
        if status.trivy_failed_count and layers.get("trivy", {}).get("requested"):
            return False
    return True


def render_json(report: dict[str, Any]) -> str:
    """Serialize the assembled report, stable and indented."""
    return json.dumps(report, indent=2)


def _write_atomic(path: Path, text: str) -> None:
    """Write a file so no reader can ever see it half-written.

    Temp file in the same directory, flush, fsync where the platform honours
    it, then an atomic replace. The report path is the contract with whatever
    consumes it, and a consumer that reads during a plain write gets truncated
    JSON that parses as nothing."""
    fd, tmp = tempfile.mkstemp(
        dir=str(path.parent) or ".", prefix=path.name + ".", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _build_parser() -> argparse.ArgumentParser:
    """The whole command line, declared in one place."""
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
        "ago, then exit. 0 all fresh, 1 something stale, 2 something unknown. "
        "With --json, emit the lockfile-sentinel-status document instead of prose.",
    )
    parser.add_argument(
        "--check-live",
        action="store_true",
        help="With --status: also probe api.osv.dev once and report reachability. Ordinary "
        "status mode makes no network request, because freshness on disk does not need one.",
    )
    parser.add_argument(
        "--osv",
        nargs=argparse.REMAINDER,
        metavar="ARG",
        help="Pass everything that follows to `osv-scanner scan` and exit with its code, "
        "instead of running the repository sweep.",
    )
    return parser


def main() -> int:
    """Entry point: parse arguments, scan all roots, and print or write results."""
    args = _build_parser().parse_args()
    special = _dispatch_special_modes(args)
    if special is not None:
        return special
    return _run_sweep(args)


def _dispatch_special_modes(args: argparse.Namespace) -> int | None:
    """Run whichever short-circuit mode was asked for, or None for the sweep."""
    # Status reports on the inputs and changes nothing, so it runs before the
    # checks that would refresh them and skew the very ages it is reporting.
    if args.status:
        return report_status(
            Path(args.overlay_file), find_osv_scanner(args.osv_scanner_bin),
            as_json=args.json, check_live=args.check_live, output=args.output,
        )

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
        # The offline table is loaded here too. Diagnosis mode used to skip it
        # and consult osv-scanner alone, so it matched against whatever versions
        # were compiled into this file and none of the campaign versions the
        # overlay carries, which is the larger list by an order of magnitude.
        _prepare_offline_table(args)
        return diagnose_lockfiles(
            None if args.no_osv else find_osv_scanner(args.osv_scanner_bin),
            named,
            args.osv_timeout,
            live_requested=not args.no_osv,
        )

    # Passthrough mode short-circuits the sweep: no walk, no overlay, no report.
    # The overlay refresh below does not apply to it, because osv-scanner never
    # reads the overlay and the download would feed nothing.
    if args.osv is not None:
        return run_passthrough(find_osv_scanner(args.osv_scanner_bin), args.osv)
    return None


def _run_sweep(args: argparse.Namespace) -> int:
    """The repository sweep: walk, cross-check, report, exit code."""
    started_utc = _utc_now_iso()
    invocation_id = str(uuid.uuid4())
    overlay_info = _prepare_offline_table(args)

    # Default to the current directory rather than to anything guessed: a
    # scanner that silently walks somewhere the caller did not name is a scanner
    # whose report cannot be trusted to describe what they meant.
    # Resolved, not taken as given. osv-scanner reports absolute source paths in
    # its results, so a relative root produced relative index keys that never
    # matched the absolute keys coming back, and every live-database finding for
    # that run was silently discarded while the coverage line still claimed the
    # lockfile had been submitted and resolved. A package the offline table does
    # not already know would have been reported clean.
    roots = _deduplicate_roots([Path(r).resolve() for r in (args.roots or ["."])])

    # A root that does not resolve is fatal, not skippable. Skipping it left
    # all_statuses empty, printed "Repositories scanned: 0" and exited 0, so a
    # mistyped path in an automation produced a clean bill of health for a tree
    # nothing had looked at. Exit 2 is the documented code for a check that
    # could not be performed.
    # is_dir() is not enough: a directory whose permissions deny enumeration
    # passes it, and the walk then swallows the scandir error and reports an
    # empty tree with exit 0. So each root is opened here, which is the only
    # test that distinguishes "empty" from "unreadable".
    if not _roots_are_usable(roots):
        return 2

    all_statuses, lockfile_index = _walk_all_roots(roots, args)

    output = Path(args.output) if args.output else None
    sweep = _Sweep(
        args=args,
        roots=roots,
        statuses=all_statuses,
        lockfile_index=lockfile_index,
        osv_bin=(find_osv_scanner(args.osv_scanner_bin)
                 if not args.no_osv else None),
        trivy_bin=resolve_trivy() if not args.no_trivy else None,
        overlay_info=overlay_info,
        osv_run=OsvRunReport(),
        invocation_id=invocation_id,
        started_utc=started_utc,
        output=output,
        partial=output.with_name(output.name + ".partial") if output else None,
    )

    # Write the tier 1/2 snapshot as soon as the walk is done, before OSV runs.
    # From this point a killed run still leaves complete valid output on disk,
    # at the partial path and marked incomplete; batches below upgrade it.
    if output is not None:
        sweep.persist_snapshot()
        _progress(f"tier 1/2 snapshot written to {sweep.partial}; "
                  "starting OSV cross-check")

    sweep.run_live_layer()
    sweep.run_trivy_layer()
    return sweep.finish()


def _deduplicate_roots(roots: list[Path]) -> list[Path]:
    """Drop a root that repeats, or that sits inside another requested root.

    Walking the same tree twice produces duplicate repository statuses while
    the path-keyed lockfile index submits each physical lockfile once, so
    only one duplicate ever receives OSV results: the run then reads as
    partial coverage and exits 2 after a perfectly good scan. The report
    describes trees, so each tree is walked once whatever the caller typed."""
    kept: list[Path] = []
    for root in roots:
        covered_by = next(
            (other for other in roots
             if other != root and other in root.parents), None,
        )
        if covered_by is not None:
            _progress(f"root {root} is inside {covered_by}, walking it once there")
            continue
        if root in kept:
            _progress(f"root {root} was named more than once, walking it once")
            continue
        kept.append(root)
    return kept


def _roots_are_usable(roots: list[Path]) -> bool:
    """Refuse the sweep unless every named root can actually be enumerated.

    A root that does not resolve is fatal, not skippable. Skipping it left
    the status list empty, printed "Repositories scanned: 0" and exited 0, so
    a mistyped path in an automation produced a clean bill of health for a
    tree nothing had looked at. Exit 2 is the documented code for a check that
    could not be performed.

    is_dir() is not enough: a directory whose permissions deny enumeration
    passes it, and the walk then swallows the scandir error and reports an
    empty tree with exit 0. So each root is opened here, which is the only
    test that distinguishes "empty" from "unreadable"."""
    unusable: list[tuple[Path, str]] = []
    for root in roots:
        if not root.exists():
            unusable.append((root, "does not exist"))
        elif not root.is_dir():
            unusable.append((root, "is not a directory"))
        else:
            try:
                with os.scandir(root) as probe:
                    next(iter(probe), None)
            except OSError as exc:
                unusable.append((root, f"cannot be read ({exc.strerror or exc})"))
    for root, reason in unusable:
        _progress(f"FAIL: root {root} {reason}")
    if unusable:
        _progress("refusing to report on a scan that could not cover every root given")
    return not unusable


def _count_all_repositories(roots: list[Path], include_node_modules: bool) -> int:
    """Size the walk before starting it, so the percentage and the estimate
    have a denominator. Counting repositories rather than top-level directories
    is what makes the number mean something on a tree where one directory holds
    several repositories, and stopping at each .git keeps the pass to seconds."""
    counted = 0
    for root in roots:
        if not root.is_dir():
            continue
        _progress(f"counting repositories under {root} ...")
        started_count = time.monotonic()
        root_total = sum(
            count_repositories(unit, include_node_modules)
            for unit in top_level_units(root, include_node_modules)
        )
        counted += root_total
        _progress(f"  {root_total} repository(ies) in "
                  f"{format_elapsed(time.monotonic() - started_count)}")
    return counted


def _walk_all_roots(
    roots: list[Path], args: argparse.Namespace
) -> tuple[list[RepoStatus], LockfileIndex]:
    """Walk every root behind one progress bar, merging the indexes."""
    walk_progress = WalkProgress(
        _count_all_repositories(roots, args.include_node_modules), desc="walk"
    )
    all_statuses: list[RepoStatus] = []
    lockfile_index: LockfileIndex = {}
    for root in roots:
        statuses, root_lockfile_index = scan_root(
            root, args.include_node_modules, walk_progress, args.jobs
        )
        all_statuses.extend(statuses.values())
        lockfile_index.update(root_lockfile_index)
    walk_progress.finish()
    return all_statuses, lockfile_index


@dataclass
class _Sweep:
    """One sweep's fixed identity and mutable results, and the steps over them.

    The report is assembled from this state several times per run, once per
    snapshot and once at the end, so the state lives in one place rather than
    in a closure per concern."""

    args: argparse.Namespace
    roots: list[Path]
    statuses: list[RepoStatus]
    lockfile_index: LockfileIndex
    osv_bin: str | None
    trivy_bin: str | None
    overlay_info: dict[str, Any]
    osv_run: OsvRunReport
    invocation_id: str
    started_utc: str
    output: Path | None
    partial: Path | None

    def layers(self) -> dict[str, dict[str, Any]]:
        """The four layer objects as they stand right now."""
        return {
            "builtin": builtin_layer(),
            "overlay": self.overlay_info,
            "osv": osv_layer(
                not self.args.no_osv, self.osv_bin, self.osv_run,
                sum(len(s.lockfiles) for s in self.statuses),
                sum(s.osv_resolved_count for s in self.statuses),
            ),
            "trivy": trivy_layer(not self.args.no_trivy, self.trivy_bin, self.statuses),
        }

    def render(self, complete: bool, finished: str | None) -> str:
        """The report text in the requested format, human or JSON."""
        if not self.args.json:
            return render_human(self.statuses, self.osv_bin,
                                not self.args.no_advisory_lookup)
        layers = self.layers()
        return render_json(build_report(
            self.statuses,
            roots=[str(r) for r in self.roots],
            include_node_modules=self.args.include_node_modules,
            layers=layers,
            errors=collect_errors(layers, self.statuses, self.osv_run),
            osv_run=self.osv_run,
            invocation_id=self.invocation_id,
            started_utc=self.started_utc,
            finished_utc=finished,
            complete=complete,
        ))

    def persist_snapshot(self) -> None:
        """Write an interim report to the partial path, never the final one.

        The final path is the contract with whatever consumes it, so nothing
        short of a completed run may claim it: a consumer that read the
        mid-run file used to have no way to tell it from the finished report.
        The partial is what a killed run leaves behind, valid JSON marked
        incomplete. A snapshot that cannot be written is reported and does not
        stop the scan, because the final write is the one that counts."""
        if self.partial is None:
            return
        try:
            _write_atomic(self.partial, self.render(False, None))
        except OSError as exc:
            _progress(f"could not write the snapshot to {self.partial} ({exc})")

    def run_live_layer(self) -> None:
        """Run the OSV pass over every discovered lockfile, snapshotting."""
        if not self.osv_bin or not self.lockfile_index:
            return

        def on_batch_done(
            findings: dict[str, list[tuple[str, str, set[str]]]], processed: set[str]
        ) -> None:
            # The full outcome sets travel with every snapshot, not only the
            # final report, so an interrupted multi-batch run leaves a partial
            # whose per-repository counts already reconcile with what had
            # actually happened when it was written.
            apply_osv_results(
                self.lockfile_index, findings, processed,
                failed_paths={_normalize_path(p) for p in self.osv_run.failed},
                skipped_paths={_normalize_path(p)
                               for p in self.osv_run.skipped_unreadable},
                unavailable_paths={_normalize_path(p)
                                   for p in self.osv_run.unavailable},
                empty_paths={_normalize_path(p)
                             for p in self.osv_run.skipped_empty},
            )
            self.persist_snapshot()

        osv_findings, osv_processed = run_osv_scanner(
            self.osv_bin,
            list(self.lockfile_index.keys()),
            self.args.osv_batch_size,
            self.args.osv_timeout,
            on_batch_done=on_batch_done,
            debug=self.args.osv_debug,
            run_report=self.osv_run,
        )
        # Re-applied once with the failure and skip sets, which only exist in
        # full after the last batch, so the per-repository coverage counts
        # describe the whole run rather than the batches a snapshot happened
        # to have seen.
        apply_osv_results(
            self.lockfile_index, osv_findings, osv_processed,
            failed_paths={_normalize_path(p) for p in self.osv_run.failed},
            skipped_paths={_normalize_path(p)
                           for p in self.osv_run.skipped_unreadable},
            unavailable_paths={_normalize_path(p)
                               for p in self.osv_run.unavailable},
            empty_paths={_normalize_path(p)
                         for p in self.osv_run.skipped_empty},
        )

    def run_trivy_layer(self) -> None:
        """Trivy is asked only about what was already flagged, so this runs
        after the sweep and never widens the scan."""
        if self.args.no_trivy:
            return
        if self.trivy_bin:
            trivy_recheck(self.statuses, self.trivy_bin, self.args.trivy_timeout)
        else:
            _progress("trivy re-check skipped: trivy not found")

    def _write_final(self, final_text: str) -> bool:
        """Land the final report, returning whether the write failed.

        A completed scan whose report never landed is an operational failure,
        not a success with a caveat: the caller asked for a durable report and
        there is none."""
        if self.output is None:
            sys.stdout.write(final_text if final_text.endswith("\n")
                             else final_text + "\n")
            return False
        try:
            _write_atomic(self.output, final_text)
            if self.partial is not None:
                self.partial.unlink(missing_ok=True)
            _progress(f"report written to {self.output}")
            return False
        except OSError as exc:
            _progress(f"FAIL: could not write the report to {self.output} ({exc})")
            return True

    def _write_summary(self) -> bool:
        """Write the vulnerable-repositories summary, returning failure."""
        if not self.args.summary_out:
            return False
        summary_text = "\n".join(
            render_vulnerable_summary(self.statuses, not self.args.no_advisory_lookup)
        ).lstrip("\n") + "\n"
        try:
            _write_atomic(Path(self.args.summary_out), summary_text)
            _progress("vulnerable-repositories summary written to "
                      f"{self.args.summary_out}")
            return False
        except OSError as exc:
            _progress(f"FAIL: could not write the summary to "
                      f"{self.args.summary_out} ({exc})")
            return True

    def finish(self) -> int:
        """Write the final report and summary, and compute the exit code.

        0 and 1 both assert complete requested coverage; anything short of
        that is 2, findings or not, and the report carries both facts. A layer
        the caller declined with --no-osv, --no-overlay or --no-trivy is a
        recorded policy choice rather than a failure."""
        complete = report_is_complete(self.layers(), self.statuses)
        write_failed = self._write_final(self.render(complete, _utc_now_iso()))
        write_failed = self._write_summary() or write_failed
        if not complete or write_failed:
            return 2
        return 1 if any(s.vulnerable() for s in self.statuses) else 0


if __name__ == "__main__":
    sys.exit(main())
