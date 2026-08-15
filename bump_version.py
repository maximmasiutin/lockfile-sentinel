"""Set the release version everywhere it is written, or check that it agrees.

The version is deliberately duplicated across this project rather than imported
from one module into the others, because each program is meant to be copied out
and run on its own and an import would tie a standalone copy back to a checkout
it may not have. tests/test_headers.py enforces that the copies agree. This is
the other half of that arrangement: the thing that sets them, so a release does
not depend on remembering every one of them.

Every site is declared in SITES below, and a site that matches nothing is an
error rather than a silent skip. That is the whole point. A bump that quietly
misses one produces a file that misstates its own version, which is the failure
the header test exists to catch and which is far cheaper to prevent here. No
count is written down anywhere, deliberately: a number in a comment is one more
thing to be wrong after the next file is added, and `--check` answers it.

The changelog is not rewritten. Its headings are the record of what was
released, and editing one would restate history; instead the new version must
already have a section, and its absence stops the run. A release with no notes
is a release nobody can read, so this refuses to produce one.

Usage:
    python bump_version.py --check
    python bump_version.py --dry-run 0.2.0
    python bump_version.py 0.2.0
    python bump_version.py --minor
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

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# Carried per file rather than imported, because each of these programs runs on
# its own and an imported version would tie a standalone copy back to a checkout
# it may not have. tests/test_headers.py is what keeps them from drifting.
__version__ = "0.2.0"

ROOT = Path(__file__).resolve().parent

# The file whose __version__ is the one the tests compare every other site
# against, so it is also the one this program reads to learn where it stands.
REFERENCE = "lockfile_sentinel.py"

SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")

# Files whose version-shaped content is data rather than a claim about this
# release: the changelog keeps every version it has ever published, and the tests
# for this program are made of versions other than the current one, since that is
# what there is to test. A note about either is noise, and a guard that cries
# every run is one nobody reads.
STRAY_EXEMPT = frozenset({"CHANGELOG.md", "LICENSE.txt", "test_bump_version.py"})


@dataclass(frozen=True)
class Site:
    """One way the version is written, and the files it is written in.

    `pattern` must carry a group named `version` covering the digits alone, so a
    rewrite replaces the number without disturbing the text around it.

    `header_only` confines the search to the header, which is everything above
    the first `from __future__` import, the same boundary tests/test_headers.py
    uses to decide what a header is. A file with no such import is all header,
    which is what the README wants.
    """

    name: str
    globs: tuple[str, ...]
    pattern: re.Pattern[str]
    header_only: bool = False


SITES: tuple[Site, ...] = (
    Site(
        # The same line serves as the comment header of every Python file and as
        # the title of the README, so one pattern covers both.
        #
        # Confined to the header because a test fixture holds a whole miniature
        # project as string literals, headers included. Rewriting those bumped
        # the fake header while the fake __version__ beside it stayed put, since
        # that site does not read the tests directory, and the fixture came out
        # stating two versions at once. The suite then failed on the next run,
        # so the documented release command broke the tests it was released
        # with. A round trip hides it, because the second bump puts the fixture
        # back; only a one-way bump shows it.
        name="the program name line",
        globs=("*.py", "tests/*.py", "README.md"),
        pattern=re.compile(r"(?m)^# Lockfile Sentinel (?P<version>\d+\.\d+\.\d+)$"),
        header_only=True,
    ),
    Site(
        name="the __version__ assignment",
        globs=("*.py",),
        pattern=re.compile(r'(?m)^__version__ = "(?P<version>\d+\.\d+\.\d+)"$'),
    ),
    Site(
        # The quick-start command pins a raw file URL to a tag, and a stale tag
        # there hands out the previous release to anyone who copies the line.
        name="the pinned tag in a raw file URL",
        globs=("README.md",),
        pattern=re.compile(r"/v(?P<version>\d+\.\d+\.\d+)/"),
    ),
)


class BumpError(RuntimeError):
    """A condition that stops the run, reported without a traceback."""


def parse_arguments() -> argparse.Namespace:
    """Return the parsed command line."""
    parser = argparse.ArgumentParser(
        description="Set the release version in every file that states it.",
    )
    parser.add_argument(
        "new_version",
        nargs="?",
        default=None,
        metavar="VERSION",
        help="the version to write, as major.minor.patch",
    )
    step = parser.add_mutually_exclusive_group()
    step.add_argument(
        "--major",
        action="store_true",
        help="raise the major version and zero the rest, instead of naming a version",
    )
    step.add_argument(
        "--minor",
        action="store_true",
        help="raise the minor version and zero the patch, instead of naming a version",
    )
    step.add_argument(
        "--patch",
        action="store_true",
        help="raise the patch version, instead of naming a version",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="report whether every site already states the current version, and write nothing",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would change and write nothing",
    )
    parser.add_argument(
        "--allow-missing-changelog",
        action="store_true",
        help="write the version even though the changelog has no section for it",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"lockfile-sentinel bump_version {__version__}",
    )
    return parser.parse_args()


def files_for(site: Site) -> list[Path]:
    """Return the files a site applies to, in a stable order and without repeats."""
    found: list[Path] = []
    for pattern in site.globs:
        for path in sorted(ROOT.glob(pattern)):
            if path.is_file() and path not in found:
                found.append(path)
    return found


def read(path: Path) -> str:
    """Return a file's text, decoded as UTF-8, with newlines as '\\n'."""
    return path.read_text(encoding="utf-8")


def read_keeping_newlines(path: Path) -> tuple[str, str]:
    """Return a file's text and the line ending it uses.

    Path.write_text translates '\\n' to os.linesep, so on Windows a file read and
    written back unchanged comes out CRLF throughout. Every file here is stored
    LF, and the result is a program that rewrites the line endings of nine files
    as a side effect of setting a version in one place. It is invisible in
    `git diff`, because .gitattributes normalises on commit, and it is invisible
    in review for the same reason, so nothing catches it later either.

    The line ending is therefore carried out of the read and given back to the
    write. A file with mixed endings reports a tuple; the first is taken, since
    any single choice re-writes some of it and the alternative is to refuse a
    file that is merely untidy.
    """
    with path.open(encoding="utf-8") as handle:
        text = handle.read()
        seen = handle.newlines
    if isinstance(seen, tuple):
        return text, seen[0]
    return text, seen or "\n"


def write_keeping_newlines(path: Path, text: str, newline: str) -> None:
    """Write text back with the line ending the file already used."""
    with path.open("w", encoding="utf-8", newline=newline) as handle:
        handle.write(text)


def current_version() -> str:
    """Return the version the reference file declares.

    The reference is the scanner, which is what the header test compares every
    other file against. Taking it from anywhere else would let this program and
    the test disagree about what "the current version" means.
    """
    path = ROOT / REFERENCE
    if not path.is_file():
        raise BumpError(f"{REFERENCE} is missing, so there is no version to read")
    match = re.search(r'(?m)^__version__ = "(?P<version>\d+\.\d+\.\d+)"$', read(path))
    if not match:
        raise BumpError(f"{REFERENCE} declares no __version__")
    return match.group("version")


def stepped(version: str, args: argparse.Namespace) -> str:
    """Return the version one step up from the current one."""
    match = SEMVER.match(version)
    if not match:
        raise BumpError(f"the current version {version!r} is not major.minor.patch")
    major, minor, patch = (int(part) for part in match.groups())
    if args.major:
        return f"{major + 1}.0.0"
    if args.minor:
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def target_version(current: str, args: argparse.Namespace) -> str:
    """Return the version to write, from the argument or from a step."""
    stepping = bool(args.major or args.minor or args.patch)
    requested: str = str(args.new_version) if args.new_version else ""
    if requested and stepping:
        raise BumpError("name a version or ask for a step, not both")
    if stepping:
        return stepped(current, args)
    if not requested:
        raise BumpError("name a version, or ask for --major, --minor or --patch")
    if not SEMVER.match(requested):
        raise BumpError(f"{requested!r} is not major.minor.patch")
    return requested


def header_end(text: str) -> int:
    """Where a file's header stops, which is its first __future__ import.

    tests/test_headers.py draws the line in the same place and for the same
    reason: nothing after that import is a header by any reading, and a fixed
    number of characters would either stop short of a long notice or reach past
    a short one into the body.
    """
    cut = text.find("\nfrom __future__ import")
    return len(text) if cut == -1 else cut


def substitute(text: str, site: Site, version: str) -> tuple[str, int, list[str]]:
    """Return the text with every occurrence set to `version`.

    Also returns how many were found and which versions they held, so a caller
    can tell a file that was already correct from one that was changed, and can
    report a file that disagreed with the rest.
    """
    limit = header_end(text) if site.header_only else len(text)
    pieces: list[str] = []
    found: list[str] = []
    last = 0
    for match in site.pattern.finditer(text):
        start, end = match.span("version")
        if start >= limit:
            break
        found.append(match.group("version"))
        pieces.append(text[last:start])
        pieces.append(version)
        last = end
    pieces.append(text[last:])
    return "".join(pieces), len(found), found


def changelog_has(version: str) -> bool:
    """Return whether the changelog carries a section for a version."""
    path = ROOT / "CHANGELOG.md"
    if not path.is_file():
        return False
    return re.search(rf"(?m)^## {re.escape(version)}\s*$", read(path)) is not None


def stray_occurrences(version: str) -> list[str]:
    """Return places that state a version of this project other than `version`.

    SITES describes the ways the version is written today, and a project grows
    new ones: a workflow that pins a tag, a comment that quotes a release. Those
    would be missed silently, so the files are swept afterwards and anything
    found is reported rather than edited, since guessing at an unknown site is
    how a bump corrupts a file it was never taught about.

    The sweep matches only a version attached to this project's name, never a
    bare number. Everything here is a scanner whose subject matter is package
    versions: the poisoned-package floor, the self-test lockfile and most of the
    test suite are made of them, and a sweep for anything shaped like a version
    reports seventy lines of ordinary data. A guard that noisy is one nobody
    reads, which is worse than no guard, because it is mistaken for coverage.
    """
    contexts = (
        re.compile(r"Lockfile Sentinel (\d+\.\d+\.\d+)"),
        re.compile(r"lockfile-sentinel[ /@]v?(\d+\.\d+\.\d+)"),
        re.compile(r'__version__\s*=\s*"(\d+\.\d+\.\d+)"'),
    )
    reports: list[str] = []
    for path in sorted(ROOT.glob("*.py")) + sorted((ROOT / "tests").glob("*.py")) + sorted(
        ROOT.glob("*.md")
    ):
        if path.name in STRAY_EXEMPT:
            continue
        for number, line in enumerate(read(path).splitlines(), start=1):
            if any(
                match.group(1) != version
                for pattern in contexts
                for match in pattern.finditer(line)
            ):
                reports.append(f"{path.name}:{number}: {line.strip()}")
    return reports


@dataclass(frozen=True)
class Change:
    """What one file would become, computed without touching it."""

    path: Path
    text: str
    newline: str
    counts: dict[str, int]
    changed: int


def plan_file(path: Path, version: str) -> Change:
    """Work out what a file would become, and write nothing."""
    original, newline = read_keeping_newlines(path)
    text = original
    counts: dict[str, int] = {}
    changed = 0
    for site in SITES:
        if path not in files_for(site):
            continue
        text, found, seen = substitute(text, site, version)
        counts[site.name] = found
        changed += sum(1 for held in seen if held != version)
    return Change(path=path, text=text, newline=newline, counts=counts, changed=changed)


def check_sites_are_populated(counts: dict[str, int]) -> None:
    """Fail when a declared site matched nothing anywhere.

    A pattern that stops matching is the dangerous failure, because it looks
    exactly like a site that is already correct: the run reports success and
    leaves the old number in place.
    """
    empty = [name for name, count in counts.items() if count == 0]
    if empty:
        raise BumpError(
            "no occurrence found for " + ", ".join(empty) + ". The file layout changed "
            "and SITES no longer describes it; fix the pattern rather than the file."
        )


def gate_on_the_changelog(version: str, args: argparse.Namespace) -> None:
    """Refuse a version the changelog does not describe.

    Before anything is written, not after. A gate that runs at the end of the
    loop leaves every file already rewritten when it refuses, which is the one
    state worse than either outcome it was choosing between.
    """
    if changelog_has(version) or args.allow_missing_changelog:
        return
    raise BumpError(
        f"CHANGELOG.md has no '## {version}' section. Write the release notes "
        "first, or pass --allow-missing-changelog to bump without them."
    )


def plan_all(version: str) -> list[Change]:
    """Work out what every file would become, in a stable order, writing nothing."""
    paths: list[Path] = []
    for site in SITES:
        for path in files_for(site):
            if path not in paths:
                paths.append(path)
    return [plan_file(path, version) for path in sorted(paths)]


def site_totals(changes: list[Change]) -> dict[str, int]:
    """How many occurrences each declared site matched across every file."""
    totals = {site.name: 0 for site in SITES}
    for change in changes:
        for name, count in change.counts.items():
            totals[name] += count
    return totals


def report_and_write(changes: list[Change], version: str, write: bool) -> int:
    """Report each file that changes, write when asked, and return the count.

    Writing happens only after every file has been planned and the sites have
    been validated, so a run that refuses leaves the checkout untouched. Doing
    it as it went left the tree half bumped whenever validation failed, which
    reports failure while quietly making the failure permanent, and that is the
    same defect as a gate placed after the loop rather than before it.
    """
    total = 0
    for change in changes:
        if not change.changed:
            continue
        total += change.changed
        verb = "set" if write else "would set"
        found = sum(change.counts.values())
        print(f"{verb} {change.path.name} to {version} ({change.changed} of {found})")
        if write:
            write_keeping_newlines(change.path, change.text, change.newline)
    return total


def report_check(current: str, total_changed: int) -> int:
    """Report whether every site agrees, and return the exit code."""
    for stray in stray_occurrences(current):
        print(f"note: a version other than {current} appears at {stray}")
    if total_changed:
        print(f"FAIL: {total_changed} occurrences disagree with {REFERENCE} at {current}")
        return 2
    print(f"every site states {current}")
    return 0


def report_bump(version: str, total_changed: int, dry_run: bool) -> int:
    """Report what the bump did or would do, and return the exit code."""
    if not total_changed:
        print(f"nothing to do; every site already states {version}")
        return 0
    if dry_run:
        print(f"{total_changed} occurrences would change; nothing was written")
        return 2
    print(f"{total_changed} occurrences set to {version}")
    for stray in stray_occurrences(version):
        print(f"note: a version other than {version} remains at {stray}")
    print(f"remaining by hand: the release tag, as git tag v{version}")
    return 0


def run(args: argparse.Namespace) -> int:
    """Do the work described by the command line and return the exit code."""
    current = current_version()
    version = current if args.check else target_version(current, args)
    write = not (args.check or args.dry_run)

    if not args.check:
        gate_on_the_changelog(version, args)

    # Plan, validate, then write. Every refusal in this program happens before a
    # single file is touched, so a run that fails leaves the checkout exactly as
    # it found it.
    changes = plan_all(version)
    check_sites_are_populated(site_totals(changes))
    total_changed = report_and_write(changes, version, write)

    if args.check:
        return report_check(current, total_changed)
    return report_bump(version, total_changed, args.dry_run)


def main() -> int:
    """Entry point. Returns the process exit code."""
    args = parse_arguments()
    try:
        return run(args)
    except BumpError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
