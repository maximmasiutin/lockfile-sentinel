# Lockfile Sentinel 0.1.0
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Maxim Masiutin
"""Tests for the detection logic that a reader cannot verify by inspection.

These cover the parts where a mistake is silent: a range that should have been
flagged and was not, a lockfile format that stopped matching, an advisory that
stops being attributed to its campaign. The self-test in the scanner proves the
whole chain end to end; these prove the pieces without a network."""

# pylint: disable=protected-access
# The version-pattern table is private and is exactly what these cases pin, so
# reaching it directly is the test, not a shortcut around one.

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import lockfile_sentinel as ls  # noqa: E402


def test_exact_and_caret_ranges_resolve_to_a_poisoned_version() -> None:
    assert ls.range_may_resolve_to("6.0.0", "6.0.0")
    assert ls.range_may_resolve_to("^6.0.0", "6.0.0")
    assert ls.range_may_resolve_to("~6.0.0", "6.0.0")
    assert ls.range_may_resolve_to(">=5.0.0", "6.0.0")
    assert ls.range_may_resolve_to("*", "6.0.0")


def test_ranges_that_cannot_reach_the_version_are_not_flagged() -> None:
    assert not ls.range_may_resolve_to("^5.0.0", "6.0.0")
    assert not ls.range_may_resolve_to("~6.1.0", "6.0.0")
    assert not ls.range_may_resolve_to("workspace:*", "6.0.0")
    assert not ls.range_may_resolve_to("file:../local", "6.0.0")


def test_unsupported_range_forms_under_report_rather_than_guess() -> None:
    """A form the parser does not model must return False, never True.

    Reporting a range as unreachable when it is reachable loses a finding;
    reporting the reverse invents one. Under-reporting is the safe direction and
    is the documented limit."""
    assert not ls.range_may_resolve_to("6.x", "6.0.0")
    assert not ls.range_may_resolve_to("5.0.0 || 6.0.0", "6.0.0")


def test_lockfile_matching_finds_both_tarball_and_bare_token_forms(tmp_path: Path) -> None:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/keyv": {
                "version": "6.0.0",
                "resolved": "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz",
            },
        },
    }), encoding="utf-8")
    status = ls.RepoStatus(name="t", path=str(tmp_path))
    ls.scan_lockfile(lockfile, status)
    assert "6.0.0" in status.poisoned_versions.get("keyv", set())
    assert str(lockfile) in status.flagged_lockfiles


def test_a_clean_lockfile_produces_no_finding(tmp_path: Path) -> None:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"node_modules/keyv": {"version": "5.2.3"}},
    }), encoding="utf-8")
    status = ls.RepoStatus(name="t", path=str(tmp_path))
    ls.scan_lockfile(lockfile, status)
    assert not status.poisoned_versions
    assert "5.2.3" in status.present_versions.get("keyv", set())


def test_payload_artifacts_are_flagged_by_name(tmp_path: Path) -> None:
    artifact = tmp_path / "bun_environment.js"
    artifact.write_text("", encoding="utf-8")
    status = ls.RepoStatus(name="t", path=str(tmp_path))
    ls.scan_payload_filename(artifact, status)
    assert status.payload_files


def test_campaign_attribution_names_the_campaign_in_the_advisory_text() -> None:
    """Offline, so this exercises the matching rather than the network.

    lookup=False keeps campaign_of off the network and makes it read the built-in
    advisory note instead, which is the same matching path a fetched advisory
    takes."""
    label = ls.campaign_of("MAL-2026-11524", lookup=False)
    assert label is not None
    assert "Shai-Hulud" in label

    # An advisory with no campaign in its text must return None rather than
    # guessing, because the caller falls back to the advisory summary and a wrong
    # attribution is worse than none.
    assert ls.campaign_of("MAL-0000-00000", lookup=False) is None

    # The more specific patterns have to precede the generic Shai-Hulud one, or
    # every generation collapses into it and the remediation advice goes with it.
    order = [label for _, label in ls.CAMPAIGN_PATTERNS]
    generic = next(i for i, text in enumerate(order)
                   if text.startswith("Shai-Hulud, the self-propagating"))
    assert any("Mini Shai-Hulud" in text for text in order[:generic])
    assert any("SHA1-Hulud" in text for text in order[:generic])


def test_overlay_merges_into_the_builtin_table_and_rebuilds_patterns() -> None:
    """A name added by the overlay must also be searched for in lockfile text.

    Adding it to the table without rebuilding the regexes would leave it
    detectable in package.json ranges and invisible in lockfiles, which is the
    failure this rebuild exists to prevent."""
    added = ls.apply_overlay({"totally-made-up-package": ["9.9.9"]})
    assert added == 1
    assert "totally-made-up-package" in ls._VERSION_PATTERNS


def test_the_read_line_names_each_file_the_repository_was_opened_for() -> None:
    """The report otherwise never says which files were read.

    Paths are relative to the repository and slash-separated, so two workspaces
    carrying the same filename stay distinguishable and the same tree reports
    identically on Windows and on Linux."""
    root = Path("/t").resolve()
    status = ls.RepoStatus(name="t", path=str(root))
    status.has_npm = True
    status.read_files.extend([
        str(root / "package.json"),
        str(root / "package-lock.json"),
        str(root / "web" / "package.json"),
    ])
    assert ls._scanned_lines(status) == [
        "  read: package-lock.json, package.json, web/package.json"
    ]


def test_the_read_line_counts_what_it_had_to_leave_out() -> None:
    """A list cut short without saying so reads as the whole of what was opened,
    which is the same confident silence the coverage line exists to prevent."""
    root = Path("/t").resolve()
    status = ls.RepoStatus(name="t", path=str(root))
    total = ls._SCANNED_LINE_LIMIT + 3
    status.read_files.extend(
        str(root / f"w{index:03d}" / "package.json") for index in range(total)
    )
    line = ls._scanned_lines(status)[0]
    assert "and 3 more" in line
    assert line.count("package.json") == ls._SCANNED_LINE_LIMIT


def test_the_read_line_says_so_when_nothing_was_opened() -> None:
    """An empty list must not render as an empty enumeration, which reads as a
    formatting slip rather than as the fact that nothing was opened."""
    status = ls.RepoStatus(name="t", path="/t")
    assert "nothing" in ls._scanned_lines(status)[0]


def test_a_file_that_could_not_be_read_is_never_listed_as_read(tmp_path: Path) -> None:
    """A line that exists to expose an unread file must not print one as read.

    scan_package_json and scan_lockfile both return silently on a read error, and
    the walk records the name it found before either of them runs, so nothing
    downstream could tell a manifest that was parsed from one that was not."""
    repo = tmp_path / "app"
    repo.mkdir()
    good = repo / "package.json"
    good.write_text("{}", encoding="utf-8")
    # Not valid JSON, so the manifest contributes no dependency data at all.
    bad = repo / "web"
    bad.mkdir()
    (bad / "package.json").write_text("this is not json", encoding="utf-8")

    statuses, _index = ls.scan_root(tmp_path, include_node_modules=False)
    status = statuses[repo]
    assert status.read_files == [str(good)]
    assert status.unreadable_files == [str(bad / "package.json")]

    lines = ls._scanned_lines(status)
    assert lines[0] == "  read: package.json"
    assert lines[1] == "  found but unreadable: web/package.json"


def test_a_control_character_in_a_path_cannot_forge_a_report_line() -> None:
    """A directory name may hold a newline on Unix, and the tree being scanned is
    exactly the thing the scanner does not trust. Printed raw, a crafted name
    emits its own verdict line into the report."""
    root = Path("/t").resolve()
    status = ls.RepoStatus(name="t", path=str(root))
    status.read_files.append(str(root / "w\n  vulnerable: no" / "package.json"))
    status.payload_files.append("/t/\x1b[2Jbun_environment.js")

    line = ls._scanned_lines(status)[0]
    assert "\n" not in line
    assert "\\x0a" in line

    status.poisoned_versions["keyv"] = {"6.0.0"}
    report = ls.render_human([status], osv_bin=None, lookup=False)
    assert "\x1b" not in report
    assert "\\x1b" in report


def test_the_read_line_omits_a_lockfile_format_the_walk_never_opens(tmp_path: Path) -> None:
    """This is the whole point of the line.

    bun.lock is not in LOCKFILE_NAMES, so a repository pinned entirely by Bun is
    walked past and reported as not vulnerable. Before this line the report gave
    the reader nothing to tell that apart from a repository that was read and
    found clean, and the coverage line does not help: it speaks to whether the
    live database ran, not to whether a lockfile was ever opened."""
    repo = tmp_path / "bun-app"
    repo.mkdir()
    (repo / "package.json").write_text("{}", encoding="utf-8")
    (repo / "bun.lock").write_text("{}", encoding="utf-8")

    statuses, _index = ls.scan_root(tmp_path, include_node_modules=False)
    status = statuses[repo]
    assert status.has_npm is True
    assert status.lockfiles == []

    line = ls._scanned_lines(status)[0]
    assert "package.json" in line
    assert "bun.lock" not in line

    report = ls.render_human([status], osv_bin=None, lookup=False)
    assert line in report


def test_the_read_line_names_a_lockfile_the_walk_does_open(tmp_path: Path) -> None:
    """The negative case above proves nothing on its own: a line that never named
    a lockfile would pass it too."""
    repo = tmp_path / "npm-app"
    repo.mkdir()
    (repo / "package.json").write_text("{}", encoding="utf-8")
    (repo / "package-lock.json").write_text("{}", encoding="utf-8")

    statuses, _index = ls.scan_root(tmp_path, include_node_modules=False)
    line = ls._scanned_lines(statuses[repo])[0]
    assert "package-lock.json" in line
