# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Maxim Masiutin
"""Tests for the detection logic that a reader cannot verify by inspection.

These cover the parts where a mistake is silent: a range that should have been
flagged and was not, a lockfile format that stopped matching, an advisory that
stops being attributed to its campaign. The self-test in the scanner proves the
whole chain end to end; these prove the pieces without a network."""

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
