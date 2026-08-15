# Lockfile Sentinel 0.2.0
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

# pylint: disable=wrong-import-position  # the path insert above must run first
import lockfile_sentinel as ls  # noqa: E402


def test_exact_and_caret_ranges_resolve_to_a_poisoned_version() -> None:
    """The range forms npm writes must all reach the version they cover."""
    assert ls.range_may_resolve_to("6.0.0", "6.0.0")
    assert ls.range_may_resolve_to("^6.0.0", "6.0.0")
    assert ls.range_may_resolve_to("~6.0.0", "6.0.0")
    assert ls.range_may_resolve_to(">=5.0.0", "6.0.0")
    assert ls.range_may_resolve_to("*", "6.0.0")


def test_ranges_that_cannot_reach_the_version_are_not_flagged() -> None:
    """A range that excludes the version, and the forms that install no
    registry package at all, must not produce a finding."""
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
    """The two shapes a resolved version takes in lockfile text, the tarball
    URL and the bare name@version token, must both be matched."""
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
    """A watched package at an unaffected version is present, not poisoned."""
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
    """A known payload filename is a finding wherever in the tree it sits."""
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


def test_a_comma_in_a_directory_name_cannot_forge_a_second_entry() -> None:
    """The read line is comma-separated and a comma is legal in a name.

    One file under a directory called "pkg, fake" would otherwise print as two
    entries, so a single unread manifest could pose as two read ones. Escaping
    only the non-printable characters leaves that open, because a comma is
    perfectly printable."""
    root = Path("/t").resolve()
    status = ls.RepoStatus(name="t", path=str(root))
    status.read_files.append(str(root / "pkg, fake" / "package.json"))

    line = ls._scanned_lines(status)[0]
    assert line == "  read: pkg\\x2c fake/package.json"
    assert line.count(",") == 0


def test_an_escape_marker_in_a_name_is_escaped_before_it_can_pose_as_one() -> None:
    """A file genuinely named with a backslash must not render as the escape
    sequence for a character it does not contain, or the escaping meant to
    remove ambiguity would have introduced it."""
    assert ls._display("a\\x0ab") == "a\\\\x0ab"
    assert ls._display("a\nb") == "a\\x0ab"


def test_a_non_bmp_character_gets_an_escape_that_can_be_read_back() -> None:
    """A four-digit \\u escape cannot hold a code point above 0xFFFF, so the
    width has to widen rather than overflow into an unparseable run."""
    # U+E0001, a language tag character: non-BMP and not printable.
    assert ls._display("\U000e0001") == "\\U000e0001"


def test_a_repository_name_cannot_forge_a_report_line_either() -> None:
    """The label is a directory name, so it is chosen by whoever wrote the tree
    exactly as the paths are. Escaping the paths and printing the heading raw
    would leave the vector open at the one line that opens every entry."""
    status = ls.RepoStatus(name="app\n  vulnerable: no\n[other]", path="/t")
    status.has_npm = True
    status.poisoned_versions["keyv"] = {"6.0.0"}

    report = ls.render_human([status], osv_bin=None, lookup=False)
    assert "\n  vulnerable: no\n" not in report
    assert "\\x0a" in report


def test_the_read_line_omits_a_lockfile_format_the_walk_never_opens(tmp_path: Path) -> None:
    """This is the whole point of the line.

    Cargo.lock is not in LOCKFILE_NAMES and never will be, being another
    ecosystem's pin file, so a repository carrying one beside its package.json
    shows only the manifest as read. When this case was written it used
    bun.lock, which was then the gap this line existed to expose; that gap is
    closed and bun.lock now has its own positive cases below, so the foreign
    format here is one that is outside the scanner's subject by design rather
    than by omission."""
    repo = tmp_path / "mixed-app"
    repo.mkdir()
    (repo / "package.json").write_text("{}", encoding="utf-8")
    (repo / "Cargo.lock").write_text('[[package]]\nname = "serde"\n', encoding="utf-8")

    statuses, _index = ls.scan_root(tmp_path, include_node_modules=False)
    status = statuses[repo]
    assert status.has_npm is True
    assert status.lockfiles == []

    line = ls._scanned_lines(status)[0]
    assert "package.json" in line
    assert "Cargo.lock" not in line

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


def test_every_scanned_lockfile_also_marks_npm_tooling() -> None:
    """The original coverage gap was a name present in one hand-kept list and
    absent from the other, so the marker set is derived from the lockfile set
    rather than restated. This pins the derivation against a later edit that
    reverts either side to a literal."""
    assert ls.NPM_MARKER_FILES == ls.LOCKFILE_NAMES | {"package.json"}


# A real bun.lock's shape: JSONC with trailing commas, resolutions as
# "name@version" strings inside per-package tuples. The trailing commas are
# deliberate: they keep the fixture true to what bun writes, and they pin the
# fact that the text pass alone carries this format, since a strict JSON
# parser cannot accept this document if some later change tries to hand it
# one. The JSON pass is dispatched on the .json suffix and never sees this
# file at all.
BUN_LOCK = """{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "dependencies": { "keyv": "^6.0.0" }, },
  },
  "packages": {
    "keyv": ["keyv@6.0.0", "", { "dependencies": {} }, "sha512-fixture"],
  },
}
"""


def test_a_bun_lockfile_pinning_a_poisoned_version_is_found(tmp_path: Path) -> None:
    """The campaign's own payload marker is bun_environment.js, so the scanner
    found the Bun payload by filename while walking past Bun's lockfile. The
    text pass is what carries this format: the JSON pass is dispatched on the
    .json suffix and never sees bun.lock, and the resolution strings carry the
    name@version tokens the patterns match."""
    lockfile = tmp_path / "bun.lock"
    lockfile.write_text(BUN_LOCK, encoding="utf-8")
    status = ls.RepoStatus(name="t", path=str(tmp_path))
    assert ls.scan_lockfile(lockfile, status) is True
    assert "6.0.0" in status.poisoned_versions.get("keyv", set())
    assert str(lockfile) in status.flagged_lockfiles


def test_a_bun_repository_is_walked_scanned_and_reported_as_npm(tmp_path: Path) -> None:
    """End to end through the walk: a repository whose only pin file is bun.lock
    used to be reported npm: no outright, with any payload artifact charged to
    the summary rather than to the repository's own entry."""
    repo = tmp_path / "bun-app"
    repo.mkdir()
    (repo / "bun.lock").write_text(BUN_LOCK, encoding="utf-8")

    statuses, index = ls.scan_root(tmp_path, include_node_modules=False)
    status = statuses[repo]
    assert status.has_npm is True
    assert status.lockfiles == [str(repo / "bun.lock")]
    assert any("bun.lock" in key for key in index)
    assert "6.0.0" in status.poisoned_versions.get("keyv", set())

    line = ls._scanned_lines(status)[0]
    assert "bun.lock" in line


def test_a_commented_out_bun_entry_is_not_reported_as_a_resolved_pin(tmp_path: Path) -> None:
    """bun.lock is JSONC and admits comments, and the token patterns match raw
    text, so a commented-out poisoned entry produced vulnerable: YES for a pin
    the effective tree does not contain. A comment installs nothing, so
    stripping it loses no real pin and opens no evasion channel."""
    lockfile = tmp_path / "bun.lock"
    lockfile.write_text(
        '{\n'
        '  "lockfileVersion": 1,\n'
        '  // "keyv": ["keyv@6.0.0", "", {}, "sha512-dead"],\n'
        '  /* "cacheable": ["cacheable@2.5.1", "", {}, "sha512-dead"], */\n'
        '  "packages": {\n'
        '    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-live"],\n'
        '  },\n'
        '}\n',
        encoding="utf-8",
    )
    status = ls.RepoStatus(name="t", path=str(tmp_path))
    assert ls.scan_lockfile(lockfile, status) is True
    assert not status.poisoned_versions


def test_comment_markers_inside_strings_do_not_end_the_scan_of_a_line() -> None:
    """Every registry URL carries the line comment marker inside a string, so a
    stripper without string awareness would truncate the exact lines the
    tarball patterns match. The live pin beside the comments must survive."""
    text = (
        '{\n'
        '  // dead: "keyv@6.0.0"\n'
        '  "resolved": "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz",\n'
        '  "escaped": "a\\"quote//not-a-comment",\n'
        '}\n'
    )
    stripped = ls._strip_jsonc_comments(text)
    assert "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz" in stripped
    assert 'dead: "keyv@6.0.0"' not in stripped
    assert "quote//not-a-comment" in stripped


def test_a_live_bun_pin_still_matches_after_the_comments_go(tmp_path: Path) -> None:
    """The negative case proves nothing alone: a stripper that emptied the file
    would pass it too."""
    lockfile = tmp_path / "bun.lock"
    lockfile.write_text(
        '{\n'
        '  "lockfileVersion": 1,\n'
        '  // a comment above a live entry\n'
        '  "packages": {\n'
        '    "keyv": ["keyv@6.0.0", "", {}, "sha512-live"],\n'
        '  },\n'
        '}\n',
        encoding="utf-8",
    )
    status = ls.RepoStatus(name="t", path=str(tmp_path))
    ls.scan_lockfile(lockfile, status)
    assert "6.0.0" in status.poisoned_versions.get("keyv", set())


def test_a_commented_out_yarn_entry_is_not_reported_as_a_resolved_pin(
    tmp_path: Path,
) -> None:
    """yarn.lock takes `#` comments, and the same defect fixed for bun applies
    to it unchanged: a commented-out poisoned descriptor read as a resolved
    pin the effective tree does not contain."""
    lockfile = tmp_path / "yarn.lock"
    lockfile.write_text(
        "# yarn lockfile v1\n"
        '# keyv@6.0.0:\n'
        '#   resolved "https://registry.yarnpkg.com/keyv/-/keyv-6.0.0.tgz#dead"\n'
        "\n"
        'left-pad@^1.3.0:\n'
        '  version "1.3.0"\n'
        '  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#live"\n',
        encoding="utf-8",
    )
    status = ls.RepoStatus(name="t", path=str(tmp_path))
    assert ls.scan_lockfile(lockfile, status) is True
    assert not status.poisoned_versions


def test_a_commented_out_pnpm_entry_is_not_reported_as_a_resolved_pin(
    tmp_path: Path,
) -> None:
    """pnpm-lock.yaml is the other `#` format, fixed in the same pass."""
    lockfile = tmp_path / "pnpm-lock.yaml"
    lockfile.write_text(
        "lockfileVersion: '9.0'\n"
        "packages:\n"
        "  # keyv@6.0.0:\n"
        "  #   resolution: {integrity: sha512-dead}\n"
        "  left-pad@1.3.0:\n"
        "    resolution: {integrity: sha512-live}\n",
        encoding="utf-8",
    )
    status = ls.RepoStatus(name="t", path=str(tmp_path))
    assert ls.scan_lockfile(lockfile, status) is True
    assert not status.poisoned_versions


def test_a_hash_inside_a_tarball_url_does_not_start_a_comment() -> None:
    """The reason this stripper is not a split on `#`. Every yarn resolved
    line ends in `#<sha>`, and a marker with a non-space character before it
    is part of the token; cutting there would truncate the exact lines the
    tarball patterns match. A `#` inside either quote style is data too."""
    text = (
        "# a real comment\n"
        '  resolved "https://registry.yarnpkg.com/keyv/-/keyv-6.0.0.tgz#abc123"\n'
        "  single: 'not # a comment'\n"
        '  double: "also # not one"\n'
    )
    stripped = ls._strip_hash_comments(text)
    assert "keyv-6.0.0.tgz#abc123" in stripped
    assert "a real comment" not in stripped
    assert "not # a comment" in stripped
    assert "also # not one" in stripped


def test_a_live_yarn_pin_still_matches_after_the_comments_go(tmp_path: Path) -> None:
    """The negative cases prove nothing alone: a stripper that emptied the
    file would pass all of them."""
    lockfile = tmp_path / "yarn.lock"
    lockfile.write_text(
        "# yarn lockfile v1\n"
        "\n"
        'keyv@^6.0.0:\n'
        '  version "6.0.0"\n'
        '  resolved "https://registry.yarnpkg.com/keyv/-/keyv-6.0.0.tgz#live"\n',
        encoding="utf-8",
    )
    status = ls.RepoStatus(name="t", path=str(tmp_path))
    ls.scan_lockfile(lockfile, status)
    assert "6.0.0" in status.poisoned_versions.get("keyv", set())


def test_stripping_a_comment_never_joins_two_lines() -> None:
    """A stripped comment leaves its newline behind. Swallowing it would join
    a package name on one line to a version on the next and manufacture a
    coordinate neither line carried."""
    stripped = ls._strip_hash_comments("keyv@  # comment\n6.0.0\n")
    assert stripped.count("\n") == 2
    assert "keyv@6.0.0" not in stripped


def test_an_apostrophe_in_a_bare_scalar_does_not_shield_the_comment() -> None:
    """A quote opens a string only where a value may start. Read as an opening
    quote, a mid-word apostrophe makes the rest of its line string content and
    the comment behind it survives, which is the false pin this strip removes.
    Both formats reach here: a hand-written note is where an apostrophe in a
    bare scalar comes from, and a hand-written note is what carries a
    commented-out entry in the first place."""
    text = "  note: don't reinstate # keyv@6.0.0\n"
    assert "keyv@6.0.0" not in ls._strip_hash_comments(text)


def test_punctuation_inside_a_bare_scalar_does_not_open_a_string() -> None:
    """`-` and `:` indicate only when whitespace follows them, and that
    whitespace already admits the quote, so a quote directly behind either is
    scalar content. Read as an opening quote it shields the comment behind it
    and the commented-out pin survives, which is this strip's own defect."""
    for text in (
        "  note: pre-'90s # keyv@6.0.0\n",
        "  note: ratio 3:'1 # keyv@6.0.0\n",
    ):
        assert "keyv@6.0.0" not in ls._strip_hash_comments(text), text


def test_an_unclosed_quote_after_whitespace_is_an_apostrophe() -> None:
    """Whitespace alone does not make a value start: mid plain scalar an
    apostrophe follows a space too, and a scalar opened there never closes on
    its line. An unclosed quote is therefore an apostrophe, not an opener,
    and the comment behind it is still stripped."""
    for text in (
        "  note: remember the '90s # keyv@6.0.0\n",
        "  note: 'til next time # keyv@6.0.0\n",
    ):
        assert "keyv@6.0.0" not in ls._strip_hash_comments(text), text


def test_an_apostrophe_before_a_quoted_value_still_opens_that_value() -> None:
    """The narrowing must not cost the quoting it exists beside: a quote that
    does start a value keeps protecting the `#` inside it."""
    text = "  key: 'keyv@6.0.0 # inside a value'\n"
    assert "keyv@6.0.0 # inside a value" in ls._strip_hash_comments(text)


def test_a_shrinkwrap_entry_without_a_resolved_url_is_still_caught(tmp_path: Path) -> None:
    """npm-shrinkwrap.json is package-lock.json under another name, so it must
    take the structural pass too: an entry pinning a version with no resolved
    URL is invisible to the text patterns, and a scanner that gave shrinkwrap
    only the text pass would miss exactly the pin the JSON pass exists for."""
    repo = tmp_path / "shrinkwrap-app"
    repo.mkdir()
    lockfile = repo / "npm-shrinkwrap.json"
    lockfile.write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"node_modules/keyv": {"version": "6.0.0"}},
    }), encoding="utf-8")

    # Through the walk rather than by calling scan_lockfile directly, because
    # scan_lockfile reads whatever path it is handed and never consults
    # LOCKFILE_NAMES: a direct call would stay green with the name dropped
    # from the set, which is the exact regression this case exists to catch.
    statuses, _index = ls.scan_root(tmp_path, include_node_modules=False)
    status = statuses[repo]
    assert status.has_npm is True
    assert status.lockfiles == [str(lockfile)]
    assert "6.0.0" in status.poisoned_versions.get("keyv", set())
