# Lockfile Sentinel 0.1.0
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Maxim Masiutin
"""The version setter, tested against a throwaway tree rather than this one.

Every test here points bump_version at a temporary directory laid out like the
real project, because a test that exercised the real files would either rewrite
the checkout it runs in or be reduced to asserting that nothing happened.

The line-ending test is the one worth keeping. Path.write_text translates
newlines to os.linesep, so on Windows the first version of this program rewrote
nine LF files as CRLF while setting a number in one line of each. Nothing caught
it: .gitattributes normalises on commit, so `git diff` was empty and the pull
request showed one changed line per file.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring
# The name of a test that asserts one property is the description of it, and a
# docstring repeating the name in a sentence is noise a reader learns to skip.
# tests/test_regressions.py is the deliberate exception and documents every
# case, because each one names a defect that shipped.

# pylint: disable=wrong-import-position
# The programs under test sit beside this directory rather than in an installed
# package, so the path is extended before they can be imported.

import argparse
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import bump_version as bv  # noqa: E402

SCANNER = """\
\"\"\"A stand-in for the scanner.\"\"\"

# Lockfile Sentinel 0.1.0
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

__version__ = "0.1.0"
"""

README = """\
# Lockfile Sentinel 0.1.0

curl -O https://raw.githubusercontent.com/maximmasiutin/lockfile-sentinel/v0.1.0/lockfile_sentinel.py

The package keyv 6.0.0 is malicious, and that number is data rather than a release.
"""

CHANGELOG = """\
# Changelog

## 0.2.0

Second release.

## 0.1.0

First release.
"""


def write(path: Path, text: str) -> None:
    """Write text with LF endings, whatever platform the test runs on."""
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


@pytest.fixture(name="tree")
def fixture_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A minimal project laid out the way bump_version expects to find one."""
    write(tmp_path / "lockfile_sentinel.py", SCANNER)
    write(tmp_path / "README.md", README)
    write(tmp_path / "CHANGELOG.md", CHANGELOG)
    (tmp_path / "tests").mkdir()
    monkeypatch.setattr(bv, "ROOT", tmp_path)
    return tmp_path


def arguments(**overrides: object) -> argparse.Namespace:
    """A parsed command line with every field the program reads."""
    defaults: dict[str, object] = {
        "new_version": None,
        "major": False,
        "minor": False,
        "patch": False,
        "check": False,
        "dry_run": False,
        "allow_missing_changelog": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def test_a_bump_sets_every_site_it_knows_about(tree: Path) -> None:
    assert bv.run(arguments(new_version="0.2.0")) == 0
    scanner = (tree / "lockfile_sentinel.py").read_text(encoding="utf-8")
    readme = (tree / "README.md").read_text(encoding="utf-8")
    assert '__version__ = "0.2.0"' in scanner
    assert "# Lockfile Sentinel 0.2.0" in scanner
    assert "# Lockfile Sentinel 0.2.0" in readme
    assert "/v0.2.0/" in readme


def test_a_version_that_is_data_is_left_alone(tree: Path) -> None:
    """The subject matter here is package versions, and they are not releases."""
    bv.run(arguments(new_version="0.2.0"))
    assert "keyv 6.0.0" in (tree / "README.md").read_text(encoding="utf-8")


def test_line_endings_survive_a_bump(tree: Path) -> None:
    bv.run(arguments(new_version="0.2.0"))
    for name in ("lockfile_sentinel.py", "README.md"):
        assert b"\r\n" not in (tree / name).read_bytes(), f"{name} was rewritten as CRLF"


def test_crlf_is_preserved_where_that_is_what_the_file_uses(tree: Path) -> None:
    """Preserving means preserving, not converting everything to LF instead."""
    path = tree / "README.md"
    with path.open("w", encoding="utf-8", newline="\r\n") as handle:
        handle.write(README)
    bv.run(arguments(new_version="0.2.0"))
    raw = path.read_bytes()
    assert b"\r\n" in raw
    # Nothing left once the CRLF pairs are removed means no line ended in a bare LF.
    assert b"\n" not in raw.replace(b"\r\n", b"")


def test_the_changelog_gate_refuses_a_version_with_no_section(tree: Path) -> None:
    with pytest.raises(bv.BumpError, match="CHANGELOG"):
        bv.run(arguments(new_version="9.9.9"))
    assert '__version__ = "0.1.0"' in (tree / "lockfile_sentinel.py").read_text(encoding="utf-8")


def test_the_gate_can_be_overridden_deliberately(tree: Path) -> None:
    assert bv.run(arguments(new_version="9.9.9", allow_missing_changelog=True)) == 0
    assert '__version__ = "9.9.9"' in (tree / "lockfile_sentinel.py").read_text(encoding="utf-8")


def test_a_dry_run_writes_nothing_and_reports_pending(tree: Path) -> None:
    assert bv.run(arguments(new_version="0.2.0", dry_run=True)) == 2
    assert '__version__ = "0.1.0"' in (tree / "lockfile_sentinel.py").read_text(encoding="utf-8")


def test_check_passes_when_every_site_agrees(tree: Path) -> None:
    before = (tree / "README.md").read_bytes()
    assert bv.run(arguments(check=True)) == 0
    assert (tree / "README.md").read_bytes() == before, "--check wrote to a file"


def test_check_fails_when_one_file_disagrees(tree: Path) -> None:
    write(tree / "README.md", README.replace("# Lockfile Sentinel 0.1.0", "# Lockfile Sentinel 0.0.9"))
    assert bv.run(arguments(check=True)) == 2


def test_a_site_that_matches_nothing_is_an_error(tree: Path) -> None:
    """The failure this program exists to prevent, applied to itself.

    A pattern that has stopped matching looks exactly like a project that is
    already correct, so it has to be an error rather than a quiet success.
    """
    (tree / "README.md").unlink()
    with pytest.raises(bv.BumpError, match="no occurrence found"):
        bv.run(arguments(new_version="0.2.0"))


def test_a_header_inside_a_string_literal_is_not_a_header(tree: Path) -> None:
    """This file is the fixture that proved it, so the case is not hypothetical.

    A test for a version setter holds a miniature project as string literals,
    headers included. Treating those as headers bumps the fake header while the
    fake `__version__` beside it stays put, because that site does not read the
    tests directory, and the fixture comes out stating two versions at once. The
    suite then fails on the next run, so the documented release command breaks
    the tests it shipped with. A round trip hides it; only a one-way bump shows
    it.
    """
    fixture = tree / "tests" / "test_fixture_holder.py"
    fixture.write_text(
        "# Lockfile Sentinel 0.1.0\n"
        "from __future__ import annotations\n"
        'SAMPLE = """\n# Lockfile Sentinel 0.1.0\n__version__ = "0.1.0"\n"""\n',
        encoding="utf-8",
    )

    bv.run(arguments(new_version="0.2.0"))

    text = fixture.read_text(encoding="utf-8")
    assert text.startswith("# Lockfile Sentinel 0.2.0"), "the real header was not set"
    assert '\n# Lockfile Sentinel 0.1.0\n__version__ = "0.1.0"\n' in text, (
        "the header inside the string literal was rewritten and now disagrees with "
        "the __version__ beside it"
    )


def test_a_refusal_leaves_every_file_exactly_as_it_was(tree: Path) -> None:
    """Reporting failure while making the failure permanent is the worst outcome.

    The site check ran after the writing loop, so a run that refused had already
    bumped every file whose site still matched. The refusal is real and the tree
    is half bumped, which is the state neither branch of the decision wanted."""
    before = {path: path.read_bytes() for path in (
        tree / "lockfile_sentinel.py", tree / "README.md", tree / "CHANGELOG.md")}
    (tree / "README.md").unlink()

    with pytest.raises(bv.BumpError, match="no occurrence found"):
        bv.run(arguments(new_version="0.2.0"))

    assert (tree / "lockfile_sentinel.py").read_bytes() == before[tree / "lockfile_sentinel.py"]


def test_steps_move_one_component_and_zero_the_rest() -> None:
    assert bv.stepped("1.2.3", arguments(major=True)) == "2.0.0"
    assert bv.stepped("1.2.3", arguments(minor=True)) == "1.3.0"
    assert bv.stepped("1.2.3", arguments(patch=True)) == "1.2.4"


def test_a_version_that_is_not_semver_is_refused() -> None:
    with pytest.raises(bv.BumpError, match="major.minor.patch"):
        bv.target_version("0.1.0", arguments(new_version="0.2"))


def test_naming_a_version_and_asking_for_a_step_is_refused() -> None:
    with pytest.raises(bv.BumpError, match="not both"):
        bv.target_version("0.1.0", arguments(new_version="0.2.0", minor=True))
