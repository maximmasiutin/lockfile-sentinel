# Lockfile Sentinel 0.1.0
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Maxim Masiutin
"""Every source file states the program, the licence and the version it belongs to.

A file here is meant to be copied out and run on its own, so the header is the
only thing an orphaned copy carries with it: without the version it cannot be
compared against a release, and without the notice it cannot be passed on under
the terms it was given under. That makes the header content rather than
decoration, and content that is repeated in seven files is content that drifts.

The version is deliberately not imported from one module into the others, since
that would tie a standalone copy back to a checkout it may not have. The cost of
that choice is duplication, and this is what pays it: one test that reads every
file and refuses any that disagrees, so a release bump that misses a file fails
here rather than shipping a file that misstates its own version."""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import lockfile_sentinel as ls  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
PROGRAMS = ("lockfile_sentinel.py", "update_scanners.py", "schedule_tasks.py")

NAME_LINE = re.compile(r"^# Lockfile Sentinel (\d+\.\d+\.\d+)$", re.MULTILINE)
SPDX_LINE = "# SPDX-License-Identifier: GPL-3.0-only"
COPYRIGHT_LINE = "# Copyright (c) 2026 Maxim Masiutin"
VERSION_ASSIGNMENT = re.compile(r'^__version__ = "(\d+\.\d+\.\d+)"$', re.MULTILINE)


def header_of(path: Path) -> str:
    """Everything above the first import, which is where a header has to be.

    A fixed number of characters will not do: the scanner opens with a module
    docstring long enough to push its own notice past any window short enough to
    be meaningful, and a window long enough to reach it would accept a notice
    buried in the body. The first import is the real boundary, since nothing
    after it is a header by any reading, and every file here opens with
    `from __future__ import annotations`.
    """
    text = path.read_text(encoding="utf-8")
    cut = text.find("\nfrom __future__ import")
    assert cut != -1, f"{path.name} has no __future__ import to bound its header"
    return text[:cut]


def python_files() -> list[Path]:
    """Every Python file that ships, tests included, in a stable order."""
    found = sorted(ROOT.glob("*.py")) + sorted((ROOT / "tests").glob("*.py"))
    # A file that is not found is a file that is not checked, and this test is
    # worth nothing if the glob quietly returns an empty list.
    assert len(found) >= len(PROGRAMS) + 1
    return found


def test_every_file_names_the_program_the_licence_and_the_holder() -> None:
    for path in python_files():
        head = header_of(path)
        assert NAME_LINE.search(head), f"{path.name} does not name the program and its version"
        assert SPDX_LINE in head, f"{path.name} has no SPDX licence identifier"
        assert COPYRIGHT_LINE in head, f"{path.name} has no copyright notice"


def test_every_header_states_the_same_version_as_the_scanner() -> None:
    for path in python_files():
        match = NAME_LINE.search(header_of(path))
        assert match is not None
        assert match.group(1) == ls.__version__, (
            f"{path.name} says {match.group(1)} where the scanner says {ls.__version__}"
        )


def test_each_program_reports_the_version_its_header_claims() -> None:
    """A header is prose; __version__ is what --version prints. They must agree.

    Checking only the header would let a program report one version while
    describing another, which is the failure that makes a version worthless: the
    number a user quotes in a bug report would not be the number in the file.
    """
    for name in PROGRAMS:
        text = (ROOT / name).read_text(encoding="utf-8")
        declared = VERSION_ASSIGNMENT.search(text)
        assert declared is not None, f"{name} defines no __version__"
        assert declared.group(1) == ls.__version__
