# Lockfile Sentinel 0.1.0
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Maxim Masiutin
"""Tests for the scheduling details that fail silently rather than loudly.

A scheduled job that was installed but never runs looks exactly like one that
runs and finds nothing, so the cases here are the ones where a wrong string
produces no error at all: an unquoted path that truncates a cron command, a
system-crontab user field in a user crontab, and a path variable that does not
substitute."""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import schedule_tasks as st  # noqa: E402


def test_envify_substitutes_only_when_the_variable_covers_the_path() -> None:
    os.environ["LS_TEST_ROOT"] = str(Path("/opt/repos"))
    covered = str(Path("/opt/repos") / "lockfile-sentinel" / "update_scanners.py")
    assert st.envify(covered, "LS_TEST_ROOT").startswith("%LS_TEST_ROOT%")

    # Outside the variable's directory, so the absolute path must survive intact.
    outside = str(Path("/usr/bin/python3"))
    assert st.envify(outside, "LS_TEST_ROOT") == outside


def test_envify_falls_back_to_the_absolute_path_rather_than_a_dangling_variable() -> None:
    """An unset variable must not produce %NAME%, which would expand to nothing.

    A task pointing at a variable that resolves to nothing fails at run time with
    a path that looks almost right, which is the failure this fallback avoids."""
    os.environ.pop("LS_TEST_UNSET", None)
    path = str(Path("/opt/repos/tool.py"))
    assert st.envify(path, "LS_TEST_UNSET") == path
    assert st.envify(path, "") == path


def test_cron_line_quotes_every_path_it_emits(tmp_path: Path) -> None:
    """A space in the cache path used to truncate the command silently."""
    os.environ["LOCKFILE_SENTINEL_CACHE"] = str(tmp_path / "with space")
    line = st.cron_line(st.JOBS["trivy-db"], 5, "root")
    assert "'" in line
    assert "with space" in line
    # The unquoted form would leave a bare directory name in the redirect.
    assert " >> with space" not in line


def test_user_crontab_form_omits_the_user_field() -> None:
    """crontab(5) puts a user field in a system crontab and none in a user one.

    Emitting the system form into a user crontab makes cron try to run the
    username as the command, so every job fails while the install reports
    success."""
    system_line = st.cron_line(st.JOBS["trivy-db"], 0, "root")
    user_line = st.cron_line(st.JOBS["trivy-db"], 0, "")
    fields = system_line.split()
    assert fields[5] == "root"
    assert user_line.split()[5] != "root"
    assert user_line.startswith(" ".join(fields[:5]))


def test_the_tool_resolver_ignores_a_decoy_that_is_first_on_path(
        tmp_path: Path, monkeypatch) -> None:
    """A schtasks.exe planted ahead of System32 on PATH must not be the answer.

    This is the assertion the previous shutil.which implementation failed: which
    searches PATH, so the decoy is exactly what it returned, and this file
    registers scheduled tasks, usually elevated. Fabricated SystemRoot so the
    test pins the behaviour on every platform."""
    system32 = tmp_path / "windows" / "System32"
    system32.mkdir(parents=True)
    (system32 / "schtasks.exe").write_bytes(b"")
    decoy = tmp_path / "planted"
    decoy.mkdir()
    (decoy / "schtasks.exe").write_bytes(b"")
    monkeypatch.setenv("SystemRoot", str(tmp_path / "windows"))
    monkeypatch.setenv("PATH", str(decoy) + os.pathsep + os.environ.get("PATH", ""))
    assert st.resolve_system_tool("schtasks.exe") == str(system32 / "schtasks.exe")


def test_the_tool_resolver_falls_back_to_the_bare_name_not_to_path(
        tmp_path: Path, monkeypatch) -> None:
    """When System32 lacks the file, the answer is the bare name, decoy and all.

    Falling back to a PATH search would be the hijack with an extra step, so the
    decoy stays planted to pin that PATH is not consulted. The bare name also
    keeps Unix tools such as crontab working, resolved by the OS at exec."""
    monkeypatch.setenv("SystemRoot", str(tmp_path / "windows"))
    decoy = tmp_path / "planted"
    decoy.mkdir()
    (decoy / "schtasks.exe").write_bytes(b"")
    monkeypatch.setenv("PATH", str(decoy) + os.pathsep + os.environ.get("PATH", ""))
    assert st.resolve_system_tool("schtasks.exe") == "schtasks.exe"


def test_the_tool_resolver_returns_the_bare_name_when_systemroot_is_unset(
        monkeypatch) -> None:
    """No SystemRoot, no lookup: a hardcoded default would be relative on Unix,
    so a planted `./C:\\Windows/System32/crontab` could win."""
    monkeypatch.delenv("SystemRoot", raising=False)
    assert st.resolve_system_tool("crontab") == "crontab"
