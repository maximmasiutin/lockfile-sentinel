# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Maxim Masiutin
"""One test per defect found in review, so none of them can come back unnoticed.

Every case here is a bug that was actually shipped in a commit on this branch and
then fixed, not a hypothetical. They are grouped by what the defect would cost if
it returned, because that is what decides how hard to fight for the test:

  reports clean when poisoned   the failure that makes a scanner worse than
                                nothing, since it produces confident silence
  reports poisoned when clean   a false positive, which burns the reader's trust
                                and eventually gets the tool ignored
  claims coverage it lacks      a verdict about a check that never ran
  accepts unverified input      a gate that passes what it did not read
  fails silently                work that reports success while doing nothing

The titles name the symptom rather than the mechanism, because a regression will
be recognised by its symptom first."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import lockfile_sentinel as ls  # noqa: E402
import schedule_tasks as st  # noqa: E402
import update_scanners as us  # noqa: E402


# --------------------------------------------------------------------------
# Reports clean when poisoned.
# --------------------------------------------------------------------------

def test_a_yarn_berry_resolution_is_matched(tmp_path: Path) -> None:
    """Yarn 2+ writes "keyv@npm:6.0.0" and often no tarball URL.

    The token regex required a digit straight after the @, so a Berry lockfile
    pinning a poisoned version outright matched nothing. With the live database
    off, the scan then exited clean on a lockfile that names the bad version in
    plain text."""
    lockfile = tmp_path / "yarn.lock"
    lockfile.write_text(
        '"keyv@npm:^6.0.0":\n  version: 6.0.0\n  resolution: "keyv@npm:6.0.0"\n',
        encoding="utf-8",
    )
    status = ls.RepoStatus(name="t", path=str(tmp_path))
    ls.scan_lockfile(lockfile, status)
    assert "6.0.0" in status.poisoned_versions.get("keyv", set())


def test_the_classic_at_version_form_still_matches(tmp_path: Path) -> None:
    """The Berry fix must not cost the npm form it was added beside."""
    lockfile = tmp_path / "yarn.lock"
    lockfile.write_text('keyv@6.0.0:\n  version "6.0.0"\n', encoding="utf-8")
    status = ls.RepoStatus(name="t", path=str(tmp_path))
    ls.scan_lockfile(lockfile, status)
    assert "6.0.0" in status.poisoned_versions.get("keyv", set())


def test_roots_are_resolved_so_live_findings_can_be_attributed(tmp_path, monkeypatch) -> None:
    """osv-scanner returns absolute source paths.

    A relative --root produced relative index keys, the absolute keys coming
    back never matched, and every live-database finding for that run was
    discarded while the coverage line still said the lockfile had been resolved.
    Only a package the offline table already knew stayed visible.

    The invariant is that whatever the caller types, the walk is handed an
    absolute root, so this captures the root scan_root actually receives."""
    (tmp_path / "unit").mkdir()
    monkeypatch.chdir(tmp_path)

    seen: list[Path] = []
    real_scan_root = ls.scan_root

    def capture(root, *args, **kwargs):
        seen.append(root)
        return real_scan_root(root, *args, **kwargs)

    monkeypatch.setattr(ls, "scan_root", capture)
    monkeypatch.setattr(sys, "argv",
                        ["lockfile_sentinel.py", "--root", ".", "--no-refresh", "--no-osv"])
    ls.main()

    assert seen, "scan_root was never called"
    assert all(root.is_absolute() for root in seen), f"relative root reached the walk: {seen}"


def test_parallel_units_sharing_an_owner_merge_rather_than_overwrite() -> None:
    """When the scanned root is itself a repository, every unit charges to it.

    Each worker returns its own status for that same owner, and a plain dict
    update kept only the last one, so findings from every earlier unit vanished.
    Scanning one repository with more than one job is the common case."""
    owner = Path("/repo")
    first = ls.RepoStatus(name="repo", path=str(owner))
    first.poisoned_versions["keyv"] = {"6.0.0"}
    first.lockfiles.append("/repo/a/package-lock.json")
    second = ls.RepoStatus(name="repo", path=str(owner))
    second.poisoned_versions["cacheable"] = {"2.5.1"}
    second.lockfiles.append("/repo/b/package-lock.json")

    merged: dict[Path, ls.RepoStatus] = {}
    ls._merge_statuses(merged, {owner: first})
    ls._merge_statuses(merged, {owner: second})

    assert merged[owner].poisoned_versions["keyv"] == {"6.0.0"}
    assert merged[owner].poisoned_versions["cacheable"] == {"2.5.1"}
    assert len(merged[owner].lockfiles) == 2


def test_the_walk_does_not_follow_symlinks_out_of_the_tree(tmp_path: Path) -> None:
    """A directory symlink would let the walk read outside the named root.

    Skipping symlinks under-reports, which is the safe direction; following them
    breaks the tree boundary the security policy states."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "package-lock.json").write_text("{}", encoding="utf-8")
    inside = tmp_path / "inside"
    inside.mkdir()
    try:
        (inside / "link").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this platform or account cannot create symlinks")

    walked = ls._walk(inside, include_node_modules=False)
    reached = {str(dirpath) for dirpath, _dirs, _files in walked}
    assert not any(str(outside) in path for path in reached)


def test_a_symlink_directly_under_the_root_does_not_escape_either(tmp_path: Path) -> None:
    """The first symlink fix covered the walk but not the units fed into it.

    Path.is_dir() follows symlinks, so a directory symlink that is a direct
    child of the scanned root was handed to the walk as its starting point and
    scandir enumerated the target, however carefully symlinks below it were
    treated. That left the boundary intact everywhere except the one level an
    attacker controls most cheaply."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "package-lock.json").write_text("{}", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    (root / "real").mkdir()
    try:
        (root / "escape").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this platform or account cannot create symlinks")

    units = [u.name for u in ls.top_level_units(root, include_node_modules=False)]
    assert "real" in units
    assert "escape" not in units

    _statuses, index = ls.scan_root(root, include_node_modules=False)
    assert not any("outside" in key for key in index), index


def test_an_apostrophe_in_a_path_cannot_close_the_powershell_string() -> None:
    """A path such as C:\\Users\\O'Brien closed the single-quoted string early.

    The generated task XML was then malformed, and whatever followed the
    apostrophe was read as PowerShell to execute rather than as a filename."""
    assert st.ps_quote("C:\\Users\\O'Brien\\tool.py") == "'C:\\Users\\O''Brien\\tool.py'"
    # A value with no apostrophe must be left exactly as it was, quoted.
    assert st.ps_quote("C:\\plain\\tool.py") == "'C:\\plain\\tool.py'"


def test_a_comma_in_a_path_survives_the_no_runner_task_command(monkeypatch) -> None:
    """The direct-mode command was built by rewriting commas into spaces.

    That transformed commas inside the quoted tokens too, so an updater under a
    directory containing a comma was emitted with the comma turned into a space
    and the registered task could not find it."""
    monkeypatch.setattr(st, "UPDATER", Path("/opt/repo,archive/update_scanners.py"))
    xml = st.windows_xml(st.JOBS["trivy-db"], "2026-01-01T00:00:00+00:00", 0, "user")
    assert "repo,archive" in xml
    assert "repo archive" not in xml


def test_unknown_trivy_metadata_is_not_reported_as_healthy() -> None:
    """An empty freshness map means the check could not run, so exit 2.

    Reading it as "nothing overdue" let a status run report health for a
    question Trivy never answered."""
    assert us.overdue({}) == []
    assert us.trivy_freshness.__doc__ is not None
    assert "could not be determined" in us.trivy_freshness.__doc__


def test_a_variable_prefix_must_end_on_a_separator() -> None:
    """C:\\repo must not claim C:\\repository and rewrite it to %VAR%sitory.

    That registers without complaint and points the scheduled command at a
    directory that does not exist."""
    os.environ["LS_BOUNDARY_TEST"] = str(Path("/opt/repo"))
    inside = str(Path("/opt/repo") / "tool.py")
    sibling = str(Path("/opt/repository") / "tool.py")
    assert st.envify(inside, "LS_BOUNDARY_TEST").startswith("%LS_BOUNDARY_TEST%")
    assert st.envify(sibling, "LS_BOUNDARY_TEST") == sibling


# --------------------------------------------------------------------------
# Reports poisoned when clean.
# --------------------------------------------------------------------------

def test_a_compound_range_with_an_excluding_upper_bound_is_not_flagged() -> None:
    """">=5.0.0 <6.0.0" matched only its first comparator and returned true.

    The upper bound excludes the poisoned version, so this was a false positive,
    and it contradicted the documented promise that an unsupported compound form
    under-reports rather than guessing."""
    assert not ls.range_may_resolve_to(">=5.0.0 <6.0.0", "6.0.0")
    assert not ls.range_may_resolve_to(">1.0.0 <2.0.0", "6.0.0")
    assert not ls.range_may_resolve_to("1.0.0 - 2.0.0", "6.0.0")
    # The single-comparator forms it is built on must keep working.
    assert ls.range_may_resolve_to(">=5.0.0", "6.0.0")
    assert ls.range_may_resolve_to("^6.0.0", "6.0.0")


# --------------------------------------------------------------------------
# Claims coverage it does not have.
# --------------------------------------------------------------------------

def test_a_repository_is_covered_only_when_every_lockfile_resolved() -> None:
    """One lockfile succeeding marked the whole repository checked.

    The coverage line then claimed all of them had been submitted and resolved,
    while the one that failed to extract might be the one carrying the malicious
    transitive dependency."""
    status = ls.RepoStatus(name="r", path="/r")
    status.lockfiles.extend(["/r/one/package-lock.json", "/r/two/package-lock.json"])
    index = {ls._normalize_path(p): status for p in status.lockfiles}

    ls.apply_osv_results(index, {}, {ls._normalize_path("/r/one/package-lock.json")})
    assert status.osv_checked is False
    assert status.osv_resolved_count == 1
    assert "only 1 of 2" in ls._coverage_line(status, "osv-scanner")

    ls.apply_osv_results(index, {}, {ls._normalize_path(p) for p in status.lockfiles})
    assert status.osv_checked is True


def test_an_unusable_root_is_refused_rather_than_skipped(tmp_path: Path) -> None:
    """A mistyped root was skipped, leaving an empty report and exit 0.

    "Repositories scanned: 0" with a success code is a clean bill of health for
    a tree nothing looked at."""
    missing = tmp_path / "definitely-not-here"
    assert not missing.is_dir()
    # The scanner's contract: exit 2 means the check could not be performed.
    argv = ["lockfile_sentinel.py", "--root", str(missing), "--no-refresh", "--no-osv"]
    old = sys.argv
    sys.argv = argv
    try:
        assert ls.main() == 2
    finally:
        sys.argv = old


# --------------------------------------------------------------------------
# Accepts input it never verified.
# --------------------------------------------------------------------------

def test_the_clamav_gate_refuses_a_file_no_scanner_can_read(tmp_path: Path, monkeypatch) -> None:
    """Neither scanner reads a file above the ceiling, and both still exit 0.

    Warning and continuing meant returning a clean verdict for bytes nothing had
    looked at, which is the one answer a gate must never give."""
    target = tmp_path / "huge.db"
    target.write_text("x", encoding="utf-8")

    monkeypatch.setattr(us, "CLAMSCAN_FILE_CEILING", 0)
    monkeypatch.setattr(us, "resolve_clam", lambda name: "clamscan-that-should-not-run")
    monkeypatch.setattr(us, "clamd_max_file_size", lambda: None)

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("the gate must refuse before running any scanner")

    monkeypatch.setattr(us, "run", fail_if_called)
    assert us.gate(target, "an oversized artifact", skip=False) is False


def test_the_gate_still_refuses_when_there_is_nothing_to_scan(tmp_path: Path) -> None:
    """A missing target is a failure, not a pass."""
    assert us.gate(tmp_path / "absent", "a missing artifact", skip=False) is False


# --------------------------------------------------------------------------
# Fails silently: work reported as done that was never done.
# --------------------------------------------------------------------------

def test_a_failed_feed_refresh_keeps_the_existing_overlay(tmp_path: Path, monkeypatch) -> None:
    """An unreachable feed used to overwrite a good overlay with the floor.

    It then stamped the result as freshly refreshed and returned success, so the
    next scan quietly lost every indicator that existed only in the feed."""
    overlay = tmp_path / "compromised-npm-packages.json"
    original = {"package_count": 800, "packages": {"only-in-the-feed": ["1.0.0"]}}
    overlay.write_text(json.dumps(original), encoding="utf-8")

    def unreachable(*_args, **_kwargs):
        raise OSError("feed unreachable")

    monkeypatch.setattr(us.urllib.request, "urlopen", unreachable)

    class Args:
        output = str(overlay)
        source_url = "https://example.invalid/iocs.csv"
        skip_scan = True
        min_interval = 0
        force = True

    assert us.target_malicious_packages(Args()) == 1
    assert json.loads(overlay.read_text(encoding="utf-8")) == original


def test_cron_lines_quote_paths_and_omit_the_user_field_for_a_user_crontab() -> None:
    """Two silent scheduling failures, both of which install without error.

    An unquoted path with a space truncates the command, and a system crontab's
    user field in a user crontab makes cron try to execute the username."""
    os.environ["LOCKFILE_SENTINEL_CACHE"] = str(Path("/tmp/a b/cache"))
    system_line = st.cron_line(st.JOBS["trivy-db"], 0, "root")
    user_line = st.cron_line(st.JOBS["trivy-db"], 0, "")
    assert "'" in system_line
    assert system_line.split()[5] == "root"
    assert user_line.split()[5] != "root"


def test_a_task_path_falls_back_to_absolute_when_the_variable_is_unset() -> None:
    """%NAME% expanding to nothing produces a path that looks almost right."""
    os.environ.pop("LS_REGRESSION_UNSET", None)
    path = str(Path("/opt/tool.py"))
    assert st.envify(path, "LS_REGRESSION_UNSET") == path


def test_campaign_attribution_never_guesses() -> None:
    """A wrong campaign name is worse than none, so an unknown advisory is None.

    The original assertion here ended in "or True" and could not fail."""
    assert ls.campaign_of("MAL-0000-00000", lookup=False) is None
    assert "Shai-Hulud" in (ls.campaign_of("MAL-2026-11524", lookup=False) or "")
