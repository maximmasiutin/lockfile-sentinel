# Lockfile Sentinel 0.1.0
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
  destroys what it maintains    an update that leaves less behind than it found

The titles name the symptom rather than the mechanism, because a regression will
be recognised by its symptom first."""

# pylint: disable=protected-access
# A regression test for a private helper has to call the private helper. The
# alternative is to reach it through the public entry point, which is what the
# defect got past in the first place, so the test would prove less than the bug
# already disproved.

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
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


def test_diagnosis_mode_matches_the_offline_table_without_osv_scanner(
    tmp_path: Path,
) -> None:
    """--lockfile consulted osv-scanner and nothing else.

    It returned 2 the moment the scanner was absent, and where the scanner ran
    it never matched the offline table or the campaign overlay, so a lockfile
    pinning a version this program already knows to be poisoned came back as
    "no malicious-package advisories". The command most likely to be pointed at
    a lockfile the walk has no name for was the one reporting least."""
    lockfile = tmp_path / "bun.lock"
    lockfile.write_text(
        '"keyv@6.0.0": { "version": "6.0.0" }', encoding="utf-8"
    )

    # No scanner at all, which used to end the run before anything was read.
    code = ls.diagnose_lockfiles(None, [str(lockfile)], timeout=5)
    assert code == 1, "a known poisoned version must not exit 0 or 2"

    was_read, poisoned = ls._diagnose_offline(str(lockfile))
    assert was_read is True
    assert "6.0.0" in poisoned.get("keyv", set())


def test_a_file_only_one_layer_could_open_still_counts_as_examined(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """The summary derived "examined" from the offline read alone.

    The two layers open the file separately and can disagree about whether it is
    readable, so a lockfile osv-scanner extracted while the offline pass could
    not open it was counted as never examined, and the summary then understated
    what the run had actually checked."""
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text("{}", encoding="utf-8")

    # The offline pass cannot read it; osv-scanner extracts it and finds nothing.
    monkeypatch.setattr(ls, "scan_lockfile", lambda _path, _status: False)
    monkeypatch.setattr(ls, "_run_osv_batch", lambda *_a, **_k: {})

    ls.diagnose_lockfiles("osv-scanner", [str(lockfile)], timeout=5)
    summary = capsys.readouterr().err
    assert "1 named, 1 examined" in summary
    assert "1 unreadable" in summary


def test_a_scanner_that_never_answered_is_not_reported_as_a_bad_lockfile(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """A timed-out scanner was labelled an extraction failure and exited 1.

    _run_osv_batch returns None for a spawn error, a timeout and unparsable
    output as well as for a lockfile the scanner ran and rejected, and only the
    last of those is a fact about the file. Calling the others FAILED sends the
    reader to inspect a lockfile that may be perfectly sound, and exiting 1
    tells automation a finding exists where the live layer simply never ran."""
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text("{}", encoding="utf-8")

    def timed_out(*_args, **kwargs):
        failure = kwargs.get("failure")
        if failure is not None:
            failure["cause"] = "unavailable"
        return None

    monkeypatch.setattr(ls, "_run_osv_batch", timed_out)
    code = ls.diagnose_lockfiles("osv-scanner", [str(lockfile)], timeout=5)

    output = capsys.readouterr().err
    assert "FAILED" not in output
    assert "SKIPPED" in output
    assert code == 2, "a layer that never answered cannot report health, nor a finding"


def test_diagnosis_mode_honours_no_osv(tmp_path: Path, monkeypatch) -> None:
    """--no-osv was ignored by --lockfile and --lockfiles-from.

    The sweep honoured it and the diagnosis branch called find_osv_scanner
    unconditionally, so a caller who asked for an offline-only check got the
    live one anyway, with whatever network access and delay that carries.

    A layer declined on purpose is also not a layer that failed, so a clean run
    under --no-osv exits 0 rather than 2: exit 2 is for a check the caller
    expected and did not get."""
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"node_modules/keyv": {"version": "5.2.3"}},
    }), encoding="utf-8")

    def refuse(*_args, **_kwargs):
        raise AssertionError("the live layer ran despite --no-osv")

    monkeypatch.setattr(ls, "_run_osv_batch", refuse)
    monkeypatch.setattr(sys, "argv", [
        "lockfile_sentinel.py", "--lockfile", str(lockfile), "--no-osv", "--no-refresh",
    ])
    assert ls.main() == 0


def test_diagnosis_mode_without_a_scanner_never_reports_health(tmp_path: Path) -> None:
    """A clean offline pass is half a check, so it cannot exit 0.

    Exit 0 from this program means nothing was found by the checks that ran, and
    a caller cannot tell that apart from nothing being found at all unless the
    partial run says so in its code."""
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"node_modules/keyv": {"version": "5.2.3"}},
    }), encoding="utf-8")

    assert ls.diagnose_lockfiles(None, [str(lockfile)], timeout=5) == 2


def test_the_structural_pass_survives_the_file_vanishing_after_the_first_read(
    tmp_path: Path,
) -> None:
    """The JSON pass reopened the lockfile the text pass had already read.

    A lockfile removed between the two opens left the structural pass silently
    skipped while the caller still recorded the file as read, and that pass is
    the only one that sees a v2 or v3 entry carrying no `resolved` field. The
    report could therefore name a lockfile as read and call the repository not
    vulnerable on the strength of half an examination.

    Deleting the file after the single read is what proves the second open is
    gone: with one read the finding still lands, with two it disappears."""
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(json.dumps({
        "lockfileVersion": 3,
        # No "resolved" URL, so only the structural pass can see this pin.
        "packages": {"node_modules/keyv": {"version": "6.0.0"}},
    }), encoding="utf-8")
    text = lockfile.read_text(encoding="utf-8")
    lockfile.unlink()

    status = ls.RepoStatus(name="t", path=str(tmp_path))
    ls.scan_npm_lockfile_json(text, status)
    assert "6.0.0" in status.poisoned_versions.get("keyv", set())


def test_a_lockfile_written_with_a_byte_order_mark_still_parses(tmp_path: Path) -> None:
    """The caller decodes as plain utf-8, which leaves a BOM in the string, and
    json.loads rejects it. Reading the file directly used utf-8-sig and hid this,
    so moving to the caller's text would have quietly lost every finding in a
    lockfile npm wrote with a mark."""
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"node_modules/keyv": {"version": "6.0.0"}},
    }), encoding="utf-8-sig")

    status = ls.RepoStatus(name="t", path=str(tmp_path))
    assert ls.scan_lockfile(lockfile, status) is True
    assert "6.0.0" in status.poisoned_versions.get("keyv", set())


def test_every_worker_contributes_to_the_list_of_files_that_were_read() -> None:
    """A parallel scan dropped all but one unit's record of what it opened.

    Each top-level unit is walked by its own worker into its own RepoStatus, and
    every unit without a .git of its own charges its files to the outer root, so
    a repository scanned with more than one job arrives as several statuses for
    one key. _merge_statuses folds them together, and a field it does not know
    about is silently lost. The line then names one unit's manifests and reads as
    the whole of what was opened, which is the failure the line exists to
    prevent, reintroduced by the merge rather than by the walk."""
    into = {Path("/r"): ls.RepoStatus(name="r", path="/r")}
    into[Path("/r")].read_files.append("/r/package.json")
    into[Path("/r")].unreadable_files.append("/r/broken/package.json")

    other = {Path("/r"): ls.RepoStatus(name="r", path="/r")}
    other[Path("/r")].read_files.append("/r/web/package.json")
    other[Path("/r")].unreadable_files.append("/r/api/package-lock.json")

    ls._merge_statuses(into, other)
    merged = into[Path("/r")]
    assert merged.read_files == ["/r/package.json", "/r/web/package.json"]
    assert merged.unreadable_files == [
        "/r/broken/package.json", "/r/api/package-lock.json"
    ]


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


def test_the_scratch_directory_does_not_keep_the_permissions_it_inherited(
        tmp_path, monkeypatch) -> None:
    """The lockdown is issued for the directory that was just created, and drops inheritance.

    Where the mode does not reach the filesystem — an interpreter older than
    3.12.4, a mode other than exactly 0o700, an API-set build, a volume without
    ACLs — the staged database sits in a directory a general-purpose base grants
    modify on to every authenticated user. The gate scans the staged tree and the
    promotion installs it, and between those two a local user could replace an
    approved database with one nothing scanned, which is a gate passing what it
    did not read by a route that does not go through the gate at all.

    This one pins the command rather than the outcome, so it runs everywhere.
    Do not read it as evidence that the directory ends up private: the tests
    further down cover that, and one of them explains why the outcome is already
    delivered by CPython on a current build."""
    cache = tmp_path / "trivy-cache"
    cache.mkdir()
    monkeypatch.setattr(us, "SCRATCH_BASE", "")
    monkeypatch.setattr(us, "IS_WINDOWS", True)
    monkeypatch.setattr(us, "free_bytes", lambda path: 10 * 1024 ** 3)
    monkeypatch.setattr(us, "current_user_sid", lambda: "S-1-5-21-1-2-3-1001")
    issued: list[list[str]] = []

    def record(cmd, **_kwargs):
        issued.append(cmd)
        return 0, ""

    monkeypatch.setattr(us, "run", record)

    with us.scratch_dir("test", near=cache) as scratch:
        # Selected by the option that identifies it rather than by position, so
        # that any other icacls call made against the same path inside the block
        # cannot be mistaken for the restriction and fail this test with a
        # message blaming the ACL rather than the ordering. Nothing issues one
        # today — report_scratch_privacy reads the descriptor through
        # GetNamedSecurityInfoW and spawns nothing — but it did when this was
        # written, which is how the fragility was found.
        acl = [cmd for cmd in issued
               if cmd[0] == "icacls" and cmd[1] == str(scratch) and "/inheritance:r" in cmd]

    assert acl, f"the scratch directory kept its inherited ACL: {issued}"
    granted = {acl[0][index + 1] for index, arg in enumerate(acl[0]) if arg == "/grant:r"}
    assert granted == {
        "*S-1-5-21-1-2-3-1001:(OI)(CI)F",
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F",
    }, f"the replacement ACL is not this account, SYSTEM and administrators: {granted}"


def test_a_scratch_that_cannot_be_locked_down_says_so_and_still_runs(
        tmp_path, monkeypatch) -> None:
    """The warning reports the step that did not run, and claims nothing beyond it.

    Raising would stop the databases updating on any host where icacls is
    unavailable, and a stale vulnerability database is the larger everyday risk
    than a staging window that needs a second local account to exploit. What must
    not happen is the silent version, where the run reports success and nothing
    records that the hardening step failed.

    What must also not happen is the opposite, which this originally did: the
    warning asserted that the directory kept its inherited permissions and that a
    local user could substitute a database. On any interpreter from 3.12.4 that
    is false, because mkdir already protected the directory, so the alarm fired
    on the common path and was wrong. Whether the directory is exposed is a
    different question from whether this step ran, and it is answered from the
    ACL by report_scratch_privacy instead."""
    monkeypatch.setattr(us, "IS_WINDOWS", True)
    monkeypatch.setattr(us, "current_user_sid", lambda: "S-1-5-21-1-2-3-1001")
    monkeypatch.setattr(us, "run", lambda cmd, **_kwargs: (1, "Access is denied."))
    said: list[str] = []
    monkeypatch.setattr(us, "log", said.append)

    us.restrict_to_owner(tmp_path, "S-1-5-21-1-2-3-1001")

    assert any("WARNING" in line for line in said), f"the failure was not reported: {said}"
    assert any("could not restrict the permissions" in line for line in said), (
        f"the warning does not name the step that failed: {said}")
    assert not any("can substitute a database" in line for line in said), (
        f"the warning asserts an exposure it has not established: {said}")


def test_the_scratch_privacy_report_reads_the_acl_rather_than_assuming_it(
        tmp_path, monkeypatch) -> None:
    """Every shape the descriptor comes in, and silence for the ones that are correct.

    The warnings this replaced could not tell a hardening step that failed from
    a directory that is exposed, so they claimed the second whenever the first
    happened. Reading the DACL back distinguishes them, and the cost of getting
    it wrong is asymmetric: a false alarm on the common path teaches an operator
    to ignore the log, and a missed one is the exposure itself."""
    monkeypatch.setattr(us, "IS_WINDOWS", True)
    said: list[str] = []
    monkeypatch.setattr(us, "log", said.append)

    # What both mechanisms produce on a healthy host: protected, and naming only
    # principals a private scratch legitimately carries.
    monkeypatch.setattr(us, "scratch_dacl",
                        lambda path: "d\nD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)\n")
    us.report_scratch_privacy(tmp_path, "S-1-5-21-1-2-3-1001")
    assert not said, f"a correct ACL produced a warning: {said}"

    # This account named by its raw SID, which is how SDDL spells an ordinary
    # account, is the same correct outcome and must also be silent.
    said.clear()
    monkeypatch.setattr(us, "scratch_dacl",
                        lambda path: "d\nD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)\n")
    us.report_scratch_privacy(tmp_path, "S-1-5-21-1-2-3-1001")
    assert not said, f"this account's own entry produced a warning: {said}"

    # And the case the first version of this check let through in silence. Every
    # ordinary account's SID begins S-1-5-21, so exempting that prefix exempted
    # everybody: a DACL granting a different user full control passed without a
    # word, in exactly the situation the whole change exists to report.
    said.clear()
    monkeypatch.setattr(us, "scratch_dacl",
                        lambda path: "d\nD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;S-1-5-21-9-9-9-1055)\n")
    us.report_scratch_privacy(tmp_path, "S-1-5-21-1-2-3-1001")
    assert any("S-1-5-21-9-9-9-1055" in line for line in said), (
        f"another account's full control went unreported: {said}")

    # An inherited entry for authenticated users, which is the measured shape of
    # a general-purpose base and the case the whole change exists for.
    said.clear()
    monkeypatch.setattr(us, "scratch_dacl",
                        lambda path: "d\nD:AI(A;OICI;FA;;;SY)(A;OICIID;0x1301bf;;;AU)\n")
    us.report_scratch_privacy(tmp_path, "S-1-5-21-1-2-3-1001")
    assert any("AU" in line for line in said), f"the intruding principal was not named: {said}"
    assert any("can substitute a database" in line for line in said), (
        f"the warning does not say what the exposure costs: {said}")

    # Trusted principals only, but the DACL is not protected, so the base can
    # still add one later. Silence here would report a privacy with a hole in it.
    said.clear()
    monkeypatch.setattr(us, "scratch_dacl",
                        lambda path: "d\nD:AI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)\n")
    us.report_scratch_privacy(tmp_path, "S-1-5-21-1-2-3-1001")
    assert any("still inherits" in line for line in said), (
        f"an unprotected DACL was reported as private: {said}")

    # A conditional entry, which SDDL spells XA rather than A. Matching only A
    # made a DACL handing another account full control read as empty, which is
    # the same false silence the S-1-5-21 exemption produced, by a second route.
    said.clear()
    monkeypatch.setattr(
        us, "scratch_dacl",
        lambda path: 'd\nD:P(A;OICI;FA;;;SY)(XA;;FA;;;S-1-5-21-9-9-9-1055;(Title=="PM"))\n')
    us.report_scratch_privacy(tmp_path, "S-1-5-21-1-2-3-1001")
    assert any("S-1-5-21-9-9-9-1055" in line for line in said), (
        f"a conditional grant to another account went unreported: {said}")

    # A service account reading its own directory. whoami answers S-1-5-19 and
    # the descriptor abbreviates it to LS, so matching the numeric SID alone
    # reported the process as an intruder in the scratch it had just created.
    said.clear()
    monkeypatch.setattr(us, "scratch_dacl",
                        lambda path: "d\nD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;LS)\n")
    us.report_scratch_privacy(tmp_path, "S-1-5-19")
    assert not said, f"the process reported its own service account as an intruder: {said}"

    # The same alias when it is not this account is still an intruder, because
    # LocalService being the process is a different fact from LocalService
    # holding a grant on somebody else's directory.
    said.clear()
    monkeypatch.setattr(us, "scratch_dacl",
                        lambda path: "d\nD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;LS)\n")
    us.report_scratch_privacy(tmp_path, "S-1-5-21-1-2-3-1001")
    assert any("LS" in line for line in said), (
        f"a service account's grant went unreported for a different process: {said}")

    # A read-only grant. Every allow entry used to produce the substitution
    # warning regardless of its rights, so a group that can only look at the
    # directory was reported as able to replace the database. Overstating what
    # was established is the same defect as understating it, and this warning
    # replaced one that overstated.
    said.clear()
    monkeypatch.setattr(us, "scratch_dacl",
                        lambda path: "d\nD:P(A;OICI;FA;;;SY)(A;OICI;GR;;;BU)\n")
    us.report_scratch_privacy(tmp_path, "S-1-5-21-1-2-3-1001")
    assert any("readable by" in line and "BU" in line for line in said), (
        f"a read-only grant was not reported at all: {said}")
    assert not any("can substitute a database" in line for line in said), (
        f"a read-only grant was reported as able to replace the database: {said}")

    # The hexadecimal spelling of the same distinction, since a mask is what an
    # inherited entry usually carries: 0x1200a9 is read and execute, and
    # 0x1301bf is the modify set.
    said.clear()
    monkeypatch.setattr(us, "scratch_dacl",
                        lambda path: "d\nD:P(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)\n")
    us.report_scratch_privacy(tmp_path, "S-1-5-21-1-2-3-1001")
    assert not any("can substitute a database" in line for line in said), (
        f"a read-only mask was reported as write access: {said}")

    said.clear()
    monkeypatch.setattr(us, "scratch_dacl",
                        lambda path: "d\nD:P(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;AU)\n")
    us.report_scratch_privacy(tmp_path, "S-1-5-21-1-2-3-1001")
    assert any("can substitute a database" in line for line in said), (
        f"a modify mask was not reported as write access: {said}")

    # An unmapped generic bit, which the hexadecimal branch has to weigh even
    # though the letter branch never produces one: GA and GW are translated to
    # their file equivalents, but a mask spelled out in hex keeps whatever it was
    # written with, and an inherit-only entry keeps its generic bits until it is
    # inherited. GENERIC_WRITE here alongside a harmless list bit, so nothing but
    # the generic bit can carry the verdict.
    said.clear()
    monkeypatch.setattr(us, "scratch_dacl",
                        lambda path: "d\nD:P(A;OICI;FA;;;SY)(A;OICI;0x40000001;;;AU)\n")
    us.report_scratch_privacy(tmp_path, "S-1-5-21-1-2-3-1001")
    assert any("can substitute a database" in line for line in said), (
        f"an unmapped GENERIC_WRITE was reported as read-only: {said}")

    said.clear()
    monkeypatch.setattr(us, "scratch_dacl",
                        lambda path: "d\nD:P(A;OICI;FA;;;SY)(A;OICI;0x10000000;;;AU)\n")
    us.report_scratch_privacy(tmp_path, "S-1-5-21-1-2-3-1001")
    assert any("can substitute a database" in line for line in said), (
        f"an unmapped GENERIC_ALL was reported as read-only: {said}")

    # The object-rights mnemonics, whose letters describe a directory-service
    # object and whose bits mean something else on a filesystem directory. The
    # first version of this check kept a list of "write" letters and got both of
    # these the wrong way round: CC reads as create-child and is 0x1, which only
    # lists, while LC reads as list-children and is 0x4, which adds a
    # subdirectory. One of them was a false alarm and the other a false silence.
    said.clear()
    monkeypatch.setattr(us, "scratch_dacl",
                        lambda path: "d\nD:P(A;OICI;FA;;;SY)(A;OICI;LC;;;AU)\n")
    us.report_scratch_privacy(tmp_path, "S-1-5-21-1-2-3-1001")
    assert any("can substitute a database" in line for line in said), (
        f"LC adds a subdirectory and was not reported as write access: {said}")

    said.clear()
    monkeypatch.setattr(us, "scratch_dacl",
                        lambda path: "d\nD:P(A;OICI;FA;;;SY)(A;OICI;CC;;;AU)\n")
    us.report_scratch_privacy(tmp_path, "S-1-5-21-1-2-3-1001")
    assert any("readable by" in line for line in said), (
        f"CC only lists the directory and was not reported at all: {said}")
    assert not any("can substitute a database" in line for line in said), (
        f"CC only lists the directory and was reported as write access: {said}")

    # A letter pair that is not a right at all reads as write, because an entry
    # nobody can parse must not become silence.
    said.clear()
    monkeypatch.setattr(us, "scratch_dacl",
                        lambda path: "d\nD:P(A;OICI;FA;;;SY)(A;OICI;ZZ;;;AU)\n")
    us.report_scratch_privacy(tmp_path, "S-1-5-21-1-2-3-1001")
    assert any("can substitute a database" in line for line in said), (
        f"an unparseable rights field was treated as harmless: {said}")

    # And an odd number of letters, which is the same malformation arriving in a
    # shape that used to parse. The pairs were cut one short of the end, so the
    # trailing character was dropped without a word and CCD read as CC alone: a
    # field nobody could parse became a read-only verdict rather than a warning.
    said.clear()
    monkeypatch.setattr(us, "scratch_dacl",
                        lambda path: "d\nD:P(A;OICI;FA;;;SY)(A;OICI;CCD;;;AU)\n")
    us.report_scratch_privacy(tmp_path, "S-1-5-21-1-2-3-1001")
    assert any("can substitute a database" in line for line in said), (
        f"an odd-length rights field had its last character dropped: {said}")

    # A NULL DACL, which grants every account full access and which Windows
    # writes as a token rather than as entries. With nothing for the parser to
    # find, both lists came back empty, and the protected flag then silenced the
    # inheritance branch as well, so the most exposed directory a filesystem can
    # hold produced no warning at all.
    said.clear()
    monkeypatch.setattr(us, "scratch_dacl", lambda path: "d\nD:PNO_ACCESS_CONTROL\n")
    us.report_scratch_privacy(tmp_path, "S-1-5-21-1-2-3-1001")
    assert any("no access control list at all" in line for line in said), (
        f"a NULL DACL was reported as private: {said}")
    assert any("can substitute a database" in line for line in said), (
        f"a NULL DACL was not reported as write exposure: {said}")

    # And the unprotected spelling of the same thing, which would otherwise have
    # been reported as merely inheriting.
    said.clear()
    monkeypatch.setattr(us, "scratch_dacl", lambda path: "d\nD:NO_ACCESS_CONTROL\n")
    us.report_scratch_privacy(tmp_path, "S-1-5-21-1-2-3-1001")
    assert any("no access control list at all" in line for line in said), (
        f"a NULL DACL was reported as an inheritance problem: {said}")

    # And the honest answer when the ACL cannot be read at all, which is neither
    # of the two verdicts above.
    said.clear()
    monkeypatch.setattr(us, "scratch_dacl", lambda path: None)
    us.report_scratch_privacy(tmp_path, "S-1-5-21-1-2-3-1001")
    assert any("unknown rather than confirmed" in line for line in said), (
        f"an unreadable ACL was reported as a verdict: {said}")


def test_an_unreadable_account_sid_is_not_written_into_an_acl(monkeypatch) -> None:
    """Whatever whoami printed must not be pasted into a grant unexamined.

    A blank or error line parsed as a principal would either fail the icacls call
    or, worse, name something other than this account. The prefix test this
    originally used accepted "S-1-" followed by anything, which is not a SID and
    is not what the docstring promised to discard."""
    monkeypatch.setattr(us, "run", lambda cmd, **_kwargs: (0, '"CORP\\alice","S-1-5-21-9-8-7-500"\n'))
    assert us.current_user_sid() == "S-1-5-21-9-8-7-500"

    for output in ("ERROR: something went wrong\n", "S-1-\n", "S-1-5\n", '"CORP\\alice","S-1-x-y"\n'):
        monkeypatch.setattr(us, "run", lambda cmd, _o=output, **_kwargs: (0, _o))
        assert us.current_user_sid() is None, f"accepted {output!r} as a SID"

    monkeypatch.setattr(us, "run", lambda cmd, **_kwargs: (1, ""))
    assert us.current_user_sid() is None


def test_a_whoami_that_succeeds_and_says_nothing_does_not_raise(monkeypatch) -> None:
    """Exit 0 with no output is a success carrying no answer, not an impossibility.

    The first version indexed the last line of the output unconditionally, so
    this input raised IndexError from inside a function whose whole contract is
    to return None when the SID cannot be read. A redirected or policy-restricted
    whoami produces exactly this."""
    for output in ("", "   ", "\n", " \r\n \n"):
        monkeypatch.setattr(us, "run", lambda cmd, _o=output, **_kwargs: (0, _o))
        assert us.current_user_sid() is None, f"raised or accepted on {output!r}"


def test_an_unreadable_sid_warns_and_still_produces_a_usable_scratch(
        tmp_path, monkeypatch) -> None:
    """The whole path with the real parser in it, rather than stubbed past.

    The command-level test above monkeypatches current_user_sid out, which is
    exactly why the suite did not catch the crash: it fed run the empty output
    that used to raise and then arranged for the parser never to see it. Here
    the empty output reaches the real parser, and the run has to survive it."""
    cache = tmp_path / "trivy-cache"
    cache.mkdir()
    monkeypatch.setattr(us, "SCRATCH_BASE", "")
    monkeypatch.setattr(us, "IS_WINDOWS", True)
    monkeypatch.setattr(us, "free_bytes", lambda path: 10 * 1024 ** 3)
    monkeypatch.setattr(us, "run", lambda cmd, **_kwargs: (0, ""))

    with us.scratch_dir("test", near=cache) as scratch:
        assert scratch.is_dir()
    assert not scratch.exists(), f"the scratch directory was left behind at {scratch}"


def test_a_raising_hardening_step_does_not_leak_the_scratch_directory(
        tmp_path, monkeypatch) -> None:
    """The placement half of the fix, which the test above cannot reach.

    restrict_to_owner sat between the mkdir and the try whose finally removes
    the directory, so anything raising there left a directory behind that
    nothing else deletes: the name is random by design, so no later run
    recognises it as garbage. Fixing the parser stopped the raise that was
    known about, which is why the test above passes either way and would go on
    passing if the call moved back outside the try. This one injects a raise
    directly, so it pins the placement rather than the parser, and it fails on
    any future step added in the same wrong place."""
    cache = tmp_path / "trivy-cache"
    cache.mkdir()
    monkeypatch.setattr(us, "SCRATCH_BASE", "")
    monkeypatch.setattr(us, "free_bytes", lambda path: 10 * 1024 ** 3)
    monkeypatch.setattr(us.secrets, "token_hex", lambda _n: "fixedname")

    def refuse(_path, _sid):
        raise RuntimeError("the ACL could not be rewritten")

    monkeypatch.setattr(us, "restrict_to_owner", refuse)

    with pytest.raises(RuntimeError, match="the ACL could not be rewritten"):
        with us.scratch_dir("test", near=cache):
            pytest.fail("the body must not run when the hardening step raised")

    leaked = cache.parent / "temp-fixedname"
    assert not leaked.exists(), f"the scratch directory was left behind at {leaked}"


def test_a_scratch_that_someone_else_reached_first_is_refused(tmp_path, monkeypatch) -> None:
    """A fresh scratch with anything in it was not fresh, and must not be staged into.

    Where the interpreter does not apply mode 0o700 — older than 3.12.4, an
    API-set build, a volume without ACLs — the directory exists with the base's
    permissions until icacls rewrites them. An account watching the base is
    handed the name by the filesystem the moment it appears, so the random name
    does not help, and it can create a child inside that interval. icacls
    without /T does not touch that child, and the staging path adopts what it
    finds with exist_ok=True, so a hostile file would be carried through the
    ClamAV gate as though it had been downloaded.

    Refusing is the only safe answer, and it is cheap: nothing else can be in a
    directory created exclusively a moment earlier. This does not close the race
    — a handle opened during the interval keeps its access whatever the DACL
    says afterwards — and the docstrings say so rather than implying otherwise."""
    cache = tmp_path / "trivy-cache"
    cache.mkdir()
    monkeypatch.setattr(us, "SCRATCH_BASE", "")
    monkeypatch.setattr(us, "IS_WINDOWS", True)
    monkeypatch.setattr(us, "free_bytes", lambda path: 10 * 1024 ** 3)
    monkeypatch.setattr(us, "current_user_sid", lambda: "S-1-5-21-1-2-3-1001")

    # Stand in for the attacker: the lockdown step is where the interval ends, so
    # a child appearing during it is a child that was created inside it.
    def plant(path, _sid):
        (path / "cache").mkdir()

    monkeypatch.setattr(us, "restrict_to_owner", plant)

    with pytest.raises(RuntimeError, match="was not empty immediately after being created"):
        with us.scratch_dir("test", near=cache):
            pytest.fail("the body must not run on a scratch someone else reached first")


def _sddl_of(path: Path, into: Path) -> str:
    """The directory's own DACL as SDDL, or a skip if icacls cannot be used.

    Read as SDDL rather than from the display listing, because `icacls <dir>`
    prints principal names in the system's language: asserting that the English
    "Authenticated Users" is absent passes on a localised Windows whether the
    directory is shared or not, which is a security check that stops checking
    and does not say so. The /save form writes fixed aliases instead — AU for
    Authenticated Users, BU for the built-in Users group — and those do not move
    with the locale.

    /findsid is not the alternative it appears to be: it searches the files
    inside a directory rather than that directory's own ACL, and on a directory
    carrying an inherited AU entry it reports no match at all."""
    code, output = us.run(["icacls", str(path), "/save", str(into)], timeout=60)
    if code != 0 or not into.exists():
        pytest.skip(f"icacls /save is not usable here: {output}")
    # UTF-16LE with no byte-order mark, so it cannot be read as plain "utf-16":
    # that codec looks for a mark and raises without one.
    return into.read_text(encoding="utf-16-le")


@pytest.mark.skipif(not us.IS_WINDOWS, reason="the ACL this reads exists only on Windows")
def test_the_dacl_reader_actually_reads_a_dacl(tmp_path) -> None:
    """The real reader against real directories, because a stub proved nothing.

    Every other test of the privacy report monkeypatches scratch_dacl, and the
    end-to-end tests read ACLs through their own icacls helper, so nothing
    exercised this function. A rewrite of it shipped broken and the whole suite
    stayed green: it answered None for every directory, which the report then
    faithfully turned into "permissions unknown". A verifier that cannot verify
    is the quietest kind of failure, so this asserts it can.

    Two directories, distinguished by the flag that matters, so a reader that
    returned a constant or the same answer for both fails here.

    The protected one is made protected with icacls rather than with
    mkdir(mode=0o700), which is the obvious way and the wrong one. This very
    change documents four configurations in which the interpreter does not apply
    that mode — 3.12.0 to 3.12.3, a mode other than exactly 0o700, an API-set
    build, a volume without ACLs — and three of them are supported here. A test
    asserting the mode worked would therefore fail on a configuration where
    nothing is wrong and the reader is fine, which is the same conditional-read-
    as-universal mistake this branch has made repeatedly. icacls either works or
    reports that it did not, and the skip says which."""
    inherited = tmp_path / "inherited"
    inherited.mkdir()
    protected = tmp_path / "protected"
    protected.mkdir()
    # This account is granted alongside SYSTEM, rather than SYSTEM alone. The
    # first version named only SYSTEM, which does protect the directory and also
    # leaves the account running the tests unable to delete it, so pytest could
    # not clear its own temporary tree and every run left one behind. What this
    # case needs is a protected DACL, not an inaccessible one.
    #
    # Skipped rather than falling back to the administrators group when the SID
    # cannot be read. The fallback looked harmless and was not: on a
    # non-administrator account icacls would still succeed at removing this
    # account's own access, and the test would then be locked out of the
    # directory it just made instead of reporting that the setup is unavailable.
    sid = us.current_user_sid()
    if sid is None:
        pytest.skip("this account's SID could not be read, so the fixture cannot be built safely")
    code, output = us.run(
        ["icacls", str(protected), "/inheritance:r",
         "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", f"*{sid}:(OI)(CI)F"],
        timeout=60)
    if code != 0:
        pytest.skip(f"cannot protect a directory here, so the reader cannot be told apart: {output}")
    # And read back with the other reader before trusting the exit status, because
    # a zero from icacls says the command was accepted, not that the filesystem
    # kept what it accepted. On a volume that carries no ACLs — the exFAT case
    # this whole change warns about rather than refuses — the descriptor is
    # discarded and the D:P assertion below would then blame scratch_dacl for a
    # fixture the test could not build. Checked with the icacls reader rather
    # than with scratch_dacl, so that the thing under test is not also the thing
    # certifying its own input.
    if "D:P" not in _sddl_of(protected, tmp_path / "fixture.sddl"):
        pytest.skip("this volume did not keep a protected DACL, so the two cases are not distinct")

    inherited_sddl = us.scratch_dacl(inherited)
    protected_sddl = us.scratch_dacl(protected)

    assert inherited_sddl is not None, "the reader could not read an ordinary directory"
    assert protected_sddl is not None, "the reader could not read a protected directory"
    assert inherited_sddl.startswith("D:"), f"not a DACL: {inherited_sddl}"
    assert "D:P" in protected_sddl, (
        f"a directory icacls protected did not read back as protected: {protected_sddl}")
    assert "D:P" not in inherited_sddl, (
        f"an inherited directory read back as protected: {inherited_sddl}")


@pytest.mark.skipif(not us.IS_WINDOWS, reason="reparse points are a Windows shape")
def test_a_junction_left_where_the_scratch_was_is_recognised_as_a_link(tmp_path) -> None:
    """Path.is_symlink() answers False for a junction, so the scratch check cannot use it.

    An account that can delete the scratch during the window before the ACL is
    rewritten can leave a link at the same name, and everything after that point
    would describe and fill a directory somewhere else. A junction is the form
    that needs no privilege to create, and it is exactly the form is_symlink()
    misses, so a check written the obvious way would have covered only the attack
    that needs Developer Mode."""
    victim = tmp_path / "victim"
    victim.mkdir()
    plain = tmp_path / "plain"
    plain.mkdir()
    junction = tmp_path / "junction"
    made, output = us.run(["cmd", "/c", "mklink", "/J", str(junction), str(victim)], timeout=60)
    if made != 0:
        pytest.skip(f"cannot create a junction here: {output}")

    assert not junction.is_symlink(), (
        "is_symlink() now reports junctions, so the comment explaining this check is stale")
    assert us.is_reparse_point(junction), "a junction was taken for the scratch directory itself"
    assert not us.is_reparse_point(plain), "an ordinary directory was refused as a link"


@pytest.mark.skipif(not us.IS_WINDOWS, reason="the ACL this pins exists only on Windows")
def test_restrict_to_owner_privatises_a_directory_that_was_created_shared(tmp_path) -> None:
    """The only test here that can fail if restrict_to_owner stops working.

    Everything else about the scratch directory is now done by CPython itself:
    since the fix for CVE-2024-4030, mkdir(mode=0o700) creates a protected DACL
    on Windows, so a scratch is private before restrict_to_owner is reached and
    an end-to-end assertion about its permissions passes on an empty
    implementation. restrict_to_owner exists for the cases where that mechanism
    is silently absent — an interpreter older than 3.12.4, a mode other than
    exactly 0o700, an API-set build, a filesystem without ACLs — and none of
    those can be produced inside a test on this host.

    So the function is exercised directly, against a directory deliberately
    created the way those cases leave it: with the default mode, inheriting a
    base that grants Authenticated Users."""
    # Resolved once, up front, and the case skipped when it is missing. Reading
    # it inline at the call below made this test assert the opposite of what the
    # code does: with no SID, restrict_to_owner takes its documented path of
    # warning and leaving the ACL alone, so the inherited Authenticated Users
    # grant stays and every assertion here fails on behaviour that is correct.
    sid = us.current_user_sid()
    if sid is None:
        pytest.skip("this account's SID could not be read, which is the graceful path, not this one")

    base = tmp_path / "shared-base"
    base.mkdir()
    seeded, seed_output = us.run(
        ["icacls", str(base), "/grant", "*S-1-5-11:(OI)(CI)M"], timeout=60)
    if seeded != 0:
        pytest.skip(f"cannot seed a shared base here: {seed_output}")

    # No mode, so CPython creates it with the inherited ACL rather than its own
    # protected one. This is the state restrict_to_owner has to be able to fix.
    shared = base / "created-without-the-mode"
    shared.mkdir()
    before = _sddl_of(shared, tmp_path / "before.sddl")
    # Skipped rather than asserted, because this is the fixture rather than the
    # subject. icacls returning zero says the grant was accepted, and on a volume
    # that holds no ACLs it is accepted and discarded; failing here would then
    # report a regression in restrict_to_owner on a host where the shared
    # directory it is asked to fix could not be created in the first place.
    if ";AU)" not in before:
        pytest.skip(f"the base did not share, so there is nothing here to privatise: {before}")

    us.restrict_to_owner(shared, sid)

    after = _sddl_of(shared, tmp_path / "after.sddl")
    assert ";AU)" not in after, f"authenticated users can still write it: {after}"
    assert ";BU)" not in after, f"the users group can still read it: {after}"
    # P marks the DACL protected, which is what /inheritance:r sets. Without it
    # the grants would sit on top of whatever the base still passes down.
    assert "D:P" in after, f"the directory still inherits from its base: {after}"

    # The three absences above are satisfied by a protected DACL with no entries
    # at all, which locks this account out of its own staging directory and
    # fails the download rather than the test. Removing access is as much a
    # defect as leaving it, so the grants are asserted rather than assumed.
    # SYSTEM and the administrators group are asserted by their SDDL aliases,
    # which are fixed. The account's own entry is deliberately not asserted as
    # text: SDDL abbreviates a well-known SID and spells out any other, so one
    # working ACL reads as the raw S-1-5-21-...-1001 on a workstation whose
    # account is an ordinary user, and as LA on a CI runner whose account is the
    # built-in administrator at RID 500. The first version of this test pinned
    # the raw SID, passed here and failed on both Windows runners while nothing
    # was wrong, which is the same mistake as reading localised principal names
    # out of the display listing.
    assert "(A;OICI;FA;;;SY)" in after, f"SYSTEM lost full control: {after}"
    assert "(A;OICI;FA;;;BA)" in after, f"the administrators group lost full control: {after}"
    # No count of the entries here. Requiring three was meant to catch a
    # protected but empty DACL, which the two assertions above already exclude,
    # and it fails under an account that is itself one of the principals
    # granted: as LocalSystem the account grant and the SYSTEM grant collapse
    # into one entry, so a correct ACL carries two and the test failed on a
    # directory with nothing wrong with it.

    # The account's own access is claimed from the other side instead, which is
    # the stronger half anyway: an ACL that reads correctly and denies in
    # practice is the failure no string comparison can see.
    (shared / "written-after-lockdown").write_text("staged", encoding="utf-8")


@pytest.mark.skipif(not us.IS_WINDOWS, reason="the ACL this pins exists only on Windows")
def test_a_scratch_directory_ends_up_private_whichever_mechanism_did_it(
        tmp_path, monkeypatch) -> None:
    """The property that matters, without claiming which step delivered it.

    On a current interpreter and an ACL-bearing filesystem this passes because
    mkdir(mode=0o700) already produced a protected DACL, so it would pass with
    restrict_to_owner removed entirely. That is stated rather than hidden: the
    test pins the outcome a caller depends on, and the test above pins the
    function that has to deliver it everywhere else."""
    base = tmp_path / "shared-base"
    base.mkdir()
    seeded, seed_output = us.run(
        ["icacls", str(base), "/grant", "*S-1-5-11:(OI)(CI)M"], timeout=60)
    if seeded != 0:
        pytest.skip(f"cannot seed a shared base here: {seed_output}")

    cache = tmp_path / "trivy-cache"
    cache.mkdir()
    monkeypatch.setattr(us, "SCRATCH_BASE", str(base))
    monkeypatch.setattr(us, "free_bytes", lambda path: 10 * 1024 ** 3)

    with us.scratch_dir("test", near=cache) as scratch:
        assert scratch.parent == base, f"the scratch did not land on the seeded base: {scratch}"
        # A download has to be able to write here, whichever mechanism set the
        # ACL. The grants are not asserted by name because the two mechanisms
        # spell them differently — CPython's descriptor grants OWNER RIGHTS,
        # restrict_to_owner grants this account's SID — and pinning either would
        # make the test fail on the wrong build rather than on a real defect.
        (scratch / "staged.db").write_text("staged", encoding="utf-8")
        sddl = _sddl_of(scratch, tmp_path / "scratch.sddl")

    assert ";AU)" not in sddl, f"the staged database sits somewhere shared: {sddl}"
    assert ";BU)" not in sddl, f"the staged database sits somewhere shared: {sddl}"
    assert "D:P" in sddl, f"the scratch still inherits from its base: {sddl}"


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
    # The space is the whole point of the fixture; the directory is never
    # created and nothing is written to it, and it deliberately avoids the
    # conventional temporary directories so that reading this line is not
    # mistaken for a program writing to a predictable path.
    os.environ["LOCKFILE_SENTINEL_CACHE"] = str(Path("/opt/a b/cache"))
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


def test_an_offsetless_trivy_stamp_is_read_as_utc_not_local_time() -> None:
    """A naive datetime slips through astimezone() as local time, not an error.

    overdue and describe_age both call astimezone(timezone.utc) on these
    values, and on a naive one that call assumes the host's zone, shifting
    every freshness judgement by the local UTC offset while reporting nothing.
    The offset assertion is what makes the failure host-independent: a check
    on wall-clock fields after astimezone() would still pass on a UTC host.
    The equality then pins the instant the stamp names."""
    parsed = us.parse_stamp("2026-08-15T12:00:00")
    assert parsed is not None
    assert parsed.utcoffset() == timedelta(0)
    assert parsed == datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)


def test_a_non_utc_offset_is_honoured_rather_than_overwritten() -> None:
    """The careless fix replaces tzinfo wholesale and moves the instant.

    A stamp carrying +03:00 names the same moment as its UTC rendering; a fix
    that stamped UTC onto the parsed fields would shift it by three hours."""
    parsed = us.parse_stamp("2026-08-15T15:00:00+03:00")
    assert parsed is not None
    assert parsed.utcoffset() == timedelta(hours=3)
    assert parsed == datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# Destroys what it maintains.
# --------------------------------------------------------------------------

def test_a_scratch_base_set_to_the_cache_itself_is_passed_over(tmp_path, monkeypatch) -> None:
    """Staging inside the cache destroys the cache, and reports a write error.

    Promotion renames the live cache aside and then moves the staged tree into
    its place. A scratch under the cache is carried away by that first rename,
    so the move names a path that no longer exists, and the run ends with no
    live cache and both databases stranded in a .previous tree that nothing
    restores. The next run downloads a gigabyte again; the window in between has
    no vulnerability database at all."""
    cache = tmp_path / "trivy-cache"
    cache.mkdir()
    monkeypatch.setattr(us, "SCRATCH_BASE", str(cache))

    with us.scratch_dir("test", near=cache) as scratch:
        assert not us.is_inside(scratch, cache)


def test_a_scratch_base_under_the_cache_is_passed_over_too(tmp_path, monkeypatch) -> None:
    """Containment is the test, not equality: a descendant is carried away alike."""
    cache = tmp_path / "trivy-cache"
    (cache / "db" / "staging").mkdir(parents=True)
    monkeypatch.setattr(us, "SCRATCH_BASE", str(cache / "db" / "staging"))

    with us.scratch_dir("test", near=cache) as scratch:
        assert not us.is_inside(scratch, cache)


def test_a_link_pointing_into_the_cache_is_caught_as_well(tmp_path, monkeypatch) -> None:
    """Two spellings can name one directory, and the rename acts on the real one.

    Comparing the literal paths would accept this base, and the failure it
    produces is identical to the one comparing resolved paths prevents."""
    cache = tmp_path / "trivy-cache"
    (cache / "inner").mkdir(parents=True)
    link = tmp_path / "link-to-inner"
    try:
        link.symlink_to(cache / "inner", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this platform or account cannot create symlinks")
    monkeypatch.setattr(us, "SCRATCH_BASE", str(link))

    with us.scratch_dir("test", near=cache) as scratch:
        assert not us.is_inside(scratch, cache)


def test_a_promotion_from_beside_the_cache_leaves_a_live_cache(tmp_path) -> None:
    """The arrangement the guard forces has to actually work.

    Rejecting a bad scratch base is only half the claim; the other half is that
    staging beside the cache promotes cleanly, including over an existing cache,
    which is the case that renames the old tree aside first."""
    live = tmp_path / "trivy-cache"
    live.mkdir()
    (live / "db").mkdir()
    (live / "db" / "trivy.db").write_text("old", encoding="utf-8")

    staged = tmp_path / "temp-abc123"
    (staged / "db").mkdir(parents=True)
    (staged / "db" / "trivy.db").write_text("new", encoding="utf-8")

    us.promote_into(staged, live)

    assert (live / "db" / "trivy.db").read_text(encoding="utf-8") == "new"
    assert not staged.exists()
    assert not live.with_name(live.name + ".previous").exists()


def test_a_symlinked_cache_keeps_pointing_where_it_was_aimed(tmp_path) -> None:
    """Renaming a symlink moves the name, not the databases it stands for.

    A cache path is symlinked precisely when the databases have to live on a
    roomier volume than the configured location sits on. Promoting through the
    unresolved name renames the link aside, writes a real directory in its place,
    and leaves the old databases orphaned at the link target: the cache silently
    migrates back onto the small volume, which is the failure this whole area
    exists to avoid, and rmtree will not remove a symlink so a .previous link is
    left behind by every refresh."""
    target = tmp_path / "roomy-volume" / "trivy-cache"
    (target / "db").mkdir(parents=True)
    (target / "db" / "trivy.db").write_text("old", encoding="utf-8")

    live = tmp_path / "configured-cache"
    try:
        live.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this platform or account cannot create symlinks")

    staged = tmp_path / "temp-abc123"
    (staged / "db").mkdir(parents=True)
    (staged / "db" / "trivy.db").write_text("new", encoding="utf-8")

    us.promote_into(staged, live)

    assert live.is_symlink(), "the configured cache path stopped being a link"
    assert live.resolve() == target.resolve(), "the link stopped pointing at its volume"
    assert (target / "db" / "trivy.db").read_text(encoding="utf-8") == "new"
    assert not live.with_name(live.name + ".previous").exists()
    assert not target.with_name(target.name + ".previous").exists()


def test_a_symlinked_cache_stages_on_the_volume_it_points_at(tmp_path, monkeypatch) -> None:
    """The scratch has to land where the databases are, not where the name is.

    A cache path is symlinked when the databases have to live somewhere roomier,
    so the parent of the link is the small volume the link exists to avoid.
    Staging there risks the disk-full failure this mechanism was written for and
    turns the promotion into a copy across two volumes rather than a rename
    within one. promote_into resolves the cache for the same reason, and the two
    have to agree about where it is."""
    roomy = tmp_path / "roomy-volume"
    target = roomy / "trivy-cache"
    target.mkdir(parents=True)
    small = tmp_path / "small-volume"
    small.mkdir()
    cache = small / "trivy-cache"
    try:
        cache.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this platform or account cannot create symlinks")
    monkeypatch.setattr(us, "SCRATCH_BASE", "")
    # Which volume is chosen is the question; whether this machine happens to
    # have 5 GB free on the temporary volume is not, and without this the
    # candidate is passed over for room before the choice can be observed.
    monkeypatch.setattr(us, "free_bytes", lambda path: 10 * 1024 ** 3)

    with us.scratch_dir("test", near=cache) as scratch:
        assert scratch.parent == roomy, f"staged on the wrong volume: {scratch}"
        assert not us.is_inside(scratch, cache)


def test_the_last_resort_scratch_is_refused_inside_the_cache_too(tmp_path, monkeypatch) -> None:
    """The guard is worthless if the fallback walks around it.

    Where the configured base and the cache volume are both unusable, the system
    temporary directory is taken without argument. If that directory happens to
    sit inside the cache, the promotion carries the scratch away exactly as it
    would have for a configured base, and the run ends with no live cache."""
    cache = tmp_path / "trivy-cache"
    (cache / "tmp").mkdir(parents=True)
    monkeypatch.setattr(us, "SCRATCH_BASE", "")
    monkeypatch.setattr(us.tempfile, "gettempdir", lambda: str(cache / "tmp"))
    # Leave the cache volume candidate unusable so the fallback is reached at all.
    monkeypatch.setattr(us, "free_bytes", lambda path: 0)

    with us.scratch_dir("test", near=cache) as scratch:
        assert not us.is_inside(scratch, cache)


def test_campaign_attribution_never_guesses() -> None:
    """A wrong campaign name is worse than none, so an unknown advisory is None.

    The original assertion here ended in "or True" and could not fail."""
    assert ls.campaign_of("MAL-0000-00000", lookup=False) is None
    assert "Shai-Hulud" in (ls.campaign_of("MAL-2026-11524", lookup=False) or "")
