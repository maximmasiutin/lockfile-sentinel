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
        acl = [cmd for cmd in issued if cmd[0] == "icacls" and cmd[1] == str(scratch)]

    assert acl, f"the scratch directory kept its inherited ACL: {issued}"
    assert "/inheritance:r" in acl[0], "the inherited entries were left in place"
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
    """Three ACLs, three verdicts, and silence for the one that is correct.

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
    assert ";AU)" in before, f"the base did not share, so this proves nothing: {before}"

    us.restrict_to_owner(shared, us.current_user_sid())

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
    assert after.count("(A;") >= 3, f"the lockdown granted fewer principals than it names: {after}"

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
