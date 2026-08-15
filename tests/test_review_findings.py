# Lockfile Sentinel 0.2.0
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Maxim Masiutin
"""One test per finding the machine-output review produced, by its own words.

The review of the machine-output work raised forty-six findings across three
agents. Most were fixed as they arrived, several by tests written beside the
fix; this file is the other half, the one place where a reader can ask "was
that finding pinned" and get an answer without reconstructing the review.

Each test names the defect rather than the function, because a regression is
recognised by its symptom first. The order follows the review.

Findings not represented here, and why:

  the schema $id branch name       declined; the default branch is master, so
                                   the URL is correct and there is nothing to
                                   pin that test_the_published_schema does not
  the v0.2.0 tag                   a release step performed after the merge,
                                   with nothing in the tree to assert
  the semgrep rule sets            the rules file left this repository, so the
                                   claim it was aligned against is gone
  the Trivy cache resolver         deferred to the update_scanners workstream
  the version-token match          deferred likewise, and a test here would
                                   pin behaviour that workstream is changing
"""

# pylint: disable=protected-access
# Every finding but a handful was raised against a private helper, which is
# where the defect lived and therefore where the pin belongs.

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import lockfile_sentinel as ls  # noqa: E402  # pylint: disable=wrong-import-position
import update_scanners as us  # noqa: E402  # pylint: disable=wrong-import-position

ROOT = Path(__file__).resolve().parent.parent


def _flagged_repo() -> ls.RepoStatus:
    """A repository with one lockfile that produced a finding."""
    status = ls.RepoStatus(name="t", path="/t")
    status.has_npm = True
    status.lockfiles = ["/t/package-lock.json"]
    status.flagged_lockfiles = {"/t/package-lock.json"}
    return status


# --------------------------------------------------------------------------
# The schemas.
# --------------------------------------------------------------------------

def _schema(name: str) -> dict[str, Any]:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def test_neither_schema_admits_a_version_it_does_not_describe() -> None:
    """A minimum would have let a version-2 document validate against the
    version-1 schema, so negotiation could not fail closed."""
    for name in ("lockfile-sentinel-report.schema.json",
                 "lockfile-sentinel-status.schema.json"):
        version = _schema(name)["properties"]["schema"]["properties"]["version"]
        assert version == {"const": 1}


def test_the_finish_stamp_is_a_union_by_anyof_not_by_type() -> None:
    """format beside a union type is handled unevenly across validators."""
    finished = _schema("lockfile-sentinel-report.schema.json")[
        "properties"]["invocation"]["properties"]["finished_utc"]
    assert "anyOf" in finished
    assert "type" not in finished


def test_the_schema_refuses_complete_without_a_finish_stamp() -> None:
    """The one lifecycle combination no producer state allows."""
    invocation = _schema("lockfile-sentinel-report.schema.json")[
        "properties"]["invocation"]
    rule = invocation["allOf"][0]
    assert rule["if"]["properties"]["complete"] == {"const": True}
    assert rule["then"]["properties"]["finished_utc"] == {"type": "string"}


# --------------------------------------------------------------------------
# Writing the report.
# --------------------------------------------------------------------------

def test_a_snapshot_is_written_by_replacement_not_by_truncation(
    tmp_path: Path,
) -> None:
    """write_text truncated the live report before writing it, so a reader
    racing a batch update saw a half-written file.

    The identity check is the point: correct final content and no leftover
    temp file are both true of a truncating write too, so only a new inode at
    the same path distinguishes replacement from writing in place."""
    target = tmp_path / "report.json"
    target.write_text('{"first": true}', encoding="utf-8")
    before = target.stat()
    ls._write_atomic(target, '{"second": true}')
    after = target.stat()
    assert json.loads(target.read_text(encoding="utf-8")) == {"second": True}
    assert [p.name for p in tmp_path.iterdir()] == ["report.json"]
    assert (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)


def test_the_example_reconciles_its_own_submitted_counts() -> None:
    """The committed example is what a consumer builds against, so its
    top-level submitted count has to equal the sum of the repository ones."""
    example = json.loads(
        (ROOT / "lockfile-sentinel-report.example.json").read_text(encoding="utf-8")
    )
    per_repo = sum(r["coverage"]["osv"]["submitted"] for r in example["repositories"])
    assert example["inputs"]["lockfiles_submitted"] == per_repo


# --------------------------------------------------------------------------
# Coverage the report must not overstate.
# --------------------------------------------------------------------------

def test_an_unreadable_subtree_is_incomplete_coverage(tmp_path: Path, monkeypatch) -> None:
    """Everything beneath a directory the walk cannot enter goes unseen, so a
    clean verdict over it would be a verdict about nothing."""
    locked = tmp_path / "app" / "locked"
    locked.mkdir(parents=True)
    real = ls._list_directory
    monkeypatch.setattr(
        ls, "_list_directory",
        lambda current: None if current.name == "locked" else real(current),
    )
    statuses, _index = ls.scan_root(tmp_path, include_node_modules=False)
    status = statuses[tmp_path / "app"]
    assert status.unreadable_dir_total == 1
    assert ls.report_is_complete({}, [status]) is False


def test_an_empty_lockfile_reconciles_as_resolved_without_a_submission() -> None:
    """It has nothing to resolve, which is the scanner's own verdict, so it
    is inside resolved and outside submitted at both levels."""
    status = ls.RepoStatus(name="t", path="/t")
    status.lockfiles = ["/t/package-lock.json"]
    path = ls._normalize_path(status.lockfiles[0])
    ls.apply_osv_results({path: status}, {}, {path}, empty_paths={path})
    coverage = ls._repo_osv_coverage(status, requested=True, available=True)
    assert (coverage["resolved"], coverage["empty"], coverage["submitted"]) == (1, 1, 0)


def test_a_scanner_outage_is_not_a_rejected_lockfile() -> None:
    """A timeout says nothing about the file in front of the scanner, so it
    must not send an operator to repair one that may be sound."""
    run = ls.OsvRunReport(unavailable=["/t/package-lock.json"])
    layer = ls.osv_layer(True, "osv-scanner", run, 1, 0)
    assert layer["reason_code"] == "scanner_unavailable"
    outages = [e for e in ls.collect_errors({}, [], run)
               if e["code"] == "osv_scanner_unavailable"]
    assert outages and outages[0]["retryable"] is True


def test_a_systemic_outage_costs_one_invocation_not_one_per_file(
    tmp_path: Path, monkeypatch
) -> None:
    """Splitting a batch the scanner never answered multiplies the outage."""
    paths = []
    for name in ("a", "b", "c"):
        lockfile = tmp_path / name / "package-lock.json"
        lockfile.parent.mkdir()
        lockfile.write_text('{"lockfileVersion": 3}', encoding="utf-8")
        paths.append(str(lockfile))
    calls: list[int] = []

    def no_answer(_bin, batch, _timeout, _debug=False, failure=None):
        calls.append(len(batch))
        if failure is not None:
            failure["cause"] = "unavailable"

    monkeypatch.setattr(ls, "_run_osv_batch", no_answer)
    run = ls.OsvRunReport()
    ls.run_osv_scanner("osv-scanner", paths, 100, 10, run_report=run)
    assert calls == [3]
    assert run.unavailable == paths


def test_a_lockfile_free_tree_needs_no_scanner_to_be_complete() -> None:
    """Nothing to scan completes the layer whatever is installed."""
    layer = ls.osv_layer(True, None, ls.OsvRunReport(), 0, 0)
    assert (layer["state"], layer["reason_code"]) == ("completed", "nothing_to_scan")


def test_trivy_coverage_is_pending_until_the_flagged_files_go_in() -> None:
    """No failure recorded is not the same as corroboration having run, at
    either level."""
    status = _flagged_repo()
    assert ls.trivy_layer(True, "trivy", [status])["reason_code"] == "corroboration_pending"
    assert ls._repo_trivy_coverage(status, True, True)["reason_codes"] == [
        "corroboration_pending"
    ]
    status.trivy_submitted_count = 1
    assert ls.trivy_layer(True, "trivy", [status])["state"] == "completed"
    assert ls._repo_trivy_coverage(status, True, True)["state"] == "completed"


def test_a_partial_layer_is_named_in_the_errors() -> None:
    """An exit 2 whose error list is empty sends the consumer hunting."""
    layers = {"overlay": {"requested": True, "state": "partial",
                          "reason_code": "overlay_refresh_failed", "message": None}}
    codes = {e["code"] for e in ls.collect_errors(layers, [], ls.OsvRunReport())}
    assert "overlay_refresh_failed" in codes


def test_overlapping_roots_are_walked_once(tmp_path: Path) -> None:
    """Walking a tree twice halves the coverage of the duplicate statuses."""
    inner = tmp_path / "inner"
    inner.mkdir()
    assert ls._deduplicate_roots([tmp_path, tmp_path, inner]) == [tmp_path]


def test_an_unrecognised_scanner_payload_is_never_zero_findings() -> None:
    """Output in a shape this parser does not know says nothing about the
    lockfiles, so reading it as clean is the failure the tool exists against."""
    assert ls._extract_malicious_findings({"unexpected": []}) is None
    assert ls._extract_malicious_findings({"results": []}) == {}


# --------------------------------------------------------------------------
# Findings.
# --------------------------------------------------------------------------

def test_a_finding_id_survives_database_enrichment() -> None:
    """An id that moved when advisories arrived would defeat the cross-run
    correlation a stable id is advertised for."""
    def repo(with_osv: bool) -> ls.RepoStatus:
        status = ls.RepoStatus(name="app", path="/t/app")
        status.poisoned_versions = {"keyv": {"6.0.0"}}
        if with_osv:
            status.osv_malicious = {"keyv": {"6.0.0"}}
            status.osv_advisory_ids = {"keyv@6.0.0": {"MAL-2026-11524"}}
        return status

    assert (ls.build_findings([repo(False)])[0]["id"]
            == ls.build_findings([repo(True)])[0]["id"])


def test_repeated_payload_filenames_keep_distinct_ids() -> None:
    """One worm drops the same name in several directories, and two findings
    sharing an id lose one occurrence to deduplication."""
    status = ls.RepoStatus(name="app", path="/t/app")
    status.payload_files = ["/t/app/a/bun_environment.js", "/t/app/b/bun_environment.js"]
    findings = ls.build_findings([status])
    assert len({f["id"] for f in findings}) == 2


def test_every_file_carrying_a_poison_is_named_as_evidence(tmp_path: Path) -> None:
    """Attribution is per file: first-file-wins dropped every later
    occurrence from the evidence list."""
    status = ls.RepoStatus(name="t", path=str(tmp_path))
    for name in ("a", "b"):
        lockfile = tmp_path / name / "yarn.lock"
        lockfile.parent.mkdir()
        lockfile.write_text('keyv@6.0.0:\n  version "6.0.0"\n', encoding="utf-8")
        ls.scan_lockfile(lockfile, status)
    assert ls.build_findings([status])[0]["source_files"] == ["a/yarn.lock", "b/yarn.lock"]


def test_an_osv_only_package_is_attributed_from_its_advisory() -> None:
    """The prose beside the JSON names the campaign, so the JSON must too."""
    status = ls.RepoStatus(name="app", path="/t/app")
    status.osv_malicious = {"not-a-table-package": {"1.0.0"}}
    status.osv_advisory_ids = {"not-a-table-package@1.0.0": {"MAL-2026-11524"}}
    assert "Shai-Hulud" in ls.build_findings([status], lookup=False)[0]["campaign"]


def test_rendering_a_report_opens_no_connection(tmp_path: Path, monkeypatch) -> None:
    """A report generator runs over files already on disk; a request per
    finding is traffic the caller never asked for."""
    def explode(*_args, **_kwargs):
        raise AssertionError("machine mode opened a connection")

    monkeypatch.setattr(ls, "_open_https", explode)
    monkeypatch.setattr(ls, "_ADVISORY_CACHE", {})
    monkeypatch.setattr(ls, "OVERLAY_PATH", tmp_path / "overlay.json")
    status = ls.RepoStatus(name="app", path="/t/app")
    status.osv_malicious = {"unknown-package": {"1.0.0"}}
    status.osv_advisory_ids = {"unknown-package@1.0.0": {"MAL-2026-11524"}}
    assert ls.build_findings([status], lookup=True)[0]["campaign"] is not None


# --------------------------------------------------------------------------
# The status document.
# --------------------------------------------------------------------------

def _status_with_state(tmp_path: Path, monkeypatch, payload: str) -> dict[str, Any]:
    """The status document for one written updater state file."""
    monkeypatch.setenv("LOCKFILE_SENTINEL_CACHE", str(tmp_path))
    state = tmp_path / "logs" / "update-osv-scanner.state.json"
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(payload, encoding="utf-8")
    return ls.gather_status(tmp_path / "missing.json", osv_bin=None)


@pytest.mark.parametrize(
    "literal", ["true", "NaN", "1e309", "1e300", "-5", "4102444800"])
def test_an_implausible_stamp_reads_as_unknown(
    tmp_path: Path, monkeypatch, literal: str
) -> None:
    """Booleans pass an int check, NaN and 1e309 pass a finite one, 1e300
    overflows the renderer, a negative predates every run, and a future stamp
    reads as fresh forever. Each of the six arrived as its own finding.

    allow_nan=False because the default emits bare NaN and reads it back, so
    the round trip would accept a document no other JSON parser will."""
    doc = _status_with_state(tmp_path, monkeypatch, f'{{"lastCheckUnix": {literal}}}')
    engine = doc["sources"]["osv_scanner"]
    assert engine["version_checked_unix"] is None
    assert engine["state"] == "unknown"
    json.loads(json.dumps(doc, allow_nan=False))
    assert ls.render_status_human(doc)


def test_a_recent_stamp_cannot_vouch_for_a_missing_binary(
    tmp_path: Path, monkeypatch
) -> None:
    """A check stamp outlives the binary it described."""
    doc = _status_with_state(tmp_path, monkeypatch,
                             json.dumps({"lastCheckUnix": time.time()}))
    assert doc["sources"]["osv_scanner"]["state"] == "unknown"
    assert doc["overall"]["exit_code"] == 2


def test_overlay_status_follows_what_the_sweep_would_accept(
    tmp_path: Path, monkeypatch
) -> None:
    """A document the sweep rejects must not be reported as fresh inputs."""
    monkeypatch.setenv("LOCKFILE_SENTINEL_CACHE", str(tmp_path))
    overlay = tmp_path / "compromised-npm-packages.json"
    overlay.write_text(json.dumps({
        "generated_utc": "2026-08-15T00:00:00Z", "packages": {},
    }), encoding="utf-8")
    source = ls.gather_status(overlay, osv_bin=None)["sources"]["overlay"]
    assert (source["present"], source["state"]) == (False, "absent")


def test_overlay_counts_and_stamp_are_never_echoed_unvalidated(
    tmp_path: Path, monkeypatch
) -> None:
    """A corrupted overlay carried NaN counts and an unparseable stamp
    straight into a document whose schema forbids both."""
    monkeypatch.setenv("LOCKFILE_SENTINEL_CACHE", str(tmp_path))
    overlay = tmp_path / "compromised-npm-packages.json"
    overlay.write_text(
        '{"generated_utc": "not-a-date", "package_count": NaN, '
        '"version_count": true, "packages": {"keyv": ["6.0.0", "6.0.1"]}}',
        encoding="utf-8",
    )
    source = ls.gather_status(overlay, osv_bin=None)["sources"]["overlay"]
    assert (source["package_count"], source["version_count"]) == (1, 2)
    assert source["generated_utc"] is None
    json.loads(json.dumps({"sources": source}, allow_nan=False))


def test_a_future_overlay_stamp_reads_as_unknown(tmp_path: Path, monkeypatch) -> None:
    """The overlay's own stamp goes through the same bound as the state
    files, or it would read as fresh forever."""
    monkeypatch.setenv("LOCKFILE_SENTINEL_CACHE", str(tmp_path))
    overlay = tmp_path / "compromised-npm-packages.json"
    overlay.write_text(json.dumps({
        "generated_utc": "2100-01-01T00:00:00Z", "packages": {"keyv": ["6.0.0"]},
    }), encoding="utf-8")
    source = ls.gather_status(overlay, osv_bin=None)["sources"]["overlay"]
    assert source["generated_unix"] is None
    assert source["state"] == "unknown"


def test_status_writes_the_file_the_caller_asked_for(tmp_path: Path, monkeypatch) -> None:
    """A pipeline that asked for a file and got stdout lost its document."""
    monkeypatch.setenv("LOCKFILE_SENTINEL_CACHE", str(tmp_path))
    target = tmp_path / "status.json"
    ls.report_status(tmp_path / "missing.json", osv_bin=None,
                     as_json=True, output=str(target))
    assert json.loads(target.read_text(encoding="utf-8"))["schema"]["name"] == (
        "lockfile-sentinel-status"
    )


# --------------------------------------------------------------------------
# The lock, and the refusal.
# --------------------------------------------------------------------------

def test_the_overlay_lock_admits_one_holder_and_needs_no_age_rule(
    tmp_path: Path,
) -> None:
    """Every timestamp takeover protocol tried in review had a theft race one
    level down; the kernel's lock has none and dies with its holder."""
    overlay = tmp_path / "compromised-npm-packages.json"
    lock = tmp_path / "compromised-npm-packages.json.lock"
    held = ls._acquire_overlay_lock(overlay, lock)
    assert held is not None
    assert ls._acquire_overlay_lock(overlay, lock) is None
    ls._release_overlay_lock(held)
    again = ls._acquire_overlay_lock(overlay, lock)
    assert again is not None
    ls._release_overlay_lock(again)


def test_a_refused_root_replaces_a_stale_report_and_prints_one(
    tmp_path: Path, capsys
) -> None:
    """A consumer polling the output path kept reading the previous run's
    complete report, and a caller without one got nothing to parse."""
    target = tmp_path / "report.json"
    target.write_text('{"invocation": {"complete": true}}', encoding="utf-8")
    missing = tmp_path / "missing-root"
    overlay_layer = {"requested": False, "state": "not_requested",
                     "reason_code": None, "message": None}
    for output in (str(target), None):
        argv = ["--json", "--no-osv", "--no-trivy", "--no-overlay", "--no-refresh"]
        if output:
            argv += ["-o", output]
        ls._write_root_refusal(
            ls._build_parser().parse_args(argv), [missing],
            [(missing, "does not exist")], overlay_layer,
            "00000000-0000-0000-0000-000000000000", "2026-08-15T00:00:00Z",
        )
    written = json.loads(target.read_text(encoding="utf-8"))
    printed = json.loads(capsys.readouterr().out)
    for report in (written, printed):
        assert report["invocation"]["complete"] is False
        assert report["errors"][0]["code"] == "root_unreadable"


# --------------------------------------------------------------------------
# Elsewhere in the stack.
# --------------------------------------------------------------------------

def test_the_tool_version_probe_runs_once_per_binary(monkeypatch) -> None:
    """An unmemoised probe spawned a process per snapshot."""
    calls: list[object] = []

    def fake_run(cmd, **_kwargs):
        calls.append(cmd)
        raise OSError("not runnable")

    monkeypatch.setattr(ls, "_run_bounded", fake_run)
    ls._TOOL_VERSION_CACHE.pop(("probe-binary", "v"), None)
    assert ls._tool_version("probe-binary", "v") is None
    assert ls._tool_version("probe-binary", "v") is None
    assert len(calls) == 1


def test_neither_program_follows_a_redirect_off_https() -> None:
    """A 301 to http would hand the overlay or an advisory to whoever sits on
    the path, and checking only the first URL leaves that hop open. Each file
    carries its own handler, because each ships alone."""
    # HTTPError in one file and URLError in the other, each what its caller's
    # own failure path already handles; URLError is the parent of both.
    for handler in (ls._HttpsOnlyRedirects(), us.HttpsOnlyRedirects()):
        with pytest.raises(ls.urllib.error.URLError):
            handler.redirect_request(
                ls.urllib.request.Request("https://example.invalid/x"),
                None, 301, "Moved Permanently", {}, "http://example.invalid/y",
            )
    with pytest.raises(ValueError):
        ls._open_https(ls.urllib.request.Request("http://example.invalid/x"), timeout=1)


def test_the_changelog_describes_the_lock_that_shipped() -> None:
    """The entry named a staleness heuristic the implementation no longer
    has, which is the half a reader trusts."""
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "operating system itself releases" in changelog
    assert "older than fifteen minutes" not in changelog


def test_no_docstring_in_the_scanner_narrates_a_former_behaviour() -> None:
    """Comments state the present constraint; a change narrative belongs to
    the commit message, and two docstrings had drifted into one."""
    source = (ROOT / "lockfile_sentinel.py").read_text(encoding="utf-8")
    assert "advisory ids" not in source.split("def _finding_id")[1][:600]
