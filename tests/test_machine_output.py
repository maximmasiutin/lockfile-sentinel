# Lockfile Sentinel 0.2.0
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Maxim Masiutin
"""The machine-output contract: envelope, coverage, findings, errors, lifecycle.

Every case here pins a promise the report makes to a consumer that never sees
the human output: that a state named in the schema means what the schema says,
that counts reconcile, that two runs over the same tree serialize identically,
and that nothing short of a completed run ever claims the final path. The
consumer this protects is a pipeline that has twice recorded a coverage failure
as a clean scan, both times because the failure was legible only in prose."""

# pylint: disable=protected-access
# The atomic writer, the coverage builders and the normaliser are private
# helpers, and the properties pinned here are theirs: reaching them through
# main() would prove less than the report contract already requires.

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import lockfile_sentinel as ls  # noqa: E402  # pylint: disable=wrong-import-position

def _must_not_open(*_args, **_kwargs):
    """A network seam that fails the test rather than reaching the wire."""
    raise AssertionError("machine mode opened a connection")


INVOCATION_ID = "00000000-0000-0000-0000-000000000000"
STARTED = "2026-08-15T00:00:00Z"
FINISHED = "2026-08-15T00:00:05Z"


def _overlay_layer(state: str = "completed") -> dict[str, Any]:
    """A minimal overlay layer object in the shared vocabulary."""
    return {
        "requested": state != "not_requested",
        "state": state,
        "reason_code": None,
        "message": None,
        "path": "/cache/compromised-npm-packages.json",
        "generated_utc": "2026-08-15T00:00:00Z",
        "digest_sha256": None,
        "package_count": 900,
        "version_count": 1500,
        "refresh_requested": True,
        "refresh_outcome": "throttled",
        "stale_after_hours": 24.0,
    }


def _layers(
    statuses: list[ls.RepoStatus],
    osv_requested: bool = True,
    osv_bin: str | None = "osv-scanner-not-actually-run",
    trivy_requested: bool = True,
    trivy_bin: str | None = None,
    overlay_state: str = "completed",
    osv_run: ls.OsvRunReport | None = None,
) -> dict[str, dict[str, Any]]:
    discovered = sum(len(s.lockfiles) for s in statuses)
    resolved = sum(s.osv_resolved_count for s in statuses)
    return {
        "builtin": ls.builtin_layer(),
        "overlay": _overlay_layer(overlay_state),
        "osv": ls.osv_layer(osv_requested, osv_bin, osv_run or ls.OsvRunReport(),
                            discovered, resolved),
        "trivy": ls.trivy_layer(trivy_requested, trivy_bin, statuses),
    }


def _report(
    statuses: list[ls.RepoStatus],
    layers: dict[str, dict[str, Any]] | None = None,
    complete: bool = True,
    finished: str | None = FINISHED,
    osv_run: ls.OsvRunReport | None = None,
) -> dict[str, Any]:
    osv_run = osv_run or ls.OsvRunReport()
    layers = layers if layers is not None else _layers(statuses, osv_run=osv_run)
    return ls.build_report(
        statuses,
        roots=["/t"],
        include_node_modules=False,
        layers=layers,
        errors=ls.collect_errors(layers, statuses, osv_run),
        osv_run=osv_run,
        invocation_id=INVOCATION_ID,
        started_utc=STARTED,
        finished_utc=finished,
        complete=complete,
    )


def _resolved_repo() -> ls.RepoStatus:
    """One repository whose single lockfile resolved cleanly."""
    status = ls.RepoStatus(name="t", path="/t")
    status.has_npm = True
    status.lockfiles = ["/t/package-lock.json"]
    status.npm_files = ["/t/package-lock.json"]
    status.read_files = ["/t/package-lock.json"]
    status.osv_resolved_count = 1
    status.osv_checked = True
    return status


def example_report() -> dict[str, Any]:
    """The committed example report, rebuilt from the same code that ships.

    A finished run with findings and one unreadable manifest, so the example
    demonstrates the case the format exists for: findings present, coverage
    incomplete, complete false with a finish stamp, and exit 2."""
    vulnerable = ls.RepoStatus(name="vulnerable-app", path="/t/vulnerable-app")
    vulnerable.has_npm = True
    vulnerable.npm_files = [
        "/t/vulnerable-app/package.json", "/t/vulnerable-app/package-lock.json",
    ]
    vulnerable.read_files = ["/t/vulnerable-app/package-lock.json"]
    vulnerable.unreadable_files = ["/t/vulnerable-app/package.json"]
    vulnerable.lockfiles = ["/t/vulnerable-app/package-lock.json"]
    vulnerable.present_versions = {"keyv": {"6.0.0"}}
    vulnerable.poisoned_versions = {"keyv": {"6.0.0"}}
    vulnerable.osv_malicious = {"keyv": {"6.0.0"}}
    vulnerable.osv_advisory_ids = {"keyv@6.0.0": {"MAL-2026-11524"}}
    vulnerable.evidence = {
        ("resolved", "keyv", "6.0.0"): {"/t/vulnerable-app/package-lock.json"},
    }
    vulnerable.payload_files = ["/t/vulnerable-app/scripts/bun_environment.js"]
    vulnerable.flagged_lockfiles = {"/t/vulnerable-app/package-lock.json"}
    vulnerable.osv_resolved_count = 1
    vulnerable.osv_checked = True

    clean = _resolved_repo()
    clean.name = "clean-lib"
    clean.path = "/t/clean-lib"
    clean.lockfiles = ["/t/clean-lib/package-lock.json"]
    clean.npm_files = ["/t/clean-lib/package-lock.json"]
    clean.read_files = ["/t/clean-lib/package-lock.json"]

    statuses = [vulnerable, clean]
    # The submitted list carries both lockfiles so the example reconciles:
    # inputs.lockfiles_submitted must equal the sum of the per-repository
    # coverage.osv.submitted counts, which is the documented invariant.
    osv_run = ls.OsvRunReport(
        submitted=[
            "/t/vulnerable-app/package-lock.json",
            "/t/clean-lib/package-lock.json",
        ],
        duration_ms=1200,
    )
    layers = _layers(statuses, trivy_requested=False, osv_run=osv_run)
    return ls.build_report(
        statuses,
        roots=["/t"],
        include_node_modules=False,
        layers=layers,
        errors=ls.collect_errors(layers, statuses, osv_run),
        osv_run=osv_run,
        invocation_id=INVOCATION_ID,
        started_utc=STARTED,
        finished_utc=FINISHED,
        complete=ls.report_is_complete(layers, statuses),
    )


# --------------------------------------------------------------------------
# The envelope.
# --------------------------------------------------------------------------

def test_the_json_report_is_an_envelope_not_a_bare_array() -> None:
    """The bare array could not answer what ran: no schema or tool version, no
    roots, no requested layers. A consumer of the envelope decides those from
    the file alone, so each block must actually carry them."""
    report = json.loads(ls.render_json(_report([_resolved_repo()])))
    assert report["schema"] == {"name": "lockfile-sentinel-report", "version": 1}
    assert report["tool"] == {"name": "lockfile-sentinel", "version": ls.__version__}
    inv = report["invocation"]
    assert inv["complete"] is True
    assert inv["finished_utc"] == FINISHED
    assert inv["roots"] == ["/t"]
    assert inv["include_node_modules"] is False
    assert inv["requested_layers"] == ["builtin", "overlay", "osv", "trivy"]
    assert report["repositories"][0]["name"] == "t"
    for block in ("layers", "inputs", "totals", "findings", "errors"):
        assert block in report


def test_a_snapshot_write_never_claims_to_be_final() -> None:
    """The report is rewritten after every OSV batch, so a killed run leaves
    valid JSON behind. A snapshot must be distinguishable from a final report
    from the file alone: complete false and a null finish stamp are the
    distinction a consumer checks."""
    report = _report([], complete=False, finished=None)
    assert report["invocation"]["complete"] is False
    assert report["invocation"]["finished_utc"] is None


def test_snapshot_output_is_deterministic_for_a_fixed_invocation() -> None:
    """Nothing in the report reads the clock at render time: the timestamps
    are inputs. Two snapshots of the same state must be byte-identical, so a
    diff between them is a change in findings, never noise."""
    first = ls.render_json(_report([_resolved_repo()], complete=False, finished=None))
    second = ls.render_json(_report([_resolved_repo()], complete=False, finished=None))
    assert first == second


def test_the_published_schema_and_example_match_what_the_code_writes() -> None:
    """The schema and example files are what a consumer builds against, so a
    field renamed in the builder and not in them would ship a contract the
    tool no longer honours. The example is regenerated from the same helper
    and compared whole; the schema's required lists are checked against the
    rendered document at every level that has one."""
    root = Path(__file__).resolve().parent.parent
    example = json.loads(
        (root / "lockfile-sentinel-report.example.json").read_text(encoding="utf-8")
    )
    schema = json.loads(
        (root / "lockfile-sentinel-report.schema.json").read_text(encoding="utf-8")
    )
    rendered = json.loads(ls.render_json(example_report()))
    assert example == rendered
    assert set(schema["required"]) <= set(rendered)
    assert set(schema["properties"]["invocation"]["required"]) <= set(rendered["invocation"])
    assert set(schema["$defs"]["repository"]["required"]) <= set(rendered["repositories"][0])
    assert set(schema["$defs"]["finding"]["required"]) <= set(rendered["findings"][0])
    assert set(schema["$defs"]["error"]["required"]) <= set(rendered["errors"][0])
    for layer in rendered["layers"].values():
        assert set(schema["$defs"]["layer"]["required"]) <= set(layer)
    assert schema["properties"]["schema"]["properties"]["name"]["const"] == (
        rendered["schema"]["name"]
    )
    states = set(schema["$defs"]["coverage_state"]["enum"])
    for repo in rendered["repositories"]:
        assert repo["coverage"]["osv"]["state"] in states
        assert repo["coverage"]["trivy"]["state"] in states


# --------------------------------------------------------------------------
# Coverage: a state and the counts behind it, never a boolean.
# --------------------------------------------------------------------------

def test_a_rejected_lockfile_reports_partial_coverage_with_counts() -> None:
    """The plan's first acceptance scenario: three lockfiles, one rejected,
    reports partial with submitted and resolved counts, and the run is not
    complete, which is what drives exit 2."""
    status = _resolved_repo()
    status.lockfiles = [f"/t/{n}/package-lock.json" for n in ("a", "b", "c")]
    status.osv_resolved_count = 2
    status.osv_failed_count = 1
    status.osv_checked = False
    coverage = ls._repo_osv_coverage(status, requested=True, available=True)
    assert coverage["state"] == "partial"
    assert coverage["reason_codes"] == ["scanner_rejected_lockfile"]
    assert coverage["discovered"] == 3
    assert coverage["submitted"] == 3
    assert coverage["resolved"] == 2
    assert coverage["failed"] == 1
    assert ls.report_is_complete(_layers([status]), [status]) is False


def test_a_missing_scanner_is_unavailable_when_requested_and_policy_when_declined() -> None:
    """The plan's second acceptance scenario. A machine without osv-scanner is
    a coverage gap when the layer was requested, and a recorded policy choice
    under --no-osv; the two must never share a state."""
    status = _resolved_repo()
    status.osv_resolved_count = 0
    status.osv_checked = False
    requested = ls._repo_osv_coverage(status, requested=True, available=False)
    assert requested["state"] == "unavailable"
    assert requested["reason_codes"] == ["binary_not_found"]
    declined = ls._repo_osv_coverage(status, requested=False, available=False)
    assert declined["state"] == "not_requested"
    layer = ls.osv_layer(True, None, ls.OsvRunReport(), 1, 0)
    assert layer["state"] == "unavailable"
    assert layer["reason_code"] == "binary_not_found"
    assert ls.report_is_complete(
        _layers([status], osv_bin=None), [status]) is False
    declined_layers = _layers([status], osv_requested=False, osv_bin=None)
    status.unreadable_files = []
    assert ls.report_is_complete(declined_layers, [status]) is True


def test_a_repository_with_no_lockfile_is_not_applicable_not_failed() -> None:
    """Nothing for the layer to do is a different fact from a layer that broke."""
    status = ls.RepoStatus(name="t", path="/t")
    coverage = ls._repo_osv_coverage(status, requested=True, available=True)
    assert coverage["state"] == "not_applicable"
    assert not coverage["reason_codes"]


def test_trivy_coverage_distinguishes_nothing_to_confirm_from_could_not_run() -> None:
    """A clean estate completes the corroboration layer; a missing binary with
    findings to corroborate does not."""
    clean = ls.RepoStatus(name="t", path="/t")
    assert ls._repo_trivy_coverage(clean, True, False)["state"] == "not_applicable"
    flagged = ls.RepoStatus(name="t", path="/t")
    flagged.flagged_lockfiles = {"/t/package-lock.json"}
    missing = ls._repo_trivy_coverage(flagged, True, False)
    assert missing["state"] == "unavailable"
    assert missing["reason_codes"] == ["binary_not_found"]
    layer = ls.trivy_layer(True, None, [flagged])
    assert layer["state"] == "unavailable"
    quiet = ls.trivy_layer(True, None, [clean])
    assert quiet["state"] == "completed"
    assert quiet["reason_code"] == "nothing_to_confirm"


def test_an_unreadable_file_makes_the_run_incomplete() -> None:
    """An unreadable applicable input is a coverage gap, so exit 2 follows."""
    status = _resolved_repo()
    status.unreadable_files = ["/t/package.json"]
    assert ls.report_is_complete(_layers([status]), [status]) is False


def test_an_empty_lockfile_counts_as_resolved_not_as_a_gap(tmp_path: Path) -> None:
    """An empty lockfile has nothing to resolve, which is the verdict the
    scanner itself returns for one submitted alone (exit 128), so it counts
    as resolved and a scaffold file cannot fail a whole scan."""
    empty = tmp_path / "package-lock.json"
    empty.write_text("", encoding="utf-8")
    run = ls.OsvRunReport()
    findings, processed = ls.run_osv_scanner(
        "osv-scanner-never-invoked", [str(empty)], 10, 10, run_report=run
    )
    assert not findings
    assert ls._normalize_path(str(empty)) in processed
    assert run.skipped_empty == [str(empty)]
    assert not run.submitted


# --------------------------------------------------------------------------
# Child output: bounded in memory, with no temporary pathname lifecycle.
# --------------------------------------------------------------------------

def test_bounded_child_accepts_the_exact_stdout_limit() -> None:
    """The limit is inclusive, so a valid document at the boundary survives."""
    result = ls._run_bounded(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 16)"],
        timeout=10, stdout_limit=16,
    )
    assert result.stdout == "x" * 16


def test_bounded_child_kills_output_one_byte_over_the_limit() -> None:
    """One byte beyond the contract fails instead of being silently cut."""
    with pytest.raises(ls.ChildOutputTooLarge):
        ls._run_bounded(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 17)"],
            timeout=10, stdout_limit=16,
        )


def test_bounded_child_drains_both_pipes_and_keeps_only_stderr_tail() -> None:
    """Full pipes cannot deadlock, and only the diagnostic tail is retained."""
    script = (
        "import sys, threading; "
        "a=threading.Thread(target=lambda:sys.stdout.buffer.write(b'o'*2000000)); "
        "b=threading.Thread(target=lambda:sys.stderr.buffer.write(b'e'*2000000)); "
        "a.start(); b.start(); a.join(); b.join()"
    )
    result = ls._run_bounded(
        [sys.executable, "-c", script], timeout=10,
        stdout_limit=2_000_000, stderr_limit=16,
    )
    assert len(result.stdout) == 2_000_000
    assert result.stderr == "[earlier stderr truncated]\n" + "e" * 16


def test_bounded_child_timeout_reaps_the_process() -> None:
    """A silent child cannot outlive the timeout path."""
    started = time.monotonic()
    with pytest.raises(ls.subprocess.TimeoutExpired):
        ls._run_bounded(
            [sys.executable, "-c", "import time; time.sleep(60)"], timeout=1,
        )
    assert time.monotonic() - started < 5


def test_bounded_child_does_not_wait_for_an_inherited_pipe() -> None:
    """A background descendant holding the pipe cannot strand its reader."""
    script = (
        "import subprocess, sys; "
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)']); "
        "print('parent done')"
    )
    started = time.monotonic()
    result = ls._run_bounded([sys.executable, "-c", script], timeout=2)
    assert result.stdout.splitlines() == ["parent done"]
    assert time.monotonic() - started < 2


def test_osv_output_overflow_is_a_structured_retryable_failure(monkeypatch) -> None:
    """Oversized JSON is an outage, never a clean scanner response."""
    def overflow(*_args, **_kwargs):
        raise ls.ChildOutputTooLarge("too much")

    monkeypatch.setattr(ls, "_run_bounded", overflow)
    failure: dict[str, str] = {}
    assert ls._run_osv_batch("osv-scanner", ["one.lock"], 10, failure=failure) is None
    assert failure == {"cause": "output_too_large"}
    run = ls.OsvRunReport(
        unavailable=["one.lock"], output_too_large=["one.lock"]
    )
    errors = ls.collect_errors(_layers([]), [], run)
    oversized = [error for error in errors if error["code"] == "child_output_too_large"]
    assert oversized and oversized[0]["retryable"] is True


def test_trivy_output_overflow_is_distinct_from_an_ordinary_failure(monkeypatch) -> None:
    """Trivy overflow receives the same stable structured error code."""
    def overflow(*_args, **_kwargs):
        raise ls.ChildOutputTooLarge("too much")

    monkeypatch.setattr(ls, "_run_bounded", overflow)
    status = ls.RepoStatus(name="app", path="/app")
    status.flagged_lockfiles = {"/app/package-lock.json"}
    ls._trivy_recheck_repo(status, "trivy", 10)
    errors = ls._repository_errors(status)
    assert status.trivy_output_too_large_count == 1
    assert [error["code"] for error in errors] == ["child_output_too_large"]


# --------------------------------------------------------------------------
# Findings: one fact, however many layers saw it.
# --------------------------------------------------------------------------

def _poisoned_repo() -> ls.RepoStatus:
    """A repository where both layers flagged keyv 6.0.0 and Trivy agreed."""
    status = ls.RepoStatus(name="app", path="/t/app")
    status.poisoned_versions = {"keyv": {"6.0.0"}}
    status.osv_malicious = {"keyv": {"6.0.0"}}
    status.osv_advisory_ids = {"keyv@6.0.0": {"MAL-2026-11524"}}
    status.trivy_confirmed = {"keyv@6.0.0": {"CVE-0000-0000"}}
    status.evidence = {("resolved", "keyv", "6.0.0"): {"/t/app/package-lock.json"}}
    return status


def test_both_layers_seeing_one_version_is_one_finding_with_two_layers() -> None:
    """The equivalence between the summary maps is stated once, here, rather
    than rediscovered by every consumer."""
    findings = ls.build_findings([_poisoned_repo()])
    assert len(findings) == 1
    finding = findings[0]
    assert finding["kind"] == "malicious_resolved"
    assert finding["detection_layers"] == ["offline_table", "osv"]
    assert finding["advisories"] == ["MAL-2026-11524"]
    assert finding["campaign"] == "shai-hulud"
    assert finding["trivy_confirmed"] == ["CVE-0000-0000"]
    assert finding["source_files"] == ["package-lock.json"]


def test_ranges_and_payloads_are_their_own_finding_kinds() -> None:
    """A reachable range and a payload artifact are facts of different kinds,
    not versions of a resolved pin."""
    status = ls.RepoStatus(name="app", path="/t/app")
    status.poisoned_ranges = {"keyv": {"^6.0.0"}}
    status.payload_files = ["/t/app/scripts/bun_environment.js"]
    kinds = {f["kind"]: f for f in ls.build_findings([status])}
    assert set(kinds) == {"malicious_range", "payload_artifact"}
    assert kinds["malicious_range"]["range"] == "^6.0.0"
    assert kinds["malicious_range"]["version"] is None
    assert kinds["payload_artifact"]["artifact"] == "bun_environment.js"
    assert kinds["payload_artifact"]["campaign"] == "shai-hulud"
    assert kinds["payload_artifact"]["source_files"] == ["scripts/bun_environment.js"]


def test_finding_ids_are_stable_across_runs_and_distinct_across_repos() -> None:
    """The id is derived from the fact alone, never the evidence, so a run
    without OSV and a later enriched run correlate on the same id, and the id
    changes only when the subject does."""
    first = ls.build_findings([_poisoned_repo()])[0]["id"]
    second = ls.build_findings([_poisoned_repo()])[0]["id"]
    assert first == second
    unenriched = _poisoned_repo()
    unenriched.osv_malicious = {}
    unenriched.osv_advisory_ids = {}
    assert ls.build_findings([unenriched])[0]["id"] == first
    moved = _poisoned_repo()
    moved.path = "/t/elsewhere"
    assert ls.build_findings([moved])[0]["id"] != first


def test_an_osv_only_package_still_gets_its_campaign_from_the_advisory() -> None:
    """The human report attributes an OSV-only hit through the advisory text,
    and the JSON must not lose that attribution; lookup=False keeps the
    resolution to the built-in notes, honouring --no-advisory-lookup."""
    status = ls.RepoStatus(name="app", path="/t/app")
    status.osv_malicious = {"not-a-table-package": {"1.0.0"}}
    status.osv_advisory_ids = {"not-a-table-package@1.0.0": {"MAL-2026-11524"}}
    finding = ls.build_findings([status], lookup=False)[0]
    assert finding["campaign"] is not None
    assert "Shai-Hulud" in finding["campaign"]


def test_scan_lockfile_attributes_the_poison_to_the_file_that_carried_it(
    tmp_path: Path,
) -> None:
    """The findings array names its evidence, which needs the scanner to say
    which file first recorded each poisoned coordinate."""
    lockfile = tmp_path / "yarn.lock"
    lockfile.write_text('keyv@6.0.0:\n  version "6.0.0"\n', encoding="utf-8")
    status = ls.RepoStatus(name="t", path=str(tmp_path))
    ls.scan_lockfile(lockfile, status)
    assert status.evidence[("resolved", "keyv", "6.0.0")] == {str(lockfile)}


# --------------------------------------------------------------------------
# Errors: stable codes, bounded list.
# --------------------------------------------------------------------------

def test_unreadable_files_become_structured_errors() -> None:
    """A manifest and a lockfile that could not be read carry distinct codes."""
    status = _resolved_repo()
    status.unreadable_files = ["/t/package.json", "/t/pnpm-lock.yaml"]
    errors = ls.collect_errors(_layers([status]), [status], ls.OsvRunReport())
    codes = {e["file"]: e["code"] for e in errors}
    assert codes["/t/package.json"] == "manifest_unreadable"
    assert codes["/t/pnpm-lock.yaml"] == "lockfile_unreadable"


def test_the_error_list_is_bounded_and_says_when_it_was_cut() -> None:
    """A truncated list that does not say so reads as the whole story."""
    status = _resolved_repo()
    status.unreadable_files = [f"/t/{i}/package.json" for i in range(250)]
    errors = ls.collect_errors(_layers([status]), [status], ls.OsvRunReport())
    assert len(errors) == ls._ERROR_LIMIT + 1
    assert errors[-1]["code"] == "error_list_truncated"


# --------------------------------------------------------------------------
# The lifecycle: partial and final, both atomic.
# --------------------------------------------------------------------------

def test_write_atomic_leaves_the_content_and_no_temp_files(tmp_path: Path) -> None:
    """A replace-in-place write leaves the new content and nothing else."""
    target = tmp_path / "report.json"
    ls._write_atomic(target, "{}")
    ls._write_atomic(target, '{"second": true}')
    assert target.read_text(encoding="utf-8") == '{"second": true}'
    assert [p.name for p in tmp_path.iterdir()] == ["report.json"]


def test_write_atomic_raises_rather_than_half_writing(tmp_path: Path) -> None:
    """A write that cannot land must fail loudly, never leave a fragment."""
    target = tmp_path / "is-a-directory"
    target.mkdir()
    with pytest.raises(OSError):
        ls._write_atomic(target, "{}")


def test_refresh_overlay_respects_a_live_lock(tmp_path: Path, monkeypatch) -> None:
    """Two concurrent runs must not interleave writes to the overlay. A held
    lock defers to the holder rather than fetching a second copy, and the
    network must not be touched at all on that path."""
    def explode(*_args, **_kwargs):
        raise AssertionError("the locked path must not fetch")

    monkeypatch.setattr(ls, "_open_https", explode)
    overlay = tmp_path / "compromised-npm-packages.json"
    lock = tmp_path / "compromised-npm-packages.json.lock"
    held = ls._acquire_overlay_lock(overlay, lock)
    assert held is not None
    try:
        assert ls.refresh_overlay(overlay, min_interval=0) == "locked"
    finally:
        ls._release_overlay_lock(held)


def test_fetches_refuse_plain_http_and_downgrade_redirects() -> None:
    """Every URL this program fetches is https, and a server's redirect must
    not be able to quietly change that: a 301 to http:// would hand the
    overlay or an advisory to whoever sits on the path."""
    with pytest.raises(ValueError):
        ls._open_https(ls.urllib.request.Request("http://example.invalid/x"), timeout=1)
    handler = ls._HttpsOnlyRedirects()
    with pytest.raises(ls.urllib.error.HTTPError):
        handler.redirect_request(
            ls.urllib.request.Request("https://example.invalid/x"),
            None, 301, "Moved Permanently", {}, "http://example.invalid/y",
        )


def test_refresh_overlay_reports_throttled_when_the_copy_is_fresh(tmp_path: Path) -> None:
    """The throttle answers with its own word, so the report can tell a fresh
    copy from a fetch that just happened."""
    overlay = tmp_path / "compromised-npm-packages.json"
    overlay.write_text("{}", encoding="utf-8")
    assert ls.refresh_overlay(overlay, min_interval=60) == "throttled"


# --------------------------------------------------------------------------
# Coverage holes the report must not paper over.
# --------------------------------------------------------------------------

def test_an_unreadable_subtree_is_recorded_and_fails_completeness(
    tmp_path: Path, monkeypatch
) -> None:
    """A directory the walk cannot enter hides everything beneath it, so it
    must surface as incomplete coverage with its own error code rather than
    read as a clean tree that happened to be small."""
    locked = tmp_path / "app" / "locked"
    locked.mkdir(parents=True)
    (locked / "package-lock.json").write_text("{}", encoding="utf-8")
    real = ls._list_directory

    def deny(current: Path):
        return None if current.name == "locked" else real(current)

    monkeypatch.setattr(ls, "_list_directory", deny)
    statuses, _index = ls.scan_root(tmp_path, include_node_modules=False)
    status = statuses[tmp_path / "app"]
    assert status.unreadable_dirs == [str(locked)]
    assert ls.report_is_complete(_layers([status]), [status]) is False
    errors = ls.collect_errors(_layers([status]), [status], ls.OsvRunReport())
    assert any(e["code"] == "directory_unreadable" for e in errors)


def test_empty_lockfile_submission_counts_reconcile() -> None:
    """A vacuously-resolved empty lockfile is inside resolved and outside
    submitted at both levels, so the run-level and repository-level counts
    agree instead of contradicting the documented reconciliation rule."""
    status = _resolved_repo()
    path = ls._normalize_path(status.lockfiles[0])
    ls.apply_osv_results({path: status}, {}, {path}, empty_paths={path})
    coverage = ls._repo_osv_coverage(status, requested=True, available=True)
    assert coverage["state"] == "completed"
    assert coverage["resolved"] == 1
    assert coverage["empty"] == 1
    assert coverage["submitted"] == 0


def test_a_scanner_outage_is_never_reported_as_a_rejected_lockfile(
    tmp_path: Path, monkeypatch
) -> None:
    """A timeout or spawn failure says nothing about the file in front of the
    scanner, so it lands in the retryable unavailable bucket, not in failed,
    and the reason code says the scanner did not answer."""
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text('{"lockfileVersion": 3}', encoding="utf-8")

    def no_answer(_bin, _paths, _timeout, _debug=False, failure=None):
        if failure is not None:
            failure["cause"] = "unavailable"

    monkeypatch.setattr(ls, "_run_osv_batch", no_answer)
    run = ls.OsvRunReport()
    findings, processed = ls.run_osv_scanner(
        "osv-scanner-never-invoked", [str(lockfile)], 10, 10, run_report=run
    )
    assert not findings
    assert not processed
    assert run.unavailable == [str(lockfile)]
    assert not run.failed
    layer = ls.osv_layer(True, "osv-scanner-never-invoked", run, 1, 0)
    assert layer["reason_code"] == "scanner_unavailable"
    errors = ls.collect_errors(_layers([]), [], run)
    outage = [e for e in errors if e["code"] == "osv_scanner_unavailable"]
    assert outage and outage[0]["retryable"] is True


def test_repeated_payload_filenames_get_distinct_ids() -> None:
    """One worm drops the same filename in several directories; two findings
    sharing an id would deduplicate into one occurrence lost."""
    status = ls.RepoStatus(name="app", path="/t/app")
    status.payload_files = [
        "/t/app/a/bun_environment.js", "/t/app/b/bun_environment.js",
    ]
    findings = ls.build_findings([status])
    assert len(findings) == 2
    assert findings[0]["id"] != findings[1]["id"]


def test_the_tool_version_probe_runs_once_per_binary(monkeypatch) -> None:
    """The layer objects are rebuilt per snapshot, so an unmemoised probe
    would spawn a subprocess per OSV batch."""
    calls: list[object] = []

    def fake_run(cmd, **_kwargs):
        calls.append(cmd)
        raise OSError("not runnable")

    monkeypatch.setattr(ls, "_run_bounded", fake_run)
    ls._TOOL_VERSION_CACHE.pop(("probe-once-binary", "v"), None)
    assert ls._tool_version("probe-once-binary", "v") is None
    assert ls._tool_version("probe-once-binary", "v") is None
    assert len(calls) == 1


def test_the_overlay_lock_admits_exactly_one_holder_at_a_time(tmp_path: Path) -> None:
    """The kernel's advisory lock is the arbiter: one open descriptor holds
    it across processes, a second taker defers, and releasing it makes the
    lock acquirable again. No timestamp heuristic exists to race, and a
    crashed holder's lock evaporates with its process."""
    overlay = tmp_path / "compromised-npm-packages.json"
    lock = tmp_path / "compromised-npm-packages.json.lock"
    first = ls._acquire_overlay_lock(overlay, lock)
    assert first is not None
    assert ls._acquire_overlay_lock(overlay, lock) is None
    ls._release_overlay_lock(first)
    second = ls._acquire_overlay_lock(overlay, lock)
    assert second is not None
    ls._release_overlay_lock(second)


def test_unreadable_dirs_are_stored_as_a_bounded_preview_with_a_full_total(
    tmp_path: Path,
) -> None:
    """A hostile tree can manufacture unreadable directories by the thousand,
    so the stored list is a preview; the total carries the real count and is
    what completeness and the JSON counts use."""
    statuses: dict[Path, ls.RepoStatus] = {}
    dirs = [tmp_path / "app" / f"d{i:04d}" for i in range(150)]
    ls._attribute([(tmp_path / "app", [], [])], tmp_path, [], statuses, {}, dirs)
    status = statuses[tmp_path / "app"]
    assert len(status.unreadable_dirs) == ls.UNREADABLE_DIRS_STORED_LIMIT
    assert status.unreadable_dir_total == 150
    repo = ls.repo_to_dict(status, True, True, True, True)
    assert repo["counts"]["dirs_unreadable"] == 150
    assert ls.report_is_complete(_layers([status]), [status]) is False


def test_a_systemic_outage_is_recorded_without_splitting_the_batch(
    tmp_path: Path, monkeypatch
) -> None:
    """A timeout is not a property of one file, so a whole group goes to the
    unavailable bucket in one invocation instead of one per lockfile."""
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
    ls.run_osv_scanner("osv-scanner-never-invoked", paths, 100, 10, run_report=run)
    assert calls == [3]
    assert run.unavailable == paths
    assert not run.failed


def test_snapshot_outcomes_never_mention_batches_that_have_not_run(
    tmp_path: Path, monkeypatch
) -> None:
    """A snapshot written between batches describes only what has happened:
    the submitted list grows batch by batch and the failure sets are synced
    before each callback, so an interrupted partial reconciles."""
    good = tmp_path / "good" / "package-lock.json"
    bad = tmp_path / "bad" / "package-lock.json"
    for lockfile in (good, bad):
        lockfile.parent.mkdir()
        lockfile.write_text('{"lockfileVersion": 3}', encoding="utf-8")

    def per_batch(_bin, batch, _timeout, _debug=False, failure=None):
        if batch == [str(good)]:
            return {}
        if failure is not None:
            failure["cause"] = "rejected"
        return None

    monkeypatch.setattr(ls, "_run_osv_batch", per_batch)
    run = ls.OsvRunReport()
    seen: list[tuple[list[str], list[str]]] = []

    def snapshot(_findings, _processed):
        seen.append((list(run.submitted), list(run.failed)))

    ls.run_osv_scanner(
        "osv-scanner-never-invoked", [str(good), str(bad)], 1, 10,
        on_batch_done=snapshot, run_report=run,
    )
    assert seen[0] == ([str(good)], [])
    assert seen[1] == ([str(good), str(bad)], [str(bad)])


def test_trivy_stays_pending_in_snapshots_until_every_flagged_file_was_submitted() -> None:
    """A snapshot written before the Trivy pass must not claim completed
    corroboration with zero submissions; the layer completes only once every
    flagged lockfile actually went in."""
    flagged = ls.RepoStatus(name="t", path="/t")
    flagged.flagged_lockfiles = {"/t/package-lock.json"}
    pending = ls.trivy_layer(True, "trivy-not-actually-run", [flagged])
    assert pending["state"] == "partial"
    assert pending["reason_code"] == "corroboration_pending"
    flagged.trivy_submitted_count = 1
    done = ls.trivy_layer(True, "trivy-not-actually-run", [flagged])
    assert done["state"] == "completed"


def test_refused_roots_invalidate_a_stale_report_on_disk(
    tmp_path: Path,
) -> None:
    """A consumer polling -o must never keep reading the previous run's
    complete: true after a run that refused its roots; the refusal envelope
    replaces it, finished, incomplete, and naming each refused root."""
    target = tmp_path / "report.json"
    target.write_text('{"invocation": {"complete": true}}', encoding="utf-8")
    args = ls._build_parser().parse_args(
        ["--json", "-o", str(target), "--no-osv", "--no-trivy",
         "--no-overlay", "--no-refresh"]
    )
    missing = tmp_path / "missing-root"
    ls._write_root_refusal(
        args, [missing], [(missing, "does not exist")],
        _overlay_layer("not_requested"), INVOCATION_ID, STARTED,
    )
    report = json.loads(target.read_text(encoding="utf-8"))
    assert report["invocation"]["complete"] is False
    assert report["invocation"]["finished_utc"] is not None
    assert report["errors"][0]["code"] == "root_unreadable"
    assert str(missing) in report["errors"][0]["message"]


def test_an_unrecognised_scanner_payload_is_a_failure_not_zero_findings() -> None:
    """The scanner emits results on every run, empty when it found nothing, so
    a payload without it is a shape this parser does not know. Reading it as
    zero findings marked every lockfile in the batch resolved on the strength
    of output nothing understood."""
    assert ls._extract_malicious_findings({"unexpected": []}) is None
    assert ls._extract_malicious_findings({"results": []}) == {}


def test_the_json_report_resolves_campaigns_without_the_network(
    tmp_path: Path, monkeypatch
) -> None:
    """Rendering a report must not put a request on the wire per finding, so
    machine mode answers from the caches and the built-in notes alone."""
    monkeypatch.setattr(ls, "_open_https", _must_not_open)
    monkeypatch.setattr(ls, "_ADVISORY_CACHE", {})
    monkeypatch.setattr(ls, "OVERLAY_PATH", tmp_path / "overlay.json")
    status = ls.RepoStatus(name="app", path="/t/app")
    status.osv_malicious = {"not-a-table-package": {"1.0.0"}}
    status.osv_advisory_ids = {"not-a-table-package@1.0.0": {"MAL-2026-11524"}}
    finding = ls.build_findings([status], lookup=True)[0]
    assert "Shai-Hulud" in finding["campaign"]


def test_a_refused_root_still_prints_a_report_to_stdout_under_json(
    tmp_path: Path, capsys
) -> None:
    """A caller of the machine-readable mode without -o would otherwise get
    exit 2 and nothing to parse."""
    args = ls._build_parser().parse_args(
        ["--json", "--no-osv", "--no-trivy", "--no-overlay", "--no-refresh"]
    )
    missing = tmp_path / "missing-root"
    ls._write_root_refusal(
        args, [missing], [(missing, "does not exist")],
        _overlay_layer("not_requested"), INVOCATION_ID, STARTED,
    )
    report = json.loads(capsys.readouterr().out)
    assert report["invocation"]["complete"] is False
    assert report["errors"][0]["code"] == "root_unreadable"


def test_a_tree_with_no_lockfiles_completes_the_osv_layer_without_a_scanner() -> None:
    """Nothing to scan completes the layer whatever is installed, the same
    way Trivy completes with nothing to confirm; a lockfile-free tree must
    not exit 2 over a scanner it never needed."""
    layer = ls.osv_layer(True, None, ls.OsvRunReport(), 0, 0)
    assert layer["state"] == "completed"
    assert layer["reason_code"] == "nothing_to_scan"
    status = ls.RepoStatus(name="t", path="/t")
    layers = _layers([status], osv_bin=None)
    assert ls.report_is_complete(layers, [status]) is True


def test_a_partial_layer_appears_in_the_structured_errors() -> None:
    """Exit 2 with an empty error list sends the consumer hunting by hand, so
    a requested layer that half-ran is named with its own reason code."""
    layers = _layers([], overlay_state="partial")
    layers["overlay"]["reason_code"] = "overlay_refresh_failed"
    errors = ls.collect_errors(layers, [], ls.OsvRunReport())
    assert any(e["code"] == "overlay_refresh_failed" and e["scope"] == "layer"
               for e in errors)


def test_overlapping_and_repeated_roots_are_walked_once(tmp_path: Path) -> None:
    """The same tree walked twice yields duplicate statuses that the
    path-keyed lockfile index can only half-satisfy, turning a good scan
    into partial coverage and exit 2."""
    inner = tmp_path / "inner"
    inner.mkdir()
    kept = ls._deduplicate_roots([tmp_path, tmp_path, inner])
    assert kept == [tmp_path]


# --------------------------------------------------------------------------
# The status document.
# --------------------------------------------------------------------------

def test_status_json_carries_the_facts_the_human_report_prints(
    tmp_path: Path, monkeypatch
) -> None:
    """Semantic parity, not sentence parity: every fact and health decision
    exists in the document, and the prose is derived from it, so the spot
    checks here are on facts the pipeline reads to trust a scan."""
    monkeypatch.setenv("LOCKFILE_SENTINEL_CACHE", str(tmp_path))
    overlay = tmp_path / "compromised-npm-packages.json"
    overlay.write_text(json.dumps({
        "generated_utc": "2026-08-15T00:00:00Z",
        "packages": {"keyv": ["6.0.0"], "cacheable": ["2.5.1"], "flat-cache": ["6.1.24"]},
    }), encoding="utf-8")
    doc = ls.gather_status(overlay, osv_bin=None)
    assert doc["schema"] == {"name": "lockfile-sentinel-status", "version": 1}
    sources = doc["sources"]
    assert sources["overlay"]["present"] is True
    assert sources["overlay"]["package_count"] == 3
    assert sources["osv_scanner"]["state"] == "unknown"
    assert doc["overall"]["state"] == "unknown"
    assert doc["overall"]["exit_code"] == 2
    text = "\n".join(ls.render_status_human(doc))
    assert str(overlay) in text
    assert "3 packages" in text


def test_the_status_schema_matches_what_gather_status_writes(
    tmp_path: Path, monkeypatch
) -> None:
    """The status schema's required lists must describe the document the code
    actually writes, at the top level and per source."""
    monkeypatch.setenv("LOCKFILE_SENTINEL_CACHE", str(tmp_path))
    doc = ls.gather_status(tmp_path / "missing.json", osv_bin=None, check_live=False)
    root = Path(__file__).resolve().parent.parent
    schema = json.loads(
        (root / "lockfile-sentinel-status.schema.json").read_text(encoding="utf-8")
    )
    assert set(schema["required"]) <= set(doc)
    sources_schema = schema["properties"]["sources"]
    assert set(sources_schema["required"]) <= set(doc["sources"])
    for name, source_schema in sources_schema["properties"].items():
        assert set(source_schema["required"]) <= set(doc["sources"][name])
    assert doc["overall"]["state"] in schema["properties"]["overall"]["properties"]["state"]["enum"]


def test_every_lockfile_carrying_a_poison_is_attributed(tmp_path: Path) -> None:
    """The same poisoned pair in two lockfiles of one repository names both
    as evidence: attribution is per file, not first-file-wins, so with OSV
    absent the finding still lists every occurrence."""
    status = ls.RepoStatus(name="t", path=str(tmp_path))
    for name in ("a", "b"):
        lockfile = tmp_path / name / "yarn.lock"
        lockfile.parent.mkdir()
        lockfile.write_text('keyv@6.0.0:\n  version "6.0.0"\n', encoding="utf-8")
        ls.scan_lockfile(lockfile, status)
    evidence = status.evidence[("resolved", "keyv", "6.0.0")]
    assert evidence == {str(tmp_path / "a" / "yarn.lock"),
                        str(tmp_path / "b" / "yarn.lock")}
    finding = ls.build_findings([status])[0]
    assert finding["source_files"] == ["a/yarn.lock", "b/yarn.lock"]


def test_a_boolean_timestamp_in_a_state_file_reads_as_unknown(
    tmp_path: Path, monkeypatch
) -> None:
    """bool is a subclass of int, so a state file corrupted to true would
    otherwise compute freshness from timestamp 1 and emit a boolean where the
    schema promises a number or null."""
    monkeypatch.setenv("LOCKFILE_SENTINEL_CACHE", str(tmp_path))
    state = tmp_path / "logs" / "update-osv-scanner.state.json"
    state.parent.mkdir(parents=True)
    state.write_text(json.dumps({"lastCheckUnix": True}), encoding="utf-8")
    doc = ls.gather_status(tmp_path / "missing.json", osv_bin=None)
    engine = doc["sources"]["osv_scanner"]
    assert engine["version_checked_unix"] is None
    assert engine["state"] == "unknown"


def test_a_non_finite_timestamp_in_a_state_file_reads_as_unknown(
    tmp_path: Path, monkeypatch
) -> None:
    """json.loads accepts NaN and Infinity, either of which would classify
    the source as fresh, crash the human rendering, and serialize as tokens
    that are not JSON at all."""
    monkeypatch.setenv("LOCKFILE_SENTINEL_CACHE", str(tmp_path))
    state = tmp_path / "logs" / "update-osv-scanner.state.json"
    state.parent.mkdir(parents=True)
    state.write_text('{"lastCheckUnix": 1e309}', encoding="utf-8")
    doc = ls.gather_status(tmp_path / "missing.json", osv_bin=None)
    engine = doc["sources"]["osv_scanner"]
    assert engine["version_checked_unix"] is None
    assert engine["state"] == "unknown"
    json.loads(json.dumps(doc))


def test_an_unrepresentable_timestamp_reads_as_unknown_not_fresh(
    tmp_path: Path, monkeypatch
) -> None:
    """1e300 is finite, reads as impossibly fresh, and still overflows
    fromtimestamp in the human rendering; a negative stamp predates the unix
    epoch. Both read as unknown, and the human report renders without
    raising."""
    monkeypatch.setenv("LOCKFILE_SENTINEL_CACHE", str(tmp_path))
    state = tmp_path / "logs" / "update-osv-scanner.state.json"
    state.parent.mkdir(parents=True)
    for literal in ("1e300", "-5"):
        state.write_text(f'{{"lastCheckUnix": {literal}}}', encoding="utf-8")
        doc = ls.gather_status(tmp_path / "missing.json", osv_bin=None)
        engine = doc["sources"]["osv_scanner"]
        assert engine["version_checked_unix"] is None
        assert engine["state"] == "unknown"
        assert ls.render_status_human(doc)


def test_a_recent_check_stamp_cannot_call_a_missing_scanner_fresh(
    tmp_path: Path, monkeypatch
) -> None:
    """A check stamp survives the binary it described: deleted or off PATH,
    the scanner source must read unknown, or --status exits 0 while the very
    next sweep marks the OSV layer unavailable and exits 2."""
    monkeypatch.setenv("LOCKFILE_SENTINEL_CACHE", str(tmp_path))
    state = tmp_path / "logs" / "update-osv-scanner.state.json"
    state.parent.mkdir(parents=True)
    state.write_text(json.dumps({"lastCheckUnix": time.time()}), encoding="utf-8")
    doc = ls.gather_status(tmp_path / "missing.json", osv_bin=None)
    assert doc["sources"]["osv_scanner"]["state"] == "unknown"
    assert doc["overall"]["exit_code"] == 2


def test_a_timestamp_materially_in_the_future_reads_as_unknown() -> None:
    """A future stamp would read as fresh forever, so anything beyond a day
    of clock skew is refused; the skew a real machine pair can show is
    accepted."""
    assert ls._as_unix_time(time.time() + 7 * 86400) is None
    assert ls._as_unix_time(4102444800) is None
    assert ls._as_unix_time(time.time() + 60) is not None


def test_a_future_overlay_generation_stamp_reads_as_unknown(
    tmp_path: Path, monkeypatch
) -> None:
    """The overlay's own ISO stamp goes through the same plausibility bound
    as the numeric state fields: a year-2100 generated_utc over a valid
    packages map must not read as fresh forever."""
    monkeypatch.setenv("LOCKFILE_SENTINEL_CACHE", str(tmp_path))
    overlay = tmp_path / "compromised-npm-packages.json"
    overlay.write_text(json.dumps({
        "generated_utc": "2100-01-01T00:00:00Z",
        "packages": {"keyv": ["6.0.0"]},
    }), encoding="utf-8")
    doc = ls.gather_status(overlay, osv_bin=None)
    source = doc["sources"]["overlay"]
    assert source["generated_unix"] is None
    assert source["state"] == "unknown"
    assert doc["overall"]["exit_code"] == 2


def test_an_overlay_the_sweep_would_reject_is_not_reported_fresh(
    tmp_path: Path, monkeypatch
) -> None:
    """Presence means what load_overlay validates: a current stamp over an
    empty or unusable packages map is a document the sweep falls back from,
    and a status that called it fresh would vouch for inputs the scan itself
    reports unavailable."""
    monkeypatch.setenv("LOCKFILE_SENTINEL_CACHE", str(tmp_path))
    overlay = tmp_path / "compromised-npm-packages.json"
    overlay.write_text(json.dumps({
        "generated_utc": "2026-08-15T00:00:00Z", "packages": {},
    }), encoding="utf-8")
    doc = ls.gather_status(overlay, osv_bin=None)
    assert doc["sources"]["overlay"]["state"] == "absent"
    assert doc["sources"]["overlay"]["present"] is False
    assert doc["overall"]["exit_code"] == 2


def test_a_malformed_overlay_stamp_is_nulled_not_echoed(
    tmp_path: Path, monkeypatch
) -> None:
    """The schema promises a date-time or null, so echoing an unparseable
    stamp would make the document reporting the malformed input the one a
    validating consumer rejects."""
    monkeypatch.setenv("LOCKFILE_SENTINEL_CACHE", str(tmp_path))
    overlay = tmp_path / "compromised-npm-packages.json"
    overlay.write_text(json.dumps({
        "generated_utc": "not-a-date", "packages": {"keyv": ["6.0.0"]},
    }), encoding="utf-8")
    source = ls.gather_status(overlay, osv_bin=None)["sources"]["overlay"]
    assert source["generated_utc"] is None
    assert source["generated_unix"] is None
    assert source["state"] == "unknown"


def test_overlay_counts_are_recomputed_never_trusted(
    tmp_path: Path, monkeypatch
) -> None:
    """A corrupted overlay can carry NaN, booleans or strings in its own
    count fields; the status counts come from the packages map itself, so the
    document stays valid JSON and honest whatever the fields claim."""
    monkeypatch.setenv("LOCKFILE_SENTINEL_CACHE", str(tmp_path))
    overlay = tmp_path / "compromised-npm-packages.json"
    overlay.write_text(
        '{"generated_utc": "2026-08-15T00:00:00Z", "package_count": NaN, '
        '"version_count": true, "packages": {"keyv": ["6.0.0", "6.0.1"], '
        '"cacheable": ["2.5.1"]}}',
        encoding="utf-8",
    )
    doc = ls.gather_status(overlay, osv_bin=None)
    source = doc["sources"]["overlay"]
    assert source["package_count"] == 2
    assert source["version_count"] == 3
    json.loads(json.dumps(doc))


def test_status_honours_the_output_option(tmp_path: Path, monkeypatch) -> None:
    """A status pipeline that asked for a file and got stdout has silently
    lost its document, so -o writes the status there, atomically, in either
    format."""
    monkeypatch.setenv("LOCKFILE_SENTINEL_CACHE", str(tmp_path))
    target = tmp_path / "status.json"
    code = ls.report_status(tmp_path / "missing.json", osv_bin=None,
                            as_json=True, output=str(target))
    assert code == 2
    document = json.loads(target.read_text(encoding="utf-8"))
    assert document["schema"]["name"] == "lockfile-sentinel-status"


def test_status_without_an_overlay_reports_absent_and_exit_2(
    tmp_path: Path, monkeypatch
) -> None:
    """A missing overlay is unknown coverage, and unknown never reports health."""
    monkeypatch.setenv("LOCKFILE_SENTINEL_CACHE", str(tmp_path))
    doc = ls.gather_status(tmp_path / "missing.json", osv_bin=None)
    assert doc["sources"]["overlay"]["state"] == "absent"
    assert doc["overall"]["exit_code"] == 2


def test_status_makes_no_network_request_unless_asked(
    tmp_path: Path, monkeypatch
) -> None:
    """Freshness on disk needs no network, and scripts rely on that."""
    def explode(*_args, **_kwargs):
        raise AssertionError("plain status mode must not touch the network")

    monkeypatch.setattr(ls, "_open_https", explode)
    monkeypatch.setenv("LOCKFILE_SENTINEL_CACHE", str(tmp_path))
    doc = ls.gather_status(tmp_path / "missing.json", osv_bin=None)
    assert doc["sources"]["osv_live"]["live_check"] is None


def test_an_unreachable_live_check_is_unknown_not_fresh(
    tmp_path: Path, monkeypatch
) -> None:
    """An explicit live check that fails is unknown coverage, not fresh."""
    def unreachable(*_args, **_kwargs):
        raise OSError("no route")

    monkeypatch.setattr(ls, "_open_https", unreachable)
    monkeypatch.setenv("LOCKFILE_SENTINEL_CACHE", str(tmp_path))
    doc = ls.gather_status(tmp_path / "missing.json", osv_bin=None, check_live=True)
    live = doc["sources"]["osv_live"]
    assert live["live_check"]["reachable"] is False
    assert live["state"] == "unknown"
    assert doc["overall"]["exit_code"] == 2
