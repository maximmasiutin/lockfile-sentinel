"""Keep every input lockfile_sentinel.py depends on current.

One job with four targets, which is why it is one program rather than four. The
log rotation, the timestamped writer, the state file, the throttle and the
ClamAV gate are written once and shared, because a per-target copy of the gate
lets the size-aware choice between clamdscan and clamscan drift. That choice is
worth getting right in one place: the resident daemon answers in milliseconds
where a standalone clamscan of a database of this size takes minutes, and the
daemon silently skips anything above its own MaxFileSize, so which of the two to
use is a decision that has to be made from the file size every time.

Targets:

  osv-scanner         Build osv-scanner when a newer release exists, either with
                      `go install` at a tag or from a git working tree.
  malicious-packages  Refresh the Shai-Hulud campaign overlay from the DataDog
                      consolidated IOC feed into the cache directory.
  offline-db          Refresh the OSV offline npm database, about 206 MB, for an
                      air-gapped or egress-restricted scan.
  trivy-db            Refresh the Trivy vulnerability and Java databases, which
                      an update of the Trivy binary alone does not touch.
  all                 Every target above, in that order.
  status              Report the freshness of all four without changing any.

Everything downloaded is scanned with ClamAV before it is trusted, where ClamAV
is installed, and each target self-throttles so calling it before a scan is
affordable. Exit codes are uniform: 0 current, updated or throttled; 1 a step
failed; 2 a prerequisite was missing so nothing was attempted.

Nothing is written beside the script. Logs, state files and downloaded databases
all live under the cache directory, which is LOCKFILE_SENTINEL_CACHE when set
and the platform cache location otherwise, the same resolution
lockfile_sentinel.py uses so that --status finds what this program wrote.

Python 3.12, standard library only.

Usage:
    python update_scanners.py status
    python update_scanners.py osv-scanner --from-source --force
    python update_scanners.py malicious-packages --min-interval 60
    python update_scanners.py trivy-db
    python update_scanners.py all
"""

# Lockfile Sentinel 0.1.0
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Maxim Masiutin
# https://github.com/maximmasiutin/lockfile-sentinel
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <https://www.gnu.org/licenses/>.

from __future__ import annotations

import argparse
import contextlib
import csv
import io
import json
import os
import re
import secrets
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import time
import urllib.request
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

# Carried per file rather than imported, because each of these three runs on its
# own and an imported version would tie a standalone copy back to a checkout it
# may not have. tests/test_headers.py is what keeps the three from drifting.
__version__ = "0.1.0"

IS_WINDOWS = os.name == "nt"
OSV_EXE = "osv-scanner.exe" if IS_WINDOWS else "osv-scanner"
TRIVY_EXE = "trivy.exe" if IS_WINDOWS else "trivy"

# Where to put a scratch directory that needs several gigabytes. No drive letter
# is written here: LOCKFILE_SENTINEL_SCRATCH wins if set, and otherwise the
# scratch sits beside the cache the download is destined for, which is already
# named by an environment variable and is already on a volume sized to hold it.
# See scratch_dir for why this is not simply TEMP.
SCRATCH_BASE = os.environ.get("LOCKFILE_SENTINEL_SCRATCH", "")

# How much room a scratch base has to have before it is worth using. The Java
# index database is roughly 900 MB compressed and is unpacked beside the archive
# it arrived in, so the peak is a multiple of the download rather than the
# download. The figure is measured rather than guessed: the failure this whole
# mechanism exists for had 2.74 GB free and that was not enough. A base below
# this is passed over with its figure logged, because finding out by running out
# of disk costs the download and reports it as an obscure write error.
SCRATCH_MIN_FREE_BYTES = 5 * 1024 ** 3


def cache_dir() -> Path:
    """The cache root for everything this program writes.

    lockfile_sentinel.py carries an identical resolver, because each file has to
    stand alone when copied; change the two together or the scanner's --status
    will look somewhere this program never wrote."""
    explicit = os.environ.get("LOCKFILE_SENTINEL_CACHE")
    if explicit:
        return Path(explicit)
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "lockfile-sentinel"


LOG_DIR = cache_dir() / "logs"
LOG_FILE = LOG_DIR / "update-scanners.log"
MAX_LOG_BYTES = 1024 * 1024

# State file names are what lockfile_sentinel.py --status reads. Rename one here
# and the scanner reports the input as never refreshed.
OSV_STATE = LOG_DIR / "update-osv-scanner.state.json"
OVERLAY_STATE = LOG_DIR / "update-malicious-packages.state.json"

MODULE_PATH = "github.com/google/osv-scanner/v2/cmd/osv-scanner"
PROXY_LATEST = "https://proxy.golang.org/github.com/google/osv-scanner/v2/@latest"
GITHUB_LATEST = "https://api.github.com/repos/google/osv-scanner/releases/latest"
REPO_URL = "https://github.com/google/osv-scanner.git"

# The three -X targets upstream's .goreleaser.yml sets. A working-tree build that
# omits the first produces a binary whose --version is empty, which every later
# run then reads as "update still due".
VERSION_VAR = "github.com/google/osv-scanner/v2/internal/version.OSVVersion"
COMMIT_VAR = "github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd.commit"
DATE_VAR = "github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd.date"

DATADOG_CSV_URL = (
    "https://raw.githubusercontent.com/DataDog/indicators-of-compromise/"
    "main/shai-hulud-2.0/consolidated_iocs.csv"
)
OVERLAY_NAME = "compromised-npm-packages.json"

# A floor so the overlay is never weaker than lockfile_sentinel.py's own built-in
# table, even when the feed is unreachable.
KNOWN_FLOOR: dict[str, list[str]] = {
    "keyv": ["6.0.0"],
    "cacheable": ["2.5.1"],
    "cacheable-request": ["13.0.20"],
    "cache-manager": ["7.2.10"],
    "flat-cache": ["6.1.24"],
    "file-entry-cache": ["11.1.7"],
    "@cacheable/memory": ["2.2.1"],
    "@cacheable/net": ["2.1.1"],
    "@cacheable/node-cache": ["3.1.2"],
    "@cacheable/utils": ["2.5.1"],
}

# clamscan cannot read a file above this and says so in a warning rather than in
# its exit code, so anything larger is reported unscanned rather than clean.
CLAMSCAN_FILE_CEILING = 2 * 1024 * 1024 * 1024 - 1


# --------------------------------------------------------------------------
# Logging, state and the throttle, shared by every target.
# --------------------------------------------------------------------------

def rotate_log() -> None:
    """Rotate at 1 MB with one .1 generation, so a long-running installation
    cannot grow the log without bound and the previous run stays readable."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > MAX_LOG_BYTES:
            backup = LOG_FILE.with_suffix(LOG_FILE.suffix + ".1")
            backup.unlink(missing_ok=True)
            LOG_FILE.rename(backup)
    except OSError:
        pass


def log(message: str) -> None:
    """Append one timestamped line to the log and echo it to stdout."""
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}"
    try:
        with LOG_FILE.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        pass
    print(line)


def read_state(path: Path) -> dict:
    """Load a state file, or {} when it is absent or malformed."""
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def write_state(path: Path, payload: dict) -> None:
    """Record state, stamping the time as integer UTC seconds.

    An integer round-trips through JSON with no timezone or culture ambiguity,
    unlike an ISO string, which comes back as a value of uncertain kind and
    makes the age arithmetic silently misfire."""
    payload = dict(payload)
    payload.setdefault("lastCheckUnix", int(time.time()))
    payload.setdefault("lastCheckUtc", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError as exc:
        log(f"WARNING: could not write {path.name}: {exc}")


def throttled(path: Path, key: str, minutes: int, what: str) -> bool:
    """Report whether this target ran less than the given number of minutes ago."""
    if minutes <= 0:
        return False
    last = read_state(path).get(key)
    if not isinstance(last, (int, float)):
        return False
    age = (time.time() - last) / 60.0
    if age >= minutes:
        return False
    log(f"throttled: {what} checked {age:.1f} min ago (< {minutes} min), skipping")
    return True


def run(cmd: list[str], cwd: Path | None = None, env: dict | None = None,
        timeout: int = 1800) -> tuple[int, str]:
    """Run a command, returning (exit code, stdout+stderr).

    A spawn failure is reported as 127 rather than raised, so every caller
    handles one shape."""
    try:
        proc = subprocess.run(  # nosec B603
            cmd, cwd=str(cwd) if cwd else None, env=env, capture_output=True,
            text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, str(exc)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def echo(output: str, prefix: str) -> None:
    """Log each non-empty line of a subprocess's output under one prefix."""
    for line in output.splitlines():
        if line.strip():
            log(f"  [{prefix}] {line.rstrip()}")


# --------------------------------------------------------------------------
# The ClamAV gate, one implementation for every target.
# --------------------------------------------------------------------------

def resolve_clam(name: str) -> str | None:
    """Locate a ClamAV binary on PATH, or report that there is none.

    PATH alone, deliberately: guessing at install roots is how a scanner ends up
    silently not scanning on a host laid out differently from the author's."""
    return shutil.which(name)


def clamd_max_file_size() -> int | None:
    """Read MaxFileSize from clamd.conf, in bytes, or None when unreadable.

    The daemon skips any file above this and reports it clean, so the value is
    what decides whether clamdscan can honestly be used at all.

    CLAMD_CONF names the file directly. Otherwise the Unix locations are tried,
    and on Windows the configuration sits beside the daemon binary, so the one
    found on PATH points at it."""
    candidates: list[Path] = []
    explicit = os.environ.get("CLAMD_CONF")
    if explicit:
        candidates.append(Path(explicit))
    daemon = shutil.which("clamd") or shutil.which("clamdscan")
    if daemon:
        candidates.append(Path(daemon).resolve().parent / "clamd.conf")
    candidates += [Path("/etc/clamav/clamd.conf"), Path("/usr/local/etc/clamd.conf"),
                   Path("/opt/homebrew/etc/clamav/clamd.conf")]
    for candidate in candidates:
        try:
            text = candidate.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == "MaxFileSize":
                raw = parts[1].upper()
                multiplier = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}.get(raw[-1:], 1)
                digits = raw[:-1] if multiplier > 1 else raw
                try:
                    return int(digits) * multiplier
                except ValueError:
                    return None
    return None


def gate(target: Path, what: str, skip: bool) -> bool:
    """Scan a downloaded artifact, preferring the daemon where it is honest.

    clamdscan is the house default because the resident daemon answers in
    milliseconds. It is the wrong tool whenever a file exceeds clamd's
    MaxFileSize, because the daemon does not scan an oversized file, it reports
    it clean, and a scanner that passes what it never read is worse than none.
    So the size decides: the daemon when everything fits, standalone clamscan
    with the caps lifted when it does not. clamscan in turn cannot read a file
    above 2 GiB and says so only in a warning while still exiting 0, so a file
    that size is refused outright rather than passed on a clean exit code.

    Fail closed: anything other than a confirmed clean result returns False, and
    a file nothing could read is not a clean result."""
    if skip:
        log(f"ClamAV gate skipped by request: {what}")
        return True
    if not target.exists():
        log(f"FAIL: nothing to scan at {target}")
        return False

    files = [p for p in target.rglob("*") if p.is_file()] if target.is_dir() else [target]
    largest = max((p.stat().st_size for p in files), default=0)

    # A file above the ceiling is refused rather than warned about. Neither
    # scanner reads it, and both still exit 0, so warning and continuing meant
    # returning a clean verdict for bytes nothing had looked at. That is the one
    # outcome a gate must never produce, and the docstring above claimed it was
    # already refused when it was not.
    oversized = [p for p in files if p.stat().st_size > CLAMSCAN_FILE_CEILING]
    if oversized:
        for path in oversized:
            log(f"FAIL: {path} is {path.stat().st_size / 1024 / 1024:.0f} MB, above the 2 GiB "
                "libclamav ceiling, so no scanner here can read it")
        log(f"refusing to trust {what}: {len(oversized)} file(s) could not be scanned at all")
        return False

    cap = clamd_max_file_size()
    clamdscan = resolve_clam("clamdscan")
    use_daemon = bool(clamdscan) and cap is not None and largest <= cap
    if clamdscan and not use_daemon:
        log(f"daemon not used for {what}: largest file is {largest / 1024 / 1024:.0f} MB against "
            f"a clamd MaxFileSize of "
            f"{'unknown' if cap is None else f'{cap / 1024 / 1024:.0f} MB'}")

    if use_daemon:
        cmd = [str(clamdscan), "--multiscan", "--infected", "--no-summary", str(target)]
        label = "clamdscan"
    else:
        clamscan = resolve_clam("clamscan")
        if not clamscan:
            log(f"FAIL: no ClamAV scanner able to read files this size; refusing to trust {what}")
            return False
        cmd = [clamscan, "--recursive", "--infected", "--no-summary",
               "--max-filesize=0", "--max-scansize=0", str(target)]
        label = "clamscan"

    started = time.monotonic()
    code, output = run(cmd)
    echo(output, label)
    log(f"{label} finished in {time.monotonic() - started:.0f}s, exit {code}: {what}")
    if code != 0:
        log(f"FAIL: {what} did not pass the ClamAV gate (exit {code})")
        return False
    return True


# --------------------------------------------------------------------------
# Shared resolution helpers.
# --------------------------------------------------------------------------

def resolve_go() -> str | None:
    """Locate the Go toolchain on PATH."""
    return shutil.which("go")


def resolve_git() -> str | None:
    """Locate git on PATH."""
    return shutil.which("git")


def resolve_trivy() -> str | None:
    """Locate trivy on PATH. Absent means the Trivy target reports missing."""
    return shutil.which("trivy")


def go_bin(go: str) -> Path | None:
    """Return the osv-scanner path under GOBIN, else under GOPATH/bin."""
    code, out = run([go, "env", "GOBIN"], timeout=60)
    binary_dir = out.strip().splitlines()[0].strip() if code == 0 and out.strip() else ""
    if not binary_dir:
        code, out = run([go, "env", "GOPATH"], timeout=60)
        gopath = out.strip().splitlines()[0].strip() if code == 0 and out.strip() else ""
        if not gopath:
            return None
        binary_dir = str(Path(gopath) / "bin")
    return Path(binary_dir) / OSV_EXE


def osv_version(exe: Path | None) -> str | None:
    """Read 'osv-scanner version: X' from a binary."""
    if not exe or not exe.exists():
        return None
    code, out = run([str(exe), "--version"], timeout=60)
    if code == 127:
        return None
    match = re.search(r"osv-scanner version:\s*([0-9]\S*)", out)
    return match.group(1) if match else None


def semver(text: str | None) -> tuple[int, int, int] | None:
    """Parse the leading major.minor.patch of a version string."""
    if not text:
        return None
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def overlay_path() -> Path:
    """Where the campaign overlay lives: the cache directory, never the script tree.

    lockfile_sentinel.py carries an identical resolver, because each file has to
    stand alone when copied; change the two together."""
    return cache_dir() / OVERLAY_NAME


def offline_db_dir() -> Path:
    """Cache root for the OSV offline database.

    OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY is osv-scanner's own variable, so it
    wins here: pointing the two at different directories would download the
    database to one place and read it from another."""
    explicit = os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY")
    if explicit:
        return Path(explicit)
    return cache_dir() / "osv-offline-db"


def trivy_cache_dir_default() -> Path:
    """Where Trivy reads its databases, whether or not that exists yet.

    trivy_cache_dir() answers None for a cache that has never been created,
    which is right for reporting and wrong for deciding where to install a
    download, so the refresh uses this and the status report uses that."""
    explicit = os.environ.get("TRIVY_CACHE_DIR")
    if explicit:
        return Path(explicit)
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "trivy"


def trivy_cache_dir() -> Path | None:
    """The cache Trivy will actually use, or None when it cannot be determined.

    Trivy's own default is read rather than imposed, because a refresh written
    anywhere else is a refresh Trivy will not find."""
    explicit = os.environ.get("TRIVY_CACHE_DIR")
    if explicit:
        return Path(explicit)
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    candidate = Path(base) / "trivy"
    return candidate if candidate.exists() else None


# --------------------------------------------------------------------------
# Target: osv-scanner.
# --------------------------------------------------------------------------

def latest_osv_version(timeout: int = 30) -> str | None:
    """Ask the Go module proxy, then the GitHub releases API, for the latest tag.

    The proxy reports exactly what `go install @latest` would resolve, so
    detection and installation never disagree."""
    for url, key in ((PROXY_LATEST, "Version"), (GITHUB_LATEST, "tag_name")):
        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": "update-scanners", "Accept": "application/json"}
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
                data = json.loads(response.read().decode("utf-8"))
            value = data.get(key)
            if value:
                return str(value)
        except Exception as exc:  # noqa: BLE001 - try the next source, then fail
            log(f"{url} lookup failed ({exc})")
    return None


def build_from_source(args, go: str, exe: Path | None, installed: str | None,
                      latest: str) -> int:
    """Clone or update a git working tree, check out the target ref, and build."""
    git = resolve_git()
    if not git:
        log("FAIL: git not found; cannot use --from-source")
        return 2

    source_dir = Path(args.source_dir)
    target_ref = args.ref or f"v{latest}"
    log(f"source mode: {source_dir} at {target_ref} (git: {git})")

    if not (source_dir / ".git").exists():
        if source_dir.exists() and any(source_dir.iterdir()):
            log(f"FAIL: {source_dir} exists, is not a git working tree, and is not empty")
            return 1
        source_dir.parent.mkdir(parents=True, exist_ok=True)
        log(f"cloning {REPO_URL} ...")
        code, out = run([git, "clone", "--quiet", REPO_URL, str(source_dir)])
        echo(out, "git")
        if code != 0:
            log(f"FAIL: git clone exited {code}")
            return 1
    else:
        log("fetching origin ...")
        code, out = run([git, "-C", str(source_dir), "fetch", "--tags", "--prune", "--quiet",
                         "origin"])
        echo(out, "git")
        if code != 0:
            log(f"FAIL: git fetch exited {code}")
            return 1

    # A checkout over uncommitted work discards it. Refuse rather than decide
    # on the user's behalf that their edits were disposable.
    _, out = run([git, "-C", str(source_dir), "status", "--porcelain"])
    dirty = [line for line in out.splitlines() if line.strip()]
    if dirty and not args.force:
        log(f"FAIL: {source_dir} has {len(dirty)} uncommitted change(s); refusing to check out "
            f"{target_ref}. Commit, stash, or pass --force.")
        return 1

    # A tag is checked out detached; a branch is fast-forwarded. Nothing merges
    # or rebases, so the tree cannot end up conflicted.
    on_branch = False
    code, _ = run([git, "-C", str(source_dir), "-c", "advice.detachedHead=false",
                   "checkout", "--quiet", "--detach", f"refs/tags/{target_ref}"])
    if code != 0:
        code, out = run([git, "-C", str(source_dir), "checkout", "--quiet", target_ref])
        echo(out, "git")
        if code != 0:
            log(f"FAIL: '{target_ref}' is neither a tag nor a branch in {source_dir}")
            return 1
        on_branch = True
        code, out = run([git, "-C", str(source_dir), "merge", "--ff-only", "--quiet",
                         f"origin/{target_ref}"])
        echo(out, "git")
        if code != 0:
            log(f"FAIL: could not fast-forward {target_ref}")
            return 1

    _, head_out = run([git, "-C", str(source_dir), "rev-parse", "HEAD"])
    head = head_out.strip().splitlines()[0].strip() if head_out.strip() else ""
    _, date_out = run([git, "-C", str(source_dir), "show", "-s", "--format=%cI", "HEAD"])
    commit_date = date_out.strip().splitlines()[0].strip() if date_out.strip() else ""
    short = head[:12]
    # An untagged commit has no release version to claim, so a branch build says
    # so rather than impersonating the last release.
    expected = f"{latest}-{short}" if on_branch else target_ref.lstrip("v")
    log(f"checked out {target_ref} at {short} (expected version: {expected})")

    last_commit = str(read_state(OSV_STATE).get("lastCommit") or "")
    exe_present = exe is not None and exe.exists()
    if not (args.force or not exe_present or installed != expected or last_commit != head):
        log(f"already built from {short} at {installed}; nothing to compile")
        write_state(OSV_STATE, {"lastVersion": installed, "lastCommit": head})
        return 0

    if not gate(source_dir, "the osv-scanner source tree", args.skip_scan):
        return 1
    if exe is None:
        log("FAIL: could not resolve the Go bin directory to build into")
        return 2

    exe.parent.mkdir(parents=True, exist_ok=True)
    # Build beside the live binary and swap only after the gate and the version
    # check pass; writing straight to the target fails while the old one runs.
    tmp_exe = exe.with_suffix(exe.suffix + ".new")
    tmp_exe.unlink(missing_ok=True)
    ldflags = (f"-s -w -X {VERSION_VAR}={expected} -X {COMMIT_VAR}={head} "
               f"-X {DATE_VAR}={commit_date}")
    log("building with go build -trimpath ...")
    code, out = run([go, "build", "-trimpath", "-ldflags", ldflags, "-o", str(tmp_exe),
                     "./cmd/osv-scanner"], cwd=source_dir,
                    env=dict(os.environ, CGO_ENABLED="0"))
    echo(out, "go")
    if code != 0:
        tmp_exe.unlink(missing_ok=True)
        log(f"FAIL: go build exited {code}; existing osv-scanner left in place")
        return 1
    if not gate(tmp_exe, "the freshly built osv-scanner", args.skip_scan):
        tmp_exe.unlink(missing_ok=True)
        return 1
    built = osv_version(tmp_exe)
    if built != expected:
        tmp_exe.unlink(missing_ok=True)
        log(f"FAIL: built binary reports '{built}', expected '{expected}'; not installed")
        return 1
    try:
        os.replace(tmp_exe, exe)
    except OSError as exc:
        tmp_exe.unlink(missing_ok=True)
        log(f"FAIL: could not replace {exe} ({exc}); is it running?")
        return 1
    write_state(OSV_STATE, {"lastVersion": expected, "lastCommit": head})
    log(f"osv-scanner built from source: {installed or 'not installed'} -> {expected} ({short})")
    return 0


def target_osv_scanner(args) -> int:
    """Keep the osv-scanner build current."""
    if not args.force and throttled(OSV_STATE, "lastCheckUnix", args.min_interval,
                                    "the osv-scanner version"):
        return 0
    go = resolve_go()
    if not go:
        log("FAIL: go toolchain not found on PATH; cannot build osv-scanner")
        return 2

    exe = go_bin(go)
    installed = osv_version(exe)
    log(f"installed: {installed or 'not installed'} (at {exe or 'unknown'})")

    latest_raw = latest_osv_version()
    if not latest_raw:
        # Record the check so the throttle still holds, then fail: a lookup that
        # could not run is not a healthy "already current".
        write_state(OSV_STATE, {"lastVersion": installed})
        log("FAIL: could not determine the latest osv-scanner version")
        return 1
    latest = latest_raw.lstrip("v")
    log(f"latest:    {latest}")
    write_state(OSV_STATE, {"lastVersion": installed})

    if args.check_only:
        due = semver(installed) is None or (semver(latest) or (0, 0, 0)) > (semver(installed) or (0, 0, 0))
        log(f"check-only: update {'DUE' if due else 'not due'}")
        return 0

    if args.from_source:
        return build_from_source(args, go, exe, installed, latest)

    installed_key, latest_key = semver(installed), semver(latest)
    if installed_key is not None and latest_key is not None and latest_key <= installed_key:
        log(f"osv-scanner is already current at {installed}")
        return 0

    target = f"{MODULE_PATH}@v{latest}"
    log(f"building {target} with go install ...")

    # Build into a staging directory, gate it there, and only then replace the
    # binary the scanner actually runs. Installing straight into the Go bin
    # directory meant a build that failed the ClamAV gate or the version check
    # was already the copy on disk, and the scanner prefers the Go bin copy, so
    # a rejected executable stayed installed and got used on the next scan.
    with tempfile.TemporaryDirectory(prefix="lockfile-sentinel-gobin-") as staging:
        code, out = run([go, "install", target], env=dict(os.environ, GOBIN=staging))
        echo(out, "go")
        if code != 0:
            log(f"FAIL: go install exited {code}; existing osv-scanner left in place")
            return 1
        staged = Path(staging) / OSV_EXE
        if not staged.exists():
            log(f"FAIL: go install produced no {OSV_EXE} in the staging directory")
            return 2
        if not gate(staged, "the built osv-scanner", args.skip_scan):
            log("the rejected build was discarded; the existing osv-scanner is untouched")
            return 1
        after = osv_version(staged)
        if after != latest:
            log(f"FAIL: built {latest} but --version reports '{after}'; discarding the build "
                "rather than installing a binary that cannot identify itself")
            return 1
        destination = go_bin(go)
        if destination is None:
            log("FAIL: cannot determine the Go bin directory to install into")
            return 2
        # Copy beside the destination first, then os.replace, which is atomic
        # within one filesystem. shutil.move across filesystems degrades to a
        # copy over the live file, so an interrupted update could leave the
        # binary every later scan prefers truncated or half-written.
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            beside = destination.with_name(destination.name + ".incoming")
            shutil.copy2(str(staged), str(beside))
            os.replace(str(beside), str(destination))
        except OSError as exc:
            log(f"FAIL: could not install the gated binary to {destination} ({exc})")
            try:
                beside.unlink(missing_ok=True)
            except OSError:
                pass
            return 1

    write_state(OSV_STATE, {"lastVersion": after})
    log(f"osv-scanner updated: {installed or 'not installed'} -> {after}")
    return 0


# --------------------------------------------------------------------------
# Target: malicious-packages, the campaign overlay.
# --------------------------------------------------------------------------

def _pick_column(fieldnames: Sequence[str] | None, candidates: tuple[str, ...]) -> str | None:
    """Return the first candidate column present in the header, case-insensitively."""
    if not fieldnames:
        return None
    lowered = {f.lower().strip(): f for f in fieldnames}
    for candidate in candidates:
        if candidate in lowered:
            return lowered[candidate]
    return None


def _split_versions(raw: str) -> list[str]:
    """Split a joined version field, dropping empties and obvious placeholders."""
    versions: list[str] = []
    for token in raw.replace(";", ",").replace(" ", ",").split(","):
        version = token.strip().strip('"')
        if not version or version.startswith("99."):
            continue
        versions.append(version)
    return versions


def parse_datadog_csv(text: str) -> dict[str, set[str]]:
    """Parse the consolidated IOC CSV into {package_name: {versions}}."""
    packages: dict[str, set[str]] = {}
    reader = csv.DictReader(io.StringIO(text))
    name_key = _pick_column(reader.fieldnames, ("package_name", "name", "package"))
    version_key = _pick_column(reader.fieldnames, ("package_versions", "versions", "version"))
    if not name_key or not version_key:
        raise RuntimeError(f"unexpected CSV columns: {reader.fieldnames}")
    for row in reader:
        name = (row.get(name_key) or "").strip()
        if not name:
            continue
        for version in _split_versions(row.get(version_key) or ""):
            packages.setdefault(name, set()).add(version)
    return packages


def target_malicious_packages(args) -> int:
    """Refresh the campaign overlay from the consolidated IOC feed."""
    output = Path(args.output) if args.output else overlay_path()
    if not args.force and output.exists() and throttled(
        OVERLAY_STATE, "lastRefreshUnix", args.min_interval, "the campaign overlay"
    ):
        return 0

    log(f"fetching campaign IOC feed: {args.source_url}")
    packages: dict[str, set[str]] = {}
    sources: list[str] = []
    try:
        request = urllib.request.Request(
            args.source_url, headers={"User-Agent": "update-scanners"}
        )
        with urllib.request.urlopen(request, timeout=60) as response:  # nosec B310
            body = response.read()
        # Stage the download beside the overlay in the cache, never in the
        # scripts directory, so a crash between the write and the gate leaves
        # the stray file in a cache rather than in the repository.
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".csv", delete=False,
                                         dir=str(output.parent)) as handle:
            handle.write(body)
            staged = Path(handle.name)
        try:
            if not gate(staged, "the campaign IOC feed", args.skip_scan):
                return 1
            packages = parse_datadog_csv(body.decode("utf-8", errors="replace"))
            sources.append(args.source_url)
        finally:
            staged.unlink(missing_ok=True)
    except Exception as exc:  # noqa: BLE001 - keep what we have rather than fail open
        # An unreachable or malformed feed must not overwrite a good overlay.
        # Writing the built-in floor here replaced every campaign indicator that
        # existed only in the feed, stamped the result as freshly refreshed, and
        # returned success, so the next scan silently lost coverage it used to
        # have and nothing said so.
        log(f"FAIL: could not refresh from the feed ({exc})")
        if output.exists():
            log(f"keeping the existing overlay at {output} rather than replacing it with "
                "the built-in floor; its age is unchanged and --status will report it stale")
        else:
            log("no existing overlay to keep; the scanner falls back to its built-in table")
        return 1

    for name, versions in KNOWN_FLOOR.items():
        packages.setdefault(name, set()).update(versions)
    total = sum(len(v) for v in packages.values())

    payload = {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": sources or ["built-in floor only (feed unreachable)"],
        "package_count": len(packages),
        "version_count": total,
        "packages": {name: sorted(v) for name, v in sorted(packages.items())},
    }
    try:
        output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        log(f"FAIL: could not write {output} ({exc})")
        return 1
    log(f"wrote {output} ({len(packages)} packages, {total} versions)")
    write_state(OVERLAY_STATE, {"lastRefreshUnix": int(time.time()), "versionCount": total})
    return 0 if total else 1


# --------------------------------------------------------------------------
# Target: offline-db, the OSV offline npm database.
# --------------------------------------------------------------------------

def target_offline_db(args) -> int:
    """Refresh the OSV offline database, using the positive control as a self-test."""
    go = resolve_go()
    exe = go_bin(go) if go else None
    if not exe or not exe.exists():
        found = shutil.which("osv-scanner")
        exe = Path(found) if found else None
    if not exe:
        log("FAIL: osv-scanner not found; build it with the osv-scanner target first")
        return 2

    cache = offline_db_dir()
    cache.mkdir(parents=True, exist_ok=True)

    # A lockfile is needed to drive the download, and it doubles as a positive
    # control: it pins a version with a published advisory, so a refresh that
    # reports nothing has told us the database is not usable. The control is
    # written to a temporary directory and deleted, never committed, because a
    # lockfile pinning live malicious versions invites an accidental install by
    # anyone who clones this repository.
    with tempfile.TemporaryDirectory(prefix="lockfile-sentinel-control-") as tmp:
        control = Path(tmp) / "package-lock.json"
        control.write_text(json.dumps({
            "name": "offline-db-control",
            "version": "0.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "offline-db-control", "version": "0.0.0"},
                "node_modules/keyv": {
                    "version": "6.0.0",
                    "resolved": "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz",
                },
            },
        }, indent=2), encoding="utf-8")

        log(f"refreshing the offline database into {cache} (about 206 MB)")
        code, out = run(
            [str(exe), "scan", "source", "--offline-vulnerabilities",
             "--download-offline-databases", "--lockfile", str(control)],
            env=dict(os.environ, OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=str(cache)),
        )
    echo(out, "osv")
    # Exit 1 against the control is the expected, healthy outcome.
    if code not in (0, 1):
        log(f"FAIL: the offline refresh exited {code}")
        return 1
    # The control not firing is a failure, not a warning. A database that cannot
    # detect a package with a published advisory is unusable, and reporting the
    # refresh as successful would hand the scheduler exactly the outcome the
    # positive control exists to catch: a detector that reports nothing being
    # mistaken for a tree that is clean.
    if "keyv" not in out:
        log("FAIL: the database refreshed but the control package keyv was not flagged, "
            "so the downloaded database cannot be trusted to detect anything")
        return 1
    if not gate(cache, "the OSV offline database", args.skip_scan):
        return 1
    log("offline database refresh complete")
    return 0


# --------------------------------------------------------------------------
# Target: trivy-db.
# --------------------------------------------------------------------------

def parse_stamp(text: str | None) -> datetime | None:
    """Parse one of Trivy's RFC3339 timestamps, tolerating fractional seconds."""
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        return None


def trivy_freshness(trivy: str, env: dict[str, str] | None = None
                    ) -> dict[str, dict[str, datetime | None]]:
    """Return {database: {updated, next_update}} as Trivy reports it.

    An empty result means the state could not be determined, not that the
    databases are fine; every caller has to treat it that way."""
    # The exit code is deliberately ignored: Trivy reports a non-zero code for
    # conditions that still print usable version JSON, and an unparseable body
    # is handled below, so the output is the only thing worth testing.
    _code, out = run([trivy, "version", "--format", "json"], timeout=120, env=env)
    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError:
        return {}
    result: dict[str, dict[str, datetime | None]] = {}
    for key, label in (("VulnerabilityDB", "vulnerability"), ("JavaDB", "java")):
        entry = data.get(key)
        if isinstance(entry, dict):
            result[label] = {
                "updated": parse_stamp(entry.get("UpdatedAt")),
                "next_update": parse_stamp(entry.get("NextUpdate")),
            }
    return result


def describe_age(when: datetime | None) -> str:
    """Render a timestamp with how long ago it was, or say it is unknown."""
    if when is None:
        return "unknown"
    delta = datetime.now(timezone.utc) - when.astimezone(timezone.utc)
    hours = delta.total_seconds() / 3600.0
    stamp = when.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if hours < 0:
        return f"{stamp} (in {abs(hours):.1f} h)"
    if hours < 48:
        return f"{stamp} ({hours:.1f} h ago)"
    return f"{stamp} ({hours / 24:.1f} days ago)"


def overdue(freshness: dict[str, dict[str, datetime | None]]) -> list[str]:
    """Return the databases whose NextUpdate is already in the past."""
    now = datetime.now(timezone.utc)
    return [
        label for label, entry in freshness.items()
        if entry.get("next_update") is not None
        and entry["next_update"].astimezone(timezone.utc) < now  # type: ignore[union-attr]
    ]


def report_trivy(freshness: dict[str, dict[str, datetime | None]], when: str) -> None:
    """Log the state of each Trivy database."""
    if not freshness:
        log(f"{when}: Trivy reported no database metadata")
        return
    stale = set(overdue(freshness))
    for label, entry in freshness.items():
        state = "OVERDUE" if label in stale else "current"
        log(f"{when}: {label} db {state}, updated {describe_age(entry.get('updated'))}, "
            f"next due {describe_age(entry.get('next_update'))}")


def free_bytes(path: Path) -> int | None:
    """Free space at a path, or None when the filesystem will not say.

    None means unknown rather than zero, and an unknown is not treated as a
    refusal: a base that cannot be measured is still tried, because rejecting
    every unmeasurable path would send the download to the system temporary
    directory, which is the one place already known to be too small."""
    try:
        return shutil.disk_usage(path).free
    except OSError as exc:
        log(f"could not read free space at {path} ({exc}); treating it as unknown")
        return None


def describe_free(free: int | None) -> str:
    """Render a free-space figure for a log line, or say it is unknown."""
    if free is None:
        return "free space unknown"
    return f"{free / 1024 ** 3:.1f} GB free"


def is_inside(path: Path, container: Path) -> bool:
    """Whether path is container itself or sits somewhere under it.

    Both sides are resolved first, so a symlink or a junction that points into
    the container is caught. Two spellings can name one directory, and it is the
    real location that a rename acts on, not the spelling that reached us.

    A path that cannot be resolved answers True. That is the fail-closed
    direction: this question is asked to protect the only copy of the databases,
    and a path that cannot be placed is not a path that can be cleared.

    RuntimeError is caught beside OSError because the supported floor is Python
    3.12, where resolve() raises RuntimeError on a symlink loop whatever strict
    is set to. 3.13 folded that case in with every other filesystem error, so on
    a newer interpreter the clause is dead and on the declared minimum it is the
    difference between failing closed as documented and aborting the run.
    """
    try:
        return path.resolve().is_relative_to(container.resolve())
    except (OSError, RuntimeError) as exc:
        log(f"could not resolve {path} against {container} ({exc}); "
            "treating it as inside, which is the safe answer")
        return True


def promote_into(staged: Path, live: Path) -> None:
    """Replace the live cache with the staged one, keeping the old copy until it lands.

    The order matters and is the reason this is a function rather than four lines
    inline. The live tree is renamed aside first so that a failure leaves a
    complete cache under `.previous` instead of a half-populated one at `live`,
    and the old copy is removed only after the staged tree has arrived.

    This assumes the caller has established that `staged` is not inside `live`.
    If it is, the first rename carries the staged tree away with the cache, the
    move then names a path that no longer exists, and the run ends with no live
    cache at all. That is what `is_inside` exists to prevent, at the call site,
    where the answer is still useful: a caller that gets True there picks a
    different scratch base and proceeds. Repeating the check here would run
    before the rename and so would prevent the damage, but `is_inside` answers
    True for a path it cannot resolve, and that fail-closed answer would abort a
    promotion that was about to succeed on a cache which merely could not be
    stat'd at that moment.

    OSError propagates. The caller reports it, because it is the caller that
    knows the run this was part of.
    """
    # The real directory, not the name that reached us, for the same reason
    # is_inside resolves: a rename acts on the location rather than the spelling.
    # Where the cache path is a symlink onto a roomier volume, os.replace renames
    # the link and leaves its target untouched, so the cache silently migrates
    # onto the volume holding the link, which is the small one this mechanism
    # exists to stay off. The databases are stranded at the old target, and
    # rmtree refuses a symlink, so ignore_errors swallows that and a stray
    # .previous link accumulates on every refresh.
    live = live.resolve()
    live.parent.mkdir(parents=True, exist_ok=True)
    previous = live.with_name(live.name + ".previous")
    if previous.exists():
        shutil.rmtree(previous, ignore_errors=True)
    if live.exists():
        os.replace(live, previous)
    shutil.move(str(staged), str(live))
    shutil.rmtree(previous, ignore_errors=True)


def current_user_sid() -> str | None:
    """Return the SID of the account this process runs as, or None if it cannot be read.

    The SID rather than the name, because a name has to be qualified by a domain
    to be unambiguous and the environment variables that would supply one are
    both spoofable and absent under some service accounts. A SID needs no
    qualification and is what the ACL stores anyway.

    `whoami` is asked rather than the Win32 token API because the answer is one
    line of CSV and the alternative is forty lines of ctypes around
    OpenProcessToken and ConvertSidToStringSidW for a value that does not change
    during a run. The cost is a process; this is called once per scratch.

    Every failure returns None rather than raising, including the shapes a
    success can take that carry no answer. That is not defensiveness for its own
    sake: the caller's contract is to warn and continue when the SID cannot be
    read, and a function that raises instead would break that contract from the
    inside, at a point where the scratch directory exists and its cleanup has
    not been armed yet."""
    code, output = run(["whoami", "/user", "/fo", "csv", "/nh"], timeout=30)
    if code != 0:
        return None
    # Exit 0 with nothing on stdout is not a contradiction worth trusting: a
    # redirected or policy-restricted whoami can succeed and print nothing, and
    # indexing the last line of no lines would raise where the caller expects a
    # None it can warn about.
    lines = output.strip().splitlines()
    if not lines:
        return None
    # "DOMAIN\\user","S-1-5-21-...". The SID is the last quoted field, and taking
    # it from the end rather than by index survives a user name containing a comma.
    sid = lines[-1].split(",")[-1].strip().strip('"')
    # A full shape rather than a prefix. "S-1-" alone passes a startswith test and
    # is not a SID, and while icacls would merely reject it — run passes an
    # argument list, so nothing here reaches a shell — a check that admits what
    # the docstring says it discards is a claim the code does not keep.
    return sid if re.fullmatch(r"S-1-\d+(?:-\d+)+", sid) else None


def restrict_to_owner(path: Path) -> None:
    """Cut a Windows directory's inherited ACL down to this account, SYSTEM and administrators.

    `mkdir(mode=0o700)` is honoured on Unix and ignored on Windows, where the new
    directory instead inherits whatever the base grants. Measured on the host
    this was written for, that inversion is real: the Trivy cache carries an
    explicit non-inherited ACL naming its owner, SYSTEM and the administrators
    group and nobody else, while the scratch base sits under a general-purpose
    directory that grants modify to Authenticated Users. So the staged database
    is least protected exactly while it is least verified, in the window between
    the ClamAV gate approving it and the promotion installing it, which is a
    local user's opportunity to substitute a database nothing scanned.

    The three grants mirror the cache's own ACL rather than being minimised
    further. Dropping the administrators group would buy nothing, since an
    administrator can take ownership and rewrite the ACL regardless, and it would
    cost an operator the ability to clear a leaked scratch left by a scheduled
    task running as another account.

    A failure warns rather than raises. The exposure this closes needs a second
    local account to exploit, while raising would stop the databases updating at
    all on any host where `icacls` is unavailable or the account cannot rewrite
    the ACL, and a stale vulnerability database is the larger everyday risk. The
    warning names what did not happen so the log says so plainly instead of the
    docstring quietly promising a privacy the run did not obtain.

    Note the ordering: this runs immediately after an exclusive `mkdir`, so the
    directory is empty and there are no child objects carrying an ACL of their
    own for `(OI)(CI)` to miss. The microseconds between the two calls are a
    window in principle, but the directory name carries 64 bits from `secrets`,
    so there is no path for anyone to have been waiting on."""
    if not IS_WINDOWS:
        return
    sid = current_user_sid()
    if sid is None:
        log(f"WARNING: could not read this account's SID, so the scratch directory {path} "
            "keeps the permissions it inherited from its parent. A local user with write "
            "access there can substitute a database between the ClamAV gate and promotion.")
        return
    # /inheritance:r drops the inherited entries; /grant:r replaces rather than
    # adds, so a rerun is idempotent. The leading * marks each principal as a SID
    # rather than a name. S-1-5-18 is SYSTEM and S-1-5-32-544 is the local
    # administrators group; both are the same on every install and in every
    # locale, which a name is not.
    code, output = run(
        ["icacls", str(path), "/inheritance:r",
         "/grant:r", f"*{sid}:(OI)(CI)F",
         "/grant:r", "*S-1-5-18:(OI)(CI)F",
         "/grant:r", "*S-1-5-32-544:(OI)(CI)F"],
        timeout=60,
    )
    if code != 0:
        log(f"WARNING: could not restrict the permissions on the scratch directory {path}, "
            "which therefore keeps the ones it inherited from its parent. A local user with "
            "write access there can substitute a database between the ClamAV gate and "
            "promotion.")
        echo(output, "icacls")


@contextlib.contextmanager
def scratch_dir(label: str, near: Path | None = None):
    """Yield a private scratch directory on a volume with room, and remove it after.

    Trivy stages the Java index database, roughly 900 MB compressed and larger
    once unpacked, through two temporary directories before it reaches the cache.
    On the host this was written for TEMP is a deliberately small 8 GB volume,
    and the download failed with "There is not enough space on the disk" on seven
    consecutive nights while the vulnerability database, at a tenth the size,
    kept succeeding. Both databases were four days stale before anyone looked.

    Redirecting only our own staging cache would not have fixed it: the write
    that actually failed was inside Trivy's own getter directory, which Trivy
    takes from the Go runtime's temporary directory. So the caller sets those
    variables for the child process as well, TMPDIR for Unix and TMP and TEMP
    for Windows, since the two platforms read different ones.

    A base is passed over unless it has SCRATCH_MIN_FREE_BYTES to spare, because
    "a volume with room" is the whole point and is-it-a-directory does not
    establish it. A base whose free space cannot be read is still used, since
    the alternative is falling back to the volume already known to be too small.

    No drive letter appears anywhere in this resolution. LOCKFILE_SENTINEL_SCRATCH
    wins when set; otherwise the scratch goes beside `near`, the directory the
    download is destined for, which the caller takes from TRIVY_CACHE_DIR. That
    volume is already sized to hold the databases, since it stores them, and
    staging on it turns the promotion into a rename within one volume rather
    than a copy across two. The system temporary directory is the last resort,
    and is announced, because it is the one that was too small to begin with.

    The name carries 64 bits from secrets rather than a counter or a timestamp,
    because the base can be a volume root that other things write to, and a
    predictable path there is a symlink-swap target. Creation is exclusive, so a
    collision or a pre-existing directory raises rather than being adopted, and
    that half holds on every platform. The mode does not: Windows ignores it and
    the directory would inherit the parent's ACL, which on a general-purpose base
    grants modify to every authenticated user. restrict_to_owner rewrites it
    afterwards for that reason, and warns rather than raising when it cannot, so
    a run that did not obtain a private directory says so."""
    # Where the cache really is, because that is the volume sized to hold it and
    # the one a promotion renames within. A cache path is symlinked precisely
    # when the databases have to live somewhere roomier, so the parent of the
    # link is the small volume the link exists to avoid: staging there both
    # risks the disk-full failure this whole mechanism was written for and turns
    # the promotion into a copy across two volumes rather than a rename within
    # one. promote_into resolves for the same reason, and the two have to agree
    # about where the cache is or each undoes the other's care.
    real_near = near
    if near is not None:
        try:
            real_near = near.resolve()
        except (OSError, RuntimeError) as exc:
            log(f"could not resolve the cache {near} ({exc}); "
                "using the path as spelled to choose a scratch base")
    candidates = [
        (SCRATCH_BASE, "LOCKFILE_SENTINEL_SCRATCH"),
        (str(real_near.parent) if real_near else "", "the cache volume"),
    ]
    base = None
    for value, origin in candidates:
        if not value:
            continue
        path = Path(value)
        if not path.is_dir():
            log(f"scratch base {value} from {origin} is not available")
            continue
        if near is not None and is_inside(path, near):
            # Promotion renames the live cache aside before moving the staged
            # tree in. A scratch under the cache travels with that rename, so
            # the move then names a path that no longer exists and the run ends
            # with no live cache and the databases stranded in the .previous
            # tree. Refusing here is the point: a base configured to sit inside
            # the directory it is staging for is a mistake worth naming rather
            # than one worth quietly relocating.
            log(f"scratch base {value} from {origin} is inside the cache {near} that the "
                "download is promoted into, where it would be carried away by the "
                "promotion and leave no live cache; passing over it")
            continue
        free = free_bytes(path)
        if free is not None and free < SCRATCH_MIN_FREE_BYTES:
            log(f"scratch base {value} from {origin} has {describe_free(free)}, under the "
                f"{SCRATCH_MIN_FREE_BYTES / 1024 ** 3:.0f} GB a database refresh needs; "
                "passing over it")
            continue
        base = path
        break
    if base is None:
        system = Path(tempfile.gettempdir())
        if near is not None and is_inside(system, near):
            # The containment rule has to hold on the last resort too, or the
            # failure it exists to prevent simply moves here: a scratch under the
            # cache is carried off by the promotion rename, and the run ends with
            # no live cache at all. Low free space only makes the download likely
            # to fail, which is why the fallback tolerates it; containment makes
            # the promotion certain to destroy the cache, and the two are not
            # comparable.
            #
            # The parent of the cache is an ancestor rather than a descendant, so
            # it satisfies the rule by construction. It was passed over above, but
            # only for room, and a volume that is probably too small is a better
            # answer than one that is certainly fatal.
            base = real_near.parent if real_near else system
            if not base.is_dir():
                raise RuntimeError(
                    f"no scratch base is usable: the system temporary directory {system} sits "
                    f"inside the cache {near}, where a scratch would be carried away by the "
                    f"promotion, and the cache parent {base} is not a directory. Set "
                    "LOCKFILE_SENTINEL_SCRATCH to a directory outside the cache."
                )
            log(f"the system temporary directory {system} is inside the cache {near}, where a "
                f"scratch would be carried away by the promotion; using {base} instead "
                f"({describe_free(free_bytes(base))}), short of room though it may be")
        else:
            base = system
            log(f"falling back to the system temporary directory {base} "
                f"({describe_free(free_bytes(base))}), which is the volume the Java index "
                "download ran out of room on")
    path = base / f"temp-{secrets.token_hex(8)}"
    path.mkdir(mode=0o700, exist_ok=False)
    log(f"scratch: {path} ({label})")
    try:
        # Inside the try, not between the mkdir and it. restrict_to_owner is
        # written to warn rather than raise, but it is the one step here that
        # shells out, and a step that only ever warns by construction is a
        # claim rather than a guarantee. Placed above the try it held that
        # guarantee for exactly as long as it stayed true: a raise there left
        # the directory behind with nothing to remove it, which is the leak
        # this contextmanager exists to prevent. Here the finally runs whatever
        # happens, so the guarantee is the block's rather than the function's.
        restrict_to_owner(path)
        yield path
    finally:
        # Not ignore_errors: this directory can hold a gigabyte, and a removal
        # that fails quietly leaks it where nothing later looks. The failure is
        # reported rather than raised, so it cannot mask the exception that a
        # failing download is in the middle of propagating.
        try:
            shutil.rmtree(path)
        except OSError as exc:
            log(f"WARNING: could not remove the scratch directory {path} ({exc}). It holds "
                "whatever the download left behind, and nothing else will clean it up.")


def target_trivy_db(args) -> int:
    """Refresh the Trivy vulnerability and Java databases.

    Updating the Trivy binary touches no database, and Trivy refreshes on demand
    during a scan, so the gap only opens when nobody has scanned recently, which
    is when a stale database is least likely to be noticed. On the host this was
    written for the gap had reached 8.2 days for the vulnerability database and
    72.7 days for the Java index before anyone looked."""
    trivy = resolve_trivy()
    if not trivy:
        log("FAIL: trivy not found on PATH")
        return 2
    log(f"trivy: {trivy}")

    before = trivy_freshness(trivy)
    report_trivy(before, "before")

    live = trivy_cache_dir_default()
    log(f"cache: {live}")

    # Decide whether there is anything to do, before spending a gigabyte on finding
    # out there was not. The staging cache starts empty, so Trivy has no local copy
    # to compare against and always concludes it needs to download: on 2026-08-07 it
    # fetched both databases 2.8 hours before either was due, then threw the result
    # away as identical. Roughly 1 GB a night, plus 90 s of ClamAV over it.
    #
    # The decision is all-or-nothing rather than per database, and that is forced by
    # the promotion step: it replaces the whole cache directory, so a staging cache
    # holding only the database that was due would drop the other one from the live
    # cache. If either is due, both are fetched.
    required = ["vulnerability"] if args.skip_java_db else ["vulnerability", "java"]
    undated = [name for name in required
               if before.get(name, {}).get("next_update") is None]
    due = [name for name in overdue(before) if name in required]

    if args.force:
        log("--force given, so the databases are refreshed whether or not they are due")
    elif undated:
        # A database Trivy cannot date is not evidence of a database that is current.
        log(f"no next-update time for: {', '.join(undated)}; treating that as due, "
            "since a database that cannot be dated is not a database known to be fresh")
    elif due:
        log(f"due now: {', '.join(due)}")
    else:
        # `undated` is exactly the required databases whose next_update is None, and
        # it is empty here, so the filter drops nothing. Writing it as a filter rather
        # than a suppression keeps the type checker on this line, and the length check
        # turns a relaxed guard above into an error rather than the soonest of a
        # smaller set, which would be a wrong answer reported as a right one.
        stamps = [before[name]["next_update"] for name in required]
        dated = [stamp for stamp in stamps if stamp is not None]
        if len(dated) != len(stamps):
            raise RuntimeError("a required database has no next-update time here")
        soonest = min(dated)
        log(f"nothing is due yet, next at {describe_age(soonest)}; skipping the download. "
            "Pass --force to refresh anyway")
        return 0

    # Download into a staging cache, gate it there, and only then put it where
    # Trivy reads from. Downloading straight into the live cache overwrote the
    # databases before anything scanned them, so a rejected download was already
    # the copy every later Trivy run consumed, including this scanner's own
    # corroboration pass. Refusing to trust it after the fact changed nothing.
    with scratch_dir("trivy databases", near=live) as staging:
        staged = staging / "cache"
        staged.mkdir(parents=True, exist_ok=True)
        # The temporary directory goes to the same scratch as the staging cache.
        # Trivy's OCI downloader writes the compressed artifact into its own
        # temporary directory before unpacking it into the cache, so pointing
        # only TRIVY_CACHE_DIR at a roomy volume leaves the larger of the two
        # writes wherever the runtime's temporary directory happens to be.
        #
        # All three variables are set because Go reads different ones per
        # platform: os.TempDir takes TMPDIR on Unix and falls back to /tmp,
        # while Windows takes TMP then TEMP. Setting only the Windows pair
        # left this fix doing nothing at all on Linux.
        child_env = dict(os.environ, TRIVY_CACHE_DIR=str(staged),
                         TMPDIR=str(staging), TMP=str(staging), TEMP=str(staging))
        for flag, label in (("--download-db-only", "vulnerability"),
                            ("--download-java-db-only", "Java index")):
            if flag == "--download-java-db-only" and args.skip_java_db:
                continue
            log(f"downloading the {label} database into the staging cache ...")
            code, out = run([trivy, "image", flag], env=child_env)
            echo(out, "trivy")
            if code != 0:
                log(f"FAIL: {label} database download exited {code}; "
                    "the live cache is untouched")
                return 1

        if not gate(staged, "the downloaded Trivy databases", args.skip_scan):
            log("the rejected download was discarded; the live cache is untouched")
            return 1

        staged_freshness = trivy_freshness(trivy, env=child_env)
        report_trivy(staged_freshness, "downloaded")
        if not staged_freshness:
            log("FAIL: could not read database metadata from the download, so its state "
                "is unknown and it will not be promoted")
            return 2
        still = overdue(staged_freshness)
        if still:
            log(f"FAIL: still overdue after the download: {', '.join(still)}; not promoting")
            return 1

        try:
            promote_into(staged, live)
        except OSError as exc:
            log(f"FAIL: could not promote the gated databases into {live} ({exc})")
            return 1

    log(f"Trivy databases current, promoted into {live}")
    return 0


# --------------------------------------------------------------------------
# Target: status.
# --------------------------------------------------------------------------

def target_status(_args) -> int:
    """Report the freshness of everything this program maintains.

    Exit 0 when all fresh, 1 when something is stale, 2 when something could not
    be determined, following the house rule that a check which could not run
    must not report health."""
    stale = False
    unknown = False

    go = resolve_go()
    exe = go_bin(go) if go else None
    installed = osv_version(exe)
    state = read_state(OSV_STATE)
    log(f"osv-scanner: {installed or 'not installed'} at {exe or 'unknown'}")
    if state.get("lastCommit"):
        log(f"  built from commit {str(state['lastCommit'])[:12]}")
    last_check = state.get("lastCheckUnix")
    if isinstance(last_check, (int, float)):
        age = (time.time() - last_check) / 3600.0
        log(f"  version last checked {age:.1f} h ago")
        stale = stale or age > 24
    else:
        log("  version last checked: unknown")
        unknown = True

    overlay = overlay_path()
    data = read_state(overlay)
    if data:
        log(f"overlay: {data.get('package_count', '?')} packages, "
            f"{data.get('version_count', '?')} versions at {overlay}")
        generated = parse_stamp(str(data.get("generated_utc") or "").replace("Z", "+00:00"))
        log(f"  generated {describe_age(generated)}")
        if generated is not None:
            stale = stale or (datetime.now(timezone.utc) - generated).total_seconds() > 24 * 3600
        else:
            unknown = True
    else:
        log(f"overlay: absent or unreadable at {overlay}")
        unknown = True

    offline = offline_db_dir()
    if offline.is_dir():
        newest = max((p.stat().st_mtime for p in offline.rglob("*") if p.is_file()), default=0)
        log(f"offline database: present at {offline}, newest file "
            f"{(time.time() - newest) / 3600.0:.1f} h old")
    else:
        log(f"offline database: not present ({offline}), online mode is always current")

    trivy = resolve_trivy()
    if trivy:
        freshness = trivy_freshness(trivy)
        report_trivy(freshness, "trivy")
        # No metadata means the state could not be determined, which is exit 2
        # rather than a pass. Reading it as "nothing overdue" let a status run
        # report health for a check that never produced an answer.
        if not freshness:
            unknown = True
        stale = stale or bool(overdue(freshness))
    else:
        log("trivy: not found")
        unknown = True

    if unknown:
        return 2
    return 1 if stale else 0


# --------------------------------------------------------------------------

TARGETS = {
    "osv-scanner": target_osv_scanner,
    "malicious-packages": target_malicious_packages,
    "offline-db": target_offline_db,
    "trivy-db": target_trivy_db,
    "status": target_status,
}


def main() -> int:
    """Run the requested target, or every one of them in order."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("target", choices=(*TARGETS, "all"), help="What to bring up to date.")
    parser.add_argument("--min-interval", type=int, default=0,
                        help="Skip when this target ran less than this many minutes ago "
                             "(default: 0, always run).")
    parser.add_argument("--force", action="store_true",
                        help="Ignore the throttle. For trivy-db, also download even when "
                             "no database is due yet.")
    parser.add_argument("--check-only", action="store_true",
                        help="osv-scanner: report versions without installing.")
    parser.add_argument("--skip-scan", action="store_true",
                        help="Skip the ClamAV gate. For a host with no ClamAV at all.")
    parser.add_argument("--from-source", action="store_true",
                        help="osv-scanner: build from a git working tree.")
    parser.add_argument("--source-dir", default="",
                        help="Working tree for --from-source.")
    parser.add_argument("--ref", default="",
                        help="Tag or branch to build in source mode. Default: the latest tag.")
    parser.add_argument("--output", default="",
                        help="malicious-packages: where to write the overlay.")
    parser.add_argument("--source-url", default=DATADOG_CSV_URL,
                        help="malicious-packages: the IOC feed to read.")
    parser.add_argument("--skip-java-db", action="store_true",
                        help="trivy-db: refresh only the vulnerability database.")
    args = parser.parse_args()

    if not args.source_dir:
        # A working tree for --from-source, under the cache root rather than
        # anywhere near this file, so a source build never writes into a
        # checkout of this repository.
        args.source_dir = str(cache_dir() / "osv-scanner-src")

    rotate_log()
    log(f"run start: {args.target}")

    if args.target == "all":
        worst = 0
        for name in ("osv-scanner", "malicious-packages", "offline-db", "trivy-db"):
            log(f"--- {name} ---")
            worst = max(worst, TARGETS[name](args))
        log(f"run end: all targets, worst exit {worst}")
        return worst

    code = TARGETS[args.target](args)
    log(f"run end: {args.target}, exit {code}")
    return code


if __name__ == "__main__":
    sys.exit(main())
