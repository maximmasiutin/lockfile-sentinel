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
import csv
import io
import json
import os
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

IS_WINDOWS = os.name == "nt"
OSV_EXE = "osv-scanner.exe" if IS_WINDOWS else "osv-scanner"
TRIVY_EXE = "trivy.exe" if IS_WINDOWS else "trivy"


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
    above 2 GiB and says so only in a warning, so such a file is reported here
    as unscanned rather than counted as clean.

    Fail closed: anything other than a confirmed clean result returns False."""
    if skip:
        log(f"ClamAV gate skipped by request: {what}")
        return True
    if not target.exists():
        log(f"FAIL: nothing to scan at {target}")
        return False

    files = [p for p in target.rglob("*") if p.is_file()] if target.is_dir() else [target]
    largest = max((p.stat().st_size for p in files), default=0)
    for path in files:
        if path.stat().st_size > CLAMSCAN_FILE_CEILING:
            log(f"WARNING: {path} is {path.stat().st_size / 1024 / 1024:.0f} MB, above the 2 GiB "
                "scanner ceiling; it was NOT scanned and must not be read as clean")

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
    code, out = run([go, "install", target])
    echo(out, "go")
    if code != 0:
        log(f"FAIL: go install exited {code}; existing osv-scanner left in place")
        return 1
    exe = go_bin(go)
    if not exe or not exe.exists():
        log("FAIL: osv-scanner not found after go install")
        return 2
    if not gate(exe, "the built osv-scanner", args.skip_scan):
        return 1
    after = osv_version(exe)
    write_state(OSV_STATE, {"lastVersion": after})
    if after == latest:
        log(f"osv-scanner updated: {installed or 'not installed'} -> {after}")
        return 0
    log(f"WARNING: built {latest} but --version now reports '{after}'")
    return 1


# --------------------------------------------------------------------------
# Target: malicious-packages, the campaign overlay.
# --------------------------------------------------------------------------

def _pick_column(fieldnames: list[str] | None, candidates: tuple[str, ...]) -> str | None:
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
    except Exception as exc:  # noqa: BLE001 - degrade to the floor rather than fail
        log(f"WARNING: could not refresh from the feed ({exc}); writing the built-in floor only")

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
    if "keyv" not in out:
        log("WARNING: the database refreshed but the control did not flag keyv; "
            "verify the database rather than trusting this run")
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


def trivy_freshness(trivy: str) -> dict[str, dict[str, datetime | None]]:
    """Return {database: {updated, next_update}} as Trivy reports it."""
    code, out = run([trivy, "version", "--format", "json"], timeout=120)
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
    cache = trivy_cache_dir()
    log(f"trivy: {trivy}")
    log(f"cache: {cache if cache else 'unresolved'}")

    before = trivy_freshness(trivy)
    report_trivy(before, "before")

    for flag, label in (("--download-db-only", "vulnerability"),
                        ("--download-java-db-only", "Java index")):
        if flag == "--download-java-db-only" and args.skip_java_db:
            continue
        log(f"downloading the {label} database ...")
        code, out = run([trivy, "image", flag])
        echo(out, "trivy")
        if code != 0:
            log(f"FAIL: {label} database download exited {code}")
            return 1

    after = trivy_freshness(trivy)
    report_trivy(after, "after")

    if cache and cache.is_dir() and not gate(cache, "the Trivy databases", args.skip_scan):
        return 1

    # A database still past its own NextUpdate after a download that reported
    # success means the download did not achieve what it claimed.
    still = overdue(after)
    if still:
        log(f"FAIL: still overdue after the refresh: {', '.join(still)}")
        return 1
    log("Trivy databases current")
    return 0


# --------------------------------------------------------------------------
# Target: status.
# --------------------------------------------------------------------------

def target_status(args) -> int:
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
    parser.add_argument("--force", action="store_true", help="Ignore the throttle.")
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
