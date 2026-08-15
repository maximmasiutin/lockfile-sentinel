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

# Lockfile Sentinel 0.2.0
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
import errno
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
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

# Carried per file rather than imported, because each of these three runs on its
# own and an imported version would tie a standalone copy back to a checkout it
# may not have. tests/test_headers.py is what keeps the three from drifting.
__version__ = "0.2.0"

IS_WINDOWS = os.name == "nt"


def user_cache_base() -> Path:
    """The per-user cache root the platform convention names.

    One resolver for every cache path this program computes, because the
    fallback spellings were drifting candidates: a base spelled differently in
    one resolver is a cache written where the others never look."""
    if IS_WINDOWS:
        return Path(os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local"))
    return Path(os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache"))
OSV_EXE = "osv-scanner.exe" if IS_WINDOWS else "osv-scanner"
TRIVY_EXE = "trivy.exe" if IS_WINDOWS else "trivy"

# Where to put a scratch directory that needs several gigabytes. No drive letter
# is written here: LOCKFILE_SENTINEL_SCRATCH wins if set, and otherwise the
# scratch sits beside the cache the download is destined for, which is already
# named by an environment variable and is already on a volume sized to hold it.
# See scratch_dir for why this is not simply TEMP.
SCRATCH_BASE = os.environ.get("LOCKFILE_SENTINEL_SCRATCH", "")

# How much room a scratch base has to have before it is worth using, expressed
# per database so a run that stages less can require less. The Java index is
# roughly 900 MB compressed and is unpacked beside the archive it arrived in,
# so its peak is a multiple of the download rather than the download; the
# vulnerability database is roughly a tenth its size. The total for a full
# refresh is measured rather than guessed: the failure this whole mechanism
# exists for had 2.74 GB free and that was not enough, and the two figures
# below sum to the 5 GB margin that has proved sufficient since. A base below
# the requirement is passed over with its figure logged, because finding out by
# running out of disk costs the download and reports it as an obscure write
# error. The requirement is derived from what staging will actually hold, not
# from which flags were passed, so it stays correct if the set of staged
# databases ever changes for another reason.
SCRATCH_NEED_BYTES = {
    "vulnerability": 512 * 1024 ** 2,
    "java": 4608 * 1024 ** 2,
}
SCRATCH_MIN_FREE_BYTES = sum(SCRATCH_NEED_BYTES.values())


def cache_dir() -> Path:
    """The cache root for everything this program writes.

    lockfile_sentinel.py carries an identical resolver, because each file has to
    stand alone when copied; change the two together or the scanner's --status
    will look somewhere this program never wrote."""
    explicit = os.environ.get("LOCKFILE_SENTINEL_CACHE")
    if explicit:
        return Path(explicit)
    return user_cache_base() / "lockfile-sentinel"


LOG_DIR = cache_dir() / "logs"
LOG_FILE = LOG_DIR / "update-scanners.log"
MAX_LOG_BYTES = 1024 * 1024

# State file names are what lockfile_sentinel.py --status reads. Rename one here
# and the scanner reports the input as never refreshed.
OSV_STATE = LOG_DIR / "update-osv-scanner.state.json"
OVERLAY_STATE = LOG_DIR / "update-malicious-packages.state.json"
# Which Trivy binary last wrote the promoted databases. NextUpdate stamps know
# nothing about binaries, so without this record an upgraded Trivy expecting a
# schema the cache does not carry reads "nothing due" over a cache it cannot
# use, and the failure surfaces later, in a scan, as an obscure error.
TRIVY_STATE = LOG_DIR / "update-trivy-db.state.json"

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


def resolve_system_tool(name: str) -> str:
    """The System32 path of a Windows utility, or the bare name if it is absent.

    A bare name handed to subprocess is resolved by CreateProcess, which looks
    in the application directory and the current directory before PATH, so an
    executable planted in any of the three runs in place of the system copy.
    This script is meant to run from a scheduled task, often as a more
    privileged account than the ones that can write to those places, which is
    what makes the substitution worth someone's while.

    Resolved against %SystemRoot%\\System32 rather than with `shutil.which`,
    because which searches PATH and therefore closes only the current-directory
    vector. Measured on Python 3.13 with a decoy whoami.exe: a decoy in the
    current directory lost to System32, and a decoy first on PATH won. A PATH
    entry ahead of System32 is exactly the planting an unprivileged account can
    arrange, so a resolver that consults PATH is a fix that reads as one and is
    not.

    The bare name is kept as the fallback when the file is not there, so a host
    with an unusual layout still runs and fails with the tool's own message
    rather than a fabricated one. `name` therefore needs its extension, since
    the file test sees no PATHEXT. With SystemRoot unset, the usual Unix case,
    the bare name is returned at once: a hardcoded default would be a relative
    path there, reopening the current-directory vector."""
    root = os.environ.get("SystemRoot")
    if not root:
        return name
    candidate = Path(root) / "System32" / name
    return str(candidate) if candidate.is_file() else name


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
    for candidate in _clamd_conf_candidates():
        try:
            text = candidate.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == "MaxFileSize":
                return _parse_clamd_size(parts[1])
    return None


def _clamd_conf_candidates() -> list[Path]:
    """Every place a clamd.conf may sit, most authoritative first."""
    candidates: list[Path] = []
    explicit = os.environ.get("CLAMD_CONF")
    if explicit:
        candidates.append(Path(explicit))
    daemon = shutil.which("clamd") or shutil.which("clamdscan")
    if daemon:
        candidates.append(Path(daemon).resolve().parent / "clamd.conf")
    candidates += [Path("/etc/clamav/clamd.conf"), Path("/usr/local/etc/clamd.conf"),
                   Path("/opt/homebrew/etc/clamav/clamd.conf")]
    return candidates


def _parse_clamd_size(value: str) -> int | None:
    """A clamd.conf size value in bytes, or None where it does not parse."""
    raw = value.upper()
    multiplier = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}.get(raw[-1:], 1)
    digits = raw[:-1] if multiplier > 1 else raw
    try:
        return int(digits) * multiplier
    except ValueError:
        return None


def _refuse_oversized(files: list[Path], what: str) -> bool:
    """True when a file exceeds the 2 GiB libclamav ceiling.

    A file above the ceiling is refused rather than warned about. Neither
    scanner reads it, and both still exit 0, so warning and continuing meant
    returning a clean verdict for bytes nothing had looked at. That is the one
    outcome a gate must never produce, and gate's docstring claimed it was
    already refused when it was not."""
    oversized = [p for p in files if p.stat().st_size > CLAMSCAN_FILE_CEILING]
    if not oversized:
        return False
    for path in oversized:
        log(f"FAIL: {path} is {path.stat().st_size / 1024 / 1024:.0f} MB, above the 2 GiB "
            "libclamav ceiling, so no scanner here can read it")
    log(f"refusing to trust {what}: {len(oversized)} file(s) could not be scanned at all")
    return True


def _scan_command(target: Path, largest: int, what: str) -> tuple[list[str], str] | None:
    """The scanner invocation the sizes allow, or None where nothing can read them."""
    cap = clamd_max_file_size()
    clamdscan = resolve_clam("clamdscan")
    use_daemon = bool(clamdscan) and cap is not None and largest <= cap
    if clamdscan and not use_daemon:
        log(f"daemon not used for {what}: largest file is {largest / 1024 / 1024:.0f} MB against "
            f"a clamd MaxFileSize of "
            f"{'unknown' if cap is None else f'{cap / 1024 / 1024:.0f} MB'}")
    if use_daemon:
        return ([str(clamdscan), "--multiscan", "--infected", "--no-summary", str(target)],
                "clamdscan")
    clamscan = resolve_clam("clamscan")
    if not clamscan:
        log(f"FAIL: no ClamAV scanner able to read files this size; refusing to trust {what}")
        return None
    return [clamscan, "--recursive", "--infected", "--no-summary",
            "--max-filesize=0", "--max-scansize=0", str(target)], "clamscan"


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

    if _refuse_oversized(files, what):
        return False

    chosen = _scan_command(target, largest, what)
    if chosen is None:
        return False
    cmd, label = chosen

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
    match = re.search(r"osv-scanner version:\s*(\d\S*)", out)
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
    return user_cache_base() / "trivy"


def trivy_cache_dir() -> Path | None:
    """The cache Trivy will actually use, or None when it cannot be determined.

    Trivy's own default is read rather than imposed, because a refresh written
    anywhere else is a refresh Trivy will not find."""
    explicit = os.environ.get("TRIVY_CACHE_DIR")
    if explicit:
        return Path(explicit)
    candidate = user_cache_base() / "trivy"
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
            # The URL is one of two module-level https constants, and the
            # https-only opener keeps a redirect from carrying the connection
            # somewhere those constants do not name.
            with open_https(request, timeout=timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
            value = data.get(key)
            if value:
                return str(value)
        # Broad on purpose: whatever this source's failure was, the next
        # source is the answer, and only after both comes the None.
        except Exception as exc:  # noqa: BLE001
            log(f"{url} lookup failed ({exc})")
    return None


def _sync_source_tree(git: str, source_dir: Path) -> int:
    """Clone the repository, or fetch into the working tree already there."""
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
    return 0


def _checkout_target(git: str, source_dir: Path, target_ref: str) -> bool | None:
    """Check out the ref, saying whether it was a branch; None means failure.

    A tag is checked out detached; a branch is fast-forwarded. Nothing merges
    or rebases, so the tree cannot end up conflicted."""
    code, _ = run([git, "-C", str(source_dir), "-c", "advice.detachedHead=false",
                   "checkout", "--quiet", "--detach", f"refs/tags/{target_ref}"])
    if code == 0:
        return False
    code, out = run([git, "-C", str(source_dir), "checkout", "--quiet", target_ref])
    echo(out, "git")
    if code != 0:
        log(f"FAIL: '{target_ref}' is neither a tag nor a branch in {source_dir}")
        return None
    code, out = run([git, "-C", str(source_dir), "merge", "--ff-only", "--quiet",
                     f"origin/{target_ref}"])
    echo(out, "git")
    if code != 0:
        log(f"FAIL: could not fast-forward {target_ref}")
        return None
    return True


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

    code = _sync_source_tree(git, source_dir)
    if code != 0:
        return code

    # A checkout over uncommitted work discards it. Refuse rather than decide
    # on the user's behalf that their edits were disposable.
    _, out = run([git, "-C", str(source_dir), "status", "--porcelain"])
    dirty = [line for line in out.splitlines() if line.strip()]
    if dirty and not args.force:
        log(f"FAIL: {source_dir} has {len(dirty)} uncommitted change(s); refusing to check out "
            f"{target_ref}. Commit, stash, or pass --force.")
        return 1

    on_branch = _checkout_target(git, source_dir, target_ref)
    if on_branch is None:
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

    return _compile_and_swap(args, go, exe, source_dir, expected, head, commit_date,
                             installed, short)


def _compile_and_swap(args, go: str, exe: Path, source_dir: Path, expected: str,
                      head: str, commit_date: str, installed: str | None, short: str) -> int:
    """Build beside the live binary and swap only after the gate and the version
    check pass; writing straight to the target fails while the old one runs."""
    exe.parent.mkdir(parents=True, exist_ok=True)
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

    return _go_install_latest(args, go, latest, installed)


def _go_install_latest(args, go: str, latest: str, installed: str | None) -> int:
    """Build the released module with go install, gate it, and swap it in."""
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


class HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse any redirect whose target leaves https.

    urlopen follows redirects across schemes, so a checked https URL can still
    hand the connection to cleartext one hop later: the feed host answers 302
    with an http location, the downgrade is followed silently, and the scheme
    gate above the call never sees it. Raised as URLError so the caller's
    existing failure path reports it and keeps the previous overlay."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise urllib.error.URLError(f"refusing a redirect off https: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_https(request: urllib.request.Request, timeout: int):
    """Open an https request through an opener that cannot be redirected off it.

    The scheme of the request's own URL is the caller's gate; this closes the
    hop that gate cannot see."""
    opener = urllib.request.build_opener(HttpsOnlyRedirects())
    return opener.open(request, timeout=timeout)  # nosec B310 # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected


def target_malicious_packages(args) -> int:
    """Refresh the campaign overlay from the consolidated IOC feed."""
    output = Path(args.output) if args.output else overlay_path()
    if not args.force and output.exists() and throttled(
        OVERLAY_STATE, "lastRefreshUnix", args.min_interval, "the campaign overlay"
    ):
        return 0

    # The feed URL is operator-supplied, and urlopen would happily read a
    # file:// or http:// source. A local file is not a feed, and a cleartext
    # fetch invites the substitution this overlay exists to catch, so anything
    # but https is refused before a request is built. urlsplit itself raises on
    # a malformed authority such as an unmatched bracket, and a mistyped URL
    # deserves the same one-line refusal as a wrong scheme, not a traceback.
    try:
        scheme = urllib.parse.urlsplit(args.source_url).scheme
    except ValueError:
        scheme = ""
    if scheme != "https":
        log(f"refusing a non-https IOC feed URL: {args.source_url}")
        return 1

    log(f"fetching campaign IOC feed: {args.source_url}")
    packages: dict[str, set[str]] = {}
    sources: list[str] = []
    try:
        request = urllib.request.Request(
            args.source_url, headers={"User-Agent": "update-scanners"}
        )
        with open_https(request, timeout=60) as response:
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
        parsed = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # Trivy's timestamps are UTC by contract. Left naive, astimezone() in
        # overdue and describe_age would read the value as local time and every
        # freshness judgement would shift by the host's UTC offset, silently.
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


TrivyFreshness = dict[str, dict[str, "datetime | int | None"]]


def trivy_freshness(trivy: str, env: dict[str, str] | None = None
                    ) -> TrivyFreshness:
    """Return {database: {updated, next_update, schema}} as Trivy reports it.

    An empty result means the state could not be determined, not that the
    databases are fine; every caller has to treat it that way. `schema` is the
    metadata's own Version integer, carried through so status can report a
    cache whose schema the installed binary does not expect; it was read and
    discarded before, which left status unable to describe the one mismatch
    the offline, air-gapped case cannot repair by scanning."""
    # The exit code is deliberately ignored: Trivy reports a non-zero code for
    # conditions that still print usable version JSON, and an unparseable body
    # is handled below, so the output is the only thing worth testing.
    _code, out = run([trivy, "version", "--format", "json"], timeout=120, env=env)
    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError:
        return {}
    result: TrivyFreshness = {}
    for key, label in (("VulnerabilityDB", "vulnerability"), ("JavaDB", "java")):
        entry = data.get(key)
        if isinstance(entry, dict):
            schema = entry.get("Version")
            result[label] = {
                "updated": parse_stamp(entry.get("UpdatedAt")),
                "next_update": parse_stamp(entry.get("NextUpdate")),
                "schema": schema if isinstance(schema, int) else None,
            }
    return result


def trivy_binary_version(trivy: str) -> str | None:
    """The installed Trivy's own version string, or None when it will not say.

    Read from the same `version --format json` answer the freshness comes
    from, but as a separate call on purpose: freshness is asked about a
    specific cache through TRIVY_CACHE_DIR, while the binary version is a
    property of the executable alone."""
    _code, out = run([trivy, "version", "--format", "json"], timeout=120)
    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError:
        return None
    version = data.get("Version")
    return version if isinstance(version, str) and version else None


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


def overdue(freshness: TrivyFreshness) -> list[str]:
    """Return the databases whose NextUpdate is already in the past."""
    now = datetime.now(timezone.utc)
    return [
        label for label, entry in freshness.items()
        if isinstance(stamp := entry.get("next_update"), datetime)
        and stamp.astimezone(timezone.utc) < now
    ]


def report_trivy(freshness: TrivyFreshness, when: str) -> None:
    """Log the state of each Trivy database."""
    if not freshness:
        log(f"{when}: Trivy reported no database metadata")
        return
    stale = set(overdue(freshness))
    for label, entry in freshness.items():
        state = "OVERDUE" if label in stale else "current"
        schema = entry.get("schema")
        suffix = f", schema v{schema}" if schema is not None else ""
        updated = entry.get("updated")
        next_due = entry.get("next_update")
        log(f"{when}: {label} db {state}, "
            f"updated {describe_age(updated if isinstance(updated, datetime) else None)}, "
            f"next due {describe_age(next_due if isinstance(next_due, datetime) else None)}"
            f"{suffix}")


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


class ScratchSwappedError(RuntimeError):
    """The staged tree is not the one that was scanned.

    A distinct type so the caller can report a substituted directory as a
    refusal with its own message rather than as a malfunction."""


def dir_identity(path: Path) -> tuple[int, int]:
    """The (device, inode) of the entry at `path`, not of what it points at.

    lstat, so a link left where the directory was answers for itself and fails
    the comparison. Following it would report the identity of the moved-aside
    original and pass. st_ino is meaningful on Windows too: since 3.5 CPython
    fills it from the NTFS file index, which is what GetFileInformationByHandle
    reports."""
    info = path.lstat()
    return info.st_dev, info.st_ino


SCRATCH_MARKER = ".lockfile-sentinel-scratch-id"


def _mark_scratch(staged: Path) -> str:
    """Write a random token into the staged tree and return it.

    The token is what an identity comparison cannot supply: two stats taken
    either side of a copy agree again if the original directory is renamed back
    before the second one, so a tree substituted only for the duration of the
    copy passes. A copy carrying this token came from the directory that held
    it, and the directory's ACL is what keeps the token unreadable."""
    token = secrets.token_hex(16)
    (staged / SCRATCH_MARKER).write_text(token, encoding="utf-8")
    return token


def _require_marker(copied: Path, token: str) -> None:
    """Refuse a copy that does not carry the token the source was marked with."""
    try:
        found = (copied / SCRATCH_MARKER).read_text(encoding="utf-8")
    except OSError as exc:
        raise ScratchSwappedError(
            f"the copy at {copied} carries no scratch marker ({exc}), so it did not "
            "come from the tree the scanner passed") from exc
    if found != token:
        raise ScratchSwappedError(
            f"the copy at {copied} carries a different scratch marker, so its source "
            "was substituted while it was being copied")


def _refuse_if_swapped(staged: Path, identity: tuple[int, int] | None,
                       when: str = "before the promotion") -> None:
    """Refuse when `staged` is no longer the directory `identity` came from.

    Narrows the window rather than closing it: an account able to rename the
    scratch aside can still do so between this stat and the operation that
    follows. A handle held open across the whole interval would close it, but
    the call that opens a directory handle is Windows-only, and portable code
    here is worth more than the remaining microseconds.

    A reparse point at the name is refused outright rather than compared. It
    cannot match an lstat identity recorded for a real directory, but saying so
    in its own words names what happened."""
    if identity is None:
        return
    if is_reparse_point(staged):
        raise ScratchSwappedError(
            f"the staged tree {staged} is a link rather than the directory that was "
            "scanned, so another account replaced it after the gate")
    try:
        current = dir_identity(staged)
    except OSError as exc:
        raise ScratchSwappedError(
            f"the staged tree {staged} could not be stat'd {when} ({exc}), so it "
            "cannot be shown to be the tree the scanner passed") from exc
    if current != identity:
        raise ScratchSwappedError(
            f"the staged tree {staged} is not the directory that was scanned: it was "
            f"{identity} when it was created and is {current} now, so another account "
            f"replaced it after the gate and {when}")


def promote_into(staged: Path, live: Path, keep: tuple[str, ...] = (),
                 staged_identity: tuple[int, int] | None = None) -> None:
    """Replace the live cache with the staged one, keeping the old copy until it lands.

    The order matters and is the reason this is a function rather than four lines
    inline. The staged tree is brought onto the destination volume first, as an
    `.incoming` sibling of the cache, because that is the one step that can be a
    copy rather than a rename: when the scratch sits on another filesystem a
    move is a file-by-file copy that can fail part-way, and the staging design
    exists precisely so that a partial tree never stands where Trivy reads. With
    the copy done while `live` is untouched, everything after it is a rename
    within one volume, cheap and atomic. The live tree is renamed aside next, so
    that a failure leaves a complete cache under `.previous` instead of a
    half-populated one at `live`, and if the final rename into place fails the
    `.previous` copy is renamed straight back, so `live` is never left absent.

    `keep` names child directories to carry forward from the outgoing cache
    when the staged tree does not hold them: a run that deliberately skipped a
    database must not delete the copy the cache already has. The carry is a
    rename out of `.previous` after the swap, within one volume, so it moves no
    data; a failure there is logged rather than raised, because the promotion
    itself has already succeeded and the carried database is re-downloadable.

    This assumes the caller has established that `staged` is not inside `live`.
    The `.incoming` step happens to move such a tree out before the cache is
    renamed aside, but that is an accident of ordering, not a contract: a
    staged tree inside the cache still means the scratch base was configured
    into the very directory being replaced, which is a mistake worth refusing.
    That is what `is_inside` exists to prevent, at the call site,
    where the answer is still useful: a caller that gets True there picks a
    different scratch base and proceeds. Repeating the check here would run
    before the rename and so would prevent the damage, but `is_inside` answers
    True for a path it cannot resolve, and that fail-closed answer would abort a
    promotion that was about to succeed on a cache which merely could not be
    stat'd at that moment.

    `staged_identity` is the (device, inode) the caller recorded when it made
    the staged tree. It is re-read immediately before the tree leaves the
    scratch, and again after a cross-device copy, which also has to carry the
    marker token written just before it, since an identity restored after a
    substitution passes a comparison and cannot forge a token. A failure of
    either refuses the promotion: between the ClamAV gate and the rename the tree is otherwise
    trusted by pathname alone, and a base that grants another account
    DELETE_CHILD lets that account rename the scanned tree aside and leave its
    own at the same name.

    OSError propagates. The caller reports it, because it is the caller that
    knows the run this was part of. ScratchSwappedError propagates the same way.
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
    incoming = live.with_name(live.name + ".incoming")
    # A promotion killed between its two renames leaves the only good cache
    # at .previous and nothing at live. Restore it before any cleanup below,
    # because the .previous clearing a few lines down would otherwise delete
    # the only copy while live is absent, and a second failure of the swap
    # would then leave no cache at all.
    if not live.exists() and previous.exists():
        log(f"an interrupted promotion left the cache renamed aside at {previous}; "
            "restoring it before promoting")
        os.replace(previous, live)
    # A leftover .incoming is a promotion that died between the copy and the
    # swap on an earlier run; it was never trusted, so it is cleared rather
    # than adopted.
    if incoming.exists():
        shutil.rmtree(incoming)
    # Here rather than at the top of the function: the restore and the rmtree
    # above can take a while on a large leftover tree, and a check that ran
    # before them would leave that whole interval unguarded.
    _refuse_if_swapped(staged, staged_identity)
    # Marked after the identity check and before the copy, so the token names
    # this tree at the moment it was last shown to be the scanned one.
    token = _mark_scratch(staged) if staged_identity is not None else None
    try:
        # Same volume: a rename, and the except clause never runs. Another
        # volume: rename fails (EXDEV on POSIX, a not-same-device error on
        # Windows), and the copy happens here, while the live cache is still
        # complete and still in place.
        os.replace(staged, incoming)
    except OSError as exc:
        # Only a not-same-device rename earns the copy. Falling back on any
        # OSError turned a permission or missing-path failure into a copy that
        # half-writes the incoming tree and then reports its own error in place
        # of the real cause. Windows raises error 17 here rather than EXDEV.
        if exc.errno != errno.EXDEV and getattr(exc, "winerror", None) != 17:
            raise
        # The cross-device path reads the source by pathname for as long as a
        # gigabyte takes to copy, so the check above covers none of it. The
        # copy is required to carry the token as well as the source to still
        # have the identity: an ABA rename, aside during the copy and back
        # before the check, restores the inode and defeats the comparison
        # alone, but not a token the substituted tree could not read.
        shutil.copytree(staged, incoming)
        try:
            _refuse_if_swapped(staged, staged_identity, when="during the copy")
            if token is not None:
                _require_marker(incoming, token)
        except ScratchSwappedError:
            shutil.rmtree(incoming, ignore_errors=True)
            raise
    # The marker belongs to the transfer, not to the cache Trivy reads.
    (incoming / SCRATCH_MARKER).unlink(missing_ok=True)
    if previous.exists():
        shutil.rmtree(previous, ignore_errors=True)
    if live.exists():
        os.replace(live, previous)
    try:
        os.replace(incoming, live)
    except OSError:
        # Put the outgoing cache back before reporting, so a failed swap
        # leaves the previous good databases where Trivy reads rather than
        # nothing at all.
        if previous.exists() and not live.exists():
            os.replace(previous, live)
        raise
    _carry_kept_forward(previous, live, keep)
    shutil.rmtree(previous, ignore_errors=True)


def _carry_kept_forward(previous: Path, live: Path, keep: tuple[str, ...]) -> None:
    """Rename each kept database out of the outgoing cache into the new one.

    Same volume by construction, so this moves no data. A failure is logged
    rather than raised, because the promotion has already succeeded and the
    carried database is re-downloadable; a name the staged tree already holds
    is left alone, since the download is fresher than the carry."""
    for name in keep:
        held = previous / name
        if not held.is_dir() or (live / name).exists():
            continue
        try:
            os.replace(held, live / name)
        except OSError as exc:
            log(f"WARNING: could not carry {name} forward from the previous cache "
                f"({exc}); it will be downloaded again on the next run that needs it")


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
    read, so raising instead would break that contract from the inside. The
    caller now resolves this before it creates the scratch directory, precisely
    so that the interval between creating and hardening holds no process spawn,
    which means a raise here would abort the run before any directory exists
    rather than leaking one."""
    code, output = run([resolve_system_tool("whoami.exe"),
                        "/user", "/fo", "csv", "/nh"], timeout=30)
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


def is_reparse_point(path: Path) -> bool:
    """Whether this name is a link of some kind rather than the directory itself.

    The attribute rather than `Path.is_symlink()`, which answers False for a
    junction. Measured on 3.13: a junction reports `is_symlink()` False with the
    reparse attribute set and tag 0xa0000003, while a symbolic link reports both.
    That is the wrong way round for a check like this. Creating a symbolic link
    needs SeCreateSymbolicLinkPrivilege or Developer Mode, while a junction needs
    nothing beyond write access to the parent, so the attack any account can
    mount is precisely the one `is_symlink()` would have waved through.

    False off Windows, where there is no such attribute and where the scratch
    base is not the shared directory this guards against."""
    if sys.platform != "win32":
        return False
    try:
        return bool(os.lstat(path).st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT)
    except OSError:
        # A name that cannot be stat'd is not a name this program should stage
        # a database through, so the conservative answer is the same as for a
        # link: refuse it rather than continue on an unread directory.
        return True


def restrict_to_owner(path: Path, sid: str | None) -> None:
    """Cut a Windows directory's inherited ACL down to this account, SYSTEM and administrators.

    `sid` is resolved by the caller before the directory exists, deliberately.
    Resolving it here put a process spawn inside the interval between creating
    the directory and restricting it, which is the interval an attacker uses.

    This is a backstop, not the primary mechanism, and the distinction is the
    whole reason it is worth its two subprocesses. Since the fix for
    CVE-2024-4030, CPython special-cases `mkdir(mode=0o700)` on Windows and
    creates the directory with
    `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)`, which is already
    private. So on a current interpreter, on NTFS, the mode has done this job
    before this function runs and it finds nothing to fix. An earlier version of
    this docstring claimed Windows ignores the mode. That was true once and is
    not now, and the claim survived because the measurement behind it read the
    permissions of the scratch *base* rather than of a directory Python had
    actually created.

    What is left is the set of cases where that mechanism is silently absent,
    and the silence is what makes them worth covering:

      * Version. The fix shipped in 3.12.4, and this program supports 3.12 or
        newer, so 3.12.0 through 3.12.3 are in range and create the directory
        with the inherited ACL instead.
      * Mode. CPython tests `mode == 0700` for exact equality and ignores every
        other value, so editing that literal to anything else, however
        reasonable-looking, drops the protection without a word.
      * Build. The special case sits behind an API-set guard, and CPython's own
        comment says that where those APIs are missing it has "no choice but to
        silently create a directory with default ACL".
      * Filesystem. `CreateDirectoryW` accepts the security attributes and
        discards them on a filesystem that does not carry ACLs. That one is not
        hypothetical here: scratch_dir deliberately hunts for a volume with
        room, which is how a download ends up on an exFAT external disk or a
        network share.

    None of those raise. Each leaves the staged database in a directory the
    base's ACL governs, during the window between the ClamAV gate approving it
    and the promotion installing it, which is a local user's opportunity to
    substitute a database nothing scanned.

    The three grants match what CPython's own descriptor grants, less the
    substitution of this account's SID for OWNER RIGHTS, so a directory that
    took either path ends up with the same access. Dropping the administrators
    group would buy nothing, since an administrator can take ownership and
    rewrite the ACL regardless, and it would cost an operator the ability to
    clear a leaked scratch left by a scheduled task running as another account.

    A failure warns rather than raises. The exposure this closes needs a second
    local account to exploit, while raising would stop the databases updating at
    all on any host where `icacls` is unavailable or the account cannot rewrite
    the ACL, and a stale vulnerability database is the larger everyday risk. The
    warning names what did not happen so the log says so plainly instead of the
    docstring quietly promising a privacy the run did not obtain.

    What this does not do is close the race, and an earlier version of this
    docstring said otherwise. It claimed the gap between `mkdir` and the rewrite
    was microseconds and that the random name left nobody able to wait for it.
    Both halves were wrong. The gap included a `whoami` process spawn, which is
    milliseconds rather than microseconds, and the name defeats predicting the
    path rather than learning it: an account watching the base is handed the name
    by ReadDirectoryChangesW the moment the directory appears. Worse, Windows
    checks access when a handle is opened, so tightening the DACL afterwards does
    not revoke a handle already opened against the permissive one.

    So the ordering is now the caller's job and the window is one `icacls` call
    rather than two spawns, because the SID is resolved before the directory
    exists and passed in. That narrows the race; it does not end it. What ends it
    is the interpreter creating the directory protected in the first place, which
    needs 3.12.4 or newer, a build carrying the guarded API set, and a filesystem
    that holds ACLs. That is why the caller refuses a scratch that is not empty
    once this returns, and why it reads the resulting ACL back rather than
    inferring it: a fresh directory with something already in it is one somebody
    else reached first, and a version number cannot tell you about the build or
    the volume."""
    if not IS_WINDOWS:
        return
    if sid is None:
        # Says what did not happen and stops there. Whether the directory is
        # actually exposed is a separate question with a separate answer, and
        # report_scratch_privacy reads the DACL to give it. Asserting the
        # exposure here would be a false alarm on every current interpreter,
        # where mkdir already protected the directory before this ran.
        log(f"WARNING: could not read this account's SID, so the scratch directory {path} "
            "was not hardened by this step.")
        return
    # /inheritance:r drops the inherited entries; /grant:r replaces rather than
    # adds, so a rerun is idempotent. The leading * marks each principal as a SID
    # rather than a name. S-1-5-18 is SYSTEM and S-1-5-32-544 is the local
    # administrators group; both are the same on every install and in every
    # locale, which a name is not.
    #
    # /L operates on the name given rather than on what it points at, and it is
    # here so that this call cannot be aimed at somebody else's directory. In the
    # fallback cases this function exists for, the scratch is created with the
    # inherited ACL, so an account holding Modify on the base can delete the
    # empty directory and put a reparse point in its place during the window
    # before this runs. Without /L the command would then strip the inheritance
    # from the *target* and rewrite it with this process's privileges, which
    # turns an exposed scratch into damage to an arbitrary directory.
    #
    # Measured rather than assumed, because the two kinds of reparse point do not
    # behave alike: with a junction, icacls writes the junction's own ACL and the
    # target is untouched, so only a true symbolic link follows. That narrows the
    # case to an account holding SeCreateSymbolicLinkPrivilege or a machine with
    # Developer Mode on — which is a developer machine, and this is a developer's
    # tool. On an ordinary directory /L changes nothing.
    command = [resolve_system_tool("icacls.exe"), str(path), "/L", "/inheritance:r"]
    for grant in (f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"):
        command += ["/grant:r", grant]
    code, output = run(command, timeout=60)
    if code != 0:
        log(f"WARNING: could not restrict the permissions on the scratch directory {path}. "
            "Whether that leaves it exposed is reported separately, from the ACL itself.")
        echo(output, "icacls")


# SDDL abbreviates the well-known principals, and these are the ones a private
# scratch legitimately names. SY is SYSTEM and BA the administrators group, which
# both mechanisms grant. OW is OWNER RIGHTS, which is what CPython's own
# descriptor uses for the creating account, and LA the built-in administrator,
# which is how a RID-500 account is spelled. CO is CREATOR OWNER, which appears
# on some inherited layouts. Anything else holding an allow entry is somebody
# this directory was not meant to be readable by.
TRUSTED_SDDL_PRINCIPALS = frozenset({"SY", "BA", "OW", "LA", "CO"})

# What SDDL calls the accounts a scheduled task is likely to run as. `whoami`
# answers with the numeric SID and the descriptor abbreviates it, so a service
# account would otherwise be reported as an intruder in its own scratch
# directory: LocalService is S-1-5-19 and appears as LS. The alias is added only
# when it is this account's, rather than trusted outright, because LocalService
# being the process is a different fact from LocalService having been granted
# access to a directory belonging to somebody else.
SDDL_ALIAS_FOR_SID = {
    "S-1-5-18": "SY",
    "S-1-5-19": "LS",
    "S-1-5-20": "NS",
    "S-1-5-32-544": "BA",
}

# FILE_ATTRIBUTE_REPARSE_POINT. Named here rather than written as a bare 0x400 at
# the one place it is tested, because a bare constant in a security check is a
# claim nobody can audit without a search engine. stat carries no name for it.
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

# The bits in an access mask that let the holder change what is in a directory,
# rather than only look at it: write data, append, write extended attributes and
# attributes, delete a child, delete the object, and rewrite its owner or its
# ACL. Reading alone is a smaller finding and gets a smaller sentence.
#
# The last two are the generic bits, GENERIC_ALL and GENERIC_WRITE, and they are
# here because a mask is not always mapped by the time it is stored. The letter
# spellings GA and GW are translated to their file equivalents by the table
# below, so those meet this mask already; a mask written out in hexadecimal is
# taken as it stands, and an ACE can legitimately keep its generic bits — an
# inherit-only entry keeps them until it is inherited, and an entry set through
# the raw API keeps whatever was written. So (A;;0x40000000;;;AU) granted every
# authenticated user write access and was reported as read-only.
SDDL_WRITE_MASK = (0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000
                   | 0x10000000 | 0x40000000)

# What each two-letter right is worth as a mask, so that one definition decides
# both spellings. Keeping a separate set of "write" letters beside the mask above
# was the first attempt and it was wrong in both directions: the object-rights
# mnemonics describe a directory-service object, and on a filesystem directory
# the same bits mean something else. CC is 0x1, which lists the directory and
# grants nothing, while it reads as "create child"; LC is 0x4, which adds a
# subdirectory, while it reads as "list children". So the set called CC a write
# and LC a read, each the reverse of the truth.
#
# The generic four are given their file equivalents rather than their generic
# bits, because that is what they mean once the generic mapping is applied and it
# lets every spelling meet the same mask.
SDDL_RIGHT_BITS = {
    "CC": 0x1,        # list directory
    "DC": 0x2,        # add file
    "LC": 0x4,        # add subdirectory
    "SW": 0x8,        # read extended attributes
    "RP": 0x10,       # write extended attributes
    "WP": 0x20,       # traverse
    "DT": 0x40,       # delete child
    "LO": 0x80,       # read attributes
    "CR": 0x100,      # write attributes
    "SD": 0x10000,    # delete
    "RC": 0x20000,    # read the security descriptor
    "WD": 0x40000,    # rewrite the ACL
    "WO": 0x80000,    # take ownership
    "FA": 0x1F01FF,   # file all
    "FR": 0x120089,   # file generic read
    "FW": 0x120116,   # file generic write
    "FX": 0x1200A0,   # file generic execute
    "GA": 0x1F01FF,   # generic all, mapped
    "GR": 0x120089,   # generic read, mapped
    "GW": 0x120116,   # generic write, mapped
    "GX": 0x1200A0,   # generic execute, mapped
}


def sddl_grants_write(rights: str) -> bool:
    """Whether an SDDL rights field lets its holder change the directory.

    Rights arrive in two spellings and both are reduced to a mask so that one
    definition answers for both. A hexadecimal field is taken as it stands; a run
    of two-letter codes is split into pairs and each looked up.

    Anything that does not parse is reported as write. Guessing "read only"
    would turn an entry nobody could read into silence, and this function exists
    to stop the report claiming more than it established, not to start it
    claiming less."""
    text = rights.strip()
    if text.lower().startswith("0x"):
        try:
            return bool(int(text, 16) & SDDL_WRITE_MASK)
        except ValueError:
            return True
    # An odd length is malformed and is treated as such, rather than parsed as
    # far as it goes. Stopping one short of the end was how the pairs were cut,
    # so a trailing character was dropped in silence: "CCD" read as CC alone and
    # was called read-only, which is the one direction this function must never
    # fail in.
    if len(text) % 2:
        return True
    codes = [text[index:index + 2].upper() for index in range(0, len(text), 2)]
    if not codes or any(code not in SDDL_RIGHT_BITS for code in codes):
        return True
    mask = 0
    for code in codes:
        mask |= SDDL_RIGHT_BITS[code]
    return bool(mask & SDDL_WRITE_MASK)


def scratch_dacl(path: Path) -> str | None:
    """The directory's DACL as SDDL, or None when it cannot be read.

    Read rather than assumed, because the two mechanisms that can protect this
    directory fail in different ways and neither reports it. Asking the
    filesystem what the ACL actually says is the only answer that covers both,
    and it is the difference between warning about an exposure and warning about
    a step that did not run."""
    # Asked of the kernel directly, which took three attempts to arrive at and is
    # worth recording, because each rejected route failed for a different reason
    # and all three reasons are the sort a security check must not carry.
    #
    # `icacls /save` needs an interchange file and every location is wrong. The
    # system temporary directory is the small volume this whole mechanism exists
    # to keep writes off. The scratch's base is the directory whose permissions
    # are under suspicion, so on the very base this was written for the file
    # inherits Authenticated Users and another account can replace it between the
    # write and the read, forging a descriptor that says the directory is
    # private. The scratch itself is circular: an account that can write there
    # can forge the answer saying it cannot.
    #
    # PowerShell's Get-Acl returns the descriptor on stdout and needs no file,
    # but it failed outright here: Windows PowerShell could not autoload its own
    # Security module under a PSModulePath inherited from PowerShell 7, and
    # dropping that variable did not fix it. A check that depends on which shell
    # launched the updater is a check that reports "unknown" for reasons having
    # nothing to do with the directory.
    #
    # GetNamedSecurityInfoW has none of those failure modes: no file to forge, no
    # process to spawn, no environment to inherit, no PATH entry to hijack and no
    # locale to translate the answer.
    import ctypes  # pylint: disable=import-outside-toplevel

    # sys.platform rather than the IS_WINDOWS constant used everywhere else, and
    # not interchangeable with it here. ctypes.WinDLL does not exist off Windows,
    # so a type checker running for Linux reports the attribute as missing; it
    # narrows on sys.platform and treats what follows as unreachable, where
    # os.name tells it nothing. The caller already returns early off Windows, so
    # this guard is for the checker rather than for the run — which is exactly
    # how it was found, by CI failing on Linux and macOS while the same command
    # passed here.
    if sys.platform != "win32":
        return None
    try:
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except OSError:
        return None

    # Declared rather than left to ctypes' defaults, because a pointer returned
    # into an undeclared restype is truncated to 32 bits on a 64-bit build, and
    # the failure is a wild free rather than an error.
    advapi32.GetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_int, ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = ctypes.c_ulong
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_wchar_p), ctypes.POINTER(ctypes.c_ulong),
    ]
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = ctypes.c_int
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    se_file_object = 1
    dacl_security_information = 0x00000004
    sddl_revision_1 = 1

    descriptor = ctypes.c_void_p()
    if advapi32.GetNamedSecurityInfoW(
            str(path), se_file_object, dacl_security_information,
            None, None, None, None, ctypes.byref(descriptor)) != 0:
        return None
    try:
        text = ctypes.c_wchar_p()
        if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor, sddl_revision_1, dacl_security_information,
                ctypes.byref(text), None):
            return None
        try:
            # Copied out of the ctypes buffer before it is freed, and as a plain
            # str: c_wchar_p.value carries the ctypes type through to every
            # caller, so the annotation said str while the object did not.
            sddl = text.value
            return str(sddl) if sddl is not None else None
        finally:
            kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
    finally:
        kernel32.LocalFree(descriptor)


def report_scratch_privacy(path: Path, sid: str | None) -> None:
    """Say whether the scratch directory is actually private, from its own ACL.

    This exists because the two earlier warnings could not tell the difference
    between a hardening step that did not run and a directory that is exposed.
    On any interpreter from 3.12.4 the directory was already protected by
    `mkdir`, so a failure in the icacls step usually leaves nothing wrong, and
    saying otherwise raised a security alarm that was false on the common path.
    A scanner that cries wolf about its own staging is a scanner whose warnings
    stop being read.

    `sid` is this account, and only this account is exempt. The first version
    exempted every principal whose SID began S-1-5-21, on the reasoning that a
    raw SID in the output was this account's. That prefix belongs to every local
    and domain account, so a DACL granting a different user full control passed
    without a word: the false alarm had been traded for a false silence, in the
    one case the whole change exists to catch. Where the SID could not be read
    there is nothing to exempt and nothing lost, because that is also the case
    where the icacls step did not run, leaving CPython's own descriptor, which
    names the creating account as OWNER RIGHTS rather than by SID.

    So nothing is said when the ACL is what it should be. What is said otherwise
    names the principals actually found, because "somebody else can write here"
    is only actionable if the operator can see who."""
    if not IS_WINDOWS:
        return
    sddl = scratch_dacl(path)
    if sddl is None:
        log(f"WARNING: could not read the permissions on the scratch directory {path}, so "
            "whether the staged database is private here is unknown rather than confirmed.")
        return
    # A NULL DACL is not an empty one. It grants every account full access, and
    # Windows writes it as this token instead of as entries, so there is nothing
    # for the parser below to find: `writers` and `readers` both come back empty
    # and the protected-flag branch is skipped whenever the descriptor also
    # carries P. The most exposed directory a filesystem can hold would have
    # produced silence, which is the failure this whole report exists to avoid,
    # so it is tested for before anything is parsed.
    if "NO_ACCESS_CONTROL" in sddl:
        log(f"WARNING: the scratch directory {path} has no access control list at all, which "
            "grants every account full access rather than none. A local user can substitute a "
            "database between the ClamAV gate and promotion.")
        return
    trusted = set(TRUSTED_SDDL_PRINCIPALS)
    if sid is not None:
        trusted.add(sid)
        alias = SDDL_ALIAS_FOR_SID.get(sid)
        if alias is not None:
            trusted.add(alias)
    # An allow entry is <type>;<flags>;<rights>;<object>;<inherit>;<principal>,
    # and the type is not only A: SDDL spells an access-allowed entry as OA when
    # it carries object GUIDs and as XA or ZA when it carries a condition. All
    # four grant access, so matching only A left a DACL that hands another
    # account full control through a conditional entry looking empty, which is
    # the same false silence the S-1-5-21 exemption produced.
    #
    # The principal stops at the next separator rather than at the closing
    # bracket, because a conditional entry continues past it with the condition
    # itself: (XA;;FA;;;WD;(Title=="PM")).
    #
    # A protected DACL is the other half: without the P flag the directory still
    # inherits, so an entry can arrive after this check.
    #
    # The rights are read as well as the principal, because the two lead to
    # different sentences. Every allow entry used to produce the substitution
    # warning, so a read-only grant such as (A;OICI;GR;;;BU) was reported as an
    # account that can replace the database, which it cannot. Overstating what
    # was established is the same defect as understating it, and this warning
    # exists precisely because the previous one overstated.
    entries = [
        (match.group(2), match.group(1))
        for match in re.finditer(
            r"\((?:A|OA|XA|ZA);[^;]*;([^;]*);[^;]*;[^;]*;([^);]+)", sddl)
        if match.group(2) not in trusted
    ]
    writers = sorted({principal for principal, rights in entries if sddl_grants_write(rights)})
    readers = sorted({principal for principal, rights in entries
                      if not sddl_grants_write(rights)})
    if writers:
        log(f"WARNING: the scratch directory {path} grants write access to {', '.join(writers)} "
            "as well as this account, SYSTEM and the administrators. A local user with write "
            "access there can substitute a database between the ClamAV gate and promotion.")
    if readers:
        log(f"WARNING: the scratch directory {path} is readable by {', '.join(readers)} as well "
            "as this account, SYSTEM and the administrators. That does not let them replace the "
            "staged database, so it is a smaller finding than a write grant, and it is still "
            "not the private directory this step is meant to produce.")
    if writers or readers:
        return
    if "D:P" not in sddl:
        log(f"WARNING: the scratch directory {path} still inherits permissions from its base, "
            "so an entry granted there later reaches the staged database.")


def _ensure_cache_parent(real_near: Path | None) -> None:
    """Create the cache parent so it can serve as a scratch base.

    It is a candidate below and promotion creates it without hesitating a few
    dozen lines later, so refusing to stage in a directory the run is about to
    create anyway was an inconsistency: on a first run against a host with no
    cache yet, it sent the download to the small system temporary volume, the
    one case the whole mechanism exists for. A configured
    LOCKFILE_SENTINEL_SCRATCH that does not exist is still passed over rather
    than created, since a path someone typed wrong is a mistake worth
    reporting."""
    if real_near is None:
        return
    try:
        real_near.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        log(f"could not create the cache parent {real_near.parent} ({exc}); "
            "it stays out of the running as a scratch base")


class ScratchUnavailableError(RuntimeError):
    """No scratch base can hold the download, stated before a byte is spent.

    A distinct type rather than a bare RuntimeError so the caller can tell a
    missing prerequisite, which is worth its own exit code, from a genuine
    malfunction, which deserves a traceback."""


def _pick_scratch_base(real_near: Path | None, near: Path | None,
                       need: int, passed_over: list[str]) -> Path | None:
    """The first configured base that is present, outside the cache, and roomy.

    `need` is what this refresh will actually stage, stated by the caller, so
    a run that downloads less is not rejected for room it does not need.
    Every rejection is logged where it happens and summarised into
    `passed_over`, so a later refusal can name each base and why it lost
    without re-measuring anything."""
    candidates = [
        (SCRATCH_BASE, "LOCKFILE_SENTINEL_SCRATCH"),
        (str(real_near.parent) if real_near else "", "the cache volume"),
    ]
    for value, origin in candidates:
        if not value:
            continue
        path = Path(value)
        if not path.is_dir():
            log(f"scratch base {value} from {origin} is not available")
            passed_over.append(f"{value} from {origin} (not a directory)")
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
            passed_over.append(f"{value} from {origin} (inside the cache)")
            continue
        free = free_bytes(path)
        if free is not None and free < need:
            log(f"scratch base {value} from {origin} has {describe_free(free)}, under the "
                f"{need / 1024 ** 3:.1f} GB this refresh needs; "
                "passing over it")
            passed_over.append(f"{value} from {origin} ({describe_free(free)})")
            continue
        return path
    return None


def _fallback_scratch_base(real_near: Path | None, near: Path | None,
                           need: int, passed_over: list[str]) -> Path:
    """The last resort when every candidate lost, or the refusal to have one.

    Raises ScratchUnavailableError rather than returning a base that is
    measurably short or certainly fatal, since deciding here is what spares
    the run from finding out a gigabyte later."""
    system = Path(tempfile.gettempdir())
    if near is not None and is_inside(system, near):
        # The containment rule has to hold on the last resort too, or the
        # failure it exists to prevent simply moves here: a scratch under the
        # cache is carried off by the promotion rename, and the run ends with
        # no live cache at all. Low free space only makes the download likely
        # to fail, which is why this branch tolerates it; containment makes
        # the promotion certain to destroy the cache, and the two are not
        # comparable.
        #
        # The parent of the cache is an ancestor rather than a descendant, so
        # it satisfies the rule by construction. It was passed over above, but
        # only for room, and a volume that is probably too small is a better
        # answer than one that is certainly fatal.
        base = real_near.parent if real_near else system
        if not base.is_dir():
            raise ScratchUnavailableError(
                f"no scratch base is usable: the system temporary directory {system} sits "
                f"inside the cache {near}, where a scratch would be carried away by the "
                f"promotion, and the cache parent {base} is not a directory. Set "
                "LOCKFILE_SENTINEL_SCRATCH to a directory outside the cache."
            )
        log(f"the system temporary directory {system} is inside the cache {near}, where a "
            f"scratch would be carried away by the promotion; using {base} instead "
            f"({describe_free(free_bytes(base))}), short of room though it may be")
        return base
    # The last resort is size-checked like any other base, because it is the
    # volume the Java index download actually ran out of room on. Proceeding
    # anyway spent the transfer to reach the original failure and reported it
    # as an obscure write error from inside a child process; refusing here
    # states the cause before a byte is spent, naming every base that was
    # considered and why it lost. An unmeasurable figure still proceeds,
    # since unknown is not known-short and every alternative was already
    # passed over.
    system_free = free_bytes(system)
    if system_free is not None and system_free < need:
        considered = "; ".join(passed_over) if passed_over else "none was configured"
        raise ScratchUnavailableError(
            f"no volume has the {need / 1024 ** 3:.1f} GB this refresh needs: "
            f"candidates passed over: {considered}; the system temporary "
            f"directory {system} has {describe_free(system_free)}. Free some "
            "space, or set LOCKFILE_SENTINEL_SCRATCH to a volume with room."
        )
    log(f"falling back to the system temporary directory {system} "
        f"({describe_free(system_free)}), which is the volume the Java index "
        "download ran out of room on")
    return system


@contextlib.contextmanager
def scratch_dir(label: str, near: Path | None = None,
                need: int = SCRATCH_MIN_FREE_BYTES,
                leaks: list[Path] | None = None):
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

    A base is passed over unless it has `need` bytes to spare, because "a
    volume with room" is the whole point and is-it-a-directory does not
    establish it. The caller states `need` from what it will actually stage,
    since a run that downloads less needs less; the default is the full-refresh
    figure. A base whose free space cannot be read is still used, since the
    alternative is falling back to the volume already known to be too small.
    When every base including the last-resort system temporary directory is
    measurably short, ScratchUnavailableError is raised before a byte is
    downloaded, naming each candidate and its figure: proceeding anyway spent
    the transfer to reach the original disk-full failure and reported it as an
    obscure write error from inside a child process. The cache parent is
    created first when it does not exist, since promotion creates it moments
    later anyway and refusing to stage in it sent a first run on a fresh host
    to the small system volume, the one case this mechanism exists for.

    `leaks` is how a cleanup failure reaches the caller's exit code: the
    finally that removes the scratch cannot raise without masking whatever
    exception is already propagating, so a directory it could not remove is
    appended to the caller's list instead, beside the WARNING in the log.

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
    collision or a pre-existing directory raises rather than being adopted.

    The mode is load-bearing on both platforms, for different reasons. Unix
    applies it directly. Windows applies it too, since the fix for
    CVE-2024-4030, but only for exactly 0o700, only from 3.12.4, only on a build
    carrying the API set the special case sits behind, and only on a filesystem
    that holds ACLs; outside those the directory is created with the base's
    inherited permissions and nothing says so.

    That distinction is the whole security story, and it is sharper than a
    fallback. Where the interpreter applies the mode, the directory is created
    protected by one call and there is no interval in which it is not. Where it
    does not, restrict_to_owner narrows the interval to a single icacls but
    cannot remove it, because Windows grants access when a handle is opened and
    a later DACL does not revoke one already held.

    Which of those happened is not knowable from the version alone, since the
    build and the filesystem are conditions the interpreter does not report. So
    the answer is read rather than inferred: report_scratch_privacy asks the
    filesystem what the ACL says once both mechanisms have had their turn, and
    the emptiness check above catches the cheap half of the remaining race."""
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
    _ensure_cache_parent(real_near)
    passed_over: list[str] = []
    base = _pick_scratch_base(real_near, near, need, passed_over)
    if base is None:
        base = _fallback_scratch_base(real_near, near, need, passed_over)
    # Before the directory exists, so that the interval between creating it and
    # restricting it holds one icacls call and not a whoami spawn as well. On a
    # 3.12.4 or newer interpreter with ACL support this interval does not matter,
    # because mkdir below creates the directory already protected; it matters on
    # exactly the builds and filesystems where that does not happen, which are
    # the ones restrict_to_owner exists for.
    # A temp-* sibling already in the base is evidence of a cleanup that
    # failed on an earlier run, which is exactly the leak the finally below
    # reports: the names are random by design, so nothing else ever
    # recognises one as garbage. Reported rather than deleted, because a
    # directory that could not be removed may be one something still holds
    # open, and one of these may belong to a run happening right now.
    leftovers = sorted(entry.name for entry in base.glob("temp-*") if entry.is_dir())
    if leftovers:
        # A handful of names identifies the leak; hundreds of them, the very
        # accumulation this NOTE exists to surface, would bloat the log line.
        shown = ", ".join(leftovers[:5])
        more = f" and {len(leftovers) - 5} more" if len(leftovers) > 5 else ""
        log(f"NOTE: {base} already holds {len(leftovers)} temp-* "
            f"director{'y' if len(leftovers) == 1 else 'ies'} "
            f"({shown}{more}); each is either a concurrent run's scratch "
            "or a leak from a cleanup that failed, and nothing removes the latter")
    sid = current_user_sid() if IS_WINDOWS else None
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
        restrict_to_owner(path, sid)
        # And it is still the directory mkdir made, rather than a reparse point
        # standing where that directory was. An account that can delete the
        # scratch during the window before the step above can leave a junction or
        # a symbolic link at the same name, and every check after this one would
        # then describe, and every download would then fill, a directory
        # somewhere else entirely. mkdir refused to follow one, so anything
        # bearing the attribute here appeared after it and is not ours.
        if is_reparse_point(path):
            raise RuntimeError(
                f"the scratch directory {path} is a link rather than the directory that was "
                "just created there, so another account replaced it. Nothing staged through "
                "it would be under this program's control."
            )
        # A directory created exclusively a moment ago has nothing in it. If it
        # does, another account wrote there while the ACL was still the base's,
        # and the rewrite did not touch that child because icacls without /T
        # does not recurse. Refusing is the only safe answer: the staged tree is
        # adopted with exist_ok=True further on, so a hostile child left here
        # would be adopted rather than noticed, and it would sit inside the very
        # window between the ClamAV gate and the promotion that this directory
        # exists to protect. The finally below removes it either way.
        intruders = sorted(entry.name for entry in path.iterdir())
        if intruders:
            raise RuntimeError(
                f"the scratch directory {path} was not empty immediately after being created, "
                f"holding {', '.join(intruders)}. Another account reached it before its "
                "permissions were restricted, so nothing staged there can be trusted."
            )
        # After both mechanisms have had their turn, and after the emptiness
        # check, so the answer describes the directory the download will use.
        report_scratch_privacy(path, sid)
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
            # The caller that passed a list gets the fact as well as the log
            # line, so the run's exit code can say a gigabyte leaked without
            # this finally raising over an exception already in flight.
            if leaks is not None:
                leaks.append(path)


def _download_into_staging(trivy: str, skip_java_db: bool,
                           child_env: dict[str, str]) -> int:
    """Fetch each required database into the staging cache, 0 on success.

    A non-zero download exit stops the run before the gate, with the live
    cache untouched, since a partial staging cache is exactly what the
    staging design exists to keep away from promotion."""
    for flag, label in (("--download-db-only", "vulnerability"),
                        ("--download-java-db-only", "Java index")):
        if flag == "--download-java-db-only" and skip_java_db:
            continue
        log(f"downloading the {label} database into the staging cache ...")
        code, out = run([trivy, "image", flag], env=child_env)
        echo(out, "trivy")
        if code != 0:
            log(f"FAIL: {label} database download exited {code}; "
                "the live cache is untouched")
            return 1
    return 0


def _trivy_refresh_due(force: bool, trivy: str, before: TrivyFreshness,
                       required: list[str]) -> bool:
    """Whether anything obliges a download, logging the reason either way.

    Four grounds, in order of certainty: the operator said so, a database
    cannot be dated, a database is past its stamp, or the binary that will
    read the cache is not the one that wrote it. Only when none holds is the
    skip earned, and the log then names when the next refresh falls due."""
    if force:
        log("--force given, so the databases are refreshed whether or not they are due")
        return True
    undated = [name for name in required
               if before.get(name, {}).get("next_update") is None]
    if undated:
        # A database Trivy cannot date is not evidence of a database that is current.
        log(f"no next-update time for: {', '.join(undated)}; treating that as due, "
            "since a database that cannot be dated is not a database known to be fresh")
        return True
    due = [name for name in overdue(before) if name in required]
    if due:
        log(f"due now: {', '.join(due)}")
        return True
    changed = _trivy_binary_changed(trivy)
    if changed:
        # A NextUpdate stamp knows nothing about binaries. Before the skip
        # existed the download always ran, and an incompatible cache was
        # replaced as a side effect of running at all; the skip is what makes
        # the binary worth checking, since an upgraded Trivy expecting a
        # schema the cache does not carry would otherwise read "nothing due"
        # over databases it cannot use, and the failure would surface later,
        # in a scan, as an obscure error. This forces exactly one refresh per
        # binary change and needs no table of which binary expects which
        # schema, which is the part that would age badly.
        log(changed)
        return True
    # `undated` is exactly the required databases whose next_update is None, and
    # it is empty here, so the filter drops nothing. Writing it as a filter rather
    # than a suppression keeps the type checker on this line, and the length check
    # turns a relaxed guard above into an error rather than the soonest of a
    # smaller set, which would be a wrong answer reported as a right one.
    stamps = [before[name]["next_update"] for name in required]
    dated = [stamp for stamp in stamps if isinstance(stamp, datetime)]
    if len(dated) != len(stamps):
        missing = [name for name in required if before[name]["next_update"] is None]
        raise RuntimeError(
            "no next-update time for: " + ", ".join(missing) + ", which the "
            "`undated` guard above should have excluded; taking the soonest of "
            "the rest would report a wrong answer as a right one")
    soonest = min(dated)
    log(f"nothing is due yet, next at {describe_age(soonest)}; skipping the download. "
        "Pass --force to refresh anyway")
    return False


def _trivy_binary_changed(trivy: str) -> str | None:
    """A message when the installed Trivy is not the one that wrote the cache.

    None means no refresh is owed on this ground: the versions match, or the
    binary will not say its version, in which case a mismatch cannot be
    claimed. A cache written before this record existed answers with the
    unrecorded wording; the record is written only by a full refresh, so a
    --skip-java-db run keeps answering that way until one runs."""
    installed = trivy_binary_version(trivy)
    if not installed:
        return None
    recorded = str(read_state(TRIVY_STATE).get("trivyVersion") or "")
    if installed == recorded:
        return None
    was = f"trivy {recorded}" if recorded else "a trivy version that was never recorded"
    return (f"the installed trivy is {installed} but the cached databases were "
            f"written under {was}; treating them as due, since a newer binary "
            "can expect a schema the cache does not carry")


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
    # to compare against and always concludes it needs to download: measured on a
    # nightly run, it fetched both databases 2.8 hours before either was due, then
    # threw the result away as identical. Roughly 1 GB a night, plus 90 s of ClamAV
    # over it.
    #
    # The decision is all-or-nothing rather than per database. The promotion
    # step replaces the whole cache directory, and while it can now carry a
    # database forward from the outgoing cache, that carry exists for the one
    # database the operator deliberately excluded with --skip-java-db, where
    # the alternative was deleting a copy the flag promised to leave alone.
    # Widening it into a general per-database refresh would put every promotion
    # in the business of deciding which halves of two caches to interleave; if
    # either required database is due, both are fetched.
    required = ["vulnerability"] if args.skip_java_db else ["vulnerability", "java"]
    if not _trivy_refresh_due(args.force, trivy, before, required):
        return 0

    # Download into a staging cache, gate it there, and only then put it where
    # Trivy reads from. Downloading straight into the live cache overwrote the
    # databases before anything scanned them, so a rejected download was already
    # the copy every later Trivy run consumed, including this scanner's own
    # corroboration pass. Refusing to trust it after the fact changed nothing.
    # The space requirement follows what staging will hold, not which flags
    # were passed: --skip-java-db stages a tenth the bytes, and the carried-
    # forward Java index is a rename that stages nothing. Deriving the figure
    # from `required` keeps it correct if that set ever changes for another
    # reason.
    need = sum(SCRATCH_NEED_BYTES[name] for name in required)
    # The list outlives the scratch on purpose: the finally that removes the
    # directory runs as the block exits, so a cleanup failure lands here in
    # time for the exit code below to say the work succeeded but a scratch
    # was left behind.
    leaked: list[Path] = []
    with scratch_dir("trivy databases", near=live, need=need, leaks=leaked) as staging:
        staged = staging / "cache"
        staged.mkdir(parents=True, exist_ok=True)
        # Recorded here, checked again by promote_into just before the tree
        # leaves the scratch, so a directory substituted for this one after the
        # ClamAV gate is refused rather than promoted.
        staged_identity = dir_identity(staged)
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
        if _download_into_staging(trivy, args.skip_java_db, child_env) != 0:
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
            # A run that skipped the Java index still owes the cache the copy
            # it already had: promotion replaces the whole directory, so the
            # skipped database is named here to be carried forward rather than
            # silently dropped, which is what --skip-java-db used to do.
            promote_into(staged, live,
                         keep=("java-db",) if args.skip_java_db else (),
                         staged_identity=staged_identity)
        except ScratchSwappedError as exc:
            log(f"FAIL: {exc}; the live cache is untouched")
            return 1
        except OSError as exc:
            log(f"FAIL: could not promote the gated databases into {live} ({exc})")
            return 1

        # Recorded only on a full refresh: a --skip-java-db run promotes a
        # carried-forward Java index the installed binary never validated, so
        # the record keeps naming the binary that wrote it and the next full
        # run still sees the mismatch. The cost is a re-download of the small
        # database on each skip run after an upgrade, which is the safe side.
        if not args.skip_java_db:
            write_state(TRIVY_STATE, {"trivyVersion": trivy_binary_version(trivy) or ""})

    log(f"Trivy databases current, promoted into {live}")
    if leaked:
        # The two outcomes are genuinely different and the exit code says
        # which happened: the databases are correctly promoted, and a scratch
        # directory that can hold a gigabyte could not be removed. A scheduled
        # run turns amber rather than green, instead of a leak per night
        # accumulating behind an exit 0 that looked identical to a clean one.
        log(f"WARNING: the refresh succeeded but {len(leaked)} scratch "
            f"director{'y' if len(leaked) == 1 else 'ies'} could not be removed; "
            "exiting 3 so the leak is visible to whatever scheduled this run")
        return 3
    return 0


# --------------------------------------------------------------------------
# Target: status.
# --------------------------------------------------------------------------

def _status_osv() -> tuple[bool, bool]:
    """The osv-scanner build's freshness, as (stale, unknown)."""
    go = resolve_go()
    exe = go_bin(go) if go else None
    installed = osv_version(exe)
    state = read_state(OSV_STATE)
    log(f"osv-scanner: {installed or 'not installed'} at {exe or 'unknown'}")
    if state.get("lastCommit"):
        log(f"  built from commit {str(state['lastCommit'])[:12]}")
    last_check = state.get("lastCheckUnix")
    if not isinstance(last_check, (int, float)):
        log("  version last checked: unknown")
        return False, True
    age = (time.time() - last_check) / 3600.0
    log(f"  version last checked {age:.1f} h ago")
    return age > 24, False


def _status_overlay() -> tuple[bool, bool]:
    """The campaign overlay's freshness, as (stale, unknown)."""
    overlay = overlay_path()
    data = read_state(overlay)
    if not data:
        log(f"overlay: absent or unreadable at {overlay}")
        return False, True
    log(f"overlay: {data.get('package_count', '?')} packages, "
        f"{data.get('version_count', '?')} versions at {overlay}")
    generated = parse_stamp(str(data.get("generated_utc") or "").replace("Z", "+00:00"))
    log(f"  generated {describe_age(generated)}")
    if generated is None:
        return False, True
    return (datetime.now(timezone.utc) - generated).total_seconds() > 24 * 3600, False


def _status_offline_db() -> None:
    """Report the offline database; informational, never stale or unknown."""
    offline = offline_db_dir()
    if offline.is_dir():
        newest = max((p.stat().st_mtime for p in offline.rglob("*") if p.is_file()), default=0)
        log(f"offline database: present at {offline}, newest file "
            f"{(time.time() - newest) / 3600.0:.1f} h old")
    else:
        log(f"offline database: not present ({offline}), online mode is always current")


def target_status(_args) -> int:
    """Report the freshness of everything this program maintains.

    Exit 0 when all fresh, 1 when something is stale, 2 when something could not
    be determined, following the house rule that a check which could not run
    must not report health."""
    checks = [_status_osv(), _status_overlay()]
    _status_offline_db()
    checks.append(_status_trivy())

    if any(unknown for _, unknown in checks):
        return 2
    return 1 if any(stale for stale, _ in checks) else 0


def _status_trivy() -> tuple[bool, bool]:
    """The Trivy half of status: (stale, unknown).

    No metadata means the state could not be determined, which is exit 2
    rather than a pass: reading it as "nothing overdue" let a status run
    report health for a check that never produced an answer. The binary
    version is checked beside the stamps because a schema mismatch is the one
    staleness the stamps cannot express, and status is where the air-gapped
    host, the one case an ordinary scan will not quietly repair, gets to find
    out."""
    trivy = resolve_trivy()
    if not trivy:
        log("trivy: not found")
        return False, True
    freshness = trivy_freshness(trivy)
    report_trivy(freshness, "trivy")
    stale = bool(overdue(freshness))
    mismatch = _trivy_binary_changed(trivy)
    if mismatch:
        log(f"  {mismatch}")
        stale = True
    return stale, not freshness


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
                        help="trivy-db: refresh only the vulnerability database; "
                             "a cached Java index is left in place.")
    args = parser.parse_args()

    if not args.source_dir:
        # A working tree for --from-source, under the cache root rather than
        # anywhere near this file, so a source build never writes into a
        # checkout of this repository.
        args.source_dir = str(cache_dir() / "osv-scanner-src")

    rotate_log()
    log(f"run start: {args.target}")

    def dispatch(name: str) -> int:
        # A refusal to stage is a prerequisite that is missing, not work that
        # failed: the run decided before downloading rather than during, so
        # it exits 2 with the refusal's own accounting of every base and its
        # free space, instead of an obscure write error from inside a child
        # process after the transfer was already spent.
        try:
            return TARGETS[name](args)
        except ScratchUnavailableError as exc:
            log(f"FAIL: {exc}")
            return 2

    if args.target == "all":
        worst = 0
        for name in ("osv-scanner", "malicious-packages", "offline-db", "trivy-db"):
            log(f"--- {name} ---")
            worst = max(worst, dispatch(name))
        log(f"run end: all targets, worst exit {worst}")
        return worst

    code = dispatch(args.target)
    log(f"run end: {args.target}, exit {code}")
    return code


if __name__ == "__main__":
    sys.exit(main())
