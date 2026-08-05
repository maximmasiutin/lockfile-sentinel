"""Schedule the scanner maintenance jobs, on Windows or on Linux, idempotently.

Every job is one target of update_scanners.py, so this schedules one program
four times rather than four programs once.

On Windows it writes a Task Scheduler definition and feeds it to
`schtasks /Create /XML`, which is the only way to set the logon type, the run
level and StartWhenAvailable together. A wrapper script named by --runner is
invoked in front of the updater when one is given, for a site that logs its own
scheduled runs; without it the updater is called directly.

On Linux it writes a file into /etc/cron.d when that directory is writable, and
otherwise manages a marked block in the user crontab. /etc/cron.daily is
deliberately not used: run-parts decides the hour there, so the staggered times
and the random spread would both be lost, and those exist to stop four jobs
waking one machine at the same second.

Idempotent on both. The intended content is rendered first and compared with
what is already installed, so an unchanged job is reported and skipped without a
write, and running this twice costs nothing.

Usage:
    python schedule_tasks.py --list
    python schedule_tasks.py --dry-run
    python schedule_tasks.py --only trivy-db --elevate
    python schedule_tasks.py --all --elevate
    python schedule_tasks.py --all --elevate --remove
    python schedule_tasks.py --all --elevate --prefix Acme- --runner run-task.ps1
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Maxim Masiutin
# https://github.com/maximmasiutin/lockfile-sentinel
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
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
import ctypes
import os
import subprocess  # nosec B404
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from xml.sax.saxutils import escape

SCRIPT_DIR = Path(__file__).resolve().parent
UPDATER = SCRIPT_DIR / "update_scanners.py"

IS_WINDOWS = os.name == "nt"

# Task names are built from this, so it decides what the four jobs are called in
# Task Scheduler. --prefix overrides it, which is how an existing installation
# keeps the names it already has instead of gaining four duplicates.
DEFAULT_PREFIX = "lockfile-sentinel-"

# One entry per scheduled job. The times are staggered rather than shared
# because the jobs compete for the same disk and the same network, and because
# a failure is easier to attribute when only one of them was running.
JOBS: dict[str, dict[str, object]] = {
    "osv-scanner": {
        "task": "Update-OSV-Scanner",
        "log": "osv-scanner-daily",
        "args": ["osv-scanner", "--from-source"],
        "time": "11:50",
    },
    "malicious-packages": {
        "task": "Update-Malicious-Packages",
        "log": "malicious-packages-daily",
        "args": ["malicious-packages"],
        "time": "12:00",
    },
    "offline-db": {
        "task": "Update-OSV-Offline-DB",
        "log": "osv-offline-db-daily",
        "args": ["offline-db"],
        "time": "00:20",
    },
    "trivy-db": {
        "task": "Update-Trivy-DB",
        "log": "trivy-db-daily",
        "args": ["trivy-db"],
        "time": "01:20",
    },
}


def task_name(job: dict[str, object], prefix: str) -> str:
    """The Task Scheduler name for a job, which is the prefix plus its suffix."""
    return f"{prefix}{job['task']}"


def is_admin() -> bool:
    """True when the current process can write a system-wide schedule."""
    if not IS_WINDOWS:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - any failure means "assume not"
        return False


def relaunch_elevated(argv: list[str]) -> int:
    """Re-run through the UAC prompt and wait, so a failure in the elevated
    child is visible rather than hidden behind a window that closes."""
    params = " ".join(f'"{a}"' for a in [str(Path(__file__).resolve())] + argv)
    see_mask_nocloseprocess = 0x00000040

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.c_ulong), ("fMask", ctypes.c_ulong),
            ("hwnd", ctypes.c_void_p), ("lpVerb", ctypes.c_wchar_p),
            ("lpFile", ctypes.c_wchar_p), ("lpParameters", ctypes.c_wchar_p),
            ("lpDirectory", ctypes.c_wchar_p), ("nShow", ctypes.c_int),
            ("hInstApp", ctypes.c_void_p), ("lpIDList", ctypes.c_void_p),
            ("lpClass", ctypes.c_wchar_p), ("hkeyClass", ctypes.c_void_p),
            ("dwHotKey", ctypes.c_ulong), ("hIcon", ctypes.c_void_p),
            ("hProcess", ctypes.c_void_p),
        ]

    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = see_mask_nocloseprocess
    info.lpVerb = "runas"
    info.lpFile = sys.executable
    info.lpParameters = params
    info.nShow = 1
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)):  # type: ignore[attr-defined]
        print("elevation was declined or failed")
        return 1
    ctypes.windll.kernel32.WaitForSingleObject(info.hProcess, 0xFFFFFFFF)  # type: ignore[attr-defined]
    code = ctypes.c_ulong()
    ctypes.windll.kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))  # type: ignore[attr-defined]
    ctypes.windll.kernel32.CloseHandle(info.hProcess)  # type: ignore[attr-defined]
    return int(code.value)


def resolve_pwsh() -> str | None:
    """PowerShell 7: the machine-wide MSI install first, then the WinGet Links
    shim, which is a stable symlink across upgrades where the versioned path is
    not. Never powershell.exe, which is 5.1."""
    for candidate in (
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "PowerShell" / "7" / "pwsh.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Links" / "pwsh.exe",
    ):
        if candidate.exists():
            return str(candidate)
    import shutil  # noqa: PLC0415 - only needed on the fallback path

    return shutil.which("pwsh")


def boundary(hour: int, minute: int) -> str:
    """Build a StartBoundary for the next occurrence of a local time.

    Two things about this were learned by watching the times move rather than
    from documentation. A naive 2020-01-01T11:50:00 is ambiguous and Windows
    rewrites it: a task registered that way came back moved by thirteen hours.
    Stamping the current offset onto that same 2020 date is not enough either,
    because a boundary years in the past is renormalized against a different
    offset than the one it was written with, and a January date carries the
    winter offset while the stamp carries today's. So the boundary is the next
    real occurrence, with that date's own offset, and nothing is in the past for
    Windows to normalize."""
    now = datetime.now().astimezone()
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return target.strftime("%Y-%m-%dT%H:%M:%S%z")[:-2] + ":" + target.strftime("%z")[-2:]


# --------------------------------------------------------------------------
# Windows.
# --------------------------------------------------------------------------

def windows_xml(job: dict, start: str, delay: int, user_id: str, runner: str = "") -> str:
    """Render the Task Scheduler definition for one job.

    RandomDelay is a child of CalendarTrigger and must precede the schedule
    element; placed wrongly it is dropped silently rather than rejected."""
    # Quote by hand rather than with repr: repr escapes a backslash, and a
    # PowerShell single-quoted string is literal, so a Windows path would arrive
    # with the doubled separators intact and resolve nowhere.
    argument_list = ",".join(f"'{a}'" for a in [str(UPDATER)] + [str(a) for a in job["args"]])
    if runner:
        inner = (f"& '{runner}' -Name '{job['log']}' -FilePath '{sys.executable}' "
                 f"-ArgumentList {argument_list} "
                 f"-WorkingDirectory '{SCRIPT_DIR}'; exit $LASTEXITCODE")
    else:
        inner = (f"& '{sys.executable}' {argument_list.replace(',', ' ')}; "
                 f"exit $LASTEXITCODE")
    arguments = f'-NoProfile -ExecutionPolicy Bypass -Command "{inner}"'
    random_delay = f"\n      <RandomDelay>PT{delay}M</RandomDelay>" if delay > 0 else ""
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Supply-chain scanning stack maintenance.</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>{start}</StartBoundary>
      <Enabled>true</Enabled>{random_delay}
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{escape(user_id)}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escape(resolve_pwsh() or 'pwsh.exe')}</Command>
      <Arguments>{escape(arguments)}</Arguments>
      <WorkingDirectory>{escape(str(SCRIPT_DIR))}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def windows_install(name: str, xml: str, dry_run: bool) -> int:
    """Create or replace one task. schtasks requires UTF-16 and rejects UTF-8."""
    if dry_run:
        print(f"would register {name}")
        return 0
    handle = tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, encoding="utf-16")
    try:
        handle.write(xml)
        handle.close()
        proc = subprocess.run(  # nosec B603
            ["schtasks.exe", "/Create", "/TN", name, "/XML", handle.name, "/F"],
            capture_output=True, text=True, check=False,
        )
    finally:
        Path(handle.name).unlink(missing_ok=True)
    if proc.returncode != 0:
        print(f"FAIL: could not register {name}: {(proc.stdout + proc.stderr).strip()}")
        return 1
    print(f"{name} registered.")
    return 0


def windows_remove(name: str, dry_run: bool) -> int:
    """Delete one task, treating "not there" as success."""
    if dry_run:
        print(f"would remove {name}")
        return 0
    proc = subprocess.run(  # nosec B603
        ["schtasks.exe", "/Delete", "/TN", name, "/F"],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        output = (proc.stdout + proc.stderr).strip().lower()
        if "cannot find" in output or "does not exist" in output:
            print(f"{name} is not registered, nothing to remove.")
            return 0
        print(f"FAIL: could not remove {name}: {output}")
        return 1
    print(f"{name} removed.")
    return 0


# --------------------------------------------------------------------------
# Linux.
# --------------------------------------------------------------------------

CRON_DIR = Path("/etc/cron.d")
MARK_BEGIN = "# BEGIN update_scanners (managed by schedule_tasks.py)"
MARK_END = "# END update_scanners (managed by schedule_tasks.py)"


def cache_dir() -> Path:
    """The cache root, resolved exactly as update_scanners.py resolves it.

    Duplicated rather than imported because each file has to stand alone when
    copied; change the two together. The cron lines log under this root, so a
    scheduled run writes nowhere near the checkout, which matters when
    /etc/cron.d runs the job as a user with no write access to it."""
    explicit = os.environ.get("LOCKFILE_SENTINEL_CACHE")
    if explicit:
        return Path(explicit)
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "lockfile-sentinel"


def cron_line(job: dict, delay: int, user: str) -> str:
    """One crontab line for a job, with the random spread reproduced by a sleep.

    $RANDOM is a bash builtin rather than POSIX, which is why the file sets
    SHELL. Without it cron runs /bin/sh and the spread silently becomes zero.

    The redirect target is created by the line itself. A redirect into a missing
    directory fails in the shell before the payload runs, which would leave the
    job doing nothing and writing no output to say why."""
    hour, minute = (int(part) for part in str(job["time"]).split(":"))
    payload = " ".join([sys.executable, str(UPDATER), *[str(a) for a in job["args"]]])
    spread = f"sleep $((RANDOM % {delay * 60})); " if delay > 0 else ""
    log_dir = cache_dir() / "logs"
    log_file = log_dir / f"{job['log']}.log"
    return (f"{minute} {hour} * * * {user} mkdir -p {log_dir} && {spread}"
            f"{payload} >> {log_file} 2>&1")


def cron_body(selected: list[str], delay: int, user: str) -> str:
    """The whole managed block, rendered so it can be compared byte for byte."""
    lines = [MARK_BEGIN, "SHELL=/bin/bash",
             f"PATH={os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}"]
    lines.extend(cron_line(JOBS[name], delay, user) for name in selected)
    lines.append(MARK_END)
    return "\n".join(lines) + "\n"


def linux_install(selected: list[str], delay: int, dry_run: bool, remove: bool) -> int:
    """Install or remove the managed block, writing only when it would change."""
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or "root"
    target = CRON_DIR / "update-scanners"

    if os.access(CRON_DIR, os.W_OK):
        desired = "" if remove else cron_body(selected, delay, user)
        current = target.read_text(encoding="utf-8") if target.exists() else ""
        if current == desired:
            print(f"{target} is already current, nothing written.")
            return 0
        if dry_run:
            print(f"would {'remove' if remove else 'write'} {target}")
            return 0
        try:
            if remove:
                target.unlink(missing_ok=True)
                print(f"{target} removed.")
            else:
                target.write_text(desired, encoding="utf-8")
                target.chmod(0o644)
                print(f"{target} written.")
        except OSError as exc:
            print(f"FAIL: {exc}")
            return 1
        return 0

    # No write access to /etc/cron.d, so manage a marked block in the user
    # crontab instead. Replacing the block as a unit is what keeps this
    # idempotent without disturbing anything else the user has scheduled.
    proc = subprocess.run(["crontab", "-l"], capture_output=True, text=True, check=False)  # nosec B603 B607
    existing = proc.stdout if proc.returncode == 0 else ""
    kept = []
    inside = False
    for line in existing.splitlines():
        if line.strip() == MARK_BEGIN:
            inside = True
            continue
        if line.strip() == MARK_END:
            inside = False
            continue
        if not inside:
            kept.append(line)
    block = "" if remove else cron_body(selected, delay, user)
    desired = ("\n".join(kept).rstrip() + "\n\n" + block).lstrip() if block else \
        "\n".join(kept).rstrip() + "\n"
    if desired == existing:
        print("the user crontab is already current, nothing written.")
        return 0
    if dry_run:
        print("would rewrite the managed block in the user crontab")
        return 0
    write = subprocess.run(["crontab", "-"], input=desired, text=True,  # nosec B603 B607
                           capture_output=True, check=False)
    if write.returncode != 0:
        print(f"FAIL: crontab rejected the block: {(write.stdout + write.stderr).strip()}")
        return 1
    print("the managed block in the user crontab was updated.")
    return 0


# --------------------------------------------------------------------------

def main() -> int:
    """Install, remove or list the scheduled jobs."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--only", action="append", dest="only", choices=tuple(JOBS),
                        help="Schedule this job. Repeatable. Default: all of them.")
    parser.add_argument("--all", action="store_true", help="Schedule every job.")
    parser.add_argument("--random-delay", type=int, default=5,
                        help="Minutes of spread after the start time (default: 5, 0 for none).")
    parser.add_argument("--remove", action="store_true", help="Remove instead of installing.")
    parser.add_argument("--elevate", action="store_true",
                        help="Windows: relaunch through the UAC prompt.")
    parser.add_argument("--dry-run", action="store_true", help="Report without changing anything.")
    parser.add_argument("--list", action="store_true", help="Print the job table and exit.")
    parser.add_argument("--show-cron", action="store_true",
                        help="Print the crontab block that would be installed and exit, on any "
                             "platform. The Linux install is easier to review before it is "
                             "written than after, and this renders exactly what gets written.")
    parser.add_argument("--prefix", default=DEFAULT_PREFIX,
                        help="Windows: prefix for the task names "
                             f"(default: {DEFAULT_PREFIX!r}). An existing installation must "
                             "pass the prefix it already uses, or it gains a second set.")
    parser.add_argument("--runner", default="",
                        help="Windows: a PowerShell wrapper to invoke in front of the updater, "
                             "for a site that logs its own scheduled runs. Default: none, so "
                             "the updater is called directly.")
    args = parser.parse_args()

    if args.runner and not Path(args.runner).exists():
        print(f"FAIL: --runner {args.runner} does not exist")
        return 2

    selected = args.only or list(JOBS)
    if args.all:
        selected = list(JOBS)

    if args.list:
        for name in selected:
            job = JOBS[name]
            print(f"{name:<20} {job['time']}  {task_name(job, args.prefix)}  "
                  f"update_scanners.py {' '.join(str(a) for a in job['args'])}")
        return 0

    if args.show_cron:
        user = os.environ.get("USER") or os.environ.get("LOGNAME") or "root"
        print(cron_body(selected, args.random_delay, user), end="")
        return 0

    if not UPDATER.exists():
        print(f"FAIL: missing {UPDATER}")
        return 2

    if not IS_WINDOWS:
        return linux_install(selected, args.random_delay, args.dry_run, args.remove)

    if args.elevate and not is_admin():
        return relaunch_elevated([a for a in sys.argv[1:] if a != "--elevate"])
    if not is_admin() and not args.dry_run:
        print("not elevated; schtasks will be denied for a root-folder task. Use --elevate.")
        return 2

    user_id = f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}".strip("\\")
    worst = 0
    for name in selected:
        job = JOBS[name]
        name_in_scheduler = task_name(job, args.prefix)
        if args.remove:
            worst = max(worst, windows_remove(name_in_scheduler, args.dry_run))
            continue
        hour, minute = (int(part) for part in str(job["time"]).split(":"))
        xml = windows_xml(job, boundary(hour, minute), args.random_delay, user_id, args.runner)
        worst = max(worst, windows_install(name_in_scheduler, xml, args.dry_run))
    return worst


if __name__ == "__main__":
    sys.exit(main())
