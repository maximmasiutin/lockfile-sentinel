# External Tools Scan Log

Every run of an external security scanner against this repository, with the date, the target, and what came back. A tool that can raise a security finding is recorded here; linters and formatters are not.

## 2026-08-12: bump_version.py

New file, scanned before it was proposed for merge. Target was the single file in each case, except pytest, which runs the whole suite.

| Tool | Version | Started (UTC) | Result |
| --- | --- | --- | --- |
| bandit | 1.9.4 | 04:48:51 | Completed. No issues identified across 298 lines. |
| semgrep | p/python and p/security-audit, 1115 rules | 04:48:55 | Completed. 0 findings, 0 blocking. |
| SonarQube Community Build | 25.11.0.114957, scanner CLI 8.1.0.6389 | 04:52:20 | Completed. 1 code smell, since fixed. |
| SonarQube Community Build | as above, rerun after the fix and with coverage | 05:05 | Completed. Quality gate OK: 0 bugs, 0 vulnerabilities, 0 code smells, 0 security hotspots, coverage 84.9 percent. |

The single Sonar finding was `python:S3776`, cognitive complexity 28 against a limit of 15 in `run()`. It was fixed by splitting the function into the changelog gate, the sweep and the two report paths, rather than by raising the threshold or marking the finding won't-fix. The rerun reports zero.

Non-security tools were run in the same pass and are noted here only for completeness, not as scans: mypy 2.3.0 in strict mode with no issues, pylint 4.0.7 at 10.00/10 against the committed `.pylintrc`, and the pytest suite at 52 passed.
