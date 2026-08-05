# Security Policy

## Reporting a Vulnerability

Report privately through GitHub's security advisory form for this repository, under the Security tab, rather than by opening an issue. That keeps the report out of public view until there is something to say about it.

Please include what you ran, what happened, and what you expected. A lockfile or a directory layout that reproduces the problem is worth more than a description of it, and a sanitized reproduction is fine.

## What to Expect

This project has a single maintainer, so the commitments below are the ones that can actually be kept.

| Stage | Commitment |
| --- | --- |
| Acknowledgement | Within 72 hours |
| Triage and an assessment of severity | Within 14 days |
| Fix, or a published advisory explaining the risk and any workaround | No fixed date |

There is deliberately no promised fix deadline. A date that cannot be met becomes a broken public commitment during the week it matters most. What is promised instead is that a vulnerability which cannot be fixed quickly will be disclosed in an advisory with the risk and any mitigation described, rather than left silent.

## Scope

In scope: anything in `lockfile_sentinel.py` that causes it to miss a malicious package it should report, to report one that is not there, to execute code from a scanned repository, to read or write outside the paths it was given, or to leak the contents of a scanned tree.

The last two deserve emphasis, because the tool is pointed at untrusted source trees by design. It parses lockfiles as text and JSON and never executes anything from a scanned tree, and any path by which a scanned repository could influence execution is a vulnerability in this tool.

Out of scope: vulnerabilities in osv-scanner, Trivy, or the OSV.dev service, which should go to those projects; and the packages this tool reports, which are the malicious packages it exists to find.

## Supported Versions

The most recent release. This is a single file with no dependency chain, so upgrading means replacing one file.
