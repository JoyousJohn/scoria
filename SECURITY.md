# Security policy

Scoria reads directory metadata from whole disks. Treat reports, example paths, and
JSON digests as sensitive.

## Reporting a vulnerability

Do not open a public issue for a security problem. Use GitHub Security Advisories for
this repository so the report stays private until a fix is ready.

Include:

- Scoria version or commit SHA
- Windows version and filesystem
- the command line used
- a minimal reproduction
- impact, especially if it involves a write, move, delete, exclusion bypass, unintended
  content read, or path leakage

Never attach a full scan report, a real user profile tree, or credentials. Sanitize
paths first.

## Scope

In scope:

- any path that causes Scoria to delete, move, rename, or write to a scanned file
- bypass of the exclusion or protected-path policy
- unintended file-content reads outside `-dupes`
- report or digest content that leaks files the user excluded
- network access, telemetry, or crash uploads
- low-integrity mode failing open

Out of scope:

- recommendations the user disagrees with, unless they touch a protected or excluded path
- Windows permission denials that the scanner reports as skipped
- antivirus false positives without a concrete indicator

The product has no delete, move, or rename path by design. If you find one, it is a
critical bug.
