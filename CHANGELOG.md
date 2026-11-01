# Changelog

## Unreleased

### Added

- `-pause` waits for Enter before exiting, for double-clicked runs.

## 0.1.0 - 2026-11-01

### Added

- Windows-only `FindFirstFileExW` enumeration with a bounded directory worker pool.
- Reparse-point skipping, long-path support, permission-denied and placeholder reporting.
- Enumeration-time exclusion rules with the sensitive preset.
- Bounded aggregates: totals, extension rollups, top-N files and directories, size counts.
- Rules engine: generated directories, large/old files, temp extensions, duplicate leads.
- Protected-path filtering for recommendations.
- Opt-in duplicate verification with `-dupes` (reads candidate file contents).
- Versioned JSON digest with stable recommendation IDs, priority, and confidence.
- Self-contained HTML report with priority/size sorting.
- Interactive setup and post-scan sort toggle.
- Optional low-integrity scan mode with `-low-integrity`.
- Color, progress, and thousands-separated human sizes.
- CI write-API tripwire and PE import-table dumper.
