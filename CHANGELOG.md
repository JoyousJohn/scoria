# Changelog

## 0.2.0 - 2026-11-02

### Added

- Offline analyzer interface, redacted payload builder, and `-ai-preview`.
- Optional OpenRouter cloud analysis with `-ai` and `-model`; sends only the redacted
  path-free payload.
- `-base-url` and `SCORIA_BASE_URL` select any OpenAI-compatible endpoint instead of
  OpenRouter; non-loopback endpoints must use HTTPS and a key, while loopback endpoints
  may use plain HTTP without one.
- `-provider` selects a known OpenAI-compatible endpoint (`openrouter`, `openai`,
  `gemini`, `deepseek`, `together`, `fireworks`, `deepinfra`, `groq`), and the guided
  setup offers the same list with a custom URL option. Presets are conveniences;
  `-base-url` still overrides.
- Custom exclusions via `-exclude`, `-exclude-glob`, `-exclude-ext`,
  `-exclude-name`, and `-exclude-file`.
- Default exclusion config lookup at `%APPDATA%\Scoria\exclusions.txt`, disabled with
  `-no-config`.
- Optional directory-pattern discovery with `-ai-discover`; sends aggregate basenames
  only, and suggestions are never applied automatically.
- Guided setup now covers output format (HTML report, console, or JSON), duplicate
  verification, AI review, exclusions, and advanced tuning, with a confirmation
  summary before scanning.

### Changed

- Console colors now use semantic roles: green for clean outcomes, dim zero-skip
  counts and confidence labels, and yellow only for nonzero skips and real caveats.
  Recommendations never use success green.

## 0.1.2 - 2026-11-01

### Fixed

- Interactive prompts are separated by blank lines.
- Top-N and worker explanations are inline with their prompts instead of appearing
  above the next question.

## 0.1.1 - 2026-11-01

### Added

- `-pause` waits for Enter before exiting.
- Double-clicking the exe, or running it with no arguments in a console, starts
  interactive setup and pauses before exit.

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
