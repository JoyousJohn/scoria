# Scoria design

Scoria is a read-only Windows disk scanner. It walks a directory tree, collects
metadata, applies deterministic rules, and reports review candidates with reasons and
confidence.

The product premise is structural: **it cannot delete, move, or rename anything.**

## Guarantees

- No `DeleteFile`, `MoveFile`, `SHFileOperation`, `NtSetInformationFile`, `RegDeleteKey`,
  or `GENERIC_WRITE` in the scanner.
- No network access, telemetry, or crash reporting by default. `-ai` and
  `-ai-discover` are the only network paths, and they are explicit.
- Metadata-only by default. `-dupes` is the only content-reading path, and it is opt-in.
- Exclusions are filtered at enumeration time, before paths enter totals, logs, the
  digest, or the report.
- Protected paths are never recommendations, regardless of size or age.
- Memory stays bounded by aggregates, not by corpus size.
- The JSON digest is a versioned contract with stable per-scan recommendation IDs.

Recommendations are review candidates. Confidence describes the evidence, not
permission to remove anything.

## Non-goals for v1

- MFT or elevated indexer
- LLM analyzer
- treemap
- broad content inspection
- script export
- local model bundling
- Microsoft Store distribution

## Pipeline

```text
enumerate metadata
  -> bounded aggregates
  -> deterministic rules
  -> versioned digest
  -> console / JSON / HTML report
```

Duplicate content verification is a separate, opt-in pass.

## Scan design

- `FindFirstFileExW` with `FindExInfoBasic` and `FIND_FIRST_EX_LARGE_FETCH`.
- A bounded worker pool (default 2x logical CPUs) processes directories.
- All paths use `\\?\`; long paths are supported.
- Reparse points are skipped and counted.
- Cloud placeholders are counted and never opened for content.
- File opens use `FILE_READ_ATTRIBUTES` only.
- Hard links are deduplicated by file ID.
- `-dupes` hashes same-size candidates: first 8 KiB, then full content only on prefix
  match. It skips protected paths, reparse points, placeholders, exclusions, and
  hard-link duplicates.

## Counting semantics

Two distinct numbers:

- **entries** — one per directory entry; a file with three hard links counts three times
- **unique files** — deduplicated by file ID

Totals are logical sizes, matching `Get-ChildItem -File` and `robocopy /BYTES`.
Size-on-disk is not implemented.

## Aggregates

- totals and skipped buckets
- extension rollups
- top-N largest and oldest files
- top-N directories by direct contents
- `size -> count` map
- generated-directory rollups (`node_modules`, `__pycache__`, `.venv`, build outputs)
- per-rule exclusion aggregates

The corpus is never retained per file. Candidate-only work re-walks the tree.

## Recommendations

Rules produce:

| Rule | Signal |
|---|---|
| generated directory | known dependency, cache, or build output |
| large file | size threshold |
| old file | last write older than threshold |
| temporary extension | `.tmp`, `.part`, `.crdownload`, `.dmp` |
| duplicate candidate | same size only, not verified |
| verified duplicate | content hashes matched after `-dupes` |

Priority order: verified duplicates, generated directories, temp extensions, size-only
duplicates, old files, large files.

Every recommendation carries an opaque ID (`c1`, `c2`, ...), priority, confidence,
item and byte totals, and optional example paths.

## Duplicate verification

`-dupes` is the one content-reading phase:

- re-walks the tree with the same exclusions and protected-path checks
- considers only files >= 1 MiB whose size occurs more than once
- hashes an 8 KiB prefix, then the full file only for prefix collisions
- publishes `verified-duplicates` only after a full hash match
- replaces the size-only duplicate lead when it runs
- announces the content read before starting

## Outputs

- **Console** — totals, top-N lists, skipped buckets, recommendations, optional
  duplicate-check statistics. Interactive mode can re-sort recommendations by priority
  or size without rescanning.
- **JSON** — versioned digest (`version: 1`) with recommendations and duplicate stats.
- **HTML** — self-contained report written only when `-html` is given. It uses inline CSS
  and small vanilla JavaScript for priority/size sorting.

## Exclusions and protected paths

The sensitive preset is on by default and covers `.ssh`, common password-manager and
browser-profile directories, crypto wallets, and `.kdbx`, `.pem`, `.key`, and
`wallet.dat`.

Custom rules support directory subtrees, globs, extensions, and exact filenames through
repeatable flags or a readable config file. They are filtered at enumeration time,
reported per rule, and warned about when a custom rule matches nothing.

Protected paths include Windows, Program Files, System Volume Information,
`$Recycle.Bin`, root Recovery, Windows.old, pagefile, hiberfil, and swapfile. They are
filtered from recommendations; they are not silently removed from totals unless they
are also excluded.

## Low-integrity mode

`-low-integrity` opens the current process token and sets
`TokenIntegrityLevel` to `S-1-16-4096` before scanning. This is defense in depth, not a
sandbox: it blocks write-up to most of the user profile, but it is not AppContainer and
does not restrict reads or network. File report output is disabled in this mode because
a low-integrity process cannot create a report in a normal user directory. `-html -`
still works through the inherited stdout handle.

## Measurement

Any benchmark must state:

- warm or cold cache
- drive type
- Defender real-time status
- tree size
- Go version and build flags

Validate counts and byte totals with an independent tool on a real tree. Never benchmark
the repository itself. See [IMPLEMENTATION-NOTES.md](IMPLEMENTATION-NOTES.md).

## Known limits

- Old/large recommendations come from retained top-N lists, not a full per-file index.
- Duplicate leads are size-only unless `-dupes` runs.
- Size-on-disk is not implemented.
- The protected-path list is hardcoded in v1.
- Individual example paths appear in the report and digest; a path-redaction toggle is
  not implemented.
- `-low-integrity` is opt-in because report writing needs a higher-integrity parent.

## Trust evidence

CI rejects the forbidden write symbols in `cmd/` and `internal/`, and checks the static
PE import table. `tools/imports` prints that table. Release artifacts include the binary,
`SHA256SUMS`, and `IMPORTS.txt`.

## Future analysis

If an LLM analyzer is added, it only ranks and explains candidates the rules layer
already produced. The payload contains opaque candidate IDs and coarse attributes, never
paths. The producer redacts before the analyzer interface, the response is validated
against the candidate set, and protected paths are rejected regardless of model output.

The offline payload builder and rules-only analyzer live in `internal/analyzer`.
`-ai-preview` prints the payload and exits without making a network request.

The discovery mode sends aggregate directory basenames, extension classes, and the
existing rule names, never paths. The model may propose directory-name patterns, but
the local validator accepts only names present in the payload and rejects names already
covered by built-in rules. Suggestions are shown for review and are never applied
automatically.

## License

MIT. See [LICENSE](LICENSE).
