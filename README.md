# Scoria

**Find what's safe to remove. Without removing it.**

Repository: <https://github.com/JoyousJohn/scoria>

Scoria is a read-only Windows disk scanner. It walks a directory tree, collects
metadata, applies deterministic rules, and reports review candidates with reasons.

It cannot delete, move, or rename anything. It writes only the HTML report you
explicitly request.

Status: early v1, rules-only. No installer, no GUI framework, no network client, no
telemetry. Console, JSON, and self-contained HTML output. Windows 10 or later.

## What it does

- Enumerates with `FindFirstFileExW` using `FindExInfoBasic` and large fetch.
- Walks directories with a bounded worker pool and reuses path buffers.
- Skips reparse points, so junctions and symlinks cannot loop the scan.
- Filters exclusions at enumeration time, before paths enter totals or output.
- Tracks entries and unique files separately, including hard-link deduplication.
- Aggregates totals, extension rollups, largest/oldest lists, and directory totals
  with bounded memory.
- Produces rules-only recommendations:
  - generated directories such as `node_modules`, `__pycache__`, `.venv`, `build`,
    `dist`, `target`, `obj`
  - large files and old files, filtered against protected paths
  - temporary and crash-dump extensions
  - size-only duplicate leads
  - content-verified duplicate groups with opt-in `-dupes`
- Treats protected paths as non-recommendable: Windows, Program Files, restore
  points, `$Recycle.Bin`, `Recovery`, pagefile, hiberfil, and swapfile.
- Writes a self-contained HTML report only when you request one with `-html`.
- Can lower the process to low mandatory integrity before scanning with
  `-low-integrity`.

Recommendations are review candidates, never deletion instructions. Confidence is
a statement about the evidence, not permission to remove anything.

## Build

Requires Go 1.27.3 or later. No C compiler is needed.

```powershell
git clone https://github.com/JoyousJohn/scoria.git
cd scoria
$env:CGO_ENABLED = "0"
go build -trimpath -ldflags="-s -w" -o dist/scoria.exe ./cmd/scoria
```

The result is a single self-contained `.exe`. `dist/` is ignored by git.

## Usage

```powershell
# scan a directory
.\dist\scoria.exe -root C:\Users\me

# interactive setup: root, hard-link counting, duplicate hashing, top-N, workers
.\dist\scoria.exe -interactive

# verify duplicate candidates by content, sorted by size
.\dist\scoria.exe -root C:\Users\me -dupes -sort=size

# machine-readable digest
.\dist\scoria.exe -root C:\Users\me -json -progress=never -color=never > digest.json

# self-contained HTML report, opened in the default browser
.\dist\scoria.exe -root C:\Users\me -html scoria-report.html

# report to stdout without opening a browser
.\dist\scoria.exe -root C:\Users\me -html - -open=false > report.html

# lower the process to low integrity before scanning; console or JSON output only
.\dist\scoria.exe -root C:\Users\me -low-integrity
```

Double-clicking the exe, or running it with no arguments in a console, starts
interactive setup and waits for Enter before exiting. Pass any flag to run
non-interactively.

| Flag | Meaning |
|---|---|
| `-root` | directory to scan (default `.`) |
| `-workers` | directory workers; `0` = 2x logical CPUs |
| `-top` | entries kept in each largest/oldest list; `0` disables the lists |
| `-links` | open each file read-only for hard-link and unique-file totals (default `true`, slower) |
| `-dupes` | verify same-size duplicates >= 1 MiB by hashing candidates; **reads candidate file contents** |
| `-interactive` | prompt for options, then offer a post-scan priority/size sort toggle |
| `-low-integrity` | lower the process to low mandatory integrity before scanning; file report output is disabled |
| `-sort` | recommendation order: `priority` (default) or `size` |
| `-json` | write the versioned digest to stdout |
| `-html` | write a self-contained HTML report to this path; `-` writes to stdout |
| `-open` | open the report in the default browser (default `true`) |
| `-pause` | wait for Enter before exiting; automatic for no-argument console runs |
| `-color` | `auto`, `always`, or `never` |
| `-progress` | progress line: `auto`, `always`, or `never` |

`-dupes` is the one content-reading path. It is off by default, prints a warning, and
only reads files whose size occurs more than once. The metadata-only guarantee applies
to the normal scan.

## Reading the output

Recommendations carry a rule, a confidence, a priority, item and byte totals, and
optional example paths.

| Confidence | Meaning |
|---|---|
| `high` | content hash matched, for verified duplicate groups |
| `medium` | strong deterministic signal, such as a known generated directory or temp extension |
| `low` | metadata heuristic, such as size or age alone; verify before acting |

Priority order is: verified duplicates, generated directories, temp extensions,
size-only duplicate leads, old files, large files.

Free space and size-on-disk are not guessed. Totals are logical sizes, which is what
`Get-ChildItem -File` and `robocopy /BYTES` report.

## Read-only and privacy

- The scanner opens files with read-only attribute access.
- The normal scan reads metadata only; it never reads file contents.
- `-dupes` is opt-in and reads only duplicate candidates.
- The only file write is the HTML report path passed to `-html`; without `-html`,
  Scoria writes no files.
- `-low-integrity` lowers the process to `S-1-16-4096` before scanning. A low-integrity
  process cannot write to most of the user profile, even if the scanner has a bug.
  File report output is disabled in this mode; `-html -` still works through the
  inherited stdout handle.
- No network access, no telemetry, no crash reports.
- No delete, move, rename, registry-write, or shell file-operation APIs.
- Excluded and sensitive paths are filtered before aggregation. The sensitive preset
  covers `.ssh`, common password-manager and browser-profile directories, crypto
  wallets, and `.kdbx`, `.pem`, `.key`, and `wallet.dat`.

Hard links are counted both ways: directory entries and unique file IDs. An excluded
file with an unprotected second hard link can still appear under that second path;
this is a filesystem property, not a scanner bug.

## Read-only evidence

CI rejects the source symbols `DeleteFile`, `MoveFile`, `SHFileOperation`,
`NtSetInformationFile`, `RegDeleteKey`, and `GENERIC_WRITE` in `cmd/` and
`internal/`. It also inspects the built binary's static import table:

```powershell
go run ./tools/imports dist/scoria.exe
```

Partial output:

```text
kernel32.dll
  CloseHandle
  GetConsoleMode
  GetProcAddress
  LoadLibraryExW
  WriteFile
```

`WriteFile` is the console/report output path, not a scanned-file write. Go resolves
most Win32 calls through `LoadLibraryExW` and `GetProcAddress`, so the static import
table is not the whole proof; the source grep and reproducible build are the stronger
checks. A `dumpbin /imports dist\scoria.exe` shows the same table on machines with
Visual Studio tools.

## Documentation

- [DESIGN.md](DESIGN.md) - product and architecture decisions
- [IMPLEMENTATION-NOTES.md](IMPLEMENTATION-NOTES.md) - Windows and implementation traps
- [TESTDATA.md](TESTDATA.md) - edge-case corpus and expected behavior
- [CONTRIBUTING.md](CONTRIBUTING.md) - working on the code
- [SECURITY.md](SECURITY.md) - private vulnerability reporting
- [CHANGELOG.md](CHANGELOG.md) - current and past changes
- [docs/index.html](docs/index.html) - landing page

## For scripts and automation

Scoria is read-only. It never deletes, moves, or renames anything. Treat
recommendations as review candidates, not instructions.

Use non-interactive mode:

```powershell
scoria -root C:\Users\me -json -progress=never -color=never > digest.json
```

The JSON digest is versioned (`"version": 1`). Recommendations have stable per-scan
IDs (`c1`, `c2`), a rule ID, priority, confidence, byte totals, and optional example
paths. Reject any returned ID that is not in the candidate set.

Do not auto-delete based on this output. Require human confirmation. Do not use
`-interactive` in automation. Remember that `-dupes` reads candidate file contents,
while the default scan does not.

## License

MIT. See [LICENSE](LICENSE).
