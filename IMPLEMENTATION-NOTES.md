# Implementation Notes — v1 scanner

Companion to [DESIGN.md](DESIGN.md). DESIGN.md says *what* and *why*; this file is the
implementation-level traps that are not obvious until you hit them.

---

## 1. Dependency budget

`stdlib` + `golang.org/x/sys/windows`. Nothing else without written justification.

No Cobra, no Viper, no logrus, no SQLite, no CLI framework. Besides the size argument,
dependency minimalism is a **trust argument**: every third-party package is supply-chain
surface in a tool people run with read access to their whole disk.

---

## 2. Go + Win32 specifics

### 2.1 The MAX_PATH truncation trap (read this first)

`syscall.Win32finddata` declares `FileName [MAX_PATH - 1]uint16`. Any path you get from
`FindFirstFile`/`FindNextFile` through that struct is **silently truncated at 259
characters**. You will not get an error — you will get a wrong name, or a wrong parent, or
a duplicate.

Consequences:
- A `FindFirstFileExW`-only design cannot support long paths, regardless of `\\?\`
  prefixes, because the *output struct* is the limiter.
- For genuine long-path support you need `NtQueryDirectoryFile` with
  `FILE_ID_BOTH_DIR_INFO` / `FILE_BOTH_DIR_INFORMATION`, or `GetFileInformationByHandleEx`.
- For v1 it is acceptable to detect the condition and **count it in the "skipped" bucket**
  rather than silently corrupting names. Do not pretend you covered paths you could not.

### 2.2 `os.ReadDir` may already be the fast path

On Go 1.20+ Windows, `os.ReadDir` uses a batched directory-info syscall rather than
per-entry `FindNextFile` + `stat`, and `DirEntry.Info()` is served from that cached data.
Verify against the Godoc for the Go version you pin — but if it holds, the naive
"reimplement FindFirstFileEx" step may be a **downgrade**.

What `os.ReadDir` does not give you cheaply:
- creation time and last-access time (the `FileInfo` interface only exposes `ModTime`;
  the underlying Windows `fileStat` has all three, so you may need `GetFileAttributesEx`
  or a type assertion — check per version)
- attributes (`FILE_ATTRIBUTE_REPARSE_POINT`, `RECALL_ON_DATA_ACCESS`)
- file ID

So: measure `os.ReadDir` before writing raw Win32. Use `FindFirstFileExW` with
`FindExInfoBasic` (skips 8.3 short-name resolution) + `FIND_FIRST_EX_LARGE_FETCH` (0x2)
only if you need attributes in the same pass.

### 2.3 Other calls

| Need | API |
|---|---|
| allocated / on-disk size | `GetCompressedFileSizeW` |
| hard-link identity | `GetFileInformationByHandleEx` → `FileIdInfo` (`FILE_ID_INFO`: `VolumeSerialNumber` + 128-bit `FileId.Identifier`) |
| attributes + all three timestamps | `GetFileAttributesExW` |
| low-integrity token | `CreateRestrictedToken` + `SetTokenInformation(TokenIntegrityLevel)` → `S-1-16-4096` |

Constants worth having on hand: `FindExInfoBasic = 1`, `FIND_FIRST_EX_LARGE_FETCH = 0x2`,
`FILE_ATTRIBUTE_REPARSE_POINT = 0x400`, `FILE_ATTRIBUTE_OFFLINE = 0x1000`,
`FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000`,
`FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000`.

### 2.4 Throughput hygiene

- Reuse the path buffer per worker. `UTF16ToString` allocates per entry — that is what
  actually caps throughput, not the syscall.
- Prefer one shared, append-only result channel over a mutex per directory.
- Consider `debug.SetGCPercent(200)` for the scan phase; the scan is allocation-heavy and
  GC pressure shows up as noise in your own measurement.
- Do **not** call `runtime.LockOSThread`.

### 2.5 Low-integrity token

`GetCurrentProcessToken` is a pseudo-handle and `SetTokenInformation` on it fails with
"The handle is invalid". Open the real token first:

```go
windows.OpenProcessToken(windows.CurrentProcess(),
    windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_QUERY, &token)
```

Then set `TokenIntegrityLevel` to the SID `S-1-16-4096`. This works without elevation
when lowering the current process; `CreateRestrictedToken` is not required (and is not
exposed by `x/sys/windows`).

Consequences:
- The scan runs at low IL and can still read most files; write-up is denied.
- Writing an HTML report file to a normal user directory fails. Use `-html -` through
  the inherited stdout handle, or run without `-low-integrity`.
- Do not launch the browser from a low-IL process; skip auto-open in this mode.

---

## 3. Define counting semantics before you measure anything

Two different numbers, both legitimate, and they will not match a naive `dir /s`:

- **entries** — one per directory entry seen; a hard-linked file with three links counts 3×.
- **unique files** — deduplicated by `FILE_ID_INFO`; counts 1×.

Record both from day one. When your numbers disagree with TreeSize/WizTree, this
distinction is the explanation ~90% of the time, and discovering that after publishing a
benchmark is embarrassing.

Also record separately: inaccessible directories (permission denied), skipped reparse
points, and skipped long paths. Those are the "skipped by the tool" bucket.

### 3.1 Duplicate verification is a separate, consent-gated phase

Pass 1 is metadata-only (D2). Duplicate verification is the one place that reads file
contents, and it must stay opt-in:

- enabled by `-dupes`, **off by default**;
- re-walks the tree and reads only files whose size occurs more than once;
- uses a 1 MiB minimum candidate size, so tiny files are not hashed;
- skips protected paths, reparse points, cloud placeholders, and excluded files;
- hashes the first 8 KiB, then the full file only for prefix matches;
- deduplicates hard links before hashing so two links are not reported as duplicates;
- uses read-only opens; no write API is involved.

The CLI must say plainly that this phase reads contents and that the metadata-only
guarantee does not apply to it. The rules engine switches from the size-only
`duplicate-candidates` lead to `verified-duplicates` groups only when this phase ran.

---

## 4. Measurement protocol

Any number you report must state:

1. **warm or cold** cache (cold = `RAMMap`/reboot, or at minimum a distinct large tree)
2. drive type (NVMe / SATA SSD / spinning)
3. **whether Defender real-time scanning was on** — it can halve throughput, and it is the
   single biggest reason a user cannot reproduce your benchmark
4. tree size (file count and bytes)
5. Go version and build flags

Never benchmark `D:\Projects\scoria` — it is tiny and warm. Use a real large directory.

### Ground truth, mandatory

Before reporting plausible-looking numbers, validate against an independent tool on a tree
you understand:

```powershell
# independent file count and byte total (ignore errors, count what is readable)
$m = Get-ChildItem -LiteralPath "D:\sometree" -Recurse -Force -File -ErrorAction SilentlyContinue |
     Measure-Object -Property Length -Sum
"files=$($m.Count) bytes=$($m.Sum)"

# robocopy as a second opinion: /L = list only, never copies
robocopy "D:\sometree" "D:\null" /L /S /BYTES /NFL /NDL /NJH /NP
```

If Scoria's numbers differ, explain the delta with the counting semantics above. A scanner
that is fast and wrong is worse than slow and right.

Optional for clean dev benchmarks (requires admin, user-run, never silently):
`Add-MpPreference -ExclusionPath "D:\Projects\scoria"`.

---

## 5. Test corpus — build it now, not later

`TESTDATA.md` / a `testdata/gen.ps1` that creates the edge-case tree. Suggested commands:

```powershell
# hard links: same file ID, two paths
New-Item -ItemType File "D:\t\a.txt" -Force | Out-Null
cmd /c mklink /H "D:\t\b-hardlink.txt" "D:\t\a.txt"

# junction: must be skipped, must not loop
New-Item -ItemType Directory "D:\t\target" -Force | Out-Null
cmd /c mklink /J "D:\t\j-junction" "D:\t\target"

# NTFS compression: size vs size-on-disk diverge
New-Item -ItemType File "D:\t\c-compress.txt" -Force | Out-Null
fsutil file setvaliddata "D:\t\c-compress.txt" 1048576
compact /c "D:\t\c-compress.txt"

# sparse file
fsutil sparse setflag "D:\t\c-compress.txt"
fsutil file setrange "D:\t\c-compress.txt" 0 1048576
```

Plus: reserved names (`CON`, `PRN`, `NUL`, `AUX`), trailing dot/space names, case
collisions, zero-byte files, a 300+ character path, deep nesting, and a directory with
25k+ entries in one level.

`mklink /H` and `/J` do not require admin; `/D` (directory symlink) does without Developer
Mode. Notes in `TESTDATA.md` should say which need elevation.

---

## 6. The digest is the contract — define it early

`internal/digest` should hold a **versioned** struct from day one, because it is the
interface between three things that will diverge if nobody owns it:

1. the scanner (producer)
2. the rules analyzer and any future LLM analyzer (consumers)
3. the HTML report, and later the optional "drag this JSON onto the website" flow

Version it (`"v": 1`), keep it free of absolute paths until the last possible stage, and
write one test that round-trips it. Redaction belongs in the producer, not the consumers.

### 6.1 Cloud payloads: opaque candidate IDs, not reversible path pseudonymization

Do not build a random-word substitution table for paths. It leaks directory structure,
collides, and creates a re-identification key that must be protected and correctly
reversed. The model does not need paths to rank candidates; see the analysis rule in
[DESIGN.md](DESIGN.md).

Instead:

- the rules layer assigns each candidate a stable per-scan opaque ID (`c1`, `c2`, ...);
- the digest sends only that ID plus coarse attributes: rule ID, extension class, size
  bucket, age bucket, depth;
- the ID -> path map stays in memory in the local process and is never persisted;
- model output is accepted only for IDs that exist in the candidate set;
- any recommendation touching a protected path is rejected regardless of model output;
- the local report resolves IDs to paths only after validation.

This keeps D8 structural: an invented path has no ID to resolve.

If a future design concludes paths are genuinely needed:

- use a per-scan random ID or salted hash, never a word list;
- allowlist fields rather than blocklisting usernames;
- send counts, not names, for document/medical/financial extensions;
- show the literal JSON and byte count in the payload preview before sending;
- remember that pseudonymized filenames are still personal data under GDPR.

All of this belongs in the digest producer, before `IAnalyzer`, so no provider can
bypass it. v1 has no analyzer; the digest contract is where the hook goes.

---

## 7. Docs copy discipline

When you write `docs/index.html`, every claim must be true and checkable:

- It cannot delete anything (and never imply otherwise in copy — no "safely remove").
- It sends nothing unless the user opts in.
- Link the binary via `releases/latest/download/scoria.exe`; never commit the exe.

Do not invent a benchmark number, a user count, or a security guarantee that is not in
[DESIGN.md](DESIGN.md) or the code. If the copy needs a claim the code does not yet
support, cut the claim.

---

## 8. License — decided: MIT

The project uses the MIT license in [LICENSE](LICENSE). The earlier open decision is
closed. Do not change it without the owner's explicit instruction.

---

## 9. Definition of done for the checkpoint

All of these, or it is not done:

- builds with `CGO_ENABLED=0 go build -ldflags="-s -w"`
- `go vet ./...` clean; at least one unit test on rule matching and one on the digest
  round-trip
- runs against a real large tree and produces entry/byte totals **validated per the
  measurement protocol above**
- reparse points skipped and counted; permission denials counted
- no write-capable API in the source (grep clean for `cmd/` + `internal/`)
- committed, with the measurement numbers and their caveats in the report back
