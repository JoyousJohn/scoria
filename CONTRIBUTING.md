# Contributing

Scoria is a Windows-only, read-only disk scanner. The read-only property is the
product, not a preference.

## Before you start

Read [DESIGN.md](DESIGN.md) and the invariants below.

- no delete, move, rename, shell file-operation, registry-write, or `GENERIC_WRITE` code
- exclusions are filtered at enumeration time
- metadata-only by default; only `-dupes` may read candidate contents
- protected paths are never recommendations
- the digest is versioned
- no network, telemetry, GUI framework, database, or LLM client

## Build and test

```powershell
$env:CGO_ENABLED = "0"
go build -trimpath -ldflags="-s -w" -o dist/scoria.exe ./cmd/scoria
go vet ./...
go test ./...
```

CI also runs a source-level write-API tripwire and an import-table check. Run the
import check locally with:

```powershell
go run ./tools/imports dist/scoria.exe
```

## Pull requests

- Keep changes small and focused.
- Add or update tests for behavior changes.
- Update README claims if behavior changes.
- Do not commit binaries, generated corpora, or report output.
- Use conventional commit messages, for example `fix(scan): ...` or `feat(rules): ...`.

By contributing, you agree that your contribution is licensed under the MIT license in
[LICENSE](LICENSE).
