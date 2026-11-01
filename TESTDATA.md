# Test corpus

The generator writes to `D:\scoria-testdata` by default so the repository stays small.
It rewrites that directory on every run.

```powershell
.\testdata\gen.ps1
```

## What it creates

| Case | Purpose | Elevation |
|---|---|---|
| `a.txt` + `b-hardlink.txt` | same file ID, two directory entries | no (`mklink /H`) |
| `j-junction` | must be skipped, must not loop or double count | no (`mklink /J`) |
| `compressed.bin` | logical size vs size-on-disk divergence | no |
| `sparse.bin` | sparse extent handling | possibly (`fsutil sparse`) |
| 60-level `d0\d1\...` | deep nesting, short components | no |
| 300+ character path | `\\?\` enumeration and long-path handling | no |
| `trailingdot.`, `trailingspace ` | Win32 name normalisation | no |
| `CON`, `PRN`, `NUL`, `AUX` | reserved-name handling | no |
| `café-文件.txt` | non-ASCII names | no |
| `zero-byte.txt` | zero-byte accounting | no |
| `many\f000000.tmp` ... | 25,000 entries in one directory | no |

Reserved names and trailing dot/space names only succeed through `\\?\` paths on
some builds; the generator warns and continues when the filesystem refuses.

## Permission-denied bucket

The generator creates `denied\secret.txt`. To make it actually inaccessible to the
scanner, deny read access to the current user before the run and restore it afterwards:

```powershell
$root = "D:\scoria-testdata"
$me = whoami
icacls "$root\denied" /deny "${me}:(OI)(CI)(RX)"
.\dist\scoria.exe -root $root
icacls "$root\denied" /remove:d "$me"
```

Do not leave the deny ACE in place. `icacls` prints the identity it accepted.

## Expected totals

The corpus has one hard link, so entries exceed unique files by one. The junction
contributes to the reparse-point bucket and never to file/byte totals. Excluded
sensitive files (for example a planted `.kdbx`) are excluded before aggregation, so
they appear only in the `excluded by rules` section.

Do not compare the corpus to `Get-ChildItem -Recurse` without accounting for the
junction, reserved names, and ASCII-vs-UTF-16 name quirks.
