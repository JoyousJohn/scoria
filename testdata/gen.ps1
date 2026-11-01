param(
    [string]$Root = "D:\scoria-testdata",
    [int]$ManyFiles = 25000
)

$ErrorActionPreference = "Stop"

if (Test-Path -LiteralPath $Root) {
    cmd /c rd /s /q "\\?\$Root"
}
[System.IO.Directory]::CreateDirectory($Root) | Out-Null

[System.IO.File]::WriteAllText((Join-Path $Root "a.txt"), "hardlink source")
[System.IO.File]::WriteAllText((Join-Path $Root "zero-byte.txt"), "")
[System.IO.File]::WriteAllText((Join-Path $Root "secret.pem"), "private key stand-in")
[System.IO.File]::WriteAllText((Join-Path $Root "vault.kdbx"), "vault stand-in")
[System.IO.File]::WriteAllText((Join-Path $Root "wallet.dat"), "wallet stand-in")
$unicodeName = "caf" + [char]0x00E9 + "-" + [char]0x6587 + [char]0x4EF6 + ".txt"
[System.IO.File]::WriteAllText((Join-Path $Root $unicodeName), "unicode name")

cmd /c mklink /H "$Root\b-hardlink.txt" "$Root\a.txt" | Out-Null
[System.IO.Directory]::CreateDirectory((Join-Path $Root "target")) | Out-Null
[System.IO.File]::WriteAllText((Join-Path $Root "target\inner.txt"), "inner")
cmd /c mklink /J "$Root\j-junction" "$Root\target" | Out-Null

$compress = Join-Path $Root "compressed.bin"
$bytes = New-Object byte[] (1024 * 1024)
[System.IO.File]::WriteAllBytes($compress, $bytes)
compact /c "$compress" | Out-Null

$sparse = Join-Path $Root "sparse.bin"
[System.IO.File]::WriteAllBytes($sparse, (New-Object byte[] 4096))
fsutil sparse setflag "$sparse" | Out-Null
fsutil file setrange "$sparse" 0 1048576 | Out-Null

$deep = $Root
for ($i = 0; $i -lt 60; $i++) {
    $deep = Join-Path $deep ("d$i")
}
[System.IO.Directory]::CreateDirectory("\\?\$deep") | Out-Null
[System.IO.File]::WriteAllText("\\?\$deep\bottom.txt", "bottom")

$long = $Root
for ($i = 0; $i -lt 12; $i++) {
    $long = Join-Path $long ("segment$i-xxxxxxxxxxxxxxxxxxxx")
}
[System.IO.Directory]::CreateDirectory("\\?\$long") | Out-Null
[System.IO.File]::WriteAllText("\\?\$long\leaf.txt", "long path leaf")

$trailingDot = "\\?\$Root\trailingdot."
$trailingSpace = "\\?\$Root\trailingspace "
try { [System.IO.File]::WriteAllText($trailingDot, "dot") } catch { Write-Warning "trailing dot: $($_.Exception.Message)" }
try { [System.IO.File]::WriteAllText($trailingSpace, "space") } catch { Write-Warning "trailing space: $($_.Exception.Message)" }

foreach ($reserved in @("CON", "PRN", "NUL", "AUX")) {
    $p = "\\?\$Root\$reserved"
    try { [System.IO.File]::WriteAllText($p, $reserved) } catch { Write-Warning "reserved ${reserved}: $($_.Exception.Message)" }
}

$many = Join-Path $Root "many"
[System.IO.Directory]::CreateDirectory($many) | Out-Null
for ($i = 0; $i -lt $ManyFiles; $i++) {
    $path = Join-Path $many ("f{0:D6}.tmp" -f $i)
    [System.IO.File]::WriteAllText($path, "")
}

$denied = Join-Path $Root "denied"
[System.IO.Directory]::CreateDirectory($denied) | Out-Null
[System.IO.File]::WriteAllText((Join-Path $denied "secret.txt"), "denied")

$count = (Get-ChildItem -LiteralPath $Root -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Output "created $Root with $count files"
Write-Output "restore ACL after scanning: icacls `"$denied`" /remove:d `"$env:USERDOMAIN\$env:USERNAME`""
