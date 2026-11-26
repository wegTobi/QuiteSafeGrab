# Baut das Release-ZIP fuer GitHub aus den von Git verwalteten Dateien (nur fuer den Entwickler).
#   powershell -ExecutionPolicy Bypass -File .\make-release.ps1          (Version aus der Datei VERSION)
# Lokale Dateien (config.toml, python\, lib\, tools\, venv\, Downloads, Arbeitsordner) kommen nie hinein.
# Vor dem Packen wird jede Textdatei nach persoenlichen Angaben dieses PCs durchsucht
# (Benutzername und seine Teile, Profilpfad, Rechnername, lokale IPv4-Adressen, Git-E-Mail
# sowie alles aus -Forbid). Ein Treffer bricht ab.
# Auf GitHub als Release hochladen: Tag "v<Version>", Dateien QuiteSafeGrab-Windows-<Version>.zip
# UND .zip.sha256 (beide braucht die Update-Funktion von setup.ps1).
param(
  [ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version = '',
  [string[]]$Forbid = @()
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
Add-Type -AssemblyName System.IO.Compression.FileSystem
$fileVersion = (Get-Content -LiteralPath 'VERSION' -TotalCount 1).Trim()
if (-not $Version) { $Version = $fileVersion }
if ($Version -ne $fileVersion) { throw "Version $Version passt nicht zur Datei VERSION ($fileVersion). Erst VERSION anpassen." }

# Inhalt = alle Dateien, die Git verwaltet (lokale/persoenliche Dateien schliesst .gitignore aus),
# abzueglich reiner Entwicklerwerkzeuge. Neue Dateien kommen so automatisch mit.
$devOnly = @('make-release.ps1')
$untracked = @(git ls-files --others --exclude-standard)
if ($LASTEXITCODE -ne 0) { throw 'git ist noetig (Dateiliste kommt aus dem Repository).' }
if ($untracked) { throw "Nicht in Git und nicht ignoriert - erst 'git add' oder in .gitignore eintragen: $($untracked -join ', ')" }
$files = New-Object System.Collections.Generic.List[string]
foreach ($f in @(git ls-files)) {
  if ($devOnly -contains $f) { continue }
  $path = $f.Replace('/', '\')
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "In Git, aber nicht vorhanden: $path" }
  $files.Add($path)
}

# ---- Suche nach persoenlichen Angaben
$needles = New-Object System.Collections.Generic.List[string]
foreach ($n in @($env:USERNAME, $env:USERPROFILE, $env:COMPUTERNAME) + $Forbid) { if ($n) { $needles.Add($n) } }
foreach ($part in ($env:USERNAME -split '[\s._-]+')) { if ($part.Length -ge 4) { $needles.Add($part) } }
try { $mail = (& git config --global user.email 2>$null); if ($mail) { $needles.Add($mail.Trim()) } } catch {}
try {
  # VPN-Tunneladressen vergibt der Anbieter fuer alle Nutzer gleich (Proton: 10.2.0.2) - nicht persoenlich.
  $vpnAliases = @(Get-NetAdapter -ErrorAction Stop | Where-Object { "$($_.Name) $($_.InterfaceDescription)" -match 'Proton|ProTUN|WireGuard|Wintun|TAP-Windows|OpenVPN' } | ForEach-Object { $_.Name })
  Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
    Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and $vpnAliases -notcontains $_.InterfaceAlias } |
    ForEach-Object { $needles.Add($_.IPAddress) }
} catch {}
$hits = @()
foreach ($f in $files) {
  if ($f.EndsWith('.whl')) { continue }   # Wheels sind per SHA256 an PyPI gebunden
  $text = [IO.File]::ReadAllText((Join-Path $PSScriptRoot $f))
  foreach ($n in $needles) {
    if ($text.IndexOf($n, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $hits += "$f enthaelt eine persoenliche Angabe (Laenge $($n.Length), beginnt mit '$($n.Substring(0, [Math]::Min(2, $n.Length)))')" }
  }
}
if ($hits) { $hits | ForEach-Object { Write-Host "  $_" }; throw 'Persoenliche Angaben gefunden - nichts gepackt.' }

# ---- Windows-Zeilenenden: cmd.exe liest Batchdateien mit reinem LF fehlerhaft (vor allem, wenn ein Update sie ersetzt)
$lfOnly = @($files | Where-Object { $_ -match '\.(cmd|ps1)$' } | Where-Object {
  [IO.File]::ReadAllText((Join-Path $PSScriptRoot $_)) -match "(?<!`r)`n" })
if ($lfOnly) { throw "Ohne CRLF-Zeilenenden: $($lfOnly -join ', ') (git rm --cached -r . ; git reset --hard)" }

# ---- Packen
$name = "QuiteSafeGrab-Windows-$Version"
$dist = Join-Path $PSScriptRoot 'dist'
if (-not (Test-Path -LiteralPath $dist)) { New-Item -ItemType Directory -Path $dist | Out-Null }
$zip = Join-Path $dist "$name.zip"
if (Test-Path -LiteralPath $zip) { throw "Gibt es schon: $zip (Version erhoehen oder Datei selbst loeschen)." }
$archive = [IO.Compression.ZipFile]::Open($zip, 'Create')
try {
  foreach ($f in ($files | Sort-Object)) {
    [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, (Join-Path $PSScriptRoot $f), "$name/" + $f.Replace('\', '/'), 'Optimal') | Out-Null
  }
} finally { $archive.Dispose() }
$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$zip.sha256" -Value "$hash  $name.zip" -Encoding ascii
Write-Host "Fertig: $zip ($($files.Count) Dateien)"
Write-Host "SHA256: $hash"
