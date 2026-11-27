# Baut das Release-ZIP fuer GitHub aus den von Git verwalteten Dateien (nur fuer den Entwickler).
#   powershell -ExecutionPolicy Bypass -File .\make-release.ps1          (Version aus der Datei VERSION)
# Lokale Dateien (config.toml, python\, lib\, tools\, Downloads, Arbeitsordner) kommen nie hinein.
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
# Scheitert eine dieser Abfragen, bricht das Skript ab: ein Scan mit weniger Begriffen faellt sonst niemandem auf.
# git config: Exit 0 = gesetzt, 1 = nicht gesetzt, alles andere = Fehler.
$mails = @()
foreach ($scope in @(@('--global'), @())) {
  try { $mail = @(& git config @scope user.email 2>$null); $code = $LASTEXITCODE } catch { throw "Git-E-Mail nicht lesbar - Suche nach persoenlichen Angaben unvollstaendig, nichts gepackt." }
  if ($code -ne 0 -and $code -ne 1) { throw "Git-E-Mail nicht lesbar (git config, Exitcode $code) - nichts gepackt." }
  foreach ($m in $mail) { if ("$m".Trim()) { $mails += "$m".Trim() } }
}
if (-not $mails) { throw 'Keine Git-E-Mail gefunden (git config user.email) - Suche waere unvollstaendig, nichts gepackt.' }
foreach ($m in $mails) { $needles.Add($m) }
try {
  # VPN-Tunneladressen vergibt der Anbieter fuer alle Nutzer gleich (Proton: 10.2.0.2) - nicht persoenlich.
  $vpnAliases = @(Get-NetAdapter -ErrorAction Stop | Where-Object { "$($_.Name) $($_.InterfaceDescription)" -match 'Proton|ProTUN|WireGuard|Wintun|TAP-Windows|OpenVPN' } | ForEach-Object { $_.Name })
  Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
    Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and $vpnAliases -notcontains $_.InterfaceAlias } |
    ForEach-Object { $needles.Add($_.IPAddress) }
} catch { throw "Lokale IPv4-Adressen nicht lesbar - Suche nach persoenlichen Angaben unvollstaendig, nichts gepackt. ($($_.Exception.Message))" }
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

# ---- PowerShell 5.1 liest .ps1 ohne BOM als ANSI: Umlaute wuerden verfaelscht. Nicht-ASCII nur mit UTF-8-BOM.
$latin1 = [Text.Encoding]::GetEncoding(28591)   # Byte fuer Byte, damit jedes Byte >= 0x80 sichtbar wird
$noBom = @($files | Where-Object { $_ -match '\.ps1$' } | Where-Object {
  $bytes = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $_))
  $hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
  (-not $hasBom) -and ($latin1.GetString($bytes) -match '[^\x00-\x7F]') })
if ($noBom) { throw "Nicht-ASCII ohne UTF-8-BOM (PowerShell 5.1 liest das falsch): $($noBom -join ', ')" }

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
