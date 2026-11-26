# Baut das Release-ZIP fuer GitHub aus einer festen Liste von Dateien (nur fuer den Entwickler).
#   powershell -ExecutionPolicy Bypass -File .\make-release.ps1 -Version 1.0.0
# Lokale Dateien (config.toml, python\, lib\, tools\, venv\, Downloads, Arbeitsordner) kommen nie hinein.
# Vor dem Packen wird jede Textdatei nach persoenlichen Angaben dieses PCs durchsucht
# (Benutzername und seine Teile, Profilpfad, Rechnername, lokale IPv4-Adressen, Git-E-Mail
# sowie alles aus -Forbid). Ein Treffer bricht ab.
param(
  [Parameter(Mandatory = $true)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
  [string[]]$Forbid = @()
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
Add-Type -AssemblyName System.IO.Compression.FileSystem

$include = @(
  'grab.py', 'syscompat.py', 'winguard.py', 'fw.py', 'voe_resolver.py', 'ui.py',
  'ui\index.html', 'ui\app.css', 'ui\app.js',
  'qsgrab.cmd', 'Oberflaeche-starten.cmd', 'setup.ps1', 'haertung.ps1', 'config.default.toml',
  'requirements.txt', 'requirements.lock', 'vendor-sha256.json',
  'README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md', '.gitignore'
)
$includeDirs = @{ 'voe_dl' = '*.py'; 'tests' = '*.py'; 'wheels' = '*.whl' }

$files = New-Object System.Collections.Generic.List[string]
foreach ($f in $include) {
  if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { throw "Fehlt: $f" }
  $files.Add($f)
}
foreach ($d in $includeDirs.Keys) {
  Get-ChildItem -LiteralPath $d -Recurse -File -Filter $includeDirs[$d] |
    Where-Object { $_.FullName -notmatch '\\__pycache__\\' } |
    ForEach-Object { $files.Add($_.FullName.Substring($PSScriptRoot.Length + 1)) }
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
