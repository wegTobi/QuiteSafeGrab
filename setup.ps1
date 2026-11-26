# Quite Safe Grab fuer Windows - einmalige Einrichtung. Windows PowerShell 5.1 oder neuer, keine Adminrechte.
#
# Legt eine EIGENE Python-Laufzeit nur fuer Quite Safe Grab an (.\python, offizielles "Embeddable Package"
# von python.org). Ein bereits installiertes Python wird weder benutzt noch veraendert; die
# Firewallregeln von Quite Safe Grab betreffen deshalb keine anderen Python-Programme.
#
# Heruntergeladen wird nur, was fehlt, und nur von fest eingetragenen Adressen mit fest
# eingetragener SHA256-Pruefsumme (Abweichung = Abbruch, nichts wird installiert):
#   - Python 3.14.10 Embeddable (python.org)
#   - FFmpeg 9.1 essentials (gyan.dev-Build auf GitHub, GPLv3) - nur ffmpeg.exe und ffprobe.exe
# Python-Abhaengigkeiten kommen ausschliesslich aus .\wheels (SHA256 aus requirements.lock).
#
#   powershell -ExecutionPolicy Bypass -File .\setup.ps1
#   powershell -ExecutionPolicy Bypass -File .\setup.ps1 -PythonZip D:\python-3.14.10-embed-amd64.zip -FfmpegZip D:\ffmpeg-9.1-essentials_build.zip
#   powershell -ExecutionPolicy Bypass -File .\setup.ps1 -Offline     (laedt nichts; Dateien muessen schon da sein)
param(
  [string]$PythonZip = '',   # bereits heruntergeladenes Embeddable-ZIP verwenden (wird trotzdem geprueft)
  [string]$FfmpegZip = '',   # bereits heruntergeladenes FFmpeg-ZIP verwenden (wird trotzdem geprueft)
  [switch]$Offline           # nichts aus dem Internet laden
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Fortschrittsbalken macht Invoke-WebRequest in PS 5.1 sehr langsam
Set-Location -LiteralPath $PSScriptRoot
Add-Type -AssemblyName System.IO.Compression.FileSystem

# ---- Feste Quellen (bei einem Update: Version, Adresse und Pruefsumme gemeinsam aendern)
$PY_VERSION = '3.14.10'
$PY_TAG = 'python314'
$PY_SOURCES = @{
  'amd64' = @{ Url = "https://www.python.org/ftp/python/$PY_VERSION/python-$PY_VERSION-embed-amd64.zip"; Sha256 = '90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159' }
  'arm64' = @{ Url = "https://www.python.org/ftp/python/$PY_VERSION/python-$PY_VERSION-embed-arm64.zip"; Sha256 = 'bbe116bb1248820359cbf25127ac5c7794ea161869d83686cfbc9a45203ff836' }
}
$FF_VERSION = '9.1'
$FF_URL = "https://github.com/GyanD/codexffmpeg/releases/download/$FF_VERSION/ffmpeg-$FF_VERSION-essentials_build.zip"
$FF_SHA256 = 'b9bbbb3acece000cbeec994f856649354e52c773807841e78908374b24d658fd'

$pyDir = Join-Path $PSScriptRoot 'python'
$libDir = Join-Path $PSScriptRoot 'lib'
$toolsDir = Join-Path $PSScriptRoot 'tools'
$dlDir = Join-Path $PSScriptRoot 'downloads'

function Step([string]$text) { Write-Host ''; Write-Host "== $text" }

function Get-Sha256([string]$path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }

function Get-Verified([string]$url, [string]$sha, [string]$given, [string]$what) {
  # Liefert den Pfad einer Datei mit genau dieser Pruefsumme: vorgegebene Datei, frueherer Download oder neuer Download.
  if ($given) {
    $path = [IO.Path]::GetFullPath($given)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "$what nicht gefunden: $path" }
    if ((Get-Sha256 $path) -ne $sha) { throw "$what hat die falsche Pruefsumme (erwartet $sha). Datei nicht verwendet." }
    return $path
  }
  $name = [IO.Path]::GetFileName(([uri]$url).AbsolutePath)
  $path = Join-Path $dlDir $name
  if ((Test-Path -LiteralPath $path) -and ((Get-Sha256 $path) -eq $sha)) { Write-Host "Bereits geladen und geprueft: $name"; return $path }
  if ($Offline) { throw "$what fehlt und -Offline ist gesetzt. Datei $name von $url selbst laden und mit -PythonZip/-FfmpegZip angeben." }
  if (-not (Test-Path -LiteralPath $dlDir)) { New-Item -ItemType Directory -Path $dlDir | Out-Null }
  $part = "$path.part"
  if (Test-Path -LiteralPath $part) { Remove-Item -LiteralPath $part -Force }
  Write-Host "Lade $what von $url ..."
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -Uri $url -OutFile $part -UseBasicParsing -MaximumRedirection 5
  $actual = Get-Sha256 $part
  if ($actual -ne $sha) {
    Remove-Item -LiteralPath $part -Force
    throw "$what hat die falsche Pruefsumme (erwartet $sha, erhalten $actual). Download verworfen, nichts installiert."
  }
  if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
  Move-Item -LiteralPath $part -Destination $path
  Write-Host "Pruefsumme stimmt: $name"
  return $path
}

function Read-LockHashes {
  $hashes = @{}
  foreach ($line in Get-Content -LiteralPath (Join-Path $PSScriptRoot 'requirements.lock')) {
    $m = [regex]::Match($line, '^\s*([A-Za-z0-9_.\-]+)==([^\s]+)\s+--hash=sha256:([0-9a-f]{64})\s*$')
    if ($m.Success) { $hashes[$m.Groups[3].Value] = "$($m.Groups[1].Value)==$($m.Groups[2].Value)" }
    elseif ($line.Trim() -and -not $line.TrimStart().StartsWith('#')) { throw "requirements.lock: unerwartete Zeile: $line" }
  }
  if ($hashes.Count -eq 0) { throw 'requirements.lock enthaelt keine Pakete.' }
  return $hashes
}

# ---- 1. Rechner pruefen
Step 'Rechner pruefen'
if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Nur unter Windows.' }
$arch = switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { 'amd64' } 'ARM64' { 'arm64' } default { $null } }
if (-not $arch -and $env:PROCESSOR_ARCHITEW6432 -eq 'AMD64') { throw 'Bitte die 64-Bit-PowerShell verwenden (nicht "Windows PowerShell (x86)").' }
if (-not $arch) { throw "Nicht unterstuetzte Prozessorarchitektur: $($env:PROCESSOR_ARCHITECTURE) (noetig: 64-Bit x64 oder ARM64)." }
Write-Host "Windows, Architektur $arch"
if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'venv')) {
  Write-Warning 'Ordner venv aus einer aelteren Einrichtung gefunden. Er wird nicht mehr benutzt und kann geloescht werden (danach qsgrab.cmd firewall apply erneut).'
}

# ---- 2. Eigene Python-Laufzeit
Step "Python $PY_VERSION (eigene Laufzeit in .\python)"
$pyExe = Join-Path $pyDir 'python.exe'
$pth = Join-Path $pyDir "$PY_TAG._pth"
if (Test-Path -LiteralPath $pyDir) {
  if (-not (Test-Path -LiteralPath $pth)) {
    throw 'Ordner python existiert, ist aber kein QuiteSafeGrab-Embeddable-Python (z. B. aus einer alten Einrichtung). Ordner python loeschen und setup.ps1 erneut starten.'
  }
  $have = (& $pyExe -I -c "import platform;print(platform.python_version())").Trim()
  if ($LASTEXITCODE -ne 0) { throw 'Vorhandenes .\python startet nicht. Ordner python loeschen und setup.ps1 erneut starten.' }
  if ($have -ne $PY_VERSION) {
    throw "Vorhandenes .\python ist Version $have statt $PY_VERSION. Fuer ein Update Ordner python loeschen und setup.ps1 erneut starten (danach qsgrab.cmd firewall apply)."
  }
  Write-Host "Vorhanden: Python $have"
} else {
  $src = $PY_SOURCES[$arch]
  $zip = Get-Verified $src.Url $src.Sha256 $PythonZip 'Python-Paket'
  $tmp = "$pyDir.new"
  if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
  [IO.Compression.ZipFile]::ExtractToDirectory($zip, $tmp)
  if (-not (Test-Path -LiteralPath (Join-Path $tmp "$PY_TAG._pth"))) { Remove-Item -LiteralPath $tmp -Recurse -Force; throw "Python-Paket ohne $PY_TAG._pth - unerwarteter Inhalt." }
  Move-Item -LiteralPath $tmp -Destination $pyDir
  Write-Host "Entpackt nach $pyDir"
}
# Suchpfade festlegen: Standardbibliothek, QuiteSafeGrab-Programmordner (..) und Abhaengigkeiten (..\lib).
# Keine site-packages, kein Benutzerverzeichnis, keine Umgebungsvariablen (Embeddable-Python ignoriert sie).
$pthText = "$PY_TAG.zip`r`n.`r`n..`r`n..\lib`r`n"
[IO.File]::WriteAllText($pth, $pthText, (New-Object Text.UTF8Encoding($false)))

# ---- 3. Abhaengigkeiten aus .\wheels
Step 'Python-Abhaengigkeiten (nur aus .\wheels, SHA256-geprueft)'
$locked = Read-LockHashes
$wheels = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'wheels') -Filter '*.whl' -File)
$seen = @{}
foreach ($w in $wheels) {
  $h = Get-Sha256 $w.FullName
  if (-not $locked.ContainsKey($h)) { throw "Wheel nicht in requirements.lock (oder veraendert): $($w.Name)" }
  if (-not $w.Name.EndsWith('-py3-none-any.whl')) { throw "Nur reine Python-Wheels erlaubt: $($w.Name)" }
  $seen[$h] = $w
}
foreach ($h in $locked.Keys) { if (-not $seen.ContainsKey($h)) { throw "Wheel fehlt in .\wheels: $($locked[$h])" } }
$tmpLib = "$libDir.new"
if (Test-Path -LiteralPath $tmpLib) { Remove-Item -LiteralPath $tmpLib -Recurse -Force }
New-Item -ItemType Directory -Path $tmpLib | Out-Null
foreach ($w in $seen.Values) {
  # Ein reines Wheel ist ein ZIP-Archiv mit fertigen Paketordnern; Entpacken entspricht der Installation.
  [IO.Compression.ZipFile]::ExtractToDirectory($w.FullName, $tmpLib)
  Write-Host "Installiert: $($w.Name)"
}
if (Test-Path -LiteralPath $libDir) { Remove-Item -LiteralPath $libDir -Recurse -Force }
Move-Item -LiteralPath $tmpLib -Destination $libDir
& $pyExe -I -c "import yt_dlp, bs4, soupsieve, typing_extensions, ssl, sqlite3, ctypes, tomllib; print('Module OK, yt-dlp', yt_dlp.version.__version__)"
if ($LASTEXITCODE -ne 0) { throw 'Python-Laufzeit oder Abhaengigkeiten unvollstaendig.' }

# ---- 4. FFmpeg
Step "FFmpeg (ffmpeg.exe und ffprobe.exe in .\tools)"
$ffExe = Join-Path $toolsDir 'ffmpeg.exe'
$fpExe = Join-Path $toolsDir 'ffprobe.exe'
if ((Test-Path -LiteralPath $ffExe) -and (Test-Path -LiteralPath $fpExe)) {
  Write-Host 'Vorhanden (nicht ersetzt). Fuer die mitgelieferte Version Ordner tools loeschen und setup.ps1 erneut starten.'
} else {
  $zip = Get-Verified $FF_URL $FF_SHA256 $FfmpegZip 'FFmpeg-Paket'
  if (-not (Test-Path -LiteralPath $toolsDir)) { New-Item -ItemType Directory -Path $toolsDir | Out-Null }
  $archive = [IO.Compression.ZipFile]::OpenRead($zip)
  try {
    foreach ($want in 'ffmpeg.exe', 'ffprobe.exe', 'LICENSE') {
      $entry = @($archive.Entries | Where-Object { $_.FullName -match "^[^/]+/(bin/)?$([regex]::Escape($want))$" }) | Select-Object -First 1
      if (-not $entry) { throw "FFmpeg-Paket enthaelt $want nicht." }
      $target = Join-Path $toolsDir $(if ($want -eq 'LICENSE') { 'FFMPEG-LICENSE.txt' } else { $want })
      [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $true)
    }
  } finally { $archive.Dispose() }
  Write-Host "FFmpeg $FF_VERSION entpackt nach $toolsDir"
}
if ($arch -eq 'arm64') { Write-Host 'Hinweis: FFmpeg ist ein x64-Programm und laeuft auf ARM64 per Emulation.' }

# ---- 5. Konfiguration
Step 'Konfiguration'
$cfg = Join-Path $PSScriptRoot 'config.toml'
if (Test-Path -LiteralPath $cfg) { Write-Host 'config.toml vorhanden (nicht ueberschrieben).' }
else {
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'config.default.toml') -Destination $cfg
  Write-Host 'config.toml aus config.default.toml angelegt. Bitte home_country und vpn_adapter_patterns pruefen (siehe README).'
}

# ---- 6. Aufraeumen und Abschluss
if (Test-Path -LiteralPath $dlDir) { Remove-Item -LiteralPath $dlDir -Recurse -Force }
$sys32 = Join-Path $env:SystemRoot 'System32'
foreach ($tool in 'curl.exe', 'nslookup.exe') {
  if (-not (Test-Path -LiteralPath (Join-Path $sys32 $tool))) { Write-Warning "Fehlt in System32: $tool (Windows 10 ab 1803 bringt es mit)." }
}
Write-Host ''
Write-Host 'Fertig.'
Write-Host 'Naechster Schritt (einmalig, VPN verbunden): .\qsgrab.cmd firewall apply   - legt die Netzsperre an (UAC-Abfrage).'
Write-Host 'Danach: .\qsgrab.cmd "<Adresse>"'
