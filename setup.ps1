# Quite Safe Grab für Windows – Einrichtung und Aktualisierung.
# Windows PowerShell 5.1 oder neuer, keine Administratorrechte (nur die Netzsperre fragt per UAC).
#
# Am einfachsten: Doppelklick auf "Einrichten.cmd".
#
# Erster Lauf:  lädt Python und FFmpeg (feste Adressen + SHA256), fragt Land, Internetanbieter,
#               VPN, Browser und Speicherort ab, schreibt config.toml, legt auf Wunsch die
#               Netzsperre und eine Desktop-Verknüpfung an und sagt, was man startet.
# Später:       erkennt die fertige Einrichtung, fragt nichts erneut (außer gewünscht), sucht
#               auf Wunsch eine neue Quite-Safe-Grab-Version auf GitHub, erneuert Python, FFmpeg
#               und Abhängigkeiten nur bei neuerer Vorgabe und prüft die Netzsperre.
#
# Optionen:
#   -Reconfigure     Einstellungen (config.toml) neu abfragen
#   -Defaults        keine Fragen, erkannte Vorgaben übernehmen (für Tests/Automatisierung)
#   -NoUpdateCheck   nicht auf GitHub nach einer neuen Version suchen
#   -Offline         nichts aus dem Internet laden
#   -PythonZip/-FfmpegZip <Datei>  bereits geladene Pakete verwenden (werden trotzdem geprüft)
param(
  [string]$PythonZip = '',
  [string]$FfmpegZip = '',
  [switch]$Offline,
  [switch]$Reconfigure,
  [switch]$Defaults,
  [switch]$NoUpdateCheck,
  [switch]$AfterUpdate        # intern: zweiter Lauf direkt nach dem Einspielen einer neuen Version
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Fortschrittsbalken macht Invoke-WebRequest in PS 5.1 sehr langsam
Set-Location -LiteralPath $PSScriptRoot
Add-Type -AssemblyName System.IO.Compression.FileSystem

# ---- Feste Quellen (bei einem Update: Version, Adresse und Prüfsumme gemeinsam ändern)
$PY_VERSION = '3.14.10'
$PY_TAG = 'python314'
$PY_SOURCES = @{
  'amd64' = @{ Url = "https://www.python.org/ftp/python/$PY_VERSION/python-$PY_VERSION-embed-amd64.zip"; Sha256 = '90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159' }
  'arm64' = @{ Url = "https://www.python.org/ftp/python/$PY_VERSION/python-$PY_VERSION-embed-arm64.zip"; Sha256 = 'bbe116bb1248820359cbf25127ac5c7794ea161869d83686cfbc9a45203ff836' }
}
$FF_VERSION = '9.1'
$FF_URL = "https://github.com/GyanD/codexffmpeg/releases/download/$FF_VERSION/ffmpeg-$FF_VERSION-essentials_build.zip"
$FF_SHA256 = 'b9bbbb3acece000cbeec994f856649354e52c773807841e78908374b24d658fd'
$REPO = 'wegTobi/QuiteSafeGrab'   # GitHub-Repository für die Update-Suche (Releases)

$app = $PSScriptRoot
$pyDir = Join-Path $app 'python'
$pyExe = Join-Path $pyDir 'python.exe'
$libDir = Join-Path $app 'lib'
$toolsDir = Join-Path $app 'tools'
$dlDir = Join-Path $app 'downloads'
$cfgFile = Join-Path $app 'config.toml'
$stateFile = Join-Path $app '.install.json'
$appVersion = (Get-Content -LiteralPath (Join-Path $app 'VERSION') -TotalCount 1).Trim()
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# ---------------------------------------------------------------- Hilfsfunktionen
function Step([string]$text) { Write-Host ''; Write-Host "== $text" -ForegroundColor White }
function Info([string]$text) { Write-Host "   $text" }
function Good([string]$text) { Write-Host "   $text" -ForegroundColor Green }
function Warn([string]$text) { Write-Host "   $text" -ForegroundColor Yellow }

function Ask([string]$question, [string]$default = '') {
  if ($Defaults) { return $default }
  $suffix = if ($default) { " [$default]" } else { '' }
  $answer = Read-Host "   $question$suffix"
  if ([string]::IsNullOrWhiteSpace($answer)) { return $default }
  return $answer.Trim()
}

function AskYesNo([string]$question, [bool]$default = $true) {
  if ($Defaults) { return $default }
  $hint = if ($default) { 'J/n' } else { 'j/N' }
  while ($true) {
    $a = (Read-Host "   $question ($hint)").Trim().ToLowerInvariant()
    if (-not $a) { return $default }
    if ($a -in 'j', 'ja', 'y', 'yes') { return $true }
    if ($a -in 'n', 'nein', 'no') { return $false }
    Write-Host '   Bitte j oder n eingeben.'
  }
}

function Choose([string]$question, [string[]]$options, [int]$default = 1) {
  if ($Defaults) { return $default }
  for ($i = 0; $i -lt $options.Count; $i++) { Write-Host ("     {0}) {1}" -f ($i + 1), $options[$i]) }
  while ($true) {
    $a = Read-Host "   $question [$default]"
    if (-not $a) { return $default }
    $n = 0
    if ([int]::TryParse($a, [ref]$n) -and $n -ge 1 -and $n -le $options.Count) { return $n }
    Write-Host "   Bitte eine Zahl von 1 bis $($options.Count) eingeben."
  }
}

function Get-Sha256([string]$path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }

function Get-Verified([string]$url, [string]$sha, [string]$given, [string]$what) {
  # Liefert den Pfad einer Datei mit genau dieser Prüfsumme: vorgegebene Datei, früherer Download oder neuer Download.
  if ($given) {
    $path = [IO.Path]::GetFullPath($given)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "$what nicht gefunden: $path" }
    if ((Get-Sha256 $path) -ne $sha) { throw "$what hat die falsche Prüfsumme (erwartet $sha). Datei nicht verwendet." }
    return $path
  }
  $name = [IO.Path]::GetFileName(([uri]$url).AbsolutePath)
  $path = Join-Path $dlDir $name
  if ((Test-Path -LiteralPath $path) -and ((Get-Sha256 $path) -eq $sha)) { Info "Bereits geladen und geprüft: $name"; return $path }
  if ($Offline) { throw "$what fehlt und -Offline ist gesetzt. Datei $name von $url selbst laden und mit -PythonZip/-FfmpegZip angeben." }
  if (-not (Test-Path -LiteralPath $dlDir)) { New-Item -ItemType Directory -Path $dlDir | Out-Null }
  $part = "$path.part"
  if (Test-Path -LiteralPath $part) { Remove-Item -LiteralPath $part -Force }
  Info "Lade $what von $url ..."
  Invoke-WebRequest -Uri $url -OutFile $part -UseBasicParsing -MaximumRedirection 5
  $actual = Get-Sha256 $part
  if ($actual -ne $sha) {
    Remove-Item -LiteralPath $part -Force
    throw "$what hat die falsche Prüfsumme (erwartet $sha, erhalten $actual). Download verworfen, nichts installiert."
  }
  if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
  Move-Item -LiteralPath $part -Destination $path
  Good "Prüfsumme stimmt: $name"
  return $path
}

function Read-State {
  try { return (Get-Content -LiteralPath $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}
function Write-State($data) {
  [IO.File]::WriteAllText($stateFile, ($data | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
}

function Read-LockHashes {
  $hashes = @{}
  foreach ($line in Get-Content -LiteralPath (Join-Path $app 'requirements.lock')) {
    $m = [regex]::Match($line, '^\s*([A-Za-z0-9_.\-]+)==([^\s]+)\s+--hash=sha256:([0-9a-f]{64})\s*$')
    if ($m.Success) { $hashes[$m.Groups[3].Value] = "$($m.Groups[1].Value)==$($m.Groups[2].Value)" }
    elseif ($line.Trim() -and -not $line.TrimStart().StartsWith('#')) { throw "requirements.lock: unerwartete Zeile: $line" }
  }
  if ($hashes.Count -eq 0) { throw 'requirements.lock enthält keine Pakete.' }
  return $hashes
}

function Toml-String([string]$s) { '"' + $s.Replace('\', '\\').Replace('"', '\"') + '"' }
function Toml-List([string[]]$items) { '[' + ((@($items) | Where-Object { $_ } | ForEach-Object { Toml-String $_ }) -join ', ') + ']' }
function Set-TomlKey([string]$text, [string]$key, [string]$value) {
  $rx = New-Object Text.RegularExpressions.Regex ("(?m)^\s*" + [regex]::Escape($key) + "\s*=.*$")
  if (-not $rx.IsMatch($text)) { throw "Vorlage ohne Eintrag $key" }
  return $rx.Replace($text, [Text.RegularExpressions.MatchEvaluator] { param($m) "$key = $value" }, 1)
}
function Split-List([string]$s) { @($s -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }

function Invoke-Py([string[]]$arguments) {
  # PS 5.1 macht aus Fehlerausgaben nativer Programme sonst abbrechende Fehler.
  $ErrorActionPreference = 'Continue'
  $out = & $pyExe @arguments 2>&1 | ForEach-Object { "$_" }
  return @{ Code = $LASTEXITCODE; Text = @($out) }
}

function Test-Config {
  $r = Invoke-Py @('-I', '-c', "import sys; sys.path.insert(0, r'$app'); import grab; grab.load_config(r'$cfgFile'); print('CONFIG-OK')")
  return ($r.Code -eq 0 -and ($r.Text -join '') -match 'CONFIG-OK')
}

function Get-VpnStatus {
  # Exitcode von "fw.py status": 0 = Netzsperre passt, 2 = fehlt/passt nicht/kein VPN
  return Invoke-Py @('-I', (Join-Path $app 'fw.py'), 'status')
}

# ---------------------------------------------------------------- 1. Rechner und Stand
Write-Host ''
Write-Host "Quite Safe Grab $appVersion – Einrichtung" -ForegroundColor White
Write-Host '„Quite safe“: ziemlich sicher – aber ehrlich nie hundertprozentig.'

Step 'Rechner prüfen'
if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Nur unter Windows.' }
$arch = switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { 'amd64' } 'ARM64' { 'arm64' } default { $null } }
if (-not $arch -and $env:PROCESSOR_ARCHITEW6432 -eq 'AMD64') { throw 'Bitte die 64-Bit-PowerShell verwenden (nicht "Windows PowerShell (x86)").' }
if (-not $arch) { throw "Nicht unterstützte Prozessorarchitektur: $($env:PROCESSOR_ARCHITECTURE) (nötig: 64-Bit x64 oder ARM64)." }
Info "Windows, Architektur $arch"
$state = Read-State
$installed = (Test-Path -LiteralPath $cfgFile) -and (Test-Path -LiteralPath $pyExe)
if ($installed) { Good "Vorhandene Einrichtung erkannt$(if ($state -and $state.app_version) { " (Version $($state.app_version))" }) – es wird nur aktualisiert, was nötig ist." }
else { Info 'Neue Einrichtung.' }
if (Test-Path -LiteralPath (Join-Path $app 'venv')) { Warn 'Ordner venv aus einer älteren Einrichtung gefunden – wird nicht mehr benutzt und kann gelöscht werden.' }

# ---------------------------------------------------------------- 2. Neue Version auf GitHub?
if ($installed -and -not $AfterUpdate -and -not $NoUpdateCheck -and -not $Offline) {
  Step 'Neue Version von Quite Safe Grab?'
  if (AskYesNo 'Auf GitHub nach einer neuen Version suchen?' $true) {
    $release = $null
    try {
      $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$REPO/releases/latest" -UseBasicParsing -TimeoutSec 20 `
        -Headers @{ 'User-Agent' = 'QuiteSafeGrab-Setup'; 'Accept' = 'application/vnd.github+json' }
    } catch { Warn 'Update-Suche nicht möglich (offline, Repository privat oder noch kein Release). Weiter mit der lokalen Prüfung.' }
    if ($release) {
      $latest = ($release.tag_name -replace '^[vV]', '')
      $newer = $false
      try { $newer = [version]$latest -gt [version]$appVersion } catch { Warn "Unbekanntes Versionsformat auf GitHub: $($release.tag_name)" }
      if (-not $newer) { Good "Du hast die aktuelle Version ($appVersion)." }
      else {
        Info "Neue Version verfügbar: $latest (installiert: $appVersion)."
        if (AskYesNo "Version $latest jetzt herunterladen und einspielen? (Einstellungen und Videos bleiben erhalten)" $true) {
          $zipAsset = @($release.assets | Where-Object { $_.name -match '^QuiteSafeGrab-Windows-.+\.zip$' }) | Select-Object -First 1
          $shaAsset = @($release.assets | Where-Object { $_.name -eq "$($zipAsset.name).sha256" }) | Select-Object -First 1
          if (-not $zipAsset -or -not $shaAsset) { throw 'Release ohne Paket oder Prüfsummendatei – Update abgebrochen, nichts geändert.' }
          if (-not (Test-Path -LiteralPath $dlDir)) { New-Item -ItemType Directory -Path $dlDir | Out-Null }
          $zipPath = Join-Path $dlDir $zipAsset.name
          $shaPath = "$zipPath.sha256"
          Info "Lade $($zipAsset.name) ..."
          Invoke-WebRequest -Uri $zipAsset.browser_download_url -OutFile $zipPath -UseBasicParsing -MaximumRedirection 5
          Invoke-WebRequest -Uri $shaAsset.browser_download_url -OutFile $shaPath -UseBasicParsing -MaximumRedirection 5
          $expected = ((Get-Content -LiteralPath $shaPath -TotalCount 1) -split '\s+')[0].ToLowerInvariant()
          if ($expected -notmatch '^[0-9a-f]{64}$' -or (Get-Sha256 $zipPath) -ne $expected) { throw 'Prüfsumme des Updates stimmt nicht – nichts geändert.' }
          $stage = Join-Path $app 'update.new'
          if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
          [IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $stage)
          $root = @(Get-ChildItem -LiteralPath $stage -Directory) | Select-Object -First 1
          if (-not $root -or -not (Test-Path -LiteralPath (Join-Path $root.FullName 'setup.ps1'))) { throw 'Unerwarteter Paketinhalt – nichts geändert.' }
          foreach ($f in Get-ChildItem -LiteralPath $root.FullName -Recurse -File) {
            $rel = $f.FullName.Substring($root.FullName.Length + 1)
            if ($rel -ieq 'config.toml') { continue }   # eigene Einstellungen nie überschreiben
            $target = Join-Path $app $rel
            $dir = Split-Path $target -Parent
            if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            Copy-Item -LiteralPath $f.FullName -Destination $target -Force
          }
          Remove-Item -LiteralPath $stage -Recurse -Force
          Good "Version $latest eingespielt. Starte die neue Einrichtung ..."
          $passOn = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $app 'setup.ps1'), '-AfterUpdate')
          if ($Defaults) { $passOn += '-Defaults' }
          & powershell.exe @passOn
          exit $LASTEXITCODE
        }
      }
    }
  }
}

# ---------------------------------------------------------------- 3. Python
Step "Python $PY_VERSION (eigene Laufzeit in .\python)"
$pth = Join-Path $pyDir "$PY_TAG._pth"
$needPython = $true
if (Test-Path -LiteralPath $pyDir) {
  $have = $null
  if (Test-Path -LiteralPath $pth) {
    $v = Invoke-Py @('-I', '-c', 'import platform;print(platform.python_version())')
    if ($v.Code -eq 0) { $have = $v.Text[-1].Trim() }
  }
  if ($have -eq $PY_VERSION) { Good "Aktuell: Python $have"; $needPython = $false }
  elseif (-not (Test-Path -LiteralPath $pth) -and -not (Get-ChildItem -LiteralPath $pyDir -Filter 'python3*._pth' -ErrorAction SilentlyContinue)) {
    throw 'Ordner python existiert, ist aber keine Quite-Safe-Grab-Laufzeit (z. B. aus einer alten Einrichtung). Ordner python löschen und erneut starten.'
  } else {
    Info "Vorhanden: Python $(if ($have) { $have } else { 'unbekannt' }) – Update auf $PY_VERSION."
  }
}
if ($needPython) {
  $src = $PY_SOURCES[$arch]
  $zip = Get-Verified $src.Url $src.Sha256 $PythonZip 'Python-Paket'
  $tmp = "$pyDir.new"
  if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
  [IO.Compression.ZipFile]::ExtractToDirectory($zip, $tmp)
  if (-not (Test-Path -LiteralPath (Join-Path $tmp "$PY_TAG._pth"))) { Remove-Item -LiteralPath $tmp -Recurse -Force; throw "Python-Paket ohne $PY_TAG._pth – unerwarteter Inhalt." }
  if (Test-Path -LiteralPath $pyDir) { Remove-Item -LiteralPath $pyDir -Recurse -Force }   # gleicher Pfad: Firewallregel bleibt gültig
  Move-Item -LiteralPath $tmp -Destination $pyDir
  Good "Python $PY_VERSION eingerichtet."
}
# Suchpfade: Standardbibliothek, Programmordner (..) und Abhängigkeiten (..\lib). Keine site-packages, keine Umgebungsvariablen.
[IO.File]::WriteAllText($pth, "$PY_TAG.zip`r`n.`r`n..`r`n..\lib`r`n", (New-Object Text.UTF8Encoding($false)))

# ---------------------------------------------------------------- 4. Abhängigkeiten
Step 'Python-Abhängigkeiten (nur aus .\wheels, SHA256-geprüft)'
$lockSha = Get-Sha256 (Join-Path $app 'requirements.lock')
if ($state -and $state.lock_sha256 -eq $lockSha -and (Test-Path -LiteralPath $libDir) -and -not $needPython) {
  Good 'Aktuell.'
} else {
  $locked = Read-LockHashes
  $seen = @{}
  foreach ($w in @(Get-ChildItem -LiteralPath (Join-Path $app 'wheels') -Filter '*.whl' -File)) {
    $h = Get-Sha256 $w.FullName
    if (-not $locked.ContainsKey($h)) { throw "Wheel nicht in requirements.lock (oder verändert): $($w.Name)" }
    if (-not $w.Name.EndsWith('-py3-none-any.whl')) { throw "Nur reine Python-Wheels erlaubt: $($w.Name)" }
    $seen[$h] = $w
  }
  foreach ($h in $locked.Keys) { if (-not $seen.ContainsKey($h)) { throw "Wheel fehlt in .\wheels: $($locked[$h])" } }
  $tmpLib = "$libDir.new"
  if (Test-Path -LiteralPath $tmpLib) { Remove-Item -LiteralPath $tmpLib -Recurse -Force }
  New-Item -ItemType Directory -Path $tmpLib | Out-Null
  foreach ($w in $seen.Values) { [IO.Compression.ZipFile]::ExtractToDirectory($w.FullName, $tmpLib); Info "Installiert: $($w.Name)" }
  if (Test-Path -LiteralPath $libDir) { Remove-Item -LiteralPath $libDir -Recurse -Force }
  Move-Item -LiteralPath $tmpLib -Destination $libDir
}
$check = Invoke-Py @('-I', '-c', 'import yt_dlp, bs4, soupsieve, typing_extensions, ssl, sqlite3, ctypes, tomllib; print(yt_dlp.version.__version__)')
if ($check.Code -ne 0) { throw 'Python-Laufzeit oder Abhängigkeiten unvollständig.' }
Info "yt-dlp $($check.Text[-1])"

# ---------------------------------------------------------------- 5. FFmpeg
Step "FFmpeg $FF_VERSION (.\tools)"
$ffExe = Join-Path $toolsDir 'ffmpeg.exe'
$fpExe = Join-Path $toolsDir 'ffprobe.exe'
$haveFf = $null
if ((Test-Path -LiteralPath $ffExe) -and (Test-Path -LiteralPath $fpExe)) {
  $ErrorActionPreference = 'Continue'
  $line = (& $ffExe -hide_banner -version 2>$null | Select-Object -First 1)
  $ErrorActionPreference = 'Stop'
  $m = [regex]::Match("$line", '^ffmpeg version (\d+(?:\.\d+)*)')
  if ($m.Success) { $haveFf = $m.Groups[1].Value }
}
$ffNewer = $false
if ($haveFf) { try { $ffNewer = [version]$FF_VERSION -gt [version]$haveFf } catch { $ffNewer = $false } }
if ($haveFf -and -not $ffNewer) { Good "Aktuell: FFmpeg $haveFf" }
else {
  if ($haveFf) { Info "Vorhanden: FFmpeg $haveFf – Update auf $FF_VERSION." }
  $zip = Get-Verified $FF_URL $FF_SHA256 $FfmpegZip 'FFmpeg-Paket'
  if (-not (Test-Path -LiteralPath $toolsDir)) { New-Item -ItemType Directory -Path $toolsDir | Out-Null }
  $archive = [IO.Compression.ZipFile]::OpenRead($zip)
  try {
    foreach ($want in 'ffmpeg.exe', 'ffprobe.exe', 'LICENSE') {
      $entry = @($archive.Entries | Where-Object { $_.FullName -match "^[^/]+/(bin/)?$([regex]::Escape($want))$" }) | Select-Object -First 1
      if (-not $entry) { throw "FFmpeg-Paket enthält $want nicht." }
      $target = Join-Path $toolsDir $(if ($want -eq 'LICENSE') { 'FFMPEG-LICENSE.txt' } else { $want })
      [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $true)
    }
  } finally { $archive.Dispose() }
  Good "FFmpeg $FF_VERSION eingerichtet."
  $haveFf = $FF_VERSION
}
if ($arch -eq 'arm64') { Info 'Hinweis: FFmpeg ist ein x64-Programm und läuft auf ARM64 per Emulation.' }

# ---------------------------------------------------------------- 6. Einstellungen
Step 'Einstellungen'
$askSettings = -not (Test-Path -LiteralPath $cfgFile) -or $Reconfigure
if (-not $askSettings) {
  if (Test-Config) {
    Good 'config.toml vorhanden und gültig.'
    $askSettings = AskYesNo 'Einstellungen ändern (Land, Internetanbieter, VPN, Browser, Speicherort)?' $false
  } else {
    Warn 'config.toml ist ungültig oder unvollständig (z. B. nach einem Update) – bitte neu abfragen.'
    $askSettings = $true
  }
}
if ($askSettings) {
  $template = [IO.File]::ReadAllText((Join-Path $app 'config.default.toml'))
  $text = $template

  # -- Land (Vorschlag aus den Windows-Regionseinstellungen)
  $region = [Globalization.RegionInfo]::CurrentRegion
  Info "Dein Heimatland: Taucht es bei einer Prüfung auf, läuft der Verkehr nicht über das VPN -> Abbruch."
  while ($true) {
    $cc = (Ask 'Heimatland als Zwei-Buchstaben-Kürzel (DE, AT, CH, ...)' $region.TwoLetterISORegionName).ToUpperInvariant()
    try { $r = New-Object Globalization.RegionInfo $cc; if ($cc -match '^[A-Z]{2}$') { break } } catch { }
    Write-Host '   Unbekanntes Kürzel. Beispiele: DE, AT, CH, NL, FR.'
  }
  $names = @($r.EnglishName, $r.NativeName, $r.DisplayName) | Where-Object { $_ } | Select-Object -Unique
  Good "Land: $cc ($($names -join ', '))"
  $text = Set-TomlKey $text 'home_country' (Toml-String $cc)
  $text = Set-TomlKey $text 'home_country_names' (Toml-List $names)

  # -- Internetanbieter
  $ispPresets = @{
    'DE' = @('Deutsche Telekom', 'Vodafone', '1&1', 'Telefónica', 'Unitymedia')
    'AT' = @('A1 Telekom', 'Magenta', 'Hutchison Drei', 'UPC')
    'CH' = @('Swisscom', 'Sunrise', 'Salt', 'UPC')
  }
  $preset = if ($ispPresets.ContainsKey($cc)) { $ispPresets[$cc] } else { @() }
  Info 'Internetanbieter, die nie als Ausgang erscheinen dürfen (dein eigener Anschluss).'
  if ($preset) { Info "Vorgabe für ${cc}: $($preset -join ', ')" }
  $extra = Ask 'Dein Anbieter, falls nicht dabei (mehrere mit Komma; leer = keiner)' ''
  $isps = @($preset) + (Split-List $extra) | Select-Object -Unique
  if (-not $isps) { $isps = @('Deutsche Telekom') ; Warn 'Kein Anbieter angegeben – die Heimatland-Prüfung schützt trotzdem.' }
  $text = Set-TomlKey $text 'blocked_orgs' (Toml-List $isps)

  # -- VPN
  $vpnChoice = Choose 'Welches VPN nutzt du?' @('Proton VPN (Windows-App) – empfohlen, getestet', 'Ein anderes VPN mit eigenem Netzwerkadapter')
  if ($vpnChoice -eq 1) {
    $text = Set-TomlKey $text 'vpn_adapter_patterns' (Toml-List @('Proton', 'ProTUN'))
    $text = Set-TomlKey $text 'allowed_patterns' (Toml-List @('Proton', 'M247', 'Datacamp', 'WorldStream'))
    Good 'Proton VPN eingestellt.'
  } else {
    Info 'Bitte VPN jetzt verbinden. Aktive Netzwerkadapter:'
    $adapters = @(Get-NetAdapter | Where-Object Status -eq 'Up' | Sort-Object Name)
    $labels = @($adapters | ForEach-Object { "$($_.Name)  ($($_.InterfaceDescription))" })
    if (-not $labels) { throw 'Keine aktiven Netzwerkadapter gefunden.' }
    $pick = Choose 'Welcher davon ist das VPN?' $labels 1
    $adapterName = $adapters[$pick - 1].Name
    $provider = Ask 'Name deines VPN-Anbieters, wie er bei Prüfungen erscheint (z. B. Mullvad, NordVPN; mehrere mit Komma)' ''
    if (-not $provider) { throw 'Ohne Anbieternamen kann die Ausgangsprüfung nicht arbeiten.' }
    $text = Set-TomlKey $text 'vpn_adapter_patterns' (Toml-List @([regex]::Escape($adapterName)))
    $text = Set-TomlKey $text 'allowed_patterns' (Toml-List (Split-List $provider))
    Warn 'Tipp: Die Oberfläche zeigt bei jeder Prüfung den Anbieternamen. Lautet er anders, in config.toml unter allowed_patterns ergänzen.'
  }

  # -- Browser für die Oberfläche
  $mullvad = @(
    (Join-Path $env:LOCALAPPDATA 'Mullvad\MullvadBrowser\Release\mullvadbrowser.exe'),
    (Join-Path $env:ProgramFiles 'Mullvad Browser\Browser\mullvadbrowser.exe')
  ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
  if ($mullvad) {
    Good 'Mullvad Browser gefunden – empfohlen für die Oberfläche (immer privat, keine Telemetrie).'
    $b = Choose 'Browser für die Oberfläche?' @('Mullvad Browser, sonst Edge (auto)', 'Nur Mullvad Browser (streng)', 'Immer Edge') 1
  } else {
    Info 'Mullvad Browser nicht gefunden – die Oberfläche nutzt Edge mit eigenem, leerem Profil.'
    Info 'Empfehlung: Mullvad Browser installieren (https://mullvad.net/browser); danach nimmt die Oberfläche ihn automatisch.'
    $b = 1
  }
  $text = Set-TomlKey $text 'ui_browser' (Toml-String @('auto', 'mullvad', 'edge')[$b - 1])

  # -- Speicherort
  $defaultStore = Join-Path $env:USERPROFILE 'Videos\QuiteSafeGrab'
  while ($true) {
    $store = Ask 'Wo sollen die Videos gespeichert werden?' $defaultStore
    $store = [Environment]::ExpandEnvironmentVariables($store)
    $full = [IO.Path]::GetFullPath($store)
    $inOneDrive = $false
    foreach ($od in @($env:OneDrive, $env:OneDriveConsumer, $env:OneDriveCommercial) | Where-Object { $_ }) {
      if ($full.StartsWith($od.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { $inOneDrive = $true }
    }
    if ($inOneDrive -and -not (AskYesNo 'Der Ordner liegt in OneDrive und würde synchronisiert. Trotzdem verwenden?' $false)) { continue }
    break
  }
  $text = Set-TomlKey $text 'storage' (Toml-String $full)

  if (Test-Path -LiteralPath $cfgFile) { Copy-Item -LiteralPath $cfgFile -Destination "$cfgFile.bak" -Force; Info 'Alte Einstellungen gesichert: config.toml.bak' }
  [IO.File]::WriteAllText($cfgFile, $text, (New-Object Text.UTF8Encoding($false)))
  if (-not (Test-Config)) { throw 'Die neue config.toml ist ungültig – bitte setup.ps1 -Reconfigure erneut ausführen.' }
  Good "Einstellungen gespeichert: $cfgFile"
}

# ---------------------------------------------------------------- 7. Aufräumen und Stand merken
if (Test-Path -LiteralPath $dlDir) { Remove-Item -LiteralPath $dlDir -Recurse -Force }
foreach ($tool in 'curl.exe', 'nslookup.exe') {
  if (-not (Test-Path -LiteralPath (Join-Path $env:SystemRoot "System32\$tool"))) { Warn "Fehlt in System32: $tool (Windows 10 ab 1803 bringt es mit)." }
}
Write-State ([ordered]@{ app_version = $appVersion; python = $PY_VERSION; ffmpeg = $haveFf; lock_sha256 = $lockSha
                         updated = (Get-Date).ToString('yyyy-MM-dd HH:mm') })

# ---------------------------------------------------------------- 8. Netzsperre
Step 'Netzsperre (Windows-Firewall)'
$fw = Get-VpnStatus
if ($fw.Code -eq 0) { Good 'Netzsperre vollständig und passend.' }
else {
  $vpnMissing = ($fw.Text -join "`n") -match 'KEINER aktiv|nicht pruefbar'
  Info 'Die Netzsperre fehlt oder passt nicht mehr zur VPN-Adresse. Sie wird einmalig mit Administratorrechten angelegt.'
  $doApply = AskYesNo 'Netzsperre jetzt anlegen?' (-not $Defaults)
  while ($doApply) {
    if ($vpnMissing) {
      Warn 'Dein VPN ist nicht verbunden. Bitte jetzt verbinden und dann Enter drücken (oder "s" zum Überspringen).'
      if (((Read-Host '   ').Trim().ToLowerInvariant()) -eq 's') { break }
      $fw = Get-VpnStatus
      $vpnMissing = ($fw.Text -join "`n") -match 'KEINER aktiv|nicht pruefbar'
      if ($fw.Code -eq 0) { break }
      continue
    }
    Info 'Gleich erscheint eine Windows-Abfrage (UAC): mit "Ja" bestätigen und im neuen Fenster am Ende Enter drücken.'
    (Invoke-Py @('-I', (Join-Path $app 'fw.py'), 'apply')).Text | ForEach-Object { Info $_ }
    $fw = Get-VpnStatus
    break
  }
  if ($fw.Code -eq 0) { Good 'Netzsperre vollständig und passend.' }
  else { Warn 'Netzsperre noch nicht eingerichtet. Später mit verbundenem VPN: Einrichten.cmd erneut starten (oder qsgrab.cmd firewall apply).' }
}

# ---------------------------------------------------------------- 9. Verknüpfung
$desktop = [Environment]::GetFolderPath('Desktop')
$lnk = Join-Path $desktop 'Quite Safe Grab.lnk'
if (-not (Test-Path -LiteralPath $lnk)) {
  Step 'Desktop-Verknüpfung'
  if (AskYesNo 'Verknüpfung "Quite Safe Grab" auf dem Desktop anlegen?' (-not $Defaults)) {
    $shell = New-Object -ComObject WScript.Shell
    $s = $shell.CreateShortcut($lnk)
    $s.TargetPath = Join-Path $app 'Oberflaeche-starten.cmd'
    $s.WorkingDirectory = $app
    $s.Description = 'Quite Safe Grab starten'
    $s.IconLocation = "$env:SystemRoot\System32\shell32.dll,175"
    $s.Save()
    Good "Angelegt: $lnk"
  }
}

# ---------------------------------------------------------------- Fertig
Write-Host ''
Write-Host '======================================================================' -ForegroundColor Green
Write-Host " Fertig – Quite Safe Grab $appVersion ist eingerichtet." -ForegroundColor Green
Write-Host '======================================================================' -ForegroundColor Green
Write-Host ''
Write-Host ' So startest du das Programm:' -ForegroundColor White
Write-Host '   1. VPN verbinden.'
if (Test-Path -LiteralPath $lnk) { Write-Host '   2. Doppelklick auf "Quite Safe Grab" auf dem Desktop' }
else { Write-Host '   2. Doppelklick auf diese Datei:' }
Write-Host "      $(Join-Path $app 'Oberflaeche-starten.cmd')" -ForegroundColor Cyan
Write-Host '   Das schwarze Fenster offen lassen; im Browser oben muss "Geschützt" stehen.'
Write-Host ''
Write-Host ' Updates und Einstellungen: diese Einrichtung jederzeit erneut starten (Einrichten.cmd).'
if ($fw.Code -ne 0) { Write-Host ' Achtung: Die Netzsperre fehlt noch – ohne sie startet kein Download.' -ForegroundColor Yellow }
Write-Host ''
