# Quite Safe Grab für Windows – Einrichtung und Aktualisierung.
# Windows PowerShell 5.1 oder neuer, keine Administratorrechte (nur die Netzsperre fragt per UAC).
#
# Am einfachsten: Doppelklick auf "!Einrichten.cmd".
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
# Farben: alles grau, Eingaben grün, Warnungen gelb.
function Step([string]$text) { Write-Host ''; Write-Host "== $text" -ForegroundColor Gray }
function Info([string]$text) { Write-Host "   $text" -ForegroundColor Gray }
function Warn([string]$text) { Write-Host "   $text" -ForegroundColor Yellow }
function Question([string]$number, [string]$title, [string[]]$explain) {
  # Eine Frage als eigener, abgesetzter Block.
  Write-Host ''
  Write-Host "   ----------------------------------------------------------------" -ForegroundColor DarkGray
  Write-Host "   $number  $title" -ForegroundColor Gray
  foreach ($line in $explain) { Write-Host "       $line" -ForegroundColor DarkGray }
  Write-Host ''
}
function Read-Green([string]$prompt) {
  Write-Host "   $prompt" -ForegroundColor Green -NoNewline
  return [string](Read-Host)
}

function Ask([string]$question, [string]$default = '') {
  if ($Defaults) { return $default }
  $suffix = if ($default) { " [$default]" } else { '' }
  $answer = Read-Green "$question$suffix`: "
  if ([string]::IsNullOrWhiteSpace($answer)) { return $default }
  return $answer.Trim()
}

function AskYesNo([string]$question, [bool]$default = $true) {
  if ($Defaults) { return $default }
  $hint = if ($default) { 'J/n' } else { 'j/N' }
  while ($true) {
    $a = (Read-Green "$question ($hint): ").Trim().ToLowerInvariant()
    if (-not $a) { return $default }
    if ($a -in 'j', 'ja', 'y', 'yes') { return $true }
    if ($a -in 'n', 'nein', 'no') { return $false }
    Info 'Bitte j oder n eingeben.'
  }
}

function Choose([string]$question, [string[]]$options, [int]$default = 1) {
  if ($Defaults) { return $default }
  for ($i = 0; $i -lt $options.Count; $i++) { Write-Host ("     {0}) {1}" -f ($i + 1), $options[$i]) -ForegroundColor Green }
  while ($true) {
    $a = Read-Green "$question [$default]: "
    if (-not $a) { return $default }
    $n = 0
    if ([int]::TryParse($a, [ref]$n) -and $n -ge 1 -and $n -le $options.Count) { return $n }
    Info "Bitte eine Zahl von 1 bis $($options.Count) eingeben."
  }
}

function Save-Download([string]$url, [string]$target, [string]$what) {
  # Download mit Fortschrittsanzeige (Prozent, MB, Geschwindigkeit) in einer Zeile.
  $request = [Net.HttpWebRequest]::Create($url)
  $request.UserAgent = 'QuiteSafeGrab-Setup'
  $request.AllowAutoRedirect = $true
  $request.Timeout = 30000
  $request.ReadWriteTimeout = 60000
  $response = $request.GetResponse()
  try {
    $total = $response.ContentLength
    $in = $response.GetResponseStream()
    $out = [IO.File]::Create($target)
    try {
      $buffer = New-Object byte[] 262144
      $done = 0L
      $watch = [Diagnostics.Stopwatch]::StartNew()
      $lastDraw = -1000
      $spin = '|/-\'
      $tick = 0
      while (($n = $in.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $out.Write($buffer, 0, $n)
        $done += $n
        if ($watch.ElapsedMilliseconds - $lastDraw -ge 200) {
          $lastDraw = $watch.ElapsedMilliseconds
          $mb = $done / 1MB
          $speed = if ($watch.Elapsed.TotalSeconds -gt 0) { $mb / $watch.Elapsed.TotalSeconds } else { 0 }
          if ($total -gt 0) {
            $pct = [Math]::Min(100, [int]($done * 100 / $total))
            $bar = ([string][char]0x2588 * [int]($pct / 4)) + ([string][char]0x2591 * (25 - [int]($pct / 4)))
            $line = "   $bar {0,3} %  {1:N1} / {2:N1} MB  ({3:N1} MB/s)" -f $pct, $mb, ($total / 1MB), $speed
          } else {
            $tick++
            $line = "   [{0}] {1:N1} MB geladen  ({2:N1} MB/s)" -f $spin[$tick % 4], $mb, $speed
          }
          Write-Host ("`r" + $line.PadRight(72)) -NoNewline -ForegroundColor Gray
        }
      }
      $line = "   {0} 100 %  {1:N1} MB in {2:N0} s" -f ([string][char]0x2588 * 25), ($done / 1MB), $watch.Elapsed.TotalSeconds
      Write-Host ("`r" + $line.PadRight(72)) -ForegroundColor Gray
    } finally { $out.Dispose(); $in.Dispose() }
  } finally { $response.Close() }
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
  Info "Lade $what von $url"
  Save-Download $url $part $what
  $actual = Get-Sha256 $part
  if ($actual -ne $sha) {
    Remove-Item -LiteralPath $part -Force
    throw "$what hat die falsche Prüfsumme (erwartet $sha, erhalten $actual). Download verworfen, nichts installiert."
  }
  if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
  Move-Item -LiteralPath $part -Destination $path
  Info "Prüfsumme stimmt: $name"
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

function Invoke-Py([string[]]$arguments, [string]$busy = '') {
  # Ohne $busy: direkt ausführen. Mit $busy: im Hintergrund, dabei eine sich drehende Anzeige mit Text.
  if (-not $busy) {
    $ErrorActionPreference = 'Continue'   # PS 5.1 macht aus Fehlerausgaben nativer Programme sonst abbrechende Fehler
    $out = & $pyExe @arguments 2>&1 | ForEach-Object { "$_" }
    return @{ Code = $LASTEXITCODE; Text = @($out) }
  }
  $outFile = [IO.Path]::GetTempFileName(); $errFile = [IO.Path]::GetTempFileName()
  try {
    $argLine = ($arguments | ForEach-Object { if ($_ -match '[\s"]') { '"' + $_.Replace('"', '\"') + '"' } else { $_ } }) -join ' '
    $p = Start-Process -FilePath $pyExe -ArgumentList $argLine -NoNewWindow -PassThru `
      -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    $null = $p.Handle   # Exitcode später verlässlich abrufbar
    $spin = '|/-\'; $i = 0; $watch = [Diagnostics.Stopwatch]::StartNew()
    while (-not $p.HasExited) {
      Write-Host ("`r   [{0}] {1} ({2:N0} s)" -f $spin[$i % 4], $busy, $watch.Elapsed.TotalSeconds).PadRight(78) -NoNewline -ForegroundColor Gray
      Start-Sleep -Milliseconds 150; $i++
    }
    $p.WaitForExit()
    Write-Host ("`r" + ''.PadRight(78) + "`r") -NoNewline
    $text = @(Get-Content -LiteralPath $outFile -Encoding UTF8) + @(Get-Content -LiteralPath $errFile -Encoding UTF8) | Where-Object { $_ -ne $null }
    return @{ Code = $p.ExitCode; Text = @($text) }
  } finally { Remove-Item -LiteralPath $outFile, $errFile -ErrorAction SilentlyContinue }
}

function Test-Config {
  $r = Invoke-Py @('-I', '-c', "import sys; sys.path.insert(0, r'$app'); import grab; grab.load_config(r'$cfgFile'); print('CONFIG-OK')") 'Prüfe Einstellungen'
  return ($r.Code -eq 0 -and ($r.Text -join '') -match 'CONFIG-OK')
}

function Get-VpnStatus {
  # Exitcode von "fw.py status": 0 = Netzsperre passt, 2 = fehlt/passt nicht, 3 = kein VPN
  return Invoke-Py @('-I', (Join-Path $app 'fw.py'), 'status') 'Prüfe VPN und Firewall-Regeln'
}

function Get-RuleFolders {
  # Ordner, für deren Programme es bereits Quite-Safe-Grab-Regeln gibt (Lesen braucht keine Adminrechte).
  try {
    return @(Get-NetFirewallRule -Name 'QuiteSafeGrab-*' -ErrorAction Stop | Get-NetFirewallApplicationFilter |
      ForEach-Object { $_.Program } | Where-Object { $_ -match '\\python\\python\.exe$' } |
      ForEach-Object { Split-Path (Split-Path $_ -Parent) -Parent } | Select-Object -Unique)
  } catch { return @() }
}

# ---------------------------------------------------------------- 1. Rechner und Stand
Write-Host ''
Write-Host "Quite Safe Grab $appVersion – Einrichtung" -ForegroundColor Gray
Write-Host '„Quite safe“: ziemlich sicher – aber ehrlich nie hundertprozentig.'

Step 'Rechner prüfen'
if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Nur unter Windows.' }
$arch = switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { 'amd64' } 'ARM64' { 'arm64' } default { $null } }
if (-not $arch -and $env:PROCESSOR_ARCHITEW6432 -eq 'AMD64') { throw 'Bitte die 64-Bit-PowerShell verwenden (nicht "Windows PowerShell (x86)").' }
if (-not $arch) { throw "Nicht unterstützte Prozessorarchitektur: $($env:PROCESSOR_ARCHITECTURE) (nötig: 64-Bit x64 oder ARM64)." }
Info "Windows, Architektur $arch"
$state = Read-State
$installed = (Test-Path -LiteralPath $cfgFile) -and (Test-Path -LiteralPath $pyExe)
if ($installed -and $AfterUpdate) { Info "Programmdateien auf Version $appVersion aktualisiert – jetzt wird der Rest geprüft." }
elseif ($installed) { Info "Vorhandene Einrichtung erkannt$(if ($state -and $state.app_version) { " (Version $($state.app_version))" }) – es wird nur aktualisiert, was nötig ist." }
else { Info 'Neue Einrichtung.' }
if (Test-Path -LiteralPath (Join-Path $app 'venv')) { Warn 'Ordner venv aus einer älteren Einrichtung gefunden – wird nicht mehr benutzt und kann gelöscht werden.' }

# ---------------------------------------------------------------- 2. Neue Version auf GitHub?
if ($installed -and -not $AfterUpdate -and -not $NoUpdateCheck -and -not $Offline) {
  Step 'Neue Version von Quite Safe Grab?'
  if (AskYesNo 'Auf GitHub nach einer neuen Version suchen?' $true) {
    $release = $null
    # Nur über das VPN: sonst erfährt GitHub, dass die echte Adresse Quite Safe Grab nutzt.
    # fw.py status: 0 = Netzsperre passt, 2 = VPN da, Regeln passen nicht, 3 = kein VPN
    $vpnCheck = Get-VpnStatus
    if ($vpnCheck.Code -ne 0 -and $vpnCheck.Code -ne 2) {
      Warn 'Update-Suche übersprungen: VPN nicht verbunden. Mit verbundenem VPN !Einrichten.cmd erneut starten, um nach Updates zu suchen.'
    } else {
      try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$REPO/releases/latest" -UseBasicParsing -TimeoutSec 20 `
          -Headers @{ 'User-Agent' = 'QuiteSafeGrab-Setup'; 'Accept' = 'application/vnd.github+json' }
      } catch { Warn 'Update-Suche nicht möglich (offline, Repository privat oder noch kein Release). Weiter mit der lokalen Prüfung.' }
    }
    if ($release) {
      $latest = ($release.tag_name -replace '^[vV]', '')
      $newer = $false
      try { $newer = [version]$latest -gt [version]$appVersion } catch { Warn "Unbekanntes Versionsformat auf GitHub: $($release.tag_name)" }
      if (-not $newer) { Info "Du hast die aktuelle Version ($appVersion)." }
      else {
        Info "Neue Version verfügbar: $latest (installiert: $appVersion)."
        if (AskYesNo "Version $latest jetzt herunterladen und einspielen? (Einstellungen und Videos bleiben erhalten)" $true) {
          $zipAsset = @($release.assets | Where-Object { $_.name -match '^QuiteSafeGrab-Windows-.+\.zip$' }) | Select-Object -First 1
          $shaAsset = @($release.assets | Where-Object { $_.name -eq "$($zipAsset.name).sha256" }) | Select-Object -First 1
          if (-not $zipAsset -or -not $shaAsset) { throw 'Release ohne Paket oder Prüfsummendatei – Update abgebrochen, nichts geändert.' }
          if (-not (Test-Path -LiteralPath $dlDir)) { New-Item -ItemType Directory -Path $dlDir | Out-Null }
          $zipPath = Join-Path $dlDir $zipAsset.name
          $shaPath = "$zipPath.sha256"
          Info "Lade $($zipAsset.name)"
          Save-Download $zipAsset.browser_download_url $zipPath 'Update'
          Save-Download $shaAsset.browser_download_url $shaPath 'Prüfsumme'
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
          Info "Version $latest eingespielt. Starte die neue Einrichtung ..."
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
  if ($have -eq $PY_VERSION) { Info "Aktuell: Python $have"; $needPython = $false }
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
  Info "Python $PY_VERSION eingerichtet."
}
# Suchpfade: Standardbibliothek, Programmordner (..) und Abhängigkeiten (..\lib). Keine site-packages, keine Umgebungsvariablen.
[IO.File]::WriteAllText($pth, "$PY_TAG.zip`r`n.`r`n..`r`n..\lib`r`n", (New-Object Text.UTF8Encoding($false)))

# ---------------------------------------------------------------- 4. Abhängigkeiten
Step 'Python-Abhängigkeiten (nur aus .\wheels, SHA256-geprüft)'
$lockSha = Get-Sha256 (Join-Path $app 'requirements.lock')
if ($state -and $state.lock_sha256 -eq $lockSha -and (Test-Path -LiteralPath $libDir) -and -not $needPython) {
  Info 'Aktuell.'
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
$check = Invoke-Py @('-I', '-c', 'import yt_dlp, bs4, soupsieve, typing_extensions, ssl, sqlite3, ctypes, tomllib; print(yt_dlp.version.__version__)') 'Prüfe Python-Laufzeit'
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
if ($haveFf -and -not $ffNewer) { Info "Aktuell: FFmpeg $haveFf" }
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
  Info "FFmpeg $FF_VERSION eingerichtet."
  $haveFf = $FF_VERSION
}
if ($arch -eq 'arm64') { Info 'Hinweis: FFmpeg ist ein x64-Programm und läuft auf ARM64 per Emulation.' }

# ---------------------------------------------------------------- 6. Einstellungen
Step 'Einstellungen'
$askSettings = -not (Test-Path -LiteralPath $cfgFile) -or $Reconfigure
if (-not $askSettings) {
  if (Test-Config) {
    Info 'config.toml vorhanden und gültig.'
    $askSettings = AskYesNo 'Einstellungen ändern (Heimatland, Speicherort, VPN)?' $false
  } else {
    Warn 'config.toml ist ungültig oder unvollständig (z. B. nach einem Update) – bitte neu abfragen.'
    $askSettings = $true
  }
}
if ($askSettings) {
  $text = [IO.File]::ReadAllText((Join-Path $app 'config.default.toml'))
  $templateCountry = [regex]::Match($text, '(?m)^\s*home_country\s*=\s*"([A-Z]{2})"').Groups[1].Value

  # -- Frage 1: Heimatland (Vorschlag aus den Windows-Regionseinstellungen)
  $region = [Globalization.RegionInfo]::CurrentRegion
  Question '[1/2]' 'Heimatland' @(
    'Zeigt eine Prüfung dieses Land an, läuft der Verkehr nicht über das VPN – dann wird abgebrochen.',
    "Vorschlag aus deinen Windows-Einstellungen: $($region.TwoLetterISORegionName) ($($region.NativeName)). Enter übernimmt ihn.")
  while ($true) {
    $cc = (Ask 'Zwei-Buchstaben-Kürzel (z. B. DE, AT, CH)' $region.TwoLetterISORegionName).ToUpperInvariant()
    $r = $null
    if ($cc -match '^[A-Z]{2}$') { try { $r = New-Object Globalization.RegionInfo $cc } catch { $r = $null } }
    if ($r) { break }
    Info 'Unbekanntes Kürzel. Beispiele: DE, AT, CH, NL, FR.'
  }
  $names = @($r.EnglishName, $r.NativeName, $r.DisplayName) | Where-Object { $_ } | Select-Object -Unique
  Info "Heimatland: $cc ($($names -join ', '))"
  $text = Set-TomlKey $text 'home_country' (Toml-String $cc)
  $text = Set-TomlKey $text 'home_country_names' (Toml-List $names)

  # Internetanbieter: keine Frage. Zusatzsicherung mit bekannten Anbietern des Landes (DE/AT/CH);
  # den eigentlichen Schutz trägt die Heimatland-Prüfung. Automatisch erkennen ginge nur über
  # einen Geodienst mit der echten Adresse (ohne VPN) - das wäre ein Datenleck.
  # Für das Land der Vorlage (config.default.toml) gelten deren Anbieter; sonst Vorgabe je Land oder leer.
  $ispPresets = @{
    'AT' = @('A1 Telekom', 'Magenta', 'Hutchison Drei', 'UPC')
    'CH' = @('Swisscom', 'Sunrise', 'Salt', 'UPC')
  }
  if ($cc -ne $templateCountry) {
    $isps = if ($ispPresets.ContainsKey($cc)) { $ispPresets[$cc] } else { @() }
    $text = Set-TomlKey $text 'blocked_orgs' (Toml-List $isps)
  }

  # -- Frage 2: Speicherort
  $defaultStore = Join-Path $env:USERPROFILE 'Videos\QuiteSafeGrab'
  Question '[2/2]' 'Speicherort für die Videos' @(
    'Nicht in OneDrive (würde synchronisiert). Enter übernimmt den Vorschlag.')
  while ($true) {
    $store = [Environment]::ExpandEnvironmentVariables((Ask 'Ordner' $defaultStore))
    try { $full = [IO.Path]::GetFullPath($store) } catch { Info 'Ungültiger Pfad.'; continue }
    $inOneDrive = $false
    foreach ($od in @($env:OneDrive, $env:OneDriveConsumer, $env:OneDriveCommercial) | Where-Object { $_ }) {
      if ($full.StartsWith($od.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { $inOneDrive = $true }
    }
    if ($inOneDrive -and -not (AskYesNo 'Der Ordner liegt in OneDrive und würde synchronisiert. Trotzdem verwenden?' $false)) { continue }
    break
  }
  Info "Speicherort: $full"
  $text = Set-TomlKey $text 'storage' (Toml-String $full)

  # -- VPN: Proton wird erkannt, nur sonst wird gefragt
  $protonInstalled = (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'Proton\VPN')) -or
    [bool](Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
           Where-Object { $_.DisplayName -match '^Proton ?VPN' })
  # Die Vorlage enthält bereits die Proton-Werte (vpn_adapter_patterns, allowed_patterns).
  if ($protonInstalled) {
    Info 'VPN: Proton VPN erkannt.'
  } else {
    Question '[+]' 'Kein Proton VPN gefunden' @(
      'Quite Safe Grab lädt nur über ein aktives VPN. Empfohlen und getestet ist Proton VPN (https://protonvpn.com).',
      'Ein anderes VPN geht auch, wenn es einen eigenen Netzwerkadapter hat (z. B. Mullvad, NordVPN mit WireGuard/OpenVPN).')
    $vpnChoice = Choose 'Wie weiter?' @('Ich installiere Proton VPN später (Einstellungen für Proton übernehmen)', 'Ich nutze ein anderes VPN – es ist jetzt verbunden') 1
    if ($vpnChoice -eq 1) {
      Warn 'Proton-Einstellungen übernommen. Nach der Installation von Proton: !Einrichten.cmd erneut starten (für die Netzsperre).'
    } else {
      $adapters = @(Get-NetAdapter | Where-Object Status -eq 'Up' | Sort-Object Name)
      $labels = @($adapters | ForEach-Object { "$($_.Name)  ($($_.InterfaceDescription))" })
      if (-not $labels) { throw 'Keine aktiven Netzwerkadapter gefunden.' }
      Info 'Aktive Netzwerkadapter:'
      $pick = Choose 'Welcher davon ist das VPN?' $labels 1
      $adapterName = $adapters[$pick - 1].Name
      $provider = Ask 'Name des VPN-Anbieters (z. B. Mullvad, NordVPN; mehrere mit Komma)' ''
      if (-not $provider) { throw 'Ohne Anbieternamen kann die Ausgangsprüfung nicht arbeiten.' }
      $text = Set-TomlKey $text 'vpn_adapter_patterns' (Toml-List @([regex]::Escape($adapterName)))
      $text = Set-TomlKey $text 'allowed_patterns' (Toml-List (Split-List $provider))
      Warn 'Tipp: Die Oberfläche zeigt bei jeder Prüfung den Anbieternamen. Lautet er anders, in config.toml unter allowed_patterns ergänzen.'
    }
  }

  # Browser: keine Frage. Mullvad Browser, wenn vorhanden, sonst Edge (ui_browser = "auto").
  $text = Set-TomlKey $text 'ui_browser' (Toml-String 'auto')
  $mullvad = @(
    (Join-Path $env:LOCALAPPDATA 'Mullvad\MullvadBrowser\Release\mullvadbrowser.exe'),
    (Join-Path $env:ProgramFiles 'Mullvad Browser\Browser\mullvadbrowser.exe')
  ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
  if ($mullvad) { Info 'Browser für die Oberfläche: Mullvad Browser.' }
  else { Info 'Browser für die Oberfläche: Edge (eigenes, leeres Profil). Tipp: Mit installiertem Mullvad Browser (https://mullvad.net/browser) nimmt Quite Safe Grab automatisch diesen.' }

  if (Test-Path -LiteralPath $cfgFile) { Copy-Item -LiteralPath $cfgFile -Destination "$cfgFile.bak" -Force; Info 'Alte Einstellungen gesichert: config.toml.bak' }
  [IO.File]::WriteAllText($cfgFile, $text, (New-Object Text.UTF8Encoding($false)))
  if (-not (Test-Config)) { throw 'Die neue config.toml ist ungültig – bitte !Einrichten.cmd erneut starten.' }
  Write-Host ''
  Info "Einstellungen gespeichert: $cfgFile"
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
Info 'Firewall-Regeln erlauben den Programmen von Quite Safe Grab nur den Weg über das VPN.'
$fw = Get-VpnStatus
function Test-VpnDown($status) { $status.Code -eq 3 }   # fw.py status: 3 = kein VPN verbunden
if ($fw.Code -ne 0 -and (Test-VpnDown $fw)) {
  Warn 'Dein VPN ist nicht verbunden – deshalb kann die Netzsperre gerade nicht geprüft werden.'
  if (-not $Defaults) {
    while ($true) {
      $a = (Read-Green 'Bitte VPN verbinden und Enter drücken (oder "s" zum Überspringen): ').Trim().ToLowerInvariant()
      if ($a -eq 's') { break }
      $fw = Get-VpnStatus
      if (-not (Test-VpnDown $fw)) { break }
      Warn 'Noch kein VPN erkannt.'
    }
  }
}
if ($fw.Code -eq 0) { Info 'Netzsperre vollständig und passend.' }
elseif (Test-VpnDown $fw) { Warn 'Übersprungen. Später mit verbundenem VPN: !Einrichten.cmd erneut starten.' }
else {
  Info 'Die Netzsperre fehlt für diesen Ordner oder passt nicht mehr zur VPN-Adresse.'
  $others = @(Get-RuleFolders | Where-Object { $_ -and ($_.TrimEnd('\') -ne $app.TrimEnd('\')) })
  if ($others) {
    Warn 'Achtung: Die Netzsperre gilt bisher für eine andere Quite-Safe-Grab-Installation:'
    foreach ($o in $others) { Warn "   $o" }
    Warn 'Windows kennt nur EINE Netzsperre für Quite Safe Grab. Legst du sie hier an, startet die andere'
    Warn 'Installation keine Downloads mehr (Sicherheitsabbruch), bis dort die Einrichtung erneut läuft.'
  }
  Write-Host ''
  Info 'So läuft es ab:'
  Info '  1. Windows fragt "Möchten Sie zulassen, dass ... Änderungen vornimmt?" -> auf "Ja" klicken.'
  Info '  2. Ein zweites schwarzes Fenster öffnet sich. Es braucht einige Sekunden – bitte nichts drücken.'
  Info '  3. Am Ende steht dort FERTIG, und das Fenster schließt sich nach ein paar Sekunden von selbst.'
  Info '     (Steht dort FEHLER, bleibt es offen – dann die Meldung lesen und Enter drücken.)'
  if (AskYesNo 'Netzsperre jetzt anlegen?' (-not $Defaults)) {
    $r = Invoke-Py @('-I', (Join-Path $app 'fw.py'), 'apply') 'Warte auf das zweite Fenster (Administrator)'
    if ($r.Code -ne 0 -and (($r.Text -join "`n") -match 'abgebrochen')) { Warn 'Die Windows-Abfrage wurde abgelehnt oder geschlossen.' }
    $fw = Get-VpnStatus
  }
  if ($fw.Code -eq 0) { Info 'Netzsperre vollständig und passend.' }
  else { Warn 'Netzsperre noch nicht eingerichtet – ohne sie startet kein Download. Später: !Einrichten.cmd erneut starten.' }
}

# ---------------------------------------------------------------- 9. Verknüpfung
$desktop = [Environment]::GetFolderPath('Desktop')
$lnk = Join-Path $desktop 'Quite Safe Grab.lnk'
if (Test-Path -LiteralPath $lnk) {
  # Vorhandene Verknüpfung auf diesen Ordner: Logo aktuell halten.
  $shell = New-Object -ComObject WScript.Shell
  $s = $shell.CreateShortcut($lnk)
  if ($s.TargetPath -ieq (Join-Path $app 'Oberflaeche-starten.cmd') -and (Test-Path -LiteralPath (Join-Path $app 'logo.ico'))) {
    $s.IconLocation = "$(Join-Path $app 'logo.ico'),0"; $s.Save()
  }
} else {
  Step 'Desktop-Verknüpfung'
  if (AskYesNo 'Verknüpfung "Quite Safe Grab" auf dem Desktop anlegen?' (-not $Defaults)) {
    $shell = New-Object -ComObject WScript.Shell
    $s = $shell.CreateShortcut($lnk)
    $s.TargetPath = Join-Path $app 'Oberflaeche-starten.cmd'
    $s.WorkingDirectory = $app
    $s.Description = 'Quite Safe Grab starten'
    $s.IconLocation = "$(Join-Path $app 'logo.ico'),0"
    $s.Save()
    Info "Angelegt: $lnk"
  }
}

# ---------------------------------------------------------------- Fertig
Write-Host ''
Write-Host '======================================================================' -ForegroundColor Gray
Write-Host " Fertig – Quite Safe Grab $appVersion ist eingerichtet." -ForegroundColor Gray
Write-Host '======================================================================' -ForegroundColor Gray
Write-Host ''
Write-Host ' So startest du das Programm:' -ForegroundColor Gray
Write-Host '   1. VPN verbinden.'
if (Test-Path -LiteralPath $lnk) { Write-Host '   2. Doppelklick auf "Quite Safe Grab" auf dem Desktop' }
else { Write-Host '   2. Doppelklick auf diese Datei:' }
Write-Host "      $(Join-Path $app 'Oberflaeche-starten.cmd')" -ForegroundColor Gray
Write-Host '   Das schwarze Fenster offen lassen; im Browser oben muss "Geschützt" stehen.'
Write-Host ''
Write-Host ' Updates und Einstellungen: diese Einrichtung jederzeit erneut starten (!Einrichten.cmd).'
if ($fw.Code -ne 0) { Write-Host ' Achtung: Die Netzsperre fehlt noch – ohne sie startet kein Download.' -ForegroundColor Yellow }
Write-Host ''
