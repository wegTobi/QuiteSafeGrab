# Kleine Windows-Haertungen fuer Quite Safe Grab. Ohne Schalter nur ein BERICHT (aendert nichts).
#   powershell -ExecutionPolicy Bypass -File .\haertung.ps1
#   powershell -ExecutionPolicy Bypass -File .\haertung.ps1 -Storage D:\Quite Safe GrabDaten
#   powershell -ExecutionPolicy Bypass -File .\haertung.ps1 -DisableShellHistory -DisableRecentFiles
# Keine Adminrechte noetig. Jede Aenderung ist einzeln zuschaltbar und wird angezeigt.
param(
  [string]$Storage = '',
  [switch]$DisableShellHistory,
  [switch]$DisableRecentFiles
)
$ErrorActionPreference = 'Stop'
$config = Join-Path $PSScriptRoot 'config.toml'
if (-not (Test-Path -LiteralPath $config)) { throw 'config.toml fehlt.' }

function Expand-Storage([string]$p) { if ($p -eq '~' -or $p.StartsWith('~/') -or $p.StartsWith('~\')) { $p = $env:USERPROFILE + $p.Substring(1) }; [IO.Path]::GetFullPath($p) }
function Under-OneDrive([string]$path) {
  foreach ($root in @($env:OneDrive, $env:OneDriveConsumer, $env:OneDriveCommercial) | Where-Object { $_ }) {
    if ($path.TrimEnd('\').StartsWith($root.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { return $true }
  }
  return ($path -match '\\OneDrive[^\\]*\\')
}
function Current-Storage {
  $m = [regex]::Match([IO.File]::ReadAllText($config), '(?m)^\s*storage\s*=\s*(?:"([^"]*)"|''([^'']*)'')')
  if (-not $m.Success) { throw 'storage in config.toml nicht lesbar.' }
  if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
}
function Has-Reparse([string]$path) {
  $p = $path
  while ($p -and (Test-Path -LiteralPath $p)) {
    if ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { return $true }
    $p = Split-Path $p -Parent
  }
  return $false
}

# ---- Aenderungen
if ($Storage) {
  $target = Expand-Storage $Storage
  if (Under-OneDrive $target) { throw "Speicherort liegt in OneDrive ($target) - wuerde synchronisiert. Anderen Ordner waehlen." }
  if (-not (Test-Path -LiteralPath $target)) { New-Item -ItemType Directory -Path $target | Out-Null }
  if (Has-Reparse $target) { throw "Pfad enthaelt eine Verknuepfung/Junction/Cloud-Platzhalter: $target" }
  $item = Get-Item -LiteralPath $target -Force
  $item.Attributes = $item.Attributes -bor [IO.FileAttributes]::NotContentIndexed   # nicht in den Windows-Suchindex (erbt auf neue Dateien)
  & attrib.exe +I $target /S /D | Out-Null
  $text = [IO.File]::ReadAllText($config)
  $line = "storage = '" + $target.Replace("'", '') + "'"
  $new = [regex]::Replace($text, '(?m)^\s*storage\s*=.*$', [Text.RegularExpressions.MatchEvaluator]{ param($m) $line }, 1)
  [IO.File]::WriteAllText($config, $new, (New-Object Text.UTF8Encoding($true)))
  Write-Host "Speicherort gesetzt: $target (nicht indiziert). config.toml aktualisiert."
}
if ($DisableShellHistory) {
  $profilePath = $PROFILE.CurrentUserCurrentHost
  $marker = '# Quite Safe Grab: keine PowerShell-Befehlshistorie speichern'
  if (-not (Test-Path -LiteralPath $profilePath)) { New-Item -ItemType File -Path $profilePath -Force | Out-Null }
  if (-not (Select-String -LiteralPath $profilePath -SimpleMatch $marker -Quiet)) {
    Add-Content -LiteralPath $profilePath -Value ("`r`n" + $marker + "`r`nSet-PSReadLineOption -HistorySaveStyle SaveNothing")
    Write-Host "PowerShell-Profil ergaenzt: $profilePath (gilt fuer neue Fenster; bestehende Historie bleibt, ggf. selbst loeschen)."
  } else { Write-Host 'PowerShell-Verlauf ist bereits abgeschaltet.' }
}
if ($DisableRecentFiles) {
  $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer'
  Set-ItemProperty -Path $key -Name ShowRecent -Value 0 -Type DWord
  Set-ItemProperty -Path $key -Name ShowFrequent -Value 0 -Type DWord
  Write-Host 'Explorer: "Zuletzt verwendete/haeufige Dateien" abgeschaltet (Neustart des Explorers/Anmeldung noetig).'
}

# ---- Bericht
Write-Host ''
Write-Host '=== Bericht ==='
$stor = Expand-Storage (Current-Storage)
Write-Host "Speicherort: $stor"
Write-Host ("  in OneDrive:        " + $(if (Under-OneDrive $stor) { 'JA  <- wird synchronisiert; -Storage <Ordner> verwenden' } else { 'nein' }))
Write-Host ("  Verknuepfung im Pfad: " + $(if (Has-Reparse $stor) { 'JA  <- Quite Safe Grab verweigert den Start' } else { 'nein' }))
if (Test-Path -LiteralPath $stor) {
  $ni = ((Get-Item -LiteralPath $stor -Force).Attributes -band [IO.FileAttributes]::NotContentIndexed) -ne 0
  Write-Host ("  vom Suchindex ausgenommen: " + $(if ($ni) { 'ja' } else { 'NEIN  <- Dateinamen landen im Windows-Suchindex; -Storage <Ordner> setzt das' }))
} else { Write-Host '  (Ordner existiert noch nicht)' }
try {
  $h = Get-PSReadLineOption
  Write-Host ("PowerShell-Verlauf: " + $h.HistorySaveStyle + $(if ($h.HistorySaveStyle -ne 'SaveNothing') { '  <- Befehle mit URLs werden gespeichert; -DisableShellHistory' } else { '' }))
} catch { Write-Host 'PowerShell-Verlauf: nicht feststellbar' }
$r = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' -ErrorAction SilentlyContinue
Write-Host ("Zuletzt verwendete Dateien (Explorer): " + $(if ($r -and $r.ShowRecent -eq 0) { 'aus' } else { 'an  <- -DisableRecentFiles' }))
$own = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'python') -Filter 'python*._pth' -File -ErrorAction SilentlyContinue).Count -gt 0
Write-Host ("Eigene Python-Laufzeit (.\python) fuer die Firewallregeln: " + $(if ($own) { 'ja' } else { 'NEIN - setup.ps1 noch nicht ausgefuehrt' }))
Write-Host 'Nur manuell moeglich: WLAN -> Einstellungen -> "Zufaellige Hardwareadressen" fuer dein Netz einschalten (Windows 10/11).'
Write-Host 'Nicht aenderbar: Defender/SmartScreen-Abfragen, Windows-Diagnosedaten, Prefetch (Systemweit).'
