# Quite Safe Grab – Technische Details

Ausführliche Beschreibung für Fortgeschrittene. Die Kurzanleitung steht in der [README](../README.md).

*Quite safe* – ziemlich sicher, aber ehrlich nie hundertprozentig. (Und möglichst *quiet*.)

Archivwerkzeug für Videos, die **gemeinfrei oder frei lizenziert** sind (zum Beispiel Creative Commons, Open Movies, eigene Aufnahmen). Quite Safe Grab lädt einzelne Videos von direkten Adressen, HLS-Streams und VOE-Links und speichert sie unverändert (verlustfreier Remux mit FFmpeg).

Der Download läuft **nur, wenn dein VPN nachweislich aktiv ist**. Vor jedem Schritt prüft Quite Safe Grab Adapter, Firewallregeln, öffentliche IP, IPv6 und DNS-Ausgang. Ist etwas unklar, bricht es ab (Exitcode 2), statt ungeschützt weiterzumachen.

> **Bitte beachten:** Lade nur Inhalte, die du laden darfst. Quite Safe Grab umgeht keinen Kopierschutz und keine Anmeldung. Anonymität ist **nicht** garantiert: Metadaten, Wasserzeichen und Kennungen in Bild und Ton bleiben erhalten, und Windows hinterlässt lokale Spuren.

## Voraussetzungen

- Windows 10 (ab 1803) oder Windows 11, 64 Bit (x64 oder ARM64)
- Ein VPN-Client mit eigenem Netzwerkadapter. Getestet mit dem **Proton VPN**-Windows-Client (Adapter `ProTUN`). Andere VPNs sind möglich, müssen aber in `config.toml` eingetragen werden (siehe unten).
- Etwa 400 MB freier Speicher und eine Internetverbindung für die Einrichtung.
- Ein bereits installiertes Python wird **nicht** gebraucht und nicht verändert.

## Einrichtung (einmalig, ca. 5 Minuten)

1. **ZIP herunterladen** von der Release-Seite (`QuiteSafeGrab-Windows-x.y.z.zip`) und in einen Ordner entpacken, der **nicht** in OneDrive liegt (z. B. `C:\Tools\QuiteSafeGrab`).
   Vorher: Rechtsklick auf die ZIP → Eigenschaften → unten „Zulassen“ anhaken → OK. Sonst warnt Windows bei jedem Skript.
2. **VPN verbinden** (Kill-Switch im VPN-Client einschalten wird empfohlen).
3. **Doppelklick auf `!Einrichten.cmd`.** Die Einrichtung
   - lädt eine eigene Python-Laufzeit (`python\`, ca. 10 MB) und FFmpeg (`tools\`, ca. 114 MB) – nur von fest eingetragenen Adressen (python.org, GitHub/gyan.dev), jede Datei per SHA256 geprüft; ein vorhandenes Python wird weder benutzt noch verändert,
   - fragt nur zwei Dinge: dein **Heimatland** (Vorschlag aus den Windows-Regionseinstellungen) und den **Speicherort**. Proton VPN erkennt sie selbst (sonst Auswahl des VPN-Adapters), den Browser wählt sie automatisch (Mullvad, sonst Edge), Internetanbieter kommen aus einer Ländervorgabe (DE/AT/CH; die Heimatland-Prüfung trägt den Schutz). Daraus entsteht `config.toml`,
   - legt auf Wunsch die **Netzsperre** an (Windows fragt einmal nach Administratorrechten: „Ja“; das zweite Fenster zeigt FERTIG und schließt sich selbst) und eine **Desktop-Verknüpfung** mit Logo,
   - sagt am Ende, welche Datei du startest.

Die Einrichtung kann **jederzeit erneut** gestartet werden: Sie erkennt die fertige Einrichtung, fragt nichts erneut (außer du möchtest Einstellungen ändern), sucht auf Wunsch eine **neue Version auf GitHub** und spielt sie ein, erneuert Python, FFmpeg und Abhängigkeiten nur bei Bedarf und prüft die Netzsperre.

Ohne Doppelklick geht es auch in PowerShell: `powershell -ExecutionPolicy Bypass -File .\setup.ps1` (Optionen: `-Reconfigure` Einstellungen neu abfragen, `-NoUpdateCheck`, `-Offline`, `-Defaults` ohne Fragen).

## Benutzung

### Oberfläche (empfohlen)

Doppelklick auf **`Oberflaeche-starten.cmd`** (oder `.\qsgrab.cmd ui`). Es öffnet sich ein Browserfenster mit:

- **Sicherheit:** Ampel für VPN-Adapter, Netzsperre, Selbsttest, IPv4-Ausgang, IPv6 und DNS-Ausgang, jeweils mit Ergebnis und Uhrzeit. „Jetzt prüfen“ testet alles ohne Download. Vor und nach jedem Download prüft Quite Safe Grab ohnehin automatisch.
- **Links hinzufügen:** ein Link pro Zeile, optional ein eigener Dateiname. Quite Safe Grab sucht sofort die **Titel aller neuen Links** (mit denselben Sicherheitsprüfungen wie vor einem Download) und zeigt sie in der Warteschlange an; nicht auflösbare Links werden schon jetzt als Fehler markiert. Danach „Start“ – wer schon während der Titelsuche „Start“ drückt, startet die Downloads direkt im Anschluss.
- **Aktuell:** Titel, Phase (Prüfen → Probe → Auflösen → Download → Remux → Abschluss), Fortschritt, Geschwindigkeit, Restzeit, Größe.
- **Warteschlange**, **fertige Videos** (mit „Ordner öffnen“) und ein **Protokoll**.

Beim Start prüft Quite Safe Grab einmal automatisch alles, die Ampel ist also sofort aktuell. Das schwarze Konsolenfenster offen lassen; schließen beendet Quite Safe Grab. Schließt du das QuiteSafeGrab-Browserfenster, beendet sich Quite Safe Grab nach wenigen Sekunden selbst (nie während eines Downloads). Öffne die Oberfläche immer über die Startdatei: Jeder Start hat eine neue Adresse und einen neuen Schlüssel, alte Lesezeichen funktionieren nicht.

**Welcher Browser?** Einstellung `ui_browser` in `config.toml`:

| Wert | Verhalten |
|---|---|
| `"auto"` (Vorgabe) | [Mullvad Browser](https://mullvad.net/browser), wenn installiert, sonst Microsoft Edge |
| `"mullvad"` | nur Mullvad Browser – ohne ihn startet die Oberfläche nicht |
| `"edge"` | immer Edge |

Empfohlen ist der Mullvad Browser: immer privat, keine Telemetrie, keine Synchronisierung. Quite Safe Grab startet ihn mit einem **eigenen Profil** im Ordner `.ui-profile\mullvad`, getrennt von deinem normalen Mullvad-Fenster. Beim ersten Mal richtet Quite Safe Grab dieses Profil kurz unsichtbar ein (Mullvad installiert dabei seine Erweiterungen); danach bleibt es bestehen, enthält aber keinen Verlauf, weil Mullvad immer privat surft. Edge wird als eigenes App-Fenster mit **eigenem, leerem Profil** gestartet (ohne Anmeldung, Sync und Erweiterungen); dieses Profil löscht Quite Safe Grab bei jedem Start und Ende. Dein normaler Browser bleibt in beiden Fällen unberührt.

Bleibt die Seite leer bzw. „Nicht geprüft“ und erscheint ein Hinweis zu JavaScript: Im QuiteSafeGrab-Mullvad-Fenster über das Schild-Symbol die Sicherheitsstufe „Standard“ wählen. Die Seite lädt nur Dateien von diesem PC.

**Datenschutz der Oberfläche:** Sie läuft nur auf diesem PC (`127.0.0.1`, zufälliger Port) und ist im Netz nicht erreichbar. Jede Anfrage braucht einen zufälligen Schlüssel, der bei jedem Start neu entsteht; fremde Webseiten im selben Browser können sie nicht steuern. Die Seite lädt nichts von außen (keine Schriften, Skripte oder Bilder aus dem Internet). Video-Adressen werden nur als Text angezeigt, nie als anklickbarer Link. Links und Warteschlange liegen nur im Arbeitsspeicher; gespeichert werden nur die letzten Prüfergebnisse (ohne Links) in `.state\ui-checks.json` im Speicherort. Downloads und alle Sicherheitsprüfungen laufen unverändert im selben Programm wie auf der Kommandozeile.

### Kommandozeile

```powershell
.\qsgrab.cmd "https://beispiel.example/video.mp4"
.\qsgrab.cmd "https://beispiel.example/video.mp4" "Mein Dateiname"
.\qsgrab.cmd                      # ohne Adresse: interaktive Warteschlange
.\qsgrab.cmd --check-only         # nur alle Sicherheitsprüfungen, kein Download
Get-Content links.txt | .\qsgrab.cmd --preview   # nur Titel ermitteln (ein Link pro Zeile), kein Download
```

Adressen immer in Anführungszeichen setzen. Fertige Videos liegen in `%USERPROFILE%\Videos\QuiteSafeGrab\finished\` (änderbar über `storage`).

Exitcodes: 0 Erfolg · 1 Eingabe/Konfiguration/Abbruch · 2 Netzwerk/VPN (Sicherheitsabbruch) · 4 Download/Auflösung · 5 Remux/Metadaten.

## Häufige Meldungen

| Meldung | Bedeutung und Abhilfe |
|---|---|
| `VPN_ADAPTER_MISSING` | VPN ist nicht verbunden. Verbinden und erneut starten. |
| `FIREWALL_RULES_MISSING` | Die VPN-Adresse hat sich geändert (anderer Server-Typ/Protokoll) oder die Regeln fehlen. `.\qsgrab.cmd firewall apply` erneut ausführen. |
| `FIREWALL_SELFTEST_FAILED` | Eine Verbindung an der Firewall vorbei war möglich. `.\qsgrab.cmd firewall apply` erneut; bleibt es so, nicht weiter benutzen und ein Issue anlegen. |
| `DNS_GEO_FAILED` / `TUNNEL_STATUS_UNAVAILABLE` | Die Geodienste (am.i.mullvad.net, ipapi.co, ipinfo.io) haben nicht geantwortet oder drosseln. Ein paar Minuten warten oder einen anderen VPN-Server wählen. |
| `VOE_RESOLUTION_FAILED` | Video gelöscht, oder VOE leitet auf eine neue Spiegel-Domain um. Domain in `voe_hosts` in `config.toml` ergänzen (siehe unten). |
| `HOME_COUNTRY_DETECTED` / `BLOCKED_ORG` | Verkehr läuft sichtbar nicht über das VPN. Nicht weiter benutzen, VPN prüfen. |

**Neuen VOE-Host finden:** Den VOE-Link im Browser öffnen und nachsehen, auf welche Domain die Adresszeile springt. Diese Domain (ohne `https://` und Pfad) in die Liste `voe_hosts` aufnehmen.

## Wie die Netzsperre funktioniert

Für die Programme des Downloaders legt `qsgrab.cmd firewall apply` je eine ausgehende **Blockregel** in der Windows-Firewall an: `python\python.exe` (die eigene Laufzeit von Quite Safe Grab), `tools\ffmpeg.exe`, `tools\ffprobe.exe` sowie `curl.exe` und `nslookup.exe` aus `System32`. Gesperrt ist jeder Verkehr, dessen Quelladresse weder die VPN-Adresse noch Loopback ist; IPv6 ist für diese Programme ganz gesperrt. Fällt das VPN aus, scheitert jede Verbindung sofort an der Firewall.

Vor jedem Prüfpunkt kontrolliert Quite Safe Grab Adapter, Regeln und Firewall-Profile. Beim ersten Start je VPN-Adresse folgt ein Selbsttest: Von jeder anderen lokalen Adresse aus muss ein Verbindungsversuch scheitern (blockiert, oder es gibt von dort keinen Weg ins Netz).

**Welche Dienste Quite Safe Grab fragt:** Die öffentliche IP und ihr Land/Anbieter kommen von `am.i.mullvad.net` (ersatzweise `ipapi.co`). Den DNS-Ausgang ermittelt eine DNS-Abfrage an Google (`o-o.myaddr.l.google.com`); Land/Anbieter dieser Adresse kommen von `ipapi.co`, bei Drosselung ersatzweise von `ipinfo.io`. Alle Abfragen laufen über das VPN, und keiner dieser Dienste erfährt, was du herunterlädst.

Wichtige Hinweise:

- **Nebenwirkung:** `curl.exe` und `nslookup.exe` sind Windows-Programme. Ohne VPN funktionieren sie auch außerhalb von Quite Safe Grab nicht mehr (mit VPN normal). Python-Programme außerhalb von Quite Safe Grab sind nicht betroffen.
- Die Regeln bleiben nach dem Beenden aktiv (wie ein Kill-Switch). Entfernen: `.\qsgrab.cmd firewall remove`. Status ohne Adminrechte: `.\qsgrab.cmd firewall status`.
- `firewall_enforce = false` schaltet die Erzwingung ab (nur noch Adapterprüfung, mit Warnung bei jedem Start). Nicht empfohlen.
- Gesperrt werden Programme, kein ganzer Netzbereich. Wer Administratorrechte hat, kann die Regeln ändern; gegen einen kompromittierten PC schützt das nicht.

## Mehr Privatsphäre auf dem PC (optional)

```powershell
powershell -ExecutionPolicy Bypass -File .\haertung.ps1                       # nur Bericht
powershell -ExecutionPolicy Bypass -File .\haertung.ps1 -Storage "D:\Quite Safe Grab" -DisableShellHistory -DisableRecentFiles
```

`-Storage` setzt einen Speicherort außerhalb von OneDrive und nimmt ihn aus dem Windows-Suchindex. `-DisableShellHistory` schaltet den PowerShell-Verlauf ab (neue Fenster). `-DisableRecentFiles` schaltet „Zuletzt verwendet/Häufig“ im Explorer ab. Nur von Hand möglich: Einstellungen → WLAN → „Zufällige Hardwareadressen“.

## Update und Deinstallation

- **Update:** `!Einrichten.cmd` erneut starten und die Frage nach einer neuen Version mit „j“ beantworten. Die neue Version (geprüft per SHA256 aus dem Release) wird in denselben Ordner eingespielt; `config.toml` und deine Videos bleiben unberührt, die Netzsperre bleibt gültig.
- **Python- und FFmpeg-Updates** kommen mit neuen Quite-Safe-Grab-Versionen; die Einrichtung erneuert sie dann automatisch.
- **Deinstallation:** `.\qsgrab.cmd firewall remove`, danach den Ordner löschen.

## Was nicht unterstützt wird

- **YouTube** und andere Seiten, die JavaScript-Ausführung oder eine Anmeldung brauchen: yt-dlp läuft bewusst ohne JavaScript-Laufzeit und ohne Cookies.
- Playlists (nur einzelne Videos).

## Entwicklung

- Tests: `python\python.exe -m unittest discover -s tests -v` (nach `setup.ps1`).
- Release bauen: `powershell -ExecutionPolicy Bypass -File .\make-release.ps1 -Version 1.0.0` – packt nur eine feste Dateiliste und bricht ab, wenn Benutzername, Profilpfad, Rechnername, lokale IP-Adressen oder die Git-E-Mail dieses PCs in einer Datei stehen.
- Python- oder FFmpeg-Version wechseln: Version, Adresse und SHA256 oben in `setup.ps1` gemeinsam ändern (Prüfsummen von der offiziellen Download-Seite).
- Herkunft: Portierung einer Raspberry-Pi-Fassung (Linux-Netzwerk-Namespace mit WireGuard). Plattformabhängiges steht in `syscompat.py` und `winguard.py`.

## Lizenz

GPL-3.0-only, siehe `LICENSE`. Fremdkomponenten und ihre Lizenzen: `THIRD_PARTY_NOTICES.md`.
