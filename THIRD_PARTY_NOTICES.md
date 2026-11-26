# Fremdkomponenten

Quite Safe Grab selbst steht unter **GPL-3.0-only** (siehe `LICENSE`).

## Im Paket enthalten

| Komponente | Version | Lizenz | Herkunft |
|---|---|---|---|
| yt-dlp | 2026.10.26 | Unlicense | <https://github.com/yt-dlp/yt-dlp>, Wheel von PyPI (`wheels\`, SHA256 in `requirements.lock`) |
| Beautiful Soup 4 | 4.14.3 | MIT | <https://www.crummy.com/software/BeautifulSoup/>, Wheel von PyPI |
| Soup Sieve | 4.1 | MIT | <https://github.com/facelessuser/soupsieve>, Wheel von PyPI |
| typing_extensions | 4.16.0 | PSF-2.0 | <https://github.com/python/typing_extensions>, Wheel von PyPI |
| voe-dl (Auszug) | 1.9.0, Commit `b82c920d96f12fb047f7d0ccc4223f6dc08e0578` | GPL-3.0 | <https://github.com/MPZ-00/voe-dl> (Fork von <https://github.com/p4ul17/voe-dl>, ebenfalls GPL-3.0); `voe_dl\` enthält nur Dekodierung, Bait-Filter und Quellenmethoden. Unveränderte Dateien samt SHA256 in `vendor-sha256.json`; `voe_dl\__init__.py` ist ersetzt (ohne Kommandozeilen-Seiteneffekt). |

Die Lizenztexte der Python-Pakete liegen in den Wheels (Ordner `*.dist-info` nach der Einrichtung in `lib\`).

## Von setup.ps1 geladen (nicht im Paket)

| Komponente | Version | Lizenz | Quelle |
|---|---|---|---|
| Python (Windows Embeddable Package) | 3.14.10 | PSF License | <https://www.python.org/downloads/release/python-31410/> |
| FFmpeg „essentials“-Build von Gyan Doshi | 9.1 | GPL-3.0 | <https://www.gyan.dev/ffmpeg/builds/>, <https://github.com/GyanD/codexffmpeg/releases/tag/9.1>; Quellcode: <https://ffmpeg.org/download.html>. `setup.ps1` legt `tools\FFMPEG-LICENSE.txt` ab. |

Beide werden nur von den in `setup.ps1` fest eingetragenen Adressen geladen und vor dem Entpacken gegen die dort eingetragene SHA256-Prüfsumme geprüft.
