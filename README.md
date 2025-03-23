# WiFi Handshake Cracker

Ein automatisiertes System zum Cracken von WiFi-Handshakes und Senden von Ergebnissen per E-Mail.

## Überblick

Dieses System besteht aus zwei Hauptprogrammen:

1. **Handshake Cracker**: Überwacht ein Verzeichnis auf neue Handshake-Dateien, versucht Passwörter zu cracken und sendet die Ergebnisse per E-Mail.
2. **Wordlist Generator**: Erzeugt Wortlisten zum Cracken der Passwörter basierend auf benutzerdefinierten Parametern.

## Schnelle Installation

```bash
sudo ./install.sh
```

Nach der Installation:
1. Bearbeiten Sie die Konfigurationsdatei: `/etc/handshake_cracker/config.ini`
2. Aktualisieren Sie die E-Mail-Einstellungen (GMX-Zugangsdaten)
3. Optional: Erstellen Sie eine angepasste Wortliste

## Verwendung

### Handshake cracken:

1. Legen Sie eine Handshake-Datei in das Verzeichnis `/var/handshake_cracker/handshakes`
2. Der Dienst erkennt die Datei automatisch und beginnt mit dem Cracken
3. Nach erfolgreichem Cracken oder Timeout (1 Stunde) wird die Datei gelöscht
4. Ergebnisse werden per E-Mail gesendet

### Wortliste generieren:

```bash
sudo python3 /usr/local/bin/wordlist_generator.py [OPTIONEN]
```

## Konfiguration

Die Konfigurationsdatei befindet sich unter `/etc/handshake_cracker/config.ini`:

```ini
[Directories]
monitor_dir = /var/handshake_cracker/handshakes
wordlist_path = /var/handshake_cracker/wordlist.txt

[Email]
sender = sender@gmx.de
password = your_password
recipient = recipient@example.com
server = mail.gmx.net
port = 587
```

## Dienstverwaltung

```bash
# Status überprüfen
sudo systemctl status handshake_cracker.service

# Dienst starten
sudo systemctl start handshake_cracker.service

# Dienst stoppen
sudo systemctl stop handshake_cracker.service

# Dienst neustarten
sudo systemctl restart handshake_cracker.service

# Logs anzeigen
sudo tail -f /var/log/handshake_cracker.log
```

## Parameter: handshake_cracker.py

```
--daemon        Als Daemon im Hintergrund ausführen
--config        Pfad zur Konfigurationsdatei (Standard: /etc/handshake_cracker/config.ini)
--pid-file      Pfad zur PID-Datei (Standard: /var/run/handshake_cracker.pid)
```

## Parameter: wordlist_generator.py

```
-o, --output         Ausgabedatei für die Wortliste (Standard: /var/handshake_cracker/wordlist.txt)
--min-length         Minimale Passwortlänge (Standard: 8)
--max-length         Maximale Passwortlänge (Standard: 10)
--lowercase          Kleinbuchstaben einschließen (Standard: aktiviert)
--uppercase          Großbuchstaben einschließen
--digits             Ziffern einschließen (Standard: aktiviert)
--special            Sonderzeichen einschließen
--no-lowercase       Kleinbuchstaben ausschließen
--no-digits          Ziffern ausschließen
--base-words         Datei mit Grundwörtern, die einbezogen werden sollen
--no-patterns        Generierung häufiger Muster mit Grundwörtern deaktivieren
```

## Unterstützte Handshake-Formate

- `.cap` - Hauptformat von Aircrack-ng
- `.pcap` - Standard-Packet-Capture-Format
- `.pcapng` - Next-Generation-Packet-Capture-Format
- `.hccapx` - Hashcat-Format

Das System konvertiert automatisch zwischen den Formaten je nach verwendetem Cracking-Tool.

## Wortlisten-Strategien

Der Wordlist Generator kann verschiedene Kombinationen erstellen:

1. **Zeichensätze**:
   - Kleinbuchstaben: a-z
   - Großbuchstaben: A-Z
   - Ziffern: 0-9
   - Sonderzeichen: !@#$%^&*()_+ usw.

2. **Kombination mit Basiswörtern**:
   - Reine Wörterbucheinträge
   - Wörter + Jahre (1990-2029)
   - Wörter + häufige Suffixe (123, !, #, usw.)
   - Wörter mit Großschreibung des ersten Buchstabens

## Fehlerbehebung

- **Dienst startet nicht**: Überprüfen Sie die Logs mit `journalctl -u handshake_cracker.service`
- **E-Mail wird nicht gesendet**: Überprüfen Sie die GMX-Zugangsdaten und SMTP-Einstellungen
- **Passwort wurde nicht gefunden**: Versuchen Sie, eine umfangreichere Wortliste zu erstellen

## Abhängigkeiten

Das Installationsskript installiert automatisch:
- Python 3
- Aircrack-ng
- Hashcat
- Python-Pakete: python-daemon, lockfile, tqdm

## Verzeichnisstruktur

```
/etc/handshake_cracker/config.ini  - Konfigurationsdatei
/usr/local/bin/handshake_cracker.py - Hauptprogramm
/usr/local/bin/wordlist_generator.py - Wortlistengenerator
/var/handshake_cracker/handshakes/ - Verzeichnis für Handshake-Dateien
/var/handshake_cracker/wordlist.txt - Standard-Wortliste
/var/log/handshake_cracker.log - Logdatei
/var/run/handshake_cracker.pid - PID-Datei
```

## Sicherheitshinweise

- Dieses Tool ist nur für legitime Zwecke gedacht, wie das Wiederherstellen von Passwörtern für eigene Netzwerke
- Die Verwendung zum Knacken von Passwörtern fremder Netzwerke ist illegal
- Bewahren Sie die Konfigurationsdatei mit den E-Mail-Anmeldedaten sicher auf
