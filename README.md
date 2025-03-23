# WiFi Security Audit Tool

## WICHTIGER BILDUNGSZWECK UND RECHTLICHER HINWEIS

Dieses Repository dient **ausschließlich Bildungs- und Forschungszwecken** zur Verbesserung des Verständnisses von WLAN-Sicherheit. Es wurde entwickelt, um das Bewusstsein für WLAN-Sicherheit zu schärfen und zur Entwicklung besserer Schutzmaßnahmen beizutragen.

**RECHTLICHE SITUATION IN DEUTSCHLAND:**
Nach deutschem Recht (insbesondere §202a, §202b, §202c und §303b StGB) ist das unbefugte Eindringen in fremde Netzwerke, das Abfangen von Daten und das Vorbereiten solcher Handlungen strafbar und kann mit Freiheitsstrafen von bis zu 2 Jahren oder Geldstrafen geahndet werden. Dieses Tool wird ausschließlich zu Bildungszwecken bereitgestellt und darf NICHT für illegale Aktivitäten verwendet werden.

**Die Nutzung dieses Tools ist NUR erlaubt für:**
- Sicherheitsüberprüfung Ihrer **eigenen** WLAN-Netzwerke
- Autorisierte Penetrationstests mit **schriftlicher und rechtsgültiger Einwilligung** des Netzwerkeigentümers (vor Beginn der Tests einzuholen)
- Bildungszwecke in isolierten, kontrollierten Laborumgebungen ohne Zugriff auf fremde Daten

Der Autor übernimmt keine Haftung für Missbrauch dieses Tools. Jede Verwendung erfolgt auf eigene Verantwortung und eigenes rechtliches Risiko.

## Überblick

Dieses System besteht aus zwei Hauptkomponenten:

1. **Security Audit Tool**: Analysiert Handshake-Dateien für Sicherheitsüberprüfungen und sendet Berichte per E-Mail.
2. **Wörterbuchgenerator**: Erzeugt anpassbare Wörterlisten für Sicherheitsüberprüfungen.

## Rechtliche Einordnung und Verantwortung

Die Nutzung von Tools zur WLAN-Sicherheitsanalyse unterliegt in Deutschland strengen rechtlichen Rahmenbedingungen:

- Nach §202c StGB ist bereits das Vorbereiten des Ausspähens von Daten unter bestimmten Umständen strafbar
- Die Nutzung dieses Tools für fremde Netzwerke ohne Genehmigung ist eine Straftat
- Auch der Versuch ist strafbar
- Bei professionellem Einsatz (z.B. als IT-Sicherheitsberater) sind angemessene Verträge und Dokumentation notwendig

**Bevor Sie dieses Tool verwenden:**
1. Stellen Sie sicher, dass Sie die rechtlichen Bestimmungen in Deutschland verstehen
2. Besorgen Sie alle erforderlichen Genehmigungen **vor** Beginn der Sicherheitsüberprüfung
3. Dokumentieren Sie die Genehmigung sorgfältig (vorzugsweise schriftlich)
4. Nutzen Sie das Tool nur in autorisierten Netzwerken oder vollständig isolierten Testumgebungen

## Schnelle Installation

```bash
sudo ./install.sh
```

Nach der Installation:
1. Bearbeiten Sie die Konfigurationsdatei: `/etc/wifi_security_audit/config.ini`
2. Aktualisieren Sie die E-Mail-Einstellungen (GMX-Zugangsdaten)
3. Optional: Erstellen Sie eine angepasste Wörterliste
4. Fügen Sie die erforderliche Genehmigungsdokumentation hinzu

## Verwendung

### Sicherheitsüberprüfung starten:

1. Stellen Sie sicher, dass Sie eine schriftliche Genehmigung haben (in `/var/wifi_security_audit/auth/` ablegen)
2. Legen Sie eine Handshake-Datei in das Verzeichnis `/var/wifi_security_audit/handshakes`
3. Der Dienst prüft die Genehmigung und beginnt mit der Analyse
4. Nach Abschluss der Analyse oder Timeout (1 Stunde) wird ein Bericht per E-Mail gesendet
5. Alle Aktivitäten werden für Audit-Zwecke protokolliert

### Wörterliste generieren:

```bash
sudo python3 /usr/local/bin/dictionary_generator.py [OPTIONEN]
```

## Konfiguration

Die Konfigurationsdatei befindet sich unter `/etc/wifi_security_audit/config.ini`:

```ini
[Directories]
monitor_dir = /var/wifi_security_audit/handshakes
wordlist_path = /var/wifi_security_audit/wordlist.txt
auth_dir = /var/wifi_security_audit/auth

[Email]
sender = sender@gmx.de
password = your_password
recipient = recipient@example.com
server = mail.gmx.net
port = 587

[Security]
require_authorization = true
audit_logging = true
local_network_only = true
```

## Dienstverwaltung

```bash
# Status überprüfen
sudo systemctl status wifi_security_audit.service

# Dienst starten
sudo systemctl start wifi_security_audit.service

# Dienst stoppen
sudo systemctl stop wifi_security_audit.service

# Dienst neustarten
sudo systemctl restart wifi_security_audit.service

# Logs anzeigen
sudo tail -f /var/log/wifi_security_audit.log
```

## Parameter: security_audit_tool.py

```
--daemon        Als Daemon im Hintergrund ausführen
--config        Pfad zur Konfigurationsdatei (Standard: /etc/wifi_security_audit/config.ini)
--pid-file      Pfad zur PID-Datei (Standard: /var/run/wifi_security_audit.pid)
--educational   Aktiviert den Bildungsmodus mit detaillierten Analyseberichten
```

## Parameter: dictionary_generator.py

```
-o, --output         Ausgabedatei für die Wörterliste (Standard: /var/wifi_security_audit/wordlist.txt)
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

Das System konvertiert automatisch zwischen den Formaten für eine optimale Analyse.

## Wörterlisten-Strategien

Der Wörterbuchgenerator kann verschiedene Kombinationen erstellen:

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

- **Dienst startet nicht**: Überprüfen Sie die Logs mit `journalctl -u wifi_security_audit.service`
- **E-Mail wird nicht gesendet**: Überprüfen Sie die GMX-Zugangsdaten und SMTP-Einstellungen
- **Analyse fehlgeschlagen**: Prüfen Sie die Genehmigungsdatei und stellen Sie sicher, dass diese gültig ist

## Abhängigkeiten

Das Installationsskript installiert automatisch:
- Python 3
- Aircrack-ng
- Hashcat
- Python-Pakete: python-daemon, lockfile, tqdm

## Verzeichnisstruktur

```
/etc/wifi_security_audit/config.ini   - Konfigurationsdatei
/usr/local/bin/security_audit_tool.py - Hauptprogramm
/usr/local/bin/dictionary_generator.py - Wörterbuchgenerator
/var/wifi_security_audit/handshakes/  - Verzeichnis für Handshake-Dateien
/var/wifi_security_audit/auth/        - Verzeichnis für Genehmigungsdateien
/var/wifi_security_audit/wordlist.txt - Standard-Wörterliste
/var/log/wifi_security_audit.log      - Logdatei
/var/run/wifi_security_audit.pid      - PID-Datei
```

## Bildungszweck und ethische Nutzung

Dieses Tool wurde entwickelt, um das Verständnis für WiFi-Sicherheit zu fördern und Netzwerkadministratoren bei der Identifizierung von Schwachstellen zu unterstützen. Die Kenntnis potenzieller Sicherheitslücken ist entscheidend für die Implementierung effektiver Schutzmaßnahmen.

Wir empfehlen folgende Best Practices für sichere WLAN-Netzwerke:
- Verwendung von WPA3 anstelle von WPA2 wo möglich
- Komplexe Passwörter mit mindestens 12 Zeichen
- Regelmäßige Änderung der Netzwerkschlüssel
- Aktivierung der Netzwerkisolierung für Gäste-WLANs
- Deaktivierung von WPS (Wi-Fi Protected Setup)

## Audit-Protokollierung

Alle Aktivitäten dieses Tools werden umfassend protokolliert, um Transparenz zu gewährleisten und Missbrauch zu verhindern. Die Protokolle enthalten:
- Zeitstempel für alle Aktionen
- Benutzeridentifikation
- Analysierte SSIDs und MAC-Adressen
- Verwendete Genehmigungsdokumente
- Erfolg oder Misserfolg der Sicherheitsüberprüfungen

Diese Protokolle dienen als Nachweis der ausschließlich legitimen Nutzung und können für Compliance-Nachweise verwendet werden.

## Lizenz

Dieses Projekt ist unter der GNU General Public License v3.0 lizenziert - siehe die LICENSE-Datei für Details.
