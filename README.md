# ServerArk (modernized)

**ServerArk** ist ein leichtgewichtiges UDP-Flood-Protection-Tool für Linux-Game- und Anwendungs-Server. Es überwacht eingehende UDP-Pakete über `libpcap` und blockiert Angreifer per `iptables`, bevor die Pakete den eigentlichen Server erreichen.

**ServerArk** ist eine Anwendung für Linux-Gaming-Server, die eingehende UDP-Pakete auf Kernel-Ebene in Echtzeit abtastet und analysiert, um festzustellen, ob einige dieser Pakete Teil eines UDP-Flood-Angriffs sind. Flood-Angriffe auf Gaming-Server sind typischerweise darauf ausgelegt, bei den Spielern auf dem Server so starke Lags zu verursachen, dass das Spiel nicht mehr spielbar ist. Sie können sogar einige Game-Server zum Absturz bringen.

**ServerArk** erkennt automatisch, wenn ein UDP-Flood-Angriff auftritt, und verwendet iptables-Regeln auf Kernel-Ebene, um diese Pakete dynamisch zu blockieren, sodass sie vom Game-Server überhaupt nicht verarbeitet werden. Im Grunde hebt es den Game-Server „über die Flut“ und ermöglicht, dass das Spiel selbst unter sehr starken Angriffen weiterhin spielbar bleibt.

Es kann interaktiv mit hoher Ausführlichkeit ausgeführt werden (um seine Logik in Aktion beobachten zu können), oder unauffällig als Daemon mit Ausgaben in tägliche Logdateien (typische Verwendung).

- Plattform: **Linux** (getestet auf Debian/Ubuntu)
- Sprache: **C**
- WebUI: **eingebauter HTTP-Server (Port 8888 standardmäßig)**
- Lizenz: MIT-Lizenz; basiert auf dem ursprünglichen ServerArk von Boyd G. Gafford Ph.D. (drboyd), erweitert von **wahke.lu**
---

## Features

- 🔍 **UDP-Traffic-Analyse** per `libpcap` (wie `tcpdump`)
- 🛡 **Automatisches Blocken von IPs** via `iptables -j DROP`
- 📈 Konfigurierbare Schwellenwerte:
  - Pakete pro Sekunde pro Spieler
  - globaler Threshold-Faktor
- 🧾 **Block-Liste** ( aktuell geblockte IPs )
- ✅ **Whitelist**:
  - IPs, die niemals geblockt werden
  - bereits geblockte IPs werden automatisch wieder freigegeben
- 🌐 **Integrierte WebUI**:
  - Status (On/Off, Threshold, Frequenz)
  - Konfiguration bearbeiten (Analyse & WebUI)
  - Blockierte IPs ansehen & freigeben
  - Whitelist verwalten
  - Live-Log-Viewer
  - Mehrsprachig: Deutsch & Englisch
- 🧷 **Konfigurationsdatei** unter `/etc/serverark.conf`
- 📜 **Whitelist-Datei** unter `/etc/serverark.whitelist`

---

## Systemvoraussetzungen

- Linux (mit `iptables`)
- `libpcap-dev` (Header für `pcap.h`)
- `pthread` (meist in glibc enthalten)

### Debian / Ubuntu

```bash
sudo apt update
```
```bash
sudo apt install build-essential libpcap-dev iptables
```
```bash
wget https://github.com/wahke/ServerARK/releases/latest/download/serverarkd-linux-amd64.zip
```
```bash
unzip serverarkd-linux-amd64.zip
```
Zum Testen direkt starten:
```bash
sudo ./serverarkd
```
---

### Konfiguration

Standardpfad:
```
/etc/serverark.conf
```

Wenn die Datei fehlt:

 - Start mit Defaults
 - Beim Speichern über das WebUI wird /etc/serverark.conf automatisch geschrieben (sofern serverarkd ausreichende Rechte hat, in der Regel root).

Beispiel für `/etc/serverark.conf`
```
[general]
enabled = 1
frequency = 60
threshold = 1.500
interface = eth0
network = 0.0.0.0/0
udp_persec = 60
max_blocked_ips = 1024

[webui]
listen_ip = 0.0.0.0
port = 8888
user = admin
password = changeme
```

Wichtige Felder:

 - enabled: 1 = Überwachung aktiv, 0 = aus
 - frequency: Analyse-Intervall in Sekunden
 - threshold: Anomalie-Schwellwert
 - interface: Netzwerkschnittstelle (z. B. eth0; leer = auto)
 - network: BPF-Filter, z. B. 192.168.0.0/24 oder 0.0.0.0/0
 - udp_persec: UDP-Pakete pro Sekunde/Spieler, ab denen ein Angriff angenommen wird
 - max_blocked_ips: maximale Anzahl gleichzeitig blockierter IPs
 - listen_ip + port: WebUI-Bind-Adresse
 - user + password: WebUI-Login

---

## WebUI

Standard-URL:
```
http://<dein-server>:8888/
```

Login:
 - Benutzername: (Default: admin)
 - Passwort: (Default: changeme)

Tabs:
 - Status
 - An/Aus-Status
 - Intervall
 - Schwellwert
 - Button „Überwachung ein/aus“

Config
 - Sämtliche Konfiguration aus /etc/serverark.conf
 - Speichern schreibt die Datei zurück
Blocked IPs
 - Zeigt aktuelle iptables-DROP-Regeln

 - Button zum Freigeben einzelner IPs

Whitelist
 - IPs, die nie geblockt werden
 - Hinzufügen/Entfernen von IPs
 - Bereits geblockte IPs werden beim Whitelisten automatisch freigegeben

Logs
 - Live-Logausgabe

Sprachen:
 - Umschaltbar (Select oben rechts): DE / EN


## Systemd-Beispiel (optional)

Beispiel-Service-Unit /etc/systemd/system/serverarkd.service:
```
[Unit]
Description=ServerARK UDP flood protection
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/serverarkd
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
```

Dann:
```
sudo systemctl daemon-reload
sudo systemctl enable serverarkd
sudo systemctl start serverarkd
sudo systemctl status serverarkd
```

---
### Version


- v1.1.0
    - Das komplette WebUI (HTML/JS/CSS) im Binary eingebettet – es wird **kein `webroot`-Ordner zur Laufzeit** mehr benötigt.
    - Einfacher Deployment-Workflow (ein Binary)
    - Build-System angepasst (xxd-basierte .inc-Files)
    - README aktualisiert
- v1.0.0 Erste stabile Version mit
    - UDP-Anomalie-Erkennung
    - iptables-Blocking
    - WebUI mit Status/Config/Whitelist/Logs
    - Konfigurationsdatei /etc/serverark.conf