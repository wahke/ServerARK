# ServerArk (modernized)

**ServerArk** ist ein leichtgewichtiges UDP-Flood-Protection-Tool für Linux-Game- und Anwendungs-Server.  
Es überwacht eingehende UDP-Pakete über `libpcap` und blockiert Angreifer per `iptables`, bevor die Pakete den eigentlichen Server erreichen.

- Plattform: Linux (getestet auf Debian/Ubuntu)
- Sprache: C
- WebUI: eingebauter HTTP-Server (Port 8888 standardmäßig)
- Lizenz: basiert auf dem ursprünglichen ServerArk von Dr. Boyd G. Gafford (LGPL), erweitert von wahke.lu

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
- 🔢 **Version & Build-Info** in Logs/Konsole:
  - z.B. `ServerArk 1.0.0 (Build: abc1234)`

---

## Systemvoraussetzungen

- Linux (mit `iptables`)
- `gcc` oder kompatibler C-Compiler
- `make`
- `libpcap-dev` (Header für `pcap.h`)
- `pthread` (meist in glibc enthalten)

### Debian / Ubuntu

```bash
sudo apt update
sudo apt install build-essential libpcap-dev iptables
