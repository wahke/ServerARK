// Projekt: ServerARK
// Copyright (c) 2021-2025 wahke.lu
// Website: https://wahke.lu
// Lizenz: MIT
// Alle Rechte vorbehalten.
//
// File: serverark_conf.h
#ifndef SERVERARK_CONF_H
#define SERVERARK_CONF_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int   enabled;                 // 1 = Schutz aktiv, 0 = aus
    int   frequency;               // Analyse-Intervall in Sekunden
    double threshold;              // Faktor für UDP/sek Schwellwert
    char  listen_ip[32];           // WebUI Bind-IP (z.B. "0.0.0.0")
    int   web_port;                // WebUI Port (z.B. 8888)
    char  web_user[64];            // WebUI Benutzername
    char  web_password[64];        // WebUI Passwort
    char  interface[64];           // Netz-Interface für pcap (z.B. "eth0", leer = auto)
    char  network[64];             // zu überwachendes Netz (z.B. "0.0.0.0/0")
    int   udp_persec;              // erwartete UDP-Pakete pro Sekunde
    int   max_blocked_ips;         // max. Anzahl geblockter IPs
} serverark_config_t;

int  load_config(const char *path);     // liest Config, legt sie ggf. neu an
int  save_config(void);                 // schreibt aktuelle Config nach g_conf_path
serverark_config_t *conf_get(void);     // Zeiger auf globale Config
int  get_frequency_seconds(void);       // Frequency mit sinnvoller Untergrenze

#ifdef __cplusplus
}
#endif

#endif /* SERVERARK_CONF_H */
