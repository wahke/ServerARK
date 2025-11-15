// Projekt: ServerARK
// Copyright (c) 2021-2025 wahke.lu
// Website: https://wahke.lu
// Lizenz: MIT
// Alle Rechte vorbehalten.
//
// File: serverark_conf.c

#include "serverark_conf.h"
#include "serverark_log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static serverark_config_t g_conf;
static char g_conf_path[256] = "/etc/serverark.conf";

serverark_config_t *conf_get(void) {
    return &g_conf;
}

static void set_defaults(void) {
    memset(&g_conf, 0, sizeof(g_conf));

    g_conf.enabled   = 1;
    g_conf.frequency = 60;
    g_conf.threshold = 1.5;

    snprintf(g_conf.listen_ip, sizeof(g_conf.listen_ip), "0.0.0.0");
    g_conf.web_port = 8888;
    snprintf(g_conf.web_user,     sizeof(g_conf.web_user),     "admin");
    snprintf(g_conf.web_password, sizeof(g_conf.web_password), "changeme");

    g_conf.interface[0] = '\0'; // leer = auto via pcap_lookupdev()
    snprintf(g_conf.network, sizeof(g_conf.network), "0.0.0.0/0");

    g_conf.udp_persec      = 60;
    g_conf.max_blocked_ips = 1024;
}

static void trim(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (p != s) memmove(s, p, strlen(p)+1);
    size_t len = strlen(s);
    while (len>0 && (s[len-1]==' ' || s[len-1]=='\t' || s[len-1]=='\r' || s[len-1]=='\n')) {
        s[len-1]=0; len--;
    }
}

int load_config(const char *path) {
    if (path && *path) {
        snprintf(g_conf_path, sizeof(g_conf_path), "%s", path);
    }

    // immer Defaults setzen
    set_defaults();

    FILE *f = fopen(g_conf_path, "r");
    if (!f) {
        // KEINE Config: Defaults auf Platte schreiben
        log_msg("[CONF] No config file at %s, writing defaults", g_conf_path);
        if (save_config() != 0) {
            log_msg("[CONF] ERROR: could not write default config, using in-memory defaults");
            return -1;
        }
        return 0;
    }

    char line[256];
    char section[64] = "";
    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if (line[0]=='#' || line[0]==';' || line[0]==0) continue;
        if (line[0]=='[') {
            char *end = strchr(line, ']');
            if (end) {
                *end = 0;
                snprintf(section, sizeof(section), "%s", line+1);
            }
            continue;
        }
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        char *key = line;
        char *val = eq+1;
        trim(key); trim(val);

        if (strcmp(section, "general")==0) {
            if (strcmp(key, "enabled")==0) g_conf.enabled = atoi(val);
            else if (strcmp(key, "frequency")==0) g_conf.frequency = atoi(val);
            else if (strcmp(key, "threshold")==0) g_conf.threshold = atof(val);
            else if (strcmp(key, "interface")==0) snprintf(g_conf.interface,sizeof(g_conf.interface),"%s",val);
            else if (strcmp(key, "network")==0) snprintf(g_conf.network,sizeof(g_conf.network),"%s",val);
            else if (strcmp(key, "udp_persec")==0) g_conf.udp_persec = atoi(val);
            else if (strcmp(key, "max_blocked_ips")==0) g_conf.max_blocked_ips = atoi(val);
        } else if (strcmp(section, "webui")==0) {
            if (strcmp(key, "listen_ip")==0) snprintf(g_conf.listen_ip, sizeof(g_conf.listen_ip), "%s", val);
            else if (strcmp(key, "port")==0) g_conf.web_port = atoi(val);
            else if (strcmp(key, "user")==0) snprintf(g_conf.web_user, sizeof(g_conf.web_user), "%s", val);
            else if (strcmp(key, "password")==0) snprintf(g_conf.web_password, sizeof(g_conf.web_password), "%s", val);
        }
    }
    fclose(f);
    log_msg("[CONF] Loaded config from %s", g_conf_path);
    return 0;
}

int save_config(void) {
    FILE *f = fopen(g_conf_path, "w");
    if (!f) {
        log_msg("[CONF] ERROR: cannot write %s", g_conf_path);
        return -1;
    }
    fprintf(f,
        "# ServerArk configuration\n"
        "\n"
        "[general]\n"
        "enabled = %d\n"
        "frequency = %d\n"
        "threshold = %.3f\n"
        "interface = %s\n"
        "network = %s\n"
        "udp_persec = %d\n"
        "max_blocked_ips = %d\n"
        "\n"
        "[webui]\n"
        "listen_ip = %s\n"
        "port = %d\n"
        "user = %s\n"
        "password = %s\n",
        g_conf.enabled,
        g_conf.frequency,
        g_conf.threshold,
        g_conf.interface,
        g_conf.network,
        g_conf.udp_persec,
        g_conf.max_blocked_ips,
        g_conf.listen_ip,
        g_conf.web_port,
        g_conf.web_user,
        g_conf.web_password
    );
    fclose(f);
    log_msg("[CONF] Saved config to %s", g_conf_path);
    return 0;
}

int get_frequency_seconds(void) {
    return g_conf.frequency > 0 ? g_conf.frequency : 60;
}
