// Projekt: ServerARK
// Copyright (c) 2021-2025 wahke.lu
// Website: https://wahke.lu
// Lizenz: MIT
// Alle Rechte vorbehalten.
//
// File: serverarkd.c

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include "serverark_core.h"     // serverark_init(), serverark_is_enabled(), capture_and_analyze_once(), serverark_shutdown()
#include "serverark_web.h"      // webui_thread()
#include "serverark_conf.h"     // load_config()
#include "serverark_log.h"      // log_msg()
#include "serverark_version.h"  // SERVERARK_VERSION, SERVERARK_BUILD

// global, von serverark_core.c via extern genutzt
volatile sig_atomic_t term_flag = 0;

static void sig_handler(int sig)
{
    // SIGINT (Ctrl+C) oder SIGTERM (z.B. systemctl stop)
    term_flag = 1;
}

int main(int argc, char **argv)
{
    // Signale mit sigaction installieren
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (load_config("/etc/serverark.conf") != 0) {
        log_msg("[MAIN] Using defaults (no /etc/serverark.conf)");
    }
    // Versions- und Copyright-Info
    log_msg("[MAIN] ServerArk %s (Build: %s)", SERVERARK_VERSION, SERVERARK_BUILD);
    log_msg("[MAIN] Copyright (c) wahke.lu – Idee von: drboyd");
    log_msg("[MAIN] ServerArk starting"); 

    serverark_init();

    // WebUI-Thread starten
    pthread_t web_thread;
    if (pthread_create(&web_thread, NULL, webui_thread, NULL) != 0) {
        perror("[ERROR] pthread_create webui_thread");
        return 1;
    }
    log_msg("[MAIN] WebUI thread spawned");

    // Hauptloop: läuft, bis term_flag gesetzt ist
    while (!term_flag) {
        if (serverark_is_enabled()) {
            capture_and_analyze_once();
        } else {
            sleep(1);
        }
    }

    log_msg("[MAIN] Signal received, shutting down");

    // Aufräumen: iptables-Regeln entfernen, usw.
    serverark_shutdown();

    fflush(NULL);
    _exit(0);   // alle Threads hart beenden
}
