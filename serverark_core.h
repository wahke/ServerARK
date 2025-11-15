// Projekt: ServerARK
// Copyright (c) 2021-2025 wahke.lu
// Website: https://wahke.lu
// Lizenz: MIT
// Alle Rechte vorbehalten.
//
// File: serverark_core.h

#ifndef SERVERARK_CORE_H
#define SERVERARK_CORE_H

void serverark_init(void);
void serverark_shutdown(void);

int  serverark_is_enabled(void);
void serverark_set_enabled(int e);

void capture_and_analyze_once(void);

int core_get_blocked_json(char *buf, int maxlen);
int core_unblock_ip(const char *ip);

int core_get_whitelist_json(char *buf, int maxlen);
int core_add_whitelist_ip(const char *ip);
int core_del_whitelist_ip(const char *ip);

#endif
