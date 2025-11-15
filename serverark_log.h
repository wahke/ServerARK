// Projekt: ServerARK
// Copyright (c) 2021-2025 wahke.lu
// Website: https://wahke.lu
// Lizenz: MIT
// Alle Rechte vorbehalten.
//
// File: serverark_log.h

#ifndef SERVERARK_LOG_H
#define SERVERARK_LOG_H

#include <stddef.h>

void log_msg(const char *fmt, ...);
size_t log_dump(char *dest, size_t max);

#endif
