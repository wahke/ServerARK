// Projekt: ServerARK
// Copyright (c) 2021-2025 wahke.lu
// Website: https://wahke.lu
// Lizenz: MIT
// Alle Rechte vorbehalten.
//
// File: serverark_static.h

#ifndef SERVERARK_STATIC_H
#define SERVERARK_STATIC_H

#include <stddef.h>

typedef struct {
    const char *path;         // z.B. "/index.html"
    const char *content_type; // z.B. "text/html"
    const unsigned char *data;
    size_t length;
} static_file_t;

// Liefert Pointer auf eingebettete Datei (oder NULL, wenn nicht gefunden)
const static_file_t *static_file_lookup(const char *path);

#endif