// Projekt: ServerARK
// Copyright (c) 2021-2025 wahke.lu
// Website: https://wahke.lu
// Lizenz: MIT
// Alle Rechte vorbehalten.
//
// File: serverark_static.c

#include "serverark_static.h"
#include <string.h>

// diese .inc Dateien enthalten automatisch generierte Arrays:
//   unsigned char webroot_index_html[];
//   unsigned int  webroot_index_html_len;   // wird NICHT mehr im init benutzt
#include "static_index_html.inc"
#include "static_app_js.inc"
#include "static_style_css.inc"

// Hinweis: wir verwenden sizeof(webroot_...) als Länge, weil das eine
// echte Compile-Time-Konstante ist.
static const static_file_t g_files[] = {
    {
        "/index.html",
        "text/html",
        webroot_index_html,
        sizeof(webroot_index_html)
    },
    {
        "/",
        "text/html",
        webroot_index_html,
        sizeof(webroot_index_html)
    },
    {
        "/app.js",
        "application/javascript",
        webroot_app_js,
        sizeof(webroot_app_js)
    },
    {
        "/style.css",
        "text/css",
        webroot_style_css,
        sizeof(webroot_style_css)
    },
};

const static_file_t *static_file_lookup(const char *path)
{
    for (size_t i = 0; i < sizeof(g_files)/sizeof(g_files[0]); ++i) {
        if (strcmp(g_files[i].path, path) == 0) {
            return &g_files[i];
        }
    }
    return NULL;
}
