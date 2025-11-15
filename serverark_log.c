// Projekt: ServerARK
// Copyright (c) 2021-2025 wahke.lu
// Website: https://wahke.lu
// Lizenz: MIT
// Alle Rechte vorbehalten.
//
// File: serverark_log.c

#include "serverark_log.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#define LOG_BUF_LINES 512
#define LOG_LINE_LEN  256

static char log_lines[LOG_BUF_LINES][LOG_LINE_LEN];
static int  log_head = 0;
static int  log_count = 0;

void log_msg(const char *fmt, ...) {
    char msg[LOG_LINE_LEN];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    char line[LOG_LINE_LEN];
    snprintf(line, sizeof(line), "%02d:%02d:%02d %s",
             tm.tm_hour, tm.tm_min, tm.tm_sec, msg);

    strncpy(log_lines[log_head], line, LOG_LINE_LEN-1);
    log_lines[log_head][LOG_LINE_LEN-1] = 0;
    log_head = (log_head + 1) % LOG_BUF_LINES;
    if (log_count < LOG_BUF_LINES) log_count++;

    fprintf(stdout, "%s\n", line);
    fflush(stdout);
}

size_t log_dump(char *dest, size_t max) {
    if (!dest || max == 0) return 0;
    size_t written = 0;
    int lines = log_count;
    int start = (log_head - log_count + LOG_BUF_LINES) % LOG_BUF_LINES;
    for (int i = 0; i < lines; i++) {
        const char *ln = log_lines[(start + i) % LOG_BUF_LINES];
        size_t len = strlen(ln);
        if (written + len + 1 >= max) break;
        memcpy(dest + written, ln, len);
        written += len;
        dest[written++] = '\n';
    }
    if (written < max) dest[written] = 0;
    return written;
}
