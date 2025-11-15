# Projekt: ServerARK
# Copyright (c) 2021-2025 wahke.lu
# Website: https://wahke.lu
# Hinweis: Ursprünglicher ServerArk-Code von Dr. Boyd G. Gafford (LGPL).
#
# File: Makefile

# ---------------------------------------------------------
# Compiler / Basisflags
# ---------------------------------------------------------
CC      ?= cc
BASE_CFLAGS := -Wall -O2 -pthread
LDFLAGS ?= -lpcap

# ---------------------------------------------------------
# Version / Build aus Git
# ---------------------------------------------------------
# Version aus letztem Git-Tag (z.B. v1.0.0), Fallback: 0.0.0-dev
VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo "0.0.0-dev")

# Build aus kurzem Commit-Hash, Fallback: local
BUILD   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "local")

# Diese Defines landen in serverark_version.h (via CFLAGS)
VERSION_DEFS := -DSERVERARK_VERSION=\"$(VERSION)\" -DSERVERARK_BUILD=\"$(BUILD)\"

# endgültige CFLAGS
CFLAGS ?= $(BASE_CFLAGS)
CFLAGS += $(VERSION_DEFS)

# ---------------------------------------------------------
# Dateien
# ---------------------------------------------------------
SRCS = \
    serverarkd.c \
    serverark_core.c \
    serverark_web.c \
    serverark_conf.c \
    serverark_log.c \
    serverark_static.c

OBJS = $(SRCS:.c=.o)

TARGET = serverarkd

# Installationspfade (für "make install")
PREFIX  ?= /usr/local
SBINDIR ?= $(PREFIX)/sbin
ETCDIR  ?= /etc

.PHONY: all clean install uninstall debug

# ---------------------------------------------------------
# Default-Target
# ---------------------------------------------------------
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# ---------------------------------------------------------
# Debug-Build (mit -g, ohne -O2)
# ---------------------------------------------------------
debug: CFLAGS := -Wall -g -O0 -pthread $(VERSION_DEFS)
debug: clean $(TARGET)

# ---------------------------------------------------------
# Aufräumen
# ---------------------------------------------------------
clean:
	rm -f $(OBJS) $(TARGET)

# ---------------------------------------------------------
# Installation (optional)
# ---------------------------------------------------------
install: $(TARGET)
	@echo "Installiere $(TARGET) nach $(SBINDIR)..."
	mkdir -p "$(DESTDIR)$(SBINDIR)"
	cp "$(TARGET)" "$(DESTDIR)$(SBINDIR)/"
	@echo "Optional: Beispiel-Config nach $(ETCDIR)/serverark.conf kopieren."

uninstall:
	@echo "Entferne $(TARGET) aus $(SBINDIR)..."
	rm -f "$(DESTDIR)$(SBINDIR)/$(TARGET)"
