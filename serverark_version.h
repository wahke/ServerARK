// Projekt: ServerARK
// Copyright (c) 2021-2025 wahke.lu
// Website: https://wahke.lu
// Lizenz: MIT
// Alle Rechte vorbehalten.
//
// File: serverark_version.h

#ifndef SERVERARK_VERSION_H
#define SERVERARK_VERSION_H

// Kann zur Build-Zeit via -D SERVERARK_VERSION="\"1.0.0\"" überschrieben werden
#ifndef SERVERARK_VERSION
#define SERVERARK_VERSION "1.0.0-dev"
#endif

// Kann zur Build-Zeit via -D SERVERARK_BUILD="\"<git-hash>\"" überschrieben werden
#ifndef SERVERARK_BUILD
#define SERVERARK_BUILD __DATE__ " " __TIME__
#endif

#endif