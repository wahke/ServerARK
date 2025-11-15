// Projekt: ServerARK
// Copyright (c) 2021-2025 wahke.lu
// Website: https://wahke.lu
// Lizenz: MIT
// Alle Rechte vorbehalten.
//
// File: serverark_web.c

#include "serverark_web.h"
#include "serverark_core.h"
#include "serverark_conf.h"
#include "serverark_log.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void send_response(int c, const char *status, const char *ctype, const char *body) {
    dprintf(c,
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n%s",
        status,
        ctype,
        body ? strlen(body) : 0,
        body ? body : ""
    );
}

static int check_api_key(const char *headers) {
    serverark_config_t *cfg = conf_get();
    const char *h = strstr(headers, "X-Api-Key:");
    if (!h) return 0;
    h += strlen("X-Api-Key:");
    while (*h==' ' || *h=='\t') h++;
    char key[128]={0};
    int i=0;
    while (*h && *h!='\r' && *h!='\n' && i < (int)sizeof(key)-1) {
        key[i++] = *h++;
    }
    key[i]=0;
    return strcmp(key, cfg->web_password)==0;
}

/* -------- /api/login: Username + Passwort prüfen, OHNE X-Api-Key -------- */
static void handle_api_login(int c, const char *body) {
    serverark_config_t *cfg = conf_get();
    char *tmp = strdup(body ? body : "");
    if (!tmp) {
        send_response(c,"500 Internal Server Error","text/plain","OOM");
        return;
    }

    char user[64] = {0};
    char pass[64] = {0};

    /* user=...&password=... (x-www-form-urlencoded, ohne echtes URL-Decoding) */
    char *p = strstr(tmp, "user=");
    if (p) {
        p += 5;
        strncpy(user, p, sizeof(user)-1);
        char *amp = strchr(user, '&');
        if (amp) *amp = 0;
        char *nl = strchr(user, '\n');
        if (nl) *nl = 0;
        char *cr = strchr(user, '\r');
        if (cr) *cr = 0;
    }

    p = strstr(tmp, "password=");
    if (p) {
        p += 9;
        strncpy(pass, p, sizeof(pass)-1);
        char *amp = strchr(pass, '&');
        if (amp) *amp = 0;
        char *nl = strchr(pass, '\n');
        if (nl) *nl = 0;
        char *cr = strchr(pass, '\r');
        if (cr) *cr = 0;
    }

    free(tmp);

    if (!user[0] || !pass[0]) {
        send_response(c,"400 Bad Request","application/json","{\"ok\":0}");
        return;
    }

    if (strcmp(user, cfg->web_user)==0 && strcmp(pass, cfg->web_password)==0) {
        send_response(c,"200 OK","application/json","{\"ok\":1}");
    } else {
        send_response(c,"401 Unauthorized","application/json","{\"ok\":0}");
    }
}

/* ---------------------------- Status / Toggle ---------------------------- */

static void handle_api_status(int c) {
    serverark_config_t *cfg = conf_get();
    char buf[256];
    snprintf(buf,sizeof(buf),
        "{ \"enabled\": %d, \"frequency\": %d, \"threshold\": %.3f }",
        serverark_is_enabled(), cfg->frequency, cfg->threshold);
    send_response(c,"200 OK","application/json",buf);
}

static void handle_api_toggle(int c) {
    int cur = serverark_is_enabled();
    serverark_set_enabled(!cur);
    handle_api_status(c);
}

/* ------------------------------ Config API ------------------------------- */

static void handle_api_config_get(int c) {
    serverark_config_t *cfg = conf_get();
    char body[1024];
    snprintf(body,sizeof(body),
        "enabled=%d\n"
        "frequency=%d\n"
        "threshold=%.3f\n"
        "interface=%s\n"
        "network=%s\n"
        "udp_persec=%d\n"
        "max_blocked_ips=%d\n"
        "listen_ip=%s\n"
        "port=%d\n"
        "user=%s\n"
        "password=%s\n",
        cfg->enabled,
        cfg->frequency,
        cfg->threshold,
        cfg->interface,
        cfg->network,
        cfg->udp_persec,
        cfg->max_blocked_ips,
        cfg->listen_ip,
        cfg->web_port,
        cfg->web_user,
        cfg->web_password
    );
    send_response(c,"200 OK","text/plain",body);
}

static void handle_api_config_post(int c, const char *body) {
    serverark_config_t *cfg = conf_get();
    char *tmp = strdup(body ? body : "");
    if (!tmp) {
        send_response(c,"500 Internal Server Error","text/plain","OOM");
        return;
    }
    char *saveptr=NULL;
    char *line = strtok_r(tmp, "\n", &saveptr);
    while (line) {
        char *eq = strchr(line, '=');
        if (eq) {
            *eq = 0;
            char *k = line;
            char *v = eq+1;
            while (*k==' '||*k=='\t') k++;
            while (*v==' '||*v=='\t') v++;
            char *end;
            end = k + strlen(k);
            while (end>k && (end[-1]==' '||end[-1]=='\r'||end[-1]=='\t')) *--end=0;
            end = v + strlen(v);
            while (end>v && (end[-1]==' '||end[-1]=='\r'||end[-1]=='\t')) *--end=0;

            if (strcmp(k,"enabled")==0) cfg->enabled = atoi(v);
            else if (strcmp(k,"frequency")==0) cfg->frequency = atoi(v);
            else if (strcmp(k,"threshold")==0) cfg->threshold = atof(v);
            else if (strcmp(k,"interface")==0) snprintf(cfg->interface,sizeof(cfg->interface),"%s",v);
            else if (strcmp(k,"network")==0) snprintf(cfg->network,sizeof(cfg->network),"%s",v);
            else if (strcmp(k,"udp_persec")==0) cfg->udp_persec = atoi(v);
            else if (strcmp(k,"max_blocked_ips")==0) cfg->max_blocked_ips = atoi(v);
            else if (strcmp(k,"listen_ip")==0) snprintf(cfg->listen_ip,sizeof(cfg->listen_ip),"%s",v);
            else if (strcmp(k,"port")==0) cfg->web_port = atoi(v);
            else if (strcmp(k,"user")==0) snprintf(cfg->web_user,sizeof(cfg->web_user),"%s",v);
            else if (strcmp(k,"password")==0) snprintf(cfg->web_password,sizeof(cfg->web_password),"%s",v);
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }
    free(tmp);
    save_config();
    handle_api_config_get(c);
}

/* --------------------------- Blocked / Logs / WL ------------------------- */

static void handle_api_blocked_get(int c) {
    char json[4096];
    if (core_get_blocked_json(json, sizeof(json)) != 0) {
        send_response(c,"500 Internal Server Error","text/plain","error");
        return;
    }
    send_response(c,"200 OK","application/json",json);
}

static void handle_api_unblock(int c, const char *body) {
    char *tmp = strdup(body ? body : "");
    if (!tmp) {
        send_response(c,"500 Internal Server Error","text/plain","OOM");
        return;
    }
    char ip[64] = {0};
    char *eq = strstr(tmp, "ip=");
    if (eq) {
        eq += 3;
        strncpy(ip, eq, sizeof(ip)-1);
        char *nl = strchr(ip, '\n');
        if (nl) *nl = 0;
        char *cr = strchr(ip, '\r');
        if (cr) *cr = 0;
    }
    free(tmp);
    if (!ip[0]) {
        send_response(c,"400 Bad Request","text/plain","missing ip");
        return;
    }
    if (core_unblock_ip(ip) == 0) {
        send_response(c,"200 OK","text/plain","unblocked");
    } else {
        send_response(c,"400 Bad Request","text/plain","failed");
    }
}

static void handle_api_logs(int c) {
    char buf[8192];
    log_dump(buf, sizeof(buf));
    send_response(c,"200 OK","text/plain",buf);
}

static void handle_api_whitelist_get(int c) {
    char json[4096];
    if (core_get_whitelist_json(json, sizeof(json)) != 0) {
        send_response(c,"500 Internal Server Error","text/plain","error");
        return;
    }
    send_response(c,"200 OK","application/json",json);
}

static void handle_api_whitelist_add(int c, const char *body) {
    char *tmp = strdup(body ? body : "");
    if (!tmp) {
        send_response(c,"500 Internal Server Error","text/plain","OOM");
        return;
    }
    char ip[64] = {0};
    char *eq = strstr(tmp, "ip=");
    if (eq) {
        eq += 3;
        strncpy(ip, eq, sizeof(ip)-1);
        char *nl = strchr(ip, '\n');
        if (nl) *nl = 0;
        char *cr = strchr(ip, '\r');
        if (cr) *cr = 0;
    }
    free(tmp);
    if (!ip[0]) {
        send_response(c,"400 Bad Request","text/plain","missing ip");
        return;
    }
    if (core_add_whitelist_ip(ip) == 0) {
        send_response(c,"200 OK","text/plain","added");
    } else {
        send_response(c,"400 Bad Request","text/plain","failed");
    }
}

static void handle_api_whitelist_del(int c, const char *body) {
    char *tmp = strdup(body ? body : "");
    if (!tmp) {
        send_response(c,"500 Internal Server Error","text/plain","OOM");
        return;
    }
    char ip[64] = {0};
    char *eq = strstr(tmp, "ip=");
    if (eq) {
        eq += 3;
        strncpy(ip, eq, sizeof(ip)-1);
        char *nl = strchr(ip, '\n');
        if (nl) *nl = 0;
        char *cr = strchr(ip, '\r');
        if (cr) *cr = 0;
    }
    free(tmp);
    if (!ip[0]) {
        send_response(c,"400 Bad Request","text/plain","missing ip");
        return;
    }
    if (core_del_whitelist_ip(ip) == 0) {
        send_response(c,"200 OK","text/plain","deleted");
    } else {
        send_response(c,"400 Bad Request","text/plain","failed");
    }
}

/* ----------------------------- Static Files ------------------------------ */

static int serve_static(int c, const char *path) {
    char full[256];
    const char *fname = NULL;
    if (strcmp(path,"/")==0 || strcmp(path,"/index.html")==0) fname = "index.html";
    else if (strcmp(path,"/app.js")==0) fname = "app.js";
    else if (strcmp(path,"/style.css")==0) fname = "style.css";
    if (!fname) return 0;

    snprintf(full,sizeof(full),"webroot/%s",fname);
    FILE *f = fopen(full,"r");
    if (!f) {
        send_response(c,"404 Not Found","text/plain","Not found");
        return 1;
    }
    fseek(f,0,SEEK_END);
    long sz = ftell(f);
    fseek(f,0,SEEK_SET);
    char *buf = malloc(sz+1);
    if (!buf) {
        fclose(f);
        send_response(c,"500 Internal Server Error","text/plain","OOM");
        return 1;
    }
    fread(buf,1,sz,f);
    buf[sz]=0;
    fclose(f);
    const char *ctype = "text/html";
    if (strstr(fname,".js")) ctype="application/javascript";
    if (strstr(fname,".css")) ctype="text/css";
    send_response(c,"200 OK",ctype,buf);
    free(buf);
    return 1;
}

/* ----------------------------- WebUI Thread ------------------------------ */

void *webui_thread(void *arg) {
    serverark_config_t *cfg = conf_get();
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in a;
    a.sin_family = AF_INET;
    a.sin_port   = htons(cfg->web_port);
    a.sin_addr.s_addr = inet_addr(cfg->listen_ip);
    if (bind(s,(struct sockaddr*)&a,sizeof(a))<0) {
        perror("[WebUI] bind");
        return NULL;
    }
    if (listen(s, 10)<0) {
        perror("[WebUI] listen");
        close(s);
        return NULL;
    }
    log_msg("[WebUI] Listening on %s:%d", cfg->listen_ip, cfg->web_port);

    for (;;) {
        int c = accept(s,NULL,NULL);
        if (c<0) continue;

        char buf[8192];
        int n = read(c, buf, sizeof(buf)-1);
        if (n<=0) { close(c); continue; }
        buf[n]=0;

        char method[8]={0}, path[256]={0};
        sscanf(buf,"%7s %255s", method, path);

        char *hdr_end = strstr(buf, "\r\n\r\n");
        char *body = NULL;
        if (hdr_end) {
            *hdr_end = 0;
            body = hdr_end + 4;
        } else {
            hdr_end = buf + strlen(buf);
        }
        const char *headers = buf;

        /* WICHTIG: /api/login VOR check_api_key behandeln */
        if (strcmp(path,"/api/login")==0 && strcmp(method,"POST")==0) {
            handle_api_login(c, body ? body : "");
        }
        else if (strncmp(path,"/api/",5)==0) {
            if (!check_api_key(headers)) {
                send_response(c,"401 Unauthorized","text/plain","Unauthorized");
            } else {
                if (strcmp(path,"/api/status")==0 && strcmp(method,"GET")==0) {
                    handle_api_status(c);
                } else if (strcmp(path,"/api/toggle")==0 && strcmp(method,"POST")==0) {
                    handle_api_toggle(c);
                } else if (strcmp(path,"/api/config")==0 && strcmp(method,"GET")==0) {
                    handle_api_config_get(c);
                } else if (strcmp(path,"/api/config")==0 && strcmp(method,"POST")==0) {
                    handle_api_config_post(c, body ? body : "");
                } else if (strcmp(path,"/api/blocked")==0 && strcmp(method,"GET")==0) {
                    handle_api_blocked_get(c);
                } else if (strcmp(path,"/api/unblock")==0 && strcmp(method,"POST")==0) {
                    handle_api_unblock(c, body ? body : "");
                } else if (strcmp(path,"/api/logs")==0 && strcmp(method,"GET")==0) {
                    handle_api_logs(c);
                } else if (strcmp(path,"/api/whitelist")==0 && strcmp(method,"GET")==0) {
                    handle_api_whitelist_get(c);
                } else if (strcmp(path,"/api/whitelist_add")==0 && strcmp(method,"POST")==0) {
                    handle_api_whitelist_add(c, body ? body : "");
                } else if (strcmp(path,"/api/whitelist_del")==0 && strcmp(method,"POST")==0) {
                    handle_api_whitelist_del(c, body ? body : "");
                } else {
                    send_response(c,"404 Not Found","text/plain","Unknown API");
                }
            }
        } else {
            if (!serve_static(c,path)) {
                send_response(c,"404 Not Found","text/plain","Not found");
            }
        }

        close(c);
    }

    close(s);
    return NULL;
}
