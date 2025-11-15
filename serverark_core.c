// Projekt: ServerARK
// Copyright (c) 2021-2025 wahke.lu
// Website: https://wahke.lu
// Lizenz: MIT
// Alle Rechte vorbehalten.
//
// File: serverark_core.c

#define _GNU_SOURCE
#include "serverark_core.h"
#include "serverark_conf.h"
#include "serverark_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/time.h>
#include <stdint.h>
#include <signal.h>

extern volatile sig_atomic_t term_flag;

#define MAX_PLAYERS          128
#define MAX_BLOCKED_IPS_HARD 2048
#define MAX_WHITELIST        512
#define SAMPLE_MSEC          1000
#define WHITELIST_PATH       "/etc/serverark.whitelist"

typedef struct {
    struct in_addr address;
    int            port;
    int            total_packets;
} PLAYER;

typedef struct {
    PLAYER players[MAX_PLAYERS];
    int    num_players;
    int    total_packets;
} ANALYSIS_BUCKET;

static int g_enabled = 1;
static unsigned long g_cycles = 0;

static ANALYSIS_BUCKET g_bucket;
static int g_num_blocked = 0;
static struct in_addr g_blocked[MAX_BLOCKED_IPS_HARD];

static int g_num_whitelist = 0;
static struct in_addr g_whitelist[MAX_WHITELIST];

static int64_t get_msecs(struct timeval *tvp) {
    int64_t sec, usec;
    if (tvp == NULL) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        sec = tv.tv_sec; usec = tv.tv_usec;
    } else {
        sec = tvp->tv_sec; usec = tvp->tv_usec;
    }
    return (sec * (int64_t)1000) + (usec / (int64_t)1000);
}

static void clear_analysis(void) {
    memset(&g_bucket, 0, sizeof(g_bucket));
}

static void add_player(in_addr_t saddr, int sport) {
    for (int i=0; i<g_bucket.num_players; i++) {
        if (g_bucket.players[i].address.s_addr == saddr &&
            g_bucket.players[i].port == sport) {
            g_bucket.players[i].total_packets++;
            return;
        }
    }
    if (g_bucket.num_players < MAX_PLAYERS) {
        g_bucket.players[g_bucket.num_players].address.s_addr = saddr;
        g_bucket.players[g_bucket.num_players].port = sport;
        g_bucket.players[g_bucket.num_players].total_packets = 1;
        g_bucket.num_players++;
    }
}

static int is_blocked_ip(in_addr_t saddr) {
    for (int i=0; i<g_num_blocked; i++) {
        if (g_blocked[i].s_addr == saddr) return 1;
    }
    return 0;
}

static int is_whitelisted(in_addr_t saddr) {
    for (int i=0; i<g_num_whitelist; i++) {
        if (g_whitelist[i].s_addr == saddr) return 1;
    }
    return 0;
}

static void load_whitelist(void) {
    g_num_whitelist = 0;
    FILE *f = fopen(WHITELIST_PATH, "r");
    if (!f) {
        log_msg("[CORE] No whitelist file at %s (ok)", WHITELIST_PATH);
        return;
    }
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        if (line[0] == 0 || line[0] == '#') continue;
        struct in_addr addr;
        if (inet_aton(line, &addr) != 0) {
            if (g_num_whitelist < MAX_WHITELIST) {
                g_whitelist[g_num_whitelist++] = addr;
            }
        }
    }
    fclose(f);
    log_msg("[CORE] Loaded %d whitelist entries", g_num_whitelist);
}

static void save_whitelist(void) {
    FILE *f = fopen(WHITELIST_PATH, "w");
    if (!f) {
        log_msg("[CORE] ERROR: cannot write whitelist file %s", WHITELIST_PATH);
        return;
    }
    for (int i=0; i<g_num_whitelist; i++) {
        fprintf(f, "%s\n", inet_ntoa(g_whitelist[i]));
    }
    fclose(f);
    log_msg("[CORE] Saved whitelist (%d entries)", g_num_whitelist);
}

static void block_ip(in_addr_t saddr) {
    serverark_config_t *cfg = conf_get();

    if (is_whitelisted(saddr)) {
        struct in_addr tmp;
        tmp.s_addr = saddr;
        log_msg("[CORE] %s is WHITELISTED, skipping block", inet_ntoa(tmp));
        return;
    }

    if (is_blocked_ip(saddr)) return;
    if (g_num_blocked >= cfg->max_blocked_ips ||
        g_num_blocked >= MAX_BLOCKED_IPS_HARD) {
        log_msg("[CORE] Max blocked IPs reached, not blocking more.");
        return;
    }

    g_blocked[g_num_blocked].s_addr = saddr;

    char cmd[256];
    snprintf(cmd,sizeof(cmd),
             "iptables -I INPUT -s %s -p udp -j DROP",
             inet_ntoa(g_blocked[g_num_blocked]));
    int status = system(cmd);
    if (status != 0) {
        log_msg("[CORE] iptables add rule failed for %s (status=%d)",
                inet_ntoa(g_blocked[g_num_blocked]), status);
    } else {
        log_msg("[CORE] Blocked %s via iptables DROP",
                inet_ntoa(g_blocked[g_num_blocked]));
        g_num_blocked++;
    }
}

static void remove_all_blocks(void) {
    for (int i=0; i<g_num_blocked; i++) {
        char cmd[256];
        snprintf(cmd,sizeof(cmd),
                 "iptables -D INPUT -s %s -p udp -j DROP",
                 inet_ntoa(g_blocked[i]));
        int status = system(cmd);
        if (status != 0) {
            log_msg("[CORE] iptables delete rule failed for %s (status=%d)",
                    inet_ntoa(g_blocked[i]), status);
        } else {
            log_msg("[CORE] Unblocked %s", inet_ntoa(g_blocked[i]));
        }
    }
    g_num_blocked = 0;
}

static void act_on_analysis(void) {
    serverark_config_t *cfg = conf_get();
    if (g_bucket.total_packets <= 0) {
        return;
    }
    int udp_persec = cfg->udp_persec > 0 ? cfg->udp_persec : 60;
    double thr = cfg->threshold > 0.1 ? cfg->threshold : 1.5;
    int max_packets = (int)((double)udp_persec * thr);

    int anomaly = 0;
    for (int i=0; i<g_bucket.num_players; i++) {
        if (g_bucket.players[i].total_packets >= max_packets) {
            if (!anomaly) {
                log_msg("[CORE] Detected anomaly: %d players, %d packets total",
                        g_bucket.num_players, g_bucket.total_packets);
                anomaly = 1;
            }
            log_msg("[CORE] %d packets from %s:%d exceeded %d -> probable attack",
                    g_bucket.players[i].total_packets,
                    inet_ntoa(g_bucket.players[i].address),
                    g_bucket.players[i].port,
                    max_packets);
        }
    }
    for (int i=0; i<g_bucket.num_players; i++) {
        if (g_bucket.players[i].total_packets >= max_packets) {
            block_ip(g_bucket.players[i].address.s_addr);
        }
    }
}

void serverark_init(void) {
    serverark_config_t *cfg = conf_get();
    g_enabled = cfg->enabled;
    log_msg("[CORE] Init: enabled=%d, freq=%d, threshold=%.3f, udp_persec=%d, net=%s, iface=%s",
           cfg->enabled, cfg->frequency, cfg->threshold,
           cfg->udp_persec, cfg->network, cfg->interface);
    load_whitelist();
}

void serverark_shutdown(void) {
    log_msg("[CORE] Shutdown after %lu analysis cycles, removing %d blocks",
           g_cycles, g_num_blocked);
    remove_all_blocks();
}

int serverark_is_enabled(void) {
    return g_enabled;
}

void serverark_set_enabled(int e) {
    g_enabled = e ? 1 : 0;
    serverark_config_t *cfg = conf_get();
    cfg->enabled = g_enabled;
    save_config();
    log_msg("[CORE] Protection %s via WebUI", g_enabled ? "ENABLED" : "DISABLED");
}

void capture_and_analyze_once(void) {
    serverark_config_t *cfg = conf_get();
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = NULL;
    bpf_u_int32 net = 0, mask = 0;
    pcap_t *handle = NULL;
    struct bpf_program fp;

    clear_analysis();
    g_cycles++;

    if (term_flag) {
        // schon beim Eintritt ein Stop-Signal -> gar nicht erst anfangen
        return;
    }

    if (cfg->interface[0]) {
        dev = cfg->interface;
    } else {
        dev = pcap_lookupdev(errbuf);
        if (!dev) {
            log_msg("[CORE] pcap_lookupdev failed: %s", errbuf);
            sleep(1);
            return;
        }
    }

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        log_msg("[CORE] Could not get netmask for %s: %s", dev, errbuf);
        net = 0; mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, SAMPLE_MSEC, errbuf);
    if (!handle) {
        log_msg("[CORE] pcap_open_live failed on %s: %s", dev, errbuf);
        sleep(1);
        return;
    }

    char filter_exp[128];
    snprintf(filter_exp,sizeof(filter_exp), "ip and udp and dst net %s", cfg->network);
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        log_msg("[CORE] pcap_compile failed: %s", pcap_geterr(handle));
        pcap_close(handle);
        sleep(1);
        return;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        log_msg("[CORE] pcap_setfilter failed: %s", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        sleep(1);
        return;
    }
    pcap_freecode(&fp);

    log_msg("[CORE] Cycle %lu: capturing UDP on %s with filter '%s'",
           g_cycles, dev, filter_exp);

    const u_char *packet;
    struct pcap_pkthdr header;
    int packets_analyzed = 0;
    int ipoffset = sizeof(struct ether_header);
    int udpoffset = ipoffset + sizeof(struct iphdr);
    int64_t startmsecs = get_msecs(NULL);
    int64_t nowmsecs = startmsecs;
    int64_t endmsecs = startmsecs + (int64_t)SAMPLE_MSEC;

    do {
        if (term_flag) {
            log_msg("[CORE] Termination requested, aborting capture loop");
            break;
        }

        packet = pcap_next(handle, &header);
        if (!packet) {
            break;
        }
        nowmsecs = get_msecs(&header.ts);

        struct ether_header *eptr = (struct ether_header *) packet;
        if (ntohs(eptr->ether_type) == ETHERTYPE_IP) {
            struct ip *iptr = (struct ip *)&packet[ipoffset];
            if (iptr->ip_p == IPPROTO_UDP) {
                struct udphdr *uptr = (struct udphdr *)&packet[udpoffset];
                g_bucket.total_packets++;
                add_player(iptr->ip_src.s_addr, (int)ntohs(uptr->source));
                packets_analyzed++;
            }
        } else {
            eptr = (struct ether_header *)&packet[2];
            if (ntohs(eptr->ether_type) == ETHERTYPE_IP) {
                struct ip *iptr = (struct ip *)&packet[ipoffset+2];
                if (iptr->ip_p == IPPROTO_UDP) {
                    struct udphdr *uptr = (struct udphdr *)&packet[udpoffset+2];
                    g_bucket.total_packets++;
                    add_player(iptr->ip_src.s_addr, (int)ntohs(uptr->source));
                    packets_analyzed++;
                }
            }
        }
    } while (!term_flag && nowmsecs < endmsecs);

    pcap_close(handle);

    if (term_flag) {
        log_msg("[CORE] Cycle %lu aborted due to shutdown request", g_cycles);
        return;
    }

    if (packets_analyzed > 0) {
        log_msg("[CORE] Cycle %lu: analyzed %d packets, %d players",
               g_cycles, packets_analyzed, g_bucket.num_players);
        act_on_analysis();
    } else {
        log_msg("[CORE] Cycle %lu: no packets captured", g_cycles);
    }
}

int core_get_blocked_json(char *buf, int maxlen) {
    if (!buf || maxlen <= 0) return -1;
    int off = 0;
    off += snprintf(buf+off, maxlen-off, "{ \"blocked\": [");
    for (int i = 0; i < g_num_blocked; i++) {
        char ip[32];
        snprintf(ip,sizeof(ip), "%s", inet_ntoa(g_blocked[i]));
        off += snprintf(buf+off, maxlen-off, "%s\"%s\"",
                        (i==0 ? "" : ","), ip);
        if (off >= maxlen-32) break;
    }
    off += snprintf(buf+off, maxlen-off, "] }");
    if (off >= maxlen) buf[maxlen-1] = 0;
    return 0;
}

int core_unblock_ip(const char *ip) {
    if (!ip || !*ip) return -1;
    struct in_addr addr;
    if (inet_aton(ip, &addr) == 0) return -1;
    int idx = -1;
    for (int i=0; i<g_num_blocked; i++) {
        if (g_blocked[i].s_addr == addr.s_addr) {
            idx = i; break;
        }
    }
    if (idx < 0) return -1;

    char cmd[256];
    snprintf(cmd,sizeof(cmd),
             "iptables -D INPUT -s %s -p udp -j DROP", ip);
    int status = system(cmd);
    if (status != 0) {
        log_msg("[CORE] iptables delete rule failed for %s (status=%d)", ip, status);
        return -1;
    }

    log_msg("[CORE] Unblocked %s via WebUI", ip);
    for (int j=idx+1; j<g_num_blocked; j++) {
        g_blocked[j-1] = g_blocked[j];
    }
    g_num_blocked--;
    return 0;
}

int core_get_whitelist_json(char *buf, int maxlen) {
    if (!buf || maxlen <= 0) return -1;
    int off = 0;
    off += snprintf(buf+off, maxlen-off, "{ \"whitelist\": [");
    for (int i = 0; i < g_num_whitelist; i++) {
        char ip[32];
        snprintf(ip,sizeof(ip), "%s", inet_ntoa(g_whitelist[i]));
        off += snprintf(buf+off, maxlen-off, "%s\"%s\"",
                        (i==0 ? "" : ","), ip);
        if (off >= maxlen-32) break;
    }
    off += snprintf(buf+off, maxlen-off, "] }");
    if (off >= maxlen) buf[maxlen-1] = 0;
    return 0;
}

int core_add_whitelist_ip(const char *ip) {
    if (!ip || !*ip) return -1;
    struct in_addr addr;
    if (inet_aton(ip, &addr) == 0) return -1;

    if (is_whitelisted(addr.s_addr)) {
        return 0;
    }
    if (g_num_whitelist >= MAX_WHITELIST) {
        log_msg("[CORE] Whitelist full, cannot add %s", ip);
        return -1;
    }
    g_whitelist[g_num_whitelist++] = addr;
    save_whitelist();

    core_unblock_ip(ip);

    log_msg("[CORE] Added %s to whitelist", ip);
    return 0;
}

int core_del_whitelist_ip(const char *ip) {
    if (!ip || !*ip) return -1;
    struct in_addr addr;
    if (inet_aton(ip, &addr) == 0) return -1;

    int idx = -1;
    for (int i=0; i<g_num_whitelist; i++) {
        if (g_whitelist[i].s_addr == addr.s_addr) {
            idx = i; break;
        }
    }
    if (idx < 0) return -1;

    for (int j=idx+1; j<g_num_whitelist; j++) {
        g_whitelist[j-1] = g_whitelist[j];
    }
    g_num_whitelist--;
    save_whitelist();
    log_msg("[CORE] Removed %s from whitelist", ip);
    return 0;
}
