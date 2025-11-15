// Projekt: ServerARK
// Copyright (c) 2021-2025 wahke.lu
// Website: https://wahke.lu
// Lizenz: MIT
// Alle Rechte vorbehalten.
//
// File: webroot/app.js

let apiKey = null;
let logTimer = null;
let statusTimer = null;
let blockedTimer = null;
let whitelistTimer = null;

let currentLang = 'de';
let lastStatus = null;

const translations = {
    de: {
        tab_status: "Status",
        tab_config: "Einstellungen",
        tab_blocked: "Blockierte IPs",
        tab_whitelist: "Whitelist",
        tab_logs: "Protokolle",

        login_title: "Anmeldung",
        login_user_hint: "Benutzername:",
        login_user_placeholder: "Benutzername",
        login_password_placeholder: "Passwort",
        login_hint: "Passwort",
        login_btn: "Anmelden",
        login_error: "Anmeldung fehlgeschlagen",
        login_error: "Anmeldung fehlgeschlagen",
        login_missing: "Bitte Benutzername und Passwort eingeben.",

        status_title: "Status",
        status_enabled_label: "Überwachung:",
        status_frequency_label: "Intervall:",
        status_threshold_label: "Schwellenwert:",
        status_enabled_on: "Aktiv",
        status_enabled_off: "Inaktiv",
        status_toggle_btn: "Überwachung ein/aus",

        config_title: "Konfiguration (Analyse & Weboberfläche)",
        cfg_enabled: "Überwachung aktiv:",
        cfg_frequency: "Intervall (s):",
        cfg_threshold: "Schwellenwert:",
        cfg_interface: "Auf Interface lauschen:",
        cfg_interface_placeholder: "z.b. eth0 / (leer = auto)", 
        cfg_network: "Netzwerkfilter (BPF):",
        cfg_network_placeholder: "z.B. 192.168.0.0/24",
        cfg_udp_persec: "UDP pro Sek. (pro Spieler):",
        cfg_max_blocked: "Max. blockierte IPs:",
        cfg_listen_ip: "Web Listen IP:",
        cfg_port: "Web-Port:",
        cfg_user: "Web-Benutzer:",
        cfg_password: "Web-Passwort:",
        cfg_save: "Speichern",

        blocked_title: "Blockierte IPs",
        blocked_hint: "Liste der IP-Adressen, die derzeit über iptables blockiert sind.",
        blocked_ip: "IP-Adresse",
        blocked_action: "Aktion",
        blocked_unblock_btn: "Freigeben",
        blocked_empty: "Derzeit sind keine IPs blockiert.",
        blocked_error: "Fehler beim Laden der blockierten IPs.",

        wl_title: "Whitelist",
        wl_hint: "IPs in der Whitelist werden <strong>nie blockiert</strong>. Bereits blockierte IPs werden automatisch wieder freigegeben.",
        wl_add_label: "Neue IP zur Whitelist hinzufügen:",
        wl_add_btn: "Hinzufügen",
        wl_ip: "IP-Adresse",
        wl_action: "Aktion",
        wl_new_ip_placeholder: "z.B. 1.2.3.4",
        wl_remove_btn: "Entfernen",
        wl_empty: "Keine IPs in der Whitelist.",
        wl_add_ok: "IP hinzugefügt (und ggf. freigegeben).",
        wl_add_error: "Fehler beim Hinzufügen.",
        wl_del_ok: "IP entfernt.",
        wl_del_error: "Fehler beim Entfernen.",
        wl_need_ip: "Bitte eine IP-Adresse eingeben.",
        wl_load_error: "Fehler beim Laden der Whitelist.",

        logs_title: "Protokolle (Live)",
        footer_text: "© 2025 wahke.lu – Idee von drboyd",
        cfg_saved: "Einstellungen gespeichert.",
        cfg_save_error: "Fehler beim Speichern der Einstellungen."
    },
    en: {
        tab_status: "Status",
        tab_config: "Config",
        tab_blocked: "Blocked IPs",
        tab_whitelist: "Whitelist",
        tab_logs: "Logs",

        login_title: "Login",
        login_hint: "Password",
        login_user_hint: "Username:",
        login_user_placeholder: "Username",
        login_password_placeholder: "Password",
        login_btn: "Login",
        login_error: "Login failed",
        login_error: "Login failed",
        login_missing: "Please enter username and password.",

        status_title: "Status",
        status_enabled_label: "Status:",
        status_frequency_label: "Frequency:",
        status_threshold_label: "Threshold:",
        status_enabled_on: "On",
        status_enabled_off: "Off",
        status_toggle_btn: "Toggle protection",

        config_title: "Configuration (Analysis + WebUI)",
        cfg_enabled: "Enabled:",
        cfg_frequency: "Frequency (s):",
        cfg_threshold: "Threshold:",
        cfg_interface: "Capture Interface:",
        cfg_interface2: "e.g. eth0 / (empty = auto)",
        cfg_network: "Network (BPF):",
        cfg_udp_persec: "UDP per sec (per player):",
        cfg_max_blocked: "Max blocked IPs:",
        cfg_listen_ip: "Web listen IP:",
        cfg_port: "Web port:",
        cfg_user: "Web user:",
        cfg_password: "Web password:",
        cfg_save: "Save",

        blocked_title: "Blocked IPs",
        blocked_hint: "List of IP addresses currently blocked via iptables.",
        blocked_ip: "IP",
        blocked_action: "Action",
        blocked_unblock_btn: "Unblock",
        blocked_empty: "No IPs blocked.",
        blocked_error: "Error loading list.",

        wl_title: "Whitelist",
        wl_hint: "IPs on the whitelist are <strong>never blocked</strong>. If they were blocked before, they will be unblocked automatically.",
        wl_add_label: "Add IP to whitelist:",
        wl_add_btn: "Add",
        wl_ip: "IP",
        wl_action: "Action",
        wl_remove_btn: "Remove",
        wl_empty: "No IPs on whitelist.",
        wl_add_ok: "Added (and unblocked if needed).",
        wl_add_error: "Error adding IP.",
        wl_del_ok: "Removed.",
        wl_del_error: "Error removing IP.",
        wl_need_ip: "Please enter an IP.",
        wl_load_error: "Error loading whitelist.",
        cfg_interface_placeholder: "e.g. eth0 / (empty = auto)",
        cfg_network_placeholder: "e.g. 192.168.0.0/24",
        wl_new_ip_placeholder: "e.g. 1.2.3.4",

        logs_title: "Logs (live)",

        cfg_saved: "Saved.",
        footer_text: "© 2025 wahke.lu – idea by drboyd",
        cfg_save_error: "Error saving"
    }
};

function t(key) {
    const lang = translations[currentLang] || translations.de;
    return lang[key] || key;
}

function applyTranslations() {
    // normale Texte
    document.querySelectorAll("[data-i18n]").forEach(el => {
        const key = el.getAttribute("data-i18n");
        if (!key) return;

        if (el.tagName === "BUTTON") {
            el.innerText = t(key);
        } else if (key === "wl_hint") {
            // dieser Text enthält HTML (<strong>…), daher innerHTML
            el.innerHTML = t(key);
        } else {
            el.innerText = t(key);
        }
    });

    // NEU: Placeholder-Texte (Inputs etc.)
    document.querySelectorAll("[data-i18n-ph]").forEach(el => {
        const key = el.getAttribute("data-i18n-ph");
        if (!key) return;
        const txt = t(key);
        if (typeof txt === "string") {
            el.placeholder = txt;
        }
    });

    // vorhandene Login-Fehlermeldung ggf. lokalisieren
    const loginError = document.getElementById("login-error");
    if (loginError && loginError.innerText) {
        loginError.innerText = t("login_error");
    }
}


function setLang(lang) {
    currentLang = lang === "en" ? "en" : "de";
    applyTranslations();
    if (lastStatus) {
        renderStatus(lastStatus);
    }
}

function api(url, options = {}) {
    if (!options.headers) options.headers = {};
    if (apiKey) options.headers["X-Api-Key"] = apiKey;
    return fetch(url, options);
}

function doLogin() {
    const userEl = document.getElementById("username");
    const passEl = document.getElementById("password");
    const errEl  = document.getElementById("login-error");

    const user = userEl ? userEl.value.trim() : "";
    const pass = passEl ? passEl.value : "";

    errEl.innerText = "";

    if (!user || !pass) {
        errEl.innerText = t("login_missing");
        return;
    }

    // wie früher: Passwort = apiKey, Backend prüft X-Api-Key
    apiKey = pass;

    api("/api/status")
        .then(r => {
            if (!r.ok) throw new Error("login");
            return r.json();
        })
        .then(jStatus => {
            // Login erfolgreich → UI freischalten
            document.getElementById("login-box").style.display = "none";
            document.getElementById("main").style.display      = "block";
            document.getElementById("nav-tabs").style.display  = "flex";
            errEl.innerText = "";

            initTabs();
            applyTranslations();

            renderStatus(jStatus);
            loadConfig();
            loadBlocked();
            loadWhitelist();
            loadLogs();

            statusTimer    = setInterval(() => refreshStatus(),  5000);
            blockedTimer   = setInterval(() => loadBlocked(),    7000);
            whitelistTimer = setInterval(() => loadWhitelist(), 10000);
            logTimer       = setInterval(() => loadLogs(),       3000);
        })
        .catch(err => {
            console.error(err);
            errEl.innerText = t("login_error");
            apiKey = null;
        });
}


function renderStatus(j) {
    lastStatus = j;

    const enabledText = j.enabled
        ? t("status_enabled_on")
        : t("status_enabled_off");

    document.getElementById("status-enabled").innerText   = enabledText;
    document.getElementById("status-frequency").innerText = j.frequency;
    document.getElementById("status-threshold").innerText = j.threshold;

    const btn = document.getElementById("status-toggle-btn");
    if (btn) btn.innerText = t("status_toggle_btn");
}

function refreshStatus() {
    api("/api/status").then(r => r.json()).then(renderStatus);
}

function toggle() {
    api("/api/toggle", {method:"POST"}).then(r => r.json()).then(renderStatus);
}

function loadConfig() {
    api("/api/config").then(r => r.text()).then(tconf => {
        const lines = tconf.split("\n");
        const cfg = {};
        lines.forEach(l => {
            const idx = l.indexOf("=");
            if (idx>0) {
                const k = l.slice(0,idx).trim();
                const v = l.slice(idx+1).trim();
                cfg[k]=v;
            }
        });
        document.getElementById("cfg-enabled").value      = cfg.enabled || 1;
        document.getElementById("cfg-frequency").value    = cfg.frequency || 60;
        document.getElementById("cfg-threshold").value    = cfg.threshold || 1.5;
        document.getElementById("cfg-interface").value    = cfg.interface || "";
        document.getElementById("cfg-network").value      = cfg.network || "0.0.0.0/0";
        document.getElementById("cfg-udp-persec").value   = cfg.udp_persec || 60;
        document.getElementById("cfg-max-blocked").value  = cfg.max_blocked_ips || 1024;
        document.getElementById("cfg-listen-ip").value    = cfg.listen_ip || "0.0.0.0";
        document.getElementById("cfg-port").value         = cfg.port || 8888;
        document.getElementById("cfg-user").value         = cfg.user || "admin";
        document.getElementById("cfg-password").value     = cfg.password || "";
    });
}

function saveConfig() {
    const body =
        "enabled="       + document.getElementById("cfg-enabled").value + "\n" +
        "frequency="     + document.getElementById("cfg-frequency").value + "\n" +
        "threshold="     + document.getElementById("cfg-threshold").value + "\n" +
        "interface="     + document.getElementById("cfg-interface").value + "\n" +
        "network="       + document.getElementById("cfg-network").value + "\n" +
        "udp_persec="    + document.getElementById("cfg-udp-persec").value + "\n" +
        "max_blocked_ips="+ document.getElementById("cfg-max-blocked").value + "\n" +
        "listen_ip="     + document.getElementById("cfg-listen-ip").value + "\n" +
        "port="          + document.getElementById("cfg-port").value + "\n" +
        "user="          + document.getElementById("cfg-user").value + "\n" +
        "password="      + document.getElementById("cfg-password").value + "\n";

    api("/api/config", {method:"POST", body}).then(r => {
        if (!r.ok) throw new Error("save");
        return r.text();
    }).then(tconf => {
        document.getElementById("cfg-msg").innerText = t("cfg_saved");
        loadConfig();
    }).catch(err => {
        document.getElementById("cfg-msg").innerText = t("cfg_save_error");
    });
}

function loadBlocked() {
    api("/api/blocked").then(r => r.json()).then(j => {
        const tbody = document.querySelector("#blocked-table tbody");
        tbody.innerHTML = "";
        (j.blocked || []).forEach(ip => {
            const tr = document.createElement("tr");
            const tdIp = document.createElement("td");
            tdIp.innerText = ip;
            const tdAct = document.createElement("td");
            const btn = document.createElement("button");
            btn.innerText = t("blocked_unblock_btn");
            btn.onclick = () => unblockIp(ip);
            tdAct.appendChild(btn);
            tr.appendChild(tdIp);
            tr.appendChild(tdAct);
            tbody.appendChild(tr);
        });
        document.getElementById("blocked-msg").innerText =
            (j.blocked && j.blocked.length > 0) ? "" : t("blocked_empty");
    }).catch(err => {
        document.getElementById("blocked-msg").innerText = t("blocked_error");
    });
}

function unblockIp(ip) {
    const body = "ip=" + ip + "\n";
    api("/api/unblock", {method:"POST", body}).then(r => r.text()).then(tresp => {
        loadBlocked();
    });
}

function loadWhitelist() {
    api("/api/whitelist").then(r => r.json()).then(j => {
        const tbody = document.querySelector("#whitelist-table tbody");
        tbody.innerHTML = "";
        (j.whitelist || []).forEach(ip => {
            const tr = document.createElement("tr");
            const tdIp = document.createElement("td");
            tdIp.innerText = ip;
            const tdAct = document.createElement("td");
            const btn = document.createElement("button");
            btn.innerText = t("wl_remove_btn");
            btn.onclick = () => whitelistDel(ip);
            tdAct.appendChild(btn);
            tr.appendChild(tdIp);
            tr.appendChild(tdAct);
            tbody.appendChild(tr);
        });
        document.getElementById("whitelist-msg").innerText =
            (j.whitelist && j.whitelist.length > 0) ? "" : t("wl_empty");
    }).catch(err => {
        document.getElementById("whitelist-msg").innerText = t("wl_load_error");
    });
}

function whitelistAdd() {
    const ip = document.getElementById("wl-new-ip").value.trim();
    if (!ip) {
        document.getElementById("whitelist-msg").innerText = t("wl_need_ip");
        return;
    }
    const body = "ip=" + ip + "\n";
    api("/api/whitelist_add", {method:"POST", body}).then(r => r.text()).then(tresp => {
        document.getElementById("wl-new-ip").value = "";
        loadWhitelist();
        loadBlocked();
        document.getElementById("whitelist-msg").innerText = t("wl_add_ok");
    }).catch(err => {
        document.getElementById("whitelist-msg").innerText = t("wl_add_error");
    });
}

function whitelistDel(ip) {
    const body = "ip=" + ip + "\n";
    api("/api/whitelist_del", {method:"POST", body}).then(r => r.text()).then(tresp => {
        loadWhitelist();
        document.getElementById("whitelist-msg").innerText = t("wl_del_ok");
    }).catch(err => {
        document.getElementById("whitelist-msg").innerText = t("wl_del_error");
    });
}

function loadLogs() {
    api("/api/logs").then(r => r.text()).then(tlogs => {
        const box = document.getElementById("logs-box");
        box.innerText = tlogs;
        box.scrollTop = box.scrollHeight;
    });
}

function initTabs() {
    const buttons = document.querySelectorAll(".tab-btn");
    buttons.forEach(btn => {
        btn.onclick = () => {
            const target = btn.getAttribute("data-tab");
            document.querySelectorAll(".tab").forEach(tab => {
                tab.style.display = (tab.id === target) ? "block" : "none";
            });
            buttons.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
        };
    });
}

document.addEventListener("DOMContentLoaded", () => {
    const sel = document.getElementById("lang-select");
    if (sel) {
        sel.value = currentLang;
    }
    applyTranslations();
});
