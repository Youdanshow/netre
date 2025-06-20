#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <time.h>

#ifdef _WIN32
#define OS_WINDOWS
const char *OS_NAME = "Windows";
#elif __APPLE__
#define OS_DARWIN
const char *OS_NAME = "Darwin";
#else
#define OS_LINUX
const char *OS_NAME = "Linux";
#endif

static char *run_command(const char *cmd) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;
    char *result = NULL;
    size_t len = 0;
    char buf[256];
    while (fgets(buf, sizeof(buf), fp)) {
        size_t l = strlen(buf);
        char *tmp = realloc(result, len + l + 1);
        if (!tmp) { free(result); pclose(fp); return NULL; }
        result = tmp;
        memcpy(result + len, buf, l);
        len += l;
        result[len] = '\0';
    }
    pclose(fp);
    return result;
}

static int command_available(const char *cmd) {
#ifdef OS_WINDOWS
    char check[256];
    snprintf(check, sizeof(check), "where %s >nul 2>&1", cmd);
#else
    char check[256];
    snprintf(check, sizeof(check), "command -v %s >/dev/null 2>&1", cmd);
#endif
    int ret = system(check);
    return ret == 0;
}

static json_t *get_ip_addresses(void) {
    json_t *obj = json_object();
    json_t *results = json_array();
    json_object_set_new(obj, "results", results);
    const char *cmd = "";
#ifdef OS_LINUX
    cmd = "ip -j addr";
    json_object_set_new(obj, "command", json_string(cmd));
    if (!command_available("ip")) {
        json_object_set_new(obj, "error", json_string("ip needs to be installed"));
        return obj;
    }
    char *out = run_command(cmd);
    if (!out) return obj;
    json_error_t err;
    json_t *data = json_loads(out, 0, &err);
    free(out);
    if (!data || !json_is_array(data)) {
        if (data) json_decref(data);
        return obj;
    }
    size_t i; json_t *iface;
    json_array_foreach(data, i, iface) {
        const char *ifname = json_string_value(json_object_get(iface, "ifname"));
        json_t *addr_info = json_object_get(iface, "addr_info");
        if (!ifname || !json_is_array(addr_info)) continue;
        size_t j; json_t *addr;
        json_array_foreach(addr_info, j, addr) {
            const char *ip = json_string_value(json_object_get(addr, "local"));
            if (ip) {
                json_t *item = json_object();
                json_object_set_new(item, "interface", json_string(ifname));
                json_object_set_new(item, "ip", json_string(ip));
                json_array_append_new(results, item);
            }
        }
    }
    json_decref(data);
#elif defined(OS_WINDOWS)
    cmd = "ipconfig";
    json_object_set_new(obj, "command", json_string(cmd));
    if (!command_available("ipconfig")) {
        json_object_set_new(obj, "error", json_string("ipconfig needs to be installed"));
        return obj;
    }
    char *out = run_command(cmd);
    if (!out) return obj;
    char *line = strtok(out, "\n");
    while (line) {
        char *trim = line;
        while (*trim == ' ' || *trim == '\t') trim++;
        if (strncmp(trim, "IPv4", 4) == 0) {
            char *colon = strchr(trim, ':');
            if (colon) {
                colon++; while (*colon == ' ') colon++;
                json_t *item = json_object();
                json_object_set_new(item, "interface", json_string("unknown"));
                json_object_set_new(item, "ip", json_string(colon));
                json_array_append_new(results, item);
            }
        }
        line = strtok(NULL, "\n");
    }
    free(out);
#elif defined(OS_DARWIN)
    cmd = "ifconfig";
    json_object_set_new(obj, "command", json_string(cmd));
    if (!command_available("ifconfig")) {
        json_object_set_new(obj, "error", json_string("ifconfig needs to be installed"));
        return obj;
    }
    char *out = run_command(cmd);
    if (!out) return obj;
    char *line = strtok(out, "\n");
    while (line) {
        char *trim = line; while (*trim == ' ' || *trim == '\t') trim++;
        if (strncmp(trim, "inet ", 5) == 0 && strstr(trim, "127.0.0.1") == NULL) {
            char *ip = trim + 5;
            char *end = strchr(ip, ' ');
            if (end) *end = '\0';
            json_t *item = json_object();
            json_object_set_new(item, "interface", json_string("unknown"));
            json_object_set_new(item, "ip", json_string(ip));
            json_array_append_new(results, item);
        }
        line = strtok(NULL, "\n");
    }
    free(out);
#else
    json_object_set_new(obj, "command", json_string(""));
    json_object_set_new(obj, "error", json_string("unsupported platform"));
#endif
    return obj;
}

static json_t *get_open_ports(void) {
    json_t *obj = json_object();
    json_t *results = json_array();
    json_object_set_new(obj, "results", results);
    const char *cmd = "";
#ifdef OS_LINUX
    cmd = "ss -tuln";
    json_object_set_new(obj, "command", json_string(cmd));
    if (!command_available("ss")) {
        json_object_set_new(obj, "error", json_string("ss needs to be installed"));
        return obj;
    }
    char *out = run_command(cmd);
    if (!out) return obj;
    char *line = strtok(out, "\n");
    if (line) line = strtok(NULL, "\n"); /* skip header */
    while (line) {
        char *parts[6];
        int idx = 0;
        char *tok = strtok(line, " \t");
        while (tok && idx < 6) {
            parts[idx++] = tok;
            tok = strtok(NULL, " \t");
        }
        if (idx >= 5) {
            json_t *item = json_object();
            json_object_set_new(item, "protocol", json_string(parts[0]));
            json_object_set_new(item, "local_address", json_string(parts[4]));
            json_array_append_new(results, item);
        }
        line = strtok(NULL, "\n");
    }
    free(out);
#elif defined(OS_WINDOWS)
    cmd = "netstat -ano";
    json_object_set_new(obj, "command", json_string(cmd));
    if (!command_available("netstat")) {
        json_object_set_new(obj, "error", json_string("netstat needs to be installed"));
        return obj;
    }
    char *out = run_command(cmd);
    if (!out) return obj;
    char *line = strtok(out, "\n");
    while (line) {
        char *parts[6];
        int idx = 0;
        char *tok = strtok(line, " \t");
        while (tok && idx < 6) {
            parts[idx++] = tok;
            tok = strtok(NULL, " \t");
        }
        if (idx >= 2 && (strncmp(parts[0], "TCP", 3) == 0 || strncmp(parts[0], "UDP", 3) == 0)) {
            json_t *item = json_object();
            json_object_set_new(item, "protocol", json_string(parts[0]));
            json_object_set_new(item, "local_address", json_string(parts[1]));
            json_array_append_new(results, item);
        }
        line = strtok(NULL, "\n");
    }
    free(out);
#elif defined(OS_DARWIN)
    cmd = "lsof -i -nP";
    json_object_set_new(obj, "command", json_string(cmd));
    if (!command_available("lsof")) {
        json_object_set_new(obj, "error", json_string("lsof needs to be installed"));
        return obj;
    }
    char *out = run_command(cmd);
    if (!out) return obj;
    char *line = strtok(out, "\n");
    if (line) line = strtok(NULL, "\n");
    while (line) {
        char *parts[10];
        int idx = 0;
        char *tok = strtok(line, " \t");
        while (tok && idx < 10) {
            parts[idx++] = tok;
            tok = strtok(NULL, " \t");
        }
        if (idx >= 9) {
            json_t *item = json_object();
            json_object_set_new(item, "protocol", json_string(parts[7]));
            json_object_set_new(item, "local_address", json_string(parts[8]));
            json_array_append_new(results, item);
        }
        line = strtok(NULL, "\n");
    }
    free(out);
#else
    json_object_set_new(obj, "command", json_string(""));
    json_object_set_new(obj, "error", json_string("unsupported platform"));
#endif
    return obj;
}

static json_t *get_running_services(void) {
    json_t *obj = json_object();
    json_t *results = json_array();
    json_object_set_new(obj, "results", results);
    const char *cmd = "";
#ifdef OS_LINUX
    cmd = "systemctl list-units --type=service --state=running --no-pager --no-legend";
    json_object_set_new(obj, "command", json_string(cmd));
    if (!command_available("systemctl")) {
        json_object_set_new(obj, "error", json_string("systemctl needs to be installed"));
        return obj;
    }
    char *out = run_command(cmd);
    if (!out) return obj;
    char *line = strtok(out, "\n");
    while (line) {
        char *service = strtok(line, " \t");
        if (service) {
            json_t *item = json_string(service);
            json_array_append_new(results, item);
        }
        line = strtok(NULL, "\n");
    }
    free(out);
#elif defined(OS_WINDOWS)
    cmd = "sc query state=running";
    json_object_set_new(obj, "command", json_string(cmd));
    if (!command_available("sc")) {
        json_object_set_new(obj, "error", json_string("sc needs to be installed"));
        return obj;
    }
    char *out = run_command(cmd);
    if (!out) return obj;
    char *line = strtok(out, "\n");
    while (line) {
        while (*line == ' ' || *line == '\t') line++;
        if (strncmp(line, "SERVICE_NAME:", 13) == 0) {
            char *name = line + 13;
            while (*name == ' ') name++;
            json_array_append_new(results, json_string(name));
        }
        line = strtok(NULL, "\n");
    }
    free(out);
#else
    json_object_set_new(obj, "command", json_string(""));
    json_object_set_new(obj, "error", json_string("unsupported platform"));
#endif
    return obj;
}

static json_t *scan_vulnerabilities(const char *target) {
    json_t *obj = json_object();
    json_t *results = json_array();
    json_object_set_new(obj, "command", json_string("nmap -sV --script vulners 127.0.0.1"));
    json_object_set_new(obj, "results", results);
    if (!command_available("nmap")) {
        json_object_set_new(obj, "error", json_string("nmap needs to be installed"));
        return obj;
    }
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nmap -sV --script vulners %s", target);
    char *out = run_command(cmd);
    if (!out) return obj;
    char *line = strtok(out, "\n");
    char current_port[32] = "";
    int collecting = 0;
    while (line) {
        char *trim = line;
        while (*trim == ' ' || *trim == '\t') trim++;
        if (strncmp(trim, "| vulners:", 10) == 0) {
            collecting = 1;
            line = strtok(NULL, "\n");
            continue;
        }
        if (collecting) {
            if (*trim != '|') { collecting = 0; line = strtok(NULL, "\n"); continue; }
            char *content = trim + 1;
            while (*content == ' ') content++;
            char *parts[4];
            int idx = 0;
            char *tok = strtok(content, " \t");
            while (tok && idx < 4) {
                parts[idx++] = tok;
                tok = strtok(NULL, " \t");
            }
            if (idx >= 3 && strncmp(parts[0], "CVE-", 4) == 0) {
                json_t *item = json_object();
                json_object_set_new(item, "port", json_string(current_port));
                json_object_set_new(item, "cve", json_string(parts[0]));
                json_object_set_new(item, "cvss", json_string(parts[1]));
                json_object_set_new(item, "link", json_string(parts[2]));
                json_array_append_new(results, item);
            }
        } else {
            if (strstr(trim, "/tcp") || strstr(trim, "/udp")) {
                char *space = strchr(trim, ' ');
                if (space) *space = '\0';
                strncpy(current_port, trim, sizeof(current_port)-1);
                current_port[sizeof(current_port)-1] = '\0';
                char *slash = strchr(current_port, '/');
                if (slash) *slash = '\0';
            }
        }
        line = strtok(NULL, "\n");
    }
    free(out);
    return obj;
}

int main(void) {
    json_t *root = json_object();

    fprintf(stderr, "loading...\n");
    const int total = 4;
    int i = 0;
    clock_t start = clock();

    json_object_set_new(root, "ip_addresses", get_ip_addresses());
    fprintf(stderr, "[##########                    ] %d/%d\r", ++i, total);
    json_object_set_new(root, "open_ports", get_open_ports());
    fprintf(stderr, "[####################          ] %d/%d\r", ++i, total);
    json_object_set_new(root, "running_services", get_running_services());
    fprintf(stderr, "[############################  ] %d/%d\r", ++i, total);
    json_object_set_new(root, "vulnerabilities", scan_vulnerabilities("127.0.0.1"));
    fprintf(stderr, "[##############################] %d/%d\n", ++i, total);

    double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
    fprintf(stderr, "Completed in %.2f seconds\n", elapsed);

    json_dumpf(root, stdout, JSON_INDENT(2));
    json_decref(root);
    return 0;
}

