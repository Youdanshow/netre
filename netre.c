#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <jansson.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#endif

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

static double get_time_seconds(void) {
#ifdef OS_WINDOWS
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return uli.QuadPart / 10000000.0;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
#endif
}

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

static void print_progress(int step, int total) {
    int filled = (30 * step) / total;
    fprintf(stderr, "\r[");
    for (int i = 0; i < filled; i++) fputc('#', stderr);
    for (int i = filled; i < 30; i++) fputc(' ', stderr);
    fprintf(stderr, "] %d/%d", step, total);
    if (step == total) fputc('\n', stderr);
    fflush(stderr);
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
    char *saveptr_line = NULL;
    char *line = strtok_r(out, "\n", &saveptr_line);
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
    char *saveptr_line = NULL;
    char *line = strtok_r(out, "\n", &saveptr_line);
    if (line) line = strtok_r(NULL, "\n", &saveptr_line); /* skip header */
    while (line) {
        char *parts[6];
        int idx = 0;
        char *saveptr_tok = NULL;
        char *tok = strtok_r(line, " \t", &saveptr_tok);
        while (tok && idx < 6) {
            parts[idx++] = tok;
            tok = strtok_r(NULL, " \t", &saveptr_tok);
        }
        if (idx >= 5) {
            json_t *item = json_object();
            json_object_set_new(item, "protocol", json_string(parts[0]));
            json_object_set_new(item, "local_address", json_string(parts[4]));
            json_array_append_new(results, item);
        }
        line = strtok_r(NULL, "\n", &saveptr_line);
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
    char *saveptr_line = NULL;
    char *line = strtok_r(out, "\n", &saveptr_line);
    while (line) {
        char *parts[6];
        int idx = 0;
        char *saveptr_tok = NULL;
        char *tok = strtok_r(line, " \t", &saveptr_tok);
        while (tok && idx < 6) {
            parts[idx++] = tok;
            tok = strtok_r(NULL, " \t", &saveptr_tok);
        }
        if (idx >= 2 && (strncmp(parts[0], "TCP", 3) == 0 || strncmp(parts[0], "UDP", 3) == 0)) {
            json_t *item = json_object();
            json_object_set_new(item, "protocol", json_string(parts[0]));
            json_object_set_new(item, "local_address", json_string(parts[1]));
            json_array_append_new(results, item);
        }
        line = strtok_r(NULL, "\n", &saveptr_line);
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
    char *saveptr_line = NULL;
    char *line = strtok_r(out, "\n", &saveptr_line);
    if (line) line = strtok_r(NULL, "\n", &saveptr_line);
    while (line) {
        char *parts[10];
        int idx = 0;
        char *saveptr_tok = NULL;
        char *tok = strtok_r(line, " \t", &saveptr_tok);
        while (tok && idx < 10) {
            parts[idx++] = tok;
            tok = strtok_r(NULL, " \t", &saveptr_tok);
        }
        if (idx >= 9) {
            json_t *item = json_object();
            json_object_set_new(item, "protocol", json_string(parts[7]));
            json_object_set_new(item, "local_address", json_string(parts[8]));
            json_array_append_new(results, item);
        }
        line = strtok_r(NULL, "\n", &saveptr_line);
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
    char *saveptr_line = NULL;
    char *line = strtok_r(out, "\n", &saveptr_line);
    while (line) {
        char *saveptr_tok = NULL;
        char *service = strtok_r(line, " \t", &saveptr_tok);
        if (service) {
            json_t *item = json_string(service);
            json_array_append_new(results, item);
        }
        line = strtok_r(NULL, "\n", &saveptr_line);
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
    char *saveptr_line = NULL;
    char *line = strtok_r(out, "\n", &saveptr_line);
    while (line) {
        while (*line == ' ' || *line == '\t') line++;
        if (strncmp(line, "SERVICE_NAME:", 13) == 0) {
            char *name = line + 13;
            while (*name == ' ') name++;
            json_array_append_new(results, json_string(name));
        }
        line = strtok_r(NULL, "\n", &saveptr_line);
    }
    free(out);
#else
    json_object_set_new(obj, "command", json_string(""));
    json_object_set_new(obj, "error", json_string("unsupported platform"));
#endif
    return obj;
}

static json_t *get_disk_usage(void) {
    json_t *obj = json_object();
    json_t *results = json_array();
    json_object_set_new(obj, "results", results);
    const char *cmd = "";
#ifdef OS_LINUX
    cmd = "df -h";
    json_object_set_new(obj, "command", json_string(cmd));
    if (!command_available("df")) {
        json_object_set_new(obj, "error", json_string("df needs to be installed"));
        return obj;
    }
    char *out = run_command(cmd);
    if (!out) return obj;
    char *saveptr_line = NULL;
    char *line = strtok_r(out, "\n", &saveptr_line);
    if (line) line = strtok_r(NULL, "\n", &saveptr_line); /* skip header */
    while (line) {
        char *parts[6];
        int idx = 0;
        char *saveptr_tok = NULL;
        char *tok = strtok_r(line, " \t", &saveptr_tok);
        while (tok && idx < 6) {
            parts[idx++] = tok;
            tok = strtok_r(NULL, " \t", &saveptr_tok);
        }
        if (idx >= 6) {
            json_t *item = json_object();
            json_object_set_new(item, "filesystem", json_string(parts[0]));
            json_object_set_new(item, "size", json_string(parts[1]));
            json_object_set_new(item, "used", json_string(parts[2]));
            json_object_set_new(item, "available", json_string(parts[3]));
            json_object_set_new(item, "use%", json_string(parts[4]));
            json_object_set_new(item, "mount", json_string(parts[5]));
            json_array_append_new(results, item);
        }
        line = strtok_r(NULL, "\n", &saveptr_line);
    }
    free(out);
#elif defined(OS_WINDOWS)
    cmd = "wmic logicaldisk get size,freespace,caption";
    json_object_set_new(obj, "command", json_string(cmd));
    if (!command_available("wmic")) {
        json_object_set_new(obj, "error", json_string("wmic needs to be installed"));
        return obj;
    }
    char *out = run_command(cmd);
    if (!out) return obj;
    char *saveptr_line = NULL;
    char *line = strtok_r(out, "\n", &saveptr_line);
    if (line) line = strtok_r(NULL, "\n", &saveptr_line); /* skip header */
    while (line) {
        char *parts[3];
        int idx = 0;
        char *saveptr_tok = NULL;
        char *tok = strtok_r(line, " \t", &saveptr_tok);
        while (tok && idx < 3) {
            parts[idx++] = tok;
            tok = strtok_r(NULL, " \t", &saveptr_tok);
        }
        if (idx == 3) {
            const char *caption = parts[0];
            long long free_i = atoll(parts[1]);
            long long size_i = atoll(parts[2]);
            long long used_i = size_i - free_i;
            char usepct[32];
            if (size_i > 0)
                snprintf(usepct, sizeof(usepct), "%.1f%%", 100.0 * used_i / size_i);
            else
                strcpy(usepct, "0%");
            char size_s[32], used_s[32], free_s[32];
            snprintf(size_s, sizeof(size_s), "%lld", size_i);
            snprintf(used_s, sizeof(used_s), "%lld", used_i);
            snprintf(free_s, sizeof(free_s), "%lld", free_i);
            json_t *item = json_object();
            json_object_set_new(item, "filesystem", json_string(caption));
            json_object_set_new(item, "size", json_string(size_s));
            json_object_set_new(item, "used", json_string(used_s));
            json_object_set_new(item, "available", json_string(free_s));
            json_object_set_new(item, "use%", json_string(usepct));
            json_object_set_new(item, "mount", json_string(caption));
            json_array_append_new(results, item);
        }
        line = strtok_r(NULL, "\n", &saveptr_line);
    }
    free(out);
#elif defined(OS_DARWIN)
    cmd = "df -h";
    json_object_set_new(obj, "command", json_string(cmd));
    if (!command_available("df")) {
        json_object_set_new(obj, "error", json_string("df needs to be installed"));
        return obj;
    }
    char *out = run_command(cmd);
    if (!out) return obj;
    char *saveptr_line = NULL;
    char *line = strtok_r(out, "\n", &saveptr_line);
    if (line) line = strtok_r(NULL, "\n", &saveptr_line); /* skip header */
    while (line) {
        char *parts[6];
        int idx = 0;
        char *saveptr_tok = NULL;
        char *tok = strtok_r(line, " \t", &saveptr_tok);
        while (tok && idx < 6) {
            parts[idx++] = tok;
            tok = strtok_r(NULL, " \t", &saveptr_tok);
        }
        if (idx >= 6) {
            json_t *item = json_object();
            json_object_set_new(item, "filesystem", json_string(parts[0]));
            json_object_set_new(item, "size", json_string(parts[1]));
            json_object_set_new(item, "used", json_string(parts[2]));
            json_object_set_new(item, "available", json_string(parts[3]));
            json_object_set_new(item, "use%", json_string(parts[4]));
            json_object_set_new(item, "mount", json_string(parts[5]));
            json_array_append_new(results, item);
        }
        line = strtok_r(NULL, "\n", &saveptr_line);
    }
    free(out);
#else
    json_object_set_new(obj, "command", json_string(""));
    json_object_set_new(obj, "error", json_string("unsupported platform"));
#endif
    return obj;
}

static json_t *get_memory_usage(void) {
    json_t *obj = json_object();
    json_t *results = json_array();
    json_object_set_new(obj, "results", results);
    const char *cmd = "";
#ifdef OS_LINUX
    cmd = "free -h";
    json_object_set_new(obj, "command", json_string(cmd));
    if (!command_available("free")) {
        json_object_set_new(obj, "error", json_string("free needs to be installed"));
        return obj;
    }
    char *out = run_command(cmd);
    if (!out) return obj;
    char *saveptr_line = NULL;
    char *line = strtok_r(out, "\n", &saveptr_line);
    while (line) {
        char *lower = strdup(line);
        for (char *p = lower; *p; ++p) *p = tolower(*p);
        if (strncmp(lower, "mem:", 4) == 0 || strncmp(lower, "mem ", 4) == 0) {
            char *parts[4];
            int idx = 0;
            char *saveptr_tok = NULL;
            char *tok = strtok_r(line, " \t", &saveptr_tok);
            while (tok && idx < 4) {
                parts[idx++] = tok;
                tok = strtok_r(NULL, " \t", &saveptr_tok);
            }
            if (idx >= 4) {
                json_t *item = json_object();
                json_object_set_new(item, "total", json_string(parts[1]));
                json_object_set_new(item, "used", json_string(parts[2]));
                json_object_set_new(item, "free", json_string(parts[3]));
                json_array_append_new(results, item);
            }
        }
        free(lower);
        line = strtok_r(NULL, "\n", &saveptr_line);
    }
    free(out);
#elif defined(OS_WINDOWS)
    cmd = "wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /Value";
    json_object_set_new(obj, "command", json_string(cmd));
    if (!command_available("wmic")) {
        json_object_set_new(obj, "error", json_string("wmic needs to be installed"));
        return obj;
    }
    char *out = run_command(cmd);
    if (!out) return obj;
    char *saveptr_line = NULL;
    char *line = strtok_r(out, "\n", &saveptr_line);
    long long total_kb = 0, free_kb = 0;
    while (line) {
        char *eq = strchr(line, '=');
        if (eq) {
            *eq = '\0';
            char *key = line;
            char *val = eq + 1;
            while (*val == ' ' || *val == '\t') val++;
            if (strcmp(key, "TotalVisibleMemorySize") == 0)
                total_kb = atoll(val);
            else if (strcmp(key, "FreePhysicalMemory") == 0)
                free_kb = atoll(val);
        }
        line = strtok_r(NULL, "\n", &saveptr_line);
    }
    if (total_kb > 0) {
        long long used_kb = total_kb - free_kb;
        char total_s[32], used_s[32], free_s[32];
        snprintf(total_s, sizeof(total_s), "%lldM", total_kb / 1024);
        snprintf(used_s, sizeof(used_s), "%lldM", used_kb / 1024);
        snprintf(free_s, sizeof(free_s), "%lldM", free_kb / 1024);
        json_t *item = json_object();
        json_object_set_new(item, "total", json_string(total_s));
        json_object_set_new(item, "used", json_string(used_s));
        json_object_set_new(item, "free", json_string(free_s));
        json_array_append_new(results, item);
    }
    free(out);
#elif defined(OS_DARWIN)
    cmd = "vm_stat";
    json_object_set_new(obj, "command", json_string(cmd));
    if (!command_available("vm_stat")) {
        json_object_set_new(obj, "error", json_string("vm_stat needs to be installed"));
        return obj;
    }
    char *out = run_command(cmd);
    if (!out) return obj;
    long long page_size = 4096;
    long long free = 0, active = 0, inactive = 0;
    char *saveptr_line = NULL;
    char *line = strtok_r(out, "\n", &saveptr_line);
    while (line) {
        char *colon = strchr(line, ':');
        if (colon) {
            *colon = '\0';
            char *key = line;
            char *val = colon + 1;
            while (*val == ' ' || *val == '\t') val++;
            long long pages = atoll(val);
            if (strcmp(key, "Pages free") == 0)
                free = pages * page_size;
            else if (strcmp(key, "Pages active") == 0)
                active = pages * page_size;
            else if (strcmp(key, "Pages inactive") == 0)
                inactive = pages * page_size;
        }
        line = strtok_r(NULL, "\n", &saveptr_line);
    }
    long long used = active + inactive;
    long long total = used + free;
    if (total > 0) {
        char total_s[32], used_s[32], free_s[32];
        snprintf(total_s, sizeof(total_s), "%lldM", total / (1024 * 1024));
        snprintf(used_s, sizeof(used_s), "%lldM", used / (1024 * 1024));
        snprintf(free_s, sizeof(free_s), "%lldM", free / (1024 * 1024));
        json_t *item = json_object();
        json_object_set_new(item, "total", json_string(total_s));
        json_object_set_new(item, "used", json_string(used_s));
        json_object_set_new(item, "free", json_string(free_s));
        json_array_append_new(results, item);
    }
    free(out);
#else
    json_object_set_new(obj, "command", json_string(""));
    json_object_set_new(obj, "error", json_string("unsupported platform"));
#endif
    return obj;
}

static json_t *get_uptime(void) {
    json_t *obj = json_object();
    json_t *results = json_array();
    json_object_set_new(obj, "results", results);
    const char *cmd = "";
#if defined(OS_LINUX) || defined(OS_DARWIN)
    cmd = "uptime -p";
    json_object_set_new(obj, "command", json_string(cmd));
    if (!command_available("uptime")) {
        json_object_set_new(obj, "error", json_string("uptime needs to be installed"));
        return obj;
    }
    char *out = run_command(cmd);
    if (out) {
        char *start = out;
        while (*start && (*start == '\n' || *start == '\r')) start++;
        char *end = start + strlen(start);
        while (end > start && (end[-1] == '\n' || end[-1] == '\r')) end--;
        *end = '\0';
        json_array_append_new(results, json_string(start));
        free(out);
    }
#elif defined(OS_WINDOWS)
    cmd = "wmic os get lastbootuptime";
    json_object_set_new(obj, "command", json_string(cmd));
    if (!command_available("wmic")) {
        json_object_set_new(obj, "error", json_string("wmic needs to be installed"));
        return obj;
    }
    char *out = run_command(cmd);
    if (out) {
        char *line = strtok(out, "\n");
        char *boot = NULL;
        while (line) {
            while (*line == ' ' || *line == '\t') line++;
            if (*line && strncmp(line, "LastBootUpTime", 13) != 0) { boot = line; break; }
            line = strtok(NULL, "\n");
        }
        if (boot) {
            char ts[15];
            strncpy(ts, boot, 14);
            ts[14] = '\0';
            struct tm tm = {0};
            if (strptime(ts, "%Y%m%d%H%M%S", &tm)) {
                time_t boot_t = mktime(&tm);
                time_t now = time(NULL);
                long diff = difftime(now, boot_t);
                int days = diff / 86400;
                int hours = (diff % 86400) / 3600;
                int minutes = (diff % 3600) / 60;
                char buf[128];
                snprintf(buf, sizeof(buf), "%d days, %d hours, %d minutes", days, hours, minutes);
                json_array_append_new(results, json_string(buf));
            }
        }
        free(out);
    }
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
    char *saveptr_line = NULL;
    char *line = strtok_r(out, "\n", &saveptr_line);
    char current_port[32] = "";
    int collecting = 0;
    while (line) {
        char *trim = line;
        while (*trim == ' ' || *trim == '\t') trim++;
        if (strncmp(trim, "| vulners:", 10) == 0) {
            collecting = 1;
            line = strtok_r(NULL, "\n", &saveptr_line);
            continue;
        }
        if (collecting) {
            if (*trim != '|') { collecting = 0; line = strtok_r(NULL, "\n", &saveptr_line); continue; }
            char *content = trim + 1;
            while (*content == ' ') content++;
            char *parts[4];
            int idx = 0;
            char *saveptr_tok = NULL;
            char *tok = strtok_r(content, " \t", &saveptr_tok);
            while (tok && idx < 4) {
                parts[idx++] = tok;
                tok = strtok_r(NULL, " \t", &saveptr_tok);
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
        line = strtok_r(NULL, "\n", &saveptr_line);
    }
    free(out);
    return obj;
}

int main(void) {
    json_t *root = json_object();

    fprintf(stderr, "loading...\n");
    const int total = 7;
    int i = 0;
    double start = get_time_seconds();

    json_object_set_new(root, "ip_addresses", get_ip_addresses());
    print_progress(++i, total);
    json_object_set_new(root, "open_ports", get_open_ports());
    print_progress(++i, total);
    json_object_set_new(root, "running_services", get_running_services());
    print_progress(++i, total);
    json_object_set_new(root, "disk_usage", get_disk_usage());
    print_progress(++i, total);
    json_object_set_new(root, "memory", get_memory_usage());
    print_progress(++i, total);
    json_object_set_new(root, "uptime", get_uptime());
    print_progress(++i, total);
    json_object_set_new(root, "vulnerabilities", scan_vulnerabilities("127.0.0.1"));
    print_progress(++i, total);

    double elapsed = get_time_seconds() - start;
    fprintf(stderr, "Completed in %.2f seconds\n", elapsed);

    json_dumpf(root, stdout, JSON_INDENT(2));
    json_decref(root);
    return 0;
}

