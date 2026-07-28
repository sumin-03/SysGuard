#include "jsonl_writer.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

FILE *jsonl_open(const char *path) {
    return fopen(path, "a");
}

// JSON string escape. Besides '"' and '\\', control characters (e.g. the
// newlines in a multi-line `python3 -c ...` argv) must be escaped or the
// JSONL line breaks apart and the Python analyzer cannot parse the session.
static void esc(char *dst, size_t sz, const char *src) {
    size_t j = 0;
    if (!src) { dst[0] = '\0'; return; }
    for (size_t i = 0; src[i] && j + 7 < sz; i++) {
        unsigned char c = (unsigned char)src[i];
        switch (c) {
            case '"':  dst[j++] = '\\'; dst[j++] = '"';  break;
            case '\\': dst[j++] = '\\'; dst[j++] = '\\'; break;
            case '\n': dst[j++] = '\\'; dst[j++] = 'n';  break;
            case '\t': dst[j++] = '\\'; dst[j++] = 't';  break;
            case '\r': dst[j++] = '\\'; dst[j++] = 'r';  break;
            default:
                if (c < 0x20) {
                    j += snprintf(dst + j, sz - j, "\\u%04x", c);
                } else {
                    dst[j++] = (char)c;
                }
        }
    }
    dst[j] = '\0';
}

static const char *event_str(uint32_t t) {
    switch (t) {
        case SYSGUARD_EVENT_EXEC:   return "execve";
        case SYSGUARD_EVENT_OPEN:   return "openat";
        case SYSGUARD_EVENT_UNLINK: return "unlinkat";
        case SYSGUARD_EVENT_RENAME: return "renameat2";
        case SYSGUARD_EVENT_CHMOD:  return "fchmodat";
        case SYSGUARD_EVENT_CONNECT:return "connect";
        case SYSGUARD_EVENT_EXIT:   return "exit_group";
        default:                    return "unknown";
    }
}

// Render the binary connect destination into a printable string (empty for
// non-connect / unsupported family / render failure). The wire struct stays
// binary; JSON consumers get plain text so they never decode bytes themselves.
static void render_dest_addr(char *dst, size_t sz, const struct sysguard_event *ev) {
    dst[0] = '\0';
    if (!ev) return;
    if (ev->addr_family == AF_INET) {
        struct in_addr a;
        memcpy(&a, ev->dest_addr, sizeof(a));
        if (!inet_ntop(AF_INET, &a, dst, sz)) dst[0] = '\0';
    } else if (ev->addr_family == AF_INET6) {
        struct in6_addr a6;
        memcpy(&a6, ev->dest_addr, sizeof(a6));
        if (!inet_ntop(AF_INET6, &a6, dst, sz)) dst[0] = '\0';
    }
}

void jsonl_write_event(FILE *fp, const struct sysguard_event *ev,
                        const char *session_id, const char *project_path,
                        const char *target_comm, const char *home_path) {
    if (!fp || !ev) return;
    char c[64], ep[512], av[512], p[512], op[512], np[512], si[128], pp[512], tc[64];
    char da_raw[64], da[128];
    esc(c,  sizeof(c),  ev->comm);
    esc(ep, sizeof(ep), ev->exe_path);
    esc(av, sizeof(av), ev->argv);
    esc(p,  sizeof(p),  ev->path);
    esc(op, sizeof(op), ev->old_path);
    esc(np, sizeof(np), ev->new_path);
    esc(si, sizeof(si), session_id);
    esc(pp, sizeof(pp), project_path);
    esc(tc, sizeof(tc), target_comm);
    char hp[SYSGUARD_MAX_PATH * 2];
    esc(hp, sizeof(hp), home_path);
    render_dest_addr(da_raw, sizeof(da_raw), ev);
    esc(da, sizeof(da), da_raw);

    // old_path/new_path/flags/mode/addr_family/dest_addr/dest_port are additive
    // fields: readers that ignore unknown keys keep working, while
    // rename/chmod/open/connect evidence is preserved.
    fprintf(fp,
        "{\"timestamp_ns\":%llu,\"session_id\":\"%s\","
        "\"event\":\"%s\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,"
        "\"comm\":\"%s\",\"argv\":\"%s\",\"path\":\"%s\","
        "\"old_path\":\"%s\",\"new_path\":\"%s\",\"flags\":%d,\"mode\":%d,"
        "\"addr_family\":%d,\"dest_addr\":\"%s\",\"dest_port\":%u,"
        "\"project_path\":\"%s\",\"target_comm\":\"%s\",\"home_path\":\"%s\"}\n",
        (unsigned long long)ev->timestamp_ns, si,
        event_str(ev->type), ev->pid, ev->ppid, ev->uid,
        c, ev->type == SYSGUARD_EVENT_EXEC ? av : "",
        ev->type == SYSGUARD_EVENT_OPEN ? p : (ev->type == SYSGUARD_EVENT_EXEC ? ep : p),
        op, np, ev->flags, ev->mode,
        ev->addr_family, da, (unsigned)ev->dest_port,
        pp, tc, hp);
    fflush(fp);
}

void jsonl_write_alert(FILE *fp, const struct sysguard_event *ev,
                        const struct sysguard_alert *a,
                        const char *session_id, const char *project_path,
                        const char *target_comm, const char *home_path) {
    if (!fp || !a) return;
    char c[64], ri[128], re[512], rc[512], ep[512], p[512], av[512], op[512], np[512];
    char si[128], pp[512], tc[64], da_raw[64], da[128];
    esc(c,  sizeof(c),  a->comm);
    esc(ri, sizeof(ri), a->rule_id);
    esc(re, sizeof(re), a->reason);
    esc(rc, sizeof(rc), a->recommendation);
    esc(si, sizeof(si), session_id);
    esc(pp, sizeof(pp), project_path);
    esc(tc, sizeof(tc), target_comm);
    char hp[SYSGUARD_MAX_PATH * 2];
    esc(hp, sizeof(hp), home_path);
    ep[0] = p[0] = av[0] = op[0] = np[0] = '\0';
    render_dest_addr(da_raw, sizeof(da_raw), ev);
    esc(da, sizeof(da), da_raw);
    if (ev) {
        esc(ep, sizeof(ep), ev->exe_path);
        esc(p,  sizeof(p),  ev->path);
        esc(av, sizeof(av), ev->argv);
        esc(op, sizeof(op), ev->old_path);
        esc(np, sizeof(np), ev->new_path);
    }

    // Same syscall payload fields as jsonl_write_event so alert and non-alert
    // records stay structurally consistent.
    fprintf(fp,
        "{\"timestamp_ns\":%llu,\"session_id\":\"%s\","
        "\"event\":\"%s\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,"
        "\"comm\":\"%s\",\"argv\":\"%s\",\"path\":\"%s\","
        "\"old_path\":\"%s\",\"new_path\":\"%s\",\"flags\":%d,\"mode\":%d,"
        "\"addr_family\":%d,\"dest_addr\":\"%s\",\"dest_port\":%u,"
        "\"project_path\":\"%s\",\"target_comm\":\"%s\",\"home_path\":\"%s\","
        "\"alert\":true,\"rule_id\":\"%s\",\"severity\":\"%s\","
        "\"reason\":\"%s\",\"recommendation\":\"%s\"}\n",
        (unsigned long long)a->timestamp_ns, si,
        ev ? event_str(ev->type) : "unknown",
        a->pid, a->ppid, a->uid, c,
        ev && ev->type == SYSGUARD_EVENT_EXEC ? av : "",
        ev && ev->type == SYSGUARD_EVENT_EXEC ? ep : p,
        op, np, ev ? ev->flags : 0, ev ? ev->mode : 0,
        ev ? ev->addr_family : 0, da, (unsigned)(ev ? ev->dest_port : 0),
        pp, tc, hp,
        ri, sysguard_severity_string(a->severity), re, rc);
    fflush(fp);
}

void jsonl_close(FILE *fp) {
    if (fp) fclose(fp);
}
