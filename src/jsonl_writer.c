#include "jsonl_writer.h"
#include <string.h>

FILE *jsonl_open(const char *path) {
    return fopen(path, "a");
}

static void esc(char *dst, size_t sz, const char *src) {
    size_t j = 0;
    if (!src) { dst[0] = '\0'; return; }
    for (size_t i = 0; src[i] && j < sz - 2; i++) {
        if (src[i] == '"' || src[i] == '\\') dst[j++] = '\\';
        dst[j++] = src[i];
    }
    dst[j] = '\0';
}

static const char *event_str(uint32_t t) {
    switch (t) {
        case SYSGUARD_EVENT_EXEC:   return "execve";
        case SYSGUARD_EVENT_OPEN:   return "openat";
        case SYSGUARD_EVENT_UNLINK: return "unlinkat";
        case SYSGUARD_EVENT_RENAME: return "renameat";
        case SYSGUARD_EVENT_CHMOD:  return "fchmodat";
        case SYSGUARD_EVENT_EXIT:   return "exit_group";
        default:                    return "unknown";
    }
}

void jsonl_write_event(FILE *fp, const struct sysguard_event *ev,
                        const char *session_id, const char *project_path,
                        const char *target_comm) {
    if (!fp || !ev) return;
    char c[64], ep[512], av[512], p[512], si[128], pp[512], tc[64];
    esc(c,  sizeof(c),  ev->comm);
    esc(ep, sizeof(ep), ev->exe_path);
    esc(av, sizeof(av), ev->argv);
    esc(p,  sizeof(p),  ev->path);
    esc(si, sizeof(si), session_id);
    esc(pp, sizeof(pp), project_path);
    esc(tc, sizeof(tc), target_comm);

    fprintf(fp,
        "{\"timestamp_ns\":%llu,\"session_id\":\"%s\","
        "\"event\":\"%s\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,"
        "\"comm\":\"%s\",\"argv\":\"%s\",\"path\":\"%s\","
        "\"project_path\":\"%s\",\"target_comm\":\"%s\"}\n",
        (unsigned long long)ev->timestamp_ns, si,
        event_str(ev->type), ev->pid, ev->ppid, ev->uid,
        c, ev->type == SYSGUARD_EVENT_EXEC ? av : "",
        ev->type == SYSGUARD_EVENT_OPEN ? p : (ev->type == SYSGUARD_EVENT_EXEC ? ep : p),
        pp, tc);
    fflush(fp);
}

void jsonl_write_alert(FILE *fp, const struct sysguard_event *ev,
                        const struct sysguard_alert *a,
                        const char *session_id, const char *project_path,
                        const char *target_comm) {
    if (!fp || !a) return;
    char c[64], ri[128], re[512], rc[512], ep[512], p[512], av[512];
    char si[128], pp[512], tc[64];
    esc(c,  sizeof(c),  a->comm);
    esc(ri, sizeof(ri), a->rule_id);
    esc(re, sizeof(re), a->reason);
    esc(rc, sizeof(rc), a->recommendation);
    esc(si, sizeof(si), session_id);
    esc(pp, sizeof(pp), project_path);
    esc(tc, sizeof(tc), target_comm);
    ep[0] = p[0] = av[0] = '\0';
    if (ev) {
        esc(ep, sizeof(ep), ev->exe_path);
        esc(p,  sizeof(p),  ev->path);
        esc(av, sizeof(av), ev->argv);
    }

    fprintf(fp,
        "{\"timestamp_ns\":%llu,\"session_id\":\"%s\","
        "\"event\":\"%s\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,"
        "\"comm\":\"%s\",\"argv\":\"%s\",\"path\":\"%s\","
        "\"project_path\":\"%s\",\"target_comm\":\"%s\","
        "\"alert\":true,\"rule_id\":\"%s\",\"severity\":\"%s\","
        "\"reason\":\"%s\",\"recommendation\":\"%s\"}\n",
        (unsigned long long)a->timestamp_ns, si,
        ev ? event_str(ev->type) : "unknown",
        a->pid, a->ppid, a->uid, c,
        ev ? av : "", ev ? p : "",
        pp, tc,
        ri, sysguard_severity_string(a->severity), re, rc);
    fflush(fp);
}

void jsonl_close(FILE *fp) {
    if (fp) fclose(fp);
}
