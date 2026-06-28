#include "jsonl_writer.h"
#include <time.h>
#include <string.h>

FILE *jsonl_open(const char *path) {
    return fopen(path, "a");
}

static void escape_json(char *dst, size_t dst_sz, const char *src) {
    size_t j = 0;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    for (size_t i = 0; src[i] && j < dst_sz - 2; i++) {
        if (src[i] == '"' || src[i] == '\\') {
            dst[j++] = '\\';
        }
        dst[j++] = src[i];
    }
    dst[j] = '\0';
}

static const char *event_type_str(enum sysguard_event_type t) {
    return t == SYSGUARD_EVENT_EXEC ? "execve" : "openat";
}

void jsonl_write_event(FILE *fp, const struct sysguard_event *ev) {
    if (!fp || !ev) return;
    char comm_esc[128], exe_path_esc[512], path_esc[512];
    escape_json(comm_esc, sizeof(comm_esc), ev->comm);
    escape_json(exe_path_esc, sizeof(exe_path_esc), ev->exe_path);
    escape_json(path_esc, sizeof(path_esc), ev->path);

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", tm);

    fprintf(fp,
        "{\"timestamp_ns\":%llu,\"type\":%u,"
        "\"pid\":%u,\"ppid\":%u,\"uid\":%u,"
        "\"comm\":\"%s\",\"exe_path\":\"%s\",\"path\":\"%s\"}\n",
        (unsigned long long)ev->timestamp_ns, ev->type,
        ev->pid, ev->ppid, ev->uid,
        comm_esc, exe_path_esc, path_esc);
    fflush(fp);
}

void jsonl_write_alert(FILE *fp, const struct sysguard_event *ev, const struct sysguard_alert *a) {
    if (!fp || !a) return;
    char comm_esc[128], rule_id_esc[128], reason_esc[512], rec_esc[512];
    char exe_path_esc[512] = {0}, path_esc[512] = {0};
    
    escape_json(comm_esc, sizeof(comm_esc), a->comm);
    escape_json(rule_id_esc, sizeof(rule_id_esc), a->rule_id);
    escape_json(reason_esc, sizeof(reason_esc), a->reason);
    escape_json(rec_esc, sizeof(rec_esc), a->recommendation);

    if (ev) {
        escape_json(exe_path_esc, sizeof(exe_path_esc), ev->exe_path);
        escape_json(path_esc, sizeof(path_esc), ev->path);
    }

    fprintf(fp,
        "{\"timestamp_ns\":%llu,\"type\":%u,\"rule_id\":\"%s\",\"severity\":%d,"
        "\"pid\":%u,\"ppid\":%u,\"uid\":%u,"
        "\"comm\":\"%s\",\"reason\":\"%s\",\"recommendation\":\"%s\","
        "\"exe_path\":\"%s\",\"path\":\"%s\",\"alert\":true}\n",
        (unsigned long long)a->timestamp_ns, ev->type, rule_id_esc, a->severity,
        a->pid, a->ppid, a->uid,
        comm_esc, reason_esc, rec_esc,
        exe_path_esc, path_esc);
    fflush(fp);
}

void jsonl_close(FILE *fp) {
    if (fp) fclose(fp);
}
