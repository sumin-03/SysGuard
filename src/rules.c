#include "rules.h"
#include <string.h>
#include <stdio.h>

const char *sysguard_severity_string(enum sysguard_severity severity) {
    switch (severity) {
        case SYSGUARD_SEV_LOW:      return "LOW";
        case SYSGUARD_SEV_MEDIUM:   return "MEDIUM";
        case SYSGUARD_SEV_HIGH:     return "HIGH";
        case SYSGUARD_SEV_CRITICAL: return "CRITICAL";
        default:                    return "UNKNOWN";
    }
}

static const char *suspicious_commands[] = {
    "curl", "wget", "nc", "ncat", "nmap",
    "tcpdump", "strace", "ltrace", "gdb",
    "chmod", "chown", "useradd", "passwd",
    "base64", "xxd", "dd",
    NULL
};

static const char *sensitive_files[] = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/root/.ssh",
    "/root/.bash_history",
    "/proc/kcore",
    "/var/log/auth.log",
    NULL
};

int rules_evaluate(const struct sysguard_event *ev, struct sysguard_alert *out) {
    memset(out, 0, sizeof(*out));
    out->timestamp_ns = ev->timestamp_ns;
    out->pid = ev->pid;
    out->ppid = ev->ppid;
    out->uid = ev->uid;
    strncpy(out->comm, ev->comm, sizeof(out->comm) - 1);

    const char *filename = (ev->type == SYSGUARD_EVENT_EXEC) ? ev->exe_path : ev->path;

    if (ev->type == SYSGUARD_EVENT_EXEC) {
        for (int i = 0; suspicious_commands[i]; i++) {
            if (strstr(ev->comm, suspicious_commands[i]) ||
                (filename && strstr(filename, suspicious_commands[i]))) {
                out->severity = SYSGUARD_SEV_MEDIUM;
                snprintf(out->rule_id, sizeof(out->rule_id), "SUSPICIOUS_EXEC");
                snprintf(out->reason, sizeof(out->reason),
                         "Suspicious command executed: %s", ev->comm);
                snprintf(out->recommendation, sizeof(out->recommendation),
                         "Review process execution logs.");
                return 1;
            }
        }
    }

    if (ev->type == SYSGUARD_EVENT_OPEN) {
        for (int i = 0; sensitive_files[i]; i++) {
            if (filename && strstr(filename, sensitive_files[i])) {
                out->severity = SYSGUARD_SEV_CRITICAL;
                snprintf(out->rule_id, sizeof(out->rule_id), "SENSITIVE_FILE_ACCESS");
                snprintf(out->reason, sizeof(out->reason),
                         "Sensitive file accessed: %s by %s (pid %u)",
                         filename, ev->comm, ev->pid);
                snprintf(out->recommendation, sizeof(out->recommendation),
                         "Check user authorization.");
                return 1;
            }
        }
    }

    return 0;
}