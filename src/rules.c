#include "rules.h"
#include <string.h>
#include <stdio.h>

const char *sysguard_severity_string(enum sysguard_severity severity) {
    switch (severity) {
        case SYSGUARD_SEV_LOW:      return "low";
        case SYSGUARD_SEV_MEDIUM:   return "medium";
        case SYSGUARD_SEV_HIGH:     return "high";
        case SYSGUARD_SEV_CRITICAL: return "critical";
        default:                    return "unknown";
    }
}

static int match_any(const char *haystack, const char *needles[], int count) {
    if (!haystack || !haystack[0]) return 0;
    for (int i = 0; i < count; i++) {
        if (strstr(haystack, needles[i])) return 1;
    }
    return 0;
}

static void fill_alert(struct sysguard_alert *out, const struct sysguard_event *ev,
                        const char *rule_id, enum sysguard_severity sev,
                        const char *reason, const char *rec) {
    out->timestamp_ns = ev->timestamp_ns;
    out->pid  = ev->pid;
    out->ppid = ev->ppid;
    out->uid  = ev->uid;
    strncpy(out->comm, ev->comm, sizeof(out->comm) - 1);
    strncpy(out->rule_id, rule_id, sizeof(out->rule_id) - 1);
    out->severity = sev;
    snprintf(out->reason, sizeof(out->reason), "%s", reason);
    snprintf(out->recommendation, sizeof(out->recommendation), "%s", rec);
}

int rules_evaluate(const struct sysguard_event *ev, struct sysguard_alert *out) {
    memset(out, 0, sizeof(*out));

    if (ev->type == SYSGUARD_EVENT_EXEC) {
        /* shadow access via exec (unlikely but safe to check) */
        if (strstr(ev->argv, "git reset --hard") || strstr(ev->exe_path, "git reset --hard")) {
            char reason[256];
            snprintf(reason, sizeof(reason), "Destructive git command: %s", ev->argv);
            fill_alert(out, ev, "git-reset-hard", SYSGUARD_SEV_HIGH,
                       reason, "Review git reflog and verify intended changes.");
            return 1;
        }
        if (strstr(ev->argv, "git clean -fd") || strstr(ev->argv, "git clean -f")) {
            char reason[256];
            snprintf(reason, sizeof(reason), "Destructive git command: %s", ev->argv);
            fill_alert(out, ev, "git-clean-force", SYSGUARD_SEV_HIGH,
                       reason, "Check for untracked files that may have been lost.");
            return 1;
        }
        if (strstr(ev->argv, "rm -rf") || strstr(ev->argv, "rm -r")) {
            char reason[256];
            snprintf(reason, sizeof(reason), "Destructive remove command: %s", ev->argv);
            fill_alert(out, ev, "destructive-rm", SYSGUARD_SEV_HIGH,
                       reason, "Verify target directory. Check git status for lost files.");
            return 1;
        }
        if (strstr(ev->argv, "chmod 777") || strstr(ev->argv, "chmod a+rwx")) {
            char reason[256];
            snprintf(reason, sizeof(reason), "Unsafe permission change: %s", ev->argv);
            fill_alert(out, ev, "unsafe-chmod", SYSGUARD_SEV_MEDIUM,
                       reason, "Restrict permissions to minimum required.");
            return 1;
        }
        if (strstr(ev->argv, "chown root")) {
            char reason[256];
            snprintf(reason, sizeof(reason), "Ownership change to root: %s", ev->argv);
            fill_alert(out, ev, "unsafe-chown", SYSGUARD_SEV_HIGH,
                       reason, "Verify ownership change is intentional.");
            return 1;
        }

        /* shell-exec */
        {
            const char *shells[] = {"bash", "sh", "zsh"};
            if (match_any(ev->comm, shells, 3)) {
                char reason[256];
                snprintf(reason, sizeof(reason), "Shell process executed: %s", ev->comm);
                fill_alert(out, ev, "shell-exec", SYSGUARD_SEV_MEDIUM,
                           reason, "Review shell command context.");
                return 1;
            }
        }

        /* suspicious-netcat */
        {
            const char *nc[] = {"nc", "netcat", "ncat"};
            if (match_any(ev->comm, nc, 3) || match_any(ev->exe_path, nc, 3)) {
                char reason[256];
                snprintf(reason, sizeof(reason), "Netcat-like tool executed: %s", ev->comm);
                fill_alert(out, ev, "suspicious-netcat", SYSGUARD_SEV_HIGH,
                           reason, "Investigate network activity. Check for reverse shell.");
                return 1;
            }
        }

        /* downloader-exec */
        {
            const char *dl[] = {"curl", "wget"};
            if (match_any(ev->comm, dl, 2) || match_any(ev->exe_path, dl, 2)) {
                char reason[256];
                snprintf(reason, sizeof(reason), "Downloader executed: %s", ev->comm);
                fill_alert(out, ev, "downloader-exec", SYSGUARD_SEV_MEDIUM,
                           reason, "Check download target and destination.");
                return 1;
            }
        }
    }

    if (ev->type == SYSGUARD_EVENT_OPEN) {
        /* sensitive-shadow-access */
        if (strstr(ev->path, "/etc/shadow")) {
            char reason[256];
            snprintf(reason, sizeof(reason), "/etc/shadow accessed by %s (pid %u)", ev->comm, ev->pid);
            fill_alert(out, ev, "shadow-access", SYSGUARD_SEV_CRITICAL,
                       reason, "Verify authorization. This file contains password hashes.");
            return 1;
        }

        /* sudoers-access */
        if (strstr(ev->path, "/etc/sudoers")) {
            char reason[256];
            snprintf(reason, sizeof(reason), "/etc/sudoers accessed by %s (pid %u)", ev->comm, ev->pid);
            fill_alert(out, ev, "sudoers-access", SYSGUARD_SEV_HIGH,
                       reason, "Check for privilege escalation attempt.");
            return 1;
        }

        /* docker-sock-access */
        if (strstr(ev->path, "/var/run/docker.sock")) {
            char reason[256];
            snprintf(reason, sizeof(reason), "Docker socket accessed by %s (pid %u)", ev->comm, ev->pid);
            fill_alert(out, ev, "docker-sock-access", SYSGUARD_SEV_HIGH,
                       reason, "Docker socket access can lead to container escape.");
            return 1;
        }

        /* ssh-key-access */
        if (strstr(ev->path, ".ssh/id_rsa") || strstr(ev->path, ".ssh/id_ed25519") ||
            strstr(ev->path, ".ssh/config")) {
            char reason[256];
            snprintf(reason, sizeof(reason), "SSH key/config accessed: %s by %s", ev->path, ev->comm);
            fill_alert(out, ev, "ssh-key-access", SYSGUARD_SEV_CRITICAL,
                       reason, "Check whether SSH credentials were exposed.");
            return 1;
        }

        /* env-file-access */
        if (strstr(ev->path, ".env")) {
            char reason[256];
            snprintf(reason, sizeof(reason), ".env file accessed: %s by %s (pid %u)", ev->path, ev->comm, ev->pid);
            fill_alert(out, ev, "env-file-access", SYSGUARD_SEV_HIGH,
                       reason, "Review whether secrets were exposed. Rotate API keys if needed.");
            return 1;
        }

        /* aws-credentials */
        if (strstr(ev->path, ".aws/credentials")) {
            char reason[256];
            snprintf(reason, sizeof(reason), "AWS credentials accessed: %s by %s", ev->path, ev->comm);
            fill_alert(out, ev, "aws-cred-access", SYSGUARD_SEV_CRITICAL,
                       reason, "Rotate AWS access keys immediately if exposure is suspected.");
            return 1;
        }
    }

    return 0;
}
