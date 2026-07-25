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

/* Read-only system locations every process touches at startup (loader, libs,
 * locale, /proc self-inspection, common tool config). Mirrors app/policy.py's
 * SYSTEM_PATH_PREFIXES so terminal/JSONL are not flooded with boundary HIGH
 * alerts for routine system access. Genuinely sensitive system files
 * (/etc/shadow, /etc/sudoers, ~/.ssh, ...) are still caught by the protected
 * rules above, which run first by first-match ordering. */
static const char *system_path_prefixes[] = {
    "/usr/", "/lib/", "/lib64/", "/opt/",
    "/proc/", "/sys/", "/dev/", "/run/",
    "/etc/ld.so", "/etc/locale", "/etc/nsswitch.conf",
    "/etc/passwd", "/etc/group", "/etc/localtime",
    "/etc/gitconfig", "/etc/gitattributes",
    "/etc/terminfo", "/etc/inputrc", "/etc/bash",
};

/* Benign per-user tool config, matched as a substring (mirrors policy.py). */
static const char *user_config_suffixes[] = {
    "/.gitconfig", "/.config/git/",
};

static int path_is_system_allowlisted(const char *path) {
    if (!path || !path[0]) return 0;
    for (size_t i = 0; i < sizeof(system_path_prefixes) / sizeof(system_path_prefixes[0]); i++) {
        if (strncmp(path, system_path_prefixes[i], strlen(system_path_prefixes[i])) == 0)
            return 1;
    }
    for (size_t i = 0; i < sizeof(user_config_suffixes) / sizeof(user_config_suffixes[0]); i++) {
        if (strstr(path, user_config_suffixes[i]))
            return 1;
    }
    return 0;
}

/* The boundary rule is only meaningful with an absolute project root. A NULL
 * ctx, NULL/empty project_path, or a relative root ("." etc.) disables it. */
static int boundary_ctx_valid(const struct sysguard_rule_ctx *ctx) {
    return ctx && ctx->project_path && ctx->project_path[0] == '/';
}

/* Component-aware containment. A single trailing '/' on the root is ignored so
 * "/p" and "/p/" behave identically. The path is inside iff it equals the root
 * exactly or begins with root + "/". This keeps "/work/project2" out of
 * "/work/project". A root of "/" contains every absolute path. Lexical only —
 * symlink/realpath resolution is the Python layer's job. */
static int path_is_inside_project(const char *path, const char *project_path) {
    size_t rlen = strlen(project_path);
    if (rlen > 1 && project_path[rlen - 1] == '/')
        rlen--;                       /* ignore one trailing slash */
    if (rlen <= 1)
        return path[0] == '/';        /* root is "/" -> all absolute paths inside */
    if (strncmp(path, project_path, rlen) != 0)
        return 0;
    return path[rlen] == '\0' || path[rlen] == '/';
}

int rules_evaluate(const struct sysguard_event *ev,
                   const struct sysguard_rule_ctx *ctx,
                   struct sysguard_alert *out) {
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
        /* downloader-exec: curl/wget executed. Match on exe_path/argv (the
         * program that actually ran), never comm — at execve entry comm is the
         * CALLER (e.g. the shell), not the downloader itself. See event.h
         * FIELD SEMANTICS. */
        {
            const char *dl[] = {"curl", "wget"};
            if (match_any(ev->exe_path, dl, 2) || match_any(ev->argv, dl, 2)) {
                char reason[256];
                snprintf(reason, sizeof(reason), "Downloader executed: %s",
                         ev->exe_path[0] ? ev->exe_path : ev->argv);
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

        /* project-boundary-access: openat of an absolute path outside the
         * configured project root. Evaluated LAST in the OPEN branch so the
         * specific protected-path rules above win by first-match, and skipped
         * for routine system/tool-config paths so it does not flood alerts. */
        if (boundary_ctx_valid(ctx) &&
            ev->path[0] == '/' &&
            !path_is_system_allowlisted(ev->path) &&
            !path_is_inside_project(ev->path, ctx->project_path)) {
            char reason[256];
            snprintf(reason, sizeof(reason),
                     "File accessed outside project boundary: %s (project root %s)",
                     ev->path, ctx->project_path);
            fill_alert(out, ev, "project-boundary-access", SYSGUARD_SEV_HIGH,
                       reason, "Investigate access outside the project directory.");
            return 1;
        }
    }

    if (ev->type == SYSGUARD_EVENT_UNLINK) {
        /* file-unlink: a deletion was requested (captured at syscall entry, so
         * this records the attempt, not a confirmed removal). */
        char reason[256];
        snprintf(reason, sizeof(reason),
                 "File deletion requested: %s by %s (pid %u)",
                 ev->path, ev->comm, ev->pid);
        fill_alert(out, ev, "file-unlink", SYSGUARD_SEV_MEDIUM,
                   reason, "Verify the file was meant to be removed. Check git status.");
        return 1;
    }

    if (ev->type == SYSGUARD_EVENT_CHMOD) {
        /* unsafe-chmod: world-writable bit (0002) requested via fchmodat. mode
         * is a permission bitmask, so match bits and render the reason in octal
         * (e.g. 0777), never the decimal value. */
        if ((ev->mode & 0002) != 0) {
            char reason[256];
            snprintf(reason, sizeof(reason),
                     "World-writable permission set: chmod %o on %s by %s",
                     (unsigned int)(ev->mode & 07777), ev->path, ev->comm);
            fill_alert(out, ev, "unsafe-chmod", SYSGUARD_SEV_HIGH,
                       reason, "Restrict permissions to the minimum required.");
            return 1;
        }
    }

    return 0;
}
