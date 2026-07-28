#define _GNU_SOURCE   /* expose O_TMPFILE from <fcntl.h> */
#include "rules.h"
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

/* Note: the C engine has no system-path READ allowlist. Reads never raise an
 * alert here (the only openat rules are the protected-path rules and the
 * mutation-only outside-project-write rule), so routine system reads already
 * produce no output — an allowlist would be dead weight. System-path *writes*
 * are intentionally NOT exempt: writing to /usr, /etc, /opt, ... is a
 * persistence/tampering signal. The read-noise allowlist lives only in
 * app/policy.py, where it trims the informational read sample. */

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

/* True when a CONNECT destination is NOT outbound: an unspecified, loopback, or
 * link-local address, or a non-IP family. Deliberately does NOT treat RFC1918 /
 * IPv6 ULA as local — connecting to another host on a private LAN is still
 * outbound from the monitored process. Operates on the binary dest_addr bytes. */
static int connect_is_local(const struct sysguard_event *ev) {
    const unsigned char *a = ev->dest_addr;
    if (ev->addr_family == AF_INET) {
        if (a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0) return 1;  /* 0.0.0.0 */
        if (a[0] == 127) return 1;                        /* 127.0.0.0/8 loopback */
        if (a[0] == 169 && a[1] == 254) return 1;         /* 169.254/16 link-local */
        return 0;
    }
    if (ev->addr_family == AF_INET6) {
        int hi_zero = 1;
        for (int i = 0; i < 15; i++) if (a[i]) { hi_zero = 0; break; }
        if (hi_zero && a[15] == 0) return 1;              /* :: unspecified */
        if (hi_zero && a[15] == 1) return 1;              /* ::1 loopback */
        if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) return 1; /* fe80::/10 link-local */
        return 0;
    }
    return 1;  /* AF_UNIX / unsupported / unparsed -> not an outbound IP target */
}

/* Render a CONNECT destination as "ip:port" (IPv4) or "[ip]:port" (IPv6) for
 * human-facing reason text. Mirrors the JSONL address renderer. */
static void format_connect_endpoint(char *dst, size_t sz, const struct sysguard_event *ev) {
    char ip[64] = "";
    if (ev->addr_family == AF_INET) {
        struct in_addr a;
        memcpy(&a, ev->dest_addr, sizeof(a));
        if (inet_ntop(AF_INET, &a, ip, sizeof(ip)))
            snprintf(dst, sz, "%s:%u", ip, (unsigned)ev->dest_port);
        else
            snprintf(dst, sz, "(unknown):%u", (unsigned)ev->dest_port);
    } else if (ev->addr_family == AF_INET6) {
        struct in6_addr a6;
        memcpy(&a6, ev->dest_addr, sizeof(a6));
        if (inet_ntop(AF_INET6, &a6, ip, sizeof(ip)))
            snprintf(dst, sz, "[%s]:%u", ip, (unsigned)ev->dest_port);
        else
            snprintf(dst, sz, "[unknown]:%u", (unsigned)ev->dest_port);
    } else {
        snprintf(dst, sz, "(unknown)");
    }
}

/* True if an openat with these flags can MUTATE the filesystem (write / create
 * / truncate / append). O_RDONLY|O_CREAT still creates, so check the bits, not
 * only the access mode. Must match app/policy.py's open_flags_may_mutate. */
static int open_flags_may_mutate(int32_t flags) {
    int acc = flags & O_ACCMODE;
    if (acc == O_WRONLY || acc == O_RDWR)
        return 1;
    if (flags & (O_CREAT | O_TRUNC | O_APPEND))
        return 1;
#ifdef O_TMPFILE
    if ((flags & O_TMPFILE) == O_TMPFILE)
        return 1;
#endif
    return 0;
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

        /* outside-project-write: an openat that can MUTATE a file outside the
         * configured project root. Evaluated LAST in the OPEN branch so the
         * protected-path rules above win by first-match. Read-only outside-
         * project access (an agent reading its own runtime/config/caches/certs)
         * is routine and NOT flagged — only writes/creates are. The system
         * allowlist deliberately does NOT apply here: writing to /usr, /etc,
         * /opt, /run, etc. is a persistence/tampering signal, so the allowlist
         * only ever suppresses informational reads, never mutations. */
        if (boundary_ctx_valid(ctx) &&
            ev->path[0] == '/' &&
            open_flags_may_mutate(ev->flags) &&
            !path_is_inside_project(ev->path, ctx->project_path)) {
            char reason[256];
            snprintf(reason, sizeof(reason),
                     "Write/create outside project boundary: %s (flags 0x%x, project root %s)",
                     ev->path, (unsigned)ev->flags, ctx->project_path);
            fill_alert(out, ev, "outside-project-write", SYSGUARD_SEV_HIGH,
                       reason, "Verify writes/creates outside the project directory were intended.");
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

    if (ev->type == SYSGUARD_EVENT_CONNECT) {
        /* outbound-connect: an IP connection attempt leaving the local host.
         * Loopback/link-local/unspecified and non-IP families are excluded.
         * Captured at syscall entry, so this is an attempt, not a success. */
        if ((ev->addr_family == AF_INET || ev->addr_family == AF_INET6)
                && !connect_is_local(ev)) {
            char endpoint[96], reason[256];
            format_connect_endpoint(endpoint, sizeof(endpoint), ev);
            snprintf(reason, sizeof(reason),
                     "Outbound connection attempt to %s by %s (pid %u)",
                     endpoint, ev->comm, ev->pid);
            fill_alert(out, ev, "outbound-connect", SYSGUARD_SEV_MEDIUM,
                       reason, "Verify the destination and that the connection was intended.");
            return 1;
        }
    }

    return 0;
}
