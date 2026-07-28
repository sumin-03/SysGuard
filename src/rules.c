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

/* --- TASK-B-012: write classification by EFFECT ----------------------------
 * These tables MIRROR app/policy.py (RUNTIME_NOISE_* / PERSIST_*). The shared
 * parity fixture in tests/ exercises both engines with the same rows; keep the
 * two in step when editing either. Matching is exact / prefix / component-aware
 * — never a bare substring like "/.cache/" — so an exempt runtime directory
 * cannot be turned into a hiding place by an adjacent path. */

/* Agent/toolchain bookkeeping writes, relative to the monitored home. See the
 * limitation note in app/policy.py: session-env and plugins/cache are exempted
 * by path alone, an accepted cache-poisoning / session-script tradeoff. */
static const char *runtime_noise_home_prefixes[] = {
    ".claude/projects/", ".claude/sessions/", ".claude/backups/",
    ".claude/file-history/",
    ".claude/session-env/", ".claude/plugins/cache/",
    ".npm/_cacache/", ".npm/_logs/",
    ".cache/claude-cli-nodejs/", ".config/Code/logs/",
    ".claude/shell-snapshots/",
};
static const char *runtime_noise_home_exact[] = {
    ".claude/history.jsonl",
};
/* No-op sinks and the exact kernel tracing markers (never all of /dev|/proc|/sys). */
static const char *runtime_noise_abs_exact[] = {
    "/dev/null", "/dev/tty",
    "/sys/kernel/debug/tracing/trace_marker",
    "/sys/kernel/tracing/trace_marker",
};

/* Deletion is NOT the same as writing: the write-noise set must not be reused
 * wholesale. Deleting ~/.claude/history.jsonl, backups/ or file-history/ is
 * destructive, and unlinking /dev/null or a kernel trace marker is not routine
 * bookkeeping. Only genuinely disposable locations. Mirrors
 * RUNTIME_NOISE_DELETION_HOME_PREFIXES in app/policy.py. */
static const char *runtime_noise_deletion_home_prefixes[] = {
    ".npm/_cacache/", ".npm/_logs/",
    ".cache/claude-cli-nodejs/", ".config/Code/logs/",
};

/* Persistence / activation targets: a MUTATION here is UNSAFE. Reads are
 * ordinary — shells read .bashrc on every invocation. */
static const char *persist_home_exact[] = {
    ".bashrc", ".bash_profile", ".profile",
    ".zshrc", ".zprofile", ".zlogin", ".zshenv",
    ".gitconfig", ".config/git/config",
    ".claude.json", ".claude/settings.json", ".claude/settings.local.json",
    ".ssh/authorized_keys", ".ssh/authorized_keys2",
};
static const char *persist_home_prefixes[] = {
    ".config/autostart/", ".config/systemd/user/",
    ".local/share/systemd/user/", ".config/environment.d/",
};
static const char *persist_abs_exact[] = {
    "/etc/crontab", "/etc/profile", "/etc/bash.bashrc",
    "/etc/ld.so.preload", "/etc/ld.so.conf",
};
static const char *persist_abs_prefixes[] = {
    "/etc/cron.d/", "/var/spool/cron/",
    "/etc/systemd/system/", "/run/systemd/system/",
    "/usr/lib/systemd/system/", "/lib/systemd/system/",
    "/etc/profile.d/", "/etc/zsh/", "/etc/ld.so.conf.d/",
};

/* renameat2 RENAME_EXCHANGE (linux/fs.h): the two paths are SWAPPED, so both
 * are mutated. Defined locally so <linux/fs.h> is not required. */
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

static int str_in(const char *s, const char *list[], size_t n) {
    if (!s || !s[0]) return 0;
    for (size_t i = 0; i < n; i++)
        if (strcmp(s, list[i]) == 0) return 1;
    return 0;
}

static int has_prefix_in(const char *s, const char *list[], size_t n) {
    if (!s || !s[0]) return 0;
    for (size_t i = 0; i < n; i++)
        if (strncmp(s, list[i], strlen(list[i])) == 0) return 1;
    return 0;
}

/* A home is usable for home-relative matching only when absolute and not "/". */
static int home_ctx_valid(const struct sysguard_rule_ctx *ctx) {
    return ctx && ctx->home_path && ctx->home_path[0] == '/' && ctx->home_path[1] != '\0';
}

/* Return the portion of `path` under the monitored home (".bashrc"), or NULL. */
static const char *home_relative(const char *path, const struct sysguard_rule_ctx *ctx) {
    if (!home_ctx_valid(ctx) || !path || path[0] != '/') return NULL;
    size_t hlen = strlen(ctx->home_path);
    while (hlen > 1 && ctx->home_path[hlen - 1] == '/') hlen--;   /* ignore trailing '/' */
    if (strncmp(path, ctx->home_path, hlen) != 0) return NULL;
    if (path[hlen] != '/') return NULL;
    return path + hlen + 1;
}

/* NOTE (documented limitation): this engine matches paths LEXICALLY — it runs in
 * the real-time hot path and cannot stat/realpath every event. A symlink under
 * /tmp could therefore make an exempt-looking scratch path resolve elsewhere.
 * app/policy.py, which owns the user-visible verdict, resolves these paths and
 * refuses the exemption on any mismatch (`_tmp_path_is_redirected`), so the
 * reported verdict is not affected. See README §6.
 *
 * Agent scratch under /tmp: "/tmp/claude-<uid>/..." or "/tmp/claude-<id>-cwd".
 * Deliberately NOT all of /tmp — only the writer's OWN run directory (the
 * numeric component must equal `uid`, so a monitored process cannot hide writes
 * behind a predictable name like /tmp/claude-9999/) and cwd markers. Mirrors
 * _TMP_AGENT_*_RE in app/policy.py. */
static int is_tmp_agent_scratch(const char *path, uint32_t uid) {
    static const char *pfx = "/tmp/claude-";
    size_t plen = strlen(pfx);
    if (strncmp(path, pfx, plen) != 0) return 0;
    const char *p = path + plen;
    /* "/tmp/claude-<uid>/" -> the writer's own uid-scoped run directory. The
     * component is bounded to 10 digits (uid_t is 32-bit) and accumulated in a
     * 64-bit value, so a crafted over-long number cannot wrap around to match. */
    const char *d = p;
    unsigned long long n = 0;
    int digits = 0;
    while (*d >= '0' && *d <= '9') {
        if (++digits > 10) return 0;            /* longer than any uid -> reject */
        n = n * 10ULL + (unsigned long long)(*d - '0');
        d++;
    }
    if (digits > 0 && *d == '/') {
        /* Canonical spelling only: "/tmp/claude-00001000/" is an attacker-chosen
         * directory, not the agent's actual runtime dir, so a leading zero is
         * rejected rather than compared numerically. uid 0 never qualifies. */
        if (p[0] == '0') return 0;
        return n <= 0xFFFFFFFFULL && n == (unsigned long long)uid;
    }
    /* "/tmp/claude-<lowercase-hex>-cwd", exact, 4..16 hex digits — deliberately
     * narrow, since the name alone is not an authenticator (/tmp is
     * world-writable). Cross-account planting cannot reach this rule: the
     * collector only emits events from the monitored process subtree, so the
     * writer is always the agent or its children. A prompt-injected child
     * writing here is the documented tradeoff class shared with session-env /
     * shell-snapshots (README §6). */
    const char *a = p;
    int hex = 0;
    while ((*a >= '0' && *a <= '9') || (*a >= 'a' && *a <= 'f')) { a++; hex++; }
    return hex >= 4 && hex <= 16 && strcmp(a, "-cwd") == 0;
}

/* Background-job bookkeeping under ".claude/jobs/": "pins.json", or
 * "<job>/timeline.jsonl" / "<job>/state.json[.tmp.<hex>]". Matched as specific
 * files, NOT as a subtree, so ".claude/jobs/x/payload" stays reportable.
 * Mirrors _CLAUDE_JOBS_RE in app/policy.py. */
static int is_claude_jobs_file(const char *rel) {
    static const char *pfx = ".claude/jobs/";
    size_t plen = strlen(pfx);
    if (strncmp(rel, pfx, plen) != 0) return 0;
    const char *p = rel + plen;
    if (strcmp(p, "pins.json") == 0) return 1;
    const char *slash = strchr(p, '/');
    if (!slash || slash == p) return 0;          /* need a <job> component */
    const char *file = slash + 1;
    if (!*file || strchr(file, '/')) return 0;   /* exactly one more component */
    if (strcmp(file, "timeline.jsonl") == 0) return 1;
    if (strcmp(file, "state.json") == 0) return 1;
    static const char *sp = "state.json.tmp.";
    size_t splen = strlen(sp);
    if (strncmp(file, sp, splen) != 0) return 0;
    const char *h = file + splen;
    if (!*h) return 0;
    for (; *h; h++) {
        int hex = (*h >= '0' && *h <= '9') || (*h >= 'a' && *h <= 'f') ||
                  (*h >= 'A' && *h <= 'F');
        if (!hex) return 0;
    }
    return 1;
}

/* .claude.json.tmp.<decimal-pid>.<hex> directly under home (atomic staging). */
static int is_claude_json_tmp(const char *rel) {
    static const char *pfx = ".claude.json.tmp.";
    size_t plen = strlen(pfx);
    if (!rel || strncmp(rel, pfx, plen) != 0) return 0;
    const char *p = rel + plen;
    if (!(*p >= '0' && *p <= '9')) return 0;            /* pid: 1+ digits */
    while (*p >= '0' && *p <= '9') p++;
    if (*p != '.') return 0;
    p++;
    if (!*p) return 0;                                   /* hex: 1+ digits */
    for (; *p; p++) {
        int hex = (*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') ||
                  (*p >= 'A' && *p <= 'F');
        if (!hex) return 0;
    }
    return 1;
}

/* True when any component of `path` is "." or ".." — a lexical prefix match
 * cannot then be trusted to describe the real target. */
static int path_has_dot_segment(const char *path) {
    if (!path) return 0;
    const char *p = path;
    while (*p) {
        const char *seg = p;
        while (*p && *p != '/') p++;
        size_t len = (size_t)(p - seg);
        if ((len == 1 && seg[0] == '.') || (len == 2 && seg[0] == '.' && seg[1] == '.'))
            return 1;
        while (*p == '/') p++;
    }
    return 0;
}

/* Lexically collapse "." and ".." components (no symlink resolution — the
 * kernel-side path is already absolute). Mirrors Python's os.path.normpath for
 * the shapes we match on. Returns `out`, or `path` when it does not fit. */
static const char *normalize_lexical(const char *path, char *out, size_t out_sz) {
    if (!path || path[0] != '/' || out_sz < 2) return path;
    size_t w = 0;
    out[w++] = '/';
    const char *p = path + 1;
    while (*p) {
        const char *seg = p;
        while (*p && *p != '/') p++;
        size_t len = (size_t)(p - seg);
        if (len == 1 && seg[0] == '.') {
            /* skip */
        } else if (len == 2 && seg[0] == '.' && seg[1] == '.') {
            while (w > 1 && out[w - 1] != '/') w--;      /* drop trailing name */
            if (w > 1) w--;                              /* drop its '/' */
            if (w == 0) out[w++] = '/';
        } else if (len > 0) {
            if (w > 1) {
                if (w + 1 >= out_sz) return path;
                out[w++] = '/';
            }
            if (w + len >= out_sz) return path;
            memcpy(out + w, seg, len);
            w += len;
        }
        while (*p == '/') p++;
    }
    if (w == 0) out[w++] = '/';
    out[w] = '\0';
    return out;
}

/* Protected/sensitive targets, in the same order and with the same substrings
 * the OPEN branch uses. Shared so a rename DESTINATION gets identical
 * precedence: staging a file in an exempt runtime dir and renaming it onto
 * ~/.aws/credentials or .env must not slip through unreported. Returns the
 * rule_id and severity, or NULL when the path is not protected. */
static const char *path_protected_rule(const char *path, enum sysguard_severity *sev) {
    if (!path || !path[0]) return NULL;
    if (strstr(path, "/etc/shadow"))        { *sev = SYSGUARD_SEV_CRITICAL; return "shadow-access"; }
    if (strstr(path, "/etc/sudoers"))       { *sev = SYSGUARD_SEV_HIGH;     return "sudoers-access"; }
    if (strstr(path, ".ssh/id_rsa") || strstr(path, ".ssh/id_ed25519") ||
        strstr(path, ".ssh/config"))        { *sev = SYSGUARD_SEV_CRITICAL; return "ssh-key-access"; }
    if (strstr(path, ".aws/credentials"))   { *sev = SYSGUARD_SEV_CRITICAL; return "aws-credentials-access"; }
    if (strstr(path, "config/secrets.json")){ *sev = SYSGUARD_SEV_HIGH;     return "secrets-file-access"; }
    if (strstr(path, ".env"))               { *sev = SYSGUARD_SEV_HIGH;     return "env-file-access"; }
    return NULL;
}

/* Trusted per-session toolchain temp root (--tool-tmp), i.e. the TMPDIR handed
 * to the monitored agent. Unlike /tmp/cc* filename matching, this is an exact
 * root agreed in advance and validated by main.c (absolute, owned by the
 * monitored uid, mode 0700), so an attacker cannot forge membership by choosing
 * a filename. `gcc -o /tmp/payload` still lands outside it and stays reported. */
static int path_in_tool_tmp(const char *path, const struct sysguard_rule_ctx *ctx) {
    if (!ctx || !ctx->tool_tmp_path || ctx->tool_tmp_path[0] != '/') return 0;
    if (!path || path[0] != '/') return 0;
    if (path_has_dot_segment(path)) return 0;
    size_t rlen = strlen(ctx->tool_tmp_path);
    while (rlen > 1 && ctx->tool_tmp_path[rlen - 1] == '/') rlen--;
    /* "/" would make every absolute path a member — never a valid root. */
    if (rlen < 2) return 0;
    if (strncmp(path, ctx->tool_tmp_path, rlen) != 0) return 0;
    return path[rlen] == '/' && path[rlen + 1] != '\0';
}

/* Narrowly recognized agent/toolchain bookkeeping write -> informational. */
static int path_is_runtime_noise(const char *path, const struct sysguard_rule_ctx *ctx,
                                 uint32_t uid) {
    /* Never exempt a path we cannot read literally: traversal defeats prefix
     * matching, so fail closed and let it be reported. */
    if (path_has_dot_segment(path)) return 0;
    if (str_in(path, runtime_noise_abs_exact, ARRAY_LEN(runtime_noise_abs_exact)))
        return 1;
    if (path_in_tool_tmp(path, ctx))
        return 1;
    if (is_tmp_agent_scratch(path, uid))
        return 1;
    const char *rel = home_relative(path, ctx);
    if (!rel) return 0;
    if (str_in(rel, runtime_noise_home_exact, ARRAY_LEN(runtime_noise_home_exact)))
        return 1;
    if (!strchr(rel, '/') && is_claude_json_tmp(rel))
        return 1;
    if (is_claude_jobs_file(rel))
        return 1;
    return has_prefix_in(rel, runtime_noise_home_prefixes, ARRAY_LEN(runtime_noise_home_prefixes));
}

/* Deletion of a genuinely disposable runtime artifact -> informational.
 * Narrower than path_is_runtime_noise by design; callers must run the protected
 * and persistence checks first. */
static int path_is_runtime_noise_deletion(const char *path,
                                          const struct sysguard_rule_ctx *ctx,
                                          uint32_t uid) {
    if (path_has_dot_segment(path)) return 0;
    if (path_in_tool_tmp(path, ctx)) return 1;
    if (is_tmp_agent_scratch(path, uid)) return 1;
    const char *rel = home_relative(path, ctx);
    if (!rel) return 0;
    if (!strchr(rel, '/') && is_claude_json_tmp(rel)) return 1;
    return has_prefix_in(rel, runtime_noise_deletion_home_prefixes,
                         ARRAY_LEN(runtime_noise_deletion_home_prefixes));
}

/* Mutation of these is a persistence/activation risk -> critical. */
static int path_is_persistence_sensitive(const char *path, const struct sysguard_rule_ctx *ctx) {
    if (!path || !path[0]) return 0;
    /* Collapse "." / ".." so traversal cannot evade DETECTION either. */
    char norm_buf[SYSGUARD_MAX_PATH];
    if (path_has_dot_segment(path))
        path = normalize_lexical(path, norm_buf, sizeof(norm_buf));
    if (str_in(path, persist_abs_exact, ARRAY_LEN(persist_abs_exact))) return 1;
    if (has_prefix_in(path, persist_abs_prefixes, ARRAY_LEN(persist_abs_prefixes))) return 1;
    if (strstr(path, "/.git/hooks/")) return 1;   /* complete path component */
    const char *rel = home_relative(path, ctx);
    if (!rel) return 0;
    if (str_in(rel, persist_home_exact, ARRAY_LEN(persist_home_exact))) return 1;
    return has_prefix_in(rel, persist_home_prefixes, ARRAY_LEN(persist_home_prefixes));
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

        /* persistence-sensitive-write: a MUTATION of a persistence/activation
         * target (shell startup files, authorized_keys, cron, systemd units,
         * autostart, git hooks, live agent config, ld.so preload). Evaluated
         * after the protected rules but BEFORE the boundary rule, and before any
         * runtime-noise exemption, so severity always wins. Reads are ordinary:
         * a shell reads .bashrc on every invocation. Fires regardless of whether
         * the target is inside or outside the project (a .git/hooks write inside
         * the repo is still persistence). */
        if (open_flags_may_mutate(ev->flags) &&
            path_is_persistence_sensitive(ev->path, ctx)) {
            char reason[256];
            snprintf(reason, sizeof(reason),
                     "Write to persistence/activation target: %s (flags 0x%x)",
                     ev->path, (unsigned)ev->flags);
            fill_alert(out, ev, "persistence-sensitive-write", SYSGUARD_SEV_CRITICAL,
                       reason,
                       "Verify this was intended and inspect the target for injected commands.");
            return 1;
        }

        /* outside-project-write: an openat that can MUTATE a file outside the
         * configured project root. Evaluated LAST in the OPEN branch so the
         * protected-path and persistence rules above win by first-match.
         * Read-only outside-project access (an agent reading its own runtime/
         * config/caches/certs) is routine and NOT flagged — only writes/creates
         * are. The system allowlist deliberately does NOT apply here: writing to
         * /usr, /etc, /opt, /run, etc. is a persistence/tampering signal.
         * Narrowly recognized runtime bookkeeping writes (the agent's own
         * session state, npm/IDE caches and logs, atomic config staging) are
         * informational and produce no alert. */
        if (boundary_ctx_valid(ctx) &&
            ev->path[0] == '/' &&
            open_flags_may_mutate(ev->flags) &&
            !path_is_inside_project(ev->path, ctx->project_path) &&
            !path_is_runtime_noise(ev->path, ctx, ev->uid)) {
            char reason[256];
            snprintf(reason, sizeof(reason),
                     "Write/create outside project boundary: %s (flags 0x%x, project root %s)",
                     ev->path, (unsigned)ev->flags, ctx->project_path);
            fill_alert(out, ev, "outside-project-write", SYSGUARD_SEV_HIGH,
                       reason, "Verify writes/creates outside the project directory were intended.");
            return 1;
        }
    }

    if (ev->type == SYSGUARD_EVENT_RENAME) {
        /* A rename is classified by its DESTINATION, with the same precedence as
         * an open: protected first, then persistence, then an ordinary outside
         * target. Otherwise a file staged in an exempt runtime directory could be
         * renamed onto .env / credentials / ~/.claude.json, or out to
         * /tmp/payload, and never be reported.
         *
         * RENAME_EXCHANGE swaps the two files, so under that flag BOTH paths are
         * destinations and both must be classified. */
        const char *targets[2];
        int n_targets = 0;
        if (ev->new_path[0]) targets[n_targets++] = ev->new_path;
        if ((ev->flags & RENAME_EXCHANGE) && ev->old_path[0])
            targets[n_targets++] = ev->old_path;

        /* Severity-major ordering: this engine returns ONE alert, so a
         * protected or persistence target must win no matter which side of the
         * exchange it is on. Scanning target-by-target would let an ordinary
         * outside new_path mask a critical old_path. */
        for (int t = 0; t < n_targets; t++) {
            enum sysguard_severity psev;
            const char *prule = path_protected_rule(targets[t], &psev);
            if (prule) {
                char reason[256];
                snprintf(reason, sizeof(reason),
                         "Protected path %s by rename: %s <-> %s",
                         (ev->flags & RENAME_EXCHANGE) ? "exchanged" : "replaced",
                         ev->old_path, ev->new_path);
                fill_alert(out, ev, prule, psev, reason,
                           "Verify the replacement was intended. Rotate the affected credentials if exposure is possible.");
                return 1;
            }
        }
        for (int t = 0; t < n_targets; t++) {
            if (path_is_persistence_sensitive(targets[t], ctx)) {
                char reason[256];
                snprintf(reason, sizeof(reason),
                         "Rename onto persistence/activation target: %s", targets[t]);
                fill_alert(out, ev, "persistence-sensitive-write", SYSGUARD_SEV_CRITICAL,
                           reason,
                           "Verify this was intended and inspect the target for injected commands.");
                return 1;
            }
        }
        for (int t = 0; t < n_targets; t++) {
            const char *dest = targets[t];
            if (boundary_ctx_valid(ctx) && dest && dest[0] == '/' &&
                !path_is_inside_project(dest, ctx->project_path) &&
                !path_is_runtime_noise(dest, ctx, ev->uid)) {
                char reason[256];
                snprintf(reason, sizeof(reason),
                         "Rename to a target outside project boundary: %s (project root %s)",
                         dest, ctx->project_path);
                fill_alert(out, ev, "outside-project-write", SYSGUARD_SEV_HIGH,
                           reason, "Verify writes/creates outside the project directory were intended.");
                return 1;
            }
        }
    }

    if (ev->type == SYSGUARD_EVENT_UNLINK) {
        /* A deletion gets the same precedence as an open: protected, then
         * persistence, then the (narrower) deletion-safe runtime set, then the
         * ordinary review signal. Removing an activation target mutates it — a
         * deleted authorized_keys or shell rc changes what runs next time — so a
         * protected-looking target must not become informational just because an
         * outer directory is exempt. */
        enum sysguard_severity dsev;
        const char *drule = path_protected_rule(ev->path, &dsev);
        if (drule) {
            char reason[256];
            snprintf(reason, sizeof(reason),
                     "Protected path deletion requested: %s by %s (pid %u)",
                     ev->path, ev->comm, ev->pid);
            fill_alert(out, ev, drule, dsev, reason,
                       "Verify the removal was authorized. Rotate the affected credentials if exposure is possible.");
            return 1;
        }
        if (path_is_persistence_sensitive(ev->path, ctx)) {
            char reason[256];
            snprintf(reason, sizeof(reason),
                     "Deletion of persistence/activation target: %s by %s (pid %u)",
                     ev->path, ev->comm, ev->pid);
            fill_alert(out, ev, "persistence-sensitive-write", SYSGUARD_SEV_CRITICAL,
                       reason,
                       "Verify this was intended; removing an activation target changes what runs next session.");
            return 1;
        }
        /* Disposable runtime artifact (own scratch, staging, caches/logs) —
         * informational, no real-time alert. */
        if (path_is_runtime_noise_deletion(ev->path, ctx, ev->uid))
            return 0;

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
