#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <pwd.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>
#include "collector.h"
#include "target_filter.h"

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig) {
    (void)sig;
    running = 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --output <path.jsonl> [options]\n"
        "\n"
        "Options:\n"
        "  --output <path>      Path for the JSONL session log (required)\n"
        "  --fake               Use the fake event generator (no root/eBPF)\n"
        "  --agent-mode         Mark this run as AI-agent monitoring\n"
        "  --target-comm <name> Scope to a process (e.g. claude) + its children\n"
        "  --target-pid <pid>   Scope to a PID + its children\n"
        "  --project-path <dir> Project root recorded for boundary analysis\n"
        "  --session-id <id>    Session identifier (defaults to the output stem)\n"
        "  --home-path <dir>    Monitored user's home (default: the invoking\n"
        "                       non-root user's home, SUDO_USER-aware)\n"
        "  --tool-tmp <dir>     Trusted TMPDIR handed to the agent, so build\n"
        "                       toolchain temp files are classified as runtime\n"
        "                       noise. Must be absolute, owned by the monitored\n"
        "                       user and mode 0700, or it is refused.\n",
        prog);
    exit(1);
}

// Resolve the MONITORED user's home directory, never root's. Under sudo the
// invoking user is recovered from SUDO_UID/SUDO_USER, so ~/.claude and friends
// resolve to the human's home rather than /root. On failure the buffer is left
// empty, which disables every home-relative match (fail closed).
static void resolve_monitored_home(char *dst, size_t dst_sz) {
    dst[0] = '\0';
    uid_t uid = 0;
    const char *sudo_uid = getenv("SUDO_UID");
    if (sudo_uid && sudo_uid[0]) {
        // Require the WHOLE value to be numeric: a malformed SUDO_UID must not
        // silently decay to 0 (root) via strtoul's partial-parse behavior.
        char *end = NULL;
        unsigned long parsed = strtoul(sudo_uid, &end, 10);
        if (!end || *end != '\0' || parsed == 0 || parsed > 0xFFFFFFFFUL)
            return;   // malformed, or root -> no trusted home
        uid = (uid_t)parsed;
    } else {
        uid = geteuid();
    }
    // Root has no "monitored user" home: never trust /root for the home-relative
    // exemptions, or a write under /root could be silently exempted.
    if (uid == 0)
        return;
    struct passwd *pw = getpwuid(uid);
    if (!pw || !pw->pw_dir || pw->pw_dir[0] != '/' || !pw->pw_dir[1])
        return;   // lookup failed, or the home is unusable ("/" / relative)
    snprintf(dst, dst_sz, "%s", pw->pw_dir);
}

// Derive a session id from the output path when --session-id is omitted:
// "logs/session_20260701_001500.jsonl" -> "session_20260701_001500".
static void derive_session_id(char *dst, size_t dst_sz, const char *output) {
    const char *base = strrchr(output, '/');
    base = base ? base + 1 : output;
    snprintf(dst, dst_sz, "%s", base);
    char *ext = strstr(dst, ".jsonl");
    if (ext)
        *ext = '\0';
}

// Accept a --tool-tmp root only when it cannot be used as a hiding place by
// anyone but the monitored user: absolute, no trailing '/', no "." / ".."
// components, fully canonical (no symlink in ANY component), an existing real
// directory, owned by the monitored uid, and mode 0700. Anything else is refused
// with a warning, leaving toolchain temp files reportable.
//
// Residual risk (documented): validation happens once at startup, so the
// monitored user could replace the directory afterwards (TOCTOU). The C engine
// matches lexically and cannot re-check per event in the hot path; the Python
// verdict layer independently resolves each candidate path and refuses the
// exemption when it no longer resolves to itself. See README section 6.
static int tool_tmp_is_trusted(const char *dir, uid_t owner) {
    if (!dir || dir[0] != '/') {
        fprintf(stderr, "[WARN] --tool-tmp must be an absolute path; ignoring.\n");
        return 0;
    }
    // A trailing slash makes the kernel resolve a final symlink before lstat(),
    // so "/tmp/link/" would report the TARGET and sail past the symlink check
    // while the rules still match the lexical (symlinked) prefix. Refuse it.
    size_t dlen = strlen(dir);
    if (dlen > 1 && dir[dlen - 1] == '/') {
        fprintf(stderr, "[WARN] --tool-tmp must not end with '/'; ignoring.\n");
        return 0;
    }
    if (dlen < 2) {
        fprintf(stderr, "[WARN] --tool-tmp must not be the filesystem root; ignoring.\n");
        return 0;
    }
    if (strstr(dir, "/../") || strstr(dir, "/./") ||
        (dlen >= 3 && strcmp(dir + dlen - 3, "/..") == 0) ||
        (dlen >= 2 && strcmp(dir + dlen - 2, "/.") == 0)) {
        fprintf(stderr, "[WARN] --tool-tmp must not contain '.' or '..'; ignoring.\n");
        return 0;
    }
    struct stat st;
    if (lstat(dir, &st) != 0) {
        fprintf(stderr, "[WARN] --tool-tmp '%s' does not exist; ignoring.\n", dir);
        return 0;
    }
    if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) {
        fprintf(stderr, "[WARN] --tool-tmp '%s' is not a real directory; ignoring.\n", dir);
        return 0;
    }
    // lstat() only inspects the FINAL component, so a symlinked parent
    // ("/tmp/link/tool-tmp") would still pass. The rules match the lexical
    // prefix, so such a root could redirect writes outside the trusted tree.
    // Require the path to be fully canonical: realpath() resolves every
    // component, and any difference means some component was a symlink.
    char resolved[PATH_MAX];
    if (!realpath(dir, resolved)) {
        fprintf(stderr, "[WARN] --tool-tmp '%s' cannot be resolved; ignoring.\n", dir);
        return 0;
    }
    if (strcmp(resolved, dir) != 0) {
        fprintf(stderr,
                "[WARN] --tool-tmp '%s' contains a symlinked component (resolves to '%s'); ignoring.\n",
                dir, resolved);
        return 0;
    }
    if (st.st_uid != owner) {
        fprintf(stderr, "[WARN] --tool-tmp '%s' is not owned by uid %u; ignoring.\n",
                dir, (unsigned)owner);
        return 0;
    }
    if ((st.st_mode & 07777) != 0700) {
        fprintf(stderr, "[WARN] --tool-tmp '%s' must be mode 0700 (is %04o); ignoring.\n",
                dir, (unsigned)(st.st_mode & 07777));
        return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    const char *output = NULL;
    const char *target_comm = NULL;
    const char *project_path = NULL;
    const char *session_id = NULL;
    const char *home_path = NULL;
    const char *tool_tmp = NULL;
    unsigned long target_pid = 0;
    int fake = 0;
    int agent_mode = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--fake") == 0) {
            fake = 1;
        } else if (strcmp(argv[i], "--agent-mode") == 0) {
            agent_mode = 1;
        } else if (strcmp(argv[i], "--output") == 0) {
            if (++i >= argc) usage(argv[0]);
            output = argv[i];
        } else if (strcmp(argv[i], "--target-comm") == 0) {
            if (++i >= argc) usage(argv[0]);
            target_comm = argv[i];
        } else if (strcmp(argv[i], "--target-pid") == 0) {
            if (++i >= argc) usage(argv[0]);
            target_pid = strtoul(argv[i], NULL, 10);
        } else if (strcmp(argv[i], "--project-path") == 0) {
            if (++i >= argc) usage(argv[0]);
            project_path = argv[i];
        } else if (strcmp(argv[i], "--session-id") == 0) {
            if (++i >= argc) usage(argv[0]);
            session_id = argv[i];
        } else if (strcmp(argv[i], "--home-path") == 0) {
            if (++i >= argc) usage(argv[0]);
            home_path = argv[i];
        } else if (strcmp(argv[i], "--tool-tmp") == 0) {
            if (++i >= argc) usage(argv[0]);
            tool_tmp = argv[i];
        } else {
            usage(argv[0]);
        }
    }

    if (!output) {
        fprintf(stderr, "[ERROR] --output is required.\n\n");
        usage(argv[0]);
    }

    // Build the session metadata handed to the collector / JSONL writer.
    struct sysguard_session session;
    memset(&session, 0, sizeof(session));
    if (session_id)
        snprintf(session.session_id, sizeof(session.session_id), "%s", session_id);
    else
        derive_session_id(session.session_id, sizeof(session.session_id), output);
    if (project_path)
        snprintf(session.project_path, sizeof(session.project_path), "%s", project_path);
    if (target_comm)
        snprintf(session.target_comm, sizeof(session.target_comm), "%s", target_comm);
    if (home_path)
        snprintf(session.home_path, sizeof(session.home_path), "%s", home_path);
    else
        resolve_monitored_home(session.home_path, sizeof(session.home_path));
    if (tool_tmp) {
        // Trust is anchored to the home we just resolved: the temp root must
        // belong to the same monitored user, never to root or a third party.
        struct stat hst;
        uid_t owner = (uid_t)-1;
        if (session.home_path[0] && stat(session.home_path, &hst) == 0)
            owner = hst.st_uid;
        if (owner != (uid_t)-1 && owner != 0 && tool_tmp_is_trusted(tool_tmp, owner)) {
            // Never store a TRUNCATED root: a shortened prefix would exempt
            // sibling paths that were never validated (e.g. ".../tool-tmp" cut
            // to ".../tool" would also cover ".../tooling/").
            if (strlen(tool_tmp) >= sizeof(session.tool_tmp))
                fprintf(stderr,
                        "[WARN] --tool-tmp path is too long (max %zu bytes); ignoring.\n",
                        sizeof(session.tool_tmp) - 1);
            else
                snprintf(session.tool_tmp, sizeof(session.tool_tmp), "%s", tool_tmp);
        } else if (owner == (uid_t)-1 || owner == 0)
            fprintf(stderr, "[WARN] --tool-tmp needs a trusted monitored home; ignoring.\n");
    }
    session.agent_mode = agent_mode;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("========================================\n");
    printf("  SysGuard - AI Agent Boundary Auditor\n");
    printf("========================================\n");
    printf("  Mode    : %s\n", fake ? "FAKE (demo)" : "eBPF (live)");
    printf("  Output  : %s\n", output);
    printf("  Session : %s\n", session.session_id);
    if (session.target_comm[0])  printf("  Target  : comm=%s\n", session.target_comm);
    if (target_pid)              printf("  Target  : pid=%lu\n", target_pid);
    if (session.project_path[0]) printf("  Project : %s\n", session.project_path);
    if (session.home_path[0])
        printf("  Home    : %s\n", session.home_path);
    else
        printf("  Home    : (untrusted - home-relative rules disabled)\n");
    if (session.tool_tmp[0])
        printf("  ToolTmp : %s\n", session.tool_tmp);
    if (agent_mode)              printf("  Agent   : on\n");
    printf("========================================\n\n");

    if (fake) {
        fake_collector_run(output, session.session_id, project_path, target_comm,
                           session.home_path, session.tool_tmp);
    } else {
#ifdef HAS_BPF_COLLECTOR
        // Scope live collection to the target's process subtree. With no target
        // set the filter passes everything through (and warns about volume).
        struct target_filter *filter = target_filter_new(
            session.target_comm[0] ? session.target_comm : NULL,
            (uint32_t)target_pid);
        if (!filter) {
            fprintf(stderr, "[ERROR] failed to allocate target filter.\n");
            return 1;
        }
        if (!session.target_comm[0] && target_pid == 0)
            fprintf(stderr,
                "[WARN] No --target-comm/--target-pid set: capturing ALL "
                "processes (high volume).\n"
                "       Pass a target to scope collection to one agent subtree.\n\n");

        bpf_collector_run(output, &session, filter);
        target_filter_free(filter);
#else
        fprintf(stderr,
            "[ERROR] Real eBPF mode not available in this build.\n"
            "        Use --fake for testing.\n");
        return 1;
#endif
    }

    printf("\n[SysGuard] Session complete. Log: %s\n", output);
    return 0;
}
