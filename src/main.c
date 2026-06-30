#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "collector.h"
#include "target_filter.h"

static volatile int running = 1;

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
        "  --session-id <id>    Session identifier (defaults to the output stem)\n",
        prog);
    exit(1);
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

int main(int argc, char **argv) {
    const char *output = NULL;
    const char *target_comm = NULL;
    const char *project_path = NULL;
    const char *session_id = NULL;
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
    session.agent_mode = agent_mode;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("========================================\n");
    printf("  SysGuard — eBPF Security Monitor\n");
    printf("========================================\n");
    printf("  Mode    : %s\n", fake ? "FAKE (demo)" : "eBPF (live)");
    printf("  Output  : %s\n", output);
    printf("  Session : %s\n", session.session_id);
    if (session.target_comm[0])  printf("  Target  : comm=%s\n", session.target_comm);
    if (target_pid)              printf("  Target  : pid=%lu\n", target_pid);
    if (session.project_path[0]) printf("  Project : %s\n", session.project_path);
    if (agent_mode)              printf("  Agent   : on\n");
    printf("========================================\n\n");

    if (fake) {
        fake_collector_run(output);
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
            "[ERROR] Real eBPF mode is not available in this build.\n"
            "        This binary was compiled without libbpf/skeleton.\n"
            "        Use --fake for testing, or build with A's bpf_collector.\n");
        return 1;
#endif
    }

    printf("\n[SysGuard] Session complete. Log saved to: %s\n", output);
    return 0;
}
