#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include "collector.h"

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig) {
    (void)sig;
    running = 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options] --output <path.jsonl>\n\n"
        "Options:\n"
        "  --fake              Use fake event generator\n"
        "  --output <path>     JSONL session log path\n"
        "  --agent-mode        Enable AI agent detection\n"
        "  --target-comm <name>  Target process name (e.g. claude)\n"
        "  --project-path <dir>  Project root directory\n",
        prog);
    exit(1);
}

int main(int argc, char **argv) {
    const char *output = NULL;
    const char *target_comm = "claude";
    const char *project_path = ".";
    int fake = 0;
    int agent_mode = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--fake") == 0) {
            fake = 1;
        } else if (strcmp(argv[i], "--output") == 0) {
            if (++i >= argc) usage(argv[0]);
            output = argv[i];
        } else if (strcmp(argv[i], "--agent-mode") == 0) {
            agent_mode = 1;
        } else if (strcmp(argv[i], "--target-comm") == 0) {
            if (++i >= argc) usage(argv[0]);
            target_comm = argv[i];
        } else if (strcmp(argv[i], "--project-path") == 0) {
            if (++i >= argc) usage(argv[0]);
            project_path = argv[i];
        } else {
            usage(argv[0]);
        }
    }

    if (!output) {
        fprintf(stderr, "[ERROR] --output is required.\n\n");
        usage(argv[0]);
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Generate session_id */
    char session_id[64];
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    strftime(session_id, sizeof(session_id), "session_%Y%m%d_%H%M%S", tm);

    printf("========================================\n");
    printf("  SysGuard - AI Agent Boundary Auditor\n");
    printf("========================================\n");
    printf("  Mode         : %s\n", fake ? "FAKE (demo)" : "eBPF (live)");
    printf("  Agent Mode   : %s\n", agent_mode ? "ON" : "OFF");
    printf("  Target Comm  : %s\n", target_comm);
    printf("  Project Path : %s\n", project_path);
    printf("  Session ID   : %s\n", session_id);
    printf("  Output       : %s\n", output);
    printf("========================================\n\n");

    if (fake) {
        fake_collector_run(output, session_id, project_path, target_comm);
    } else {
#ifdef HAS_BPF_COLLECTOR
        /* A담당자의 bpf collector 연결 */
        (void)agent_mode;
        fprintf(stderr, "[INFO] Starting eBPF collector...\n");
        /* TODO: bpf_collector_run with session context */
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
