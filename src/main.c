#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "collector.h"

static volatile int running = 1;

static void sig_handler(int sig) {
    (void)sig;
    running = 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [--fake] --output <path.jsonl>\n"
        "\n"
        "Options:\n"
        "  --fake      Use fake event generator (no root/eBPF needed)\n"
        "  --output    Path for JSONL session log\n", prog);
    exit(1);
}

int main(int argc, char **argv) {
    const char *output = NULL;
    int fake = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--fake") == 0) {
            fake = 1;
        } else if (strcmp(argv[i], "--output") == 0) {
            if (++i >= argc) usage(argv[0]);
            output = argv[i];
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

    printf("========================================\n");
    printf("  SysGuard — eBPF Security Monitor\n");
    printf("========================================\n");
    printf("  Mode   : %s\n", fake ? "FAKE (demo)" : "eBPF (live)");
    printf("  Output : %s\n", output);
    printf("========================================\n\n");

    if (fake) {
        fake_collector_run(output);
    } else {
#ifdef HAS_BPF_COLLECTOR
        bpf_collector_run(output);
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
