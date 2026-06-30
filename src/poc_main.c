// SysGuard Week-1 collector PoC entry point (owner: A).
//
// Minimal driver that exercises the real eBPF collection path end to end:
//   open_and_load -> attach -> ring_buffer poll -> print.
// It deliberately does NOT depend on the rule engine / JSONL writer (owner B),
// so the collector can be validated independently during Week 1.
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <bpf/libbpf.h>

#include "collector.h"
#include "target_filter.h"

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static const char *event_type_str(uint32_t type)
{
    switch (type) {
    case SYSGUARD_EVENT_EXEC: return "EXEC";
    case SYSGUARD_EVENT_OPEN: return "OPEN";
    default:                  return "UNKNOWN";
    }
}

static void print_event(const struct sysguard_event *e, void *ctx)
{
    (void)ctx;
    // OPEN events carry the target path (exe_path/argv are empty); EXEC events
    // carry the program path + argv (path is empty). Print the fields that are
    // actually populated for each type so openat shows its file path.
    if (e->type == SYSGUARD_EVENT_OPEN) {
        printf("[OPEN] pid=%-6u ppid=%-6u uid=%-6u comm=%-16s path=%s\n",
               e->pid, e->ppid, e->uid, e->comm, e->path);
    } else {
        printf("[%-4s] pid=%-6u ppid=%-6u uid=%-6u comm=%-16s exe=%s argv=[%s]\n",
               event_type_str(e->type), e->pid, e->ppid, e->uid,
               e->comm, e->exe_path, e->argv);
    }
    fflush(stdout);
}

// Per-event hook: apply A's target-subtree filter (and path absolutization) to
// a mutable copy of the ring-buffer event, then print only events that belong
// to the target's process family. With no target set the filter passes
// everything through (still absolutizing paths).
static void filtered_print(const struct sysguard_event *e, void *ctx)
{
    struct target_filter *tf = ctx;
    struct sysguard_event ev = *e;
    if (!target_filter_process(tf, &ev))
        return;
    print_event(&ev, NULL);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
    (void)level;
    return vfprintf(stderr, fmt, args);
}

int main(int argc, char **argv)
{
    const char *target_comm = NULL;
    unsigned long target_pid = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--target-comm") == 0 && i + 1 < argc) {
            target_comm = argv[++i];
        } else if (strcmp(argv[i], "--target-pid") == 0 && i + 1 < argc) {
            target_pid = strtoul(argv[++i], NULL, 10);
        } else {
            fprintf(stderr,
                "Usage: %s [--target-comm NAME] [--target-pid PID]\n"
                "  No target: print every execve/openat on the system.\n"
                "  With a target: print only that process and its descendants.\n",
                argv[0]);
            return 1;
        }
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    libbpf_set_print(libbpf_print_fn);

    struct target_filter *tf = target_filter_new(target_comm, (uint32_t)target_pid);
    if (!tf) {
        fprintf(stderr, "sysguard: failed to allocate target filter\n");
        return 1;
    }

    printf("SysGuard Week-1 collector PoC running.\n");
    if (target_comm || target_pid)
        printf("Filtering to target subtree (comm=%s pid=%lu).\n",
               target_comm ? target_comm : "-", target_pid);
    else
        printf("No target set: printing all events.\n");
    printf("Run commands in another shell; Ctrl-C to stop.\n\n");

    int err = sysguard_bpf_run(filtered_print, tf, &g_stop);

    target_filter_free(tf);
    return err;
}
