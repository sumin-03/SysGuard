// SysGuard Week-1 collector PoC entry point (owner: A).
//
// Minimal driver that exercises the real eBPF collection path end to end:
//   open_and_load -> attach -> ring_buffer poll -> print.
// It deliberately does NOT depend on the rule engine / JSONL writer (owner B),
// so the collector can be validated independently during Week 1.
#include <stdarg.h>
#include <stdio.h>
#include <signal.h>

#include <bpf/libbpf.h>

#include "collector.h"

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
    printf("[%-4s] pid=%-6u ppid=%-6u uid=%-6u comm=%-16s exe=%s argv=[%s]\n",
           event_type_str(e->type), e->pid, e->ppid, e->uid,
           e->comm, e->exe_path, e->argv);
    fflush(stdout);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
    (void)level;
    return vfprintf(stderr, fmt, args);
}

int main(void)
{
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    libbpf_set_print(libbpf_print_fn);

    printf("SysGuard Week-1 collector PoC running.\n");
    printf("Run commands in another shell (e.g. `ls`, `cat /etc/passwd`); Ctrl-C to stop.\n\n");

    return sysguard_bpf_run(print_event, NULL, &g_stop);
}
