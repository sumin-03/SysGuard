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
#include <sys/socket.h>
#include <arpa/inet.h>

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
    case SYSGUARD_EVENT_EXEC:   return "EXEC";
    case SYSGUARD_EVENT_OPEN:   return "OPEN";
    case SYSGUARD_EVENT_UNLINK: return "UNLINK";
    case SYSGUARD_EVENT_RENAME: return "RENAME";
    case SYSGUARD_EVENT_CHMOD:  return "CHMOD";
    case SYSGUARD_EVENT_CONNECT:return "CONNECT";
    case SYSGUARD_EVENT_EXIT:   return "EXIT";
    default:                    return "UNKNOWN";
    }
}

static void print_event(const struct sysguard_event *e, void *ctx)
{
    (void)ctx;
    // Print only the fields each event type actually populates: EXEC carries the
    // program path + argv; the file syscalls carry path(s)/mode/flags; EXIT is a
    // context-only marker.
    const char *common = event_type_str(e->type);
    switch (e->type) {
    case SYSGUARD_EVENT_OPEN:
    case SYSGUARD_EVENT_UNLINK:
        printf("[%-6s] pid=%-6u ppid=%-6u uid=%-6u comm=%-16s path=%s\n",
               common, e->pid, e->ppid, e->uid, e->comm, e->path);
        break;
    case SYSGUARD_EVENT_RENAME:
        printf("[%-6s] pid=%-6u ppid=%-6u uid=%-6u comm=%-16s old=%s new=%s flags=%d\n",
               common, e->pid, e->ppid, e->uid, e->comm,
               e->old_path, e->new_path, e->flags);
        break;
    case SYSGUARD_EVENT_CHMOD:
        printf("[%-6s] pid=%-6u ppid=%-6u uid=%-6u comm=%-16s path=%s mode=%o\n",
               common, e->pid, e->ppid, e->uid, e->comm,
               e->path, (unsigned int)(e->mode & 07777));
        break;
    case SYSGUARD_EVENT_EXIT:
        printf("[%-6s] pid=%-6u ppid=%-6u uid=%-6u comm=%-16s\n",
               common, e->pid, e->ppid, e->uid, e->comm);
        break;
    case SYSGUARD_EVENT_CONNECT: {
        char ip[64] = "";
        if (e->addr_family == AF_INET) {
            struct in_addr a;
            memcpy(&a, e->dest_addr, sizeof(a));
            inet_ntop(AF_INET, &a, ip, sizeof(ip));
        } else if (e->addr_family == AF_INET6) {
            struct in6_addr a6;
            memcpy(&a6, e->dest_addr, sizeof(a6));
            inet_ntop(AF_INET6, &a6, ip, sizeof(ip));
        }
        char endpoint[80];
        if (e->addr_family == AF_INET6)
            snprintf(endpoint, sizeof(endpoint), "[%s]:%u", ip, (unsigned)e->dest_port);
        else
            snprintf(endpoint, sizeof(endpoint), "%s:%u", ip, (unsigned)e->dest_port);
        printf("[%-6s] pid=%-6u ppid=%-6u uid=%-6u comm=%-16s dest=%s family=%d\n",
               common, e->pid, e->ppid, e->uid, e->comm, endpoint, e->addr_family);
        break;
    }
    default:  /* EXEC and anything unexpected */
        printf("[%-6s] pid=%-6u ppid=%-6u uid=%-6u comm=%-16s exe=%s argv=[%s]\n",
               common, e->pid, e->ppid, e->uid,
               e->comm, e->exe_path, e->argv);
        break;
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
