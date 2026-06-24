#ifndef SYSGUARD_EVENT_H
#define SYSGUARD_EVENT_H

#include <stdint.h>

#define TASK_COMM_LEN 16
#define SYSGUARD_MAX_PATH 256
#define SYSGUARD_MAX_ARGV 256

// Event types shared by eBPF and user-space code.
// Keep these values synchronized with bpf/sysguard.bpf.c.
enum sysguard_event_type {
    SYSGUARD_EVENT_EXEC = 1,
    SYSGUARD_EVENT_OPEN = 2,
};

// Normalized event consumed by the rule engine.
struct sysguard_event {
    uint64_t timestamp_ns;
    uint32_t type;

    // Process context.
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    char comm[TASK_COMM_LEN];

    // Exec event fields.
    char exe_path[SYSGUARD_MAX_PATH];
    char argv[SYSGUARD_MAX_ARGV];

    // Open event fields.
    char path[SYSGUARD_MAX_PATH];
    int32_t flags;
};

#endif
