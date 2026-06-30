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

    // Optional event types for future extensions.
    SYSGUARD_EVENT_UNLINK = 3,
    SYSGUARD_EVENT_RENAME = 4,
    SYSGUARD_EVENT_CHMOD = 5,
    SYSGUARD_EVENT_CONNECT = 6,
    SYSGUARD_EVENT_EXIT = 7,
};

// Normalized event consumed by the rule engine and session analyzer.
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

    // File event fields.
    char path[SYSGUARD_MAX_PATH];
    char old_path[SYSGUARD_MAX_PATH];
    char new_path[SYSGUARD_MAX_PATH];
    int32_t flags;
    int32_t mode;
};

#endif