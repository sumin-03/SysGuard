#ifndef SYSGUARD_EVENT_H
#define SYSGUARD_EVENT_H

// Under -target bpf, clang's freestanding stdint.h chains into glibc's
// stdint.h, which assumes a real architecture triple (__x86_64__ etc.) that
// the bpf pseudo-target does not define, breaking the include chain. Reuse
// vmlinux.h's kernel-style fixed-width typedefs instead when building BPF.
#ifdef __BPF__
typedef __u8 uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;
typedef __s32 int32_t;
#else
#include <stdint.h>
#endif

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
