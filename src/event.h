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
//
// FIELD SEMANTICS (contract between the collector (A) and consumers (B)):
// Events are captured at *syscall entry*, before the kernel does any work. For
// execve this matters a lot: the calling process has NOT yet been replaced by
// the new program image. So the "who" fields describe the CALLER, while the
// exec-specific fields describe the program ABOUT TO RUN.
//
//   caller (the process invoking the syscall):  pid, ppid, uid, comm
//   target (what execve is about to run):       exe_path, argv
//
// Example: a shell running `curl ...` produces comm="bash" (or "sh") and
// exe_path="/usr/bin/curl". To name the executed program, use exe_path/argv,
// NOT comm. (The --fake generator must follow the same convention to stay
// representative: comm = caller, exe_path = program.)
struct sysguard_event {
    uint64_t timestamp_ns;  // CLOCK_MONOTONIC ns (bpf_ktime_get_ns) at entry.
    uint32_t type;          // enum sysguard_event_type (EXEC / OPEN).

    // Caller process context (the process that made the syscall).
    uint32_t pid;           // Caller TGID (the userspace "PID").
    uint32_t ppid;          // Caller's parent TGID.
    uint32_t uid;           // Caller's real UID.
    char comm[TASK_COMM_LEN]; // Caller's comm — e.g. "bash" for `curl` run
                              // from a shell. NOT the executed program's name.

    // Exec event fields (valid when type == SYSGUARD_EVENT_EXEC).
    char exe_path[SYSGUARD_MAX_PATH]; // Program being executed (execve arg0
                                      // path). This is the real "what ran".
    char argv[SYSGUARD_MAX_ARGV];     // Space-separated argv, truncated. First
                                      // token is argv[0]. See bpf collector for
                                      // per-arg / arg-count limits.

    // Open event fields (valid when type == SYSGUARD_EVENT_OPEN; not yet
    // emitted by the collector — openat tracepoint is a later milestone).
    char path[SYSGUARD_MAX_PATH];     // File path passed to openat.
    int32_t flags;                    // open(2) flags.
};

#endif