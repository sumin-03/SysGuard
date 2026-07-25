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
//
// Values 1-7 are all part of the README's 7-tracepoint contract, not optional
// extras. The collector emits 6 of them today (EXEC, OPEN, UNLINK, RENAME,
// CHMOD, EXIT). CONNECT stays reserved-but-unemitted because a destination
// address needs wire fields this struct does not carry yet (Future Work). These
// numeric values are a stable ABI: never renumber or reorder them, so a rebuilt
// consumer keeps decoding older/newer producers.
enum sysguard_event_type {
    SYSGUARD_EVENT_EXEC = 1,     // execve — exe_path + argv.
    SYSGUARD_EVENT_OPEN = 2,     // openat — path + open(2) flags.
    SYSGUARD_EVENT_UNLINK = 3,   // unlinkat — file deletion target (path).
    SYSGUARD_EVENT_RENAME = 4,   // renameat2 — old_path + new_path + flags.
    SYSGUARD_EVENT_CHMOD = 5,    // fchmodat — path + mode.
    SYSGUARD_EVENT_CONNECT = 6,  // connect — reserved; address fields TBD.
    SYSGUARD_EVENT_EXIT = 7,     // exit_group — process/session end marker.
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
    uint32_t type;          // enum sysguard_event_type; selects which payload
                            // fields below are valid.

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

    // File event fields. openat (the implemented OPEN type) populates
    // path + flags. The optional file syscalls reuse these: UNLINK/CHMOD use
    // path; RENAME uses old_path + new_path. Unused fields stay zeroed.
    char path[SYSGUARD_MAX_PATH];     // Primary file path (openat target,
                                      // unlink target, chmod target).
    char old_path[SYSGUARD_MAX_PATH]; // Rename source (SYSGUARD_EVENT_RENAME).
    char new_path[SYSGUARD_MAX_PATH]; // Rename dest (SYSGUARD_EVENT_RENAME).
    int32_t flags;                    // open(2) flags (OPEN) or renameat2 flags
                                      // (RENAME); 0 for other event types.
    int32_t mode;                     // chmod mode bits (SYSGUARD_EVENT_CHMOD).
};

#endif
