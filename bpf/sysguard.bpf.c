// SPDX-License-Identifier: GPL-2.0
// SysGuard eBPF collector.
//
// Attaches to syscall tracepoints and pushes a normalized sysguard_event into a
// BPF ring buffer for the user-space engine. Implemented tracepoints:
//   execve     -> exe_path + argv
//   openat     -> path + open(2) flags
//   unlinkat   -> path (deletion target)
//   renameat2  -> old_path + new_path + rename flags
//   fchmodat   -> path + mode
//   exit_group -> process context only (session/subtree end marker)
//   connect    -> addr_family + dest_addr + dest_port (outbound attempt)
// Collection only — no filtering or verdicts in kernel space; user-space picks
// the target process and the rule engine decides what is suspicious.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// Shared event contract with user-space (src/event.h). clang ships a
// freestanding <stdint.h>, so the uintN_t types resolve under -target bpf.
#include "event.h"

char LICENSE[] SEC("license") = "GPL";

// connect() destination families. Not always present as macros in vmlinux.h.
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

// argv collection limits. Using a CONSTANT per-arg read size lets the BPF
// verifier prove every write stays in bounds across the unrolled loop: after
// i iterations the write offset is at most i * ARGV_ARG_SIZE, so as long as
// ARGV_MAX_ARGS * ARGV_ARG_SIZE <= SYSGUARD_MAX_ARGV no write can overflow
// e->argv. No runtime masking needed. Extra args / long args are truncated.
#define ARGV_ARG_SIZE 32
#define ARGV_MAX_ARGS 7   /* 7 * 32 = 224 <= 256 (SYSGUARD_MAX_ARGV) */

// Ring buffer used to deliver events to user-space.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Fill the caller-process context shared by every event type: timestamp, the
// pid/ppid/uid triple, and comm. The event type and syscall-specific payload
// are filled by each handler afterward. __always_inline keeps each tracepoint a
// single flat program for the verifier (no real function call).
static __always_inline void fill_process_context(struct sysguard_event *e)
{
    e->timestamp_ns = bpf_ktime_get_ns();

    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    e->uid = (__u32)bpf_get_current_uid_gid();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// Zero the syscall-specific payload so fields a given handler does not fill
// serialize as empty / 0. We deliberately avoid __builtin_memset over the whole
// event: struct sysguard_event is >1KB, and the BPF backend lowers a memset
// that large into an unsupported libcall. Clearing the first byte of each
// string buffer is enough — every producer NUL-terminates what it writes and
// every consumer reads these as C strings, so trailing bytes are never seen.
static __always_inline void clear_payload(struct sysguard_event *e)
{
    e->exe_path[0] = '\0';
    e->argv[0] = '\0';
    e->path[0] = '\0';
    e->old_path[0] = '\0';
    e->new_path[0] = '\0';
    e->flags = 0;
    e->mode = 0;
    /* Binary connect fields: rules + address rendering inspect all bytes, so
     * (unlike the NUL-terminated strings above) every byte must be cleared. A
     * 16-byte constant-size memset lowers to a few stores, not a libcall. */
    e->addr_family = 0;
    __builtin_memset(e->dest_addr, 0, sizeof(e->dest_addr));
    e->dest_port = 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct sysguard_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_process_context(e);
    clear_payload(e);
    e->type = SYSGUARD_EVENT_EXEC;

    // For sys_enter_execve, args[0] is the user-space filename pointer.
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->exe_path, sizeof(e->exe_path), filename);

    // args[1] is argv: a user-space array of user-space string pointers
    // (char **). Collect up to ARGV_MAX_ARGS of them, space-separated, into
    // e->argv. The unrolled loop plus a CONSTANT read size keeps the running
    // offset provably bounded (off <= i * ARGV_ARG_SIZE), so the verifier
    // accepts every write without runtime masking.
    const char *const *argv = (const char *const *)ctx->args[1];
    __u32 off = 0;

#pragma unroll
    for (int i = 0; i < ARGV_MAX_ARGS; i++) {
        const char *arg = NULL;

        // Pull the i-th user-space pointer out of the argv array.
        if (bpf_probe_read_user(&arg, sizeof(arg), &argv[i]))
            break;
        if (!arg)
            break;  // A NULL pointer marks the end of argv.

        // Separate arguments with a single space (not before the first one).
        if (i != 0)
            e->argv[off++] = ' ';

        // Copy the argument with a constant max size. The return value counts
        // the NUL terminator, so advancing by n-1 lets the next separator
        // overwrite that NUL and keep the string contiguous. Each read writes
        // its own NUL terminator and clear_payload zeroed argv[0] for the
        // no-args case, so e->argv is always NUL-terminated
        // (off <= ARGV_MAX_ARGS * ARGV_ARG_SIZE < buffer).
        long n = bpf_probe_read_user_str(&e->argv[off], ARGV_ARG_SIZE, arg);
        if (n <= 0)
            break;
        off += n - 1;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// openat(int dfd, const char *filename, int flags, umode_t mode). We capture the
// target path and the open flags; dfd-relative paths are recorded verbatim
// (resolving them against the caller's CWD/dir-fd is a user-space concern).
//
// NOTE: openat fires for essentially every file access on the box (libraries,
// configs, everything), so this is a high-volume stream. The MVP keeps kernel
// space dumb and leaves target-process filtering and sensitive-path matching to
// user-space (collector filter + rule engine), per the README design.
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct sysguard_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_process_context(e);
    clear_payload(e);
    e->type = SYSGUARD_EVENT_OPEN;

    // args[1] is the user-space pathname pointer; args[2] is the open flags.
    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->path, sizeof(e->path), filename);
    e->flags = (int32_t)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// unlinkat(int dfd, const char *pathname, int flag). We record the deletion
// target path (args[1]); the AT_REMOVEDIR flag is not carried in the wire
// struct. Like openat this fires at syscall entry, so it records an *attempt*.
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    struct sysguard_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_process_context(e);
    clear_payload(e);
    e->type = SYSGUARD_EVENT_UNLINK;

    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->path, sizeof(e->path), pathname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// renameat2(int olddfd, const char *oldname, int newdfd, const char *newname,
// unsigned int flags). Note the interleaved dir-fd args: the source path is
// args[1] and the destination path is args[3] (args[2] is newdfd, NOT a path).
// old_path and new_path get independent bounded reads into their own buffers.
/* All three rename syscalls carry the same payload — a source and a
 * destination — and differ only in argument positions and whether flags exist.
 * glibc's rename() issues sys_rename on x86_64 and coreutils/mv use renameat,
 * so tracing renameat2 alone misses almost every real rename. */
static __always_inline int emit_rename(const char *oldname, const char *newname,
                                       int32_t flags)
{
    struct sysguard_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_process_context(e);
    clear_payload(e);
    e->type = SYSGUARD_EVENT_RENAME;

    bpf_probe_read_user_str(&e->old_path, sizeof(e->old_path), oldname);
    bpf_probe_read_user_str(&e->new_path, sizeof(e->new_path), newname);
    e->flags = flags;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* rename(const char *oldname, const char *newname) — no flags, so it can never
 * be a RENAME_EXCHANGE. */
SEC("tracepoint/syscalls/sys_enter_rename")
int handle_rename(struct trace_event_raw_sys_enter *ctx)
{
    return emit_rename((const char *)ctx->args[0],
                       (const char *)ctx->args[1], 0);
}

/* renameat(int olddfd, const char *oldname, int newdfd, const char *newname) */
SEC("tracepoint/syscalls/sys_enter_renameat")
int handle_renameat(struct trace_event_raw_sys_enter *ctx)
{
    return emit_rename((const char *)ctx->args[1],
                       (const char *)ctx->args[3], 0);
}

/* renameat2(int olddfd, const char *oldname, int newdfd, const char *newname,
 *           unsigned int flags) — flags carry RENAME_EXCHANGE / RENAME_NOREPLACE. */
SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    return emit_rename((const char *)ctx->args[1],
                       (const char *)ctx->args[3],
                       (int32_t)ctx->args[4]);
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int handle_fchmodat(struct trace_event_raw_sys_enter *ctx)
{
    struct sysguard_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_process_context(e);
    clear_payload(e);
    e->type = SYSGUARD_EVENT_CHMOD;

    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->path, sizeof(e->path), pathname);
    e->mode = (int32_t)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// exit_group(int error_code): the whole thread group is exiting. We emit a
// payload-free marker carrying only process context so user-space can retire a
// tracked PID / mark the session end. The exit status (args[0]) is intentionally
// not stored — the wire struct reserves no field for it.
SEC("tracepoint/syscalls/sys_enter_exit_group")
int handle_exit_group(struct trace_event_raw_sys_enter *ctx)
{
    struct sysguard_event *e;

    (void)ctx;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_process_context(e);
    clear_payload(e);
    e->type = SYSGUARD_EVENT_EXIT;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// connect(int fd, struct sockaddr *uservaddr, int addrlen). We record the
// destination family/address/port. sockaddr is a variable, family-tagged
// user-space struct, so read sa_family first, then use CONSTANT-size reads of a
// fixed stack copy for the IPv4/IPv6 address + port — the verifier can prove
// every read is bounded. Other families keep only the family. Captured at
// syscall entry, so this is an *attempted* connection.
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct sysguard_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_process_context(e);
    clear_payload(e);
    e->type = SYSGUARD_EVENT_CONNECT;

    void *uservaddr = (void *)ctx->args[1];
    int addrlen = (int)ctx->args[2];

    __u16 fam = 0;
    if (uservaddr && addrlen >= (int)sizeof(fam) &&
        bpf_probe_read_user(&fam, sizeof(fam), uservaddr) == 0) {
        e->addr_family = fam;

        if (fam == AF_INET && addrlen >= (int)sizeof(struct sockaddr_in)) {
            struct sockaddr_in sin;
            if (bpf_probe_read_user(&sin, sizeof(sin), uservaddr) == 0) {
                __builtin_memcpy(e->dest_addr, &sin.sin_addr, sizeof(sin.sin_addr));
                e->dest_port = bpf_ntohs(sin.sin_port);
            }
        } else if (fam == AF_INET6 && addrlen >= (int)sizeof(struct sockaddr_in6)) {
            struct sockaddr_in6 sin6;
            if (bpf_probe_read_user(&sin6, sizeof(sin6), uservaddr) == 0) {
                __builtin_memcpy(e->dest_addr, &sin6.sin6_addr, sizeof(sin6.sin6_addr));
                e->dest_port = bpf_ntohs(sin6.sin6_port);
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
