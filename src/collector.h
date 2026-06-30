#ifndef SYSGUARD_COLLECTOR_H
#define SYSGUARD_COLLECTOR_H

#include <signal.h>
#include "event.h"

// Session-level metadata, constant for one monitoring run. main.c fills this
// from CLI options and hands it to the collector so every JSONL record can
// carry session_id / project_path / target_comm (the A->B schema contract).
struct sysguard_session {
    char session_id[64];                 // Matches the GUI's log file stem.
    char project_path[SYSGUARD_MAX_PATH]; // Repo root for boundary checks.
    char target_comm[TASK_COMM_LEN];     // Monitored agent (e.g. "claude").
    int  agent_mode;                     // 1 if --agent-mode was requested.
};

// Opaque target-subtree filter (see target_filter.h). Forward-declared here so
// the collector entry point can take one without pulling in the full header.
struct target_filter;

// Fake event generator (owner B): no root/eBPF needed, for demos and testing.
void fake_collector_run(const char *output_path);

// Real eBPF collector entry point (owner A): load/attach the BPF program, poll
// the ring buffer, apply the target-subtree filter, and log surviving events
// through the rule engine + JSONL writer until interrupted. session carries the
// A->B metadata; filter scopes collection to one process family (may be a
// pass-through filter). Used by main.c when built with -DHAS_BPF_COLLECTOR.
void bpf_collector_run(const char *output_path,
                       const struct sysguard_session *session,
                       struct target_filter *filter);

// Callback invoked once per decoded event delivered from the ring buffer.
typedef void (*sysguard_event_cb)(const struct sysguard_event *e, void *ctx);

// Load the eBPF skeleton, attach its programs, and poll the ring buffer,
// invoking cb for every event until *stop becomes non-zero (set from a
// signal handler) or a fatal error occurs.
//
// Returns 0 on clean shutdown, non-zero on load/attach/poll failure.
int sysguard_bpf_run(sysguard_event_cb cb, void *ctx, volatile sig_atomic_t *stop);

#endif
