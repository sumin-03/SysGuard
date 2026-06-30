#ifndef SYSGUARD_TARGET_FILTER_H
#define SYSGUARD_TARGET_FILTER_H

#include "event.h"

// User-space target-subtree filter (owner A).
//
// AI agents work through child processes (claude -> bash -> git), and the
// security-relevant action is usually performed by a descendant, not the agent
// itself. Meanwhile attaching to openat system-wide produces a flood of
// unrelated events. This filter keeps exactly the target process and its
// descendants: it seeds a PID set from the target (by comm / exe basename, or
// an explicit pid) and grows it whenever an event's ppid is already tracked.
// Events outside the subtree are dropped at the source, so downstream consumers
// (PoC printer, rule engine, JSONL writer) only ever see the agent's family.
//
// It also resolves relative openat paths to absolute form using the live
// /proc/<pid>/cwd link. That is only possible while the process is still
// alive, which is why this runs in the collector and not in post-hoc analysis.

struct target_filter;

// Create a filter. If target_comm is NULL/empty and target_pid is 0, the filter
// is inactive (pass-through: every event is accepted; paths are still made
// absolute). Returns NULL on allocation failure.
struct target_filter *target_filter_new(const char *target_comm, uint32_t target_pid);

void target_filter_free(struct target_filter *tf);

// Update subtree membership from this event, absolutize its path in place, and
// return 1 if the event belongs to the target subtree (should be emitted) or 0
// if it should be dropped. *e may be modified (path made absolute), so callers
// pass a mutable copy of the ring-buffer event.
int target_filter_process(struct target_filter *tf, struct sysguard_event *e);

#endif
