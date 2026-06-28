#ifndef SYSGUARD_COLLECTOR_H
#define SYSGUARD_COLLECTOR_H

#include <signal.h>
#include "event.h"

// Fake collector
void fake_collector_run(const char *output_path);



// Callback invoked once per decoded event delivered from the ring buffer.
typedef void (*sysguard_event_cb)(const struct sysguard_event *e, void *ctx);

// Load the eBPF skeleton, attach its programs, and poll the ring buffer,
// invoking cb for every event until *stop becomes non-zero (set from a
// signal handler) or a fatal error occurs.
//
// Returns 0 on clean shutdown, non-zero on load/attach/poll failure.
int sysguard_bpf_run(sysguard_event_cb cb, void *ctx, volatile sig_atomic_t *stop);

#endif
