#ifndef SYSGUARD_COLLECTOR_H
#define SYSGUARD_COLLECTOR_H

#include <signal.h>
#include "event.h"

void fake_collector_run(const char *output_path,
                        const char *session_id,
                        const char *project_path,
                        const char *target_comm);

typedef void (*sysguard_event_cb)(const struct sysguard_event *e, void *ctx);

int sysguard_bpf_run(sysguard_event_cb cb, void *ctx, volatile sig_atomic_t *stop);

#endif
