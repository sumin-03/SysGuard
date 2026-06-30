// SysGuard libbpf collector: load skeleton, attach, and drain the ring buffer.
#include <stdio.h>
#include <errno.h>
#include <stddef.h>

#include <bpf/libbpf.h>

#include "sysguard.skel.h"
#include "collector.h"

// Bridges the libbpf ring_buffer callback signature to sysguard_event_cb.
struct cb_wrap {
    sysguard_event_cb cb;
    void *ctx;
};

static int handle_rb_event(void *ctx, void *data, size_t size)
{
    struct cb_wrap *w = ctx;

    if (size < sizeof(struct sysguard_event))
        return 0;

    w->cb((const struct sysguard_event *)data, w->ctx);
    return 0;
}

int sysguard_bpf_run(sysguard_event_cb cb, void *ctx, volatile sig_atomic_t *stop)
{
    struct sysguard_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    struct cb_wrap wrap = { cb, ctx };
    int err;

    skel = sysguard_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "sysguard: failed to open/load BPF skeleton\n");
        return 1;
    }

    err = sysguard_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "sysguard: failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                          handle_rb_event, &wrap, NULL);
    if (!rb) {
        fprintf(stderr, "sysguard: failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    while (!*stop) {
        err = ring_buffer__poll(rb, 100 /* ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "sysguard: ring buffer poll error: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    sysguard_bpf__destroy(skel);
    return err < 0 ? -err : err;
}

#ifdef HAS_BPF_COLLECTOR
// Full-pipeline glue (owner A <-> owner B). Only compiled into the complete
// `sysguard` binary, where rules.c / jsonl_writer.c are also linked; the
// standalone PoC build leaves this out so it stays dependency-free.
#include "rules.h"
#include "alert.h"
#include "jsonl_writer.h"
#include "target_filter.h"

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

// Per-event state shared with the ring-buffer callback.
struct live_ctx {
    FILE *fp;
    struct target_filter *filter;
    const struct sysguard_session *session;
};

// Invoked once per live event: scope to the target subtree (and absolutize the
// path) via the filter, then run the rule engine and log via the JSONL writer.
static void log_event(const struct sysguard_event *e, void *ctx)
{
    struct live_ctx *lc = ctx;
    struct sysguard_event ev = *e;  // mutable copy: filter may rewrite ev.path

    // Drop events outside the monitored process family. The filter also turns a
    // relative openat path into an absolute one using the live /proc/<pid>/cwd.
    if (!target_filter_process(lc->filter, &ev))
        return;

    struct sysguard_alert alert;
    if (rules_evaluate(&ev, &alert)) {
        printf("  [%s] %s — %s\n",
               sysguard_severity_string(alert.severity),
               alert.rule_id, alert.reason);
        jsonl_write_alert(lc->fp, &ev, &alert);
    } else {
        jsonl_write_event(lc->fp, &ev);
    }
    // NOTE: lc->session carries session_id / project_path / target_comm for the
    // A->B JSONL schema. B's reworked jsonl_writer will consume it as a
    // parameter; the legacy writer above does not yet emit those fields.
    fflush(lc->fp);
}

void bpf_collector_run(const char *output_path,
                       const struct sysguard_session *session,
                       struct target_filter *filter)
{
    FILE *fp = jsonl_open(output_path);
    if (!fp) {
        fprintf(stderr, "sysguard: cannot open output %s\n", output_path);
        return;
    }

    struct live_ctx lc = { fp, filter, session };

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    printf("[SysGuard] eBPF collector running (session=%s). Ctrl-C to stop.\n\n",
           session && session->session_id[0] ? session->session_id : "-");

    sysguard_bpf_run(log_event, &lc, &g_stop);

    jsonl_close(fp);
}
#endif /* HAS_BPF_COLLECTOR */
