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
