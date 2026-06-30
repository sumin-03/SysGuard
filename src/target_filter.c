#include "target_filter.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>

struct target_filter {
    int active;                     // 0 = pass-through (no target configured).
    char target_comm[TASK_COMM_LEN]; // Seed match by comm / exe basename.
    uint32_t seed_pid;              // Optional explicit pid seed (0 = none).

    uint32_t *pids;                 // Tracked subtree PIDs.
    size_t n, cap;
};

static int contains(const struct target_filter *tf, uint32_t pid)
{
    for (size_t i = 0; i < tf->n; i++)
        if (tf->pids[i] == pid)
            return 1;
    return 0;
}

static void add_pid(struct target_filter *tf, uint32_t pid)
{
    if (pid == 0 || contains(tf, pid))
        return;
    if (tf->n == tf->cap) {
        size_t cap = tf->cap ? tf->cap * 2 : 64;
        uint32_t *p = realloc(tf->pids, cap * sizeof(*p));
        if (!p)
            return;  // Best-effort: dropping a pid only loses a few events.
        tf->pids = p;
        tf->cap = cap;
    }
    tf->pids[tf->n++] = pid;
}

static const char *basename_of(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

// Resolve a relative openat path against the process's live cwd. Leaves the
// path untouched if it is empty, already absolute, or the process is gone.
// Note: openat relative to a dirfd other than AT_FDCWD is not handled (the
// dirfd is not captured); MVP assumes cwd-relative paths.
static void absolutize_path(struct sysguard_event *e)
{
    if (e->path[0] == '\0' || e->path[0] == '/')
        return;

    char link[64];
    snprintf(link, sizeof(link), "/proc/%u/cwd", e->pid);

    char cwd[PATH_MAX];
    ssize_t n = readlink(link, cwd, sizeof(cwd) - 1);
    if (n <= 0)
        return;  // Process already exited; keep the relative path.
    cwd[n] = '\0';

    // Sized to hold cwd + '/' + path + NUL without truncation; the result is
    // then copied back into the fixed-size event field (truncated if needed).
    char joined[PATH_MAX + SYSGUARD_MAX_PATH];
    snprintf(joined, sizeof(joined), "%s/%s", cwd, e->path);

    strncpy(e->path, joined, SYSGUARD_MAX_PATH - 1);
    e->path[SYSGUARD_MAX_PATH - 1] = '\0';
}

struct target_filter *target_filter_new(const char *target_comm, uint32_t target_pid)
{
    struct target_filter *tf = calloc(1, sizeof(*tf));
    if (!tf)
        return NULL;

    if (target_comm && target_comm[0]) {
        strncpy(tf->target_comm, target_comm, sizeof(tf->target_comm) - 1);
        tf->active = 1;
    }
    if (target_pid) {
        tf->seed_pid = target_pid;
        tf->active = 1;
        add_pid(tf, target_pid);
    }
    return tf;
}

void target_filter_free(struct target_filter *tf)
{
    if (!tf)
        return;
    free(tf->pids);
    free(tf);
}

int target_filter_process(struct target_filter *tf, struct sysguard_event *e)
{
    if (!tf || !tf->active) {
        absolutize_path(e);
        return 1;  // Pass-through.
    }

    // Seed: a freshly exec'd target (its exe basename matches) or an event from
    // an already-running target (its comm matches) joins the tracked set.
    if (e->type == SYSGUARD_EVENT_EXEC &&
        strcmp(basename_of(e->exe_path), tf->target_comm) == 0)
        add_pid(tf, e->pid);
    if (strncmp(e->comm, tf->target_comm, TASK_COMM_LEN) == 0)
        add_pid(tf, e->pid);

    // Grow: any child of a tracked process is part of the subtree. Children are
    // created after their parent, so the parent's pid is already in the set by
    // the time the child's first event (exec or open) arrives.
    if (contains(tf, e->ppid))
        add_pid(tf, e->pid);

    if (!contains(tf, e->pid))
        return 0;

    absolutize_path(e);
    return 1;
}
