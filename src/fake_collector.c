#include "event.h"
#include "alert.h"
#include "rules.h"
#include "jsonl_writer.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

struct scenario {
    uint32_t type;
    const char *comm;
    const char *exe_path;
    const char *argv;
    const char *path;
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    const char *old_path;   // RENAME source (NULL/"" for other types).
    const char *new_path;   // RENAME destination.
    int32_t flags;          // RENAME renameat2 flags.
    int32_t mode;           // CHMOD mode bits (e.g. 0777).
};

static struct scenario scenarios[] = {
    /* Normal dev activity */
    {SYSGUARD_EVENT_EXEC, "git",     "/usr/bin/git",     "git status",        "", 3010, 3000, 1000, "", "", 0, 0},
    {SYSGUARD_EVENT_OPEN, "claude",  "",                 "",                  "{PROJECT}/src/main.c", 3000, 2500, 1000, "", "", 0, 0},
    {SYSGUARD_EVENT_EXEC, "make",    "/usr/bin/make",    "make",              "", 3011, 3000, 1000, "", "", 0, 0},
    {SYSGUARD_EVENT_OPEN, "claude",  "",                 "",                  "{PROJECT}/README.md", 3000, 2500, 1000, "", "", 0, 0},
    {SYSGUARD_EVENT_EXEC, "python3", "/usr/bin/python3", "python3 test.py",   "", 3012, 3000, 1000, "", "", 0, 0},

    /* Protected-path access (fires the specific protected rules, not boundary) */
    {SYSGUARD_EVENT_OPEN, "cat",     "",                 "",                  "{PROJECT}/.env", 3013, 3000, 1000, "", "", 0, 0},
    {SYSGUARD_EVENT_OPEN, "cat",     "",                 "",                  "/home/user/.ssh/id_rsa", 3014, 3000, 1000, "", "", 0, 0},
    {SYSGUARD_EVENT_OPEN, "cat",     "",                 "",                  "/etc/shadow", 3015, 3000, 0, "", "", 0, 0},
    {SYSGUARD_EVENT_OPEN, "cat",     "",                 "",                  "/etc/sudoers", 3016, 3000, 1000, "", "", 0, 0},

    /* Dangerous commands */
    {SYSGUARD_EVENT_EXEC, "git",     "/usr/bin/git",     "git reset --hard",  "", 3017, 3000, 1000, "", "", 0, 0},
    {SYSGUARD_EVENT_EXEC, "rm",      "/usr/bin/rm",      "rm -rf build/",     "", 3018, 3000, 1000, "", "", 0, 0},
    {SYSGUARD_EVENT_EXEC, "chmod",   "/usr/bin/chmod",   "chmod 777 test.sh", "", 3019, 3000, 1000, "", "", 0, 0},
    /* Caller is a shell (comm), the executed program is curl (exe_path): proves
     * downloader-exec matches exe_path/argv, not comm. */
    {SYSGUARD_EVENT_EXEC, "bash",    "/usr/bin/curl",    "curl http://example.com", "", 3020, 3000, 1000, "", "", 0, 0},
    /* Negative regression for the removed shell-exec rule: even with a shell
     * name in comm and a shell in exe_path, no alert must fire. */
    {SYSGUARD_EVENT_EXEC, "sh",      "/usr/bin/bash",    "bash -c echo hello", "", 3021, 3000, 1000, "", "", 0, 0},

    /* More file access: one file clearly outside the project root (fires
     * project-boundary-access) and one project-local file (does not). */
    {SYSGUARD_EVENT_OPEN, "cat",     "",                 "",                  "/home/user/outside-project/report.txt", 3040, 3000, 1000, "", "", 0, 0},
    {SYSGUARD_EVENT_OPEN, "claude",  "",                 "",                  "{PROJECT}/Makefile", 3000, 2500, 1000, "", "", 0, 0},

    /* File mutation events (unlinkat / renameat2 / fchmodat) */
    {SYSGUARD_EVENT_UNLINK, "rm",    "", "", "/home/user/project/build/stale.o", 3030, 3000, 1000, "", "", 0, 0},
    {SYSGUARD_EVENT_RENAME, "mv",    "", "", "",                                 3031, 3000, 1000, "/home/user/project/draft.md", "/home/user/project/final.md", 0, 0},
    {SYSGUARD_EVENT_CHMOD,  "chmod", "", "", "/home/user/project/deploy.sh",     3032, 3000, 1000, "", "", 0, 0777},
    {SYSGUARD_EVENT_CHMOD,  "chmod", "", "", "/home/user/project/notes.txt",     3033, 3000, 1000, "", "", 0, 0644},

    /* Session end marker */
    {SYSGUARD_EVENT_EXIT,   "claude", "", "", "",                                3000, 2500, 1000, "", "", 0, 0},
};

#define N_SCENARIOS (sizeof(scenarios) / sizeof(scenarios[0]))

void fake_collector_run(const char *output_path,
                        const char *session_id,
                        const char *project_path,
                        const char *target_comm) {
    FILE *fp = jsonl_open(output_path);
    if (!fp) {
        fprintf(stderr, "[ERROR] Cannot open %s\n", output_path);
        return;
    }

    printf("[SysGuard] Fake collector started. Generating %zu events...\n", N_SCENARIOS);
    uint64_t base_ts = (uint64_t)time(NULL) * 1000000000ULL;
    struct sysguard_rule_ctx rctx = { project_path };

    for (size_t i = 0; i < N_SCENARIOS; i++) {
        struct sysguard_event ev = {0};
        ev.timestamp_ns = base_ts + i * 1000000000ULL;
        ev.type = scenarios[i].type;
        ev.pid  = scenarios[i].pid;
        ev.ppid = scenarios[i].ppid;
        ev.uid  = scenarios[i].uid;
        strncpy(ev.comm, scenarios[i].comm, TASK_COMM_LEN - 1);

        /* Expand a leading "{PROJECT}/" sentinel to the runtime project root so
         * project-local fixtures track --project-path (falling back to a demo
         * root when none was supplied). */
        char path_buf[SYSGUARD_MAX_PATH];
        const char *spath = scenarios[i].path;
        if (strncmp(spath, "{PROJECT}/", 10) == 0) {
            const char *root = (project_path && project_path[0])
                                   ? project_path : "/home/user/project";
            snprintf(path_buf, sizeof(path_buf), "%s/%s", root, spath + 10);
            spath = path_buf;
        }

        switch (ev.type) {
        case SYSGUARD_EVENT_EXEC:
            strncpy(ev.exe_path, scenarios[i].exe_path, SYSGUARD_MAX_PATH - 1);
            strncpy(ev.argv,     scenarios[i].argv,     SYSGUARD_MAX_ARGV - 1);
            break;
        case SYSGUARD_EVENT_RENAME:
            strncpy(ev.old_path, scenarios[i].old_path, SYSGUARD_MAX_PATH - 1);
            strncpy(ev.new_path, scenarios[i].new_path, SYSGUARD_MAX_PATH - 1);
            ev.flags = scenarios[i].flags;
            break;
        case SYSGUARD_EVENT_CHMOD:
            strncpy(ev.path, spath, SYSGUARD_MAX_PATH - 1);
            ev.mode = scenarios[i].mode;
            break;
        case SYSGUARD_EVENT_EXIT:
            break;  /* payload-free session end marker */
        default:    /* OPEN, UNLINK: single target path */
            strncpy(ev.path, spath, SYSGUARD_MAX_PATH - 1);
            break;
        }

        struct sysguard_alert alert;
        if (rules_evaluate(&ev, &rctx, &alert)) {
            printf("  [%s] %s - %s\n",
                   sysguard_severity_string(alert.severity), alert.rule_id, alert.reason);
            jsonl_write_alert(fp, &ev, &alert, session_id, project_path, target_comm);
        } else {
            jsonl_write_event(fp, &ev, session_id, project_path, target_comm);
        }
        usleep(200000);
    }

    jsonl_close(fp);
    printf("[SysGuard] Fake collector done. Log: %s\n", output_path);
}
