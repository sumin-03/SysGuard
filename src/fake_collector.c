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
};

static struct scenario scenarios[] = {
    /* Normal dev activity */
    {SYSGUARD_EVENT_EXEC, "git",     "/usr/bin/git",     "git status",        "", 3010, 3000, 1000},
    {SYSGUARD_EVENT_OPEN, "claude",  "",                 "",                  "/home/user/project/src/main.c", 3000, 2500, 1000},
    {SYSGUARD_EVENT_EXEC, "make",    "/usr/bin/make",    "make",              "", 3011, 3000, 1000},
    {SYSGUARD_EVENT_OPEN, "claude",  "",                 "",                  "/home/user/project/README.md", 3000, 2500, 1000},
    {SYSGUARD_EVENT_EXEC, "python3", "/usr/bin/python3", "python3 test.py",   "", 3012, 3000, 1000},

    /* Boundary violations */
    {SYSGUARD_EVENT_OPEN, "cat",     "",                 "",                  "/home/user/project/.env", 3013, 3000, 1000},
    {SYSGUARD_EVENT_OPEN, "cat",     "",                 "",                  "/home/user/.ssh/id_rsa", 3014, 3000, 1000},
    {SYSGUARD_EVENT_OPEN, "cat",     "",                 "",                  "/etc/shadow", 3015, 3000, 0},
    {SYSGUARD_EVENT_OPEN, "cat",     "",                 "",                  "/etc/sudoers", 3016, 3000, 1000},

    /* Dangerous commands */
    {SYSGUARD_EVENT_EXEC, "git",     "/usr/bin/git",     "git reset --hard",  "", 3017, 3000, 1000},
    {SYSGUARD_EVENT_EXEC, "rm",      "/usr/bin/rm",      "rm -rf build/",     "", 3018, 3000, 1000},
    {SYSGUARD_EVENT_EXEC, "chmod",   "/usr/bin/chmod",   "chmod 777 test.sh", "", 3019, 3000, 1000},
    {SYSGUARD_EVENT_EXEC, "curl",    "/usr/bin/curl",    "curl http://example.com", "", 3020, 3000, 1000},
    {SYSGUARD_EVENT_EXEC, "bash",    "/usr/bin/bash",    "bash -c echo hello", "", 3021, 3000, 1000},

    /* More file access */
    {SYSGUARD_EVENT_OPEN, "node",    "",                 "",                  "/home/user/.aws/credentials", 3022, 3000, 1000},
    {SYSGUARD_EVENT_OPEN, "claude",  "",                 "",                  "/home/user/project/Makefile", 3000, 2500, 1000},
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

    for (size_t i = 0; i < N_SCENARIOS; i++) {
        struct sysguard_event ev = {0};
        ev.timestamp_ns = base_ts + i * 1000000000ULL;
        ev.type = scenarios[i].type;
        ev.pid  = scenarios[i].pid;
        ev.ppid = scenarios[i].ppid;
        ev.uid  = scenarios[i].uid;
        strncpy(ev.comm, scenarios[i].comm, TASK_COMM_LEN - 1);

        if (ev.type == SYSGUARD_EVENT_EXEC) {
            strncpy(ev.exe_path, scenarios[i].exe_path, SYSGUARD_MAX_PATH - 1);
            strncpy(ev.argv, scenarios[i].argv, SYSGUARD_MAX_ARGV - 1);
        } else {
            strncpy(ev.path, scenarios[i].path, SYSGUARD_MAX_PATH - 1);
        }

        struct sysguard_alert alert;
        if (rules_evaluate(&ev, &alert)) {
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
