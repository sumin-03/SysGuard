#include "event.h"
#include "alert.h"
#include "rules.h"
#include "jsonl_writer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

struct fake_scenario {
    enum sysguard_event_type type;
    const char *comm;
    const char *filename;
    uint32_t pid;
    uint32_t uid;
};

static struct fake_scenario scenarios[] = {
    {SYSGUARD_EVENT_EXEC, "bash",    "/usr/bin/bash",       1001, 1000},
    {SYSGUARD_EVENT_EXEC, "ls",      "/usr/bin/ls",         1002, 1000},
    {SYSGUARD_EVENT_OPEN, "cat",     "/etc/passwd",         1003, 1000},
    {SYSGUARD_EVENT_EXEC, "curl",    "/usr/bin/curl",       1004, 1000},
    {SYSGUARD_EVENT_OPEN, "vim",     "/etc/shadow",         1005, 0},
    {SYSGUARD_EVENT_EXEC, "nmap",    "/usr/bin/nmap",       1006, 1000},
    {SYSGUARD_EVENT_OPEN, "python3", "/root/.ssh/id_rsa",   1007, 1000},
    {SYSGUARD_EVENT_EXEC, "gcc",     "/usr/bin/gcc",        1008, 1000},
    {SYSGUARD_EVENT_EXEC, "base64",  "/usr/bin/base64",     1009, 1000},
    {SYSGUARD_EVENT_OPEN, "bash",    "/var/log/auth.log",   1010, 0},
    {SYSGUARD_EVENT_EXEC, "chmod",   "/usr/bin/chmod",      1011, 1000},
    {SYSGUARD_EVENT_OPEN, "cat",     "/etc/sudoers",        1012, 1000},
};

#define SCENARIO_COUNT (sizeof(scenarios) / sizeof(scenarios[0]))

void fake_collector_run(const char *output_path) {
    FILE *fp = jsonl_open(output_path);
    if (!fp) {
        fprintf(stderr, "[ERROR] Cannot open %s\n", output_path);
        return;
    }

    printf("[SysGuard] Fake collector started. Generating %zu events...\n",
           SCENARIO_COUNT);

    for (size_t i = 0; i < SCENARIO_COUNT; i++) {
        struct sysguard_event ev = {0};
        ev.timestamp_ns = (uint64_t)time(NULL) * 1000000000ULL;
        ev.type = scenarios[i].type;
        ev.pid  = scenarios[i].pid;
        ev.uid  = scenarios[i].uid;
        strncpy(ev.comm, scenarios[i].comm, TASK_COMM_LEN - 1);

        if (ev.type == SYSGUARD_EVENT_EXEC) {
            strncpy(ev.exe_path, scenarios[i].filename, SYSGUARD_MAX_PATH - 1);
        } else {
            strncpy(ev.path, scenarios[i].filename, SYSGUARD_MAX_PATH - 1);
        }

        struct sysguard_alert alert;
        if (rules_evaluate(&ev, &alert)) {
            printf("  [%s] %s — %s\n",
                   sysguard_severity_string(alert.severity), alert.rule_id, alert.reason);
            jsonl_write_alert(fp, &ev, &alert);
        } else {
            jsonl_write_event(fp, &ev);
        }

        usleep(200000);
    }

    jsonl_close(fp);
    printf("[SysGuard] Fake collector done. Log: %s\n", output_path);
}
