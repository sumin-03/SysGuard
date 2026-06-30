#ifndef SYSGUARD_ALERT_H
#define SYSGUARD_ALERT_H

#include <stdint.h>

#define SYSGUARD_MAX_REASON 256
#define SYSGUARD_MAX_RECOMMENDATION 256
#define SYSGUARD_MAX_RULE_ID 64

enum sysguard_severity {
    SYSGUARD_SEV_LOW      = 1,
    SYSGUARD_SEV_MEDIUM   = 2,
    SYSGUARD_SEV_HIGH     = 3,
    SYSGUARD_SEV_CRITICAL = 4,
};

struct sysguard_alert {
    uint64_t timestamp_ns;
    char     rule_id[SYSGUARD_MAX_RULE_ID];
    enum sysguard_severity severity;

    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    char     comm[16];

    char     reason[SYSGUARD_MAX_REASON];
    char     recommendation[SYSGUARD_MAX_RECOMMENDATION];
};

const char *sysguard_severity_string(enum sysguard_severity severity);

#endif
