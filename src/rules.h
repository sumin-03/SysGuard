#ifndef SYSGUARD_RULES_H
#define SYSGUARD_RULES_H

#include "event.h"
#include "alert.h"

// Session-scoped context for rule evaluation. Kept as a struct (rather than a
// bare parameter) so future session context can be added without changing call
// sites. ctx may be NULL, and project_path may be NULL/empty/non-absolute — in
// that case only the outside-project-write rule is disabled; all other rules
// still evaluate normally.
struct sysguard_rule_ctx {
    const char *project_path;   // Absolute repo root, or NULL/"" to disable the
                                // outside-project-write rule.
    const char *home_path;      // Monitored user's home, for home-relative
                                // persistence / runtime-noise matching. NULL,
                                // "", "/" or a relative value disables ONLY the
                                // home-relative matches (fail-closed: such
                                // writes then stay outside-project-write).
    const char *tool_tmp_path;  // Trusted per-session toolchain temp root (the
                                // TMPDIR handed to the agent), so compiler
                                // intermediates land in an already-classified
                                // location instead of /tmp/ccXXXXXX.*. NULL/""
                                // disables the exemption. main.c validates it:
                                // absolute, owned by the monitored uid, 0700.
};

int rules_evaluate(const struct sysguard_event *ev,
                   const struct sysguard_rule_ctx *ctx,
                   struct sysguard_alert *out);

#endif
