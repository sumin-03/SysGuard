#ifndef SYSGUARD_RULES_H
#define SYSGUARD_RULES_H

#include "event.h"
#include "alert.h"

// Returns 1 if event matches a rule, fills alert. 0 otherwise.
int rules_evaluate(const struct  sysguard_event *ev, struct sysguard_alert *out);

#endif
